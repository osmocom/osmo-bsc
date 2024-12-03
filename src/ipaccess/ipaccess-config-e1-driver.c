/* OpenBSC Abis input driver for ip.access */

/* (C) 2024 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * (C) 2009-2021 by Harald Welte <laforge@gnumonks.org>
 * (C) 2010 by Holger Hans Peter Freyther
 * (C) 2010 by On-Waves
 *
 * All Rights Reserved
 *
 * SPDX-License-Identifier: AGPL-3.0+
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#include <osmocom/core/select.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/macaddr.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/backtrace.h>
#include <osmocom/core/fsm.h>
#include <osmocom/core/signal.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/gsm/protocol/ipaccess.h>
#include <osmocom/gsm/ipa.h>
#include <osmocom/netif/stream.h>
#include <osmocom/netif/ipa.h>
#include <osmocom/abis/e1_input.h>
#include <osmocom/abis/ipa.h>

/* default port at BTS for incoming connections */
#define IPACCESS_BTS_LISTEN_OML_PORT 3006

/* global parameters of IPA input driver */
struct ipaccess_config_proto_pars {
	uint8_t dscp;
	uint8_t priority;
};
struct ipaccess_config_pars {
	struct ipaccess_config_proto_pars oml;
	struct ipaccess_config_proto_pars rsl;
	char *connect_addr;
};
struct ipaccess_config_pars g_e1inp_ipaccess_config_pars;

static void *tall_ipa_ctx;

struct ipaccess_line {
	bool line_already_initialized;
	struct osmo_stream_cli *ipa_cli[NUM_E1_TS]; /* 0=OML, 1+N=TRX_N */
};

static int e1inp_int_snd_event(struct e1inp_ts *ts, struct e1inp_sign_link *link, int evt)
{
	struct input_signal_data isd;
	isd.line = ts->line;
	isd.ts_nr = ts->num;
	isd.link_type = link->type;
	isd.trx = link->trx;
	isd.tei = link->tei;
	isd.sapi = link->sapi;

	/* report further upwards */
	osmo_signal_dispatch(SS_L_INPUT, evt, &isd);
	return 0;
}

static inline struct e1inp_ts *ipaccess_line_ts(struct osmo_fd *bfd, struct e1inp_line *line)
{
	if (bfd->priv_nr == E1INP_SIGN_OML)
		return e1inp_line_ipa_oml_ts(line);
	else
		return e1inp_line_ipa_rsl_ts(line, bfd->priv_nr - E1INP_SIGN_RSL);
}


static void _ipaccess_bts_down_cb(struct osmo_stream_cli *cli)
{
	struct e1inp_ts *e1i_ts = osmo_stream_cli_get_data(cli);
	struct e1inp_line *line = e1i_ts->line;

	if (line->ops->sign_link_down)
		line->ops->sign_link_down(line);
}

/* See how ts->num is assigned in e1inp_line_create: line->ts[i].num = i+1;
* As per e1inp_line_ipa_oml_ts(), first TS in line (ts->num=1) is OML.
* As per e1inp_line_ipa_rsl_ts(), second TS in line (ts->num>=2) is RSL.
*/
static inline enum e1inp_sign_type ipaccess_e1i_ts_sign_type(const struct e1inp_ts *e1i_ts)
{
	OSMO_ASSERT(e1i_ts->num != 0);
	if (e1i_ts->num == 1)
		return E1INP_SIGN_OML;
	return E1INP_SIGN_RSL;
}

static inline unsigned int ipaccess_e1i_ts_trx_nr(const struct e1inp_ts *e1i_ts)
{
	enum e1inp_sign_type sign_type = ipaccess_e1i_ts_sign_type(e1i_ts);
	if (sign_type == E1INP_SIGN_OML)
		return 0; /* OML uses trx_nr=0 */
	OSMO_ASSERT(sign_type == E1INP_SIGN_RSL);
	/* e1i_ts->num >= 2: */
	return e1i_ts->num - 2;
}

static inline struct osmo_stream_cli *ipaccess_bts_e1i_ts_stream_cli(const struct e1inp_ts *e1i_ts)
{
	OSMO_ASSERT(e1i_ts);
	struct ipaccess_line *il = e1i_ts->line->driver_data;
	OSMO_ASSERT(il);
	struct osmo_stream_cli *cli = il->ipa_cli[e1i_ts->num - 1];
	OSMO_ASSERT(cli);
	return cli;
}

static void ipaccess_close(struct e1inp_sign_link *sign_link)
{
	struct e1inp_ts *e1i_ts = sign_link->ts;
	struct osmo_fd *bfd = &e1i_ts->driver.ipaccess.fd;
	struct osmo_stream_cli *cli;

	e1inp_int_snd_event(e1i_ts, sign_link, S_L_INP_TEI_DN);
	/* the first e1inp_sign_link_destroy call closes the socket. */

	cli = ipaccess_bts_e1i_ts_stream_cli(e1i_ts);
	osmo_stream_cli_close(cli);
	bfd->fd = -1; /* Compatibility with older implementations */
}

static bool e1i_ts_has_pending_tx_msgs(struct e1inp_ts *e1i_ts)
{
	struct e1inp_sign_link *link;
	llist_for_each_entry(link, &e1i_ts->sign.sign_links, list) {
		if (!llist_empty(&link->tx_list))
			return true;
	}
	return false;
}

static int ipaccess_bts_send_msg(struct e1inp_ts *e1i_ts,
				 struct e1inp_sign_link *sign_link,
				 struct osmo_stream_cli *cli,
				 struct msgb *msg)
{
	switch (sign_link->type) {
	case E1INP_SIGN_OML:
	case E1INP_SIGN_RSL:
	case E1INP_SIGN_OSMO:
		break;
	default:
		msgb_free(msg);
		return -EINVAL;
	}

	msg->l2h = msg->data;
	ipa_prepend_header(msg, sign_link->tei);

	LOGPITS(e1i_ts, DLMI, LOGL_DEBUG, "TX: %s\n", osmo_hexdump(msg->l2h, msgb_l2len(msg)));
	osmo_stream_cli_send(cli, msg);
	return 0;
}

/* msg was enqueued in sign_link->tx_list.
 * Pop it from that list, submit it to osmo_stream_cli: */
static int ts_want_write(struct e1inp_ts *e1i_ts)
{
	int rc = 0;
	struct osmo_stream_cli *cli = ipaccess_bts_e1i_ts_stream_cli(e1i_ts);

	/* get the next msg for this timeslot */
	while (e1i_ts_has_pending_tx_msgs(e1i_ts)) {
		struct e1inp_sign_link *sign_link = NULL;
		struct msgb *msg;
		msg = e1inp_tx_ts(e1i_ts, &sign_link);
		OSMO_ASSERT(msg);
		OSMO_ASSERT(sign_link);
		rc |= ipaccess_bts_send_msg(e1i_ts, sign_link, cli, msg);
	}
	return rc;
}

static struct msgb *ipa_bts_id_ack(void)
{
	struct msgb *nmsg2;
	nmsg2 = ipa_msg_alloc(0);
	if (!nmsg2)
		return NULL;
	msgb_v_put(nmsg2, IPAC_MSGT_ID_ACK);
	ipa_prepend_header(nmsg2, IPAC_PROTO_IPACCESS);
	return nmsg2;
}

static void update_fd_settings(struct e1inp_line *line, int fd)
{
	int ret;
	int val;

	val = 1;
	ret = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));
	if (ret < 0)
		LOGPIL(line, DLINP, LOGL_ERROR, "Failed to set TCP_NODELAY: %s\n", strerror(errno));
}

static int _ipaccess_bts_handle_ccm(struct osmo_stream_cli *cli,
				    struct ipaccess_unit *dev, struct msgb *msg)
{
	/* special handling for IPA CCM. */
	if (osmo_ipa_msgb_cb_proto(msg) != IPAC_PROTO_IPACCESS)
		return 0;

	int ret = 0;
	const uint8_t *data = msgb_l2(msg);
	int len = msgb_l2len(msg);
	OSMO_ASSERT(len > 0);
	uint8_t msg_type = *data;
	struct e1inp_ts *e1i_ts = osmo_stream_cli_get_data(cli);
	/* line might not exist if != bsc||bts */

	/* ping, pong and acknowledgment cases. */
	struct osmo_fd tmp_ofd = { .fd = osmo_stream_cli_get_fd(cli) };
	OSMO_ASSERT(tmp_ofd.fd >= 0);
	ret = ipa_ccm_rcvmsg_bts_base(msg, &tmp_ofd);
	if (ret < 0)
		goto err;

	/* this is a request for identification from the BSC. */
	if (msg_type == IPAC_MSGT_ID_GET) {
		struct msgb *rmsg;
		/* The ipaccess_unit dev holds generic identity for the whole
		 * line, hence no trx_id. Patch ipaccess_unit during call to
		 * ipa_ccm_make_id_resp_from_req() to identify this TRX: */
		int store_trx_nr = dev->trx_id;
		dev->trx_id = ipaccess_e1i_ts_trx_nr(e1i_ts);
		LOGP(DLINP, LOGL_NOTICE, "received ID_GET for unit ID %u/%u/%u\n",
		     dev->site_id, dev->bts_id, dev->trx_id);
		rmsg = ipa_ccm_make_id_resp_from_req(dev, data + 1, len - 1);
		dev->trx_id = store_trx_nr;
		if (!rmsg) {
			LOGP(DLINP, LOGL_ERROR, "Failed parsing ID_GET message.\n");
			goto err;
		}
		osmo_stream_cli_send(cli, rmsg);

		/* send ID_ACK. */
		rmsg = ipa_bts_id_ack();
		if (!rmsg) {
			LOGP(DLINP, LOGL_ERROR, "Failed allocating ID_ACK message.\n");
			goto err;
		}
		osmo_stream_cli_send(cli, rmsg);
	}
	return 1;

err:
	return -1;
}

static int ipaccess_bts_read_cb(struct osmo_stream_cli *cli, int res, struct msgb *msg)
{
	enum ipaccess_proto ipa_proto = osmo_ipa_msgb_cb_proto(msg);
	struct e1inp_ts *e1i_ts = osmo_stream_cli_get_data(cli);
	struct e1inp_line *line = e1i_ts->line;
	struct e1inp_sign_link *sign_link;
	int ret;

	if (res <= 0) {
		LOGPITS(e1i_ts, DLINP, LOGL_NOTICE, "failed reading from socket: %d\n", res);
		goto err;
	}

	/* special handling for IPA CCM. */
	if (ipa_proto == IPAC_PROTO_IPACCESS) {
		uint8_t msg_type = *(msg->l2h);
		/* this is a request for identification from the BSC. */
		if (msg_type == IPAC_MSGT_ID_GET) {
			if (!line->ops->sign_link_up) {
				LOGPITS(e1i_ts, DLINP, LOGL_NOTICE,
					"Unable to set signal link, closing socket.\n");
				goto err;
			}
		}
	}

	/* core CCM handling */
	ret = _ipaccess_bts_handle_ccm(cli, line->ops->cfg.ipa.dev, msg);
	if (ret < 0)
		goto err;

	if (ret == 1 && ipa_proto == IPAC_PROTO_IPACCESS) {
		uint8_t msg_type = *(msg->l2h);
		if (msg_type == IPAC_MSGT_ID_GET) {
			enum e1inp_sign_type sign_type = ipaccess_e1i_ts_sign_type(e1i_ts);
			unsigned int trx_nr = ipaccess_e1i_ts_trx_nr(e1i_ts);
			sign_link = line->ops->sign_link_up(line->ops->cfg.ipa.dev,
							    line, sign_type + trx_nr);
			if (sign_link == NULL) {
				LOGPITS(e1i_ts, DLINP, LOGL_NOTICE,
					"Unable to set signal link, closing socket.\n");
				goto err;
			}
		}
		msgb_free(msg);
		return ret;
	}

	/* look up for some existing signaling link. */
	sign_link = e1inp_lookup_sign_link(e1i_ts, ipa_proto, 0);
	if (sign_link == NULL) {
		LOGPITS(e1i_ts, DLINP, LOGL_ERROR, "no matching signalling link for "
			"ipa_proto=0x%02x\n", ipa_proto);
		goto err;
	}
	msg->dst = sign_link;

	/* XXX better use e1inp_ts_rx? */
	if (!line->ops->sign_link) {
		LOGPITS(e1i_ts, DLINP, LOGL_ERROR, "Fix your application, "
			"no action set for signalling messages.\n");
		goto err;
	}
	return line->ops->sign_link(msg);

err:
	msgb_free(msg);
	osmo_stream_cli_close(cli);
	return -EBADF;
}

static int ipaccess_bts_connect_cb(struct osmo_stream_cli *cli)
{
	struct e1inp_ts *e1i_ts = osmo_stream_cli_get_data(cli);
	struct e1inp_line *line = e1i_ts->line;
	struct msgb *rmsg;

	update_fd_settings(line, osmo_stream_cli_get_fd(cli));

	/* send ID_ACK. */
	rmsg = ipa_bts_id_ack();
	if (!rmsg) {
		LOGP(DLINP, LOGL_ERROR, "Failed allocating ID_ACK message.\n");
		return 0;
	}
	osmo_stream_cli_send(cli, rmsg);
	return 0;
}

static int ipaccess_bts_disconnect_cb(struct osmo_stream_cli *cli)
{
	_ipaccess_bts_down_cb(cli);
	return 0;
}

static int ipaccess_line_update(struct e1inp_line *line)
{
	int ret = -ENOENT;
	struct ipaccess_line *il;

	if (!line->driver_data)
		line->driver_data = talloc_zero(line, struct ipaccess_line);

	if (!line->driver_data) {
		LOGPIL(line, DLINP, LOGL_ERROR, "ipaccess: OOM in line update\n");
		return -ENOMEM;
	}
	il = line->driver_data;

	/* We only initialize this line once. */
	if (il->line_already_initialized)
		return 0;

	struct osmo_stream_cli *cli;
	struct e1inp_ts *e1i_ts = e1inp_line_ipa_oml_ts(line);
	char cli_name[128];

	LOGPITS(e1i_ts, DLINP, LOGL_NOTICE, "enabling ipaccess BTS mode, "
		"OML connecting to %s:%u\n", g_e1inp_ipaccess_config_pars.connect_addr, IPACCESS_BTS_LISTEN_OML_PORT);

	/* Drop previous line */
	if (il->ipa_cli[0]) {
		osmo_stream_cli_close(il->ipa_cli[0]);
		e1i_ts->driver.ipaccess.fd.fd = -1;
		osmo_stream_cli_destroy(il->ipa_cli[0]);
		il->ipa_cli[0] = NULL;
	}

	e1inp_ts_config_sign(e1i_ts, line);

	cli = osmo_stream_cli_create(tall_ipa_ctx);
	OSMO_ASSERT(cli);

	snprintf(cli_name, sizeof(cli_name), "ts-%u-%u-oml", line->num, e1i_ts->num);
	osmo_stream_cli_set_name(cli, cli_name);
	osmo_stream_cli_set_data(cli, e1i_ts);
	osmo_stream_cli_set_addr(cli, g_e1inp_ipaccess_config_pars.connect_addr);
	osmo_stream_cli_set_port(cli, IPACCESS_BTS_LISTEN_OML_PORT);
	osmo_stream_cli_set_proto(cli, IPPROTO_TCP);
	osmo_stream_cli_set_nodelay(cli, true);
	osmo_stream_cli_set_priority(cli, g_e1inp_ipaccess_config_pars.oml.dscp);
	osmo_stream_cli_set_ip_dscp(cli, g_e1inp_ipaccess_config_pars.oml.priority);

	/* Reconnect is handled by upper layers: */
	osmo_stream_cli_set_reconnect_timeout(cli, -1);

	osmo_stream_cli_set_segmentation_cb(cli, osmo_ipa_segmentation_cb);
	osmo_stream_cli_set_connect_cb(cli, ipaccess_bts_connect_cb);
	osmo_stream_cli_set_disconnect_cb(cli, ipaccess_bts_disconnect_cb);
	osmo_stream_cli_set_read_cb2(cli, ipaccess_bts_read_cb);

	if (osmo_stream_cli_open(cli)) {
		LOGPITS(e1i_ts, DLINP, LOGL_ERROR, "cannot open OML BTS link: %s\n", strerror(errno));
		osmo_stream_cli_destroy(cli);
		return -EIO;
	}

	/* Compatibility with older ofd based implementation. osmo-bts accesses
	 * this fd directly in get_signlink_remote_ip() and get_rsl_local_ip() */
	e1i_ts->driver.ipaccess.fd.fd = osmo_stream_cli_get_fd(cli);

	il->ipa_cli[0] = cli;
	ret = 0;

	il->line_already_initialized = true;
	return ret;
}

static struct e1inp_driver ipaccess_config_driver = {
	.name = "ipaccess-config",
	.want_write = ts_want_write,
	.line_update = ipaccess_line_update,
	.close = ipaccess_close,
	.default_delay = 0,
	.has_keepalive = 0,
};

void e1inp_ipaccess_config_init(void *ctx)
{
	tall_ipa_ctx = talloc_named_const(ctx, 1, "ipaccess-config");
	e1inp_driver_register(&ipaccess_config_driver);

	g_e1inp_ipaccess_config_pars.connect_addr = talloc_strdup(tall_ipa_ctx, "127.0.0.1");
}

void e1inp_ipaccess_config_set_connect_addr(const char *connect_addr)
{
	osmo_talloc_replace_string(tall_ipa_ctx,
				   &g_e1inp_ipaccess_config_pars.connect_addr,
				   connect_addr);
}
