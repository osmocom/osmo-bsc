/*
 * SCCPlite MGCP handling
 *
 * (C) 2018 by Harald Welte <laforge@gnumonks.org>
 * (C) 2023 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
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

#include <string.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/sockaddr_str.h>
#include <osmocom/mgcp_client/mgcp_client_endpoint_fsm.h>
#include <osmocom/mgcp_client/mgcp_client.h>

#include <osmocom/bsc/bsc_msc_data.h>
#include <osmocom/bsc/osmo_bsc.h>
#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/debug.h>
#include <osmocom/gsm/ipa.h>
#include <osmocom/gsm/protocol/ipaccess.h>
#include <osmocom/bsc/osmo_bsc_sigtran.h>

#include <arpa/inet.h>

/* negative on error, zero upon success */
static int parse_local_endpoint_name(char *buf, size_t buf_len, const char *data)
{
	char line[1024];
	char *epstart, *sep;
	const char *start = data;
	char *eol = strpbrk(start, "\r\n");

	if (!eol)
		return -1;

	if (eol - start > sizeof(line))
		return -1;
	memcpy(line, start, eol - start);
	line[eol - start] = '\0';

	if (!(epstart = strchr(line, ' ')))
		return -1;
	epstart++;
	/* epstart now points to trans */

	if (!(epstart = strchr(epstart, ' ')))
		return -1;
	epstart++;
	/* epstart now points to endpoint */
	if (!(sep = strchr(epstart, '@')))
		return -1;
	if (sep - epstart >= buf_len)
		return -1;

	*sep = '\0';
	osmo_strlcpy(buf, epstart, buf_len);
	return 0;
}

static int _bsc_sccplite_rx_mgcp(struct bsc_msc_data *msc, struct msgb *msg)
{
	struct gsm_subscriber_connection *conn;
	char rcv_ep_local_name[1024];
	struct osmo_sockaddr_str osa_str = {};
	struct osmo_sockaddr osa = {};
	socklen_t dest_len;
	struct mgcp_client *mgcp_cli = NULL;
	int rc;

	LOG_MSC(msc, LOGL_INFO, "Received IPA-encapsulated MGCP: %s\n", (const char *)msgb_l2(msg));

	rc = parse_local_endpoint_name(rcv_ep_local_name, sizeof(rcv_ep_local_name),
				       (const char *)msgb_l2(msg));
	if (rc < 0) {
		LOG_MSC(msc, LOGL_ERROR, "Received IPA-encapsulated MGCP: Failed to parse CIC\n");
		return rc;
	}

	/* Lookup which conn attached to the MSC holds an MGW endpoint with the
	 * name Endpoint Number as the one provided in the MGCP msg we received
	 * from MSC. Since CIC are unique per MSC, that's the same MGW in the
	 * pool where we have to forward the MGCP message. */
	llist_for_each_entry(conn, &bsc_gsmnet->subscr_conns, entry) {
		const char *ep_local_name;
		if (conn->sccp.msc != msc)
			continue; /* Only conns belonging to this MSC */
		if (!conn->user_plane.mgw_endpoint)
			continue;
		ep_local_name = osmo_mgcpc_ep_local_name(conn->user_plane.mgw_endpoint);
		LOGPFSMSL(conn->fi, DMSC, LOGL_DEBUG, "ep_local_name='%s' vs rcv_ep_local_name='%s'\n",
			  ep_local_name ? : "(null)", rcv_ep_local_name);
		if (!ep_local_name)
			continue;
		if (strcmp(ep_local_name, rcv_ep_local_name) != 0)
			continue;
		mgcp_cli = osmo_mgcpc_ep_client(conn->user_plane.mgw_endpoint);
		if (!mgcp_cli)
			continue;
		break;
	}

	if (!mgcp_cli) {
		LOG_MSC(msc, LOGL_ERROR, "Received IPA-encapsulated MGCP: Failed to find associated MGW\n");
		return 0;
	}

	rc = osmo_sockaddr_str_from_str(&osa_str, mgcp_client_remote_addr_str(mgcp_cli),
					mgcp_client_remote_port(mgcp_cli));
	if (rc < 0) {
		LOG_MSC(msc, LOGL_ERROR, "Received IPA-encapsulated MGCP: Failed to parse MGCP address %s:%u\n",
			mgcp_client_remote_addr_str(mgcp_cli), mgcp_client_remote_port(mgcp_cli));
		return rc;
	}

	LOG_MSC(msc, LOGL_NOTICE, "Forwarding IPA-encapsulated MGCP to MGW at " OSMO_SOCKADDR_STR_FMT "\n",
		OSMO_SOCKADDR_STR_FMT_ARGS_NOT_NULL(&osa_str));

	rc = osmo_sockaddr_str_to_sockaddr(&osa_str, &osa.u.sas);
	if (rc < 0) {
		LOG_MSC(msc, LOGL_ERROR, "Received IPA-encapsulated MGCP: Failed to parse MGCP address " OSMO_SOCKADDR_STR_FMT "\n",
			OSMO_SOCKADDR_STR_FMT_ARGS_NOT_NULL(&osa_str));
		return rc;
	}
	dest_len = osmo_sockaddr_size(&osa);

	/* we don't have a write queue here as we simply expect the socket buffers
	 * to be large enough to deal with whatever small/infrequent MGCP messages */
	rc = sendto(msc->mgcp_ipa.ofd.fd, msgb_l2(msg), msgb_l2len(msg), 0, &osa.u.sa, dest_len);

	return rc;
}

/* We received an IPA-encapsulated MGCP message from MSC. msg owned by caller. */
int bsc_sccplite_rx_mgcp(struct bsc_msc_data *msc, struct msgb *msg)
{
	int rc;
	struct msgb *msg_resized;

	if (msgb_l2len(msg) == 0) {
		LOG_MSC(msc, LOGL_NOTICE, "Received empty IPA-encapsulated MGCP\n");
		return -ENODATA;
	}

	/* Make sure we have a NULL-terminated string to be on the safe side: */
	if (*((const char *)msgb_l2(msg) + msgb_l2len(msg) - 1) == '\0')
		return _bsc_sccplite_rx_mgcp(msc, msg);

	/* If there's extra space available in msgb from lower layers, simply nullify next char: */
	if (msgb_tailroom(msg) > 0) {
		*msg->tail = '\0';
		return _bsc_sccplite_rx_mgcp(msc, msg);
	}

	/* Otherwise, craft a resized message: */
	msg_resized = msgb_copy_resize(msg, msgb_length(msg)+1, "mgcp-resized");
	OSMO_ASSERT(msgb_tailroom(msg) == 1);
	*msg->tail = '\0';
	rc = _bsc_sccplite_rx_mgcp(msc, msg_resized);
	msgb_free(msg_resized);
	return rc;
}

/* we received some data on the UDP proxy socket from the MGW. Pass it to MSC via IPA */
int bsc_sccplite_mgcp_proxy_cb(struct osmo_fd *ofd, unsigned int what)
{
	struct bsc_msc_data *msc = ofd->data;
	struct msgb *msg;
	int rc;

	if (!(what & OSMO_FD_READ))
		return 0;

	msg = msgb_alloc_headroom(1400, 64, "MGCP->IPA");
	OSMO_ASSERT(msg);
	rc = recv(ofd->fd, msg->data, msgb_tailroom(msg), 0);
	if (rc <= 0) {
		LOGP(DMSC, LOGL_ERROR, "error receiving data from MGCP<->IPA proxy UDP socket: "
			"%s\n", strerror(errno));
		msgb_free(msg);
		return rc;
	}
	msg->l2h = msgb_put(msg, rc);
	msg->l2h[rc] = '\0';
	LOGP(DMSC, LOGL_NOTICE, "Received MGCP on UDP proxy socket: %s\n", msg->l2h);

	osmo_ipa_msg_push_header(msg, IPAC_PROTO_MGCP_OLD);
	return bsc_sccplite_msc_send(msc, msg);
}
