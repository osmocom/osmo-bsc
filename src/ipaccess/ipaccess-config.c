/* ip.access nanoBTS configuration tool */

/* (C) 2009-2010 by Harald Welte <laforge@gnumonks.org>
 * (C) 2009-2011 by Holger Hans Peter Freyther
 * (C) 2009-2010 by On-Waves
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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <ctype.h>
#include <regex.h>
#include <inttypes.h>
#include <sys/fcntl.h>
#include <sys/stat.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#include <osmocom/core/application.h>
#include <osmocom/core/select.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/talloc.h>
#include <osmocom/gsm/protocol/gsm_12_21.h>
#include <osmocom/gsm/protocol/ipaccess.h>
#include <osmocom/abis/abis.h>
#include <osmocom/abis/e1_input.h>
#include <osmocom/bsc/ipaccess.h>
#include <osmocom/bsc/abis_nm.h>
#include <osmocom/bsc/signal.h>
#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/network_listen.h>
#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/abis_nm.h>
#include <osmocom/bsc/signal.h>
#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/network_listen.h>
#include <osmocom/bsc/bss.h>
#include <osmocom/bsc/bts.h>

static int net_listen_testnr;
static int restart;
static bool get_attr;
static char *prim_oml_ip;
static char *bts_ip_addr, *bts_ip_mask, *bts_ip_gw;
static char *unit_id;
static uint16_t nv_flags;
static uint16_t nv_mask;
static char *software = NULL;
static int sw_load_state = 0;
static int oml_state = 0;
static int dump_files = 0;
static char *firmware_analysis = NULL;
static int found_trx = 0;
static int loop_tests = 0;
static bool quiet = false;

static void *tall_ctx_config = NULL;
static struct abis_nm_sw_desc *sw_load1 = NULL;
static struct abis_nm_sw_desc *sw_load2 = NULL;

extern int ipaccess_fd_cb(struct osmo_fd *bfd, unsigned int what);
extern struct e1inp_line_ops ipaccess_e1inp_line_ops;

/* Actively connect to a BTS.  Currently used by ipaccess-config.c */
static int ipaccess_connect(struct e1inp_line *line, struct sockaddr_in *sa)
{
	struct e1inp_ts *e1i_ts = &line->ts[0];
	struct osmo_fd *bfd = &e1i_ts->driver.ipaccess.fd;
	int ret, on = 1;

	bfd->fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	bfd->cb = ipaccess_fd_cb;
	bfd->when = OSMO_FD_READ | OSMO_FD_WRITE;
	bfd->data = line;
	bfd->priv_nr = E1INP_SIGN_OML;

	if (bfd->fd < 0) {
		LOGP(DLINP, LOGL_ERROR, "could not create TCP socket.\n");
		return -EIO;
	}

	ret = setsockopt(bfd->fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	if (ret < 0) {
		LOGP(DLINP, LOGL_ERROR, "could not set socket option\n");
		close(bfd->fd);
		return -EIO;
	}

	ret = connect(bfd->fd, (struct sockaddr *) sa, sizeof(*sa));
	if (ret < 0) {
		LOGP(DLINP, LOGL_ERROR, "could not connect socket\n");
		close(bfd->fd);
		return ret;
	}

	ret = osmo_fd_register(bfd);
	if (ret < 0) {
		LOGP(DLINP, LOGL_ERROR, "unable to register socket fd\n");
		close(bfd->fd);
		return ret;
	}
	return ret;
	//return e1inp_line_register(line);
}

/* configure pseudo E1 line in ip.access style and connect to BTS */
static int ia_config_connect(struct gsm_bts *bts, struct sockaddr_in *sin)
{
	struct e1inp_line *line;
	struct e1inp_ts *sign_ts, *rsl_ts;
	struct e1inp_sign_link *oml_link, *osmo_link, *rsl_link;

	line = talloc_zero(tall_bsc_ctx, struct e1inp_line);
	if (!line)
		return -ENOMEM;

	line->driver = e1inp_driver_find("ipa");
	if (!line->driver) {
		fprintf(stderr, "cannot `ipa' driver, giving up.\n");
		return -EINVAL;
	}
	e1inp_line_bind_ops(line, &ipaccess_e1inp_line_ops);
	e1_set_pcap_fd2(line, -1); /* Disable writing to pcap */

	sign_ts = e1inp_line_ipa_oml_ts(line);
	rsl_ts = e1inp_line_ipa_rsl_ts(line, 0);

	/* create E1 timeslots for signalling and TRAU frames */
	e1inp_ts_config_sign(sign_ts, line);
	e1inp_ts_config_sign(rsl_ts, line);
	rsl_ts->driver.ipaccess.fd.fd = -1;

	/* create signalling links for TRX0 */
	oml_link = e1inp_sign_link_create(sign_ts, E1INP_SIGN_OML,
					  bts->c0, IPAC_PROTO_OML, 0);
	osmo_link =  e1inp_sign_link_create(sign_ts, E1INP_SIGN_OSMO,
					    bts->c0, IPAC_PROTO_OSMO, 0);
	rsl_link = e1inp_sign_link_create(rsl_ts, E1INP_SIGN_RSL,
					  bts->c0, IPAC_PROTO_RSL, 0);

	/* create back-links from bts/trx */
	bts->oml_link = oml_link;
	bts->osmo_link = osmo_link;
	bts->c0->rsl_link_primary = rsl_link;

	/* default port at BTS for incoming connections is 3006 */
	if (sin->sin_port == 0)
		sin->sin_port = htons(3006);

	return ipaccess_connect(line, sin);
}

/*
 * Callback function for NACK on the OML NM
 *
 * Currently we send the config requests but don't check the
 * result. The nanoBTS will send us a NACK when we did something the
 * BTS didn't like.
 */
static int ipacc_msg_nack(uint8_t mt)
{
	fprintf(stderr, "Failure to set attribute. This seems fatal\n");
	exit(-1);
	return 0;
}

static void check_restart_or_exit(struct gsm_bts_trx *trx)
{
	if (restart) {
		abis_nm_ipaccess_restart(trx);
	} else {
		exit(0);
	}
}

static int ipacc_msg_ack(uint8_t mt, struct gsm_bts_trx *trx)
{
	if (mt != NM_MT_IPACC_SET_NVATTR_ACK && mt != NM_MT_IPACC_SET_ATTR_ACK)
		return 0;

	if (sw_load_state == 1) {
		fprintf(stderr, "The new software is activated.\n");
		check_restart_or_exit(trx);
	} else if (oml_state == 1) {
		fprintf(stderr, "Set the NV Attributes.\n");
		check_restart_or_exit(trx);
	}

	return 0;
}

static const uint8_t phys_conf_min[] = { 0x02 };

static uint16_t build_physconf_arfcn_by_rxlev(uint8_t *physconf_buf, const struct rxlev_stats *st)
{
	uint16_t *whitelist = (uint16_t *) (physconf_buf + 4);
	int num_arfcn;
	unsigned int arfcnlist_size;

	/* Create whitelist from rxlevels */
	physconf_buf[0] = phys_conf_min[0];
	physconf_buf[1] = NM_IPAC_EIE_ARFCN_WHITE;
	num_arfcn = ipac_rxlevstat2whitelist(whitelist, st, 0, 100);
	arfcnlist_size = num_arfcn * 2;
	*((uint16_t *) (physconf_buf+2)) = htons(arfcnlist_size);
	DEBUGP(DNM, "physconf_buf (%s)\n", osmo_hexdump(physconf_buf, arfcnlist_size+4));
	return arfcnlist_size+4;
}

static int nwl_sig_cb(unsigned int subsys, unsigned int signal,
		      void *handler_data, void *signal_data)
{
	struct gsm_bts_trx *trx;
	uint8_t physconf_buf[2*NUM_ARFCNS+16];
	uint16_t physconf_len;

	switch (signal) {
	case S_IPAC_NWL_COMPLETE:
		trx = signal_data;
		DEBUGP(DNM, "received S_IPAC_NWL_COMPLETE signal\n");
		switch (trx->ipaccess.test_nr) {
		case NM_IPACC_TESTNO_CHAN_USAGE:
			/* Dump RxLev results */
			//rxlev_stat_dump(&trx->ipaccess.rxlev_stat);
			/* Create whitelist from results */
			physconf_len = build_physconf_arfcn_by_rxlev(physconf_buf,
						      &trx->ipaccess.rxlev_stat);
			/* Start next test about BCCH channel usage */
			ipac_nwl_test_start(trx, NM_IPACC_TESTNO_BCCH_CHAN_USAGE,
					    physconf_buf, physconf_len);
			break;
		case NM_IPACC_TESTNO_BCCH_CHAN_USAGE:
			/* Dump BCCH RxLev results */
			//rxlev_stat_dump(&trx->ipaccess.rxlev_stat);
			/* Create whitelist from results */
			physconf_len = build_physconf_arfcn_by_rxlev(physconf_buf,
						      &trx->ipaccess.rxlev_stat);
			/* Start next test about BCCH info */
			ipac_nwl_test_start(trx, NM_IPACC_TESTNO_BCCH_INFO,
					    physconf_buf, physconf_len);
			break;
		case NM_IPACC_TESTNO_BCCH_INFO:
			/* re-start full process with CHAN_USAGE */
			if (loop_tests) {
				DEBUGP(DNM, "starting next test cycle\n");
				ipac_nwl_test_start(trx, net_listen_testnr, phys_conf_min,
						    sizeof(phys_conf_min));
			} else {
				exit(0);
			}
			break;
		}
		break;
	}
	return 0;
}

static const struct value_string ipa_nvflag_strs[];

static int print_attr_rep(struct msgb *mb)
{
	/* Parse using nanoBTS own formatting for Get Attribute Response */
	struct abis_om_hdr *oh = msgb_l2(mb);
	struct abis_om_fom_hdr *foh = msgb_l3(mb);
	struct e1inp_sign_link *sign_link = mb->dst;
	struct gsm_bts_trx *trx = sign_link->trx;
	struct gsm_bts *bts = trx->bts;
	struct tlv_parsed tp;
	struct in_addr ia = {0};
	char oml_ip[20] = {0};
	uint16_t oml_port = 0;
	char unit_id[40]  = {0};
	unsigned int indent = 0;


	if (abis_nm_tlv_parse(&tp, bts, foh->data, oh->length-sizeof(*foh)) < 0) {
		LOGPFOH(DNM, LOGL_ERROR, foh, "%s(): tlv_parse failed\n", __func__);
		return -EINVAL;
	}

	abis_nm_tlv_attr_primary_oml(&tp, &ia, &oml_port);
	osmo_strlcpy(oml_ip, inet_ntoa(ia), sizeof(oml_ip));

	abis_nm_tlv_attr_unit_id(&tp, unit_id,  sizeof(unit_id));

#define ENDL(last) \
	fprintf(stdout, "%s\n", last ? "" : ",")
#define print_offset(fmt, args...) \
	fprintf(stdout, "%*s" fmt, indent * 4, "", ## args)
#define print_field(field, fmt, args...) \
	print_offset("\"%s\": \"" fmt "\"", field, ## args)

	print_offset("{\n");
	indent++;

	print_field("primary_oml_ip", "%s", oml_ip); ENDL(false);
	print_field("primary_oml_port", "%u", oml_port); ENDL(false);
	print_field("unit_id", "%s", unit_id); ENDL(false);

	uint16_t Fx = (TLVP_VAL(&tp, NM_ATT_IPACC_NV_FLAGS)[2] << 8)
		    | (TLVP_VAL(&tp, NM_ATT_IPACC_NV_FLAGS)[0] << 0);
	uint16_t Mx = (TLVP_VAL(&tp, NM_ATT_IPACC_NV_FLAGS)[3] << 8)
		    | (TLVP_VAL(&tp, NM_ATT_IPACC_NV_FLAGS)[1] << 0);
	const struct value_string *nvflag = ipa_nvflag_strs;

	print_offset("\"nv_flags\": {\n");
	indent++;

	while (nvflag->value && nvflag->str) {
		const char *val = (Fx & nvflag->value) ? "yes" : "no";
		if (~Mx & nvflag->value)
			val = "unknown";
		print_field(nvflag->str, "%s", val);

		nvflag++;

		if (nvflag->value && nvflag->str)
			ENDL(false); /* more fields to print */
		else
			ENDL(true); /* this was the last field */
	}

	indent--;
	print_offset("}\n");

	indent--;
	print_offset("}\n");

	return 0;
}

static int nm_state_event(int evt, uint8_t obj_class, void *obj,
			  const struct gsm_nm_state *old_state, const struct gsm_nm_state *new_state,
			  struct abis_om_obj_inst *obj_inst);

static int nm_sig_cb(unsigned int subsys, unsigned int signal,
		     void *handler_data, void *signal_data)
{
	struct ipacc_ack_signal_data *ipacc_data;
	struct nm_statechg_signal_data *nsd;
	struct msgb *oml_msg;
	struct gsm_bts_trx *trx;

	switch (signal) {
	case S_NM_IPACC_NACK:
		ipacc_data = signal_data;
		return ipacc_msg_nack(ipacc_data->foh->msg_type);
	case S_NM_IPACC_ACK:
		ipacc_data = signal_data;
		switch (ipacc_data->foh->obj_class) {
		case NM_OC_BASEB_TRANSC:
		case NM_OC_RADIO_CARRIER:
			trx = gsm_bts_trx_num(ipacc_data->bts,
					      ipacc_data->foh->obj_inst.trx_nr);
			return ipacc_msg_ack(ipacc_data->foh->msg_type, trx);
		default:
			return 0;
		}
	case S_NM_IPACC_RESTART_ACK:
		if (!quiet)
			printf("The BTS has acked the restart. Exiting.\n");
		exit(0);
		break;
	case S_NM_IPACC_RESTART_NACK:
		if (!quiet)
			printf("The BTS has nacked the restart. Exiting.\n");
		exit(0);
		break;
	case S_NM_STATECHG:
		nsd = signal_data;
		nm_state_event(signal, nsd->obj_class, nsd->obj, &nsd->old_state,
				&nsd->new_state, nsd->obj_inst);
		break;
	case S_NM_GET_ATTR_REP:
		fprintf(stderr, "Received SIGNAL S_NM_GET_ATTR_REP\n");
		oml_msg = signal_data;
		print_attr_rep(oml_msg);
		exit(0);
	default:
		break;
	}

	return 0;
}

/* Callback function to be called every time we receive a signal from INPUT */
static int inp_sig_cb(unsigned int subsys, unsigned int signal,
		      void *handler_data, void *signal_data)
{
	struct input_signal_data *isd = signal_data;

	if (subsys != SS_L_INPUT)
		return -EINVAL;

	fprintf(stderr, "%s(): Input signal '%s' received\n", __func__,
		get_value_string(e1inp_signal_names, signal));

	switch (signal) {
	case S_L_INP_TEI_UP:
		break;
	case S_L_INP_TEI_DN:
		fprintf(stderr, "Lost E1 %s link\n", e1inp_signtype_name(isd->link_type));
		exit(1);
		break;
	default:
		break;
	}

	return 0;
}

/* callback function passed to the ABIS OML code */
static int percent;
static int percent_old;
static int swload_cbfn(unsigned int hook, unsigned int event, struct msgb *_msg,
		       void *data, void *param)
{
	struct msgb *msg;
	struct gsm_bts_trx *trx;

	if (hook != GSM_HOOK_NM_SWLOAD)
		return 0;

	trx = (struct gsm_bts_trx *) data;

	switch (event) {
	case NM_MT_LOAD_INIT_ACK:
		if (!quiet)
			fprintf(stdout, "Software Load Initiate ACK\n");
		break;
	case NM_MT_LOAD_INIT_NACK:
		fprintf(stderr, "ERROR: Software Load Initiate NACK\n");
		exit(5);
		break;
	case NM_MT_LOAD_END_ACK:
		fprintf(stderr, "LOAD END ACK...");
		/* now make it the default */
		sw_load_state = 1;

		msg = msgb_alloc(1024, "sw: nvattr");
		msg->l2h = msgb_put(msg, 3);
		msg->l3h = &msg->l2h[3];

		/* activate software */
		if (sw_load1)
			abis_nm_put_sw_desc(msg, sw_load1, true);

		if (sw_load2)
			abis_nm_put_sw_desc(msg, sw_load2, true);

		/* fill in the data */
		msg->l2h[0] = NM_ATT_IPACC_CUR_SW_CFG;
		msg->l2h[1] = msgb_l3len(msg) >> 8;
		msg->l2h[2] = msgb_l3len(msg) & 0xff;
		if (!quiet)
			printf("Foo l2h: %p l3h: %p... length l2: %u  l3: %u\n",
			       msg->l2h, msg->l3h, msgb_l2len(msg), msgb_l3len(msg));
		abis_nm_ipaccess_set_nvattr(trx, msg->l2h, msgb_l2len(msg));
		msgb_free(msg);
		break;
	case NM_MT_LOAD_END_NACK:
		fprintf(stderr, "ERROR: Software Load End NACK\n");
		exit(3);
		break;
	case NM_MT_ACTIVATE_SW_NACK:
		fprintf(stderr, "ERROR: Activate Software NACK\n");
		exit(4);
		break;
	case NM_MT_ACTIVATE_SW_ACK:
		break;
	case NM_MT_LOAD_SEG_ACK:
		percent = abis_nm_software_load_status(trx->bts);
		if (!quiet && percent > percent_old)
			printf("Software Download Progress: %d%%\n", percent);
		percent_old = percent;
		break;
	case NM_MT_LOAD_ABORT:
		fprintf(stderr, "ERROR: Load aborted by the BTS.\n");
		exit(6);
		break;
	}
	return 0;
}

static void nv_put_ip_if_cfg(struct msgb *nmsg, uint32_t ip, uint32_t mask)
{
	msgb_put_u8(nmsg, NM_ATT_IPACC_IP_IF_CFG);

	msgb_put_u32(nmsg, ip);
	msgb_put_u32(nmsg, mask);
}

static void nv_put_gw_cfg(struct msgb *nmsg, uint32_t addr, uint32_t mask, uint32_t gw)
{
	msgb_put_u8(nmsg, NM_ATT_IPACC_IP_GW_CFG);
	msgb_put_u32(nmsg, addr);
	msgb_put_u32(nmsg, mask);
	msgb_put_u32(nmsg, gw);
}

static void nv_put_unit_id(struct msgb *nmsg, const char *unit_id)
{
	msgb_tl16v_put(nmsg, NM_ATT_IPACC_UNIT_ID, strlen(unit_id)+1,
			(const uint8_t *)unit_id);
}

static void nv_put_prim_oml(struct msgb *nmsg, uint32_t ip, uint16_t port)
{
	int len;

	/* 0x88 + IP + port */
	len = 1 + sizeof(ip) + sizeof(port);

	msgb_put_u8(nmsg, NM_ATT_IPACC_PRIM_OML_CFG_LIST);
	msgb_put_u16(nmsg, len);

	msgb_put_u8(nmsg, NM_ATT_IPACC_PRIM_OML_CFG);

	/* IP address */
	msgb_put_u32(nmsg, ip);

	/* port number */
	msgb_put_u16(nmsg, port);
}

static void nv_put_flags(struct msgb *nmsg, uint16_t nv_flags, uint16_t nv_mask)
{
	msgb_put_u8(nmsg, NM_ATT_IPACC_NV_FLAGS);
	msgb_put_u16(nmsg, sizeof(nv_flags) + sizeof(nv_mask));
	msgb_put_u8(nmsg, nv_flags & 0xff);
	msgb_put_u8(nmsg, nv_mask & 0xff);
	msgb_put_u8(nmsg, nv_flags >> 8);
	msgb_put_u8(nmsg, nv_mask >> 8);
}

/* human-readable test names for the ip.access tests */
static const struct value_string ipa_test_strs[] = {
	{ 64, "ccch-usage" },
	{ 65, "bcch-usage" },
	{ 66, "freq-sync" },
	{ 67, "rtp-usage" },
	{ 68, "rtp-perf" },
	{ 69, "gprs-ccch" },
	{ 70, "pccch-usage" },
	{ 71, "gprs-usage" },
	{ 72, "esta-mf" },
	{ 73, "uplink-mf" },
	{ 74, "dolink-mf" },
	{ 75, "tbf-details" },
	{ 76, "tbf-usage" },
	{ 77, "llc-data" },
	{ 78, "pdch-usage" },
	{ 79, "power-control" },
	{ 80, "link-adaption" },
	{ 81, "tch-usage" },
	{ 82, "amr-mf" },
	{ 83, "rtp-multiplex-perf" },
	{ 84, "rtp-multiplex-usage" },
	{ 85, "srtp-multiplex-usage" },
	{ 86, "abis-traffic" },
	{ 89, "gprs-multiplex-perf" },
	{ 90, "gprs-multiplex-usage" },
	{ 0, NULL },
};

/* human-readable names for the ip.access nanoBTS NVRAM Flags */
static const struct value_string ipa_nvflag_strs[] = {
	{ 0x0001, "static-ip" },
	{ 0x0002, "static-gw" },
	{ 0x0004, "no-dhcp-vsi" },
	{ 0x0008, "dhcp-enabled" },
	{ 0x0040, "led-enabled" },
	{ 0x0100, "secondary-oml-enabled" },
	{ 0x0200, "diag-enabled" },
	{ 0x0400, "cli-enabled" },
	{ 0x0800, "http-enabled" },
	{ 0x1000, "post-enabled" },
	{ 0x2000, "snmp-enabled" },
	{ 0, NULL }
};

/* set the flags in flags/mask according to a string-identified flag and 'enable' */
static int ipa_nvflag_set(uint16_t *flags, uint16_t *mask, const char *name, int en)
{
	int rc;
	rc = get_string_value(ipa_nvflag_strs, name);
	if (rc < 0) {
		fprintf(stderr, "Unknown attribute '%s'\n", name);
		return rc;
	}

	*mask |= rc;
	if (en)
		*flags |= rc;
	else
		*flags &= ~rc;

	return 0;
}

static void bootstrap_om(struct gsm_bts_trx *trx)
{
	struct msgb *nmsg_get = msgb_alloc(1024, "nested get msgb");
	struct msgb *nmsg_set = msgb_alloc(1024, "nested set msgb");
	int need_to_set_attr = 0;
	int len;

	if (!quiet)
		printf("OML link established using TRX %d\n", trx->nr);

	if (get_attr) {
		msgb_put_u8(nmsg_get, NM_ATT_IPACC_PRIM_OML_CFG);
		msgb_put_u8(nmsg_get, NM_ATT_IPACC_UNIT_ID);
		msgb_put_u8(nmsg_get, NM_ATT_IPACC_NV_FLAGS);
	}
	if (unit_id) {
		len = strlen(unit_id);
		if (len > nmsg_set->data_len-10)
			goto out_err;
		if (!quiet)
			printf("setting Unit ID to '%s'\n", unit_id);
		nv_put_unit_id(nmsg_set, unit_id);
		need_to_set_attr = 1;
	}
	if (prim_oml_ip) {
		struct in_addr ia;

		if (!inet_aton(prim_oml_ip, &ia)) {
			fprintf(stderr, "invalid IP address: %s\n",
				prim_oml_ip);
			goto out_err;
		}

		if (!quiet)
			printf("setting primary OML link IP to '%s'\n", inet_ntoa(ia));
		nv_put_prim_oml(nmsg_set, ntohl(ia.s_addr), 0);
		need_to_set_attr = 1;
	}
	if (nv_mask) {
		if (!quiet)
			printf("setting NV Flags/Mask to 0x%04x/0x%04x\n",
			       nv_flags, nv_mask);
		nv_put_flags(nmsg_set, nv_flags, nv_mask);
		need_to_set_attr = 1;
	}
	if (bts_ip_addr && bts_ip_mask) {
		struct in_addr ia_addr, ia_mask;

		if (!inet_aton(bts_ip_addr, &ia_addr)) {
			fprintf(stderr, "invalid IP address: %s\n",
				bts_ip_addr);
			goto out_err;
		}

		if (!inet_aton(bts_ip_mask, &ia_mask)) {
			fprintf(stderr, "invalid IP address: %s\n",
				bts_ip_mask);
			goto out_err;
		}

		if (!quiet)
			printf("setting static IP Address/Mask\n");
		nv_put_ip_if_cfg(nmsg_set, ntohl(ia_addr.s_addr), ntohl(ia_mask.s_addr));
		need_to_set_attr = 1;
	}
	if (bts_ip_gw) {
		struct in_addr ia_gw;

		if (!inet_aton(bts_ip_gw, &ia_gw)) {
			fprintf(stderr, "invalid IP address: %s\n",
				bts_ip_gw);
			goto out_err;
		}

		if (!quiet)
			printf("setting static IP Gateway\n");
		/* we only set the default gateway with zero addr/mask */
		nv_put_gw_cfg(nmsg_set, 0, 0, ntohl(ia_gw.s_addr));
		need_to_set_attr = 1;
	}

	if (get_attr) {
		fprintf(stderr, "getting Attributes (%d): %s\n", nmsg_get->len, osmo_hexdump(msgb_data(nmsg_get), msgb_length(nmsg_get)));
		abis_nm_get_attr(trx->bts, NM_OC_BASEB_TRANSC, 0, trx->nr, 0xff, nmsg_get->head, nmsg_get->len);
		oml_state = 1;
	}

	if (need_to_set_attr) {
		abis_nm_ipaccess_set_nvattr(trx, nmsg_set->head, nmsg_set->len);
		oml_state = 1;
	}

	if (restart && !prim_oml_ip && !software) {
		if (!quiet)
			printf("restarting BTS\n");
		abis_nm_ipaccess_restart(trx);
	}

out_err:
	msgb_free(nmsg_get);
	msgb_free(nmsg_set);
}

static int nm_state_event(int evt, uint8_t obj_class, void *obj,
			  const struct gsm_nm_state *old_state, const struct gsm_nm_state *new_state,
			  struct abis_om_obj_inst *obj_inst)
{
	if (obj_class == NM_OC_BASEB_TRANSC) {
		if (!found_trx && obj_inst->trx_nr != 0xff) {
			struct gsm_bts_trx *trx = container_of(obj, struct gsm_bts_trx, bb_transc);
			bootstrap_om(trx);
			found_trx = 1;
		}
	} else if (evt == S_NM_STATECHG &&
	    obj_class == NM_OC_RADIO_CARRIER &&
	    new_state->availability == NM_AVSTATE_OFF_LINE) {
		struct gsm_bts_trx *trx = obj;

		if (net_listen_testnr)
			ipac_nwl_test_start(trx, net_listen_testnr,
					    phys_conf_min, sizeof(phys_conf_min));
		else if (software) {
			int rc;
			if (!quiet)
				printf("Attempting software upload with '%s'\n", software);
			rc = abis_nm_software_load(trx->bts, trx->nr, software, 19, 0, swload_cbfn, trx);
			if (rc < 0) {
				fprintf(stderr, "Failed to start software load\n");
				exit(-3);
			}
		}
	}
	return 0;
}

static struct abis_nm_sw_desc *create_swload(struct sdp_header *header)
{
	struct abis_nm_sw_desc *load;

	load = talloc_zero(tall_ctx_config, struct abis_nm_sw_desc);

	osmo_strlcpy((char *)load->file_id, header->firmware_info.sw_part,
		     sizeof(load->file_id));
	load->file_id_len = strlen((char*)load->file_id) + 1;

	osmo_strlcpy((char *)load->file_version, header->firmware_info.version,
		     sizeof(load->file_version));
	load->file_version_len = strlen((char*)load->file_version) + 1;

	return load;
}

static int find_sw_load_params(const char *filename)
{
	struct stat stat;
	struct sdp_header *header;
	struct llist_head *entry;
	int fd;
	void *tall_firm_ctx = 0;

	entry = talloc_zero(tall_firm_ctx, struct llist_head);
	INIT_LLIST_HEAD(entry);

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		perror("nada");
		return -1;
	}

	/* verify the file */
	if (fstat(fd, &stat) == -1) {
		perror("Can not stat the file");
		close(fd);
		return -1;
	}

	ipaccess_analyze_file(fd, stat.st_size, 0, entry);
	if (close(fd) != 0) {
		perror("Close failed.\n");
		return -1;
	}

	/* try to find what we are looking for */
	llist_for_each_entry(header, entry, entry) {
		if (ntohs(header->firmware_info.more_more_magic) == 0x1000) {
			sw_load1 = create_swload(header);
		} else if (ntohs(header->firmware_info.more_more_magic) == 0x2001) {
			sw_load2 = create_swload(header);
		}
	}

	if (!sw_load1 || !sw_load2) {
		fprintf(stderr, "Did not find data.\n");
		talloc_free(tall_firm_ctx);
		return -1;
        }

	talloc_free(tall_firm_ctx);
	return 0;
}

static void dump_entry(struct sdp_header_item *sub_entry, int part, int fd)
{
	int out_fd;
	int copied;
	char filename[4096];
	off_t target;

	if (!dump_files)
		return;

	if (sub_entry->header_entry.something1 == 0)
		return;

	snprintf(filename, sizeof(filename), "part.%d", part++);
	out_fd = open(filename, O_WRONLY | O_CREAT, 0660);
	if (out_fd < 0) {
		perror("Can not dump firmware");
		return;
	}

	target = sub_entry->absolute_offset + ntohl(sub_entry->header_entry.start) + 4;
	if (lseek(fd, target, SEEK_SET) != target) {
		perror("seek failed");
		close(out_fd);
		return;
	}

	for (copied = 0; copied < ntohl(sub_entry->header_entry.length); ++copied) {
		char c;
		if (read(fd, &c, sizeof(c)) != sizeof(c)) {
			perror("copy failed");
			break;
		}

		if (write(out_fd, &c, sizeof(c)) != sizeof(c)) {
			perror("write failed");
			break;
		}
	}

	close(out_fd);
}

static void analyze_firmware(const char *filename)
{
	struct stat stat;
	struct sdp_header *header;
	struct sdp_header_item *sub_entry;
	struct llist_head *entry;
	int fd;
	void *tall_firm_ctx = 0;
	int part = 0;

	entry = talloc_zero(tall_firm_ctx, struct llist_head);
	INIT_LLIST_HEAD(entry);

	if (!quiet)
		printf("Opening possible firmware '%s'\n", filename);
	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		perror("nada");
		return;
	}

	/* verify the file */
	if (fstat(fd, &stat) == -1) {
		perror("Can not stat the file");
		close(fd);
		return;
	}

	ipaccess_analyze_file(fd, stat.st_size, 0, entry);

	llist_for_each_entry(header, entry, entry) {
		printf("Printing header information:\n");
		printf("more_more_magic: 0x%x\n", ntohs(header->firmware_info.more_more_magic));
		printf("header_length: %u\n", ntohl(header->firmware_info.header_length));
		printf("file_length: %u\n", ntohl(header->firmware_info.file_length));
		printf("sw_part: %.20s\n", header->firmware_info.sw_part);
		printf("text1: %.64s\n", header->firmware_info.text1);
		printf("time: %.12s\n", header->firmware_info.time);
		printf("date: %.14s\n", header->firmware_info.date);
		printf("text2: %.10s\n", header->firmware_info.text2);
		printf("version: %.20s\n", header->firmware_info.version);
		printf("subitems...\n");

		llist_for_each_entry(sub_entry, &header->header_list, entry) {
			printf("\tsomething1: %u\n", sub_entry->header_entry.something1);
			printf("\ttext1: %.64s\n", sub_entry->header_entry.text1);
			printf("\ttime: %.12s\n", sub_entry->header_entry.time);
			printf("\tdate: %.14s\n", sub_entry->header_entry.date);
			printf("\ttext2: %.10s\n", sub_entry->header_entry.text2);
			printf("\tversion: %.20s\n", sub_entry->header_entry.version);
			printf("\tlength: %u\n", ntohl(sub_entry->header_entry.length));
			printf("\taddr1: 0x%x\n", ntohl(sub_entry->header_entry.addr1));
			printf("\taddr2: 0x%x\n", ntohl(sub_entry->header_entry.addr2));
			printf("\tstart: 0x%x\n", ntohl(sub_entry->header_entry.start));
			printf("\tabs. offset: 0x%lx\n", sub_entry->absolute_offset);
			printf("\n\n");

			dump_entry(sub_entry, part++, fd);
		}
		printf("\n\n");
	}

	if (close(fd) != 0) {
		perror("Close failed.\n");
		return;
	}

	talloc_free(tall_firm_ctx);
}

static bool check_unitid_fmt(const char* unit_id)
{
	regex_t regexp;
	int rc;

	if (strlen(unit_id) < 5)
		goto wrong_fmt;

	rc = regcomp(&regexp, "^[0-9]+/[0-9]+/[0-9]+$", REG_EXTENDED | REG_NOSUB);
	OSMO_ASSERT(!rc);

	rc = regexec(&regexp, unit_id, 0, NULL, 0);
	regfree(&regexp);

	if (rc == 0)
		return true;

wrong_fmt:
	fprintf(stderr, "ERROR: unit-id wrong format. Must be '\\d+/\\d+/\\d+'\n");
	return false;
}

static void print_usage(void)
{
	printf("Usage: ipaccess-config IP_OF_BTS\n");
}

static void print_help(void)
{
#if 0
	printf("Commands for reading from the BTS:\n");
	printf("  -D --dump\t\t\tDump the BTS configuration\n");
	printf("\n");
#endif
	printf("Commands for writing to the BTS:\n");
	printf("  -u --unit-id UNIT_ID\t\tSet the Unit ID of the BTS\n");
	printf("  -o --oml-ip IP\t\tSet primary OML IP (IP of your BSC)\n");
	printf("  -G --get-attr\t\t\tGet several attributes from BTS\n");
	printf("  -i --ip-address IP/MASK\tSet static IP address + netmask of BTS\n");
	printf("  -g --ip-gateway IP\t\tSet static IP gateway of BTS\n");
	printf("  -r --restart\t\t\tRestart the BTS (after other operations)\n");
	printf("  -n --nvram-flags FLAGS/MASK\tSet NVRAM attributes\n");
	printf("  -S --nvattr-set FLAG\t\tSet one additional NVRAM attribute\n");
	printf("  -U --nvattr-unset FLAG\tSet one additional NVRAM attribute\n");
	printf("  -l --listen TESTNR\t\tPerform specified test number\n");
	printf("  -L --Listen TEST_NAME\t\tPerform specified test\n");
	printf("  -s --stream-id ID\t\tSet the IPA Stream Identifier for OML\n");
	printf("  -d --software FIRMWARE\tDownload firmware into BTS\n");
	printf("\n");
	printf("Miscellaneous commands:\n");
	printf("  -h --help\t\t\tthis text\n");
	printf("  -H --HELP\t\t\tPrint parameter details.\n");
	printf("  -f --firmware FIRMWARE\tProvide firmware information\n");
	printf("  -w --write-firmware\t\tThis will dump the firmware parts to the filesystem. Use with -f.\n");
	printf("  -p --loop\t\t\tLoop the tests executed with the --listen command.\n");
	printf("  -q --quiet\t\t\tAvoid printing unformatted logging to stdout, useful with -G.\n");
}

static void print_value_string(const struct value_string *val, int size)
{
	int i;

	for (i = 0; i < size - 1; ++i) {
		char sep = val[i + 1].str == NULL ? '.' : ',';
		printf("%s%c ", val[i].str, sep);
	}
	printf("\n");
}

static void print_options(void)
{

	printf("Options for NVRAM (-S,-U):\n  ");
	print_value_string(&ipa_nvflag_strs[0], ARRAY_SIZE(ipa_nvflag_strs));

	printf("Options for Tests (-L):\n ");
	print_value_string(&ipa_test_strs[0], ARRAY_SIZE(ipa_test_strs));
}

static const struct log_info_cat log_categories[] = {
	[DNM] = {
		.name = "DNM",
		.description = "A-bis Network Management / O&M (NM/OML)",
		.color = "\033[1;36m",
		.loglevel = LOGL_NOTICE,
		.enabled = 1,
	},
};

static const struct log_info log_info = {
	.cat = log_categories,
	.num_cat = ARRAY_SIZE(log_categories),
};

int main(int argc, char **argv)
{
	struct gsm_bts *bts;
	struct sockaddr_in sin;
	char *bts_ip;
	int rc, option_index = 0, stream_id = 0xff;

	tall_ctx_config = talloc_named_const(NULL, 0, "ipaccess-config");
	tall_bsc_ctx = tall_ctx_config;
	msgb_talloc_ctx_init(tall_ctx_config, 0);

	osmo_init_logging2(tall_ctx_config, &log_info);
	bts_model_nanobts_init();

	while (1) {
		int c;
		unsigned long ul;
		char *slash;
		static struct option long_options[] = {
			{ "get-attr", 0, 0, 'G' },
			{ "unit-id", 1, 0, 'u' },
			{ "oml-ip", 1, 0, 'o' },
			{ "ip-address", 1, 0, 'i' },
			{ "ip-gateway", 1, 0, 'g' },
			{ "restart", 0, 0, 'r' },
			{ "nvram-flags", 1, 0, 'n' },
			{ "nvattr-set", 1, 0, 'S' },
			{ "nvattr-unset", 1, 0, 'U' },
			{ "help", 0, 0, 'h' },
			{ "HELP", 0, 0, 'H' },
			{ "listen", 1, 0, 'l' },
			{ "Listen", 1, 0, 'L' },
			{ "stream-id", 1, 0, 's' },
			{ "software", 1, 0, 'd' },
			{ "firmware", 1, 0, 'f' },
			{ "write-firmware", 0, 0, 'w' },
			{ "disable-color", 0, 0, 'c'},
			{ "loop", 0, 0, 'p' },
			{ "quiet", 0, 0, 'q' },
			{ 0, 0, 0, 0 },
		};

		c = getopt_long(argc, argv, "Gu:o:i:g:rn:S:U:l:L:hs:d:f:wcpqH", long_options,
				&option_index);

		if (c == -1)
			break;

		switch (c) {
		case 'G':
			get_attr = true;
			break;
		case 'u':
			if (!check_unitid_fmt(optarg))
				exit(2);
			unit_id = optarg;
			break;
		case 'o':
			prim_oml_ip = optarg;
			break;
		case 'i':
			slash = strchr(optarg, '/');
			if (!slash)
				exit(2);
			bts_ip_addr = optarg;
			*slash = 0;
			bts_ip_mask = slash+1;
			break;
		case 'g':
			bts_ip_gw = optarg;
			break;
		case 'r':
			restart = 1;
			break;
		case 'n':
			slash = strchr(optarg, '/');
			if (!slash)
				exit(2);
			ul = strtoul(optarg, NULL, 16);
			nv_flags = ul & 0xffff;
			ul = strtoul(slash+1, NULL, 16);
			nv_mask = ul & 0xffff;
			break;
		case 'S':
			if (ipa_nvflag_set(&nv_flags, &nv_mask, optarg, 1) < 0)
				exit(2);
			break;
		case 'U':
			if (ipa_nvflag_set(&nv_flags, &nv_mask, optarg, 0) < 0)
				exit(2);
			break;
		case 'l':
			net_listen_testnr = atoi(optarg);
			break;
		case 'L':
			net_listen_testnr = get_string_value(ipa_test_strs,
							     optarg);
			if (net_listen_testnr < 0) {
				fprintf(stderr,
					"The test '%s' is not known. Use -H to"
					" see available tests.\n", optarg);
				exit(2);
			}
			break;
		case 's':
			stream_id = atoi(optarg);
			break;
		case 'd':
			software = strdup(optarg);
			if (find_sw_load_params(optarg) != 0)
				exit(0);
			break;
		case 'f':
			firmware_analysis = optarg;
			break;
		case 'w':
			dump_files = 1;
			break;
		case 'c':
			log_set_use_color(osmo_stderr_target, 0);
			break;
		case 'p':
			loop_tests = 1;
			break;
		case 'q':
			quiet = true;
			break;
		case 'h':
			print_usage();
			print_help();
			exit(0);
		case 'H':
			print_options();
			exit(0);
		}
	};

	if (!quiet) {
		printf("ipaccess-config (C) 2009-2010 by Harald Welte and others\n");
		printf("This is FREE SOFTWARE with ABSOLUTELY NO WARRANTY\n\n");
	}

	if (firmware_analysis) {
		analyze_firmware(firmware_analysis);
		if (argc == optind) /* Nothing more to do, exit successfully */
			exit(EXIT_SUCCESS);
	}
	if (argc - optind != 1) {
		fprintf(stderr, "you have to specify the IP address of the BTS. Use --help for more information\n");
		exit(2);
	}
	bts_ip = argv[optind++];

	libosmo_abis_init(tall_ctx_config);

	bsc_gsmnet = gsm_network_init(tall_ctx_config);
	if (!bsc_gsmnet)
		exit(1);

	bts = gsm_bts_alloc_register(bsc_gsmnet, GSM_BTS_TYPE_NANOBTS,
				     HARDCODED_BSIC);
	/* ip.access supports up to 4 chained TRX */
	gsm_bts_trx_alloc(bts);
	gsm_bts_trx_alloc(bts);
	gsm_bts_trx_alloc(bts);
	bts->oml_tei = stream_id;

	osmo_signal_register_handler(SS_NM, nm_sig_cb, NULL);
	osmo_signal_register_handler(SS_L_INPUT, inp_sig_cb, NULL);
	osmo_signal_register_handler(SS_IPAC_NWL, nwl_sig_cb, NULL);

	ipac_nwl_init();

	if (!quiet)
		printf("Trying to connect to ip.access BTS %s...\n", bts_ip);

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	inet_aton(bts_ip, &sin.sin_addr);
	rc = ia_config_connect(bts, &sin);
	if (rc < 0) {
		perror("Error connecting to the BTS");
		exit(1);
	}

	bts->oml_link->ts->sign.delay = 10;
	bts->c0->rsl_link_primary->ts->sign.delay = 10;
	while (1) {
		rc = osmo_select_main(0);
		if (rc < 0)
			exit(3);
	}

	exit(0);
}
