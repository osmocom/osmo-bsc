/* ip.access nanoBTS specific code */

/* (C) 2009-2018 by Harald Welte <laforge@gnumonks.org>
 * (C) 2020 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 *
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

#include <arpa/inet.h>
#include <time.h>

#include <osmocom/gsm/tlv.h>

#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/signal.h>
#include <osmocom/bsc/abis_nm.h>
#include <osmocom/abis/e1_input.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/stat_item.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/abis_nm.h>
#include <osmocom/bsc/abis_rsl.h>
#include <osmocom/bsc/abis_osmo.h>
#include <osmocom/bsc/debug.h>
#include <osmocom/abis/subchan_demux.h>
#include <osmocom/gsm/ipa.h>
#include <osmocom/abis/ipaccess.h>
#include <osmocom/core/logging.h>
#include <osmocom/bsc/ipaccess.h>
#include <osmocom/bsc/bts_ipaccess_nanobts_omlattr.h>
#include <osmocom/bsc/paging.h>
#include <osmocom/bsc/timeslot_fsm.h>
#include <osmocom/bsc/bts.h>
#include <osmocom/bsc/bts_sm.h>
#include <osmocom/bsc/nm_common_fsm.h>
#include <osmocom/bsc/bsc_stats.h>

static int bts_model_nanobts_start(struct gsm_network *net);
static void bts_model_nanobts_e1line_bind_ops(struct e1inp_line *line);

static int power_ctrl_send_def_params(const struct gsm_bts_trx *trx);
static int power_ctrl_enc_rsl_params(struct msgb *msg, const struct gsm_power_ctrl_params *cp);

static char *get_oml_status(const struct gsm_bts *bts)
{
	if (bts->oml_link)
		return all_trx_rsl_connected_unlocked(bts) ? "connected" : "degraded";

	return "disconnected";
}

struct gsm_bts_model bts_model_nanobts = {
	.type = GSM_BTS_TYPE_NANOBTS,
	.name = "nanobts",
	.start = bts_model_nanobts_start,
	.oml_rcvmsg = &abis_nm_rcvmsg,
	.oml_status = &get_oml_status,
	.e1line_bind_ops = bts_model_nanobts_e1line_bind_ops,

	/* MS/BS Power control specific API */
	.power_ctrl_send_def_params = &power_ctrl_send_def_params,
	.power_ctrl_enc_rsl_params = &power_ctrl_enc_rsl_params,

	/* Some nanoBTS firmwares (if not all) don't support SI2ter and cause
	 * problems on some MS if it is enabled, see OS#3063. Disable it by
	 * default, can still be enabled through VTY cmd with same name.
	 */
	.force_combined_si = true,
	.nm_att_tlvdef = {
		.def = {
			/* ip.access specifics */
			[NM_ATT_IPACC_DST_IP] =		{ TLV_TYPE_FIXED, 4 },
			[NM_ATT_IPACC_DST_IP_PORT] =	{ TLV_TYPE_FIXED, 2 },
			[NM_ATT_IPACC_STREAM_ID] =	{ TLV_TYPE_TV, },
			[NM_ATT_IPACC_SEC_OML_CFG] =	{ TLV_TYPE_FIXED, 6 },
			[NM_ATT_IPACC_IP_IF_CFG] =	{ TLV_TYPE_FIXED, 8 },
			[NM_ATT_IPACC_IP_GW_CFG] =	{ TLV_TYPE_FIXED, 12 },
			[NM_ATT_IPACC_IN_SERV_TIME] =	{ TLV_TYPE_FIXED, 4 },
			[NM_ATT_IPACC_LOCATION] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_PAGING_CFG] =	{ TLV_TYPE_FIXED, 2 },
			[NM_ATT_IPACC_UNIT_ID] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_UNIT_NAME] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_SNMP_CFG] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_PRIM_OML_CFG_LIST] = { TLV_TYPE_TL16V },
			[NM_ATT_IPACC_NV_FLAGS] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_FREQ_CTRL] =	{ TLV_TYPE_FIXED, 2 },
			[NM_ATT_IPACC_PRIM_OML_FB_TOUT] = { TLV_TYPE_TL16V },
			[NM_ATT_IPACC_CUR_SW_CFG] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_TIMING_BUS] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_CGI] =		{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_RAC] =		{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_OBJ_VERSION] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_GPRS_PAGING_CFG]= { TLV_TYPE_TL16V },
			[NM_ATT_IPACC_NSEI] =		{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_BVCI] =		{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_NSVCI] =		{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_NS_CFG] =		{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_BSSGP_CFG] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_NS_LINK_CFG] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_RLC_CFG] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_ALM_THRESH_LIST]=	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_MONIT_VAL_LIST] = { TLV_TYPE_TL16V },
			[NM_ATT_IPACC_TIB_CONTROL] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_SUPP_FEATURES] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_CODING_SCHEMES] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_RLC_CFG_2] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_HEARTB_TOUT] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_UPTIME] =		{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_RLC_CFG_3] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_SSL_CFG] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_SEC_POSSIBLE] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_IML_SSL_STATE] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_REVOC_DATE] =	{ TLV_TYPE_TL16V },
		},
	},
};


/* Callback function to be called whenever we get a GSM 12.21 state change event */
static int nm_statechg_event(int evt, struct nm_statechg_signal_data *nsd)
{
	uint8_t obj_class = nsd->obj_class;
	void *obj = nsd->obj;

	struct gsm_bts_sm *bts_sm;
	struct gsm_bts *bts;
	struct gsm_bts_trx *trx;
	struct gsm_bts_bb_trx *bb_transc;
	struct gsm_bts_trx_ts *ts;
	struct gsm_gprs_nsvc *nsvc;
	struct gsm_gprs_nse *nse;
	struct gsm_gprs_cell *cell;

	if (!is_ipaccess_bts(nsd->bts))
		return 0;

	switch (obj_class) {
	case NM_OC_SITE_MANAGER:
		bts_sm = obj;
		osmo_fsm_inst_dispatch(bts_sm->mo.fi, NM_EV_STATE_CHG_REP, nsd);
		break;
	case NM_OC_BTS:
		bts = obj;
		osmo_fsm_inst_dispatch(bts->mo.fi, NM_EV_STATE_CHG_REP, nsd);
		break;
	case NM_OC_BASEB_TRANSC:
		bb_transc = obj;
		osmo_fsm_inst_dispatch(bb_transc->mo.fi, NM_EV_STATE_CHG_REP, nsd);
		break;
	case NM_OC_CHANNEL:
		ts = obj;
		trx = ts->trx;
		osmo_fsm_inst_dispatch(ts->mo.fi, NM_EV_STATE_CHG_REP, nsd);
		break;
	case NM_OC_RADIO_CARRIER:
		trx = obj;
		osmo_fsm_inst_dispatch(trx->mo.fi, NM_EV_STATE_CHG_REP, nsd);
		break;
	case NM_OC_GPRS_NSE:
		nse = obj;
		osmo_fsm_inst_dispatch(nse->mo.fi, NM_EV_STATE_CHG_REP, nsd);
		break;
	case NM_OC_GPRS_CELL:
		cell = obj;
		osmo_fsm_inst_dispatch(cell->mo.fi, NM_EV_STATE_CHG_REP, nsd);
		break;
	case NM_OC_GPRS_NSVC:
		nsvc = obj;
		/* We skip NSVC1 since we only use NSVC0 */
		if (nsvc->id == 1)
			break;
		osmo_fsm_inst_dispatch(nsvc->mo.fi, NM_EV_STATE_CHG_REP, nsd);
		break;
	default:
		break;
	}
	return 0;
}

/* Callback function to be called every time we receive a 12.21 SW activated report */
static int sw_activ_rep(struct msgb *mb)
{
	struct abis_om_fom_hdr *foh = msgb_l3(mb);
	struct e1inp_sign_link *sign_link = mb->dst;
	struct gsm_bts *bts = sign_link->trx->bts;
	struct gsm_bts_trx *trx;
	struct gsm_gprs_nsvc *nsvc;
	struct gsm_bts_trx_ts *ts;

	if (!is_ipaccess_bts(bts))
		return 0;

	switch (foh->obj_class) {
	case NM_OC_SITE_MANAGER:
		osmo_fsm_inst_dispatch(bts->site_mgr->mo.fi, NM_EV_SW_ACT_REP, NULL);
		break;
	case NM_OC_BTS:
		osmo_fsm_inst_dispatch(bts->mo.fi, NM_EV_SW_ACT_REP, NULL);
		break;
	case NM_OC_BASEB_TRANSC:
		if (!(trx = gsm_bts_trx_num(bts, foh->obj_inst.trx_nr)))
			return -EINVAL;
		osmo_fsm_inst_dispatch(trx->bb_transc.mo.fi, NM_EV_SW_ACT_REP, NULL);
		break;
	case NM_OC_RADIO_CARRIER:
		if (!(trx = gsm_bts_trx_num(bts, foh->obj_inst.trx_nr)))
			return -EINVAL;
		osmo_fsm_inst_dispatch(trx->mo.fi, NM_EV_SW_ACT_REP, NULL);
		break;
	case NM_OC_CHANNEL:
		if (!(ts = abis_nm_get_ts(mb)))
			return -EINVAL;
		osmo_fsm_inst_dispatch(ts->mo.fi, NM_EV_SW_ACT_REP, NULL);
		break;
	case NM_OC_GPRS_NSE:
		osmo_fsm_inst_dispatch(bts->site_mgr->gprs.nse.mo.fi, NM_EV_SW_ACT_REP, NULL);
		break;
	case NM_OC_GPRS_CELL:
		osmo_fsm_inst_dispatch(bts->gprs.cell.mo.fi, NM_EV_SW_ACT_REP, NULL);
		break;
	case NM_OC_GPRS_NSVC:
		if (!(nsvc = gsm_bts_sm_nsvc_num(bts->site_mgr, foh->obj_inst.trx_nr)))
			return -EINVAL;
		osmo_fsm_inst_dispatch(nsvc->mo.fi, NM_EV_SW_ACT_REP, NULL);
		break;
	}
	return 0;
}

static void nm_rx_opstart_ack_chan(struct msgb *oml_msg)
{
	struct gsm_bts_trx_ts *ts;
	ts = abis_nm_get_ts(oml_msg);
	if (!ts)
		/* error already logged in abis_nm_get_ts() */
		return;
	if (!ts->fi) {
		LOG_TS(ts, LOGL_ERROR, "Channel OPSTART ACK for uninitialized TS\n");
		return;
	}
	osmo_fsm_inst_dispatch(ts->mo.fi, NM_EV_OPSTART_ACK, NULL);
	osmo_fsm_inst_dispatch(ts->fi, TS_EV_OML_READY, NULL);
}

static void nm_rx_opstart_ack(struct msgb *oml_msg)
{
	struct abis_om_fom_hdr *foh = msgb_l3(oml_msg);
	struct e1inp_sign_link *sign_link = oml_msg->dst;
	struct gsm_bts *bts = sign_link->trx->bts;
	struct gsm_bts_trx *trx;
	struct gsm_gprs_nsvc *nsvc;

	switch (foh->obj_class) {
	case NM_OC_SITE_MANAGER:
		osmo_fsm_inst_dispatch(bts->site_mgr->mo.fi, NM_EV_OPSTART_ACK, NULL);
		break;
	case NM_OC_BTS:
		osmo_fsm_inst_dispatch(bts->mo.fi, NM_EV_OPSTART_ACK, NULL);
		break;
	case NM_OC_RADIO_CARRIER:
		if (!(trx = gsm_bts_trx_num(bts, foh->obj_inst.trx_nr)))
			return;
		osmo_fsm_inst_dispatch(trx->mo.fi, NM_EV_OPSTART_ACK, NULL);
		break;
	case NM_OC_BASEB_TRANSC:
		if (!(trx = gsm_bts_trx_num(bts, foh->obj_inst.trx_nr)))
			return;
		osmo_fsm_inst_dispatch(trx->bb_transc.mo.fi, NM_EV_OPSTART_ACK, NULL);
		break;
	case NM_OC_CHANNEL:
		nm_rx_opstart_ack_chan(oml_msg);
		break;
	case NM_OC_GPRS_NSE:
		osmo_fsm_inst_dispatch(bts->site_mgr->gprs.nse.mo.fi, NM_EV_OPSTART_ACK, NULL);
		break;
	case NM_OC_GPRS_CELL:
		osmo_fsm_inst_dispatch(bts->gprs.cell.mo.fi, NM_EV_OPSTART_ACK, NULL);
		break;
	case NM_OC_GPRS_NSVC:
		if (!(nsvc = gsm_bts_sm_nsvc_num(bts->site_mgr, foh->obj_inst.trx_nr)))
			return;
		osmo_fsm_inst_dispatch(nsvc->mo.fi, NM_EV_OPSTART_ACK, NULL);
		break;
	default:
		break;
	}
}

static void nm_rx_opstart_nack(struct msgb *oml_msg)
{
	struct abis_om_fom_hdr *foh = msgb_l3(oml_msg);
	struct e1inp_sign_link *sign_link = oml_msg->dst;
	struct gsm_bts *bts = sign_link->trx->bts;
	struct gsm_bts_trx *trx;
	struct gsm_bts_trx_ts *ts;
	struct gsm_gprs_nsvc *nsvc;

	switch (foh->obj_class) {
	case NM_OC_SITE_MANAGER:
		osmo_fsm_inst_dispatch(bts->site_mgr->mo.fi, NM_EV_OPSTART_NACK, NULL);
		break;
	case NM_OC_BTS:
		osmo_fsm_inst_dispatch(bts->mo.fi, NM_EV_OPSTART_ACK, NULL);
		break;
	case NM_OC_RADIO_CARRIER:
		if (!(trx = gsm_bts_trx_num(bts, foh->obj_inst.trx_nr)))
			return;
		osmo_fsm_inst_dispatch(trx->mo.fi, NM_EV_OPSTART_NACK, NULL);
		break;
	case NM_OC_BASEB_TRANSC:
		if (!(trx = gsm_bts_trx_num(bts, foh->obj_inst.trx_nr)))
			return;
		osmo_fsm_inst_dispatch(trx->bb_transc.mo.fi, NM_EV_OPSTART_NACK, NULL);
		break;
	case NM_OC_CHANNEL:
		if (!(ts = abis_nm_get_ts(oml_msg)))
			return;
		osmo_fsm_inst_dispatch(ts->mo.fi, NM_EV_OPSTART_NACK, NULL);
		break;
	case NM_OC_GPRS_NSE:
		osmo_fsm_inst_dispatch(bts->site_mgr->gprs.nse.mo.fi, NM_EV_OPSTART_NACK, NULL);
		break;
	case NM_OC_GPRS_CELL:
		osmo_fsm_inst_dispatch(bts->gprs.cell.mo.fi, NM_EV_OPSTART_NACK, NULL);
		break;
	case NM_OC_GPRS_NSVC:
		if (!(nsvc = gsm_bts_sm_nsvc_num(bts->site_mgr, foh->obj_inst.trx_nr)))
			return;
		osmo_fsm_inst_dispatch(nsvc->mo.fi, NM_EV_OPSTART_NACK, NULL);
		break;
	default:
		break;
	}
}

static void nm_rx_get_attr_rep(struct msgb *oml_msg)
{
	struct abis_om_fom_hdr *foh = msgb_l3(oml_msg);
	struct e1inp_sign_link *sign_link = oml_msg->dst;
	struct gsm_bts *bts = sign_link->trx->bts;
	struct gsm_bts_trx *trx;

	switch (foh->obj_class) {
	case NM_OC_BTS:
		osmo_fsm_inst_dispatch(bts->mo.fi, NM_EV_GET_ATTR_REP, NULL);
		break;
	case NM_OC_BASEB_TRANSC:
		if (!(trx = gsm_bts_trx_num(bts, foh->obj_inst.trx_nr)))
			return;
		osmo_fsm_inst_dispatch(trx->bb_transc.mo.fi, NM_EV_GET_ATTR_REP, NULL);
		break;
	default:
		LOGPFOH(DNM, LOGL_ERROR, foh, "Get Attributes Response received on incorrect object class %d!\n", foh->obj_class);
	}
}

static void nm_rx_set_bts_attr_ack(struct msgb *oml_msg)
{
	struct abis_om_fom_hdr *foh = msgb_l3(oml_msg);
	struct e1inp_sign_link *sign_link = oml_msg->dst;
	struct gsm_bts *bts = sign_link->trx->bts;

	if (foh->obj_class != NM_OC_BTS) {
		LOG_BTS(bts, DNM, LOGL_ERROR, "Set BTS Attr Ack received on non BTS object!\n");
		return;
	}
	osmo_fsm_inst_dispatch(bts->mo.fi, NM_EV_SET_ATTR_ACK, NULL);
}


static void nm_rx_set_radio_attr_ack(struct msgb *oml_msg)
{
	struct abis_om_fom_hdr *foh = msgb_l3(oml_msg);
	struct e1inp_sign_link *sign_link = oml_msg->dst;
	struct gsm_bts *bts = sign_link->trx->bts;
	struct gsm_bts_trx *trx = gsm_bts_trx_num(bts, foh->obj_inst.trx_nr);

	if (!trx || foh->obj_class != NM_OC_RADIO_CARRIER) {
		LOGPFOH(DNM, LOGL_ERROR, foh, "Set Radio Carrier Attr Ack received on non Radio Carrier object!\n");
		return;
	}
	osmo_fsm_inst_dispatch(trx->mo.fi, NM_EV_SET_ATTR_ACK, NULL);
}

static void nm_rx_set_chan_attr_ack(struct msgb *oml_msg)
{
	struct abis_om_fom_hdr *foh = msgb_l3(oml_msg);
	struct gsm_bts_trx_ts *ts = abis_nm_get_ts(oml_msg);

	if (!ts || foh->obj_class != NM_OC_CHANNEL) {
		LOGPFOH(DNM, LOGL_ERROR, foh, "Set Channel Attr Ack received on non Radio Channel object!\n");
		return;
	}
	osmo_fsm_inst_dispatch(ts->mo.fi, NM_EV_SET_ATTR_ACK, NULL);
}

static void nm_rx_ipacc_set_attr_ack(struct msgb *oml_msg)
{
	struct e1inp_sign_link *sign_link = oml_msg->dst;
	struct gsm_bts *bts = sign_link->trx->bts;
	struct abis_om_hdr *oh = msgb_l2(oml_msg);
	uint8_t idstrlen = oh->data[0];
	struct abis_om_fom_hdr *foh;
	void *obj;
	struct gsm_gprs_nse *nse;
	struct gsm_gprs_cell *cell;
	struct gsm_gprs_nsvc *nsvc;

	foh = (struct abis_om_fom_hdr *) (oh->data + 1 + idstrlen);
	obj = gsm_objclass2obj(bts, foh->obj_class, &foh->obj_inst);

	switch (foh->obj_class) {
	case NM_OC_GPRS_NSE:
		nse = obj;
		osmo_fsm_inst_dispatch(nse->mo.fi, NM_EV_SET_ATTR_ACK, NULL);
		break;
	case NM_OC_GPRS_CELL:
		cell = obj;
		osmo_fsm_inst_dispatch(cell->mo.fi, NM_EV_SET_ATTR_ACK, NULL);
		break;
	case NM_OC_GPRS_NSVC:
		if (!(nsvc = gsm_bts_sm_nsvc_num(bts->site_mgr, foh->obj_inst.trx_nr)))
			return;
		osmo_fsm_inst_dispatch(nsvc->mo.fi, NM_EV_SET_ATTR_ACK, NULL);
		break;
	default:
		LOGPFOH(DNM, LOGL_ERROR, foh, "IPACC Set Attr Ack received on incorrect object class %d!\n", foh->obj_class);
	}
}

/* Callback function to be called every time we receive a signal from NM */
static int bts_ipa_nm_sig_cb(unsigned int subsys, unsigned int signal,
		     void *handler_data, void *signal_data)
{
	if (subsys != SS_NM)
		return 0;

	switch (signal) {
	case S_NM_SW_ACTIV_REP:
		return sw_activ_rep(signal_data);
	case S_NM_STATECHG:
		return nm_statechg_event(signal, signal_data);
	case S_NM_OPSTART_ACK:
		nm_rx_opstart_ack(signal_data);
		return 0;
	case S_NM_OPSTART_NACK:
		nm_rx_opstart_nack(signal_data);
		return 0;
	case S_NM_GET_ATTR_REP:
		nm_rx_get_attr_rep(signal_data);
		return 0;
	case S_NM_SET_BTS_ATTR_ACK:
		nm_rx_set_bts_attr_ack(signal_data);
		return 0;
	case S_NM_SET_RADIO_ATTR_ACK:
		nm_rx_set_radio_attr_ack(signal_data);
		return 0;
	case S_NM_SET_CHAN_ATTR_ACK:
		nm_rx_set_chan_attr_ack(signal_data);
		return 0;
	case S_NM_IPACC_SET_ATTR_ACK:
		nm_rx_ipacc_set_attr_ack(signal_data);
		return 0;
	default:
		break;
	}
	return 0;
}

static int bts_model_nanobts_start(struct gsm_network *net)
{
	osmo_signal_unregister_handler(SS_NM, bts_ipa_nm_sig_cb, NULL);
	osmo_signal_register_handler(SS_NM, bts_ipa_nm_sig_cb, NULL);
	return 0;
}

int bts_model_nanobts_init(void)
{
	bts_model_nanobts.features.data = &bts_model_nanobts._features_data[0];
	bts_model_nanobts.features.data_len =
				sizeof(bts_model_nanobts._features_data);

	osmo_bts_set_feature(&bts_model_nanobts.features, BTS_FEAT_GPRS);
	osmo_bts_set_feature(&bts_model_nanobts.features, BTS_FEAT_EGPRS);
	osmo_bts_set_feature(&bts_model_nanobts.features, BTS_FEAT_MULTI_TSC);

	return gsm_bts_model_register(&bts_model_nanobts);
}

#define OML_UP         0x0001
#define RSL_UP         0x0002

static struct gsm_bts *
find_bts_by_unitid(struct gsm_network *net, uint16_t site_id, uint16_t bts_id)
{
	struct gsm_bts *bts;

	llist_for_each_entry(bts, &net->bts_list, list) {
		if (!is_ipaccess_bts(bts))
			continue;

		if (bts->ip_access.site_id == site_id &&
		    bts->ip_access.bts_id == bts_id)
			return bts;
	}
	return NULL;
}

/* These are exported because they are used by the VTY interface. */
void ipaccess_drop_rsl(struct gsm_bts_trx *trx, const char *reason)
{
	if (!trx->rsl_link_primary)
		return;

	LOG_TRX(trx, DLINP, LOGL_NOTICE, "Dropping RSL link: %s\n", reason);
	e1inp_sign_link_destroy(trx->rsl_link_primary);
	trx->rsl_link_primary = NULL;
	osmo_stat_item_dec(osmo_stat_item_group_get_item(trx->bts->bts_statg, BTS_STAT_RSL_CONNECTED), 1);

	if (trx->bts->c0 == trx)
		paging_flush_bts(trx->bts, NULL);
}

void ipaccess_drop_oml(struct gsm_bts *bts, const char *reason)
{
	struct gsm_bts *rdep_bts;
	struct gsm_bts_trx *trx;
	struct gsm_bts_trx_ts *ts ;
	uint8_t tn;
	uint8_t i;

	/* First of all, remove deferred drop if enabled */
	osmo_timer_del(&bts->oml_drop_link_timer);

	if (!bts->oml_link)
		return;

	LOG_BTS(bts, DLINP, LOGL_NOTICE, "Dropping OML link: %s\n", reason);
	e1inp_sign_link_destroy(bts->oml_link);
	bts->oml_link = NULL;
	bts->uptime = 0;
	osmo_stat_item_dec(osmo_stat_item_group_get_item(bts->bts_statg, BTS_STAT_OML_CONNECTED), 1);
	gsm_bts_stats_reset(bts);

	/* Also drop the associated OSMO link */
	e1inp_sign_link_destroy(bts->osmo_link);
	bts->osmo_link = NULL;

	/* we have issues reconnecting RSL, drop everything. */
	llist_for_each_entry(trx, &bts->trx_list, list) {
		ipaccess_drop_rsl(trx, "OML link drop");
		osmo_fsm_inst_dispatch(trx->bb_transc.mo.fi, NM_EV_OML_DOWN, NULL);
		osmo_fsm_inst_dispatch(trx->mo.fi, NM_EV_OML_DOWN, NULL);
		for (tn = 0; tn < TRX_NR_TS; tn++) {
			ts = &trx->ts[tn];
			osmo_fsm_inst_dispatch(ts->mo.fi, NM_EV_OML_DOWN, NULL);
		}
	}

	osmo_fsm_inst_dispatch(bts->site_mgr->mo.fi, NM_EV_OML_DOWN, NULL);
	osmo_fsm_inst_dispatch(bts->site_mgr->gprs.nse.mo.fi, NM_EV_OML_DOWN, NULL);
	for (i = 0; i < ARRAY_SIZE(bts->site_mgr->gprs.nsvc); i++)
		osmo_fsm_inst_dispatch(bts->site_mgr->gprs.nsvc[i].mo.fi, NM_EV_OML_DOWN, NULL);

	osmo_fsm_inst_dispatch(bts->mo.fi, NM_EV_OML_DOWN, NULL);
	osmo_fsm_inst_dispatch(bts->gprs.cell.mo.fi, NM_EV_OML_DOWN, NULL);
	gsm_bts_all_ts_dispatch(bts, TS_EV_OML_DOWN, NULL);

	bts->ip_access.flags = 0;

	/*
	 * Go through the list and see if we are the depndency of a BTS
	 * and then drop the BTS. This can lead to some recursion but it
	 * should be fine in userspace.
	 * The oml_link is serving as recursion anchor for us and
	 * it is set to NULL some lines above.
	 */
	llist_for_each_entry(rdep_bts, &bts->network->bts_list, list) {
		if (!bts_depend_is_depedency(rdep_bts, bts))
			continue;
		LOGP(DLINP, LOGL_NOTICE, "Dropping BTS(%u) due BTS(%u).\n",
			rdep_bts->nr, bts->nr);
		ipaccess_drop_oml(rdep_bts, "Dependency link drop");
	}
}

/*! Callback for  \ref ipaccess_drop_oml_deferred_cb.
 */
static void ipaccess_drop_oml_deferred_cb(void *data)
{
	struct gsm_bts *bts = (struct gsm_bts *) data;
	ipaccess_drop_oml(bts, "Deferred link drop");
}
/*! Deferr \ref ipacces_drop_oml through a timer to avoid dropping structures in
 *  current code context. This may be needed if we want to destroy the OML link
 *  while being called from a lower layer "struct osmo_fd" cb, were it is
 *  mandatory to return -EBADF if the osmo_fd has been destroyed. In case code
 *  destroying an OML link is called through an osmo_signal, it becomes
 *  impossible to return any value, thus deferring the destruction is required.
 */
void ipaccess_drop_oml_deferred(struct gsm_bts *bts)
{
	if (!osmo_timer_pending(&bts->oml_drop_link_timer) && bts->oml_link) {
		LOG_BTS(bts, DLINP, LOGL_NOTICE, "Deferring Drop of OML link.\n");
		osmo_timer_setup(&bts->oml_drop_link_timer, ipaccess_drop_oml_deferred_cb, bts);
		osmo_timer_schedule(&bts->oml_drop_link_timer, 0, 0);
	}
}

/* Reject BTS because of an unknown unit ID */
static void ipaccess_sign_link_reject(const struct ipaccess_unit *dev, const struct e1inp_ts* ts)
{
	uint16_t site_id = dev->site_id;
	uint16_t bts_id = dev->bts_id;
	uint16_t trx_id = dev->trx_id;
	char ip[INET6_ADDRSTRLEN];
	struct gsm_bts_rejected *entry = NULL;
	struct gsm_bts_rejected *pos;

	/* Write to log and increase counter */
	LOGP(DLINP, LOGL_ERROR, "Unable to find BTS configuration for %u/%u/%u, disconnecting\n", site_id, bts_id,
		trx_id);
	rate_ctr_inc(rate_ctr_group_get_ctr(bsc_gsmnet->bsc_ctrs, BSC_CTR_UNKNOWN_UNIT_ID));

	/* Get remote IP */
	if (osmo_sock_get_remote_ip(ts->driver.ipaccess.fd.fd, ip, sizeof(ip)))
		return;

	/* Rejected list: unlink existing entry */
	llist_for_each_entry(pos, &bsc_gsmnet->bts_rejected, list) {
		if (pos->site_id == site_id && pos->bts_id == bts_id && !strcmp(pos->ip, ip)) {
			entry = pos;
			llist_del(&entry->list);
			break;
		}
	}

	/* Allocate new entry */
	if (!entry) {
		entry = talloc_zero(tall_bsc_ctx, struct gsm_bts_rejected);
		if (!entry)
			return;
		entry->site_id = site_id;
		entry->bts_id = bts_id;
		osmo_strlcpy(entry->ip, ip, sizeof(entry->ip));
	}

	/* Add to beginning with current timestamp */
	llist_add(&entry->list, &bsc_gsmnet->bts_rejected);
	entry->time = time(NULL);

	/* Cut off last (oldest) element if we have too many */
	if (llist_count(&bsc_gsmnet->bts_rejected) > 25) {
		pos = llist_last_entry(&bsc_gsmnet->bts_rejected, struct gsm_bts_rejected, list);
		llist_del(&pos->list);
		talloc_free(pos);
	}
}

/* This function is called once the OML/RSL link becomes up. */
static struct e1inp_sign_link *
ipaccess_sign_link_up(void *unit_data, struct e1inp_line *line,
		      enum e1inp_sign_type type)
{
	struct gsm_bts *bts;
	struct ipaccess_unit *dev = unit_data;
	struct e1inp_sign_link *sign_link = NULL;
	struct timespec tp;
	int rc;
	struct e1inp_ts *sign_ts = e1inp_line_ipa_oml_ts(line);

	bts = find_bts_by_unitid(bsc_gsmnet, dev->site_id, dev->bts_id);
	if (!bts) {
		ipaccess_sign_link_reject(dev, sign_ts);
		return NULL;
	}
	DEBUGP(DLINP, "%s: Identified BTS %u/%u/%u\n", e1inp_signtype_name(type),
			dev->site_id, dev->bts_id, dev->trx_id);

	/* Check if this BTS has a valid configuration. If not we will drop it
	 * immediately. */
	if (gsm_bts_check_cfg(bts) != 0) {
		LOGP(DLINP, LOGL_NOTICE, "(bts=%u) BTS config invalid, dropping BTS!\n", bts->nr);
		ipaccess_drop_oml_deferred(bts);
		return NULL;
	}

	switch(type) {
	case E1INP_SIGN_OML:
		/* remove old OML signal link for this BTS. */
		ipaccess_drop_oml(bts, "new OML link");

		if (!bts_depend_check(bts)) {
			LOGP(DLINP, LOGL_NOTICE,
				"Dependency not full-filled for %u/%u/%u\n",
				dev->site_id, dev->bts_id, dev->trx_id);
			return NULL;
		}

		/* create new OML link. */
		sign_link = bts->oml_link =
			e1inp_sign_link_create(sign_ts,
						E1INP_SIGN_OML, bts->c0,
						bts->oml_tei, 0);
		rc = osmo_clock_gettime(CLOCK_MONOTONIC, &tp);
		bts->uptime = (rc < 0) ? 0 : tp.tv_sec; /* we don't need sub-second precision for uptime */
		if (!(sign_link->trx->bts->ip_access.flags & OML_UP)) {
			e1inp_event(sign_link->ts, S_L_INP_TEI_UP,
					sign_link->tei, sign_link->sapi);
			sign_link->trx->bts->ip_access.flags |= OML_UP;
		}
		osmo_stat_item_inc(osmo_stat_item_group_get_item(bts->bts_statg, BTS_STAT_OML_CONNECTED), 1);

		/* Create link for E1INP_SIGN_OSMO */
		//SAPI must be 0, no IPAC_PROTO_EXT_PCU, see ipaccess_bts_read_cb
		bts->osmo_link = e1inp_sign_link_create(sign_ts, E1INP_SIGN_OSMO, bts->c0, IPAC_PROTO_OSMO, 0);
		break;
	case E1INP_SIGN_RSL: {
		struct e1inp_ts *ts;
		struct gsm_bts_trx *trx = gsm_bts_trx_num(bts, dev->trx_id);

		/* no OML link set yet? give up. */
		if (!bts->oml_link || !trx)
			return NULL;

		/* remove old RSL link for this TRX. */
		ipaccess_drop_rsl(trx, "new RSL link");

		/* set new RSL link for this TRX. */
		line = bts->oml_link->ts->line;
		ts = e1inp_line_ipa_rsl_ts(line, dev->trx_id);
		e1inp_ts_config_sign(ts, line);
		sign_link = trx->rsl_link_primary =
				e1inp_sign_link_create(ts, E1INP_SIGN_RSL,
						       trx, trx->rsl_tei_primary, 0);
		trx->rsl_link_primary->ts->sign.delay = 0;
		if (!(sign_link->trx->bts->ip_access.flags &
					(RSL_UP << sign_link->trx->nr))) {
			e1inp_event(sign_link->ts, S_L_INP_TEI_UP,
					sign_link->tei, sign_link->sapi);
			sign_link->trx->bts->ip_access.flags |=
					(RSL_UP << sign_link->trx->nr);
		}
		osmo_stat_item_inc(osmo_stat_item_group_get_item(bts->bts_statg, BTS_STAT_RSL_CONNECTED), 1);
		break;
	}
	default:
		break;
	}
	return sign_link;
}

static void ipaccess_sign_link_down(struct e1inp_line *line)
{
	/* No matter what link went down, we close both signal links. */
	struct e1inp_ts *ts = e1inp_line_ipa_oml_ts(line);
	struct gsm_bts *bts = NULL;
	struct e1inp_sign_link *link;

	LOGPIL(line, DLINP, LOGL_NOTICE, "Signalling link down\n");

	llist_for_each_entry(link, &ts->sign.sign_links, list) {
		/* Get bts pointer from the first element of the list. */
		if (bts == NULL)
			bts = link->trx->bts;
		/* Cancel RSL connection timeout in case are still waiting for an RSL connection. */
		if (link->trx->mo.nm_state.administrative == NM_STATE_UNLOCKED)
			osmo_timer_del(&link->trx->rsl_connect_timeout);
	}
	if (bts != NULL)
		ipaccess_drop_oml(bts, "link down");
	else
		LOGPIL(line, DLINP, LOGL_NOTICE, "Signalling link down for unknown BTS\n");
}

/* This function is called if we receive one OML/RSL message. */
static int ipaccess_sign_link(struct msgb *msg)
{
	int ret = 0;
	struct e1inp_sign_link *link = msg->dst;

	switch (link->type) {
	case E1INP_SIGN_RSL:
	        ret = abis_rsl_rcvmsg(msg);
	        break;
	case E1INP_SIGN_OML:
	        ret = abis_nm_rcvmsg(msg);
	        break;
	case E1INP_SIGN_OSMO:
	        ret = abis_osmo_rcvmsg(msg);
	        break;
	default:
		LOGP(DLINP, LOGL_ERROR, "Unknown signal link type %d\n",
			link->type);
		msgb_free(msg);
		break;
	}
	return ret;
}

/* not static, ipaccess-config needs it. */
struct e1inp_line_ops ipaccess_e1inp_line_ops = {
	.cfg = {
		.ipa = {
			.addr = "0.0.0.0",
			.role = E1INP_LINE_R_BSC,
		},
	},
	.sign_link_up	= ipaccess_sign_link_up,
	.sign_link_down	= ipaccess_sign_link_down,
	.sign_link	= ipaccess_sign_link,
};

static void bts_model_nanobts_e1line_bind_ops(struct e1inp_line *line)
{
        e1inp_line_bind_ops(line, &ipaccess_e1inp_line_ops);
}

static void enc_meas_proc_params(struct msgb *msg, uint8_t ptype,
				 const struct gsm_power_ctrl_meas_params *mp)
{
	struct ipac_preproc_ave_cfg *ave_cfg;
	uint8_t *ie_len;

	/* No averaging => no Measurement Averaging parameters */
	if (mp->algo == GSM_PWR_CTRL_MEAS_AVG_ALGO_NONE)
		return;

	/* (TLV) Measurement Averaging parameters for RxLev/RxQual */
	ie_len = msgb_tl_put(msg, RSL_IPAC_EIE_MEAS_AVG_CFG);

	ave_cfg = (struct ipac_preproc_ave_cfg *) msgb_put(msg, sizeof(*ave_cfg));
	ave_cfg->param_id = ptype & 0x03;

	/* H_REQAVE and H_REQT */
	ave_cfg->h_reqave = mp->h_reqave & 0x1f;
	ave_cfg->h_reqt = mp->h_reqt & 0x1f;

	/* Averaging method and parameters */
	ave_cfg->ave_method = (mp->algo - 1) & 0x07;
	switch (mp->algo) {
	case GSM_PWR_CTRL_MEAS_AVG_ALGO_OSMO_EWMA:
		msgb_v_put(msg, mp->ewma.alpha);
		break;
	case GSM_PWR_CTRL_MEAS_AVG_ALGO_WEIGHTED:
	case GSM_PWR_CTRL_MEAS_AVG_ALGO_MOD_MEDIAN:
		/* FIXME: unknown format */
		break;
	case GSM_PWR_CTRL_MEAS_AVG_ALGO_UNWEIGHTED:
	case GSM_PWR_CTRL_MEAS_AVG_ALGO_NONE:
		/* No parameters here */
		break;
	}

	/* Update length part of the containing IE */
	*ie_len = msg->tail - (ie_len + 1);
}

static void enc_power_params(struct msgb *msg, const struct gsm_power_ctrl_params *cp)
{
	struct ipac_preproc_pc_comp *thresh_comp;
	struct ipac_preproc_pc_thresh *thresh;

	/* These parameters are valid for dynamic mode only */
	OSMO_ASSERT(cp->mode == GSM_PWR_CTRL_MODE_DYN_BTS);

	/* (TLV) Measurement Averaging Configure */
	enc_meas_proc_params(msg, IPAC_RXQUAL_AVE, &cp->rxqual_meas);
	enc_meas_proc_params(msg, IPAC_RXLEV_AVE, &cp->rxlev_meas);

	/* (TV) Thresholds: {L,U}_RXLEV_XX_P and {L,U}_RXQUAL_XX_P */
	if (cp->dir == GSM_PWR_CTRL_DIR_UL)
		msgb_v_put(msg, RSL_IPAC_EIE_MS_PWR_CTL);
	else
		msgb_v_put(msg, RSL_IPAC_EIE_BS_PWR_CTL);

	thresh = (struct ipac_preproc_pc_thresh *) msgb_put(msg, sizeof(*thresh));

	/* {L,U}_RXLEV_XX_P (see 3GPP TS 45.008, A.3.2.1, a & b) */
	thresh->l_rxlev = cp->rxlev_meas.lower_thresh & 0x3f;
	thresh->u_rxlev = cp->rxlev_meas.upper_thresh & 0x3f;

	/* {L,U}_RXQUAL_XX_P (see 3GPP TS 45.008, A.3.2.1, c & d) */
	thresh->l_rxqual = cp->rxqual_meas.lower_thresh & 0x07;
	thresh->u_rxqual = cp->rxqual_meas.upper_thresh & 0x07;

	/* (TV) PC Threshold Comparators */
	msgb_v_put(msg, RSL_IPAC_EIE_PC_THRESH_COMP);

	thresh_comp = (struct ipac_preproc_pc_comp *) msgb_put(msg, sizeof(*thresh_comp));

	/* RxLev: P1, N1, P2, N2 (see 3GPP TS 45.008, A.3.2.1, a & b) */
	thresh_comp->p1 = cp->rxlev_meas.lower_cmp_p & 0x1f;
	thresh_comp->n1 = cp->rxlev_meas.lower_cmp_n & 0x1f;
	thresh_comp->p2 = cp->rxlev_meas.upper_cmp_p & 0x1f;
	thresh_comp->n2 = cp->rxlev_meas.upper_cmp_n & 0x1f;

	/* RxQual: P3, N3, P4, N4 (see 3GPP TS 45.008, A.3.2.1, c & d) */
	thresh_comp->p3 = cp->rxqual_meas.lower_cmp_p & 0x1f;
	thresh_comp->n3 = cp->rxqual_meas.lower_cmp_n & 0x1f;
	thresh_comp->p4 = cp->rxqual_meas.upper_cmp_p & 0x1f;
	thresh_comp->n4 = cp->rxqual_meas.upper_cmp_n & 0x1f;

	/* Minimum interval between power level changes (P_CON_INTERVAL) */
	thresh_comp->pc_interval = cp->ctrl_interval;

	/* Change step limitations: POWER_{INC,RED}_STEP_SIZE */
	thresh_comp->inc_step_size = cp->inc_step_size_db & 0x0f;
	thresh_comp->red_step_size = cp->red_step_size_db & 0x0f;
}

void osmobts_enc_power_params_osmo_ext(struct msgb *msg, const struct gsm_power_ctrl_params *cp);
static void add_power_params_ie(struct msgb *msg, enum abis_rsl_ie iei,
				const struct gsm_bts_trx *trx,
				const struct gsm_power_ctrl_params *cp)
{
	uint8_t *ie_len = msgb_tl_put(msg, iei);
	uint8_t msg_len = msgb_length(msg);

	enc_power_params(msg, cp);
	if (iei == RSL_IE_MS_POWER_PARAM && is_osmobts(trx->bts))
		osmobts_enc_power_params_osmo_ext(msg, cp);

	*ie_len = msgb_length(msg) - msg_len;
}

static int power_ctrl_send_def_params(const struct gsm_bts_trx *trx)
{
	const struct gsm_power_ctrl_params *ms_power_ctrl = &trx->bts->ms_power_ctrl;
	const struct gsm_power_ctrl_params *bs_power_ctrl = &trx->bts->bs_power_ctrl;
	struct abis_rsl_common_hdr *ch;
	struct msgb *msg;

	/* Sending this message does not make sense if neither MS Power control
	 * nor BS Power control is to be performed by the BTS itself ('dyn-bts'). */
	if (ms_power_ctrl->mode != GSM_PWR_CTRL_MODE_DYN_BTS &&
	    bs_power_ctrl->mode != GSM_PWR_CTRL_MODE_DYN_BTS)
		return 0;

	msg = rsl_msgb_alloc();
	if (msg == NULL)
		return -ENOMEM;

	ch = (struct abis_rsl_common_hdr *) msgb_put(msg, sizeof(*ch));
	ch->msg_discr = ABIS_RSL_MDISC_TRX;
	ch->msg_type = RSL_MT_IPAC_MEAS_PREPROC_DFT;

	/* BS/MS Power IEs (to be re-defined in channel specific messages) */
	msgb_tv_put(msg, RSL_IE_MS_POWER, 0); /* dummy value */
	msgb_tv_put(msg, RSL_IE_BS_POWER, 0); /* dummy value */

	/* MS/BS Power Parameters IEs */
	if (ms_power_ctrl->mode == GSM_PWR_CTRL_MODE_DYN_BTS)
		add_power_params_ie(msg, RSL_IE_MS_POWER_PARAM, trx, ms_power_ctrl);
	if (bs_power_ctrl->mode == GSM_PWR_CTRL_MODE_DYN_BTS)
		add_power_params_ie(msg, RSL_IE_BS_POWER_PARAM, trx, bs_power_ctrl);

	msg->dst = trx->rsl_link_primary;

	return abis_rsl_sendmsg(msg);
}

static int power_ctrl_enc_rsl_params(struct msgb *msg, const struct gsm_power_ctrl_params *cp)
{
	/* We send everything in "Measurement Pre-processing Defaults" */
	return 0;
}
