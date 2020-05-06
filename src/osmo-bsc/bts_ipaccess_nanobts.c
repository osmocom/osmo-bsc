/* ip.access nanoBTS specific code */

/* (C) 2009-2018 by Harald Welte <laforge@gnumonks.org>
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
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/abis_nm.h>
#include <osmocom/bsc/abis_rsl.h>
#include <osmocom/bsc/debug.h>
#include <osmocom/abis/subchan_demux.h>
#include <osmocom/gsm/ipa.h>
#include <osmocom/abis/ipaccess.h>
#include <osmocom/core/logging.h>
#include <osmocom/bsc/ipaccess.h>
#include <osmocom/bsc/bts_ipaccess_nanobts_omlattr.h>
#include <osmocom/bsc/paging.h>
#include <osmocom/bsc/timeslot_fsm.h>

static int bts_model_nanobts_start(struct gsm_network *net);
static void bts_model_nanobts_e1line_bind_ops(struct e1inp_line *line);

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
	struct gsm_nm_state *new_state = nsd->new_state;

	struct gsm_bts *bts;
	struct gsm_bts_trx *trx;
	struct gsm_bts_trx_ts *ts;
	struct gsm_bts_gprs_nsvc *nsvc;

	struct msgb *msgb;

	if (!is_ipaccess_bts(nsd->bts))
		return 0;

	/* This event-driven BTS setup is currently only required on nanoBTS */

	/* S_NM_STATECHG_ADM is called after we call chg_adm_state() and would create
	 * endless loop */
	if (evt != S_NM_STATECHG_OPER)
		return 0;

	switch (obj_class) {
	case NM_OC_SITE_MANAGER:
		bts = container_of(obj, struct gsm_bts, site_mgr);
		if ((new_state->operational == NM_OPSTATE_ENABLED &&
		     new_state->availability == NM_AVSTATE_OK) ||
		    (new_state->operational == NM_OPSTATE_DISABLED &&
		     new_state->availability == NM_AVSTATE_OFF_LINE))
			abis_nm_opstart(bts, obj_class, 0xff, 0xff, 0xff);
		break;
	case NM_OC_BTS:
		bts = obj;
		if (new_state->availability == NM_AVSTATE_DEPENDENCY) {
			msgb = nanobts_attr_bts_get(bts);
			abis_nm_set_bts_attr(bts, msgb->data, msgb->len);
			msgb_free(msgb);
			abis_nm_chg_adm_state(bts, obj_class,
					      bts->bts_nr, 0xff, 0xff,
					      NM_STATE_UNLOCKED);
			abis_nm_opstart(bts, obj_class,
					bts->bts_nr, 0xff, 0xff);
		}
		break;
	case NM_OC_CHANNEL:
		ts = obj;
		trx = ts->trx;
		if (new_state->operational == NM_OPSTATE_DISABLED &&
		    new_state->availability == NM_AVSTATE_DEPENDENCY) {
			enum abis_nm_chan_comb ccomb =
						abis_nm_chcomb4pchan(ts->pchan_from_config);
			if (abis_nm_set_channel_attr(ts, ccomb) == -EINVAL) {
				ipaccess_drop_oml_deferred(trx->bts);
				return -1;
			}
			abis_nm_chg_adm_state(trx->bts, obj_class,
					      trx->bts->bts_nr, trx->nr, ts->nr,
					      NM_STATE_UNLOCKED);
			abis_nm_opstart(trx->bts, obj_class,
					trx->bts->bts_nr, trx->nr, ts->nr);
		}
		break;
	case NM_OC_RADIO_CARRIER:
		trx = obj;
		if (new_state->operational == NM_OPSTATE_DISABLED &&
		    new_state->availability == NM_AVSTATE_OK)
			abis_nm_opstart(trx->bts, obj_class, trx->bts->bts_nr,
					trx->nr, 0xff);
		break;
	case NM_OC_GPRS_NSE:
		bts = container_of(obj, struct gsm_bts, gprs.nse);
		if (bts->gprs.mode == BTS_GPRS_NONE)
			break;
		if (new_state->availability == NM_AVSTATE_DEPENDENCY) {
			msgb = nanobts_attr_nse_get(bts);
			abis_nm_ipaccess_set_attr(bts, obj_class, bts->bts_nr,
						  0xff, 0xff, msgb->data,
						  msgb->len);
			msgb_free(msgb);
			abis_nm_opstart(bts, obj_class, bts->bts_nr,
					0xff, 0xff);
		}
		break;
	case NM_OC_GPRS_CELL:
		bts = container_of(obj, struct gsm_bts, gprs.cell);
		if (bts->gprs.mode == BTS_GPRS_NONE)
			break;
		if (new_state->availability == NM_AVSTATE_DEPENDENCY) {
			msgb = nanobts_attr_cell_get(bts);
			abis_nm_ipaccess_set_attr(bts, obj_class, bts->bts_nr,
						  0, 0xff, msgb->data,
						  msgb->len);
			msgb_free(msgb);
			abis_nm_opstart(bts, obj_class, bts->bts_nr,
					0, 0xff);
			abis_nm_chg_adm_state(bts, obj_class, bts->bts_nr,
					      0, 0xff, NM_STATE_UNLOCKED);
			abis_nm_chg_adm_state(bts, NM_OC_GPRS_NSE, bts->bts_nr,
					      0xff, 0xff, NM_STATE_UNLOCKED);
		}
		break;
	case NM_OC_GPRS_NSVC:
		nsvc = obj;
		bts = nsvc->bts;
		if (bts->gprs.mode == BTS_GPRS_NONE)
			break;
		/* We skip NSVC1 since we only use NSVC0 */
		if (nsvc->id == 1)
			break;
		if ((new_state->availability == NM_AVSTATE_OFF_LINE) ||
		    (new_state->availability == NM_AVSTATE_DEPENDENCY)) {
			msgb = nanobts_attr_nscv_get(bts);
			abis_nm_ipaccess_set_attr(bts, obj_class, bts->bts_nr,
						  nsvc->id, 0xff,
						  msgb->data, msgb->len);
			msgb_free(msgb);
			abis_nm_opstart(bts, obj_class, bts->bts_nr,
					nsvc->id, 0xff);
			abis_nm_chg_adm_state(bts, obj_class, bts->bts_nr,
					      nsvc->id, 0xff,
					      NM_STATE_UNLOCKED);
		}
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
	struct gsm_bts_trx *trx = gsm_bts_trx_num(bts, foh->obj_inst.trx_nr);

	if (!trx)
		return -EINVAL;

	if (!is_ipaccess_bts(trx->bts))
		return 0;

	switch (foh->obj_class) {
	case NM_OC_BASEB_TRANSC:
		abis_nm_chg_adm_state(trx->bts, foh->obj_class,
				      trx->bts->bts_nr, trx->nr, 0xff,
				      NM_STATE_UNLOCKED);
		abis_nm_opstart(trx->bts, foh->obj_class,
				trx->bts->bts_nr, trx->nr, 0xff);
		/* TRX software is active, tell it to initiate RSL Link */
		abis_nm_ipaccess_rsl_connect(trx, trx->bts->ip_access.rsl_ip,
					     3003, trx->rsl_tei);
		break;
	case NM_OC_RADIO_CARRIER: {
		/*
		 * Locking the radio carrier will make it go
		 * offline again and we would come here. The
		 * framework should determine that there was
		 * no change and avoid recursion.
		 *
		 * This code is here to make sure that on start
		 * a TRX remains locked.
		 */
		int rc_state = trx->mo.nm_state.administrative;
		/* Patch ARFCN into radio attribute */
		struct msgb *msgb = nanobts_attr_radio_get(trx->bts, trx);
		abis_nm_set_radio_attr(trx, msgb->data, msgb->len);
		msgb_free(msgb);
		abis_nm_chg_adm_state(trx->bts, foh->obj_class,
				      trx->bts->bts_nr, trx->nr, 0xff,
				      rc_state);
		abis_nm_opstart(trx->bts, foh->obj_class, trx->bts->bts_nr,
				trx->nr, 0xff);
		break;
		}
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

	osmo_fsm_inst_dispatch(ts->fi, TS_EV_OML_READY, NULL);
}

static void nm_rx_opstart_ack(struct msgb *oml_msg)
{
	struct abis_om_fom_hdr *foh = msgb_l3(oml_msg);
	switch (foh->obj_class) {
	case NM_OC_CHANNEL:
		nm_rx_opstart_ack_chan(oml_msg);
		break;
	default:
		break;
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
	case S_NM_STATECHG_OPER:
	case S_NM_STATECHG_ADM:
		return nm_statechg_event(signal, signal_data);
	case S_NM_OPSTART_ACK:
		nm_rx_opstart_ack(signal_data);
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
	if (!trx->rsl_link)
		return;

	LOG_TRX(trx, DLINP, LOGL_NOTICE, "Dropping RSL link: %s\n", reason);
	e1inp_sign_link_destroy(trx->rsl_link);
	trx->rsl_link = NULL;
	osmo_stat_item_set(trx->bts->bts_statg->items[BTS_STAT_NUM_RSL_CONNECTED], 0);
	osmo_stat_item_dec(trx->bts->network->bsc_statg->items[BSC_STAT_NUM_TRX_CONNECTED], 1);

	if (trx->bts->c0 == trx)
		paging_flush_bts(trx->bts, NULL);
}

void ipaccess_drop_oml(struct gsm_bts *bts, const char *reason)
{
	struct gsm_bts *rdep_bts;
	struct gsm_bts_trx *trx;

	/* First of all, remove deferred drop if enabled */
	osmo_timer_del(&bts->oml_drop_link_timer);

	if (!bts->oml_link)
		return;

	LOG_BTS(bts, DLINP, LOGL_NOTICE, "Dropping OML link: %s\n", reason);
	e1inp_sign_link_destroy(bts->oml_link);
	bts->oml_link = NULL;
	bts->uptime = 0;
	osmo_stat_item_set(bts->bts_statg->items[BTS_STAT_NUM_OML_CONNECTED], 0);
	osmo_stat_item_dec(bts->network->bsc_statg->items[BSC_STAT_NUM_BTS_CONNECTED], 1);

	/* we have issues reconnecting RSL, drop everything. */
	llist_for_each_entry(trx, &bts->trx_list, list)
		ipaccess_drop_rsl(trx, "OML link drop");

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
	rate_ctr_inc(&bsc_gsmnet->bsc_ctrs->ctr[BSC_CTR_UNKNOWN_UNIT_ID]);

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

	bts = find_bts_by_unitid(bsc_gsmnet, dev->site_id, dev->bts_id);
	if (!bts) {
		ipaccess_sign_link_reject(dev, &line->ts[E1INP_SIGN_OML - 1]);
		return NULL;
	}
	DEBUGP(DLINP, "Identified BTS %u/%u/%u\n",
			dev->site_id, dev->bts_id, dev->trx_id);

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
			e1inp_sign_link_create(&line->ts[E1INP_SIGN_OML - 1],
						E1INP_SIGN_OML, bts->c0,
						bts->oml_tei, 0);
		rc = clock_gettime(CLOCK_MONOTONIC, &tp);
		bts->uptime = (rc < 0) ? 0 : tp.tv_sec; /* we don't need sub-second precision for uptime */
		if (!(sign_link->trx->bts->ip_access.flags & OML_UP)) {
			e1inp_event(sign_link->ts, S_L_INP_TEI_UP,
					sign_link->tei, sign_link->sapi);
			sign_link->trx->bts->ip_access.flags |= OML_UP;
		}
		osmo_stat_item_set(bts->bts_statg->items[BTS_STAT_NUM_OML_CONNECTED], 1);
		osmo_stat_item_inc(bts->network->bsc_statg->items[BSC_STAT_NUM_BTS_CONNECTED], 1);
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
		ts = &line->ts[E1INP_SIGN_RSL + dev->trx_id - 1];
		e1inp_ts_config_sign(ts, line);
		sign_link = trx->rsl_link =
				e1inp_sign_link_create(ts, E1INP_SIGN_RSL,
						       trx, trx->rsl_tei, 0);
		trx->rsl_link->ts->sign.delay = 0;
		if (!(sign_link->trx->bts->ip_access.flags &
					(RSL_UP << sign_link->trx->nr))) {
			e1inp_event(sign_link->ts, S_L_INP_TEI_UP,
					sign_link->tei, sign_link->sapi);
			sign_link->trx->bts->ip_access.flags |=
					(RSL_UP << sign_link->trx->nr);
		}
		break;
		osmo_stat_item_set(bts->bts_statg->items[BTS_STAT_NUM_RSL_CONNECTED], 1);
		osmo_stat_item_inc(bts->network->bsc_statg->items[BSC_STAT_NUM_TRX_CONNECTED], 1);		
	}
	default:
		break;
	}
	return sign_link;
}

static void ipaccess_sign_link_down(struct e1inp_line *line)
{
	/* No matter what link went down, we close both signal links. */
	struct e1inp_ts *ts = &line->ts[E1INP_SIGN_OML-1];
	struct gsm_bts *bts = NULL;
	struct e1inp_sign_link *link;

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
