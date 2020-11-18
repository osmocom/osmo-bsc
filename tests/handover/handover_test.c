/*
 * (C) 2013 by Andreas Eversberg <jolly@eversberg.eu>
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
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <assert.h>

#include <osmocom/core/application.h>
#include <osmocom/core/select.h>
#include <osmocom/core/talloc.h>

#include <osmocom/mgcp_client/mgcp_client_endpoint_fsm.h>

#include <osmocom/bsc/abis_rsl.h>
#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/bsc_subscriber.h>
#include <osmocom/bsc/lchan_select.h>
#include <osmocom/bsc/lchan_fsm.h>
#include <osmocom/bsc/handover_decision.h>
#include <osmocom/bsc/system_information.h>
#include <osmocom/bsc/handover.h>
#include <osmocom/bsc/handover_cfg.h>
#include <osmocom/bsc/handover_decision_2.h>
#include <osmocom/bsc/bss.h>
#include <osmocom/bsc/gsm_08_08.h>
#include <osmocom/bsc/osmo_bsc.h>
#include <osmocom/bsc/bsc_subscr_conn_fsm.h>
#include <osmocom/bsc/timeslot_fsm.h>
#include <osmocom/bsc/lchan_fsm.h>
#include <osmocom/bsc/handover_fsm.h>
#include <osmocom/bsc/bsc_msc_data.h>
#include <osmocom/bsc/bts.h>
#include <osmocom/bsc/paging.h>

void *ctx;

struct gsm_network *bsc_gsmnet;

/* override, requires '-Wl,--wrap=osmo_mgcpc_ep_ci_request'.
 * Catch modification of an MGCP connection. */
void __real_osmo_mgcpc_ep_ci_request(struct osmo_mgcpc_ep_ci *ci,
				    enum mgcp_verb verb, const struct mgcp_conn_peer *verb_info,
				    struct osmo_fsm_inst *notify,
				    uint32_t event_success, uint32_t event_failure,
				    void *notify_data);
void __wrap_osmo_mgcpc_ep_ci_request(struct osmo_mgcpc_ep_ci *ci,
				    enum mgcp_verb verb, const struct mgcp_conn_peer *verb_info,
				    struct osmo_fsm_inst *notify,
				    uint32_t event_success, uint32_t event_failure,
				    void *notify_data)
{
	struct mgcp_conn_peer fake_data = {};
	/* All MGCP shall be successful */
	if (!notify)
		return;
	osmo_fsm_inst_dispatch(notify, event_success, &fake_data);
}

/* measurement report */

uint8_t meas_rep_ba = 0, meas_rep_valid = 1, meas_valid = 1, meas_multi_rep = 0;
uint8_t meas_dl_rxlev = 0, meas_dl_rxqual = 0;
uint8_t meas_ul_rxlev = 0, meas_ul_rxqual = 0;
uint8_t meas_tx_power_ms = 0, meas_tx_power_bs = 0, meas_ta_ms = 0;
uint8_t meas_dtx_ms = 0, meas_dtx_bs = 0, meas_nr = 0;
uint8_t meas_num_nc = 0, meas_rxlev_nc[6], meas_bsic_nc[6], meas_bcch_f_nc[6];

static void gen_meas_rep(struct gsm_lchan *lchan)
{
	struct msgb *msg = msgb_alloc_headroom(256, 64, "RSL");
	struct abis_rsl_dchan_hdr *dh;
	uint8_t chan_nr = gsm_lchan2chan_nr(lchan);
	uint8_t ulm[3], l1i[2], *buf;
	struct gsm48_hdr *gh;
	struct gsm48_meas_res *mr;

	dh = (struct abis_rsl_dchan_hdr *) msgb_put(msg, sizeof(*dh));
	dh->c.msg_discr = ABIS_RSL_MDISC_DED_CHAN;
	dh->c.msg_type = RSL_MT_MEAS_RES;
	dh->ie_chan = RSL_IE_CHAN_NR;
	dh->chan_nr = chan_nr;

	msgb_tv_put(msg, RSL_IE_MEAS_RES_NR, meas_nr++);

	ulm[0] = meas_ul_rxlev | (meas_dtx_bs << 7);
	ulm[1] = meas_ul_rxlev;
	ulm[2] = (meas_ul_rxqual << 3) | meas_ul_rxqual;
	msgb_tlv_put(msg, RSL_IE_UPLINK_MEAS, sizeof(ulm), ulm);

	msgb_tv_put(msg, RSL_IE_BS_POWER, meas_tx_power_bs);

	l1i[0] = 0;
	l1i[1] = meas_ta_ms;
	msgb_tv_fixed_put(msg, RSL_IE_L1_INFO, sizeof(l1i), l1i);

	buf = msgb_put(msg, 3);
	buf[0] = RSL_IE_L3_INFO;
	buf[1] = (sizeof(*gh) + sizeof(*mr)) >> 8;
	buf[2] = (sizeof(*gh) + sizeof(*mr)) & 0xff;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	mr = (struct gsm48_meas_res *) msgb_put(msg, sizeof(*mr));

	gh->proto_discr = GSM48_PDISC_RR;
	gh->msg_type = GSM48_MT_RR_MEAS_REP;

	/* measurement results */
	mr->rxlev_full = meas_dl_rxlev;
	mr->rxlev_sub = meas_dl_rxlev;
	mr->rxqual_full = meas_dl_rxqual;
	mr->rxqual_sub = meas_dl_rxqual;
	mr->dtx_used = meas_dtx_ms;
	mr->ba_used = meas_rep_ba;
	mr->meas_valid = !meas_valid; /* 0 = valid */
	if (meas_rep_valid) {
		mr->no_nc_n_hi = meas_num_nc >> 2;
		mr->no_nc_n_lo = meas_num_nc & 3;
	} else {
		/* no results for serving cells */
		mr->no_nc_n_hi = 1;
		mr->no_nc_n_lo = 3;
	}
	mr->rxlev_nc1 = meas_rxlev_nc[0];
	mr->rxlev_nc2_hi = meas_rxlev_nc[1] >> 1;
	mr->rxlev_nc2_lo = meas_rxlev_nc[1] & 1;
	mr->rxlev_nc3_hi = meas_rxlev_nc[2] >> 2;
	mr->rxlev_nc3_lo = meas_rxlev_nc[2] & 3;
	mr->rxlev_nc4_hi = meas_rxlev_nc[3] >> 3;
	mr->rxlev_nc4_lo = meas_rxlev_nc[3] & 7;
	mr->rxlev_nc5_hi = meas_rxlev_nc[4] >> 4;
	mr->rxlev_nc5_lo = meas_rxlev_nc[4] & 15;
	mr->rxlev_nc6_hi = meas_rxlev_nc[5] >> 5;
	mr->rxlev_nc6_lo = meas_rxlev_nc[5] & 31;
	mr->bsic_nc1_hi = meas_bsic_nc[0] >> 3;
	mr->bsic_nc1_lo = meas_bsic_nc[0] & 7;
	mr->bsic_nc2_hi = meas_bsic_nc[1] >> 4;
	mr->bsic_nc2_lo = meas_bsic_nc[1] & 15;
	mr->bsic_nc3_hi = meas_bsic_nc[2] >> 5;
	mr->bsic_nc3_lo = meas_bsic_nc[2] & 31;
	mr->bsic_nc4 = meas_bsic_nc[3];
	mr->bsic_nc5 = meas_bsic_nc[4];
	mr->bsic_nc6 = meas_bsic_nc[5];
	mr->bcch_f_nc1 = meas_bcch_f_nc[0];
	mr->bcch_f_nc2 = meas_bcch_f_nc[1];
	mr->bcch_f_nc3 = meas_bcch_f_nc[2];
	mr->bcch_f_nc4 = meas_bcch_f_nc[3];
	mr->bcch_f_nc5_hi = meas_bcch_f_nc[4] >> 1;
	mr->bcch_f_nc5_lo = meas_bcch_f_nc[4] & 1;
	mr->bcch_f_nc6_hi = meas_bcch_f_nc[5] >> 2;
	mr->bcch_f_nc6_lo = meas_bcch_f_nc[5] & 3;

	msg->dst = lchan->ts->trx->bts->c0->rsl_link;
	msg->l2h = (unsigned char *)dh;
	msg->l3h = (unsigned char *)gh;

	abis_rsl_rcvmsg(msg);
}

enum gsm_phys_chan_config pchan_from_str(const char *str)
{
	enum gsm_phys_chan_config pchan;
	if (!strcmp(str, "dyn"))
		return GSM_PCHAN_TCH_F_TCH_H_PDCH;
	if (!strcmp(str, "c+s4"))
		return GSM_PCHAN_CCCH_SDCCH4;
	if (!strcmp(str, "-"))
		return GSM_PCHAN_NONE;
	pchan = gsm_pchan_parse(str);
	if (pchan < 0) {
		fprintf(stderr, "Invalid timeslot pchan type: %s\n", str);
		exit(1);
	}
	return pchan;
}

const char * const bts_default_ts[] = {
	"c+s4", "TCH/F", "TCH/F", "TCH/F", "TCH/F", "TCH/H", "TCH/H", "-",
};

static struct gsm_bts *create_bts(int num_trx, const char * const *ts_args)
{
	static int arfcn = 870;
	struct gsm_bts *bts;
	struct e1inp_sign_link *rsl_link;
	int i;
	int trx_i;
	struct gsm_bts_trx *trx;

	fprintf(stderr, "- Creating BTS %d, %d TRX\n", bsc_gsmnet->num_bts, num_trx);
	for (trx_i = 0; trx_i < num_trx; trx_i++) {
		for (i = 0; i < 8; i++)
			fprintf(stderr, "\t%s", ts_args[8*trx_i + i]);
		fprintf(stderr, "\n");
	}

	bts = bsc_bts_alloc_register(bsc_gsmnet, GSM_BTS_TYPE_UNKNOWN, 0x3f);
	if (!bts) {
		printf("No resource for bts1\n");
		return NULL;
	}

	bts->location_area_code = 23;
	bts->c0->arfcn = arfcn++;

	bts->codec.efr = 1;
	bts->codec.hr = 1;
	bts->codec.amr = 1;

	rsl_link = talloc_zero(ctx, struct e1inp_sign_link);
	rsl_link->trx = bts->c0;
	bts->c0->rsl_link = rsl_link;

	for (trx_i = 0; trx_i < num_trx; trx_i++) {
		while (!(trx = gsm_bts_trx_num(bts, trx_i)))
			gsm_bts_trx_alloc(bts);

		trx->mo.nm_state.operational = NM_OPSTATE_ENABLED;
		trx->mo.nm_state.availability = NM_AVSTATE_OK;
		trx->mo.nm_state.administrative = NM_STATE_UNLOCKED;
		trx->bb_transc.mo.nm_state.operational = NM_OPSTATE_ENABLED;
		trx->bb_transc.mo.nm_state.availability = NM_AVSTATE_OK;
		trx->bb_transc.mo.nm_state.administrative = NM_STATE_UNLOCKED;

		/* 4 full rate and 4 half rate channels */
		for (i = 0; i < 8; i++) {
			trx->ts[i].pchan_from_config = pchan_from_str(ts_args[trx_i * 8 + i]);
			if (trx->ts[i].pchan_from_config == GSM_PCHAN_NONE)
				continue;
			trx->ts[i].mo.nm_state.operational = NM_OPSTATE_ENABLED;
			trx->ts[i].mo.nm_state.availability = NM_AVSTATE_OK;
			trx->ts[i].mo.nm_state.administrative = NM_STATE_UNLOCKED;
		}

		for (i = 0; i < ARRAY_SIZE(trx->ts); i++) {
			/* make sure ts->lchans[] get initialized */
			osmo_fsm_inst_dispatch(trx->ts[i].fi, TS_EV_RSL_READY, 0);
			osmo_fsm_inst_dispatch(trx->ts[i].fi, TS_EV_OML_READY, 0);

			/* Unused dyn TS start out as used for PDCH */
			switch (trx->ts[i].pchan_on_init) {
			case GSM_PCHAN_TCH_F_TCH_H_PDCH:
			case GSM_PCHAN_TCH_F_PDCH:
				trx->ts[i].pchan_is = GSM_PCHAN_PDCH;
				break;
			default:
				break;
			}
		}
	}

	for (i = 0; i < bsc_gsmnet->num_bts; i++) {
		if (gsm_generate_si(gsm_bts_num(bsc_gsmnet, i), SYSINFO_TYPE_2) <= 0)
			fprintf(stderr, "Error generating SI2\n");
	}
	return bts;
}

const char *ts_use_str(struct gsm_bts_trx_ts *ts)
{
	switch (ts->pchan_is) {
	case GSM_PCHAN_CCCH_SDCCH4:
		return "c+s4";

	case GSM_PCHAN_NONE:
		return "-";

	case GSM_PCHAN_TCH_F:
		if (lchan_state_is(&ts->lchan[0], LCHAN_ST_ESTABLISHED))
			return "TCH/F";
		else
			return "-";

	case GSM_PCHAN_TCH_H:
		if (lchan_state_is(&ts->lchan[0], LCHAN_ST_ESTABLISHED)
		    && lchan_state_is(&ts->lchan[1], LCHAN_ST_ESTABLISHED))
			return "TCH/HH";
		if (lchan_state_is(&ts->lchan[0], LCHAN_ST_ESTABLISHED))
			return "TCH/H-";
		if (lchan_state_is(&ts->lchan[1], LCHAN_ST_ESTABLISHED))
			return "TCH/-H";
		return "-";

	default:
		return gsm_pchan_name(ts->pchan_is);
	}
}

bool expect_ts_use(int bts_nr, int trx_nr, const char * const *ts_use)
{
	struct gsm_bts *bts;
	struct gsm_bts_trx *trx;
	int i;
	int mismatching_ts = -1;
	bts = gsm_bts_num(bsc_gsmnet, bts_nr);
	OSMO_ASSERT(bts);
	trx = gsm_bts_trx_num(bts, trx_nr);
	OSMO_ASSERT(trx);

	fprintf(stderr, "Expect TS use:");
	for (i = 0; i < 8; i++)
		fprintf(stderr, "\t%s", ts_use[i]);
	fprintf(stderr, "\n");
	fprintf(stderr, "   Got TS use:");

	for (i = 0; i < 8; i++) {
		struct gsm_bts_trx_ts *ts = &trx->ts[i];
		const char *use = ts_use_str(ts);

		fprintf(stderr, "\t%s", use);

		if (!strcmp(ts_use[i], "*"))
			continue;
		if (strcmp(ts_use[i], use) && mismatching_ts < 0)
			mismatching_ts = i;
	}
	fprintf(stderr, "\n");

	if (mismatching_ts >= 0) {
		fprintf(stderr, "Test failed: mismatching TS use in bts %d trx %d ts %d\n",
		       bts_nr, trx_nr, mismatching_ts);
		return false;
	}
	return true;
}

void create_conn(struct gsm_lchan *lchan)
{
	static unsigned int next_imsi = 0;
	char imsi[sizeof(lchan->conn->bsub->imsi)];
	struct gsm_network *net = lchan->ts->trx->bts->network;
	struct gsm_subscriber_connection *conn;
	struct mgcp_client *fake_mgcp_client = (void*)talloc_zero(net, int);

	conn = bsc_subscr_con_allocate(net);

	conn->user_plane.mgw_endpoint = osmo_mgcpc_ep_alloc(conn->fi,
							   GSCON_EV_FORGET_MGW_ENDPOINT,
							   fake_mgcp_client,
							   net->mgw.tdefs,
							   "test",
							   "fake endpoint");
	conn->sccp.msc = osmo_msc_data_alloc(net, 0);

	lchan->conn = conn;
	conn->lchan = lchan;

	/* Make up a new IMSI for this test, for logging the subscriber */
	next_imsi ++;
	snprintf(imsi, sizeof(imsi), "%06u", next_imsi);
	lchan->conn->bsub = bsc_subscr_find_or_create_by_imsi(net->bsc_subscribers, imsi, BSUB_USE_CONN);

	/* kick the FSM from INIT through to the ACTIVE state */
	osmo_fsm_inst_dispatch(conn->fi, GSCON_EV_MO_COMPL_L3, NULL);
	osmo_fsm_inst_dispatch(conn->fi, GSCON_EV_A_CONN_CFM, NULL);
}

struct gsm_lchan *lchan_act(struct gsm_lchan *lchan, int full_rate, const char *codec)
{
	/* serious hack into osmo_fsm */
	lchan->fi->state = LCHAN_ST_ESTABLISHED;
	lchan->ts->fi->state = TS_ST_IN_USE;
	lchan->type = full_rate ? GSM_LCHAN_TCH_F : GSM_LCHAN_TCH_H;

	if (lchan->ts->pchan_on_init == GSM_PCHAN_TCH_F_TCH_H_PDCH)
		lchan->ts->pchan_is = full_rate ? GSM_PCHAN_TCH_F : GSM_PCHAN_TCH_H;
	if (lchan->ts->pchan_on_init == GSM_PCHAN_TCH_F_PDCH) {
		OSMO_ASSERT(full_rate);
		lchan->ts->pchan_is = GSM_PCHAN_TCH_F;
	}

	LOG_LCHAN(lchan, LOGL_DEBUG, "activated by handover_test.c\n");

	create_conn(lchan);
	if (!strcasecmp(codec, "FR") && full_rate)
		lchan->tch_mode = GSM48_CMODE_SPEECH_V1;
	else if (!strcasecmp(codec, "HR") && !full_rate)
		lchan->tch_mode = GSM48_CMODE_SPEECH_V1;
	else if (!strcasecmp(codec, "EFR") && full_rate)
		lchan->tch_mode = GSM48_CMODE_SPEECH_EFR;
	else if (!strcasecmp(codec, "AMR")) {
		lchan->tch_mode = GSM48_CMODE_SPEECH_AMR;
		lchan->activate.info.s15_s0 = 0x0002;
	} else {
		printf("Given codec unknown\n");
		exit(EXIT_FAILURE);
	}

	lchan->conn->codec_list = (struct gsm0808_speech_codec_list){
		.codec = {
			{ .fi=true, .type=GSM0808_SCT_FR1, },
			{ .fi=true, .type=GSM0808_SCT_FR2, },
			{ .fi=true, .type=GSM0808_SCT_FR3, },
			{ .fi=true, .type=GSM0808_SCT_HR1, },
			{ .fi=true, .type=GSM0808_SCT_HR3, },
		},
		.len = 5,
	};

	return lchan;
}

struct gsm_lchan *create_lchan(struct gsm_bts *bts, int full_rate, const char *codec)
{
	struct gsm_lchan *lchan;

	lchan = lchan_select_by_type(bts, (full_rate) ? GSM_LCHAN_TCH_F : GSM_LCHAN_TCH_H);
	if (!lchan) {
		printf("No resource for lchan\n");
		exit(EXIT_FAILURE);
	}

	return lchan_act(lchan, full_rate, codec);
}

static void lchan_clear(struct gsm_lchan *lchan)
{
	lchan_release(lchan, true, false, 0);
}

static void ts_clear(struct gsm_bts_trx_ts *ts)
{
	struct gsm_lchan *lchan;
	ts_for_each_lchan(lchan, ts) {
		if (lchan_state_is(lchan, LCHAN_ST_UNUSED))
			continue;
		lchan_clear(lchan);
	}
}

bool set_ts_use(int bts_nr, int trx_nr, const char * const *ts_use)
{
	struct gsm_bts *bts;
	struct gsm_bts_trx *trx;
	int i;
	bts = gsm_bts_num(bsc_gsmnet, bts_nr);
	OSMO_ASSERT(bts);
	trx = gsm_bts_trx_num(bts, trx_nr);
	OSMO_ASSERT(trx);

	fprintf(stderr, "Setting TS use:");
	for (i = 0; i < 8; i++)
		fprintf(stderr, "\t%s", ts_use[i]);
	fprintf(stderr, "\n");

	for (i = 0; i < 8; i++) {
		struct gsm_bts_trx_ts *ts = &trx->ts[i];
		const char *want_use = ts_use[i];
		const char *is_use = ts_use_str(ts);

		if (!strcmp(want_use, "*"))
			continue;

		/* If it is already as desired, don't change anything */
		if (!strcmp(want_use, is_use))
			continue;

		if (!strcmp(want_use, "TCH/F")) {
			if (!ts_is_capable_of_pchan(ts, GSM_PCHAN_TCH_F)) {
				printf("Error: bts %d trx %d ts %d cannot be used as TCH/F\n",
				       bts_nr, trx_nr, i);
				return false;
			}
			ts_clear(ts);

			lchan_act(&ts->lchan[0], true, "AMR");
		} else if (!strcmp(want_use, "TCH/H-")
			   || !strcmp(want_use, "TCH/HH")
			   || !strcmp(want_use, "TCH/-H")) {
			bool act[2];
			int j;

			if (!ts_is_capable_of_pchan(ts, GSM_PCHAN_TCH_H)) {
				printf("Error: bts %d trx %d ts %d cannot be used as TCH/H\n",
				       bts_nr, trx_nr, i);
				return false;
			}

			if (ts->pchan_is != GSM_PCHAN_TCH_H)
				ts_clear(ts);

			act[0] = want_use[4] == 'H';
			act[1] = want_use[5] == 'H';

			for (j = 0; j < 2; j++) {
				if (lchan_state_is(&ts->lchan[j], LCHAN_ST_UNUSED)) {
					if (act[j])
						lchan_act(&ts->lchan[j], false, "AMR");
				} else if (!act[j])
					lchan_clear(&ts->lchan[j]);
			}
		} else if (!strcmp(want_use, "-") || !strcmp(want_use, "PDCH")) {
			ts_clear(ts);
		}
	}
	return true;
}

/* parse channel request */

static int got_chan_req = 0;
static struct gsm_lchan *chan_req_lchan = NULL;

static int parse_chan_act(struct gsm_lchan *lchan, uint8_t *data)
{
	chan_req_lchan = lchan;
	return 0;
}

static int parse_chan_rel(struct gsm_lchan *lchan, uint8_t *data)
{
	chan_req_lchan = lchan;
	return 0;
}

/* parse handover request */

static int got_ho_req = 0;
static struct gsm_lchan *ho_req_lchan = NULL;

static int parse_ho_command(struct gsm_lchan *lchan, uint8_t *data, int len)
{
	struct gsm48_hdr *gh = (struct gsm48_hdr *) data;
	struct gsm48_ho_cmd *ho = (struct gsm48_ho_cmd *) gh->data;
	int arfcn;
	struct gsm_bts *neigh;

	switch (gh->msg_type) {
	case GSM48_MT_RR_HANDO_CMD:
		arfcn = (ho->cell_desc.arfcn_hi << 8) | ho->cell_desc.arfcn_lo;

		/* look up trx. since every dummy bts uses different arfcn and
		 * only one trx, it is simple */
		llist_for_each_entry(neigh, &bsc_gsmnet->bts_list, list) {
			if (neigh->c0->arfcn != arfcn)
				continue;
			ho_req_lchan = lchan;
			return 0;
		}
		break;
	case GSM48_MT_RR_ASS_CMD:
		ho_req_lchan = lchan;
		return 0;
		break;
	default:
		fprintf(stderr, "Error, expecting HO or AS command\n");
		return -EINVAL;
	}

	return -1;
}

/* send channel activation ack */
static void send_chan_act_ack(struct gsm_lchan *lchan, int act)
{
	struct msgb *msg = msgb_alloc_headroom(256, 64, "RSL");
	struct abis_rsl_dchan_hdr *dh;

	dh = (struct abis_rsl_dchan_hdr *) msgb_put(msg, sizeof(*dh));
	dh->c.msg_discr = ABIS_RSL_MDISC_DED_CHAN;
	dh->c.msg_type = (act) ? RSL_MT_CHAN_ACTIV_ACK : RSL_MT_RF_CHAN_REL_ACK;
	dh->ie_chan = RSL_IE_CHAN_NR;
	dh->chan_nr = gsm_lchan2chan_nr(lchan);

	msg->dst = lchan->ts->trx->bts->c0->rsl_link;
	msg->l2h = (unsigned char *)dh;

	abis_rsl_rcvmsg(msg);
}

/* Send RLL Est Ind for SAPI[0] */
static void send_est_ind(struct gsm_lchan *lchan)
{
	struct msgb *msg = msgb_alloc_headroom(256, 64, "RSL");
	struct abis_rsl_rll_hdr *rh;
	uint8_t chan_nr = gsm_lchan2chan_nr(lchan);

	rh = (struct abis_rsl_rll_hdr *) msgb_put(msg, sizeof(*rh));
	rh->c.msg_discr = ABIS_RSL_MDISC_RLL;
	rh->c.msg_type = RSL_MT_EST_IND;
	rh->ie_chan = RSL_IE_CHAN_NR;
	rh->chan_nr = chan_nr;
	rh->ie_link_id = RSL_IE_LINK_IDENT;
	rh->link_id = 0x00;

	msg->dst = lchan->ts->trx->bts->c0->rsl_link;
	msg->l2h = (unsigned char *)rh;

	abis_rsl_rcvmsg(msg);
}

/* send handover complete */
static void send_ho_complete(struct gsm_lchan *lchan, bool success)
{
	struct msgb *msg = msgb_alloc_headroom(256, 64, "RSL");
	struct abis_rsl_rll_hdr *rh;
	uint8_t chan_nr = gsm_lchan2chan_nr(lchan);
	uint8_t *buf;
	struct gsm48_hdr *gh;
	struct gsm48_ho_cpl *hc;

	send_est_ind(lchan);
	osmo_fsm_inst_dispatch(lchan->fi, LCHAN_EV_RTP_READY, 0);

	rh = (struct abis_rsl_rll_hdr *) msgb_put(msg, sizeof(*rh));
	rh->c.msg_discr = ABIS_RSL_MDISC_RLL;
	rh->c.msg_type = RSL_MT_DATA_IND;
	rh->ie_chan = RSL_IE_CHAN_NR;
	rh->chan_nr = chan_nr;
	rh->ie_link_id = RSL_IE_LINK_IDENT;
	rh->link_id = 0x00;

	buf = msgb_put(msg, 3);
	buf[0] = RSL_IE_L3_INFO;
	buf[1] = (sizeof(*gh) + sizeof(*hc)) >> 8;
	buf[2] = (sizeof(*gh) + sizeof(*hc)) & 0xff;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	hc = (struct gsm48_ho_cpl *) msgb_put(msg, sizeof(*hc));

	gh->proto_discr = GSM48_PDISC_RR;
	gh->msg_type =
		success ? GSM48_MT_RR_HANDO_COMPL : GSM48_MT_RR_HANDO_FAIL;

	msg->dst = lchan->ts->trx->bts->c0->rsl_link;
	msg->l2h = (unsigned char *)rh;
	msg->l3h = (unsigned char *)gh;

	abis_rsl_rcvmsg(msg);
}

/* override, requires '-Wl,--wrap=abis_rsl_sendmsg'.
 * Catch RSL messages sent towards the BTS. */
int __real_abis_rsl_sendmsg(struct msgb *msg);
int __wrap_abis_rsl_sendmsg(struct msgb *msg)
{
	struct abis_rsl_dchan_hdr *dh = (struct abis_rsl_dchan_hdr *) msg->data;
	struct e1inp_sign_link *sign_link = msg->dst;
	int rc;
	struct gsm_lchan *lchan = rsl_lchan_lookup(sign_link->trx, dh->chan_nr, &rc);
	struct gsm_lchan *other_lchan;

	if (rc) {
		printf("rsl_lchan_lookup() failed\n");
		exit(1);
	}

	switch (dh->c.msg_type) {
	case RSL_MT_CHAN_ACTIV:
		rc = parse_chan_act(lchan, dh->data);
		if (rc == 0)
			got_chan_req = 1;
		break;
	case RSL_MT_RF_CHAN_REL:
		rc = parse_chan_rel(lchan, dh->data);
		if (rc == 0)
			send_chan_act_ack(chan_req_lchan, 0);

		/* send dyn TS back to PDCH if unused */
		switch (chan_req_lchan->ts->pchan_on_init) {
		case GSM_PCHAN_TCH_F_TCH_H_PDCH:
		case GSM_PCHAN_TCH_F_PDCH:
			switch (chan_req_lchan->ts->pchan_is) {
			case GSM_PCHAN_TCH_H:
				other_lchan = &chan_req_lchan->ts->lchan[
					(chan_req_lchan == &chan_req_lchan->ts->lchan[0])?
					1 : 0];
				if (lchan_state_is(other_lchan, LCHAN_ST_ESTABLISHED))
					break;
				/* else fall thru */
			case GSM_PCHAN_TCH_F:
				chan_req_lchan->ts->pchan_is = GSM_PCHAN_PDCH;
				break;
			default:
				break;
			}
			break;
		default:
			break;
		}

		break;
	case RSL_MT_DATA_REQ:
		rc = parse_ho_command(lchan, msg->l3h, msgb_l3len(msg));
		if (rc == 0)
			got_ho_req = 1;
		break;
	case RSL_MT_IPAC_CRCX:
		break;
	case RSL_MT_DEACTIVATE_SACCH:
		break;
	default:
		printf("unknown rsl message=0x%x\n", dh->c.msg_type);
	}
	return 0;
}

/* test cases */

static char *test_case_0[] = {
	"2",

	"Stay in better cell\n\n"
	"There are many neighbor cells, but only the current cell is the best\n"
	"cell, so no handover is performed\n",

	"create-n-bts", "7",
	"create-ms", "0", "TCH/F", "AMR",
	"expect-ts-use", "0", "0", "*", "TCH/F", "-", "-", "-", "-", "-", "-",
	"meas-rep", "0","0","1","0",
		"30","0",
		"6", "0","20", "1","21", "2","18", "3","20", "4","23", "5","19",
	"expect-no-chan",
	NULL
};

static char *test_case_1[] = {
	"2",

	"Handover to best better cell\n\n"
	"The best neighbor cell is selected\n",

	"create-n-bts", "7",
	"create-ms", "0", "TCH/F", "AMR",
	"expect-ts-use", "0", "0", "*", "TCH/F", "-", "-", "-", "-", "-", "-",
	"meas-rep", "0","0","1","0",
		"10","0",
		"6", "0","20", "1","21", "2","18", "3","20", "4","23", "5","19",
	"expect-chan", "5", "1",
	"ack-chan",
	"expect-ho", "0", "1",
	"ho-complete",
	"expect-ts-use", "0", "0", "*", "-", "-", "-", "-", "-", "-", "-",
	"expect-ts-use", "5", "0", "*", "TCH/F", "-", "-", "-", "-", "-", "-",
	NULL
};

static char *test_case_2[] = {
	"2",

	"Handover and Assignment must be enabled\n\n"
	"This test will start with disabled assignment and handover.  A\n"
	"better neighbor cell (assignment enabled) will not be selected and \n"
	"also no assignment from TCH/H to TCH/F to improve quality. There\n"
	"will be no handover nor assignment. After enabling assignment on the\n"
	"current cell, the MS will assign to TCH/F. After enabling handover\n"
	"in the current cell, but disabling in the neighbor cell, handover\n"
	"will not be performed, until it is enabled in the neighbor cell too.\n",

	"create-n-bts", "2",
	"afs-rxlev-improve", "0", "5",
	"create-ms", "0", "TCH/H", "AMR",
	"expect-ts-use", "0", "0", "*", "-", "-", "-", "-", "TCH/H-", "-", "-",
	"as-enable", "0", "0",
	"ho-enable", "0", "0",
	"meas-rep", "0","0","5","0", "0","0", "1","0","30",
	"expect-no-chan",
	"as-enable", "0", "1",
	"meas-rep", "0","0","5","0", "0","0", "1","0","30",
	"expect-chan", "0", "1",
	"ack-chan",
	"expect-ho", "0", "5",
	"ho-complete",
	"expect-ts-use", "0", "0", "*", "TCH/F", "-", "-", "-", "-", "-", "-",
	"ho-enable", "0", "1",
	"ho-enable", "1", "0",
	"meas-rep", "0","0","1","0", "0","0", "1","0","30",
	"expect-no-chan",
	"ho-enable", "1", "1",
	"meas-rep", "0","0","1","0", "0","0", "1","0","30",
	"expect-chan", "1", "1",
	"ack-chan",
	"expect-ho", "0", "1",
	"ho-complete",
	"expect-ts-use", "0", "0", "*", "-", "-", "-", "-", "-", "-", "-",
	"expect-ts-use", "1", "0", "*", "TCH/F", "-", "-", "-", "-", "-", "-",
	NULL
};

static char *test_case_3[] = {
	"2",

	"Penalty timer must not run\n\n"
	"The MS will try to handover to a better cell, but this will fail.\n"
	"Even though the cell is still better, handover will not be performed\n"
	"due to penalty timer after handover failure\n",

	"create-n-bts", "2",
	"create-ms", "0", "TCH/F", "AMR",
	"expect-ts-use", "0", "0", "*", "TCH/F", "-", "-", "-", "-", "-", "-",
	"meas-rep", "0","0","1","0", "20","0", "1","0","30",
	"expect-chan", "1", "1",
	"ack-chan",
	"expect-ho", "0", "1",
	"ho-failed",
	"expect-ts-use", "0", "0", "*", "TCH/F", "-", "-", "-", "-", "-", "-",
	"expect-ts-use", "1", "0", "*", "-", "-", "-", "-", "-", "-", "-",
	"meas-rep", "0","0","1","0", "20","0", "1","0","30",
	"expect-no-chan",
	NULL
};

static char *test_case_4[] = {
	"2",

	"TCH/H keeping with HR codec\n\n"
	"The MS is using half rate V1 codec, but the better cell is congested\n"
	"at TCH/H slots. As the congestion is removed, the handover takes\n"
	"place.\n",

	"create-n-bts", "2",
	"set-min-free", "1", "TCH/H", "4",
	"create-ms", "0", "TCH/H", "HR",
	"expect-ts-use", "0", "0", "*", "-", "-", "-", "-", "TCH/H-", "-", "-",
	"meas-rep", "0","0","5","0", "20","0", "1","0","30",
	"expect-no-chan",
	"set-min-free", "1", "TCH/H", "3",
	"meas-rep", "0","0","5","0", "20","0", "1","0","30",
	"expect-chan", "1", "5",
	"ack-chan",
	"expect-ho", "0", "5",
	"ho-complete",
	"expect-ts-use", "0", "0", "*", "-", "-", "-", "-", "-", "-", "-",
	"expect-ts-use", "1", "0", "*", "-", "-", "-", "-", "TCH/H-", "-", "-",
	NULL
};

static char *test_case_5[] = {
	"2",

	"TCH/F keeping with FR codec\n\n"
	"The MS is using full rate V1 codec, but the better cell is congested\n"
	"at TCH/F slots. As the congestion is removed, the handover takes\n"
	"place.\n",

	"create-n-bts", "2",
	"set-min-free", "1", "TCH/F", "4",
	"create-ms", "0", "TCH/F", "FR",
	"expect-ts-use", "0", "0", "*", "TCH/F", "-", "-", "-", "-", "-", "-",
	"meas-rep", "0","0","1","0", "20","0", "1","0","30",
	"expect-no-chan",
	"set-min-free", "1", "TCH/F", "3",
	"meas-rep", "0","0","1","0", "20","0", "1","0","30",
	"expect-chan", "1", "1",
	"ack-chan",
	"expect-ho", "0", "1",
	"ho-complete",
	"expect-ts-use", "0", "0", "*", "-", "-", "-", "-", "-", "-", "-",
	"expect-ts-use", "1", "0", "*", "TCH/F", "-", "-", "-", "-", "-", "-",
	NULL
};

static char *test_case_6[] = {
	"2",

	"TCH/F keeping with EFR codec\n\n"
	"The MS is using full rate V2 codec, but the better cell is congested\n"
	"at TCH/F slots. As the congestion is removed, the handover takes\n"
	"place.\n",

	"create-n-bts", "2",
	"set-min-free", "1", "TCH/F", "4",
	"create-ms", "0", "TCH/F", "EFR",
	"expect-ts-use", "0", "0", "*", "TCH/F", "-", "-", "-", "-", "-", "-",
	"meas-rep", "0","0","1","0", "20","0", "1","0","30",
	"expect-no-chan",
	"set-min-free", "1", "TCH/F", "3",
	"meas-rep", "0","0","1","0", "20","0", "1","0","30",
	"expect-chan", "1", "1",
	"ack-chan",
	"expect-ho", "0", "1",
	"ho-complete",
	"expect-ts-use", "0", "0", "*", "-", "-", "-", "-", "-", "-", "-",
	"expect-ts-use", "1", "0", "*", "TCH/F", "-", "-", "-", "-", "-", "-",
	NULL
};

static char *test_case_7[] = {
	"2",

	"TCH/F to TCH/H changing with AMR codec\n\n"
	"The MS is using AMR V3 codec, the better cell is congested at TCH/F\n"
	"slots. The handover is performed to non-congested TCH/H slots.\n",

	"create-n-bts", "2",
	"set-min-free", "1", "TCH/F", "4",
	"create-ms", "0", "TCH/F", "AMR",
	"expect-ts-use", "0", "0", "*", "TCH/F", "-", "-", "-", "-", "-", "-",
	"meas-rep", "0","0","1","0", "20","0", "1","0","30",
	"expect-chan", "1", "5",
	"ack-chan",
	"expect-ho", "0", "1",
	"ho-complete",
	"expect-ts-use", "0", "0", "*", "-", "-", "-", "-", "-", "-", "-",
	"expect-ts-use", "1", "0", "*", "-", "-", "-", "-", "TCH/H-", "-", "-",
	NULL
};

static char *test_case_8[] = {
	"2",

	"No handover to a cell with no slots available\n\n"
	"If no slot is available, no handover is performed\n",

	"create-n-bts", "2",
	"create-ms", "0", "TCH/F", "AMR",
	"expect-ts-use", "0", "0", "*", "TCH/F", "-", "-", "-", "-", "-", "-",
	"create-ms", "1", "TCH/F", "AMR",
	"create-ms", "1", "TCH/F", "AMR",
	"create-ms", "1", "TCH/F", "AMR",
	"create-ms", "1", "TCH/F", "AMR",
	"create-ms", "1", "TCH/H", "AMR",
	"create-ms", "1", "TCH/H", "AMR",
	"create-ms", "1", "TCH/H", "AMR",
	"create-ms", "1", "TCH/H", "AMR",
	"expect-ts-use", "1", "0", "*", "TCH/F", "TCH/F", "TCH/F", "TCH/F", "TCH/HH", "TCH/HH", "-",
	"meas-rep", "0","0","1","0", "0","0", "1","0","30",
	"expect-no-chan",
	NULL
};

static char *test_case_9[] = {
	"2",

	"No more parallel handovers, if max_unsync_ho is defined\n\n"
	"There are tree mobiles that want to handover, but only two can do\n"
	"it at a time, because the maximum number is limited to two.\n",

	"create-n-bts", "2",
	"set-max-ho", "1", "2",
	"create-ms", "0", "TCH/F", "AMR",
	"create-ms", "0", "TCH/F", "AMR",
	"create-ms", "0", "TCH/F", "AMR",
	"expect-ts-use", "0", "0", "*", "TCH/F", "TCH/F", "TCH/F", "-", "-", "-", "-",
	"meas-rep", "0","0","1","0", "0","0", "1","0","30",
	"expect-chan", "1", "1",
	"meas-rep", "0","0","2","0", "0","0", "1","0","30",
	"expect-chan", "1", "2",
	"meas-rep", "0","0","3","0", "0","0", "1","0","30",
	"expect-no-chan",
	NULL
};

static char *test_case_10[] = {
	"2",

	"Hysteresis\n\n"
	"If neighbor cell is better, handover is only performed if the\n"
	"amount of improvement is greater or equal hyteresis\n",

	"create-n-bts", "2",
	"create-ms", "0", "TCH/F", "AMR",
	"expect-ts-use", "0", "0", "*", "TCH/F", "-", "-", "-", "-", "-", "-",
	"meas-rep", "0","0","1","0", "27","0", "1","0","30",
	"expect-no-chan",
	"meas-rep", "0","0","1","0", "26","0", "1","0","30",
	"expect-chan", "1", "1",
	"ack-chan",
	"expect-ho", "0", "1",
	"ho-complete",
	"expect-ts-use", "0", "0", "*", "-", "-", "-", "-", "-", "-", "-",
	"expect-ts-use", "1", "0", "*", "TCH/F", "-", "-", "-", "-", "-", "-",
	NULL
};

static char *test_case_11[] = {
	"2",

	"No Hysteresis and minimum RX level\n\n"
	"If current cell's RX level is below mimium level, handover must be\n"
	"performed, no matter of the hysteresis. First do not perform\n"
	"handover to better neighbor cell, because the hysteresis is not\n"
	"met. Second do not perform handover because better neighbor cell is\n"
	"below minimum RX level. Third perform handover because current cell\n"
	"is below minimum RX level, even if the better neighbor cell (minimum\n"
	"RX level reached) does not meet the hysteresis.\n",

	"create-n-bts", "2",
	"create-ms", "0", "TCH/F", "AMR",
	"expect-ts-use", "0", "0", "*", "TCH/F", "-", "-", "-", "-", "-", "-",
	"meas-rep", "0","0","1","0", "10","0", "1","0","11",
	"expect-no-chan",
	"meas-rep", "0","0","1","0", "8","0", "1","0","9",
	"expect-no-chan",
	"meas-rep", "0","0","1","0", "9","0", "1","0","10",
	"expect-chan", "1", "1",
	"ack-chan",
	"expect-ho", "0", "1",
	"ho-complete",
	"expect-ts-use", "0", "0", "*", "-", "-", "-", "-", "-", "-", "-",
	"expect-ts-use", "1", "0", "*", "TCH/F", "-", "-", "-", "-", "-", "-",
	NULL
};

static char *test_case_12[] = {
	"2",

	"No handover to congested cell\n\n"
	"The better neighbor cell is congested, so no handover is performed.\n"
	"After the congestion is over, handover will be performed.\n",

	"create-n-bts", "2",
	"create-ms", "0", "TCH/F", "AMR",
	"expect-ts-use", "0", "0", "*", "TCH/F", "-", "-", "-", "-", "-", "-",
	"set-min-free", "1", "TCH/F", "4",
	"set-min-free", "1", "TCH/H", "4",
	"meas-rep", "0","0","1","0", "20","0", "1","0","30",
	"expect-no-chan",
	"set-min-free", "1", "TCH/F", "3",
	"set-min-free", "1", "TCH/H", "3",
	"meas-rep", "0","0","1","0", "20","0", "1","0","30",
	"expect-chan", "1", "1",
	"ack-chan",
	"expect-ho", "0", "1",
	"ho-complete",
	"expect-ts-use", "0", "0", "*", "-", "-", "-", "-", "-", "-", "-",
	"expect-ts-use", "1", "0", "*", "TCH/F", "-", "-", "-", "-", "-", "-",
	NULL
};

static char *test_case_13[] = {
	"2",

	"Handover to balance congestion\n\n"
	"The current and the better cell are congested, so no handover is\n"
	"performed. This is because handover would congest the neighbor cell\n"
	"more. After congestion raises in the current cell, the handover is\n"
	"performed to balance congestion\n",

	"create-n-bts", "2",
	"create-ms", "0", "TCH/F", "AMR",
	"expect-ts-use", "0", "0", "*", "TCH/F", "-", "-", "-", "-", "-", "-",
	"set-min-free", "0", "TCH/F", "4",
	"set-min-free", "0", "TCH/H", "4",
	"set-min-free", "1", "TCH/F", "4",
	"set-min-free", "1", "TCH/H", "4",
	"meas-rep", "0","0","1","0", "20","0", "1","0","30",
	"expect-no-chan",
	"create-ms", "0", "TCH/F", "AMR",
	"expect-ts-use", "0", "0", "*", "TCH/F", "TCH/F", "-", "-", "-", "-", "-",
	"meas-rep", "0","0","1","0", "20","0", "1","0","30",
	"expect-chan", "1", "1",
	"ack-chan",
	"expect-ho", "0", "1",
	"ho-complete",
	"expect-ts-use", "0", "0", "*", "-", "TCH/F", "-", "-", "-", "-", "-",
	"expect-ts-use", "1", "0", "*", "TCH/F", "-", "-", "-", "-", "-", "-",
	NULL
};

static char *test_case_14[] = {
	"2",

	"Handover to congested cell, if RX level is below minimum\n\n"
	"The better neighbor cell is congested, so no handover is performed.\n"
	"If the RX level of the current cell drops below minimum acceptable\n"
	"level, the handover is performed.\n",

	"create-n-bts", "2",
	"create-ms", "0", "TCH/F", "AMR",
	"expect-ts-use", "0", "0", "*", "TCH/F", "-", "-", "-", "-", "-", "-",
	"set-min-free", "1", "TCH/F", "4",
	"set-min-free", "1", "TCH/H", "4",
	"meas-rep", "0","0","1","0", "10","0", "1","0","30",
	"expect-no-chan",
	"meas-rep", "0","0","1","0", "9","0", "1","0","30",
	"expect-chan", "1", "1",
	"ack-chan",
	"expect-ho", "0", "1",
	"ho-complete",
	"expect-ts-use", "0", "0", "*", "-", "-", "-", "-", "-", "-", "-",
	"expect-ts-use", "1", "0", "*", "TCH/F", "-", "-", "-", "-", "-", "-",
	NULL
};

static char *test_case_15[] = {
	"2",

	"Handover to cell with worse RXLEV, if RXQUAL is below minimum\n\n"
	"The neighbor cell has worse RXLEV, so no handover is performed.\n"
	"If the RXQUAL of the current cell drops below minimum acceptable\n"
	"level, the handover is performed. It is also required that 10\n"
	"reports are received, before RXQUAL is checked.\n",
	/* (See also test 28, which tests for RXQUAL triggering HO to congested cell.) */
	/* TODO: bad RXQUAL may want to prefer assignment within the same cell to avoid interference.
	 * See Performance Enhancements in a Frequency Hopping GSM Network (Nielsen Wigard 2002), Chapter
	 * 2.1.1, "Interference" in the list of triggers on p.157. */

	"create-n-bts", "2",
	"create-ms", "0", "TCH/F", "AMR",
	"expect-ts-use", "0", "0", "*", "TCH/F", "-", "-", "-", "-", "-", "-",
	"meas-rep", "0","0","1","0", "40","6", "1","0","30",
	"expect-no-chan",
	"meas-rep", "0","0","1","0", "40","6", "1","0","30",
	"expect-no-chan",
	"meas-rep", "0","0","1","0", "40","6", "1","0","30",
	"expect-no-chan",
	"meas-rep", "0","0","1","0", "40","6", "1","0","30",
	"expect-no-chan",
	"meas-rep", "0","0","1","0", "40","6", "1","0","30",
	"expect-no-chan",
	"meas-rep", "0","0","1","0", "40","6", "1","0","30",
	"expect-no-chan",
	"meas-rep", "0","0","1","0", "40","6", "1","0","30",
	"expect-no-chan",
	"meas-rep", "0","0","1","0", "40","6", "1","0","30",
	"expect-no-chan",
	"meas-rep", "0","0","1","0", "40","6", "1","0","30",
	"expect-no-chan",
	"meas-rep", "0","0","1","0", "40","6", "1","0","30",
	"expect-chan", "1", "1",
	"ack-chan",
	"expect-ho", "0", "1",
	"ho-complete",
	"expect-ts-use", "0", "0", "*", "-", "-", "-", "-", "-", "-", "-",
	"expect-ts-use", "1", "0", "*", "TCH/F", "-", "-", "-", "-", "-", "-",
	NULL
};

static char *test_case_16[] = {
	"2",

	"Handover due to maximum TA exceeded\n\n"
	"The MS in the current (best) cell has reached maximum allowed timing\n"
	"advance. No handover is performed until the timing advance exceeds\n"
	"it. The originating cell is still the best, but no handover is\n"
	"performed back to that cell, because the penalty timer (due to\n"
	"maximum allowed timing advance) is running.\n",

	"create-n-bts", "2",
	"create-ms", "0", "TCH/F", "AMR",
	"expect-ts-use", "0", "0", "*", "TCH/F", "-", "-", "-", "-", "-", "-",
	"set-max-ta", "0", "5", /* of cell */
	"set-ta", "0", "5", /* of ms */
	"meas-rep", "0","0","1","0", "30","0", "1","0","20",
	"expect-no-chan",
	"set-ta", "0", "6", /* of ms */
	"meas-rep", "0","0","1","0", "30","0", "1","0","20",
	"expect-chan", "1", "1",
	"ack-chan",
	"expect-ho", "0", "1",
	"ho-complete",
	"expect-ts-use", "0", "0", "*", "-", "-", "-", "-", "-", "-", "-",
	"expect-ts-use", "1", "0", "*", "TCH/F", "-", "-", "-", "-", "-", "-",
	"meas-rep", "1","0","1","0", "20","0", "1","0","30",
	"expect-no-chan",
	NULL
};

static char *test_case_17[] = {
	"2",

	"Congestion check: No congestion\n\n"
	"Three cells have different number of used slots, but there is no\n"
	"congestion in any of these cells. No handover is performed.\n",

	"create-n-bts", "3",
	"set-min-free", "0", "TCH/F", "2",
	"set-min-free", "0", "TCH/H", "2",
	"set-min-free", "1", "TCH/F", "2",
	"set-min-free", "1", "TCH/H", "2",
	"set-min-free", "2", "TCH/F", "2",
	"set-min-free", "2", "TCH/H", "2",
	"create-ms", "0", "TCH/F", "AMR",
	"create-ms", "0", "TCH/F", "AMR",
	"create-ms", "0", "TCH/H", "AMR",
	"create-ms", "0", "TCH/H", "AMR",
	"create-ms", "1", "TCH/F", "AMR",
	"create-ms", "1", "TCH/H", "AMR",
	"expect-ts-use", "0", "0", "*", "TCH/F", "TCH/F", "-", "-", "TCH/HH", "-", "-",
	"expect-ts-use", "1", "0", "*", "TCH/F", "-", "-", "-", "TCH/H-", "-", "-",
	"meas-rep", "0","0","1","0", "30","0", "2","0","20","1","20",
	"expect-no-chan",
	"meas-rep", "0","0","2","0", "30","0", "2","0","20","1","20",
	"expect-no-chan",
	"meas-rep", "0","0","5","0", "30","0", "2","0","20","1","20",
	"expect-no-chan",
	"meas-rep", "0","0","5","1", "30","0", "2","0","20","1","20",
	"expect-no-chan",
	"meas-rep", "1","0","1","0", "30","0", "2","0","20","1","20",
	"expect-no-chan",
	"meas-rep", "1","0","5","0", "30","0", "2","0","20","1","20",
	"expect-no-chan",
	"congestion-check",
	"expect-no-chan",
	"expect-ts-use", "0", "0", "*", "TCH/F", "TCH/F", "-", "-", "TCH/HH", "-", "-",
	"expect-ts-use", "1", "0", "*", "TCH/F", "-", "-", "-", "TCH/H-", "-", "-",
	NULL
};

static char *test_case_18[] = {
	"2",

	"Congestion check: One out of three cells is congested\n\n"
	"Three cells have different number of used slots, but there is\n"
	"congestion at TCH/F in the first cell. Handover is performed with\n"
	"the best candidate.\n",

	"create-n-bts", "3",
	"set-min-free", "0", "TCH/F", "2",
	"set-min-free", "0", "TCH/H", "2",
	"set-min-free", "1", "TCH/F", "2",
	"set-min-free", "1", "TCH/H", "2",
	"set-min-free", "2", "TCH/F", "2",
	"set-min-free", "2", "TCH/H", "2",
	"create-ms", "0", "TCH/F", "AMR",
	"create-ms", "0", "TCH/F", "AMR",
	"create-ms", "0", "TCH/F", "AMR",
	"create-ms", "0", "TCH/H", "AMR",
	"create-ms", "0", "TCH/H", "AMR",
	"create-ms", "1", "TCH/F", "AMR",
	"create-ms", "1", "TCH/H", "AMR",
	"expect-ts-use", "0", "0", "*", "TCH/F", "TCH/F", "TCH/F", "-", "TCH/HH", "-", "-",
	"expect-ts-use", "1", "0", "*", "TCH/F", "-", "-", "-", "TCH/H-", "-", "-",
	"meas-rep", "0","0","1","0", "30","0", "2","0","20","1","20",
	"expect-no-chan",
	"meas-rep", "0","0","2","0", "30","0", "2","0","20","1","20",
	"expect-no-chan",
	"meas-rep", "0","0","3","0", "30","0", "2","0","21","1","20",
	"expect-no-chan",
	"meas-rep", "0","0","5","0", "30","0", "2","0","20","1","20",
	"expect-no-chan",
	"meas-rep", "0","0","5","1", "30","0", "2","0","20","1","20",
	"expect-no-chan",
	"meas-rep", "1","0","1","0", "30","0", "2","0","20","1","20",
	"expect-no-chan",
	"meas-rep", "1","0","5","0", "30","0", "2","0","20","1","20",
	"expect-no-chan",
	"expect-ts-use", "0", "0", "*", "TCH/F", "TCH/F", "TCH/F", "-", "TCH/HH", "-", "-",
	"expect-ts-use", "1", "0", "*", "TCH/F", "-", "-", "-", "TCH/H-", "-", "-",
	"congestion-check",
	"expect-chan", "1", "2",
	"ack-chan",
	"expect-ho", "0", "3", /* best candidate is MS 2 at BTS 0, TS 3 */
	"ho-complete",
	"expect-ts-use", "0", "0", "*", "TCH/F", "TCH/F", "-", "-", "TCH/HH", "-", "-",
	"expect-ts-use", "1", "0", "*", "TCH/F", "TCH/F", "-", "-", "TCH/H-", "-", "-",
	NULL
};

static char *test_case_19[] = {
	"2",

	"Congestion check: Balancing over congested cells\n\n"
	"Two cells are congested, but the second cell is less congested.\n"
	"Handover is performed to solve the congestion.\n",

	"create-n-bts", "2",
	"set-min-free", "0", "TCH/F", "4",
	"set-min-free", "1", "TCH/F", "4",
	"create-ms", "0", "TCH/F", "FR",
	"create-ms", "0", "TCH/F", "FR",
	"create-ms", "0", "TCH/F", "FR",
	"create-ms", "1", "TCH/F", "FR",
	"expect-ts-use", "0", "0", "*", "TCH/F", "TCH/F", "TCH/F", "-", "-", "-", "-",
	"expect-ts-use", "1", "0", "*", "TCH/F", "-", "-", "-", "-", "-", "-",
	"meas-rep", "0","0","1","0", "30","0", "1","0","20",
	"expect-no-chan",
	"meas-rep", "0","0","2","0", "30","0", "1","0","21",
	"expect-no-chan",
	"meas-rep", "0","0","3","0", "30","0", "1","0","20",
	"expect-no-chan",
	"meas-rep", "1","0","1","0", "30","0", "1","0","20",
	"expect-no-chan",
	"congestion-check",
	"expect-chan", "1", "2",
	"ack-chan",
	"expect-ho", "0", "2", /* best candidate is MS 1 at BTS 0, TS 2 */
	"ho-complete",
	"expect-ts-use", "0", "0", "*", "TCH/F", "-", "TCH/F", "-", "-", "-", "-",
	"expect-ts-use", "1", "0", "*", "TCH/F", "TCH/F", "-", "-", "-", "-", "-",
	NULL
};

static char *test_case_20[] = {
	"2",

	"Congestion check: Solving congestion by handover TCH/F -> TCH/H\n\n"
	"Two BTS, one MS in the first congested BTS must handover to\n"
	"non-congested TCH/H of second BTS, in order to solve congestion\n",
	"create-n-bts", "2",
	"set-min-free", "0", "TCH/F", "4",
	"set-min-free", "0", "TCH/H", "4",
	"set-min-free", "1", "TCH/F", "4",
	"create-ms", "0", "TCH/F", "AMR",
	"expect-ts-use", "0", "0", "*", "TCH/F", "-", "-", "-", "-", "-", "-",
	"meas-rep", "0","0","1","0", "30","0", "1","0","30",
	"expect-no-chan",
	"congestion-check",
	"expect-chan", "1", "5",
	"ack-chan",
	"expect-ho", "0", "1",
	"ho-complete",
	"expect-ts-use", "0", "0", "*", "-", "-", "-", "-", "-", "-", "-",
	"expect-ts-use", "1", "0", "*", "-", "-", "-", "-", "TCH/H-", "-", "-",
	NULL
};

static char *test_case_21[] = {
	"2",

	"Congestion check: Balancing congestion by handover TCH/F -> TCH/H\n\n"
	"Two BTS, one MS in the first congested BTS must handover to\n"
	"less-congested TCH/H of second BTS, in order to balance congestion\n",
	"create-n-bts", "2",
	"set-min-free", "0", "TCH/F", "4",
	"set-min-free", "0", "TCH/H", "4",
	"set-min-free", "1", "TCH/F", "4",
	"set-min-free", "1", "TCH/H", "4",
	"create-ms", "0", "TCH/F", "AMR",
	"create-ms", "0", "TCH/F", "AMR",
	"create-ms", "0", "TCH/H", "AMR",
	"expect-ts-use", "0", "0", "*", "TCH/F", "TCH/F", "-", "-", "TCH/H-", "-", "-",
	"meas-rep", "0","0","1","0", "30","0", "1","0","30",
	"expect-no-chan",
	"congestion-check",
	"expect-chan", "1", "1",
	"ack-chan",
	"expect-ho", "0", "1",
	"ho-complete",
	"expect-ts-use", "0", "0", "*", "-", "TCH/F", "-", "-", "TCH/H-", "-", "-",
	"expect-ts-use", "1", "0", "*", "TCH/F", "-", "-", "-", "-", "-", "-",
	NULL
};

static char *test_case_22[] = {
	"2",

	"Congestion check: Upgrading worst candidate from TCH/H -> TCH/F\n\n"
	"There is only one BTS. The TCH/H slots are congested. Since\n"
	"assignment is performed to less-congested TCH/F, the candidate with\n"
	"the worst RX level is chosen.\n",

	"create-n-bts", "1",
	"set-min-free", "0", "TCH/F", "4",
	"set-min-free", "0", "TCH/H", "4",
	"create-ms", "0", "TCH/H", "AMR",
	"create-ms", "0", "TCH/H", "AMR",
	"create-ms", "0", "TCH/H", "AMR",
	"expect-ts-use", "0", "0", "*", "-", "-", "-", "-", "TCH/HH", "TCH/H-", "-",
	"meas-rep", "0","0","5","0", "30","0", "0",
	"meas-rep", "0","0","5","1", "34","0", "0",
	"meas-rep", "0","0","6","0", "20","0", "0",
	"expect-no-chan",
	"congestion-check",
	"expect-chan", "0", "1",
	"ack-chan",
	"expect-ho", "0", "6",
	"ho-complete",
	"expect-ts-use", "0", "0", "*", "TCH/F", "-", "-", "-", "TCH/HH", "-", "-",
	NULL
};

static char *test_case_23[] = {
	"2",

	"Story: 'A neighbor is your friend'\n",

	"create-n-bts", "3",

	"print",
	"Andreas is driving along the coast, on a sunny june afternoon.\n"
	"Suddenly he is getting a call from his friend and neighbor Axel.\n"
	"\n"
	"What happens: Two MS are created, #0 for Axel, #1 for Andreas.",
	/* Axel */
	"create-ms", "2", "TCH/F", "AMR",
	/* andreas */
	"create-ms", "0", "TCH/F", "AMR",
	"expect-ts-use", "0", "0", "*", "TCH/F", "-", "-", "-", "-", "-", "-",
	"expect-ts-use", "1", "0", "*", "-", "-", "-", "-", "-", "-", "-",
	"expect-ts-use", "2", "0", "*", "TCH/F", "-", "-", "-", "-", "-", "-",
	"meas-rep", "0","0","1","0", "40","0", "1","0","30",
	"expect-no-chan",

	"print",
	"Axel asks Andreas if he would like to join them for a barbecue.\n"
	"Axel's house is right in the neighborhood and the weather is fine.\n"
	"Andreas agrees, so he drives to a close store to buy some barbecue\n"
	"skewers.\n"
	"\n"
	"What happens: While driving, a different cell (mounted atop the\n"
	"store) becomes better.",
	/* drive to bts 1 */
	"meas-rep", "0","0","1","0", "20","0", "1","0","35",
	"expect-chan", "1", "1",
	"ack-chan",
	"expect-ho", "0", "1",
	"ho-complete",
	"expect-ts-use", "0", "0", "*", "-", "-", "-", "-", "-", "-", "-",
	"expect-ts-use", "1", "0", "*", "TCH/F", "-", "-", "-", "-", "-", "-",
	"expect-ts-use", "2", "0", "*", "TCH/F", "-", "-", "-", "-", "-", "-",

	"print",
	"While Andreas is walking into the store, Axel asks, if he could also\n"
	"bring some beer. Andreas has problems understanding him: \"I have a\n"
	"bad reception here. The cell tower is right atop the store, but poor\n"
	"coverage inside. Can you repeat please?\"\n"
	"\n"
	"What happens: Inside the store the close cell is so bad, that\n"
	"handover back to the previous cell is required.",
	/* bts 1 becomes bad, so bts 0 helps out */
	"meas-rep", "1","0","1","0", "5","0", "1","0","20",
	"expect-chan", "0", "1",
	"ack-chan",
	"expect-ho", "1", "1",
	"ho-complete",
	"expect-ts-use", "0", "0", "*", "TCH/F", "-", "-", "-", "-", "-", "-",
	"expect-ts-use", "1", "0", "*", "-", "-", "-", "-", "-", "-", "-",
	"expect-ts-use", "2", "0", "*", "TCH/F", "-", "-", "-", "-", "-", "-",

	"print",
	"After Andreas bought skewers and beer, he leaves the store.\n"
	"\n"
	"What happens: Outside the store the close cell is better again, so\n"
	"handover back to the that cell is performed.",
	/* bts 1 becomes better again */
	"meas-rep", "0","0","1","0", "20","0", "1","0","35",
	"expect-chan", "1", "1",
	"ack-chan",
	"expect-ho", "0", "1",
	"ho-complete",
	"expect-ts-use", "0", "0", "*", "-", "-", "-", "-", "-", "-", "-",
	"expect-ts-use", "1", "0", "*", "TCH/F", "-", "-", "-", "-", "-", "-",
	"expect-ts-use", "2", "0", "*", "TCH/F", "-", "-", "-", "-", "-", "-",

	"print",
	/* bts 2 becomes better */
	"Andreas drives down to the lake where Axel's house is.\n"
	"\n"
	"What happens: There is a small cell at Axel's house, which becomes\n"
	"better, because the current cell has no good comverage at the lake.",
	"meas-rep", "1","0","1","0", "14","0", "2","0","2","1","63",
	"expect-chan", "2", "2",
	"ack-chan",
	"expect-ho", "1", "1",
	"ho-complete",
	"expect-ts-use", "0", "0", "*", "-", "-", "-", "-", "-", "-", "-",
	"expect-ts-use", "1", "0", "*", "-", "-", "-", "-", "-", "-", "-",
	"expect-ts-use", "2", "0", "*", "TCH/F", "TCH/F", "-", "-", "-", "-", "-",

	"print",
	"Andreas wonders why he still has good radio coverage: \"Last time it\n"
	"was so bad\". Axel says: \"I installed a pico cell in my house,\n"
	"now we can use our mobile phones down here at the lake.\"",

	NULL
};

static char *test_case_24[] = {
	"2",
	"No (or not enough) measurements for handover\n\n"
	"Do not solve congestion in cell, because there is no measurement.\n"
	"As soon as enough measurements available (1 in our case), perform\n"
	"handover. Afterwards the old cell becomes congested and the new\n"
	"cell is not. Do not perform handover until new measurements are\n"
	"received.\n",

	/* two cells, first in congested, but no handover */
	"create-n-bts", "2",
	"set-min-free", "0", "TCH/F", "4",
	"set-min-free", "0", "TCH/H", "4",
	"create-ms", "0", "TCH/F", "AMR",
	"congestion-check",
	"expect-no-chan",
	"expect-ts-use", "0", "0", "*", "TCH/F", "-", "-", "-", "-", "-", "-",

	/* send measurement and trigger congestion check */
	"meas-rep", "0","0","1","0", "20","0", "1","0","20",
	"expect-no-chan",
	"congestion-check",
	"expect-chan", "1", "1",
	"ack-chan",
	"expect-ho", "0", "1",
	"ho-complete",
	"expect-ts-use", "0", "0", "*", "-", "-", "-", "-", "-", "-", "-",
	"expect-ts-use", "1", "0", "*", "TCH/F", "-", "-", "-", "-", "-", "-",

	/* congest the first cell and remove congestion from second cell */
	"set-min-free", "0", "TCH/F", "0",
	"set-min-free", "0", "TCH/H", "0",
	"set-min-free", "1", "TCH/F", "4",
	"set-min-free", "1", "TCH/H", "4",

	/* no handover until measurements applied */
	"congestion-check",
	"expect-no-chan",
	"meas-rep", "1","0","1","0", "20","0", "1","0","20",
	"expect-no-chan",
	"congestion-check",
	"expect-chan", "0", "1",
	"ack-chan",
	"expect-ho", "1", "1",
	"ho-complete",
	"expect-ts-use", "0", "0", "*", "TCH/F", "-", "-", "-", "-", "-", "-",
	"expect-ts-use", "1", "0", "*", "-", "-", "-", "-", "-", "-", "-",
	NULL
};

static char *test_case_25[] = {
	"1",

	"Stay in better cell\n\n"
	"There are many neighbor cells, but only the current cell is the best\n"
	"cell, so no handover is performed\n",

	"create-n-bts", "7",
	"create-ms", "0", "TCH/F", "AMR",
	"expect-ts-use", "0", "0", "*", "TCH/F", "-", "-", "-", "-", "-", "-",
	"meas-rep", "0","0","1","0", "30","0",
		"6","0","20","1","21","2","18","3","20","4","23","5","19",
	"expect-no-chan",
	NULL
};

static char *test_case_26[] = {
	"1",

	"Handover to best better cell\n\n"
	"The best neighbor cell is selected\n",

	"create-n-bts", "7",
	"create-ms", "0", "TCH/F", "AMR",
	"expect-ts-use", "0", "0", "*", "TCH/F", "-", "-", "-", "-", "-", "-",
	"meas-rep", "0","0","1","0", "10","0",
		"6","0","20","1","21","2","18","3","20","4","23","5","19",
	"expect-chan", "5", "1",
	"ack-chan",
	"expect-ho", "0", "1",
	"ho-complete",
	"expect-ts-use", "0", "0", "*", "-", "-", "-", "-", "-", "-", "-",
	"expect-ts-use", "5", "0", "*", "TCH/F", "-", "-", "-", "-", "-", "-",
	NULL
};

static char *test_case_27[] = {
	"2",

	"Congestion check: Upgrading worst candidate from TCH/H -> TCH/F\n\n"
	"There is only one BTS. The TCH/H slots are congested. Since\n"
	"assignment is performed to less-congested TCH/F, the candidate with\n"
	"the worst RX level is chosen. (So far like test 22.)\n"
	"After that, trigger more congestion checks to ensure stability.\n",

	"create-n-bts", "1",
	"set-min-free", "0", "TCH/F", "2",
	"set-min-free", "0", "TCH/H", "4",
	"create-ms", "0", "TCH/H", "AMR",
	"create-ms", "0", "TCH/H", "AMR",
	"create-ms", "0", "TCH/H", "AMR",
	"expect-ts-use", "0", "0", "*", "-", "-", "-", "-", "TCH/HH", "TCH/H-", "-",
	"meas-rep", "0","0","5","0", "30","0", "0",
	"meas-rep", "0","0","5","1", "34","0", "0",
	"meas-rep", "0","0","6","0", "20","0", "0",
	"expect-no-chan",
	"congestion-check",
	"expect-chan", "0", "1",
	"ack-chan",
	"expect-ho", "0", "6",
	"ho-complete",
	"expect-ts-use", "0", "0", "*", "TCH/F", "-", "-", "-", "TCH/HH", "-", "-",
	"congestion-check",
	"expect-chan", "0", "2",
	"ack-chan",
	"expect-ho", "0", "5",
	"ho-complete",
	"expect-ts-use", "0", "0", "*", "TCH/F", "TCH/F", "-", "-", "TCH/-H", "-", "-",
	"congestion-check",
	"expect-no-chan",
	"congestion-check",
	"expect-no-chan",
	NULL
};

static char *test_case_28[] = {
	"2",

	"Handover to congested cell, if RX quality is below minimum\n\n"
	"The better neighbor cell is congested, so no handover is performed.\n"
	"If the RX quality of the current cell drops below minimum acceptable\n"
	"level, the handover is performed. It is also required that 10\n"
	"resports are received, before RX quality is checked.\n",

	"create-n-bts", "2",
	"create-ms", "0", "TCH/F", "AMR",
	"expect-ts-use", "0", "0", "*", "TCH/F", "-", "-", "-", "-", "-", "-",
	"set-min-free", "1", "TCH/F", "4",
	"set-min-free", "1", "TCH/H", "4",
	"meas-rep", "0","0","1","0", "30","6", "1","0","40",
	"expect-no-chan",
	"meas-rep", "0","0","1","0", "30","6", "1","0","40",
	"expect-no-chan",
	"meas-rep", "0","0","1","0", "30","6", "1","0","40",
	"expect-no-chan",
	"meas-rep", "0","0","1","0", "30","6", "1","0","40",
	"expect-no-chan",
	"meas-rep", "0","0","1","0", "30","6", "1","0","40",
	"expect-no-chan",
	"meas-rep", "0","0","1","0", "30","6", "1","0","40",
	"expect-no-chan",
	"meas-rep", "0","0","1","0", "30","6", "1","0","40",
	"expect-no-chan",
	"meas-rep", "0","0","1","0", "30","6", "1","0","40",
	"expect-no-chan",
	"meas-rep", "0","0","1","0", "30","6", "1","0","40",
	"expect-no-chan",
	"meas-rep", "0","0","1","0", "30","6", "1","0","40",
	"expect-chan", "1", "1",
	"ack-chan",
	"expect-ho", "0", "1",
	"ho-complete",
	"expect-ts-use", "0", "0", "*", "-", "-", "-", "-", "-", "-", "-",
	"expect-ts-use", "1", "0", "*", "TCH/F", "-", "-", "-", "-", "-", "-",
	NULL
};

static char *test_case_29[] = {
	"2",

	"Congestion check: Balancing congestion by handover TCH/F -> TCH/H\n\n"
	"One BTS, and TCH/F are considered congested, TCH/H are not.\n"
	,
	"create-n-bts", "1",
	"set-min-free", "0", "TCH/F", "3",
	"set-min-free", "0", "TCH/H", "0",
	"create-ms", "0", "TCH/F", "AMR",
	"create-ms", "0", "TCH/F", "AMR",
	"create-ms", "0", "TCH/H", "AMR",
	"expect-ts-use", "0", "0", "*", "TCH/F", "TCH/F", "-", "-", "TCH/H-", "-", "-",
	"meas-rep", "0","0","1","0", "30","0", "1","0","30",
	"expect-no-chan",
	"congestion-check",
	"expect-chan", "0", "5",
	"ack-chan",
	"expect-ho", "0", "1",
	"ho-complete",
	"expect-ts-use", "0", "0", "*", "-", "TCH/F", "-", "-", "TCH/HH", "-", "-",
	NULL
};

static char *test_case_30[] = {
	"2",

	"Congestion check: Balancing congestion by handover TCH/F -> TCH/H\n\n"
	"With dynamic timeslots.\n"
	"As soon as only one TCH/F is left, there should be HO to a dyn TS.\n"
	,
	"create-bts", "1", "c+s4", "TCH/F", "TCH/F", "TCH/F", "dyn", "dyn", "dyn", "PDCH",
	"set-min-free", "0", "TCH/F", "2",
	"set-min-free", "0", "TCH/H", "0",
	"as-enable", "0", "1",
	"set-ts-use", "0", "0", "*", "TCH/F", "TCH/F", "TCH/F", "TCH/F", "PDCH", "PDCH", "PDCH",
	"meas-rep", "0","0","1","0", "40","0", "1", "0","30",
	"meas-rep", "0","0","2","0", "40","0", "1", "0","30",
	"meas-rep", "0","0","3","0", "40","0", "1", "0","30",
	"meas-rep", "0","0","4","0", "40","0", "1", "0","30",
	"congestion-check",
	"expect-no-chan",
	"create-ms", "0", "TCH/F", "AMR",
	"meas-rep", "0","0","5","0", "40","0", "1", "0","30",
	"expect-ts-use", "0", "0", "*", "TCH/F", "TCH/F", "TCH/F", "TCH/F", "TCH/F", "PDCH", "PDCH",
	"congestion-check",
	"expect-chan", "0", "6",
	"ack-chan",
	"expect-ho", "0", "5",
	"ho-complete",
	"expect-ts-use", "0", "0", "*", "TCH/F", "TCH/F", "TCH/F", "TCH/F", "PDCH", "TCH/H-", "PDCH",
	"congestion-check",
	"expect-chan", "0", "6",
	"ack-chan",
	"expect-ho", "0", "4",
	"ho-complete",
	"expect-ts-use", "0", "0", "*", "TCH/F", "TCH/F", "TCH/F", "PDCH", "PDCH", "TCH/HH", "PDCH",
	"congestion-check",
	"expect-no-chan",
	"create-ms", "0", "TCH/F", "AMR",
	"meas-rep", "0","0","4","0", "40","0", "1", "0","30",
	"expect-ts-use", "0", "0", "*", "TCH/F", "TCH/F", "TCH/F", "TCH/F", "PDCH", "TCH/HH", "PDCH",
	"congestion-check",
	"expect-chan", "0", "5",
	"ack-chan",
	"expect-ho", "0", "4",
	"ho-complete",
	"expect-ts-use", "0", "0", "*", "TCH/F", "TCH/F", "TCH/F", "PDCH", "TCH/H-", "TCH/HH", "PDCH",
	"congestion-check",
	"expect-chan", "0", "5",
	"ack-chan",
	"expect-ho", "0", "1",
	"ho-complete",
	"expect-ts-use", "0", "0", "*", "-", "TCH/F", "TCH/F", "PDCH", "TCH/HH", "TCH/HH", "PDCH",
	"congestion-check",
	"expect-no-chan",
	"create-ms", "0", "TCH/F", "AMR",
	"meas-rep", "0","0","1","0", "40","0", "1", "0","30",
	"expect-ts-use", "0", "0", "*", "TCH/F", "TCH/F", "TCH/F", "PDCH", "TCH/HH", "TCH/HH", "PDCH",
	"congestion-check",
	"expect-chan", "0", "4",
	"ack-chan",
	"expect-ho", "0", "1",
	"ho-complete",
	"expect-ts-use", "0", "0", "*", "-", "TCH/F", "TCH/F", "TCH/H-", "TCH/HH", "TCH/HH", "PDCH",
	"congestion-check",
	"expect-chan", "0", "4",
	"ack-chan",
	"expect-ho", "0", "2",
	"ho-complete",
	"expect-ts-use", "0", "0", "*", "-", "-", "TCH/F", "TCH/HH", "TCH/HH", "TCH/HH", "PDCH",
	"congestion-check",
	"expect-no-chan",
	"create-ms", "0", "TCH/F", "AMR",
	"meas-rep", "0","0","1","0", "40","0", "1", "0","30",
	"expect-ts-use", "0", "0", "*", "TCH/F", "-", "TCH/F", "TCH/HH", "TCH/HH", "TCH/HH", "PDCH",
	"congestion-check",
	"expect-no-chan",
	"create-ms", "0", "TCH/F", "AMR",
	"meas-rep", "0","0","2","0", "40","0", "1", "0","30",
	"expect-ts-use", "0", "0", "*", "TCH/F", "TCH/F", "TCH/F", "TCH/HH", "TCH/HH", "TCH/HH", "PDCH",
	"congestion-check",
	"expect-no-chan",
	NULL
};

static char *test_case_31[] = {
	"2",

	"Congestion check: re-use half used TCH/H to avoid switching more dyn TS to TCH/H\n"
	,
	"create-bts", "1", "c+s4", "TCH/F", "TCH/F", "TCH/F", "dyn", "dyn", "dyn", "PDCH",
	"set-ts-use", "0", "0",  "*", "-", "-", "-", "PDCH", "TCH/H-", "PDCH", "PDCH",
	"create-ms", "0", "TCH/H", "AMR",
	"expect-ts-use", "0", "0",  "*", "-", "-", "-", "PDCH", "TCH/HH", "PDCH", "PDCH",
	NULL
};

static char *test_case_32[] = {
	"2",

	"Congestion check: favor moving a TCH/H that frees a half-used dyn TS completely\n"
	,
	"create-bts", "1", "c+s4", "dyn", "dyn", "dyn", "dyn", "dyn", "-", "-",
	"set-ts-use", "0", "0",  "*", "PDCH", "TCH/HH", "TCH/H-", "TCH/HH", "PDCH", "-", "-",
	"meas-rep", "0","0","2","1", "30","0", "0",
	"meas-rep", "0","0","3","0", "30","0", "0",
	"meas-rep", "0","0","4","0", "30","0", "0",
	"meas-rep", "0","0","4","1", "30","0", "0",
	/* pick one to move */
	"set-min-free", "0", "TCH/H", "6",
	"congestion-check",
	"expect-chan", "0", "1",
	"ack-chan",
	"expect-ho", "0", "3",
	"ho-complete",
	"expect-ts-use", "0", "0",  "*", "TCH/F", "TCH/HH", "PDCH", "TCH/HH", "PDCH", "-", "-",
	NULL
};

static char **test_cases[] =  {
	test_case_0,
	test_case_1,
	test_case_2,
	test_case_3,
	test_case_4,
	test_case_5,
	test_case_6,
	test_case_7,
	test_case_8,
	test_case_9,
	test_case_10,
	test_case_11,
	test_case_12,
	test_case_13,
	test_case_14,
	test_case_15,
	test_case_16,
	test_case_17,
	test_case_18,
	test_case_19,
	test_case_20,
	test_case_21,
	test_case_22,
	test_case_23,
	test_case_24,
	test_case_25,
	test_case_26,
	test_case_27,
	test_case_28,
	test_case_29,
	test_case_30,
	test_case_31,
	test_case_32,
};

static const struct log_info_cat log_categories[] = {
	[DHO] = {
		.name = "DHO",
		.description = "Hand-Over Process",
		.color = "\033[1;38m",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
	[DHODEC] = {
		.name = "DHODEC",
		.description = "Hand-Over Decision",
		.color = "\033[1;38m",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
	[DMEAS] = {
		.name = "DMEAS",
		.description = "Radio Measurement Processing",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
	[DREF] = {
		.name = "DREF",
		.description = "Reference Counting",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
	[DRSL] = {
		.name = "DRSL",
		.description = "A-bis Radio Signalling Link (RSL)",
		.color = "\033[1;35m",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
	[DRR] = {
		.name = "DRR",
		.description = "RR",
		.color = "\033[1;35m",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
	[DRLL] = {
		.name = "DRLL",
		.description = "RLL",
		.color = "\033[1;35m",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
	[DMSC] = {
		.name = "DMSC",
		.description = "Mobile Switching Center",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
	[DCHAN] = {
		.name = "DCHAN",
		.description = "lchan FSM",
		.color = "\033[1;32m",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
	[DTS] = {
		.name = "DTS",
		.description = "timeslot FSM",
		.color = "\033[1;31m",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
	[DAS] = {
		.name = "DAS",
		.description = "assignment FSM",
		.color = "\033[1;33m",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
};

const struct log_info log_info = {
	.cat = log_categories,
	.num_cat = ARRAY_SIZE(log_categories),
};

struct gsm_bts *bts_by_num_str(const char *num_str)
{
	struct gsm_bts *bts = gsm_bts_num(bsc_gsmnet, atoi(num_str));
	OSMO_ASSERT(bts);
	return bts;
}

int main(int argc, char **argv)
{
	char **test_case;
	int i;
	int algorithm;
	int test_case_i;
	int last_test_i;

	ctx = talloc_named_const(NULL, 0, "handover_test");
	msgb_talloc_ctx_init(ctx, 0);

	test_case_i = argc > 1? atoi(argv[1]) : -1;
	last_test_i = ARRAY_SIZE(test_cases) - 1;

	if (test_case_i < 0 || test_case_i > last_test_i) {
		for (i = 0; i <= last_test_i; i++) {
			printf("Test #%d (algorithm %s):\n%s\n", i,
				test_cases[i][0], test_cases[i][1]);
		}
		printf("\nPlease specify test case number 0..%d\n", last_test_i);
		return EXIT_FAILURE;
	}

	osmo_init_logging2(ctx, &log_info);

	log_set_print_category(osmo_stderr_target, 1);
	log_set_print_category_hex(osmo_stderr_target, 0);
	log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_BASENAME);
	osmo_fsm_log_addr(false);

	bsc_network_alloc();
	if (!bsc_gsmnet)
		exit(1);

	ts_fsm_init();
	lchan_fsm_init();
	bsc_subscr_conn_fsm_init();
	handover_fsm_init();

	ho_set_algorithm(bsc_gsmnet->ho, 2);
	ho_set_ho_active(bsc_gsmnet->ho, true);
	ho_set_hodec2_as_active(bsc_gsmnet->ho, true);
	ho_set_hodec2_min_rxlev(bsc_gsmnet->ho, -100);
	ho_set_hodec2_rxlev_avg_win(bsc_gsmnet->ho, 1);
	ho_set_hodec2_rxlev_neigh_avg_win(bsc_gsmnet->ho, 1);
	ho_set_hodec2_rxqual_avg_win(bsc_gsmnet->ho, 10);
	ho_set_hodec2_pwr_hysteresis(bsc_gsmnet->ho, 3);
	ho_set_hodec2_pwr_interval(bsc_gsmnet->ho, 1);
	ho_set_hodec2_afs_bias_rxlev(bsc_gsmnet->ho, 0);
	ho_set_hodec2_min_rxqual(bsc_gsmnet->ho, 5);
	ho_set_hodec2_afs_bias_rxqual(bsc_gsmnet->ho, 0);
	ho_set_hodec2_max_distance(bsc_gsmnet->ho, 9999);
	ho_set_hodec2_ho_max(bsc_gsmnet->ho, 9999);
	ho_set_hodec2_penalty_max_dist(bsc_gsmnet->ho, 300);
	ho_set_hodec2_penalty_failed_ho(bsc_gsmnet->ho, 60);
	ho_set_hodec2_penalty_failed_as(bsc_gsmnet->ho, 60);

	/* We don't really need any specific model here */
	bts_model_unknown_init();

	test_case = test_cases[test_case_i];

	fprintf(stderr, "--------------------\n");
	fprintf(stderr, "Performing the following test %d (algorithm %s):\n%s",
		test_case_i, test_case[0], test_case[1]);
	algorithm = atoi(test_case[0]);
	test_case += 2;
	fprintf(stderr, "--------------------\n");

	/* Disable the congestion check timer, we will trigger manually. */
	bsc_gsmnet->hodec2.congestion_check_interval_s = 0;

	handover_decision_1_init();
	hodec2_init(bsc_gsmnet);

	while (*test_case) {
		if (!strcmp(*test_case, "create-n-bts")) {
			int n = atoi(test_case[1]);
			for (i = 0; i < n; i++)
				create_bts(1, bts_default_ts);
			test_case += 2;
		} else
		if (!strcmp(*test_case, "create-bts")) {
			/* new BTS with one TRX:
			 * "create-bts", "1", "CCCH+SDCCH4", "TCH/F", "TCH/F", "TCH/F", "TCH/F", "TCH/H", "TCH/H", "PDCH",
			 *
			 * new BTS with two TRX:
			 * "create-bts", "2", "CCCH+SDCCH4", "TCH/F", "TCH/F", "TCH/F", "TCH/F", "TCH/H", "TCH/H", "PDCH",
			 *                    "SDCCH8", "TCH/F", "TCH/F", "TCH/F", "TCH/F", "TCH/H", "TCH/H", "PDCH",
			 */
			int num_trx = atoi(test_case[1]);
			const char * const * ts_cfg = (void*)&test_case[2];
			create_bts(num_trx, ts_cfg);
			test_case += 2 + 8 * num_trx;
		} else
		if (!strcmp(*test_case, "as-enable")) {
			fprintf(stderr, "- Set assignment enable state at "
				"BTS %s to %s\n", test_case[1], test_case[2]);
			ho_set_hodec2_as_active(bts_by_num_str(test_case[1])->ho, atoi(test_case[2]));
			test_case += 3;
		} else
		if (!strcmp(*test_case, "ho-enable")) {
			fprintf(stderr, "- Set handover enable state at "
				"BTS %s to %s\n", test_case[1], test_case[2]);
			ho_set_ho_active(bts_by_num_str(test_case[1])->ho, atoi(test_case[2]));
			test_case += 3;
		} else
		if (!strcmp(*test_case, "afs-rxlev-improve")) {
			fprintf(stderr, "- Set afs RX level improvement at "
				"BTS %s to %s\n", test_case[1], test_case[2]);
			ho_set_hodec2_afs_bias_rxlev(bts_by_num_str(test_case[1])->ho, atoi(test_case[2]));
			test_case += 3;
		} else
		if (!strcmp(*test_case, "afs-rxqual-improve")) {
			fprintf(stderr, "- Set afs RX quality improvement at "
				"BTS %s to %s\n", test_case[1], test_case[2]);
			ho_set_hodec2_afs_bias_rxqual(bts_by_num_str(test_case[1])->ho, atoi(test_case[2]));
			test_case += 3;
		} else
		if (!strcmp(*test_case, "set-min-free")) {
			fprintf(stderr, "- Setting minimum required free %s "
				"slots at BTS %s to %s\n", test_case[2],
				test_case[1], test_case[3]);
			if (!strcmp(test_case[2], "TCH/F"))
				ho_set_hodec2_tchf_min_slots(bts_by_num_str(test_case[1])->ho, atoi(test_case[3]));
			else
				ho_set_hodec2_tchh_min_slots(bts_by_num_str(test_case[1])->ho, atoi(test_case[3]));
			test_case += 4;
		} else
		if (!strcmp(*test_case, "set-max-ho")) {
			fprintf(stderr, "- Setting maximum parallel handovers "
				"at BTS %s to %s\n", test_case[1],
				test_case[2]);
			ho_set_hodec2_ho_max( bts_by_num_str(test_case[1])->ho, atoi(test_case[2]));
			test_case += 3;
		} else
		if (!strcmp(*test_case, "set-max-ta")) {
			fprintf(stderr, "- Setting maximum timing advance "
				"at BTS %s to %s\n", test_case[1],
				test_case[2]);
			ho_set_hodec2_max_distance(bts_by_num_str(test_case[1])->ho, atoi(test_case[2]));
			test_case += 3;
		} else
		if (!strcmp(*test_case, "create-ms")) {
			const char *bts_nr_str = test_case[1];
			const char *tch_type = test_case[2];
			const char *codec = test_case[3];
			struct gsm_lchan *lchan;
			fprintf(stderr, "- Creating mobile at BTS %s on "
				"%s with %s codec\n", bts_nr_str, tch_type, codec);
			lchan = create_lchan(bts_by_num_str(bts_nr_str),
				!strcmp(tch_type, "TCH/F"), codec);
			if (!lchan) {
				printf("Failed to create lchan!\n");
				return EXIT_FAILURE;
			}
			fprintf(stderr, " * New MS is at BTS %d TS %d\n",
				lchan->ts->trx->bts->nr,
				lchan->ts->nr);
			test_case += 4;
		} else
		if (!strcmp(*test_case, "set-ta")) {
			fprintf(stderr, "- Setting maximum timing advance "
				"at MS %s to %s\n", test_case[1],
				test_case[2]);
			meas_ta_ms = atoi(test_case[2]);
			test_case += 3;
		} else
		if (!strcmp(*test_case, "meas-rep")) {
			/* meas-rep <bts-nr> <trx-nr> <ts-nr> <lchan-nr> <rxlev> <rxqual> <nr-of-neighbors> [<cell-idx> <rxlev> [...]] */
			int n;
			struct gsm_bts *bts;
			struct gsm_bts_trx *trx;
			struct gsm_bts_trx_ts *ts;
			struct gsm_lchan *lc;
			int bts_nr = atoi(test_case[1]);
			int trx_nr = atoi(test_case[2]);
			int ts_nr = atoi(test_case[3]);
			int ss_nr = atoi(test_case[4]);
			meas_dl_rxlev = atoi(test_case[5]);
			meas_dl_rxqual = atoi(test_case[6]);
			n = atoi(test_case[7]);

			bts = gsm_bts_num(bsc_gsmnet, bts_nr);
			trx = gsm_bts_trx_num(bts, trx_nr);
			ts = &trx->ts[ts_nr];
			lc = &ts->lchan[ss_nr];

			if (!lchan_state_is(lc, LCHAN_ST_ESTABLISHED)) {
				printf("Error: sending measurement report for %d-%d-%d-%d which is in state %s\n",
				       bts_nr, trx_nr, ts_nr, ss_nr,
				       lchan_state_name(lc));
				exit(1);
			}

			fprintf(stderr, "- Sending measurement report from "
				"%d-%d-%d-%d (rxlev=%d, rxqual=%d)\n",
				bts_nr, trx_nr, ts_nr, ss_nr,
				meas_dl_rxlev, meas_dl_rxqual);
			meas_num_nc = n;
			test_case += 8;
			for (i = 0; i < n; i++) {
				int nr = atoi(test_case[0]);
				/* since our bts is not in the list of neighbor
				 * cells, we need to shift */
				if (nr >= lc->ts->trx->bts->nr)
					nr++;
				fprintf(stderr, " * Neighbor cell #%s, actual "
					"BTS %d (rxlev=%s)\n", test_case[0], nr,
					test_case[1]);
				meas_bcch_f_nc[i] = atoi(test_case[0]);
					/* bts number, not counting our own */
				meas_rxlev_nc[i] = atoi(test_case[1]);
				meas_bsic_nc[i] = 0x3f;
				test_case += 2;
			}
			got_chan_req = 0;
			gen_meas_rep(lc);
		} else
		if (!strcmp(*test_case, "congestion-check")) {
			fprintf(stderr, "- Triggering congestion check\n");
			got_chan_req = 0;
			if (algorithm == 2)
				hodec2_congestion_check(bsc_gsmnet);
			test_case += 1;
		} else
		if (!strcmp(*test_case, "expect-chan")) {
			fprintf(stderr, "- Expecting channel request at BTS %s "
				"TS %s\n", test_case[1], test_case[2]);
			if (!got_chan_req) {
				printf("Test failed, because no channel was "
					"requested\n");
				return EXIT_FAILURE;
			}
			fprintf(stderr, " * Got channel request at BTS %d "
				"TS %d\n", chan_req_lchan->ts->trx->bts->nr,
				chan_req_lchan->ts->nr);
			if (chan_req_lchan->ts->trx->bts->nr
						!= atoi(test_case[1])) {
				printf("Test failed, because channel was not "
					"requested on expected BTS\n");
				return EXIT_FAILURE;
			}
			if (chan_req_lchan->ts->nr != atoi(test_case[2])) {
				printf("Test failed, because channel was not "
					"requested on expected TS\n");
				return EXIT_FAILURE;
			}
			test_case += 3;
		} else
		if (!strcmp(*test_case, "expect-no-chan")) {
			fprintf(stderr, "- Expecting no channel request\n");
			if (got_chan_req) {
				fprintf(stderr, " * Got channel request at "
					"BTS %d TS %d\n",
					chan_req_lchan->ts->trx->bts->nr,
					chan_req_lchan->ts->nr);
				printf("Test failed, because channel was "
					"requested\n");
				return EXIT_FAILURE;
			}
			fprintf(stderr, " * Got no channel request\n");
			test_case += 1;
		} else
		if (!strcmp(*test_case, "expect-ho")) {
			fprintf(stderr, "- Expecting handover/assignment "
				"request at BTS %s TS %s\n", test_case[1],
				test_case[2]);
			if (!got_ho_req) {
				printf("Test failed, because no handover was "
					"requested\n");
				return EXIT_FAILURE;
			}
			fprintf(stderr, " * Got handover/assignment request at "
				"BTS %d TS %d\n",
				ho_req_lchan->ts->trx->bts->nr,
				ho_req_lchan->ts->nr);
			if (ho_req_lchan->ts->trx->bts->nr
							!= atoi(test_case[1])) {
				printf("Test failed, because "
					"handover/assignment was not commanded "
					"at the expected BTS\n");
				return EXIT_FAILURE;
			}
			if (ho_req_lchan->ts->nr != atoi(test_case[2])) {
				printf("Test failed, because "
					"handover/assignment was not commanded "
					"at the expected TS\n");
				return EXIT_FAILURE;
			}
			test_case += 3;
		} else
		if (!strcmp(*test_case, "ack-chan")) {
			fprintf(stderr, "- Acknowledging channel request\n");
			if (!got_chan_req) {
				printf("Cannot ack channel, because no "
					"request\n");
				return EXIT_FAILURE;
			}
			test_case += 1;
			got_ho_req = 0;
			send_chan_act_ack(chan_req_lchan, 1);
		} else
		if (!strcmp(*test_case, "ho-complete")) {
			fprintf(stderr, "- Acknowledging handover/assignment "
				"request\n");
			if (!got_chan_req) {
				printf("Cannot ack handover/assignment, "
					"because no chan request\n");
				return EXIT_FAILURE;
			}
			if (!got_ho_req) {
				printf("Cannot ack handover/assignment, "
					"because no ho request\n");
				return EXIT_FAILURE;
			}
			test_case += 1;
			got_chan_req = 0;
			got_ho_req = 0;
			send_ho_complete(chan_req_lchan, true);
		} else
		if (!strcmp(*test_case, "ho-failed")) {
			fprintf(stderr, "- Making handover fail\n");
			if (!got_chan_req) {
				printf("Cannot fail handover, because no chan "
					"request\n");
				return EXIT_FAILURE;
			}
			test_case += 1;
			got_chan_req = 0;
			got_ho_req = 0;
			send_ho_complete(ho_req_lchan, false);
		} else
		if (!strcmp(*test_case, "expect-ts-use")) {
			/* expect-ts-use <bts-nr> <trx-nr> 8x<ts-use>
			 * e.g.
			 * expect-ts-use 0 0  - TCH/F - - TCH/H- TCH/HH TCH/-H PDCH
			 * TCH/F: one FR call.
			 * TCH/H-: HR TS with first subslot used as TCH/H, other subslot unused.
			 * TCH/HH: HR TS with both subslots used as TCH/H
			 * TCH/-H: HR TS with only second subslot used as TCH/H
			 * PDCH: TS used for PDCH (e.g. unused dynamic TS)
			 */
			int bts_nr = atoi(test_case[1]);
			int trx_nr = atoi(test_case[2]);
			const char * const * ts_use = (void*)&test_case[3];
			if (!expect_ts_use(bts_nr, trx_nr, ts_use))
				return EXIT_FAILURE;
			test_case += 1 + 2 + 8;
		} else
		if (!strcmp(*test_case, "set-ts-use")) {
			/* set-ts-use <bts-nr> <trx-nr> 8x<ts-use>
			 * e.g.
			 * set-ts-use 0 0  * TCH/F - - TCH/H- TCH/HH TCH/-H PDCH
			 * '*': keep as is
			 * TCH/F: one FR call.
			 * TCH/H-: HR TS with first subslot used as TCH/H, other subslot unused.
			 * TCH/HH: HR TS with both subslots used as TCH/H
			 * TCH/-H: HR TS with only second subslot used as TCH/H
			 * PDCH: TS used for PDCH (e.g. unused dynamic TS)
			 */
			int bts_nr = atoi(test_case[1]);
			int trx_nr = atoi(test_case[2]);
			const char * const * ts_use = (void*)&test_case[3];
			if (!set_ts_use(bts_nr, trx_nr, ts_use))
				return EXIT_FAILURE;
			if (!expect_ts_use(bts_nr, trx_nr, ts_use))
				return EXIT_FAILURE;
			test_case += 1 + 2 + 8;
		} else
		if (!strcmp(*test_case, "print")) {
			fprintf(stderr, "\n%s\n\n", test_case[1]);
			test_case += 2;
		} else {
			printf("Unknown test command '%s', please fix!\n",
				*test_case);
			return EXIT_FAILURE;
		}

		{
			/* Help the lchan out of releasing states */
			struct gsm_bts *bts;
			llist_for_each_entry(bts, &bsc_gsmnet->bts_list, list) {
				struct gsm_bts_trx *trx;
				llist_for_each_entry(trx, &bts->trx_list, list) {
					int ts_nr;
					for (ts_nr = 0; ts_nr < TRX_NR_TS; ts_nr++) {
						struct gsm_lchan *lchan;
						ts_for_each_lchan(lchan, &trx->ts[ts_nr]) {

							if (lchan->fi && lchan->fi->state == LCHAN_ST_WAIT_BEFORE_RF_RELEASE) {
								osmo_fsm_inst_state_chg(lchan->fi, LCHAN_ST_WAIT_RF_RELEASE_ACK, 0, 0);
								osmo_fsm_inst_dispatch(lchan->fi, LCHAN_EV_RSL_RF_CHAN_REL_ACK, 0);
							}
						}
					}
				}
			}
		}
	}

	fprintf(stderr, "--------------------\n");

	printf("Test OK\n");

	fprintf(stderr, "--------------------\n");

	talloc_free(ctx);
	return EXIT_SUCCESS;
}

void rtp_socket_free() {}
void rtp_send_frame() {}
void rtp_socket_upstream() {}
void rtp_socket_create() {}
void rtp_socket_connect() {}
void rtp_socket_proxy() {}
void trau_mux_unmap() {}
void trau_mux_map_lchan() {}
void trau_recv_lchan() {}
void trau_send_frame() {}
int osmo_bsc_sigtran_send(struct gsm_subscriber_connection *conn, struct msgb *msg) { return 0; }
int osmo_bsc_sigtran_open_conn(struct gsm_subscriber_connection *conn, struct msgb *msg) { return 0; }
void bsc_sapi_n_reject(struct gsm_subscriber_connection *conn, uint8_t dlci, enum gsm0808_cause cause) {}
void bsc_cipher_mode_compl(struct gsm_subscriber_connection *conn, struct msgb *msg, uint8_t chosen_encr) {}
int bsc_compl_l3(struct gsm_lchan *lchan, struct msgb *msg, uint16_t chosen_channel)
{ return 0; }
int bsc_paging_start(struct bsc_paging_params *params)
{ return 0; }
void bsc_dtap(struct gsm_subscriber_connection *conn, uint8_t link_id, struct msgb *msg) {}
void bsc_assign_compl(struct gsm_subscriber_connection *conn, uint8_t rr_cause) {}
void bsc_cm_update(struct gsm_subscriber_connection *conn,
		   const uint8_t *cm2, uint8_t cm2_len,
		   const uint8_t *cm3, uint8_t cm3_len) {}
struct gsm0808_handover_required;
int bsc_tx_bssmap_ho_required(struct gsm_lchan *lchan, const struct gsm0808_cell_id_list2 *target_cells)
{ return 0; }
int bsc_tx_bssmap_ho_request_ack(struct gsm_subscriber_connection *conn, struct msgb *rr_ho_command)
{ return 0; }
int bsc_tx_bssmap_ho_detect(struct gsm_subscriber_connection *conn) { return 0; }
enum handover_result bsc_tx_bssmap_ho_complete(struct gsm_subscriber_connection *conn,
					       struct gsm_lchan *lchan) { return HO_RESULT_OK; }
void bsc_tx_bssmap_ho_failure(struct gsm_subscriber_connection *conn) {}
void osmo_bsc_sigtran_tx_reset(void) {}
void osmo_bsc_sigtran_tx_reset_ack(void) {}
void osmo_bsc_sigtran_reset(void) {}
void bssmap_reset_alloc(void) {}
void bssmap_reset_is_conn_ready(void) {}
