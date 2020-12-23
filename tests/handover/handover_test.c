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
#include <osmocom/vty/vty.h>

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
#include <osmocom/bsc/vty.h>

#include "../../bscconfig.h"

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
uint8_t meas_ul_rxlev = 0, meas_ul_rxqual = 0;
uint8_t meas_tx_power_ms = 0, meas_tx_power_bs = 0;
uint8_t meas_dtx_ms = 0, meas_dtx_bs = 0, meas_nr = 0;
char *codec_tch_f = NULL;
char *codec_tch_h = NULL;

struct neighbor_meas {
	uint8_t rxlev;
	uint8_t bsic;
	uint8_t bcch_f;
};

static void gen_meas_rep(struct gsm_lchan *lchan,
			 uint8_t rxlev, uint8_t rxqual, uint8_t ta,
			 int neighbors_count, struct neighbor_meas *neighbors)
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
	l1i[1] = ta;
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
	mr->rxlev_full = rxlev;
	mr->rxlev_sub = rxlev;
	mr->rxqual_full = rxqual;
	mr->rxqual_sub = rxqual;
	mr->dtx_used = meas_dtx_ms;
	mr->ba_used = meas_rep_ba;
	mr->meas_valid = 0; /* 0 = valid */
	mr->no_nc_n_hi = neighbors_count >> 2;
	mr->no_nc_n_lo = neighbors_count & 3;

	mr->rxlev_nc1 = neighbors[0].rxlev;
	mr->rxlev_nc2_hi = neighbors[1].rxlev >> 1;
	mr->rxlev_nc2_lo = neighbors[1].rxlev & 1;
	mr->rxlev_nc3_hi = neighbors[2].rxlev >> 2;
	mr->rxlev_nc3_lo = neighbors[2].rxlev & 3;
	mr->rxlev_nc4_hi = neighbors[3].rxlev >> 3;
	mr->rxlev_nc4_lo = neighbors[3].rxlev & 7;
	mr->rxlev_nc5_hi = neighbors[4].rxlev >> 4;
	mr->rxlev_nc5_lo = neighbors[4].rxlev & 15;
	mr->rxlev_nc6_hi = neighbors[5].rxlev >> 5;
	mr->rxlev_nc6_lo = neighbors[5].rxlev & 31;
	mr->bsic_nc1_hi = neighbors[0].bsic >> 3;
	mr->bsic_nc1_lo = neighbors[0].bsic & 7;
	mr->bsic_nc2_hi = neighbors[1].bsic >> 4;
	mr->bsic_nc2_lo = neighbors[1].bsic & 15;
	mr->bsic_nc3_hi = neighbors[2].bsic >> 5;
	mr->bsic_nc3_lo = neighbors[2].bsic & 31;
	mr->bsic_nc4 = neighbors[3].bsic;
	mr->bsic_nc5 = neighbors[4].bsic;
	mr->bsic_nc6 = neighbors[5].bsic;
	mr->bcch_f_nc1 = neighbors[0].bcch_f;
	mr->bcch_f_nc2 = neighbors[1].bcch_f;
	mr->bcch_f_nc3 = neighbors[2].bcch_f;
	mr->bcch_f_nc4 = neighbors[3].bcch_f;
	mr->bcch_f_nc5_hi = neighbors[4].bcch_f >> 1;
	mr->bcch_f_nc5_lo = neighbors[4].bcch_f & 1;
	mr->bcch_f_nc6_hi = neighbors[5].bcch_f >> 2;
	mr->bcch_f_nc6_lo = neighbors[5].bcch_f & 3;

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

static struct gsm_bts *_create_bts(int num_trx, const char * const *ts_args, int ts_args_count)
{
	static int arfcn = 870;
	struct gsm_bts *bts;
	struct e1inp_sign_link *rsl_link;
	int i;
	int trx_i;
	struct gsm_bts_trx *trx;

	fprintf(stderr, "- Creating BTS %d, %d TRX\n", bsc_gsmnet->num_bts, num_trx);

	bts = bsc_bts_alloc_register(bsc_gsmnet, GSM_BTS_TYPE_UNKNOWN, 0x3f);
	if (!bts) {
		fprintf(stderr, "No resource for bts1\n");
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
			int arg_i = trx_i * 8 + i;
			const char *ts_arg;
			if (arg_i >= ts_args_count)
				ts_arg = bts_default_ts[i];
			else
				ts_arg = ts_args[arg_i];
			fprintf(stderr, "\t%s", ts_arg);
			trx->ts[i].pchan_from_config = pchan_from_str(ts_arg);
			if (trx->ts[i].pchan_from_config == GSM_PCHAN_NONE)
				continue;
			trx->ts[i].mo.nm_state.operational = NM_OPSTATE_ENABLED;
			trx->ts[i].mo.nm_state.availability = NM_AVSTATE_OK;
			trx->ts[i].mo.nm_state.administrative = NM_STATE_UNLOCKED;
		}
		fprintf(stderr, "\n");

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

bool _expect_ts_use(struct gsm_bts *bts, struct gsm_bts_trx *trx, const char * const *ts_use)
{
	int i;
	int mismatching_ts = -1;

	fprintf(stderr, "bts %d trx %d: expect:", bts->nr, trx->nr);
	for (i = 0; i < 8; i++)
		fprintf(stderr, "\t%s", ts_use[i]);
	fprintf(stderr, "\nbts %d trx %d:    got:", bts->nr, trx->nr);

	for (i = 0; i < 8; i++) {
		struct gsm_bts_trx_ts *ts = &trx->ts[i];
		const char *use = ts_use_str(ts);

		fprintf(stderr, "\t%s", use);

		if (!strcmp(ts_use[i], "*"))
			continue;
		if (strcasecmp(ts_use[i], use) && mismatching_ts < 0)
			mismatching_ts = i;
	}
	fprintf(stderr, "\n");

	if (mismatching_ts >= 0) {
		fprintf(stderr, "Test failed: mismatching TS use in bts %d trx %d ts %d\n",
		       bts->nr, trx->nr, mismatching_ts);
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
	/* Fake osmo_mgcpc_ep_ci to indicate that the lchan is used for voice */
	lchan->mgw_endpoint_ci_bts = (void*)1;

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
		fprintf(stderr, "Given codec unknown\n");
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
		fprintf(stderr, "No resource for lchan\n");
		exit(EXIT_FAILURE);
	}

	return lchan_act(lchan, full_rate, codec);
}

static void lchan_release_ack(struct gsm_lchan *lchan)
{
	if (lchan->fi && lchan->fi->state == LCHAN_ST_WAIT_BEFORE_RF_RELEASE) {
		/* don't wait before release */
		osmo_fsm_inst_state_chg(lchan->fi, LCHAN_ST_WAIT_RF_RELEASE_ACK, 0, 0);
		/* ack the release */
		osmo_fsm_inst_dispatch(lchan->fi, LCHAN_EV_RSL_RF_CHAN_REL_ACK, 0);
	}
}

static void lchan_clear(struct gsm_lchan *lchan)
{
	lchan_release(lchan, true, false, 0);
	lchan_release_ack(lchan);
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

bool _set_ts_use(struct gsm_bts *bts, struct gsm_bts_trx *trx, const char * const *ts_use)
{
	int i;

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
		if (!strcasecmp(want_use, is_use))
			continue;

		if (!strcasecmp(want_use, "tch/f")) {
			if (!ts_is_capable_of_pchan(ts, GSM_PCHAN_TCH_F)) {
				fprintf(stderr, "Error: bts %d trx %d ts %d cannot be used as TCH/F\n",
				       bts->nr, trx->nr, i);
				return false;
			}
			ts_clear(ts);

			lchan_act(&ts->lchan[0], true, codec_tch_f ? : "AMR");
		} else if (!strcasecmp(want_use, "tch/h-")
			   || !strcasecmp(want_use, "tch/hh")
			   || !strcasecmp(want_use, "tch/-h")) {
			bool act[2];
			int j;

			if (!ts_is_capable_of_pchan(ts, GSM_PCHAN_TCH_H)) {
				fprintf(stderr, "Error: bts %d trx %d ts %d cannot be used as TCH/H\n",
				       bts->nr, trx->nr, i);
				return false;
			}

			if (ts->pchan_is != GSM_PCHAN_TCH_H)
				ts_clear(ts);

			act[0] = (want_use[4] == 'h' || want_use[4] == 'H');
			act[1] = (want_use[5] == 'h' || want_use[5] == 'H');

			for (j = 0; j < 2; j++) {
				if (lchan_state_is(&ts->lchan[j], LCHAN_ST_UNUSED)) {
					if (act[j])
						lchan_act(&ts->lchan[j], false, codec_tch_h ? : "AMR");
				} else if (!act[j])
					lchan_clear(&ts->lchan[j]);
			}
		} else if (!strcmp(want_use, "-") || !strcasecmp(want_use, "PDCH")) {
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

	fprintf(stderr, "- Send EST IND for %s\n", gsm_lchan_name(lchan));

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

static void send_ho_detect(struct gsm_lchan *lchan)
{
	struct msgb *msg = msgb_alloc_headroom(256, 64, "RSL");
	struct abis_rsl_rll_hdr *rh;
	uint8_t chan_nr = gsm_lchan2chan_nr(lchan);

	fprintf(stderr, "- Send HO DETECT for %s\n", gsm_lchan_name(lchan));

	rh = (struct abis_rsl_rll_hdr *) msgb_put(msg, sizeof(*rh));
	rh->c.msg_discr = ABIS_RSL_MDISC_DED_CHAN;
	rh->c.msg_type = RSL_MT_HANDO_DET;
	rh->ie_chan = RSL_IE_CHAN_NR;
	rh->chan_nr = chan_nr;
	rh->ie_link_id = RSL_IE_LINK_IDENT;
	rh->link_id = 0x00;

	msg->dst = lchan->ts->trx->bts->c0->rsl_link;
	msg->l2h = (unsigned char *)rh;

	abis_rsl_rcvmsg(msg);

	send_est_ind(lchan);
	osmo_fsm_inst_dispatch(lchan->fi, LCHAN_EV_RTP_READY, 0);

}

static void send_ho_complete(struct gsm_lchan *lchan, bool success)
{
	struct msgb *msg = msgb_alloc_headroom(256, 64, "RSL");
	struct abis_rsl_rll_hdr *rh;
	uint8_t chan_nr = gsm_lchan2chan_nr(lchan);
	uint8_t *buf;
	struct gsm48_hdr *gh;
	struct gsm48_ho_cpl *hc;

	if (success)
		fprintf(stderr, "- Send HO COMPLETE for %s\n", gsm_lchan_name(lchan));
	else
		fprintf(stderr, "- Send HO FAIL to %s\n", gsm_lchan_name(lchan));

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
		fprintf(stderr, "rsl_lchan_lookup() failed\n");
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
		fprintf(stderr, "unknown rsl message=0x%x\n", dh->c.msg_type);
	}
	return 0;
}

struct gsm_bts *bts_by_num_str(const char *num_str)
{
	struct gsm_bts *bts = gsm_bts_num(bsc_gsmnet, atoi(num_str));
	OSMO_ASSERT(bts);
	return bts;
}

struct gsm_bts_trx *trx_by_num_str(struct gsm_bts *bts, const char *num_str)
{
	struct gsm_bts_trx *trx = gsm_bts_trx_num(bts, atoi(num_str));
	OSMO_ASSERT(trx);
	return trx;
}

#define LCHAN_ARGS "lchan <0-255> <0-255> <0-7> <0-7>"
#define LCHAN_ARGS_DOC "identify an lchan\nBTS nr\nTRX nr\nTimeslot nr\nSubslot nr\n"

static struct gsm_lchan *parse_lchan_args(const char **argv)
{
	struct gsm_bts *bts = bts_by_num_str(argv[0]);
	struct gsm_bts_trx *trx = trx_by_num_str(bts, argv[1]);
	struct gsm_bts_trx_ts *ts = &trx->ts[atoi(argv[2])];
	return &ts->lchan[atoi(argv[3])];
}

#define TS_USE " (TCH/F|TCH/H-|TCH/-H|TCH/HH|PDCH" \
	       "|tch/f|tch/h-|tch/-h|tch/hh|pdch" \
	       "|-|*)"
#define TS_USE_DOC "'TCH/F': one FR call\n" \
		   "'TCH/H-': HR TS with first subslot used as TCH/H, other subslot unused\n" \
		   "'TCH/HH': HR TS with both subslots used as TCH/H\n" \
		   "'TCH/-H': HR TS with only second subslot used as TCH/H\n" \
		   "'PDCH': TS used for PDCH (e.g. unused dynamic TS)\n" \
		   "'tch/f': one FR call\n" \
		   "'tch/h-': HR TS with first subslot used as TCH/H, other subslot unused\n" \
		   "'tch/hh': HR TS with both subslots used as TCH/H\n" \
		   "'tch/-h': HR TS with only second subslot used as TCH/H\n" \
		   "'pdch': TS used for PDCH (e.g. unused dynamic TS)\n" \
		   "'-': TS unused\n" \
		   "'*': TS allowed to be in any state\n"

DEFUN(create_n_bts, create_n_bts_cmd,
      "create-n-bts <1-255>",
      "Create a number of BTS with four TCH/F and four TCH/H timeslots\n"
      "Number of BTS to create\n")
{
	int i;
	int n = atoi(argv[0]);
	for (i = 0; i < n; i++)
		_create_bts(1, NULL, 0);
	return CMD_SUCCESS;
}

DEFUN(create_bts, create_bts_cmd,
      "create-bts trx-count <1-255> timeslots .TS_CFG",
      "Create a new BTS with specific timeslot configuration\n"
      "Create N TRX in the new BTS\n"
      "TRX count\n"
      "Timeslot config\n"
      "Timeslot types for 8 * trx-count, each being one of CCCH+SDCCH4|SDCCH8|TCH/F|TCH/H|TCH/F_TCH/H_PDCH|...;"
      " shorthands: cs+4 = CCCH+SDCCH4; dyn = TCH/F_TCH/H_PDCH\n")
{
	int num_trx = atoi(argv[0]);
	_create_bts(num_trx, argv + 1, argc - 1);
	return CMD_SUCCESS;
}

DEFUN(create_ms, create_ms_cmd,
      "create-ms bts <0-999> (TCH/F|TCH/H) (AMR|HR|EFR)",
      "Create an MS using the next free matching lchan on a given BTS\n"
      "BTS index to subscribe on\n"
      "lchan type to select\n"
      "codec\n")
{
	const char *bts_nr_str = argv[0];
	const char *tch_type = argv[1];
	const char *codec = argv[2];
	struct gsm_lchan *lchan;
	fprintf(stderr, "- Creating mobile at BTS %s on "
		"%s with %s codec\n", bts_nr_str, tch_type, codec);
	lchan = create_lchan(bts_by_num_str(bts_nr_str),
			     !strcmp(tch_type, "TCH/F"), codec);
	if (!lchan) {
		fprintf(stderr, "Failed to create lchan!\n");
		return CMD_WARNING;
	}
	fprintf(stderr, " * New MS is at %s\n", gsm_lchan_name(lchan));
	return CMD_SUCCESS;
}

static int _meas_rep(struct vty *vty, int argc, const char **argv)
{
	struct gsm_lchan *lc;
	uint8_t rxlev;
	uint8_t rxqual;
	uint8_t ta;
	int i;
	struct neighbor_meas nm[6] = {};

	lc = parse_lchan_args(argv);
	argv += 4;
	argc -= 4;

	rxlev = atoi(argv[0]);
	rxqual = atoi(argv[1]);
	ta = atoi(argv[2]);
	argv += 3;
	argc -= 3;

	if (!lchan_state_is(lc, LCHAN_ST_ESTABLISHED)) {
		fprintf(stderr, "Error: sending measurement report for %s which is in state %s\n",
		       gsm_lchan_name(lc), lchan_state_name(lc));
		exit(1);
	}

	/* skip the optional [neighbors] keyword */
	if (argc) {
		argv++;
		argc--;
	}

	fprintf(stderr, "- Sending measurement report from %s: rxlev=%u rxqual=%u ta=%u (%d neighbors)\n",
		gsm_lchan_name(lc), rxlev, rxqual, ta, argc);

	for (i = 0; i < 6; i++) {
		int neighbor_bts_nr = i;
		/* since our bts is not in the list of neighbor cells, we need to shift */
		if (neighbor_bts_nr >= lc->ts->trx->bts->nr)
			neighbor_bts_nr++;
		nm[i] = (struct neighbor_meas){
			.rxlev = argc > i ? atoi(argv[i]) : 0,
			.bsic = 0x3f,
			.bcch_f = i,
		};
		if (i < argc)
			fprintf(stderr, " * Neighbor cell #%d, actual BTS %d: rxlev=%d\n", i, neighbor_bts_nr,
				nm[i].rxlev);
	}
	got_chan_req = 0;
	gen_meas_rep(lc, rxlev, rxqual, ta, argc, nm);
	return CMD_SUCCESS;
}

#define MEAS_REP_ARGS  LCHAN_ARGS " rxlev <0-255> rxqual <0-7> ta <0-255>" \
	" [neighbors] [<0-255>] [<0-255>] [<0-255>] [<0-255>] [<0-255>] [<0-255>]"
#define MEAS_REP_DOC "Send measurement report\n"
#define MEAS_REP_ARGS_DOC \
      LCHAN_ARGS_DOC \
      "rxlev\nrxlev\n" \
      "rxqual\nrxqual\n" \
      "timing advance\ntiming advance\n" \
      "neighbors list of rxlev reported by each neighbor cell\n" \
      "neighbor 0 rxlev\n" \
      "neighbor 1 rxlev\n" \
      "neighbor 2 rxlev\n" \
      "neighbor 3 rxlev\n" \
      "neighbor 4 rxlev\n" \
      "neighbor 5 rxlev\n"

DEFUN(meas_rep, meas_rep_cmd,
      "meas-rep " MEAS_REP_ARGS,
      MEAS_REP_DOC MEAS_REP_ARGS_DOC)
{
	return _meas_rep(vty, argc, argv);
}

DEFUN(meas_rep_repeat, meas_rep_repeat_cmd,
      "meas-rep repeat <0-999> " MEAS_REP_ARGS,
      MEAS_REP_DOC
      "Resend the same measurement report N times\nN\n"
      MEAS_REP_ARGS_DOC)
{
	int count = atoi(argv[0]);
	argv += 1;
	argc -= 1;

	while (count--)
		_meas_rep(vty, argc, argv);
	return CMD_SUCCESS;
}

DEFUN(congestion_check, congestion_check_cmd,
      "congestion-check",
      "Trigger a congestion check\n")
{
	fprintf(stderr, "- Triggering congestion check\n");
	got_chan_req = 0;
	hodec2_congestion_check(bsc_gsmnet);
	return CMD_SUCCESS;
}

DEFUN(expect_no_chan, expect_no_chan_cmd,
      "expect-no-chan",
      "Expect that no channel request was sent from BSC to any cell\n")
{
	fprintf(stderr, "- Expecting no channel request\n");
	if (got_chan_req) {
		fprintf(stderr, " * Got channel request at %s\n", gsm_lchan_name(chan_req_lchan));
		fprintf(stderr, "Test failed, because channel was requested\n");
		exit(1);
	}
	fprintf(stderr, " * Got no channel request\n");
	return CMD_SUCCESS;
}

static void _expect_chan_activ(struct gsm_lchan *lchan)
{
	fprintf(stderr, "- Expecting channel request at %s\n",
		gsm_lchan_name(lchan));
	if (!got_chan_req) {
		fprintf(stderr, "Test failed, because no channel was requested\n");
		exit(1);
	}
	fprintf(stderr, " * Got channel request at %s\n", gsm_lchan_name(chan_req_lchan));
	if (lchan != chan_req_lchan) {
		fprintf(stderr, "Test failed, because channel was requested on a different lchan than expected\n"
		       "expected: %s  got: %s\n",
		       gsm_lchan_name(lchan), gsm_lchan_name(chan_req_lchan));
		exit(1);
	}
}

static void _ack_chan_activ(struct gsm_lchan *lchan)
{
	fprintf(stderr, "- Acknowledging channel request on %s\n", gsm_lchan_name(lchan));
	got_ho_req = 0;
	send_chan_act_ack(lchan, 1);
}

static void _expect_ho_req(struct gsm_lchan *lchan)
{
	fprintf(stderr, "- Expecting handover/assignment request at %s\n",
		gsm_lchan_name(lchan));

	if (!got_ho_req) {
		fprintf(stderr, "Test failed, because no handover was requested\n");
		exit(1);
	}
	fprintf(stderr, " * Got handover/assignment request at %s\n", gsm_lchan_name(ho_req_lchan));
	if (ho_req_lchan != lchan) {
		fprintf(stderr, "Test failed, because handover/assignment was not commanded on the expected lchan\n");
		exit(1);
	}
}

DEFUN(expect_chan, expect_chan_cmd,
      "expect-chan " LCHAN_ARGS,
      "Expect a channel request from BSC to a cell for a specific lchan\n"
      LCHAN_ARGS_DOC)
{
	_expect_chan_activ(parse_lchan_args(argv));
	return CMD_SUCCESS;
}

DEFUN(ack_chan, ack_chan_cmd,
      "ack-chan",
      "ACK a previous Channel Request\n")
{
	OSMO_ASSERT(got_chan_req);
	_ack_chan_activ(chan_req_lchan);
	return CMD_SUCCESS;
}

DEFUN(expect_ho_req, expect_ho_req_cmd,
      "expect-ho-req " LCHAN_ARGS,
      "Expect a handover of a given lchan\n"
      LCHAN_ARGS_DOC)
{
	_expect_ho_req(parse_lchan_args(argv));
	return CMD_SUCCESS;
}

DEFUN(ho_detection, ho_detection_cmd,
      "ho-detect",
      "Send Handover Detection to the most recent HO target lchan\n")
{
	if (!got_chan_req) {
		fprintf(stderr, "Cannot ack handover/assignment, because no chan request\n");
		exit(1);
	}
	if (!got_ho_req) {
		fprintf(stderr, "Cannot ack handover/assignment, because no ho request\n");
		exit(1);
	}
	send_ho_detect(chan_req_lchan);
	return CMD_SUCCESS;
}

DEFUN(ho_complete, ho_complete_cmd,
      "ho-complete",
      "Send Handover Complete for the most recent HO target lchan\n")
{
	if (!got_chan_req) {
		fprintf(stderr, "Cannot ack handover/assignment, because no chan request\n");
		exit(1);
	}
	if (!got_ho_req) {
		fprintf(stderr, "Cannot ack handover/assignment, because no ho request\n");
		exit(1);
	}
	send_ho_complete(chan_req_lchan, true);
	lchan_release_ack(ho_req_lchan);
	return CMD_SUCCESS;
}

DEFUN(expect_ho, expect_ho_cmd,
      "expect-ho from " LCHAN_ARGS " to " LCHAN_ARGS,
      "Expect a handover of a specific lchan to a specific target lchan;"
      " shorthand for expect-chan, ack-chan, expect-ho, ho-complete.\n"
      "lchan to handover from\n" LCHAN_ARGS_DOC
      "lchan that to handover to\n" LCHAN_ARGS_DOC)
{
	struct gsm_lchan *from = parse_lchan_args(argv);
	struct gsm_lchan *to = parse_lchan_args(argv+4);

	_expect_chan_activ(to);
	_ack_chan_activ(to);
	_expect_ho_req(from);
	send_ho_detect(to);
	send_ho_complete(to, true);
	lchan_release_ack(from);
	return CMD_SUCCESS;
}

DEFUN(ho_failed, ho_failed_cmd,
      "ho-failed",
      "Fail the most recent handover request\n")
{
	if (!got_chan_req) {
		fprintf(stderr, "Cannot fail handover, because no chan request\n");
		exit(1);
	}
	got_chan_req = 0;
	got_ho_req = 0;
	send_ho_complete(ho_req_lchan, false);
	lchan_release_ack(chan_req_lchan);
	return CMD_SUCCESS;
}

DEFUN(expect_ts_use, expect_ts_use_cmd,
	"expect-ts-use trx <0-255> <0-255> states" TS_USE TS_USE TS_USE TS_USE TS_USE TS_USE TS_USE TS_USE,
	"Expect timeslots of a BTS' TRX to be in a specific state\n"
	"Indicate a BTS and TRX\n" "BTS nr\n" "TRX nr\n"
	"List of 8 expected TS states\n"
	TS_USE_DOC TS_USE_DOC TS_USE_DOC TS_USE_DOC TS_USE_DOC TS_USE_DOC TS_USE_DOC TS_USE_DOC)
{
	struct gsm_bts *bts = bts_by_num_str(argv[0]);
	struct gsm_bts_trx *trx = trx_by_num_str(bts, argv[1]);
	argv += 2;
	argc -= 2;
	if (!_expect_ts_use(bts, trx, argv))
		exit(1);
	return CMD_SUCCESS;
}

DEFUN(codec_f, codec_f_cmd,
	"codec tch/f (AMR|EFR|FR)",
	"Define which codec should be used for new TCH/F lchans (for set-ts-use)\n"
	"Configure the TCH/F codec to use\nAMR\nEFR\nFR\n")
{
	osmo_talloc_replace_string(ctx, &codec_tch_f, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(codec_h, codec_h_cmd,
	"codec tch/h (AMR|HR)",
	"Define which codec should be used for new TCH/H lchans (for set-ts-use)\n"
	"Configure the TCH/H codec to use\nAMR\nHR\n")
{
	osmo_talloc_replace_string(ctx, &codec_tch_h, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(set_ts_use, set_ts_use_cmd,
	"set-ts-use trx <0-255> <0-255> states" TS_USE TS_USE TS_USE TS_USE TS_USE TS_USE TS_USE TS_USE,
	"Put timeslots of a BTS' TRX into a specific state\n"
	"Indicate a BTS and TRX\n" "BTS nr\n" "TRX nr\n"
	"List of 8 TS states to apply\n"
	TS_USE_DOC TS_USE_DOC TS_USE_DOC TS_USE_DOC TS_USE_DOC TS_USE_DOC TS_USE_DOC TS_USE_DOC)
{
	struct gsm_bts *bts = bts_by_num_str(argv[0]);
	struct gsm_bts_trx *trx = trx_by_num_str(bts, argv[1]);
	argv += 2;
	argc -= 2;
	if (!_set_ts_use(bts, trx, argv))
		exit(1);
	if (!_expect_ts_use(bts, trx, argv))
		exit(1);
	return CMD_SUCCESS;
}

static void ho_test_vty_init()
{
	install_element(CONFIG_NODE, &create_n_bts_cmd);
	install_element(CONFIG_NODE, &create_bts_cmd);
	install_element(CONFIG_NODE, &create_ms_cmd);
	install_element(CONFIG_NODE, &meas_rep_cmd);
	install_element(CONFIG_NODE, &meas_rep_repeat_cmd);
	install_element(CONFIG_NODE, &congestion_check_cmd);
	install_element(CONFIG_NODE, &expect_no_chan_cmd);
	install_element(CONFIG_NODE, &expect_chan_cmd);
	install_element(CONFIG_NODE, &ack_chan_cmd);
	install_element(CONFIG_NODE, &expect_ho_req_cmd);
	install_element(CONFIG_NODE, &ho_detection_cmd);
	install_element(CONFIG_NODE, &ho_complete_cmd);
	install_element(CONFIG_NODE, &expect_ho_cmd);
	install_element(CONFIG_NODE, &ho_failed_cmd);
	install_element(CONFIG_NODE, &expect_ts_use_cmd);
	install_element(CONFIG_NODE, &codec_f_cmd);
	install_element(CONFIG_NODE, &codec_h_cmd);
	install_element(CONFIG_NODE, &set_ts_use_cmd);
}

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

static struct vty_app_info vty_info = {
	.name = "ho_test",
	.copyright =
	"Copyright (C) 2020 sysmocom - s.f.m.c. GmbH\r\n"
	"License AGPLv3+: GNU AGPL version 3 or later <http://gnu.org/licenses/agpl-3.0.html>\r\n"
	"This is free software: you are free to change and redistribute it.\r\n"
	"There is NO WARRANTY, to the extent permitted by law.\r\n",
	.version	= PACKAGE_VERSION,
	.usr_attr_desc	= {
		[BSC_VTY_ATTR_RESTART_ABIS_OML_LINK] = \
			"This command applies on A-bis OML link (re)establishment",
		[BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK] = \
			"This command applies on A-bis RSL link (re)establishment",
		[BSC_VTY_ATTR_NEW_LCHAN] = \
			"This command applies for newly created lchans",
	},
	.usr_attr_letters = {
		[BSC_VTY_ATTR_RESTART_ABIS_OML_LINK]	= 'o',
		[BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK]	= 'r',
		[BSC_VTY_ATTR_NEW_LCHAN]		= 'l',
	},
};

int main(int argc, char **argv)
{
	char *test_file = NULL;
	int rc;

	if (argc < 2) {
		fprintf(stderr, "Pass a handover test script as argument\n");
		exit(1);
	}
	test_file = argv[1];

	ctx = talloc_named_const(NULL, 0, "handover_test");
	msgb_talloc_ctx_init(ctx, 0);
	vty_info.tall_ctx = ctx;

	osmo_init_logging2(ctx, &log_info);

	log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_NONE);
	log_set_print_category(osmo_stderr_target, 1);
	log_set_print_category_hex(osmo_stderr_target, 0);
	log_set_print_level(osmo_stderr_target, 1);
	log_set_print_timestamp(osmo_stderr_target, 0);
	osmo_fsm_log_addr(false);

	bsc_network_alloc();
	if (!bsc_gsmnet)
		exit(1);

	vty_init(&vty_info);
	bsc_vty_init(bsc_gsmnet);
	ho_test_vty_init();

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

	/* Disable the congestion check timer, we will trigger manually. */
	bsc_gsmnet->hodec2.congestion_check_interval_s = 0;

	handover_decision_1_init();
	hodec2_init(bsc_gsmnet);

	rc = vty_read_config_file(test_file, NULL);
	if (rc < 0) {
		fprintf(stderr, "Failed to parse the test file: '%s'\n", test_file);
	}

	talloc_free(ctx);
	fprintf(stderr,"-------------------\n");
	if (!rc)
		fprintf(stderr, "pass\n");
	else
		fprintf(stderr, "FAIL\n");
	return rc;
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
const char *osmo_mgcpc_ep_name(const struct osmo_mgcpc_ep *ep)
{
	return "fake-ep";
}
const char *osmo_mgcpc_ep_ci_name(const struct osmo_mgcpc_ep_ci *ci)
{
	return "fake-ci";
}
