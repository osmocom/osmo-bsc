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
#include <osmocom/bsc/assignment_fsm.h>
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
#include <osmocom/mgcp_client/mgcp_client_pool.h>

#include "../../bscconfig.h"

void *ctx;

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
uint8_t meas_tx_power_ms = 0;
uint8_t meas_dtx_ms = 0, meas_dtx_bs = 0, meas_nr = 0;
char *codec_tch_f = NULL;
char *codec_tch_h = NULL;

struct neighbor_meas {
	uint8_t rxlev;
	uint8_t bsic;
	uint8_t bcch_f;
};

const struct timeval fake_time_start_time = { 123, 456 };

void fake_time_passes(time_t secs, suseconds_t usecs)
{
	struct timeval diff;
	/* Add time to osmo_fsm timers, using osmo_gettimeofday() */
	osmo_gettimeofday_override_add(secs, usecs);
	/* Add time to penalty timers, using osmo_clock_gettime() */
	osmo_clock_override_add(CLOCK_MONOTONIC, secs, usecs * 1000);

	timersub(&osmo_gettimeofday_override_time, &fake_time_start_time, &diff);
	fprintf(stderr, "Total time passed: %d.%06d s\n", (int)diff.tv_sec, (int)diff.tv_usec);

	osmo_timers_prepare();
	osmo_timers_update();
}

void fake_time_start()
{
	struct timespec *clock_override;

	/* osmo_fsm uses osmo_gettimeofday(). To affect FSM timeouts, we need osmo_gettimeofday_override. */
	osmo_gettimeofday_override_time = fake_time_start_time;
	osmo_gettimeofday_override = true;

	/* Penalty timers use osmo_clock_gettime(CLOCK_MONOTONIC). To affect these timeouts, we need
	 * osmo_gettimeofday_override. */
	clock_override = osmo_clock_override_gettimespec(CLOCK_MONOTONIC);
	OSMO_ASSERT(clock_override);
	clock_override->tv_sec = fake_time_start_time.tv_sec;
	clock_override->tv_nsec = fake_time_start_time.tv_usec * 1000;
	osmo_clock_override_enable(CLOCK_MONOTONIC, true);
	fake_time_passes(0, 0);
}

static void gen_meas_rep(struct gsm_lchan *lchan,
			 uint8_t bs_power_db, uint8_t rxlev, uint8_t rxqual, uint8_t ta,
			 int neighbors_count, struct neighbor_meas *neighbors)
{
	struct msgb *msg = msgb_alloc_headroom(256, 64, "RSL");
	struct abis_rsl_dchan_hdr *dh;
	uint8_t ulm[3], l1i[2], *buf;
	struct gsm48_hdr *gh;
	struct gsm48_meas_res *mr;
	int chan_nr = gsm_lchan2chan_nr(lchan, true);
	OSMO_ASSERT(chan_nr >= 0);

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

	msgb_tv_put(msg, RSL_IE_BS_POWER, (bs_power_db / 2) & 0xf);

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

	msg->dst = rsl_chan_link(lchan);
	msg->l2h = (unsigned char *)dh;
	msg->l3h = (unsigned char *)gh;

	abis_rsl_rcvmsg(msg);
}

enum gsm_phys_chan_config pchan_from_str(const char *str)
{
	enum gsm_phys_chan_config pchan;
	if (!strcmp(str, "dyn"))
		return GSM_PCHAN_OSMO_DYN;
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
	static int ci = 0;
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
	bts->cell_identity = ci++;
	bts->c0->arfcn = arfcn++;

	bts->codec.efr = 1;
	bts->codec.hr = 1;
	bts->codec.amr = 1;

	rsl_link = talloc_zero(ctx, struct e1inp_sign_link);
	rsl_link->trx = bts->c0;
	bts->c0->rsl_link_primary = rsl_link;

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
			case GSM_PCHAN_OSMO_DYN:
			case GSM_PCHAN_TCH_F_PDCH:
				ts_set_pchan_is(&trx->ts[i], GSM_PCHAN_PDCH);
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

char *lchans_use_str(struct gsm_bts_trx_ts *ts, const char *established_prefix, char established_char)
{
	char state_chars[8] = { 0 };
	struct gsm_lchan *lchan;
	bool any_lchans_established = false;
	bool any_lchans_in_use = false;
	ts_for_n_lchans(lchan, ts, ts->max_primary_lchans) {
		char state_char;
		if (lchan_state_is(lchan, LCHAN_ST_UNUSED)) {
			state_char = '-';
		} else {
			any_lchans_in_use = true;
			if (lchan_state_is(lchan, LCHAN_ST_ESTABLISHED)) {
				any_lchans_established = true;
				state_char = established_char;
			} else {
				state_char = '!';
			}
		}
		state_chars[lchan->nr] = state_char;
	}
	if (!any_lchans_in_use)
		return "-";
	if (!any_lchans_established)
		established_prefix = "";
	return talloc_asprintf(OTC_SELECT, "%s%s", established_prefix, state_chars);
}

const char *ts_use_str(struct gsm_bts_trx_ts *ts)
{
	switch (ts->pchan_is) {
	case GSM_PCHAN_CCCH_SDCCH4:
		return "c+s4";

	case GSM_PCHAN_NONE:
		return "-";

	case GSM_PCHAN_TCH_F:
		return lchans_use_str(ts, "TCH/", 'F');

	case GSM_PCHAN_TCH_H:
		return lchans_use_str(ts, "TCH/", 'H');

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

	/* Set RTP data that the MSC normally would have sent */
	OSMO_STRLCPY_ARRAY(conn->user_plane.msc_assigned_rtp_addr, "1.2.3.4");
	conn->user_plane.msc_assigned_rtp_port = 1234;

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

	if (lchan->ts->pchan_on_init == GSM_PCHAN_OSMO_DYN)
		ts_set_pchan_is(lchan->ts, full_rate ? GSM_PCHAN_TCH_F : GSM_PCHAN_TCH_H);
	if (lchan->ts->pchan_on_init == GSM_PCHAN_TCH_F_PDCH) {
		OSMO_ASSERT(full_rate);
		ts_set_pchan_is(lchan->ts, GSM_PCHAN_TCH_F);
	}

	LOG_LCHAN(lchan, LOGL_DEBUG, "activated by handover_test.c\n");

	create_conn(lchan);
	if (!strcasecmp(codec, "FR") && full_rate)
		lchan->current_ch_mode_rate.chan_mode = GSM48_CMODE_SPEECH_V1;
	else if (!strcasecmp(codec, "HR") && !full_rate)
		lchan->current_ch_mode_rate.chan_mode = GSM48_CMODE_SPEECH_V1;
	else if (!strcasecmp(codec, "EFR") && full_rate)
		lchan->current_ch_mode_rate.chan_mode = GSM48_CMODE_SPEECH_EFR;
	else if (!strcasecmp(codec, "AMR")) {
		lchan->current_ch_mode_rate.chan_mode = GSM48_CMODE_SPEECH_AMR;
		lchan->current_ch_mode_rate.s15_s0 = 0x0002;
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

	chan_counts_ts_update(lchan->ts);

	return lchan;
}

struct gsm_lchan *create_lchan(struct gsm_bts *bts, int full_rate, const char *codec)
{
	struct gsm_lchan *lchan;

	lchan = lchan_select_by_type(bts, (full_rate) ? GSM_LCHAN_TCH_F : GSM_LCHAN_TCH_H,
				     SELECT_FOR_HANDOVER);
	if (!lchan) {
		fprintf(stderr, "No resource for lchan\n");
		exit(EXIT_FAILURE);
	}

	return lchan_act(lchan, full_rate, codec);
}

static void lchan_release_ack(struct gsm_lchan *lchan)
{
	if (!lchan->fi || lchan->fi->state != LCHAN_ST_WAIT_BEFORE_RF_RELEASE)
		return;
	/* don't wait before release */
	osmo_fsm_inst_state_chg(lchan->fi, LCHAN_ST_WAIT_RF_RELEASE_ACK, 0, 0);
	if (lchan->fi->state == LCHAN_ST_UNUSED)
		return;
	/* ack the release */
	osmo_fsm_inst_dispatch(lchan->fi, LCHAN_EV_RSL_RF_CHAN_REL_ACK, 0);
}

static void lchan_clear(struct gsm_lchan *lchan)
{
	lchan_release(lchan, true, false, 0, NULL);
	lchan_release_ack(lchan);
}

static void ts_clear(struct gsm_bts_trx_ts *ts)
{
	struct gsm_lchan *lchan;

	ts_for_n_lchans(lchan, ts, ts->max_lchans_possible) {
		if (lchan_state_is(lchan, LCHAN_ST_UNUSED))
			continue;
		lchan_clear(lchan);
	}
	chan_counts_ts_update(ts);
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

static struct gsm_lchan *new_chan_req = NULL;
static struct gsm_lchan *last_chan_req = NULL;

static struct gsm_lchan *new_ho_cmd = NULL;
static struct gsm_lchan *last_ho_cmd = NULL;

static struct gsm_lchan *new_as_cmd = NULL;
static struct gsm_lchan *last_as_cmd = NULL;

/* send channel activation ack */
static void send_chan_act_ack(struct gsm_lchan *lchan, int act)
{
	struct msgb *msg = msgb_alloc_headroom(256, 64, "RSL");
	struct abis_rsl_dchan_hdr *dh;

	dh = (struct abis_rsl_dchan_hdr *) msgb_put(msg, sizeof(*dh));
	dh->c.msg_discr = ABIS_RSL_MDISC_DED_CHAN;
	dh->c.msg_type = (act) ? RSL_MT_CHAN_ACTIV_ACK : RSL_MT_RF_CHAN_REL_ACK;
	dh->ie_chan = RSL_IE_CHAN_NR;
	dh->chan_nr = gsm_lchan2chan_nr(lchan, true);

	msg->dst = rsl_chan_link(lchan);
	msg->l2h = (unsigned char *)dh;

	abis_rsl_rcvmsg(msg);
}

/* Send RR Assignment Complete for SAPI[0] */
static void send_assignment_complete(struct gsm_lchan *lchan)
{
	struct msgb *msg = msgb_alloc_headroom(256, 64, "RSL");
	struct abis_rsl_rll_hdr *rh;
	uint8_t chan_nr = gsm_lchan2chan_nr(lchan, true);
	uint8_t *buf;
	struct gsm48_hdr *gh;
	struct gsm48_ho_cpl *hc;

	fprintf(stderr, "- Send RR Assignment Complete for %s\n", gsm_lchan_name(lchan));

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
	gh->msg_type = GSM48_MT_RR_ASS_COMPL;

	msg->dst = rsl_chan_link(lchan);
	msg->l2h = (unsigned char *)rh;
	msg->l3h = (unsigned char *)gh;

	abis_rsl_rcvmsg(msg);
}

/* Send RLL Est Ind for SAPI[0] */
static void send_est_ind(struct gsm_lchan *lchan)
{
	struct msgb *msg = msgb_alloc_headroom(256, 64, "RSL");
	struct abis_rsl_rll_hdr *rh;
	uint8_t chan_nr = gsm_lchan2chan_nr(lchan, true);

	fprintf(stderr, "- Send EST IND for %s\n", gsm_lchan_name(lchan));

	rh = (struct abis_rsl_rll_hdr *) msgb_put(msg, sizeof(*rh));
	rh->c.msg_discr = ABIS_RSL_MDISC_RLL;
	rh->c.msg_type = RSL_MT_EST_IND;
	rh->ie_chan = RSL_IE_CHAN_NR;
	rh->chan_nr = chan_nr;
	rh->ie_link_id = RSL_IE_LINK_IDENT;
	rh->link_id = 0x00;

	msg->dst = rsl_chan_link(lchan);
	msg->l2h = (unsigned char *)rh;

	abis_rsl_rcvmsg(msg);
}

static void send_ho_detect(struct gsm_lchan *lchan)
{
	struct msgb *msg = msgb_alloc_headroom(256, 64, "RSL");
	struct abis_rsl_rll_hdr *rh;
	uint8_t chan_nr = gsm_lchan2chan_nr(lchan, true);

	fprintf(stderr, "- Send HO DETECT for %s\n", gsm_lchan_name(lchan));

	rh = (struct abis_rsl_rll_hdr *) msgb_put(msg, sizeof(*rh));
	rh->c.msg_discr = ABIS_RSL_MDISC_DED_CHAN;
	rh->c.msg_type = RSL_MT_HANDO_DET;
	rh->ie_chan = RSL_IE_CHAN_NR;
	rh->chan_nr = chan_nr;
	rh->ie_link_id = RSL_IE_LINK_IDENT;
	rh->link_id = 0x00;

	msg->dst = rsl_chan_link(lchan);
	msg->l2h = (unsigned char *)rh;

	abis_rsl_rcvmsg(msg);

	send_est_ind(lchan);
	osmo_fsm_inst_dispatch(lchan->fi, LCHAN_EV_RTP_READY, 0);

}

static void send_ho_complete(struct gsm_lchan *lchan, bool success)
{
	struct msgb *msg = msgb_alloc_headroom(256, 64, "RSL");
	struct abis_rsl_rll_hdr *rh;
	uint8_t chan_nr = gsm_lchan2chan_nr(lchan, true);
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

	msg->dst = rsl_chan_link(lchan);
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
	struct gsm48_hdr *gh;

	if (rc) {
		fprintf(stderr, "rsl_lchan_lookup() failed\n");
		exit(1);
	}

	switch (dh->c.msg_type) {
	case RSL_MT_CHAN_ACTIV:
		if (new_chan_req) {
			fprintf(stderr, "Test script is erratic: a channel is requested"
				" while a previous channel request is still unhandled\n");
			exit(1);
		}
		new_chan_req = lchan;
		break;
	case RSL_MT_RF_CHAN_REL:
		send_chan_act_ack(lchan, 0);

		/* send dyn TS back to PDCH if unused */
		switch (lchan->ts->pchan_on_init) {
		case GSM_PCHAN_OSMO_DYN:
		case GSM_PCHAN_TCH_F_PDCH:
			switch (lchan->ts->pchan_is) {
			case GSM_PCHAN_TCH_H:
				other_lchan = &lchan->ts->lchan[
					(lchan == &lchan->ts->lchan[0])?
					1 : 0];
				if (lchan_state_is(other_lchan, LCHAN_ST_ESTABLISHED))
					break;
				/* else fall thru */
			case GSM_PCHAN_TCH_F:
				ts_set_pchan_is(lchan->ts, GSM_PCHAN_PDCH);
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
		gh = (struct gsm48_hdr*)msg->l3h;
		switch (gh->msg_type) {
		case GSM48_MT_RR_HANDO_CMD:
			if (new_ho_cmd || new_as_cmd) {
				fprintf(stderr, "Test script is erratic: seen a Handover Command"
					" while a previous Assignment or Handover Command is still unhandled\n");
				exit(1);
			}
			new_ho_cmd = lchan;
			break;
		case GSM48_MT_RR_ASS_CMD:
			if (new_ho_cmd || new_as_cmd) {
				fprintf(stderr, "Test script is erratic: seen an Assignment Command"
					" while a previous Assignment or Handover Command is still unhandled\n");
				exit(1);
			}
			new_as_cmd = lchan;
			break;
		}
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

#define LCHAN_WILDCARD_ARGS "lchan (<0-255>|*) (<0-255>|*) (<0-7>|*) (<0-7>|*)"
#define LCHAN_WILDCARD_ARGS_DOC "identify an lchan\nBTS nr\nall BTS\nTRX nr\nall BTS\nTimeslot nr\nall TS\nSubslot nr\nall subslots\n"

static void parse_lchan_wildcard_args(const char **argv, void (*cb)(struct gsm_lchan*, void*), void *cb_data)
{
	const char *bts_str = argv[0];
	const char *trx_str = argv[1];
	const char *ts_str = argv[2];
	const char *ss_str = argv[3];
	int bts_num = (strcmp(bts_str, "*") == 0)? -1 : atoi(bts_str);
	int trx_num = (strcmp(trx_str, "*") == 0)? -1 : atoi(trx_str);
	int ts_num = (strcmp(ts_str, "*") == 0)? -1 : atoi(ts_str);
	int ss_num = (strcmp(ss_str, "*") == 0)? -1 : atoi(ss_str);

	int bts_i;
	int trx_i;
	int ts_i;
	int ss_i;

	for (bts_i = ((bts_num == -1) ? 0 : bts_num);
	     bts_i < ((bts_num == -1) ? bsc_gsmnet->num_bts : bts_num + 1);
	     bts_i++) {
		struct gsm_bts *bts = gsm_bts_num(bsc_gsmnet, bts_i);

		for (trx_i = ((trx_num == -1) ? 0 : trx_num);
		     trx_i < ((trx_num == -1) ? bts->num_trx : trx_num + 1);
		     trx_i++) {
			struct gsm_bts_trx *trx = gsm_bts_trx_num(bts, trx_i);

			for (ts_i = ((ts_num == -1) ? 0 : ts_num);
			     ts_i < ((ts_num == -1) ? 8 : ts_num + 1);
			     ts_i++) {
				struct gsm_bts_trx_ts *ts = &trx->ts[ts_i];

				for (ss_i = ((ss_num == -1) ? 0 : ss_num);
				     ss_i < ((ss_num == -1) ? pchan_subslots(ts->pchan_is) : ss_num + 1);
				     ss_i++) {
					cb(&ts->lchan[ss_i], cb_data);
				}
			}
		}
	}
}

static int vty_step = 1;

#define VTY_ECHO() \
	fprintf(stderr, "\n%d: %s\n", vty_step++, vty->buf)

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
	VTY_ECHO();
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
      "Timeslot types for 8 * trx-count, each being one of CCCH+SDCCH4|SDCCH8|TCH/F|TCH/H|TCH/F_TCH/H_SDCCH8_PDCH|...;"
      " shorthands: cs+4 = CCCH+SDCCH4; dyn = TCH/F_TCH/H_SDCCH8_PDCH\n")
{
	int num_trx = atoi(argv[0]);
	VTY_ECHO();
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
	VTY_ECHO();
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

struct meas_rep_data {
	int argc;
	const char **argv;
	uint8_t bs_power_db;
};

static void _meas_rep_cb(struct gsm_lchan *lc, void *data)
{
	struct meas_rep_data *d = data;
	int argc = d->argc;
	const char **argv = d->argv;
	uint8_t rxlev;
	uint8_t rxqual;
	uint8_t ta;
	int i;
	struct neighbor_meas nm[6] = {};

	if (!lchan_state_is(lc, LCHAN_ST_ESTABLISHED))
		return;

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
	gen_meas_rep(lc, d->bs_power_db, rxlev, rxqual, ta, argc, nm);
}

static int _meas_rep(struct vty *vty, uint8_t bs_power_db, int argc, const char **argv)
{
	struct meas_rep_data d = {
		.argc = argc - 4,
		.argv = argv + 4,
		.bs_power_db = bs_power_db,
	};
	parse_lchan_wildcard_args(argv, _meas_rep_cb, &d);
	return CMD_SUCCESS;
}


#define MEAS_REP_ARGS  LCHAN_WILDCARD_ARGS " rxlev <0-255> rxqual <0-7> ta <0-255>" \
	" [neighbors] [<0-255>] [<0-255>] [<0-255>] [<0-255>] [<0-255>] [<0-255>]"
#define MEAS_REP_DOC "Send measurement report\n"
#define MEAS_REP_ARGS_DOC \
      LCHAN_WILDCARD_ARGS_DOC \
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
	VTY_ECHO();
	return _meas_rep(vty, 0, argc, argv);
}

DEFUN(meas_rep_repeat, meas_rep_repeat_cmd,
      "meas-rep repeat <0-999> " MEAS_REP_ARGS,
      MEAS_REP_DOC
      "Resend the same measurement report N times\nN\n"
      MEAS_REP_ARGS_DOC)
{
	int count = atoi(argv[0]);
	VTY_ECHO();
	argv += 1;
	argc -= 1;

	while (count--)
		_meas_rep(vty, 0, argc, argv);
	return CMD_SUCCESS;
}

DEFUN(meas_rep_repeat_bspower, meas_rep_repeat_bspower_cmd,
      "meas-rep repeat <0-999> bspower <0-31> " MEAS_REP_ARGS,
      MEAS_REP_DOC
      "Resend the same measurement report N times\nN\n"
      "Send a nonzero BS Power value in the measurement report (downlink power reduction)\nBS Power reduction in dB\n"
      MEAS_REP_ARGS_DOC)
{
	int count = atoi(argv[0]);
	uint8_t bs_power_db = atoi(argv[1]);
	VTY_ECHO();
	argv += 2;
	argc -= 2;

	while (count--)
		_meas_rep(vty, bs_power_db, argc, argv);
	return CMD_SUCCESS;
}

DEFUN(res_ind, res_ind_cmd,
      "res-ind trx <0-255> <0-255> levels .LEVELS",
      "Send Resource Indication for a specific TRX, indicating interference levels per lchan\n"
      "Indicate a BTS and TRX\n" "BTS nr\n" "TRX nr\n"
      "Indicate interference levels: each level is an index to bts->interf_meas_params.bounds_dbm[],"
      " i.e. <0-5> or '-' to omit a report for this timeslot/lchan."
      " Separate timeslots by spaces, for individual subslots directly concatenate values."
      " If a timeslot has more subslots than provided, the last given value is repeated."
      " For example: 'res-ind trx 0 0 levels - 1 23 -': on BTS 0 TRX 0, omit ratings for the entire first timeslot,"
      " send level=1 for timeslot 1, and for timeslot 2 send level=2 for subslot 0 and level=3 for subslot 1.\n")
{
	int i;
	uint8_t level;
	struct gsm_bts *bts = bts_by_num_str(argv[0]);
	struct gsm_bts_trx *trx = trx_by_num_str(bts, argv[1]);
	struct msgb *msg = msgb_alloc_headroom(256, 64, "RES-IND");
	struct abis_rsl_common_hdr *rslh;
	uint8_t *res_info_len;
	VTY_ECHO();

	/* In this test suite, always act as if the interf_meas_params_cfg were already sent to the BTS via OML */
	bts->interf_meas_params_used = bts->interf_meas_params_cfg;

	argv += 2;
	argc -= 2;

	rslh = (struct abis_rsl_common_hdr*)msgb_put(msg, sizeof(*rslh));
	rslh->msg_discr = ABIS_RSL_MDISC_TRX;
	rslh->msg_type = RSL_MT_RF_RES_IND;
	msgb_put_u8(msg, RSL_IE_RESOURCE_INFO);
	res_info_len = msg->tail;
	msgb_put_u8(msg, 0);

	level = 0xff;
	for (i = 0; i < ARRAY_SIZE(trx->ts); i++) {
		const char *ts_str = NULL;
		struct gsm_lchan *lchan;
		size_t given_subslots = 0;
		struct gsm_bts_trx_ts *ts = &trx->ts[i];

		if (i < argc) {
			ts_str = argv[i];
			given_subslots = strlen(ts_str);
		}

		ts_for_n_lchans(lchan, ts, ts->max_lchans_possible) {
			int chan_nr;

			if (lchan->nr < given_subslots && ts_str) {
				char subslot_val = ts_str[lchan->nr];
				switch (subslot_val) {
				case '-':
					level = INTERF_BAND_UNKNOWN;
					break;
				case '0':
				case '1':
				case '2':
				case '3':
				case '4':
				case '5':
				case '6':
				case '7':
					level = subslot_val - '0';
					break;
				default:
					OSMO_ASSERT(false);
				}
			}

			if (level == INTERF_BAND_UNKNOWN)
				continue;

			chan_nr = gsm_lchan2chan_nr(lchan, true);
			if (chan_nr < 0)
				continue;

			msgb_put_u8(msg, chan_nr);
			msgb_put_u8(msg, level << 5);
		}
	}

	*res_info_len = msg->tail - res_info_len - 1;

	msg->dst = trx->rsl_link_primary;
	msg->l2h = msg->data;
	abis_rsl_rcvmsg(msg);

	return CMD_SUCCESS;
}

DEFUN(congestion_check, congestion_check_cmd,
      "congestion-check",
      "Trigger a congestion check\n")
{
	VTY_ECHO();
	fprintf(stderr, "- Triggering congestion check\n");
	hodec2_congestion_check(bsc_gsmnet);
	return CMD_SUCCESS;
}

DEFUN(expect_no_chan, expect_no_chan_cmd,
      "expect-no-chan",
      "Expect that no channel request was sent from BSC to any cell\n")
{
	VTY_ECHO();
	fprintf(stderr, "- Expecting no channel request\n");
	if (new_chan_req) {
		fprintf(stderr, " * Got channel request at %s\n", gsm_lchan_name(new_chan_req));
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
	if (!new_chan_req) {
		fprintf(stderr, "Test failed, because no channel was requested\n");
		exit(1);
	}
	last_chan_req = new_chan_req;
	new_chan_req = NULL;
	fprintf(stderr, " * Got channel request at %s\n", gsm_lchan_name(last_chan_req));
	if (lchan != last_chan_req) {
		fprintf(stderr, "Test failed, because channel was requested on a different lchan than expected\n"
		       "expected: %s  got: %s\n",
		       gsm_lchan_name(lchan), gsm_lchan_name(last_chan_req));
		exit(1);
	}
	send_chan_act_ack(lchan, 1);
}

static void _expect_ho_cmd(struct gsm_lchan *lchan)
{
	fprintf(stderr, "- Expecting Handover Command at %s\n",
		gsm_lchan_name(lchan));

	if (!new_ho_cmd) {
		fprintf(stderr, "Test failed, no Handover Command\n");
		exit(1);
	}
	fprintf(stderr, " * Got Handover Command at %s\n", gsm_lchan_name(new_ho_cmd));
	if (new_ho_cmd != lchan) {
		fprintf(stderr, "Test failed, Handover Command not on the expected lchan\n");
		exit(1);
	}
	last_ho_cmd = new_ho_cmd;
	new_ho_cmd = NULL;
}

static void _expect_as_cmd(struct gsm_lchan *lchan)
{
	fprintf(stderr, "- Expecting Assignment Command at %s\n",
		gsm_lchan_name(lchan));

	if (!new_as_cmd) {
		fprintf(stderr, "Test failed, no Assignment Command\n");
		exit(1);
	}
	fprintf(stderr, " * Got Assignment Command at %s\n", gsm_lchan_name(new_as_cmd));
	if (new_as_cmd != lchan) {
		fprintf(stderr, "Test failed, Assignment Command not on the expected lchan\n");
		exit(1);
	}
	last_as_cmd = new_as_cmd;
	new_as_cmd = NULL;
}

DEFUN(expect_chan, expect_chan_cmd,
      "expect-chan " LCHAN_ARGS,
      "Expect RSL Channel Activation of a specific lchan\n"
      LCHAN_ARGS_DOC)
{
	VTY_ECHO();
	_expect_chan_activ(parse_lchan_args(argv));
	return CMD_SUCCESS;
}

DEFUN(expect_handover_command, expect_handover_command_cmd,
      "expect-ho-cmd " LCHAN_ARGS,
      "Expect an RR Handover Command sent to a specific lchan\n"
      LCHAN_ARGS_DOC)
{
	VTY_ECHO();
	_expect_ho_cmd(parse_lchan_args(argv));
	return CMD_SUCCESS;
}

DEFUN(expect_assignment_command, expect_assignment_command_cmd,
      "expect-as-cmd " LCHAN_ARGS,
      "Expect Assignment Command for a given lchan\n"
      LCHAN_ARGS_DOC)
{
	VTY_ECHO();
	_expect_as_cmd(parse_lchan_args(argv));
	return CMD_SUCCESS;
}

DEFUN(ho_detection, ho_detection_cmd,
      "ho-detect",
      "Send Handover Detection to the most recent HO target lchan\n")
{
	VTY_ECHO();
	if (!last_chan_req) {
		fprintf(stderr, "Cannot ack handover/assignment, because no chan request\n");
		exit(1);
	}
	send_ho_detect(last_chan_req);
	return CMD_SUCCESS;
}

DEFUN(ho_complete, ho_complete_cmd,
      "ho-complete",
      "Send Handover Complete for the most recent HO target lchan\n")
{
	VTY_ECHO();
	if (!last_chan_req) {
		fprintf(stderr, "Cannot ack handover/assignment, because no chan request\n");
		exit(1);
	}
	if (!last_ho_cmd) {
		fprintf(stderr, "Cannot ack handover/assignment, because no ho request\n");
		exit(1);
	}
	send_ho_complete(last_chan_req, true);
	lchan_release_ack(last_ho_cmd);
	return CMD_SUCCESS;
}

DEFUN(expect_ho, expect_ho_cmd,
      "expect-ho from " LCHAN_ARGS " to " LCHAN_ARGS,
      "Expect a handover of a specific lchan to a specific target lchan;"
      " shorthand for expect-chan, ack-chan, expect-ho, ho-complete.\n"
      "lchan to handover from\n" LCHAN_ARGS_DOC
      "lchan to handover to\n" LCHAN_ARGS_DOC)
{
	struct gsm_lchan *from = parse_lchan_args(argv);
	struct gsm_lchan *to = parse_lchan_args(argv+4);
	VTY_ECHO();

	_expect_chan_activ(to);
	_expect_ho_cmd(from);
	send_ho_detect(to);
	send_ho_complete(to, true);

	lchan_release_ack(from);
	return CMD_SUCCESS;
}

DEFUN(expect_as, expect_as_cmd,
      "expect-as from " LCHAN_ARGS " to " LCHAN_ARGS,
      "Expect an intra-cell re-assignment of a specific lchan to a specific target lchan;"
      " shorthand for expect-chan, ack-chan, expect-as, TODO.\n"
      "lchan to be re-assigned elsewhere\n" LCHAN_ARGS_DOC
      "new lchan to re-assign to\n" LCHAN_ARGS_DOC)
{
	struct gsm_lchan *from = parse_lchan_args(argv);
	struct gsm_lchan *to = parse_lchan_args(argv+4);
	VTY_ECHO();

	_expect_chan_activ(to);
	if (from->ts->trx->bts != to->ts->trx->bts) {
		vty_out(vty, "%% Error: re-assignment only works within the same BTS%s", VTY_NEWLINE);
		return CMD_WARNING;
	}
	_expect_as_cmd(from);
	send_assignment_complete(to);
	send_est_ind(to);

	lchan_release_ack(from);
	return CMD_SUCCESS;
}

DEFUN(ho_failed, ho_failed_cmd,
      "ho-failed",
      "Fail the most recent handover request\n")
{
	VTY_ECHO();
	if (!last_chan_req) {
		fprintf(stderr, "Cannot fail handover, because no chan request\n");
		exit(1);
	}
	if (!last_ho_cmd) {
		fprintf(stderr, "Cannot fail handover, because no handover request\n");
		exit(1);
	}
	send_ho_complete(last_ho_cmd, false);
	lchan_release_ack(last_chan_req);
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
	VTY_ECHO();
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
	VTY_ECHO();
	osmo_talloc_replace_string(ctx, &codec_tch_f, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(codec_h, codec_h_cmd,
	"codec tch/h (AMR|HR)",
	"Define which codec should be used for new TCH/H lchans (for set-ts-use)\n"
	"Configure the TCH/H codec to use\nAMR\nHR\n")
{
	VTY_ECHO();
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
	VTY_ECHO();
	argv += 2;
	argc -= 2;
	if (!_set_ts_use(bts, trx, argv))
		exit(1);
	if (!_expect_ts_use(bts, trx, argv))
		exit(1);
	return CMD_SUCCESS;
}

DEFUN(wait, wait_cmd,
	"wait <0-999999> [<0-999>]",
	"Let some fake time pass. The test continues instantaneously, but this overrides osmo_gettimeofday() to let"
	" given amount of time pass virtually.\n"
	"Seconds to fake-wait\n"
	"Microseconds to fake-wait, in addition to the seconds waited\n")
{
	time_t seconds = atoi(argv[0]);
	suseconds_t useconds = 0;
	VTY_ECHO();
	if (argc > 1)
		useconds = atoi(argv[1]) * 1000;
	fake_time_passes(seconds, useconds);
	return CMD_SUCCESS;
}

static void ho_test_vty_init()
{
	install_element(CONFIG_NODE, &create_n_bts_cmd);
	install_element(CONFIG_NODE, &create_bts_cmd);
	install_element(CONFIG_NODE, &create_ms_cmd);
	install_element(CONFIG_NODE, &meas_rep_cmd);
	install_element(CONFIG_NODE, &meas_rep_repeat_cmd);
	install_element(CONFIG_NODE, &meas_rep_repeat_bspower_cmd);
	install_element(CONFIG_NODE, &res_ind_cmd);
	install_element(CONFIG_NODE, &congestion_check_cmd);
	install_element(CONFIG_NODE, &expect_no_chan_cmd);
	install_element(CONFIG_NODE, &expect_chan_cmd);
	install_element(CONFIG_NODE, &expect_handover_command_cmd);
	install_element(CONFIG_NODE, &expect_assignment_command_cmd);
	install_element(CONFIG_NODE, &ho_detection_cmd);
	install_element(CONFIG_NODE, &ho_complete_cmd);
	install_element(CONFIG_NODE, &expect_ho_cmd);
	install_element(CONFIG_NODE, &expect_as_cmd);
	install_element(CONFIG_NODE, &ho_failed_cmd);
	install_element(CONFIG_NODE, &expect_ts_use_cmd);
	install_element(CONFIG_NODE, &codec_f_cmd);
	install_element(CONFIG_NODE, &codec_h_cmd);
	install_element(CONFIG_NODE, &set_ts_use_cmd);
	install_element(CONFIG_NODE, &wait_cmd);
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

	log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_BASENAME);
	log_set_print_filename_pos(osmo_stderr_target, LOG_FILENAME_POS_LINE_END);
	log_set_print_category(osmo_stderr_target, 1);
	log_set_print_category_hex(osmo_stderr_target, 0);
	log_set_print_level(osmo_stderr_target, 1);
	log_set_print_timestamp(osmo_stderr_target, 0);
	osmo_fsm_log_addr(false);

	/* the 'wait' command above, intended to test penalty timers, adds seconds to the monotonic clock in "fake
	 * time". */
	fake_time_start();

	bsc_network_alloc();
	if (!bsc_gsmnet)
		exit(1);

	/* The MGCP client which is handling the pool (mgcp_client_pool_vty_init) is used from the bsc_vty_init, so
	 * we must allocate an empty mgw pool even though we do not need it for this test. */
	bsc_gsmnet->mgw.mgw_pool = mgcp_client_pool_alloc(bsc_gsmnet);
	if (!bsc_gsmnet->mgw.mgw_pool)
		exit(1);

	vty_init(&vty_info);
	bsc_vty_init(bsc_gsmnet);
	ho_test_vty_init();

	lchan_fsm_init();
	bsc_subscr_conn_fsm_init();
	handover_fsm_init();
	assignment_fsm_init();

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
/* Stub */
int osmo_bsc_sigtran_open_conn(struct gsm_subscriber_connection *conn, struct msgb *msg) { return 0; }
void bsc_sapi_n_reject(struct gsm_subscriber_connection *conn, uint8_t dlci, enum gsm0808_cause cause) {}
void bsc_cipher_mode_compl(struct gsm_subscriber_connection *conn, struct msgb *msg, uint8_t chosen_a5_n) {}
int bsc_compl_l3(struct gsm_lchan *lchan, struct msgb *msg, uint16_t chosen_channel)
{ return 0; }
void bsc_dtap(struct gsm_subscriber_connection *conn, uint8_t link_id, struct msgb *msg) {}
void bsc_assign_compl(struct gsm_subscriber_connection *conn, uint8_t rr_cause) {}
void bsc_cm_update(struct gsm_subscriber_connection *conn,
		   const uint8_t *cm2, uint8_t cm2_len,
		   const uint8_t *cm3, uint8_t cm3_len) {}
const char *osmo_mgcpc_ep_name(const struct osmo_mgcpc_ep *ep)
{
	return "fake-ep";
}
const char *osmo_mgcpc_ep_ci_name(const struct osmo_mgcpc_ep_ci *ci)
{
	return "fake-ci";
}
const struct mgcp_conn_peer *osmo_mgcpc_ep_ci_get_rtp_info(const struct osmo_mgcpc_ep_ci *ci)
{
	static struct mgcp_conn_peer ret = {
		.addr = "1.2.3.4",
		.port = 1234,
		.endpoint = "fake-endpoint",
	};
	return &ret;
}
struct mgcp_client *osmo_mgcpc_ep_client(const struct osmo_mgcpc_ep *ep)
{
	return NULL;
}
