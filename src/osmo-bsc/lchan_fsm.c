/* osmo-bsc API to allocate an lchan, complete with dyn TS switchover and MGCP communication to allocate
 * RTP endpoints.
 *
 * (C) 2018 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr <neels@hofmeyr.de>
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

#include <osmocom/gsm/rsl.h>
#include <osmocom/core/byteswap.h>

#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/lchan_fsm.h>
#include <osmocom/bsc/timeslot_fsm.h>
#include <osmocom/bsc/mgw_endpoint_fsm.h>
#include <osmocom/bsc/bsc_subscr_conn_fsm.h>
#include <osmocom/bsc/handover.h>
#include <osmocom/bsc/abis_rsl.h>
#include <osmocom/bsc/bsc_rll.h>
#include <osmocom/bsc/gsm_04_08_rr.h>
#include <osmocom/bsc/assignment_fsm.h>
#include <osmocom/bsc/handover_fsm.h>
#include <osmocom/bsc/bsc_msc_data.h>

static struct osmo_fsm lchan_fsm;

struct gsm_lchan *lchan_fi_lchan(struct osmo_fsm_inst *fi)
{
	OSMO_ASSERT(fi);
	OSMO_ASSERT(fi->fsm == &lchan_fsm);
	OSMO_ASSERT(fi->priv);
	return fi->priv;
}

bool lchan_may_receive_data(struct gsm_lchan *lchan)
{
	if (!lchan || !lchan->fi)
		return false;

	switch (lchan->fi->state) {
	case LCHAN_ST_WAIT_RLL_ESTABLISH:
	case LCHAN_ST_WAIT_MGW_ENDPOINT_AVAILABLE:
	case LCHAN_ST_WAIT_IPACC_CRCX_ACK:
	case LCHAN_ST_WAIT_IPACC_MDCX_ACK:
	case LCHAN_ST_WAIT_MGW_ENDPOINT_CONFIGURED:
	case LCHAN_ST_ESTABLISHED:
		return true;
	default:
		return false;
	}
}

static void lchan_set_last_error(struct gsm_lchan *lchan, const char *fmt, ...)
{
	va_list ap;
	/* This dance allows using an existing error reason in above fmt */
	char *last_error_was = lchan->last_error;
	lchan->last_error = NULL;

	if (fmt) {
		va_start(ap, fmt);
		lchan->last_error = talloc_vasprintf(lchan->ts->trx, fmt, ap);
		va_end(ap);

		LOG_LCHAN(lchan, LOGL_ERROR, "%s\n", lchan->last_error);
	}

	if (last_error_was)
		talloc_free(last_error_was);
}

/* The idea here is that we must not require to change any lchan state in order to deny a request. */
#define lchan_on_activation_failure(lchan, for_conn, activ_for) \
	_lchan_on_activation_failure(lchan, for_conn, activ_for, \
				     __FILE__, __LINE__)
static void _lchan_on_activation_failure(struct gsm_lchan *lchan, enum lchan_activate_mode activ_for,
					 struct gsm_subscriber_connection *for_conn,
					 const char *file, int line)
{
	switch (activ_for) {

	case FOR_MS_CHANNEL_REQUEST:
		LOG_LCHAN(lchan, LOGL_NOTICE, "Tx Immediate Assignment Reject (%s)\n",
			  lchan->last_error ? : "unknown error");
		rsl_tx_imm_ass_rej(lchan->ts->trx->bts, lchan->rqd_ref);
		break;

	case FOR_ASSIGNMENT:
		LOG_LCHAN(lchan, LOGL_NOTICE, "Signalling Assignment FSM of error (%s)\n",
			  lchan->last_error ? : "unknown error");
		_osmo_fsm_inst_dispatch(for_conn->assignment.fi, ASSIGNMENT_EV_LCHAN_ERROR, lchan,
					file, line);
		return;

	case FOR_HANDOVER:
		LOG_LCHAN(lchan, LOGL_NOTICE, "Signalling Handover FSM of error (%s)\n",
			  lchan->last_error ? : "unknown error");
		if (!for_conn) {
			LOG_LCHAN(lchan, LOGL_ERROR,
				  "lchan activation for Handover failed, but activation request has"
				  " no conn\n");
			break;
		}
		if (!for_conn->ho.fi) {
			LOG_LCHAN(lchan, LOGL_ERROR,
				  "lchan activation for Handover failed, but conn has no ongoing"
				  " handover procedure\n");
			break;
		}
		_osmo_fsm_inst_dispatch(for_conn->ho.fi, HO_EV_LCHAN_ERROR, lchan, file, line);
		break;

	case FOR_VTY:
		LOG_LCHAN(lchan, LOGL_ERROR, "VTY user invoked lchan activation failed (%s)\n",
			  lchan->last_error ? : "unknown error");
		break;

	default:
		LOG_LCHAN(lchan, LOGL_ERROR, "lchan activation failed (%s)\n",
			  lchan->last_error ? : "unknown error");
		break;
	}
}

static void lchan_on_activation_success(struct gsm_lchan *lchan)
{
	switch (lchan->activate.activ_for) {
	case FOR_MS_CHANNEL_REQUEST:
		/* Nothing to do here, MS is free to use the channel. */
		break;

	case FOR_ASSIGNMENT:
		if (!lchan->conn) {
			LOG_LCHAN(lchan, LOGL_ERROR,
				  "lchan activation for assignment succeeded, but lchan has no conn:"
				  " cannot trigger appropriate actions. Release.\n");
			lchan_release(lchan, false, true, RSL_ERR_EQUIPMENT_FAIL);
			break;
		}
		if (!lchan->conn->assignment.fi) {
			LOG_LCHAN(lchan, LOGL_ERROR,
				  "lchan activation for assignment succeeded, but lchan has no"
				  " assignment ongoing: cannot trigger appropriate actions. Release.\n");
			lchan_release(lchan, false, true, RSL_ERR_EQUIPMENT_FAIL);
			break;
		}
		osmo_fsm_inst_dispatch(lchan->conn->assignment.fi, ASSIGNMENT_EV_LCHAN_ESTABLISHED,
				       lchan);
		break;

	case FOR_HANDOVER:
		if (!lchan->conn) {
			LOG_LCHAN(lchan, LOGL_ERROR,
				  "lchan activation for handover succeeded, but lchan has no conn\n");
			lchan_release(lchan, false, true, RSL_ERR_EQUIPMENT_FAIL);
			break;
		}
		if (!lchan->conn->ho.fi) {
			LOG_LCHAN(lchan, LOGL_ERROR,
				  "lchan activation for handover succeeded, but lchan has no"
				  " handover ongoing\n");
			lchan_release(lchan, false, true, RSL_ERR_EQUIPMENT_FAIL);
			break;
		}
		osmo_fsm_inst_dispatch(lchan->conn->ho.fi, HO_EV_LCHAN_ESTABLISHED, lchan);
		break;

	default:
		LOG_LCHAN(lchan, LOGL_NOTICE, "lchan %s fully established\n",
			  lchan_activate_mode_name(lchan->activate.activ_for));
		break;
	}
}

struct state_timeout lchan_fsm_timeouts[32] = {
	[LCHAN_ST_WAIT_TS_READY]	= { .T=23001 },
	[LCHAN_ST_WAIT_ACTIV_ACK]	= { .T=23002 },
	[LCHAN_ST_WAIT_RLL_ESTABLISH]	= { .T=3101 },
	[LCHAN_ST_WAIT_MGW_ENDPOINT_AVAILABLE] = { .T=23004 },
	[LCHAN_ST_WAIT_IPACC_CRCX_ACK]	= { .T=23005 },
	[LCHAN_ST_WAIT_IPACC_MDCX_ACK]	= { .T=23006 },
	[LCHAN_ST_WAIT_MGW_ENDPOINT_CONFIGURED] = { .T=23004 },
	[LCHAN_ST_WAIT_SAPIS_RELEASED]	= { .T=3109 },
	[LCHAN_ST_WAIT_BEFORE_RF_RELEASE]	= { .T=3111 },
	[LCHAN_ST_WAIT_RF_RELEASE_ACK]	= { .T=3111 },
	[LCHAN_ST_WAIT_AFTER_ERROR]	= { .T=993111 },
};

/* Transition to a state, using the T timer defined in lchan_fsm_timeouts.
 * The actual timeout value is in turn obtained from network->T_defs.
 * Assumes local variable fi exists. */
#define lchan_fsm_state_chg(state) \
	fsm_inst_state_chg_T(fi, state, \
			     lchan_fsm_timeouts, \
			     ((struct gsm_lchan*)(fi->priv))->ts->trx->bts->network->T_defs, \
			     5)

/* Set a failure message, trigger the common actions to take on failure, transition to a state to
 * continue with (using state timeouts from lchan_fsm_timeouts[]). Assumes local variable fi exists. */
#define lchan_fail_to(state_chg, fmt, args...) do { \
		struct gsm_lchan *_lchan = fi->priv; \
		uint32_t state_was = fi->state; \
		lchan_set_last_error(fi->priv, "lchan %s in state %s: " fmt, \
				     _lchan->activate.concluded ? "failure" : "allocation failed", \
				     osmo_fsm_state_name(fi->fsm, state_was), ## args); \
		if (!_lchan->activate.concluded) \
			lchan_on_activation_failure(_lchan, _lchan->activate.activ_for, _lchan->conn); \
		_lchan->activate.concluded = true; \
		lchan_fsm_state_chg(state_chg); \
	} while(0)

/* Which state to transition to when lchan_fail() is called in a given state. */
uint32_t lchan_fsm_on_error[32] = {
	[LCHAN_ST_UNUSED] 			= LCHAN_ST_UNUSED,
	[LCHAN_ST_WAIT_TS_READY] 		= LCHAN_ST_UNUSED,
	[LCHAN_ST_WAIT_ACTIV_ACK] 		= LCHAN_ST_BORKEN,
	[LCHAN_ST_WAIT_RLL_ESTABLISH] 		= LCHAN_ST_WAIT_RF_RELEASE_ACK,
	[LCHAN_ST_WAIT_MGW_ENDPOINT_AVAILABLE] 	= LCHAN_ST_WAIT_SAPIS_RELEASED,
	[LCHAN_ST_WAIT_IPACC_CRCX_ACK] 		= LCHAN_ST_WAIT_SAPIS_RELEASED,
	[LCHAN_ST_WAIT_IPACC_MDCX_ACK] 		= LCHAN_ST_WAIT_SAPIS_RELEASED,
	[LCHAN_ST_WAIT_MGW_ENDPOINT_CONFIGURED]	= LCHAN_ST_WAIT_SAPIS_RELEASED,
	[LCHAN_ST_ESTABLISHED] 			= LCHAN_ST_WAIT_SAPIS_RELEASED,
	[LCHAN_ST_WAIT_SAPIS_RELEASED] 		= LCHAN_ST_WAIT_RF_RELEASE_ACK,
	[LCHAN_ST_WAIT_BEFORE_RF_RELEASE] 	= LCHAN_ST_WAIT_RF_RELEASE_ACK,
	[LCHAN_ST_WAIT_RF_RELEASE_ACK] 		= LCHAN_ST_BORKEN,
	[LCHAN_ST_WAIT_AFTER_ERROR] 		= LCHAN_ST_UNUSED,
	[LCHAN_ST_BORKEN] 			= LCHAN_ST_BORKEN,
};

#define lchan_fail(fmt, args...) lchan_fail_to(lchan_fsm_on_error[fi->state], fmt, ## args)

void lchan_activate(struct gsm_lchan *lchan, struct lchan_activate_info *info)
{
	int rc;

	OSMO_ASSERT(lchan && info);

	if (!lchan_state_is(lchan, LCHAN_ST_UNUSED))
		goto abort;

	/* ensure some basic sanity up first, before we enter the machine. */
	OSMO_ASSERT(lchan->ts && lchan->ts->fi && lchan->fi);

	switch (info->activ_for) {

	case FOR_ASSIGNMENT:
		if (!info->for_conn
		    || !info->for_conn->fi) {
			LOG_LCHAN(lchan, LOGL_ERROR, "Activation requested, but no conn\n");
			goto abort;
		}
		if (info->for_conn->assignment.new_lchan != lchan) {
			LOG_LCHAN(lchan, LOGL_ERROR,
				  "Activation for Assignment requested, but conn's state does"
				  " not reflect this lchan to be activated (instead: %s)\n",
				  info->for_conn->assignment.new_lchan?
					gsm_lchan_name(info->for_conn->assignment.new_lchan)
					: "NULL");
			goto abort;
		}
		break;

	case FOR_HANDOVER:
		if (!info->for_conn
		    || !info->for_conn->fi) {
			LOG_LCHAN(lchan, LOGL_ERROR, "Activation requested, but no conn\n");
			goto abort;
		}
		if (!info->for_conn->ho.fi)  {
			LOG_LCHAN(lchan, LOGL_ERROR,
				  "Activation for Handover requested, but conn has no HO pending.\n");
			goto abort;
		}
		if (info->for_conn->ho.new_lchan != lchan) {
			LOG_LCHAN(lchan, LOGL_ERROR,
				  "Activation for Handover requested, but conn's HO state does"
				  " not reflect this lchan to be activated (instead: %s)\n",
				  info->for_conn->ho.new_lchan?
					gsm_lchan_name(info->for_conn->ho.new_lchan)
					: "NULL");
			goto abort;
		}
		break;

	default:
		break;
	}

	/* To make sure that the lchan is actually allowed to initiate an activation, feed through an FSM
	 * event. */
	rc = osmo_fsm_inst_dispatch(lchan->fi, LCHAN_EV_ACTIVATE, info);

	if (rc) {
		LOG_LCHAN(lchan, LOGL_ERROR,
			  "Activation requested, but cannot dispatch LCHAN_EV_ACTIVATE event\n");
		goto abort;
	}
	return;

abort:
	lchan_on_activation_failure(lchan, info->activ_for, info->for_conn);
	/* Remain in state UNUSED */
}

static void lchan_fsm_update_id(struct gsm_lchan *lchan)
{
	osmo_fsm_inst_update_id_f(lchan->fi, "%u-%u-%u-%s-%u",
				  lchan->ts->trx->bts->nr, lchan->ts->trx->nr, lchan->ts->nr,
				  gsm_pchan_id(lchan->ts->pchan_on_init), lchan->nr);
}

void lchan_fsm_init()
{
	OSMO_ASSERT(osmo_fsm_register(&lchan_fsm) == 0);
}

void lchan_fsm_alloc(struct gsm_lchan *lchan)
{
	OSMO_ASSERT(lchan->ts);
	OSMO_ASSERT(lchan->ts->fi);
	OSMO_ASSERT(!lchan->fi);

	lchan->fi = osmo_fsm_inst_alloc_child(&lchan_fsm, lchan->ts->fi, TS_EV_LCHAN_UNUSED);
	OSMO_ASSERT(lchan->fi);
	lchan->fi->priv = lchan;
	lchan_fsm_update_id(lchan);
	LOGPFSML(lchan->fi, LOGL_DEBUG, "new lchan\n");
}

/* Clear volatile state of the lchan. Clear all except
 * - the ts backpointer,
 * - the nr,
 * - name,
 * - the FSM instance including its current state,
 * - last_error string.
 */
static void lchan_reset(struct gsm_lchan *lchan)
{
	LOG_LCHAN(lchan, LOGL_DEBUG, "Clearing lchan state\n");

	if (lchan->rqd_ref) {
		talloc_free(lchan->rqd_ref);
		lchan->rqd_ref = NULL;
	}
	if (lchan->mgw_endpoint_ci_bts) {
		mgw_endpoint_ci_dlcx(lchan->mgw_endpoint_ci_bts);
		lchan->mgw_endpoint_ci_bts = NULL;
	}

	/* NUL all volatile state */
	*lchan = (struct gsm_lchan){
		.ts = lchan->ts,
		.nr = lchan->nr,
		.fi = lchan->fi,
		.name = lchan->name,

		.meas_rep_last_seen_nr = 255,

		.last_error = lchan->last_error,
	};
}

static void lchan_fsm_unused_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct gsm_lchan *lchan = lchan_fi_lchan(fi);
	lchan_reset(lchan);
	osmo_fsm_inst_dispatch(lchan->ts->fi, TS_EV_LCHAN_UNUSED, lchan);
}

/*! Configure the multirate setting on this channel. */
void lchan_mr_config(struct gsm_lchan *lchan, struct gsm48_multi_rate_conf *mr_conf)
{
	struct gsm48_multi_rate_conf *ms_conf, *bts_conf;
	bool full_rate = (lchan->type == GSM_LCHAN_TCH_F);

	/* initialize the data structure */
	lchan->mr_ms_lv[0] = sizeof(*ms_conf);
	lchan->mr_bts_lv[0] = sizeof(*bts_conf);
	ms_conf = (struct gsm48_multi_rate_conf *) &lchan->mr_ms_lv[1];
	bts_conf = (struct gsm48_multi_rate_conf *) &lchan->mr_bts_lv[1];

	*ms_conf = *bts_conf = (struct gsm48_multi_rate_conf){
		.ver = 1,
		.icmi = 1,
		.m4_75 = mr_conf->m4_75,
		.m5_15 = mr_conf->m5_15,
		.m5_90 = mr_conf->m5_90,
		.m6_70 = mr_conf->m6_70,
		.m7_40 = mr_conf->m7_40,
		.m7_95 = mr_conf->m7_95,
		.m10_2 = full_rate? mr_conf->m10_2 : 0,
		.m12_2 = full_rate? mr_conf->m12_2 : 0,
	};
}

static void lchan_fsm_unused(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct lchan_activate_info *info = data;
	struct gsm_lchan *lchan = lchan_fi_lchan(fi);
	switch (event) {

	case LCHAN_EV_ACTIVATE:
		OSMO_ASSERT(info);
		OSMO_ASSERT(!lchan->conn);
		OSMO_ASSERT(!lchan->mgw_endpoint_ci_bts);
		lchan_set_last_error(lchan, NULL);
		lchan->release_requested = false;

		lchan->conn = info->for_conn;
		lchan->activate.activ_for = info->activ_for;
		lchan->activate.requires_voice_stream = info->requires_voice_stream;
		lchan->activate.msc_assigned_cic = info->msc_assigned_cic;
		lchan->activate.concluded = false;
		lchan->activate.re_use_mgw_endpoint_from_lchan = info->old_lchan;

		if (info->old_lchan) {
			/* TODO: rather take info->for_conn->encr? */
			lchan->encr = info->old_lchan->encr;
			lchan->ms_power = info->old_lchan->ms_power;
			lchan->bs_power = info->old_lchan->bs_power;
			lchan->rqd_ta = info->old_lchan->rqd_ta;
		} else {
			struct gsm_bts *bts = lchan->ts->trx->bts;
			/* TODO: rather take info->for_conn->encr? */
			lchan->encr = (struct gsm_encr){
				.alg_id = RSL_ENC_ALG_A5(0),	/* no encryption */
			};
			lchan->ms_power = ms_pwr_ctl_lvl(bts->band, bts->ms_max_power);
			lchan->bs_power = 0; /* 0dB reduction, output power = Pn */
			memset(&lchan->mr_ms_lv, 0, sizeof(lchan->mr_ms_lv));
			memset(&lchan->mr_bts_lv, 0, sizeof(lchan->mr_bts_lv));
		}

		if (info->chan_mode == GSM48_CMODE_SPEECH_AMR)
			lchan_mr_config(lchan, &info->for_conn->sccp.msc->amr_conf);

		switch (info->chan_mode) {

		case GSM48_CMODE_SIGN:
			lchan->rsl_cmode = RSL_CMOD_SPD_SIGN;
			lchan->tch_mode = GSM48_CMODE_SIGN;
			break;

		case GSM48_CMODE_SPEECH_V1:
		case GSM48_CMODE_SPEECH_EFR:
		case GSM48_CMODE_SPEECH_AMR:
			lchan->rsl_cmode = RSL_CMOD_SPD_SPEECH;
			lchan->tch_mode = info->chan_mode;
			break;

		default:
			lchan_fail("Not implemented: cannot activate for chan mode %s",
				   gsm48_chan_mode_name(info->chan_mode));
			return;
		}

		lchan_fsm_state_chg(LCHAN_ST_WAIT_TS_READY);
		break;

	default:
		OSMO_ASSERT(false);
	}
}

/* While activating an lchan, for example for Handover, we may want to re-use another lchan's MGW
 * endpoint CI. If Handover fails half way, the old lchan must keep its MGW endpoint CI, and we must not
 * clean it up. Hence keep another lchan's mgw_endpoint_ci_bts out of lchan until all is done. */
static struct mgwep_ci *lchan_use_mgw_endpoint_ci_bts(struct gsm_lchan *lchan)
{
	if (lchan->mgw_endpoint_ci_bts)
		return lchan->mgw_endpoint_ci_bts;
	if (lchan_state_is(lchan, LCHAN_ST_ESTABLISHED))
		return NULL;
	if (lchan->activate.re_use_mgw_endpoint_from_lchan)
		return lchan->activate.re_use_mgw_endpoint_from_lchan->mgw_endpoint_ci_bts;
	return NULL;
}

static void lchan_fsm_wait_ts_ready_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct mgw_endpoint *mgwep;
	struct mgcp_conn_peer crcx_info = {};
	struct gsm_lchan *lchan = lchan_fi_lchan(fi);
	struct mgwep_ci *use_mgwep_ci = lchan_use_mgw_endpoint_ci_bts(lchan);

	if (lchan->release_requested) {
		lchan_fail("Release requested while activating");
		return;
	}

	LOG_LCHAN(lchan, LOGL_INFO,
		  "Activation requested: %s voice=%s MGW-ci=%s type=%s tch-mode=%s\n",
		  lchan_activate_mode_name(lchan->activate.activ_for),
		  lchan->activate.requires_voice_stream ? "yes" : "no",
		  lchan->activate.requires_voice_stream ?
			(use_mgwep_ci ? mgwep_ci_name(use_mgwep_ci) : "new")
			: "none",
		  gsm_lchant_name(lchan->type),
		  gsm48_chan_mode_name(lchan->tch_mode));

	/* Ask for the timeslot to make ready for this lchan->type.
	 * We'll receive LCHAN_EV_TS_READY or LCHAN_EV_TS_ERROR in response. */
	osmo_fsm_inst_dispatch(lchan->ts->fi, TS_EV_LCHAN_REQUESTED, lchan);

	/* Prepare an MGW endpoint CI if appropriate. */
	if (!lchan->activate.requires_voice_stream)
		return;

	if (use_mgwep_ci) {
		lchan->activate.mgw_endpoint_available = true;
		return;
	}

	mgwep = gscon_ensure_mgw_endpoint(lchan->conn, lchan->activate.msc_assigned_cic);
	if (!mgwep) {
		lchan_fail("Internal error: cannot obtain MGW endpoint handle for conn");
		return;
	}

	lchan->mgw_endpoint_ci_bts = mgw_endpoint_ci_add(mgwep, "to-BTS");

	if (lchan->conn)
		crcx_info.call_id = lchan->conn->sccp.conn_id;
	crcx_info.ptime = 20;
	mgcp_pick_codec(&crcx_info, lchan);

	mgw_endpoint_ci_request(lchan->mgw_endpoint_ci_bts,
				MGCP_VERB_CRCX, &crcx_info,
				lchan->fi,
				LCHAN_EV_MGW_ENDPOINT_AVAILABLE,
				LCHAN_EV_MGW_ENDPOINT_ERROR, 0);
}

static void lchan_fsm_wait_ts_ready(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_lchan *lchan = lchan_fi_lchan(fi);
	switch (event) {

	case LCHAN_EV_TS_READY:
		/* timeslot agrees that we may Chan Activ now. Sending it in onenter. */
		lchan_fsm_state_chg(LCHAN_ST_WAIT_ACTIV_ACK);
		break;

	case LCHAN_EV_MGW_ENDPOINT_AVAILABLE:
		/* conn FSM is already done preparing an MGW endpoint. Remember that. */
		lchan->activate.mgw_endpoint_available = true;
		break;

	default:
		OSMO_ASSERT(false);
	}
}

static void lchan_fsm_wait_activ_ack_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	int rc;
	uint8_t act_type;
	uint8_t ho_ref = 0;
	struct gsm_lchan *lchan = lchan_fi_lchan(fi);

	if (lchan->release_requested) {
		lchan_fail_to(LCHAN_ST_UNUSED, "Release requested while activating");
		return;
	}

	switch (lchan->activate.activ_for) {
	case FOR_MS_CHANNEL_REQUEST:
		act_type = RSL_ACT_INTRA_IMM_ASS;
		break;
	case FOR_HANDOVER:
		act_type = lchan->conn->ho.async ? RSL_ACT_INTER_ASYNC : RSL_ACT_INTER_SYNC;
		ho_ref = lchan->conn->ho.ho_ref;
		break;
	default:
	case FOR_ASSIGNMENT:
		act_type = RSL_ACT_INTRA_NORM_ASS;
		break;
	}

	rc = rsl_tx_chan_activ(lchan, act_type, ho_ref);
	if (rc)
		lchan_fail_to(LCHAN_ST_UNUSED, "Tx Chan Activ failed: %s (%d)", strerror(-rc), rc);
}

static void lchan_fsm_wait_activ_ack(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_lchan *lchan = lchan_fi_lchan(fi);
	switch (event) {

	case LCHAN_EV_MGW_ENDPOINT_AVAILABLE:
		lchan->activate.mgw_endpoint_available = true;
		break;

	case LCHAN_EV_RSL_CHAN_ACTIV_ACK:
		/* Chan Activ was ack'd, but we need an RLL Establish to be sure it's working out. */
		lchan_fsm_state_chg(LCHAN_ST_WAIT_RLL_ESTABLISH);
		break;

	case LCHAN_EV_RSL_CHAN_ACTIV_NACK:
		if (data) {
			uint32_t next_state;
			lchan->rsl_error_cause = *(uint8_t*)data;
			lchan->release_in_error = true;
			if (lchan->rsl_error_cause != RSL_ERR_RCH_ALR_ACTV_ALLOC)
				next_state = LCHAN_ST_BORKEN;
			else
				/* Taking this over from legacy code: send an RF Chan Release even though
				 * the Activ was NACKed. Is this really correct? */
				next_state = LCHAN_ST_WAIT_RF_RELEASE_ACK;

			lchan_fail_to(next_state, "Chan Activ NACK: %s (0x%x)",
				      rsl_err_name(lchan->rsl_error_cause), lchan->rsl_error_cause);
		} else {
			lchan->rsl_error_cause = RSL_ERR_IE_NONEXIST;
			lchan->release_in_error = true;
			lchan_fail_to(LCHAN_ST_BORKEN, "Chan Activ NACK without cause IE");
		}
		break;

	default:
		OSMO_ASSERT(false);
	}
}

static void lchan_fsm_wait_rll_establish_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	int rc;
	struct gsm_lchan *lchan = lchan_fi_lchan(fi);
	if (lchan->release_requested) {
		lchan_fail_to(LCHAN_ST_WAIT_RF_RELEASE_ACK, "Release requested while activating");
		return;
	}

	switch (lchan->activate.activ_for) {

	case FOR_MS_CHANNEL_REQUEST:
		rc = rsl_tx_imm_assignment(lchan);
		if (rc) {
			lchan_fail("Failed to Tx RR Immediate Assignment message (rc=%d %s)\n",
				   rc, strerror(-rc));
			return;
		}
		LOG_LCHAN(lchan, LOGL_DEBUG, "Tx RR Immediate Assignment\n");
		break;

	case FOR_ASSIGNMENT:
		if (!lchan->conn) {
			LOG_LCHAN(lchan, LOGL_ERROR,
				  "lchan activation for assignment succeeded, but lchan has no conn:"
				  " cannot trigger appropriate actions. Release.\n");
			lchan_release(lchan, false, true, RSL_ERR_EQUIPMENT_FAIL);
			break;
		}
		if (!lchan->conn->assignment.fi) {
			LOG_LCHAN(lchan, LOGL_ERROR,
				  "lchan activation for assignment succeeded, but lchan has no"
				  " assignment ongoing: cannot trigger appropriate actions. Release.\n");
			lchan_release(lchan, false, true, RSL_ERR_EQUIPMENT_FAIL);
			break;
		}
		/* After the Chan Activ Ack, the MS expects to receive an RR Assignment Command.
		 * Let the assignment_fsm handle that. */
		osmo_fsm_inst_dispatch(lchan->conn->assignment.fi, ASSIGNMENT_EV_LCHAN_ACTIVE, lchan);
		break;

	case FOR_HANDOVER:
		if (!lchan->conn) {
			LOG_LCHAN(lchan, LOGL_ERROR,
				  "lchan activation for handover succeeded, but lchan has no conn:"
				  " cannot trigger appropriate actions. Release.\n");
			lchan_release(lchan, false, true, RSL_ERR_EQUIPMENT_FAIL);
			break;
		}
		if (!lchan->conn->ho.fi) {
			LOG_LCHAN(lchan, LOGL_ERROR,
				  "lchan activation for handover succeeded, but lchan has no"
				  " handover ongoing: cannot trigger appropriate actions. Release.\n");
			lchan_release(lchan, false, true, RSL_ERR_EQUIPMENT_FAIL);
			break;
		}
		/* After the Chan Activ Ack of the new lchan, send the MS an RR Handover Command on the
		 * old channel. The handover_fsm handles that. */
		osmo_fsm_inst_dispatch(lchan->conn->ho.fi, HO_EV_LCHAN_ACTIVE, lchan);
		break;

	default:
		LOG_LCHAN(lchan, LOGL_NOTICE, "lchan %s is now active\n",
			  lchan_activate_mode_name(lchan->activate.activ_for));
		break;
	}
}

static void lchan_fsm_wait_rll_establish(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_lchan *lchan = lchan_fi_lchan(fi);
	switch (event) {

	case LCHAN_EV_MGW_ENDPOINT_AVAILABLE:
		lchan->activate.mgw_endpoint_available = true;
		break;

	case LCHAN_EV_RLL_ESTABLISH_IND:
		lchan->sapis[0] = LCHAN_SAPI_MS;
		if (lchan->activate.requires_voice_stream) {
			/* For Abis/IP, we would technically only need the MGW endpoint one step later,
			 * on IPACC MDCX. But usually the MGW endpoint is anyway done by now, so keep one
			 * common endpoint wait state for all BTS types. */
			lchan_fsm_state_chg(LCHAN_ST_WAIT_MGW_ENDPOINT_AVAILABLE);
		} else
			lchan_fsm_state_chg(LCHAN_ST_ESTABLISHED);
		break;

	default:
		OSMO_ASSERT(false);
	}
}

static void lchan_fsm_tch_post_endpoint_available(struct osmo_fsm_inst *fi);

static void lchan_fsm_wait_mgw_endpoint_available_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct gsm_lchan *lchan = lchan_fi_lchan(fi);

	if (lchan->release_requested) {
		lchan_fail("Release requested while activating");
		return;
	}

	if (lchan->activate.mgw_endpoint_available) {
		LOG_LCHAN(lchan, LOGL_DEBUG, "MGW endpoint already available\n");
		lchan_fsm_tch_post_endpoint_available(fi);
	}
}

static void lchan_fsm_wait_mgw_endpoint_available(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_lchan *lchan = lchan_fi_lchan(fi);
	switch (event) {

	case LCHAN_EV_MGW_ENDPOINT_AVAILABLE:
		lchan->activate.mgw_endpoint_available = true;
		lchan_fsm_tch_post_endpoint_available(fi);
		break;

	default:
		OSMO_ASSERT(false);
	}
}

static void lchan_fsm_tch_post_endpoint_available(struct osmo_fsm_inst *fi)
{
	struct gsm_lchan *lchan = lchan_fi_lchan(fi);

	LOG_LCHAN(lchan, LOGL_DEBUG, "MGW endpoint: %s\n",
		  mgwep_ci_name(lchan_use_mgw_endpoint_ci_bts(lchan)));

	if (is_ipaccess_bts(lchan->ts->trx->bts))
		lchan_fsm_state_chg(LCHAN_ST_WAIT_IPACC_CRCX_ACK);
	else
		lchan_fsm_state_chg(LCHAN_ST_WAIT_MGW_ENDPOINT_CONFIGURED);
}

static void lchan_fsm_wait_ipacc_crcx_ack_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	int rc;
	int val;
	struct gsm_lchan *lchan = lchan_fi_lchan(fi);

	if (lchan->release_requested) {
		lchan_fail("Release requested while activating");
		return;
	}

	val = ipacc_speech_mode(lchan->tch_mode, lchan->type);
	if (val < 0) {
		lchan_fail("Cannot determine Abis/IP speech mode for tch_mode=%s type=%s\n",
			   get_value_string(gsm48_chan_mode_names, lchan->tch_mode),
			   gsm_lchant_name(lchan->type));
		return;
	}
	lchan->abis_ip.speech_mode = val;

	val = ipacc_payload_type(lchan->tch_mode, lchan->type);
	if (val < 0) {
		lchan_fail("Cannot determine Abis/IP payload type for tch_mode=%s type=%s\n",
			   get_value_string(gsm48_chan_mode_names, lchan->tch_mode),
			   gsm_lchant_name(lchan->type));
		return;
	}
	lchan->abis_ip.rtp_payload = val;

	/* recv-only */
	ipacc_speech_mode_set_direction(&lchan->abis_ip.speech_mode, false);

	rc = rsl_tx_ipacc_crcx(lchan);
	if (rc)
		lchan_fail("Failure to transmit IPACC CRCX to BTS (rc=%d, %s)",
			   rc, strerror(-rc));
}

static void lchan_fsm_wait_ipacc_crcx_ack(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {

	case LCHAN_EV_IPACC_CRCX_ACK:
		/* the CRCX ACK parsing has already noted the RTP port information at
		 * lchan->abis_ip.bound_*, see ipac_parse_rtp(). We'll use that in
		 * lchan_fsm_wait_mgw_endpoint_configured_onenter(). */
		lchan_fsm_state_chg(LCHAN_ST_WAIT_IPACC_MDCX_ACK);
		return;

	case LCHAN_EV_IPACC_CRCX_NACK:
		lchan_fail("Received NACK on IPACC CRCX");
		return;

	default:
		OSMO_ASSERT(false);
	}
}

static void lchan_fsm_wait_ipacc_mdcx_ack_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	int rc;
	struct gsm_lchan *lchan = lchan_fi_lchan(fi);
	const struct mgcp_conn_peer *mgw_rtp;

	if (lchan->release_requested) {
		lchan_fail("Release requested while activating");
		return;
	}

	mgw_rtp = mgwep_ci_get_rtp_info(lchan_use_mgw_endpoint_ci_bts(lchan));

	if (!mgw_rtp) {
		lchan_fail("Cannot send IPACC MDCX to BTS:"
			   " there is no RTP IP+port set that the BTS should send RTP to.");
		return;
	}

	/* Other RTP settings were already setup in lchan_fsm_wait_ipacc_crcx_ack_onenter() */
	lchan->abis_ip.connect_ip = ntohl(inet_addr(mgw_rtp->addr));
	lchan->abis_ip.connect_port = mgw_rtp->port;

	/* send-recv */
	ipacc_speech_mode_set_direction(&lchan->abis_ip.speech_mode, true);

	rc = rsl_tx_ipacc_mdcx(lchan);
	if (rc)
		lchan_fail("Failure to transmit IPACC MDCX to BTS (rc=%d, %s)",
			   rc, strerror(-rc));

}

static void lchan_fsm_wait_ipacc_mdcx_ack(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {

	case LCHAN_EV_IPACC_MDCX_ACK:
		/* Finally, the lchan and its RTP are established. */
		lchan_fsm_state_chg(LCHAN_ST_WAIT_MGW_ENDPOINT_CONFIGURED);
		return;

	case LCHAN_EV_IPACC_MDCX_NACK:
		lchan_fail("Received NACK on IPACC MDCX");
		return;

	default:
		OSMO_ASSERT(false);
	}
}

/* Tell the MGW endpoint about the RTP port allocated on BTS side. */
static void lchan_fsm_wait_mgw_endpoint_configured_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	int rc;
	struct mgcp_conn_peer mdcx_info;
	struct in_addr addr;
	const char *addr_str;
	struct gsm_lchan *lchan = lchan_fi_lchan(fi);

	if (lchan->release_requested) {
		lchan_fail("Release requested while activating");
		return;
	}

	mdcx_info = (struct mgcp_conn_peer){
		.port = lchan->abis_ip.bound_port,
		.ptime = 20,
	};
	mgcp_pick_codec(&mdcx_info, lchan);

	addr.s_addr = osmo_ntohl(lchan->abis_ip.bound_ip);
	addr_str = inet_ntoa(addr);
	rc = osmo_strlcpy(mdcx_info.addr, addr_str, sizeof(mdcx_info.addr));
	if (rc <= 0 || rc >= sizeof(mdcx_info.addr)) {
		lchan_fail("Cannot compose BTS side RTP IP address to send to MGW: '%s'",
			   addr_str);
		return;
	}

	/* At this point, we are taking over an old lchan's MGW endpoint (if any). */
	if (!lchan->mgw_endpoint_ci_bts
	    && lchan->activate.re_use_mgw_endpoint_from_lchan) {
		lchan->mgw_endpoint_ci_bts =
			lchan->activate.re_use_mgw_endpoint_from_lchan->mgw_endpoint_ci_bts;
		/* The old lchan shall forget the enpoint now. */
		lchan->activate.re_use_mgw_endpoint_from_lchan->mgw_endpoint_ci_bts = NULL;
	}

	if (!lchan->mgw_endpoint_ci_bts) {
		lchan_fail("No MGW endpoint ci configured");
		return;
	}

	LOG_LCHAN(lchan, LOGL_DEBUG, "Sending BTS side RTP port info %s:%u to MGW %s\n",
		  mdcx_info.addr, mdcx_info.port, mgwep_ci_name(lchan->mgw_endpoint_ci_bts));
	mgw_endpoint_ci_request(lchan->mgw_endpoint_ci_bts, MGCP_VERB_MDCX,
				&mdcx_info, fi, LCHAN_EV_MGW_ENDPOINT_CONFIGURED,
				LCHAN_EV_MGW_ENDPOINT_ERROR, 0);
}

static void lchan_fsm_wait_mgw_endpoint_configured(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {

	case LCHAN_EV_MGW_ENDPOINT_CONFIGURED:
		lchan_fsm_state_chg(LCHAN_ST_ESTABLISHED);
		return;

	case LCHAN_EV_MGW_ENDPOINT_ERROR:
		lchan_fail("Error while redirecting the MGW to the BTS' RTP port");
		return;

	default:
		OSMO_ASSERT(false);
	}
}


static void lchan_fsm_established_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct gsm_lchan *lchan = lchan_fi_lchan(fi);

	if (lchan->release_requested) {
		lchan_fail("Release requested while activating");
		return;
	}

	/* This flag ensures that when an lchan activation has succeeded, and we have already sent ACKs
	 * like Immediate Assignment or BSSMAP Assignment Complete, and if then, way later, some other
	 * error occurs, e.g. during release, that we don't send a NACK out of context. */
	lchan->activate.concluded = true;
	lchan_on_activation_success(lchan);
}

#define for_each_sapi(sapi, start, lchan) \
	for (sapi = start; sapi < ARRAY_SIZE(lchan->sapis); sapi++)

static int next_active_sapi(struct gsm_lchan *lchan, int from_sapi)
{
	int sapi;
	for_each_sapi(sapi, from_sapi, lchan) {
		if (lchan->sapis[sapi] == LCHAN_SAPI_UNUSED)
			continue;
		return sapi;
	}
	return sapi;
}

#define for_each_active_sapi(sapi, start, lchan) \
	for (sapi = next_active_sapi(lchan, start); \
	     sapi < ARRAY_SIZE(lchan->sapis); sapi=next_active_sapi(lchan, sapi+1))

static int lchan_active_sapis(struct gsm_lchan *lchan, int start)
{
	int sapis = 0;
	int sapi;
	for_each_active_sapi(sapi, start, lchan) {
		LOG_LCHAN(lchan, LOGL_DEBUG,
			  "Still active: SAPI[%d] (%d)\n", sapi, lchan->sapis[sapi]);
		sapis ++;
	}
	LOG_LCHAN(lchan, LOGL_DEBUG, "Still active SAPIs: %d\n", sapis);
	return sapis;
}

static void handle_rll_rel_ind_or_conf(struct osmo_fsm_inst *fi, uint32_t event, void *data,
				       bool wait_for_sapi0_rel)
{
	uint8_t link_id;
	uint8_t sapi;
	struct gsm_lchan *lchan = lchan_fi_lchan(fi);

	OSMO_ASSERT(data);
	link_id	= *(uint8_t*)data;
	sapi = link_id & 7;

	LOG_LCHAN(lchan, LOGL_DEBUG, "Rx RLL Release %s: SAPI=%u link_id=0x%x\n",
		  event == LCHAN_EV_RLL_REL_CONF ? "CONF" : "IND", sapi, link_id);

	/* TODO this reflects the code state before the lchan FSM. However, it would make more sense to
	 * me that a Release IND is indeed a cue for us to send a Release Request, and not count it as an
	 * equal to Release CONF. */

	lchan->sapis[sapi] = LCHAN_SAPI_UNUSED;
	rll_indication(lchan, link_id, BSC_RLLR_IND_REL_IND);

	/* Releasing SAPI 0 means the conn becomes invalid; but not if the link_id contains a TCH flag.
	 * (TODO: is this the correct interpretation?) */
	if (lchan->conn && sapi == 0 && !(link_id & 0xc0)) {
		LOG_LCHAN(lchan, LOGL_DEBUG, "lchan is releasing\n");
		gscon_lchan_releasing(lchan->conn, lchan);
	}

	if (!lchan_active_sapis(lchan, wait_for_sapi0_rel? 0 : 1))
		lchan_fsm_state_chg(LCHAN_ST_WAIT_BEFORE_RF_RELEASE);
}

static void lchan_fsm_established(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	handle_rll_rel_ind_or_conf(fi, event, data, true);
}

static bool should_sacch_deact(struct gsm_lchan *lchan)
{
	switch (lchan->ts->pchan_is) {
	case GSM_PCHAN_TCH_F:
	case GSM_PCHAN_TCH_H:
	case GSM_PCHAN_CCCH_SDCCH4:
	case GSM_PCHAN_CCCH_SDCCH4_CBCH:
	case GSM_PCHAN_SDCCH8_SACCH8C:
	case GSM_PCHAN_SDCCH8_SACCH8C_CBCH:
		return true;
	default:
		return false;
	}
}

static void lchan_fsm_wait_sapis_released_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	int sapis;
	int sapi;
	struct gsm_lchan *lchan = lchan_fi_lchan(fi);

	for (sapi=0; sapi < ARRAY_SIZE(lchan->sapis); sapi++)
		if (lchan->sapis[sapi])
			LOG_LCHAN(lchan, LOGL_DEBUG, "SAPI[%d] = %d\n", sapi, lchan->sapis[sapi]);

	if (lchan->conn)
		gsm48_send_rr_release(lchan);

	if (lchan->deact_sacch && should_sacch_deact(lchan))
		rsl_deact_sacch(lchan);

	sapis = 0;
	for_each_active_sapi(sapi, 1, lchan) {
		uint8_t link_id = sapi;

		if (lchan->type == GSM_LCHAN_TCH_F || lchan->type == GSM_LCHAN_TCH_H)
			link_id |= 0x40;
		LOG_LCHAN(lchan, LOGL_DEBUG, "Tx: Release SAPI %u link_id 0x%x\n", sapi, link_id);
		rsl_release_request(lchan, link_id, RSL_REL_LOCAL_END);
		sapis ++;
	}

	/* Do not wait for Nokia BTS to send the confirm. */
	if (is_nokia_bts(lchan->ts->trx->bts)
	    && lchan->ts->trx->bts->nokia.no_loc_rel_cnf) {

		LOG_LCHAN(lchan, LOGL_DEBUG, "Nokia InSite BTS: not waiting for RELease CONFirm\n");

		for_each_active_sapi(sapi, 1, lchan)
			lchan->sapis[sapi] = LCHAN_SAPI_UNUSED;
		sapis = 0;
	}

	if (!sapis)
		lchan_fsm_state_chg(LCHAN_ST_WAIT_BEFORE_RF_RELEASE);
}

static void lchan_fsm_wait_sapis_released(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	/* When we're telling the MS to release, we're fine to carry on with RF Channel Release when SAPI
	 * 0 release is not confirmed yet.
	 * TODO: that's how the code was before lchan FSM, is this correct/useful? */
	handle_rll_rel_ind_or_conf(fi, event, data, false);
}

static void lchan_fsm_wait_rf_release_ack_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	int rc;
	struct gsm_lchan *lchan = lchan_fi_lchan(fi);
	rc = rsl_tx_rf_chan_release(lchan);
	if (rc)
		LOG_LCHAN(lchan, LOGL_ERROR, "Failed to Tx RSL RF Channel Release: rc=%d %s\n",
			  rc, strerror(-rc));
}

static void lchan_fsm_wait_rf_release_ack(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_lchan *lchan = lchan_fi_lchan(fi);
	switch (event) {

	case LCHAN_EV_RSL_RF_CHAN_REL_ACK:
		if (lchan->rsl_error_cause)
			lchan_fsm_state_chg(LCHAN_ST_WAIT_AFTER_ERROR);
		else
			lchan_fsm_state_chg(LCHAN_ST_UNUSED);
		break;

	default:
		OSMO_ASSERT(false);
	}
}

static void lchan_fsm_borken_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct gsm_lchan *lchan = lchan_fi_lchan(fi);
	lchan_reset(lchan);
}

static void lchan_fsm_borken(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_lchan *lchan = lchan_fi_lchan(fi);
	switch (event) {

	case LCHAN_EV_RSL_CHAN_ACTIV_ACK:
		/* A late Chan Activ ACK? Release. */
		lchan->release_in_error = true;
		lchan_fsm_state_chg(LCHAN_ST_WAIT_RF_RELEASE_ACK);
		return;

	case LCHAN_EV_RSL_CHAN_ACTIV_NACK:
		/* A late Chan Activ NACK? Ok then, unused. */
		lchan_fsm_state_chg(LCHAN_ST_UNUSED);
		return;

	case LCHAN_EV_RSL_RF_CHAN_REL_ACK:
		/* A late Release ACK? */
		lchan->release_in_error = true;
		lchan_fsm_state_chg(LCHAN_ST_WAIT_AFTER_ERROR);
		/* TODO: we used to do this only for sysmobts:
			int do_free = is_sysmobts_v2(ts->trx->bts);
			LOGP(DRSL, LOGL_NOTICE,
				"%s CHAN REL ACK for broken channel. %s.\n",
				gsm_lchan_name(lchan),
				do_free ? "Releasing it" : "Keeping it broken");
			if (do_free)
				do_lchan_free(lchan);
		 * Clarify the reason. If a BTS sends a RF Chan Rel ACK, we can consider it released,
		 * independently from the BTS model, right?? */
		return;

	default:
		OSMO_ASSERT(false);
	}
}

#define S(x)	(1 << (x))

static const struct osmo_fsm_state lchan_fsm_states[] = {
	[LCHAN_ST_UNUSED] = {
		.name = "UNUSED",
		.onenter = lchan_fsm_unused_onenter,
		.action = lchan_fsm_unused,
		.in_event_mask = 0
			| S(LCHAN_EV_ACTIVATE)
			,
		.out_state_mask = 0
			| S(LCHAN_ST_WAIT_TS_READY)
			,
	},
	[LCHAN_ST_WAIT_TS_READY] = {
		.name = "WAIT_TS_READY",
		.onenter = lchan_fsm_wait_ts_ready_onenter,
		.action = lchan_fsm_wait_ts_ready,
		.in_event_mask = 0
			| S(LCHAN_EV_TS_READY)
			| S(LCHAN_EV_MGW_ENDPOINT_AVAILABLE)
			,
		.out_state_mask = 0
			| S(LCHAN_ST_UNUSED)
			| S(LCHAN_ST_WAIT_ACTIV_ACK)
			,
	},
	[LCHAN_ST_WAIT_ACTIV_ACK] = {
		.name = "WAIT_ACTIV_ACK",
		.onenter = lchan_fsm_wait_activ_ack_onenter,
		.action = lchan_fsm_wait_activ_ack,
		.in_event_mask = 0
			| S(LCHAN_EV_MGW_ENDPOINT_AVAILABLE)
			| S(LCHAN_EV_RSL_CHAN_ACTIV_ACK)
			| S(LCHAN_EV_RSL_CHAN_ACTIV_NACK)
			,
		.out_state_mask = 0
			| S(LCHAN_ST_UNUSED)
			| S(LCHAN_ST_WAIT_RLL_ESTABLISH)
			| S(LCHAN_ST_BORKEN)
			| S(LCHAN_ST_WAIT_RF_RELEASE_ACK)
			,
	},
	[LCHAN_ST_WAIT_RLL_ESTABLISH] = {
		.name = "WAIT_RLL_ESTABLISH",
		.onenter = lchan_fsm_wait_rll_establish_onenter,
		.action = lchan_fsm_wait_rll_establish,
		.in_event_mask = 0
			| S(LCHAN_EV_MGW_ENDPOINT_AVAILABLE)
			| S(LCHAN_EV_RLL_ESTABLISH_IND)
			,
		.out_state_mask = 0
			| S(LCHAN_ST_UNUSED)
			| S(LCHAN_ST_WAIT_MGW_ENDPOINT_AVAILABLE)
			| S(LCHAN_ST_ESTABLISHED)
			| S(LCHAN_ST_WAIT_RF_RELEASE_ACK)
			| S(LCHAN_ST_WAIT_SAPIS_RELEASED)
			,
	},
	[LCHAN_ST_WAIT_MGW_ENDPOINT_AVAILABLE] = {
		.name = "WAIT_MGW_ENDPOINT_AVAILABLE",
		.onenter = lchan_fsm_wait_mgw_endpoint_available_onenter,
		.action = lchan_fsm_wait_mgw_endpoint_available,
		.in_event_mask = 0
			| S(LCHAN_EV_MGW_ENDPOINT_AVAILABLE)
			,
		.out_state_mask = 0
			| S(LCHAN_ST_UNUSED)
			| S(LCHAN_ST_WAIT_IPACC_CRCX_ACK)
			| S(LCHAN_ST_WAIT_MGW_ENDPOINT_CONFIGURED)
			| S(LCHAN_ST_WAIT_SAPIS_RELEASED)
			| S(LCHAN_ST_WAIT_RF_RELEASE_ACK)
			,
	},
	[LCHAN_ST_WAIT_IPACC_CRCX_ACK] = {
		.name = "WAIT_IPACC_CRCX_ACK",
		.onenter = lchan_fsm_wait_ipacc_crcx_ack_onenter,
		.action = lchan_fsm_wait_ipacc_crcx_ack,
		.in_event_mask = 0
			| S(LCHAN_EV_IPACC_CRCX_ACK)
			| S(LCHAN_EV_IPACC_CRCX_NACK)
			,
		.out_state_mask = 0
			| S(LCHAN_ST_UNUSED)
			| S(LCHAN_ST_WAIT_IPACC_MDCX_ACK)
			| S(LCHAN_ST_WAIT_SAPIS_RELEASED)
			| S(LCHAN_ST_WAIT_RF_RELEASE_ACK)
			,
	},
	[LCHAN_ST_WAIT_IPACC_MDCX_ACK] = {
		.name = "WAIT_IPACC_MDCX_ACK",
		.onenter = lchan_fsm_wait_ipacc_mdcx_ack_onenter,
		.action = lchan_fsm_wait_ipacc_mdcx_ack,
		.in_event_mask = 0
			| S(LCHAN_EV_IPACC_MDCX_ACK)
			| S(LCHAN_EV_IPACC_MDCX_NACK)
			,
		.out_state_mask = 0
			| S(LCHAN_ST_UNUSED)
			| S(LCHAN_ST_WAIT_MGW_ENDPOINT_CONFIGURED)
			| S(LCHAN_ST_WAIT_SAPIS_RELEASED)
			| S(LCHAN_ST_WAIT_RF_RELEASE_ACK)
			,
	},
	[LCHAN_ST_WAIT_MGW_ENDPOINT_CONFIGURED] = {
		.name = "WAIT_MGW_ENDPOINT_CONFIGURED",
		.onenter = lchan_fsm_wait_mgw_endpoint_configured_onenter,
		.action = lchan_fsm_wait_mgw_endpoint_configured,
		.in_event_mask = 0
			| S(LCHAN_EV_MGW_ENDPOINT_CONFIGURED)
			,
		.out_state_mask = 0
			| S(LCHAN_ST_UNUSED)
			| S(LCHAN_ST_ESTABLISHED)
			| S(LCHAN_ST_WAIT_SAPIS_RELEASED)
			| S(LCHAN_ST_WAIT_RF_RELEASE_ACK)
			,
	},
	[LCHAN_ST_ESTABLISHED] = {
		.name = "ESTABLISHED",
		.onenter = lchan_fsm_established_onenter,
		.action = lchan_fsm_established,
		.in_event_mask = 0
			| S(LCHAN_EV_RLL_REL_IND)
			| S(LCHAN_EV_RLL_REL_CONF)
			,
		.out_state_mask = 0
			| S(LCHAN_ST_UNUSED)
			| S(LCHAN_ST_WAIT_SAPIS_RELEASED)
			| S(LCHAN_ST_WAIT_BEFORE_RF_RELEASE)
			| S(LCHAN_ST_WAIT_RF_RELEASE_ACK)
			,
	},
	[LCHAN_ST_WAIT_SAPIS_RELEASED] = {
		.name = "WAIT_SAPIS_RELEASED",
		.onenter = lchan_fsm_wait_sapis_released_onenter,
		.action = lchan_fsm_wait_sapis_released,
		.in_event_mask = 0
			| S(LCHAN_EV_RLL_REL_IND)
			| S(LCHAN_EV_RLL_REL_CONF)
			,
		.out_state_mask = 0
			| S(LCHAN_ST_UNUSED)
			| S(LCHAN_ST_WAIT_BEFORE_RF_RELEASE)
			| S(LCHAN_ST_WAIT_RF_RELEASE_ACK)
			,
	},
	[LCHAN_ST_WAIT_BEFORE_RF_RELEASE] = {
		.name = "WAIT_BEFORE_RF_RELEASE",
		.out_state_mask = 0
			| S(LCHAN_ST_UNUSED)
			| S(LCHAN_ST_WAIT_RF_RELEASE_ACK)
			,
	},
	[LCHAN_ST_WAIT_RF_RELEASE_ACK] = {
		.name = "WAIT_RF_RELEASE_ACK",
		.onenter = lchan_fsm_wait_rf_release_ack_onenter,
		.action = lchan_fsm_wait_rf_release_ack,
		.in_event_mask = 0
			| S(LCHAN_EV_RSL_RF_CHAN_REL_ACK)
			,
		.out_state_mask = 0
			| S(LCHAN_ST_UNUSED)
			| S(LCHAN_ST_WAIT_AFTER_ERROR)
			| S(LCHAN_ST_BORKEN)
			,
	},
	[LCHAN_ST_WAIT_AFTER_ERROR] = {
		.name = "WAIT_AFTER_ERROR",
		.out_state_mask = 0
			| S(LCHAN_ST_UNUSED)
			,
	},
	[LCHAN_ST_BORKEN] = {
		.name = "BORKEN",
		.onenter = lchan_fsm_borken_onenter,
		.action = lchan_fsm_borken,
		.in_event_mask = 0
			| S(LCHAN_EV_RSL_CHAN_ACTIV_ACK)
			| S(LCHAN_EV_RSL_CHAN_ACTIV_NACK)
			| S(LCHAN_EV_RSL_RF_CHAN_REL_ACK)
			,
		.out_state_mask = 0
			| S(LCHAN_ST_UNUSED)
			| S(LCHAN_ST_WAIT_AFTER_ERROR)
			,
	},
};

static const struct value_string lchan_fsm_event_names[] = {
	OSMO_VALUE_STRING(LCHAN_EV_ACTIVATE),
	OSMO_VALUE_STRING(LCHAN_EV_TS_READY),
	OSMO_VALUE_STRING(LCHAN_EV_TS_ERROR),
	OSMO_VALUE_STRING(LCHAN_EV_RSL_CHAN_ACTIV_ACK),
	OSMO_VALUE_STRING(LCHAN_EV_RSL_CHAN_ACTIV_NACK),
	OSMO_VALUE_STRING(LCHAN_EV_RLL_ESTABLISH_IND),
	OSMO_VALUE_STRING(LCHAN_EV_MGW_ENDPOINT_AVAILABLE),
	OSMO_VALUE_STRING(LCHAN_EV_MGW_ENDPOINT_CONFIGURED),
	OSMO_VALUE_STRING(LCHAN_EV_MGW_ENDPOINT_ERROR),
	OSMO_VALUE_STRING(LCHAN_EV_IPACC_CRCX_ACK),
	OSMO_VALUE_STRING(LCHAN_EV_IPACC_CRCX_NACK),
	OSMO_VALUE_STRING(LCHAN_EV_IPACC_MDCX_ACK),
	OSMO_VALUE_STRING(LCHAN_EV_IPACC_MDCX_NACK),
	OSMO_VALUE_STRING(LCHAN_EV_RLL_REL_IND),
	OSMO_VALUE_STRING(LCHAN_EV_RLL_REL_CONF),
	OSMO_VALUE_STRING(LCHAN_EV_RSL_RF_CHAN_REL_ACK),
	OSMO_VALUE_STRING(LCHAN_EV_RLL_ERR_IND),
	OSMO_VALUE_STRING(LCHAN_EV_CHAN_MODE_MODIF_ACK),
	OSMO_VALUE_STRING(LCHAN_EV_CHAN_MODE_MODIF_ERROR),
	{}
};

void lchan_fsm_allstate_action(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_lchan *lchan = lchan_fi_lchan(fi);

	switch (event) {

	case LCHAN_EV_TS_ERROR:
		lchan_fail_to(LCHAN_ST_UNUSED, "LCHAN_EV_TS_ERROR");
		return;

	case LCHAN_EV_MGW_ENDPOINT_ERROR:
		/* This event during activation means that it was not possible to establish an endpoint.
		 * After activation was successful, it could also come in at any point to signal that the
		 * MGW side has become unavailable, which should lead to graceful release. */
		if (fi->state == LCHAN_ST_WAIT_MGW_ENDPOINT_AVAILABLE) {
			/* This state is actually waiting for availability. Fail it immediately. */
			lchan_fail("LCHAN_EV_MGW_ENDPOINT_ERROR");
			return;
		}
		LOG_LCHAN(lchan, LOGL_ERROR, "Releasing due to MGW endpoint error\n");
		lchan_release(lchan, false, true, RSL_ERR_EQUIPMENT_FAIL);
		return;

	default:
		return;
	}
}

int lchan_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	struct gsm_lchan *lchan = lchan_fi_lchan(fi);
	switch (fi->state) {

	case LCHAN_ST_WAIT_BEFORE_RF_RELEASE:
		lchan_fsm_state_chg(LCHAN_ST_WAIT_RF_RELEASE_ACK);
		return 0;

	case LCHAN_ST_WAIT_AFTER_ERROR:
		lchan_fsm_state_chg(LCHAN_ST_UNUSED);
		return 0;

	default:
		lchan->release_in_error = true;
		lchan_fail("Timeout");
		return 0;
	}
}

void lchan_release(struct gsm_lchan *lchan, bool sacch_deact,
		   bool err, enum gsm48_rr_cause cause_rr)
{
	if (!lchan || !lchan->fi)
		return;
	struct osmo_fsm_inst *fi = lchan->fi;
	lchan->release_in_error = err;
	lchan->rsl_error_cause = cause_rr;
	lchan->deact_sacch = sacch_deact;

	/* This would also happen later, but better to do this a sooner. */
	if (lchan->mgw_endpoint_ci_bts) {
		mgw_endpoint_ci_dlcx(lchan->mgw_endpoint_ci_bts);
		lchan->mgw_endpoint_ci_bts = NULL;
	}

	/* States waiting for events will notice the desire to release when done waiting, so it is enough
	 * to mark for release. */
	lchan->release_requested = true;

	/* But when in error, shortcut that. */
	if (lchan->release_in_error) {
		switch (lchan->fi->state) {
		default:
			/* Normally we deact SACCH in lchan_fsm_wait_sapis_released_onenter(). When
			 * skipping that, but asked to SACCH deact, do it now. */
			if (lchan->deact_sacch)
				rsl_deact_sacch(lchan);
			lchan_fsm_state_chg(LCHAN_ST_WAIT_RF_RELEASE_ACK);
			return;
		case LCHAN_ST_WAIT_TS_READY:
			lchan_fsm_state_chg(LCHAN_ST_UNUSED);
			return;
		case LCHAN_ST_WAIT_RF_RELEASE_ACK:
		case LCHAN_ST_BORKEN:
			return;
		}
	}

	/* The only non-broken state that would stay stuck without noticing the release_requested flag
	 * is: */
	if (fi->state == LCHAN_ST_ESTABLISHED)
		lchan_fsm_state_chg(LCHAN_ST_WAIT_SAPIS_RELEASED);
}

void lchan_fsm_cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct gsm_lchan *lchan = lchan_fi_lchan(fi);
	if (lchan->conn)
		gscon_forget_lchan(lchan->conn, lchan);
	lchan_reset(lchan);
	if (lchan->last_error) {
		talloc_free(lchan->last_error);
		lchan->last_error = NULL;
	}
	lchan->fi = NULL;
}

/* The mgw_endpoint was invalidated, just and simply forget the pointer without cleanup. */
void lchan_forget_mgw_endpoint(struct gsm_lchan *lchan)
{
	if (!lchan)
		return;
	lchan->mgw_endpoint_ci_bts = NULL;
}

/* The conn is deallocating, just forget all about it */
void lchan_forget_conn(struct gsm_lchan *lchan)
{
	if (!lchan)
		return;
	lchan_forget_mgw_endpoint(lchan);
	lchan->conn = NULL;
}

static struct osmo_fsm lchan_fsm = {
	.name = "lchan",
	.states = lchan_fsm_states,
	.num_states = ARRAY_SIZE(lchan_fsm_states),
	.log_subsys = DRSL,
	.event_names = lchan_fsm_event_names,
	.allstate_action = lchan_fsm_allstate_action,
	.allstate_event_mask = 0
		| S(LCHAN_EV_TS_ERROR)
		| S(LCHAN_EV_MGW_ENDPOINT_ERROR)
		,
	.timer_cb = lchan_fsm_timer_cb,
	.cleanup = lchan_fsm_cleanup,
};
