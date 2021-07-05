/* osmo-bsc API to allocate an lchan, complete with dyn TS switchover.
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
#include <osmocom/gsm/protocol/gsm_08_08.h>

#include <osmocom/mgcp_client/mgcp_client_endpoint_fsm.h>

#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/lchan_fsm.h>
#include <osmocom/bsc/lchan_rtp_fsm.h>
#include <osmocom/bsc/timeslot_fsm.h>
#include <osmocom/bsc/bsc_subscr_conn_fsm.h>
#include <osmocom/bsc/handover.h>
#include <osmocom/bsc/abis_rsl.h>
#include <osmocom/bsc/bsc_rll.h>
#include <osmocom/bsc/gsm_04_08_rr.h>
#include <osmocom/bsc/assignment_fsm.h>
#include <osmocom/bsc/handover_fsm.h>
#include <osmocom/bsc/bsc_msc_data.h>
#include <osmocom/bsc/codec_pref.h>
#include <osmocom/bsc/bts.h>

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
	case LCHAN_ST_WAIT_RLL_RTP_ESTABLISH:
	case LCHAN_ST_ESTABLISHED:
	case LCHAN_ST_WAIT_RR_CHAN_MODE_MODIFY_ACK:
		return true;
	default:
		return false;
	}
}

static void lchan_on_mode_modify_success(struct gsm_lchan *lchan)
{
	lchan->modify.concluded = true;

	switch (lchan->modify.info.modify_for) {

	case MODIFY_FOR_ASSIGNMENT:
		osmo_fsm_inst_dispatch(lchan->conn->assignment.fi, ASSIGNMENT_EV_LCHAN_MODIFIED, lchan);
		break;

	default:
		break;
	}
}

#define lchan_on_mode_modify_failure(lchan, modify_for, for_conn) \
	_lchan_on_mode_modify_failure(lchan, modify_for, for_conn, \
				     __FILE__, __LINE__)
static void _lchan_on_mode_modify_failure(struct gsm_lchan *lchan, enum lchan_modify_for modify_for,
					  struct gsm_subscriber_connection *for_conn,
					  const char *file, int line)
{
	if (lchan->modify.concluded)
		return;
	lchan->modify.concluded = true;

	switch (modify_for) {

	case MODIFY_FOR_ASSIGNMENT:
		LOG_LCHAN(lchan, LOGL_NOTICE, "Signalling Assignment FSM of error (%s)\n",
			  lchan->last_error ? : "unknown error");
		_osmo_fsm_inst_dispatch(for_conn->assignment.fi, ASSIGNMENT_EV_LCHAN_ERROR, lchan,
					file, line);
		return;

	case MODIFY_FOR_VTY:
		LOG_LCHAN(lchan, LOGL_ERROR, "VTY user invoked lchan Channel Mode Modify failed (%s)\n",
			  lchan->last_error ? : "unknown error");
		break;

	default:
		LOG_LCHAN(lchan, LOGL_ERROR, "lchan Channel Mode Modify failed (%s)\n",
			  lchan->last_error ? : "unknown error");
		break;
	}
}

/* The idea here is that we must not require to change any lchan state in order to deny a request. */
#define lchan_on_activation_failure(lchan, for_conn, activ_for) \
	_lchan_on_activation_failure(lchan, for_conn, activ_for, \
				     __FILE__, __LINE__)
static void _lchan_on_activation_failure(struct gsm_lchan *lchan, enum lchan_activate_for activ_for,
					 struct gsm_subscriber_connection *for_conn,
					 const char *file, int line)
{
	if (lchan->activate.concluded)
		return;
	lchan->activate.concluded = true;

	switch (activ_for) {

	case ACTIVATE_FOR_MS_CHANNEL_REQUEST:
		if (!lchan->activate.immediate_assignment_sent) {
			/* Failure before Immediate Assignment message, send a reject. */
			LOG_LCHAN(lchan, LOGL_NOTICE, "Tx Immediate Assignment Reject (%s)\n",
				  lchan->last_error ? : "unknown error");
			rsl_tx_imm_ass_rej(lchan->ts->trx->bts, lchan->rqd_ref);
		}
		/* Otherwise, likely the MS never showed up after the Assignment, and the failure cause
		 * (Timeout?) was already logged elsewhere. Just continue to tear down the lchan after
		 * lchan_on_activation_failure(), no additional action or logging needed. */
		break;

	case ACTIVATE_FOR_ASSIGNMENT:
		LOG_LCHAN(lchan, LOGL_NOTICE, "Signalling Assignment FSM of error (%s)\n",
			  lchan->last_error ? : "unknown error");
		_osmo_fsm_inst_dispatch(for_conn->assignment.fi, ASSIGNMENT_EV_LCHAN_ERROR, lchan,
					file, line);
		return;

	case ACTIVATE_FOR_HANDOVER:
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

	case ACTIVATE_FOR_VTY:
		LOG_LCHAN(lchan, LOGL_ERROR, "VTY user invoked lchan activation failed (%s)\n",
			  lchan->last_error ? : "unknown error");
		break;

	case ACTIVATE_FOR_MODE_MODIFY_RTP:
		lchan_on_mode_modify_failure(lchan, lchan->modify.info.modify_for, for_conn);
		break;

	default:
		LOG_LCHAN(lchan, LOGL_ERROR, "lchan activation failed (%s)\n",
			  lchan->last_error ? : "unknown error");
		break;
	}
}

static void lchan_on_fully_established(struct gsm_lchan *lchan)
{
	if (lchan->activate.concluded)
		return;
	lchan->activate.concluded = true;

	switch (lchan->activate.info.activ_for) {
	case ACTIVATE_FOR_MS_CHANNEL_REQUEST:
		/* No signalling to do here, MS is free to use the channel, and should go on to connect
		 * to the MSC and establish a subscriber connection. */
		break;

	case ACTIVATE_FOR_ASSIGNMENT:
		if (!lchan->conn) {
			LOG_LCHAN(lchan, LOGL_ERROR,
				  "lchan activation for assignment succeeded, but lchan has no conn:"
				  " cannot trigger appropriate actions. Release.\n");
			lchan_release(lchan, false, true, RSL_ERR_EQUIPMENT_FAIL, NULL);
			break;
		}
		if (!lchan->conn->assignment.fi) {
			LOG_LCHAN(lchan, LOGL_ERROR,
				  "lchan activation for assignment succeeded, but lchan has no"
				  " assignment ongoing: cannot trigger appropriate actions. Release.\n");
			lchan_release(lchan, false, true, RSL_ERR_EQUIPMENT_FAIL, NULL);
			break;
		}
		osmo_fsm_inst_dispatch(lchan->conn->assignment.fi, ASSIGNMENT_EV_LCHAN_ESTABLISHED,
				       lchan);
		/* The lchan->fi_rtp will be notified of LCHAN_RTP_EV_ESTABLISHED in
		 * gscon_change_primary_lchan() upon assignment_success(). On failure before then, we
		 * will try to roll back a modified RTP connection. */
		break;

	case ACTIVATE_FOR_HANDOVER:
		if (!lchan->conn) {
			LOG_LCHAN(lchan, LOGL_ERROR,
				  "lchan activation for handover succeeded, but lchan has no conn\n");
			lchan_release(lchan, false, true, RSL_ERR_EQUIPMENT_FAIL, NULL);
			break;
		}
		if (!lchan->conn->ho.fi) {
			LOG_LCHAN(lchan, LOGL_ERROR,
				  "lchan activation for handover succeeded, but lchan has no"
				  " handover ongoing\n");
			lchan_release(lchan, false, true, RSL_ERR_EQUIPMENT_FAIL, NULL);
			break;
		}
		osmo_fsm_inst_dispatch(lchan->conn->ho.fi, HO_EV_LCHAN_ESTABLISHED, lchan);
		/* The lchan->fi_rtp will be notified of LCHAN_RTP_EV_ESTABLISHED in
		 * gscon_change_primary_lchan() upon handover_end(HO_RESULT_OK). On failure before then,
		 * we will try to roll back a modified RTP connection. */
		break;

	case ACTIVATE_FOR_MODE_MODIFY_RTP:
		lchan_on_mode_modify_success(lchan);
		break;

	default:
		LOG_LCHAN(lchan, LOGL_NOTICE, "lchan %s fully established\n",
			  lchan_activate_mode_name(lchan->activate.info.activ_for));
		break;
	}
}

struct osmo_tdef_state_timeout lchan_fsm_timeouts[32] = {
	[LCHAN_ST_WAIT_TS_READY]	= { .T=-5 },
	[LCHAN_ST_WAIT_ACTIV_ACK]	= { .T=-6 },
	[LCHAN_ST_WAIT_RLL_RTP_ESTABLISH]	= { .T=3101 },
	[LCHAN_ST_WAIT_RLL_RTP_RELEASED]	= { .T=3109 },
	[LCHAN_ST_WAIT_BEFORE_RF_RELEASE]	= { .T=3111 },
	[LCHAN_ST_WAIT_RF_RELEASE_ACK]	= { .T=3111 },
	[LCHAN_ST_WAIT_AFTER_ERROR]	= { .T=-3111 },
	[LCHAN_ST_WAIT_RR_CHAN_MODE_MODIFY_ACK]	= { .T=-13 },
	[LCHAN_ST_WAIT_RSL_CHAN_MODE_MODIFY_ACK]	= { .T=-14 },
};

/* Transition to a state, using the T timer defined in lchan_fsm_timeouts.
 * The actual timeout value is in turn obtained from network->T_defs.
 * Assumes local variable fi exists. */
#define lchan_fsm_state_chg(state) \
	osmo_tdef_fsm_inst_state_chg(fi, state, \
				     lchan_fsm_timeouts, \
				     ((struct gsm_lchan*)(fi->priv))->ts->trx->bts->network->T_defs, \
				     5)

/* Set a failure message, trigger the common actions to take on failure, transition to a state to
 * continue with (using state timeouts from lchan_fsm_timeouts[]). Assumes local variable fi exists. */
#define lchan_fail_to(STATE_CHG, fmt, args...) do { \
		struct gsm_lchan *_lchan = fi->priv; \
		struct osmo_fsm *fsm = fi->fsm; \
		uint32_t state_was = fi->state; \
		/* Snapshot the target state, in case the macro argument evaluates differently later */ \
		const uint32_t state_chg = STATE_CHG; \
		LOG_LCHAN(_lchan, LOGL_DEBUG, "Handling failure, will then transition to state %s\n", \
			  osmo_fsm_state_name(fsm, state_chg)); \
		LCHAN_SET_LAST_ERROR(_lchan, "lchan %s in state %s: " fmt, \
				     _lchan->activate.concluded ? "failure" : "allocation failed", \
				     osmo_fsm_state_name(fsm, state_was), ## args); \
		lchan_on_activation_failure(_lchan, _lchan->activate.info.activ_for, _lchan->conn); \
		if (fi->state != state_chg) \
			lchan_fsm_state_chg(state_chg); \
		else \
			LOG_LCHAN(_lchan, LOGL_DEBUG, "After failure handling, already in state %s\n", \
				  osmo_fsm_state_name(fsm, state_chg)); \
	} while(0)

/* Which state to transition to when lchan_fail() is called in a given state. */
uint32_t lchan_fsm_on_error[34] = {
	[LCHAN_ST_UNUSED] 			= LCHAN_ST_UNUSED,
	[LCHAN_ST_WAIT_TS_READY] 		= LCHAN_ST_UNUSED,
	[LCHAN_ST_WAIT_ACTIV_ACK] 		= LCHAN_ST_BORKEN,
	[LCHAN_ST_WAIT_RLL_RTP_ESTABLISH] 	= LCHAN_ST_WAIT_RF_RELEASE_ACK,
	[LCHAN_ST_ESTABLISHED] 			= LCHAN_ST_WAIT_RLL_RTP_RELEASED,
	[LCHAN_ST_WAIT_RLL_RTP_RELEASED] 		= LCHAN_ST_WAIT_RF_RELEASE_ACK,
	[LCHAN_ST_WAIT_BEFORE_RF_RELEASE] 	= LCHAN_ST_WAIT_RF_RELEASE_ACK,
	[LCHAN_ST_WAIT_RF_RELEASE_ACK] 		= LCHAN_ST_BORKEN,
	[LCHAN_ST_WAIT_AFTER_ERROR] 		= LCHAN_ST_UNUSED,
	[LCHAN_ST_BORKEN] 			= LCHAN_ST_BORKEN,
	[LCHAN_ST_WAIT_RR_CHAN_MODE_MODIFY_ACK]	= LCHAN_ST_WAIT_RF_RELEASE_ACK,
	[LCHAN_ST_WAIT_RSL_CHAN_MODE_MODIFY_ACK]	= LCHAN_ST_WAIT_RF_RELEASE_ACK,
};

#define lchan_fail(fmt, args...) lchan_fail_to(lchan_fsm_on_error[fi->state], fmt, ## args)

void lchan_activate(struct gsm_lchan *lchan, struct lchan_activate_info *info)
{
	int rc;

	OSMO_ASSERT(lchan && info);

	if ((info->vamos || lchan->vamos.is_secondary)
	    && !osmo_bts_has_feature(&lchan->ts->trx->bts->features, BTS_FEAT_VAMOS)) {
		lchan->last_error = talloc_strdup(lchan->ts->trx, "VAMOS related channel activation requested,"
						  " but BTS does not support VAMOS");
		LOG_LCHAN(lchan, LOGL_ERROR,
			  "VAMOS related channel activation requested, but BTS %u does not support VAMOS\n",
			  lchan->ts->trx->bts->nr);
		goto abort;
	}

	if (!lchan_state_is(lchan, LCHAN_ST_UNUSED))
		goto abort;

	/* ensure some basic sanity up first, before we enter the machine. */
	OSMO_ASSERT(lchan->ts && lchan->ts->fi && lchan->fi);

	switch (info->activ_for) {

	case ACTIVATE_FOR_ASSIGNMENT:
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

	case ACTIVATE_FOR_HANDOVER:
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

void lchan_mode_modify(struct gsm_lchan *lchan, struct lchan_modify_info *info)
{
	OSMO_ASSERT(lchan && info);

	if ((info->vamos || lchan->vamos.is_secondary)
	    && !osmo_bts_has_feature(&lchan->ts->trx->bts->features, BTS_FEAT_VAMOS)) {
		lchan->last_error = talloc_strdup(lchan->ts->trx, "VAMOS related Channel Mode Modify requested,"
						  " but BTS does not support VAMOS");
		LOG_LCHAN(lchan, LOGL_ERROR,
			  "VAMOS related Channel Mode Modify requested, but BTS %u does not support VAMOS\n",
			  lchan->ts->trx->bts->nr);
		lchan_on_mode_modify_failure(lchan, info->modify_for, lchan->conn);
		return;
	}

	/* To make sure that the lchan is actually allowed to initiate Mode Modify, feed through an FSM event. */
	if (osmo_fsm_inst_dispatch(lchan->fi, LCHAN_EV_REQUEST_MODE_MODIFY, info)) {
		LOG_LCHAN(lchan, LOGL_ERROR,
			  "Channel Mode Modify requested, but cannot dispatch LCHAN_EV_REQUEST_MODE_MODIFY event\n");
		lchan_on_mode_modify_failure(lchan, info->modify_for, lchan->conn);
	}
}

void lchan_fsm_update_id(struct gsm_lchan *lchan)
{
	lchan_update_name(lchan);
	if (!lchan->fi)
		return;
	osmo_fsm_inst_update_id_f(lchan->fi, "%u-%u-%u-%s-%s%u",
				  lchan->ts->trx->bts->nr, lchan->ts->trx->nr, lchan->ts->nr,
				  gsm_pchan_id(lchan->ts->pchan_on_init),
				  lchan->vamos.is_secondary ? "shadow" : "",
				  lchan->nr - (lchan->vamos.is_secondary ? lchan->ts->max_primary_lchans : 0));
	if (lchan->fi_rtp)
		osmo_fsm_inst_update_id_f(lchan->fi_rtp, lchan->fi->id);
}

extern void lchan_rtp_fsm_init();

void lchan_fsm_init()
{
	OSMO_ASSERT(osmo_fsm_register(&lchan_fsm) == 0);
	lchan_rtp_fsm_init();
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

	if (lchan->conn)
		gscon_forget_lchan(lchan->conn, lchan);

	if (lchan->rqd_ref) {
		talloc_free(lchan->rqd_ref);
		lchan->rqd_ref = NULL;
	}
	if (lchan->fi_rtp)
		osmo_fsm_inst_term(lchan->fi_rtp, OSMO_FSM_TERM_REQUEST, 0);
	if (lchan->mgw_endpoint_ci_bts) {
		osmo_mgcpc_ep_ci_dlcx(lchan->mgw_endpoint_ci_bts);
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

		.release.rr_cause = GSM48_RR_CAUSE_NORMAL,

		.tsc_set = 1,
	};
}

static void lchan_fsm_unused_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct gsm_lchan *lchan = lchan_fi_lchan(fi);
	struct gsm_bts *bts = lchan->ts->trx->bts;
	lchan_reset(lchan);
	osmo_fsm_inst_dispatch(lchan->ts->fi, TS_EV_LCHAN_UNUSED, lchan);

	/* Poll the channel request queue, so that waiting calls can make use of the lchan that just
	 * has become unused now. */
	abis_rsl_chan_rqd_queue_poll(bts);
}

static void lchan_fsm_wait_after_error_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct gsm_lchan *lchan = lchan_fi_lchan(fi);
	struct gsm_bts *bts = lchan->ts->trx->bts;

	/* We also need to poll the channel request queue when the FSM enters the WAIT_AFTER_ERROR
	 * state. In case of an emergency call the channel request queue will skip the waiting
	 * period. */
	abis_rsl_chan_rqd_queue_poll(bts);
}

/* Configure the multirate setting on this channel. */
static int mr_config_filter(struct gsm48_multi_rate_conf *mr_conf_result,
			    bool full_rate,
			    const struct amr_multirate_conf *amr_mrc,
			    const struct gsm48_multi_rate_conf *mr_filter_msc,
			    uint16_t s15_s0,
			    const struct gsm_lchan *lchan_for_logging)
{
	int rc;
	struct gsm48_multi_rate_conf *mr_filter_bts = (struct gsm48_multi_rate_conf*)amr_mrc->gsm48_ie;

	/* Generate mr conf struct from S15-S0 bits */
	if (gsm48_mr_cfg_from_gsm0808_sc_cfg(mr_conf_result, s15_s0) < 0) {
		LOG_LCHAN(lchan_for_logging, LOGL_ERROR,
			  "can not determine multirate configuration, S15-S0 (%04x) are ambiguous!\n", s15_s0);
		return -EINVAL;
	}

	/* Do not include 12.2 kbps rate when S1 is set. */
	if ((!full_rate) && (s15_s0 & GSM0808_SC_CFG_AMR_4_75_5_90_7_40_12_20)) {
		/* See also 3GPP TS 28.062, chapter 7.11.3.1.3:
		 *
		 *   In case this Configuration "Config-NB-Code = 1" is signalled in the TFO Negotiation for the HR_AMR
		 *   Codec Type, then it shall be assumed that AMR mode 12.2 kbps is (of course) not included.
		 *
		 * Further below, we log an error if 12k2 is included for a TCH/H lchan: removing this here ensures that
		 * we don't log that error for GSM0808_SC_CFG_AMR_4_75_5_90_7_40_12_20 on a TCH/H lchan. */
		mr_conf_result->m12_2 = 0;
	}

	if (mr_filter_msc) {
		rc = calc_amr_rate_intersection(mr_conf_result, mr_filter_msc, mr_conf_result);
		if (rc < 0) {
			LOG_LCHAN(lchan_for_logging, LOGL_ERROR,
				  "can not encode multirate configuration (invalid amr rate setting, MSC)\n");
			return -EINVAL;
		}
	}

	rc = calc_amr_rate_intersection(mr_conf_result, mr_filter_bts, mr_conf_result);
	if (rc < 0) {
		LOG_LCHAN(lchan_for_logging, LOGL_ERROR,
			  "can not encode multirate configuration (invalid amr rate setting, BTS)\n");
		return -EINVAL;
	}

	/* Set the ICMI according to the BTS. Above gsm48_mr_cfg_from_gsm0808_sc_cfg() always sets ICMI = 1, which
	 * carried through all of the above rate intersections. */
	mr_conf_result->icmi = mr_filter_bts->icmi;
	mr_conf_result->smod = mr_filter_bts->smod;

	/* 10k2 and 12k2 only work for full rate */
	if (!full_rate) {
		if (mr_conf_result->m10_2 || mr_conf_result->m12_2)
			LOG_LCHAN(lchan_for_logging, LOGL_ERROR,
				  "half rate lchan: ignoring unsupported AMR codec rates 10k2 and 12k2\n");
		mr_conf_result->m10_2 = 0;
		mr_conf_result->m12_2 = 0;
	}

	return 0;
}

/* Configure the multirate setting on this channel. */
static int lchan_mr_config(struct gsm48_multi_rate_conf *mr_conf, const struct gsm_lchan *lchan, uint16_t s15_s0)
{
	struct gsm_bts *bts = lchan->ts->trx->bts;
	bool full_rate = lchan->type == GSM_LCHAN_TCH_F;
	struct amr_multirate_conf *amr_mrc = full_rate ? &bts->mr_full : &bts->mr_half;
	struct gsm48_multi_rate_conf *mr_filter_msc = NULL;

	/* If activated for VTY, there may not be a conn indicating an MSC AMR configuration. */
	if (lchan->conn && lchan->conn->sccp.msc)
		mr_filter_msc = &lchan->conn->sccp.msc->amr_conf;

	return mr_config_filter(mr_conf,
				full_rate,
				amr_mrc, mr_filter_msc,
				s15_s0,
				lchan);
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
		if (lchan->last_error)
			talloc_free(lchan->last_error);
		lchan->last_error = NULL;
		lchan->release.requested = false;

		lchan->activate.info = *info;
		lchan->activate.concluded = false;
		lchan_fsm_state_chg(LCHAN_ST_WAIT_TS_READY);
		break;

	default:
		OSMO_ASSERT(false);
	}
}

static int lchan_activate_set_ch_mode_rate_and_mr_config(struct gsm_lchan *lchan)
{
	struct osmo_fsm_inst *fi = lchan->fi;
	lchan->activate.ch_mode_rate = lchan->activate.info.ch_mode_rate;
	lchan->activate.ch_mode_rate.chan_mode = (lchan->activate.info.vamos
		? gsm48_chan_mode_to_vamos(lchan->activate.info.ch_mode_rate.chan_mode)
		: gsm48_chan_mode_to_non_vamos(lchan->activate.info.ch_mode_rate.chan_mode));
	if (lchan->activate.ch_mode_rate.chan_mode < 0) {
		lchan_fail("Invalid chan_mode: %s", gsm48_chan_mode_name(lchan->activate.info.ch_mode_rate.chan_mode));
		return -EINVAL;
	}

	if (gsm48_chan_mode_to_non_vamos(lchan->activate.ch_mode_rate.chan_mode) == GSM48_CMODE_SPEECH_AMR) {
		if (lchan_mr_config(&lchan->activate.mr_conf_filtered, lchan, lchan->activate.ch_mode_rate.s15_s0) < 0) {
			lchan_fail("Can not generate multirate configuration IE");
			return -EINVAL;
		}
	}
	return 0;
}

static void lchan_fsm_wait_ts_ready_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct gsm_lchan *lchan = lchan_fi_lchan(fi);
	struct gsm_bts *bts = lchan->ts->trx->bts;
	struct osmo_mgcpc_ep_ci *use_mgwep_ci;
	struct gsm_lchan *old_lchan = lchan->activate.info.re_use_mgw_endpoint_from_lchan;
	struct lchan_activate_info *info = &lchan->activate.info;
	int ms_power_dbm;

	if (lchan->release.requested) {
		lchan_fail("Release requested while activating");
		return;
	}

	lchan->conn = info->for_conn;

	/* If there is a previous lchan, and the new lchan is on the same cell as previous one,
	 * take over power and TA values. Otherwise, use max power and zero TA. */
	if (old_lchan && old_lchan->ts->trx->bts == bts) {
		ms_power_dbm = ms_pwr_dbm(bts->band, old_lchan->ms_power);
		lchan_update_ms_power_ctrl_level(lchan, ms_power_dbm >= 0 ? ms_power_dbm : bts->ms_max_power);
		lchan->bs_power_db = old_lchan->bs_power_db;
	} else {
		lchan_update_ms_power_ctrl_level(lchan, bts->ms_max_power);
		/* Upon last entering the UNUSED state, from lchan_reset():
		 * - bs_power_db is still zero, 0dB reduction, output power = Pn.
		 * - TA is still zero, to be determined by RACH. */

		/* Default BS Power reduction value (in 2 dB steps) */
		if (bts->bs_power_ctrl.mode == GSM_PWR_CTRL_MODE_DYN_BTS)
			lchan->bs_power_db = bts->bs_power_ctrl.bs_power_max_db;
		else
			lchan->bs_power_db = bts->bs_power_ctrl.bs_power_val_db;
	}

	/* BS Power Control is generally not allowed on the BCCH/CCCH carrier.
	 * However, we allow it in the BCCH carrier power reduction mode of operation. */
	if (lchan->ts->trx == bts->c0) {
		lchan->bs_power_db = OSMO_MIN(lchan->ts->c0_max_power_red_db,
					      lchan->bs_power_db);
	}

	if (lchan_activate_set_ch_mode_rate_and_mr_config(lchan))
		return;

	use_mgwep_ci = lchan_use_mgw_endpoint_ci_bts(lchan);

	LOG_LCHAN(lchan, LOGL_INFO,
		  "Activation requested: %s voice=%s MGW-ci=%s type=%s tch-mode=%s encr-alg=A5/%u ck=%s\n",
		  lchan_activate_mode_name(lchan->activate.info.activ_for),
		  lchan->activate.info.requires_voice_stream ? "yes" : "no",
		  lchan->activate.info.requires_voice_stream ?
			(use_mgwep_ci ? osmo_mgcpc_ep_ci_name(use_mgwep_ci) : "new")
			: "none",
		  gsm_lchant_name(lchan->type),
		  gsm48_chan_mode_name(lchan->activate.ch_mode_rate.chan_mode),
		  (lchan->activate.info.encr.alg_id ? : 1)-1,
		  lchan->activate.info.encr.key_len ? osmo_hexdump_nospc(lchan->activate.info.encr.key,
									 lchan->activate.info.encr.key_len) : "none");

	/* Ask for the timeslot to make ready for this lchan->type.
	 * We'll receive LCHAN_EV_TS_READY or LCHAN_EV_TS_ERROR in response. */
	osmo_fsm_inst_dispatch(lchan->ts->fi, TS_EV_LCHAN_REQUESTED, lchan);

	/* Prepare an MGW endpoint CI if appropriate. */
	if (lchan->activate.info.requires_voice_stream)
		lchan_rtp_fsm_start(lchan);
}

static void lchan_fsm_wait_ts_ready(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_lchan *lchan = lchan_fi_lchan(fi);
	switch (event) {

	case LCHAN_EV_TS_READY:
		/* timeslot agrees that we may Chan Activ now. Sending it in onenter. */
		lchan_fsm_state_chg(LCHAN_ST_WAIT_ACTIV_ACK);
		break;

	case LCHAN_EV_RTP_RELEASED:
	case LCHAN_EV_RTP_ERROR:
		if (lchan->release.in_release_handler) {
			/* Already in release, the RTP is not the initial cause of failure.
			 * Just ignore. */
			return;
		}

		lchan_fail("Failed to setup RTP stream: %s in state %s",
			   osmo_fsm_event_name(fi->fsm, event),
			   osmo_fsm_inst_state_name(fi));
		return;

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

	if (lchan->release.requested) {
		lchan_fail_to(LCHAN_ST_UNUSED, "Release requested while activating");
		return;
	}

	switch (lchan->activate.info.activ_for) {
	case ACTIVATE_FOR_MS_CHANNEL_REQUEST:
		act_type = RSL_ACT_INTRA_IMM_ASS;
		break;
	case ACTIVATE_FOR_HANDOVER:
		act_type = lchan->conn->ho.async ? RSL_ACT_INTER_ASYNC : RSL_ACT_INTER_SYNC;
		ho_ref = lchan->conn->ho.ho_ref;
		break;
	default:
	case ACTIVATE_FOR_ASSIGNMENT:
		act_type = RSL_ACT_INTRA_NORM_ASS;
		break;
	}

	lchan->encr = lchan->activate.info.encr;

	/* If enabling VAMOS mode and no specific TSC Set was selected, make sure to select a sane TSC Set by
	 * default: Set 1 for the primary and Set 2 for the shadow lchan. For non-VAMOS lchans, TSC Set 1. */
	if (lchan->activate.info.tsc_set > 0)
		lchan->activate.tsc_set = lchan->activate.info.tsc_set;
	else
		lchan->activate.tsc_set = lchan->vamos.is_secondary ? 2 : 1;

	/* Use the TSC provided in the modification request, if any. Otherwise use the timeslot's configured
	 * TSC. */
	lchan->activate.tsc = (lchan->activate.info.tsc >= 0) ? lchan->activate.info.tsc : gsm_ts_tsc(lchan->ts);

	rc = rsl_tx_chan_activ(lchan, act_type, ho_ref);
	if (rc) {
		lchan_fail_to(LCHAN_ST_UNUSED, "Tx Chan Activ failed: %s (%d)", strerror(-rc), rc);
		return;
	}

	if (lchan->activate.info.ta_known)
		lchan->last_ta = lchan->activate.info.ta;
}

static void lchan_fsm_post_activ_ack(struct osmo_fsm_inst *fi);

static void lchan_fsm_wait_activ_ack(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_lchan *lchan = lchan_fi_lchan(fi);
	switch (event) {

	case LCHAN_EV_RSL_CHAN_ACTIV_ACK:
		lchan->activate.activ_ack = true;
		lchan_fsm_post_activ_ack(fi);
		break;

	case LCHAN_EV_RSL_CHAN_ACTIV_NACK:
		lchan->release.in_release_handler = true;
		if (data) {
			uint32_t next_state;
			lchan->release.rsl_error_cause = *(uint8_t*)data;
			lchan->release.rr_cause = bsc_gsm48_rr_cause_from_rsl_cause(lchan->release.rsl_error_cause);
			lchan->release.in_error = true;
			if (lchan->release.rsl_error_cause != RSL_ERR_RCH_ALR_ACTV_ALLOC)
				next_state = LCHAN_ST_BORKEN;
			else
				/* Taking this over from legacy code: send an RF Chan Release even though
				 * the Activ was NACKed. Is this really correct? */
				next_state = LCHAN_ST_WAIT_RF_RELEASE_ACK;

			lchan_fail_to(next_state, "Chan Activ NACK: %s (0x%x)",
				      rsl_err_name(lchan->release.rsl_error_cause), lchan->release.rsl_error_cause);
		} else {
			lchan->release.rsl_error_cause = RSL_ERR_IE_NONEXIST;
			lchan->release.rr_cause = bsc_gsm48_rr_cause_from_rsl_cause(lchan->release.rsl_error_cause);
			lchan->release.in_error = true;
			lchan_fail_to(LCHAN_ST_BORKEN, "Chan Activ NACK without cause IE");
		}
		lchan->release.in_release_handler = false;
		break;

	case LCHAN_EV_RTP_RELEASED:
	case LCHAN_EV_RTP_ERROR:
		if (lchan->release.in_release_handler) {
			/* Already in release, the RTP is not the initial cause of failure.
			 * Just ignore. */
			return;
		}

		lchan_fail_to(LCHAN_ST_WAIT_RF_RELEASE_ACK,
			      "Failed to setup RTP stream: %s in state %s\n",
			      osmo_fsm_event_name(fi->fsm, event),
			      osmo_fsm_inst_state_name(fi));
		return;

	default:
		OSMO_ASSERT(false);
	}
}

static void lchan_fsm_post_activ_ack(struct osmo_fsm_inst *fi)
{
	int rc;
	struct gsm_lchan *lchan = lchan_fi_lchan(fi);

	lchan->current_ch_mode_rate = lchan->activate.ch_mode_rate;
	lchan->current_mr_conf = lchan->activate.mr_conf_filtered;
	lchan->vamos.enabled = lchan->activate.info.vamos;
	lchan->tsc_set = lchan->activate.tsc_set;
	lchan->tsc = lchan->activate.tsc;
	LOG_LCHAN(lchan, LOGL_INFO, "Rx Activ ACK %s\n",
		  gsm48_chan_mode_name(lchan->current_ch_mode_rate.chan_mode));

	if (lchan->release.requested) {
		lchan_fail_to(LCHAN_ST_WAIT_RF_RELEASE_ACK, "Release requested while activating");
		return;
	}

	switch (lchan->activate.info.activ_for) {

	case ACTIVATE_FOR_MS_CHANNEL_REQUEST:
		rc = rsl_tx_imm_assignment(lchan);
		if (rc) {
			lchan_fail("Failed to Tx RR Immediate Assignment message (rc=%d %s)",
				   rc, strerror(-rc));
			return;
		}
		LOG_LCHAN(lchan, LOGL_DEBUG, "Tx RR Immediate Assignment\n");
		lchan->activate.immediate_assignment_sent = true;
		break;

	case ACTIVATE_FOR_ASSIGNMENT:
		if (!lchan->conn) {
			LOG_LCHAN(lchan, LOGL_ERROR,
				  "lchan activation for assignment succeeded, but lchan has no conn:"
				  " cannot trigger appropriate actions. Release.\n");
			lchan_release(lchan, false, true, RSL_ERR_EQUIPMENT_FAIL, NULL);
			break;
		}
		if (!lchan->conn->assignment.fi) {
			LOG_LCHAN(lchan, LOGL_ERROR,
				  "lchan activation for assignment succeeded, but lchan has no"
				  " assignment ongoing: cannot trigger appropriate actions. Release.\n");
			lchan_release(lchan, false, true, RSL_ERR_EQUIPMENT_FAIL, NULL);
			break;
		}
		/* After the Chan Activ Ack, the MS expects to receive an RR Assignment Command.
		 * Let the assignment_fsm handle that. */
		osmo_fsm_inst_dispatch(lchan->conn->assignment.fi, ASSIGNMENT_EV_LCHAN_ACTIVE, lchan);
		break;

	case ACTIVATE_FOR_HANDOVER:
		if (!lchan->conn) {
			LOG_LCHAN(lchan, LOGL_ERROR,
				  "lchan activation for handover succeeded, but lchan has no conn:"
				  " cannot trigger appropriate actions. Release.\n");
			lchan_release(lchan, false, true, RSL_ERR_EQUIPMENT_FAIL, NULL);
			break;
		}
		if (!lchan->conn->ho.fi) {
			LOG_LCHAN(lchan, LOGL_ERROR,
				  "lchan activation for handover succeeded, but lchan has no"
				  " handover ongoing: cannot trigger appropriate actions. Release.\n");
			lchan_release(lchan, false, true, RSL_ERR_EQUIPMENT_FAIL, NULL);
			break;
		}
		/* After the Chan Activ Ack of the new lchan, send the MS an RR Handover Command on the
		 * old channel. The handover_fsm handles that. */
		osmo_fsm_inst_dispatch(lchan->conn->ho.fi, HO_EV_LCHAN_ACTIVE, lchan);
		break;

	default:
		LOG_LCHAN(lchan, LOGL_NOTICE, "lchan %s is now active\n",
			  lchan_activate_mode_name(lchan->activate.info.activ_for));
		break;
	}

	lchan_fsm_state_chg(LCHAN_ST_WAIT_RLL_RTP_ESTABLISH);
}

static void lchan_fsm_wait_rll_rtp_establish_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct gsm_lchan *lchan = lchan_fi_lchan(fi);
	if (lchan->fi_rtp)
		osmo_fsm_inst_dispatch(lchan->fi_rtp, LCHAN_RTP_EV_LCHAN_READY, 0);
	/* Prepare an MGW endpoint CI if appropriate (late). */
	else if (lchan->activate.info.requires_voice_stream)
		lchan_rtp_fsm_start(lchan);

	/* When activating a channel for VTY, skip waiting for activity from
	 * lchan_rtp_fsm, but only if no voice stream is required. */
	if (lchan->activate.info.activ_for == ACTIVATE_FOR_VTY &&
	    !lchan->activate.info.requires_voice_stream) {
		lchan_fsm_state_chg(LCHAN_ST_ESTABLISHED);
	}
}

static void lchan_fsm_wait_rll_rtp_establish(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_lchan *lchan = lchan_fi_lchan(fi);
	switch (event) {

	case LCHAN_EV_RLL_ESTABLISH_IND:
		if (!lchan->activate.info.requires_voice_stream
		    || lchan_rtp_established(lchan)) {
			LOG_LCHAN(lchan, LOGL_DEBUG,
				  "%s\n",
				  (lchan->activate.info.requires_voice_stream ?
				   "RTP already established earlier" : "no voice stream required"));
			lchan_fsm_state_chg(LCHAN_ST_ESTABLISHED);
		}
		return;

	case LCHAN_EV_RTP_READY:
		if (lchan->sapis[0] != LCHAN_SAPI_UNUSED)
			lchan_fsm_state_chg(LCHAN_ST_ESTABLISHED);
		return;

	case LCHAN_EV_RTP_RELEASED:
	case LCHAN_EV_RTP_ERROR:
		if (lchan->release.in_release_handler) {
			/* Already in release, the RTP is not the initial cause of failure.
			 * Just ignore. */
			return;
		}

		lchan_fail("Failed to setup RTP stream: %s in state %s",
			   osmo_fsm_event_name(fi->fsm, event),
			   osmo_fsm_inst_state_name(fi));
		return;

	default:
		OSMO_ASSERT(false);
	}
}

static void lchan_fsm_wait_rr_chan_mode_modify_ack_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct gsm_lchan *lchan = lchan_fi_lchan(fi);
	gsm48_lchan_modify(lchan, lchan->modify.ch_mode_rate.chan_mode);
}

static void lchan_fsm_wait_rr_chan_mode_modify_ack(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {

	case LCHAN_EV_RR_CHAN_MODE_MODIFY_ACK:
		lchan_fsm_state_chg(LCHAN_ST_WAIT_RSL_CHAN_MODE_MODIFY_ACK);
		return;

	case LCHAN_EV_RR_CHAN_MODE_MODIFY_ERROR:
		lchan_fail("Failed to change channel mode on the MS side: %s in state %s",
			   osmo_fsm_event_name(fi->fsm, event),
			   osmo_fsm_inst_state_name(fi));
		return;

	default:
		OSMO_ASSERT(false);
	}
}

static void lchan_fsm_wait_rsl_chan_mode_modify_ack_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct gsm_lchan *lchan = lchan_fi_lchan(fi);
	int rc;

	rc = rsl_chan_mode_modify_req(lchan);
	if (rc < 0) {
		lchan_fail("Failed to send rsl message to change the channel mode on the BTS side: state %s",
			   osmo_fsm_inst_state_name(fi));
	}
}

static void lchan_fsm_wait_rsl_chan_mode_modify_ack(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_lchan *lchan = lchan_fi_lchan(fi);
	switch (event) {

	case LCHAN_EV_RSL_CHAN_MODE_MODIFY_ACK:
		/* The Channel Mode Modify was ACKed, now the requested values become the accepted and used values. */
		lchan->current_ch_mode_rate = lchan->modify.ch_mode_rate;
		lchan->current_mr_conf = lchan->modify.mr_conf_filtered;
		lchan->tsc_set = lchan->modify.tsc_set;
		lchan->tsc = lchan->modify.tsc;
		lchan->vamos.enabled = lchan->modify.info.vamos;

		if (lchan->modify.info.requires_voice_stream
		    && !lchan->fi_rtp) {
			/* Continue with RTP stream establishing as done in lchan_activate(). Place the requested values in
			 * lchan->activate.info and continue with voice stream setup. */
			lchan->activate.info = (struct lchan_activate_info){
				.activ_for = ACTIVATE_FOR_MODE_MODIFY_RTP,
				.for_conn = lchan->conn,
				.ch_mode_rate = lchan->modify.ch_mode_rate,
				.requires_voice_stream = true,
				.msc_assigned_cic = lchan->modify.info.msc_assigned_cic,
				.tsc_set = -1,
				.tsc = -1,
			};
			if (lchan_activate_set_ch_mode_rate_and_mr_config(lchan))
				return;

			lchan->activate.concluded = false;
			lchan_fsm_state_chg(LCHAN_ST_WAIT_RLL_RTP_ESTABLISH);
		} else {
			lchan_fsm_state_chg(LCHAN_ST_ESTABLISHED);
			lchan_on_mode_modify_success(lchan);
		}
		return;

	case LCHAN_EV_RSL_CHAN_MODE_MODIFY_NACK:
		lchan_fail("Failed to change channel mode on the BTS side: %s in state %s",
			   osmo_fsm_event_name(fi->fsm, event),
			   osmo_fsm_inst_state_name(fi));
		return;

	default:
		OSMO_ASSERT(false);
	}
}

static void lchan_fsm_established_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct gsm_lchan *lchan = lchan_fi_lchan(fi);

	if (lchan->release.requested) {
		lchan_fail("Release requested while activating");
		return;
	}

	lchan_on_fully_established(lchan);
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

static void handle_rll_rel_ind_or_conf(struct osmo_fsm_inst *fi, uint32_t event, void *data)
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

	/* The caller shall check whether all SAPIs are released and cause a state chg */
}

static void lchan_fsm_established(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_lchan *lchan = lchan_fi_lchan(fi);
	struct lchan_modify_info *modif_info;
	struct osmo_mgcpc_ep_ci *use_mgwep_ci;

	switch (event) {
	case LCHAN_EV_RLL_ESTABLISH_IND:
		/* abis_rsl.c has noticed that a SAPI was established, no need to take action here. */
		return;

	case LCHAN_EV_RLL_REL_IND:
	case LCHAN_EV_RLL_REL_CONF:
		handle_rll_rel_ind_or_conf(fi, event, data);
		if (!lchan_active_sapis(lchan, 0))
			lchan_fsm_state_chg(LCHAN_ST_WAIT_RLL_RTP_RELEASED);
		return;

	case LCHAN_EV_RTP_RELEASED:
	case LCHAN_EV_RTP_ERROR:
		if (lchan->release.in_release_handler) {
			/* Already in release, the RTP is not the initial cause of failure.
			 * Just ignore. */
			return;
		}

		lchan_fail("RTP stream closed unexpectedly: %s in state %s",
			   osmo_fsm_event_name(fi->fsm, event),
			   osmo_fsm_inst_state_name(fi));
		return;

	case LCHAN_EV_REQUEST_MODE_MODIFY:
		modif_info = data;
		lchan->modify.info = *modif_info;
		lchan->modify.concluded = false;

		use_mgwep_ci = lchan_use_mgw_endpoint_ci_bts(lchan);

		lchan->modify.ch_mode_rate = lchan->modify.info.ch_mode_rate;
		lchan->modify.ch_mode_rate.chan_mode = (lchan->modify.info.vamos
						? gsm48_chan_mode_to_vamos(lchan->modify.info.ch_mode_rate.chan_mode)
						: gsm48_chan_mode_to_non_vamos(lchan->modify.info.ch_mode_rate.chan_mode));
		if (lchan->modify.ch_mode_rate.chan_mode < 0) {
			lchan_fail("Invalid chan_mode: %s", gsm48_chan_mode_name(lchan->modify.info.ch_mode_rate.chan_mode));
			return;
		}

		if (gsm48_chan_mode_to_non_vamos(modif_info->ch_mode_rate.chan_mode) == GSM48_CMODE_SPEECH_AMR) {
			if (lchan_mr_config(&lchan->modify.mr_conf_filtered, lchan, modif_info->ch_mode_rate.s15_s0)
			    < 0) {
				lchan_fail("Can not generate multirate configuration IE");
				return;
			}
		}

		/* If enabling VAMOS mode and no specific TSC Set was selected, make sure to select a sane TSC Set by
		 * default: Set 1 for the primary and Set 2 for the shadow lchan. For non-VAMOS lchans, TSC Set 1. */
		if (lchan->modify.info.tsc_set > 0)
			lchan->modify.tsc_set = lchan->modify.info.tsc_set;
		else
			lchan->modify.tsc_set = lchan->vamos.is_secondary ? 2 : 1;

		/* Use the TSC provided in the modification request, if any. Otherwise use the timeslot's configured
		 * TSC. */
		lchan->modify.tsc = (lchan->modify.info.tsc >= 0) ? lchan->modify.info.tsc : gsm_ts_tsc(lchan->ts);

		LOG_LCHAN(lchan, LOGL_INFO,
			  "Modification requested: %s voice=%s MGW-ci=%s type=%s tch-mode=%s tsc=%d/%u\n",
			  lchan_modify_for_name(lchan->modify.info.modify_for),
			  lchan->modify.info.requires_voice_stream ? "yes" : "no",
			  lchan->modify.info.requires_voice_stream ?
			  (use_mgwep_ci ? osmo_mgcpc_ep_ci_name(use_mgwep_ci) : "new")
			  : "none",
			  gsm_lchant_name(lchan->type),
			  gsm48_chan_mode_name(lchan->modify.ch_mode_rate.chan_mode),
			  lchan->modify.tsc_set, lchan->modify.tsc);

		lchan_fsm_state_chg(LCHAN_ST_WAIT_RR_CHAN_MODE_MODIFY_ACK);
		return;

	default:
		OSMO_ASSERT(false);
	}
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

static void lchan_do_release(struct gsm_lchan *lchan)
{
	if (lchan->release.do_rr_release && lchan->sapis[0] != LCHAN_SAPI_UNUSED)
		gsm48_send_rr_release(lchan);

	if (lchan->fi_rtp)
		osmo_fsm_inst_dispatch(lchan->fi_rtp, LCHAN_RTP_EV_RELEASE, 0);

	if (should_sacch_deact(lchan))
		rsl_deact_sacch(lchan);
}

static void lchan_fsm_wait_rll_rtp_released_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	int sapis;
	int sapi;
	struct gsm_lchan *lchan = lchan_fi_lchan(fi);

	for (sapi=0; sapi < ARRAY_SIZE(lchan->sapis); sapi++)
		if (lchan->sapis[sapi])
			LOG_LCHAN(lchan, LOGL_DEBUG, "SAPI[%d] = %d\n", sapi, lchan->sapis[sapi]);

	/* It could be that we receive LCHAN_EV_RTP_RELEASED synchronously and
	   as a result we may end up in state WAIT_BEFORE_RF_RELEASE after
	   lchan_do_release has returned */
	lchan_do_release(lchan);

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

	if (!sapis && !lchan->fi_rtp && fi->state == LCHAN_ST_WAIT_RLL_RTP_RELEASED)
		lchan_fsm_state_chg(LCHAN_ST_WAIT_BEFORE_RF_RELEASE);
}

static void lchan_fsm_wait_rll_rtp_released(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_lchan *lchan = lchan_fi_lchan(fi);
	switch (event) {

	case LCHAN_EV_RLL_REL_IND:
	case LCHAN_EV_RLL_REL_CONF:
		/* When we're telling the MS to release, we're fine to carry on with RF Channel Release
		 * when SAPI 0 release is not confirmed yet.
		 * TODO: that's how the code was before lchan FSM, is this correct/useful? */
		handle_rll_rel_ind_or_conf(fi, event, data);
		break;

	case LCHAN_EV_RTP_RELEASED:
	case LCHAN_EV_RTP_ERROR:
		break;

	default:
		OSMO_ASSERT(false);
	}

	if (!lchan_active_sapis(lchan, 1) && !lchan->fi_rtp)
		lchan_fsm_state_chg(LCHAN_ST_WAIT_BEFORE_RF_RELEASE);
}

static void lchan_fsm_wait_rf_release_ack_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	int rc;
	struct gsm_lchan *lchan = lchan_fi_lchan(fi);

	/* For planned releases, a conn has already forgotten about the lchan. And later on, in
	 * lchan_reset(), we make sure it does. But in case of releases from error handling, the
	 * conn might as well notice now already that its lchan is becoming unusable. */
	if (lchan->conn) {
		gscon_forget_lchan(lchan->conn, lchan);
		lchan_forget_conn(lchan);
	}

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
		if (lchan->release.in_error)
			lchan_fsm_state_chg(LCHAN_ST_WAIT_AFTER_ERROR);
		else
			lchan_fsm_state_chg(LCHAN_ST_UNUSED);
		break;

	case LCHAN_EV_RTP_RELEASED:
		/* ignore late lchan_rtp_fsm release events */
		return;

	case LCHAN_EV_RLL_REL_IND:
		/* let's just ignore this.  We are already logging the fact
		 * that this message was received inside abis_rsl.c. There can
		 * be any number of reasons why the radio link layer failed.
		 */
		return;

	default:
		OSMO_ASSERT(false);
	}
}

static void lchan_fsm_borken_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct gsm_lchan *lchan = lchan_fi_lchan(fi);
	struct gsm_bts *bts = lchan->ts->trx->bts;
	enum bts_counter_id ctr;
	switch (prev_state) {
	case LCHAN_ST_UNUSED:
		ctr = BTS_CTR_LCHAN_BORKEN_FROM_UNUSED;
		break;
	case LCHAN_ST_WAIT_ACTIV_ACK:
		ctr = BTS_CTR_LCHAN_BORKEN_FROM_WAIT_ACTIV_ACK;
		break;
	case LCHAN_ST_WAIT_RF_RELEASE_ACK:
		ctr = BTS_CTR_LCHAN_BORKEN_FROM_WAIT_RF_RELEASE_ACK;
		break;
	case LCHAN_ST_BORKEN:
		ctr = BTS_CTR_LCHAN_BORKEN_FROM_BORKEN;
		break;
	case LCHAN_ST_WAIT_RR_CHAN_MODE_MODIFY_ACK:
		ctr = BTS_CTR_LCHAN_BORKEN_FROM_WAIT_RR_CHAN_MODE_MODIFY_ACK;
		break;
	case LCHAN_ST_WAIT_RSL_CHAN_MODE_MODIFY_ACK:
		ctr = BTS_CTR_LCHAN_BORKEN_FROM_WAIT_RSL_CHAN_MODE_MODIFY_ACK;
		break;
	default:
		ctr = BTS_CTR_LCHAN_BORKEN_FROM_UNKNOWN;
	}
	rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, ctr));
	if (prev_state != LCHAN_ST_BORKEN)
		osmo_stat_item_inc(osmo_stat_item_group_get_item(bts->bts_statg, BTS_STAT_LCHAN_BORKEN), 1);

	/* The actual action besides all the beancounting above */
	lchan_reset(lchan);
}

static void lchan_fsm_borken(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_lchan *lchan = lchan_fi_lchan(fi);
	struct gsm_bts *bts = lchan->ts->trx->bts;
	switch (event) {

	case LCHAN_EV_RSL_CHAN_ACTIV_ACK:
		/* A late Chan Activ ACK? Release. */
		rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_LCHAN_BORKEN_EV_CHAN_ACTIV_ACK));
		osmo_stat_item_dec(osmo_stat_item_group_get_item(bts->bts_statg, BTS_STAT_LCHAN_BORKEN), 1);
		lchan->release.in_error = true;
		lchan->release.rsl_error_cause = RSL_ERR_INTERWORKING;
		lchan->release.rr_cause = bsc_gsm48_rr_cause_from_rsl_cause(lchan->release.rsl_error_cause);
		lchan_fsm_state_chg(LCHAN_ST_WAIT_RF_RELEASE_ACK);
		return;

	case LCHAN_EV_RSL_CHAN_ACTIV_NACK:
		/* A late Chan Activ NACK? Ok then, unused. */
		rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_LCHAN_BORKEN_EV_CHAN_ACTIV_NACK));
		osmo_stat_item_dec(osmo_stat_item_group_get_item(bts->bts_statg, BTS_STAT_LCHAN_BORKEN), 1);
		lchan_fsm_state_chg(LCHAN_ST_UNUSED);
		return;

	case LCHAN_EV_RSL_RF_CHAN_REL_ACK:
		/* A late Release ACK? */
		rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_LCHAN_BORKEN_EV_RF_CHAN_REL_ACK));
		osmo_stat_item_dec(osmo_stat_item_group_get_item(bts->bts_statg, BTS_STAT_LCHAN_BORKEN), 1);
		lchan->release.in_error = true;
		lchan->release.rsl_error_cause = RSL_ERR_INTERWORKING;
		lchan->release.rr_cause = bsc_gsm48_rr_cause_from_rsl_cause(lchan->release.rsl_error_cause);
		lchan_fsm_state_chg(LCHAN_ST_WAIT_AFTER_ERROR);
		/* TODO: we used to do this only for sysmobts:
			int do_free = is_osmobts(ts->trx->bts);
			LOGP(DRSL, LOGL_NOTICE,
				"%s CHAN REL ACK for broken channel. %s.\n",
				gsm_lchan_name(lchan),
				do_free ? "Releasing it" : "Keeping it broken");
			if (do_free)
				do_lchan_free(lchan);
		 * Clarify the reason. If a BTS sends a RF Chan Rel ACK, we can consider it released,
		 * independently from the BTS model, right?? */
		return;

	case LCHAN_EV_RTP_RELEASED:
	case LCHAN_EV_RTP_ERROR:
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
			| S(LCHAN_ST_CBCH)
			| S(LCHAN_ST_BORKEN)
			,
	},
	[LCHAN_ST_CBCH] = {
		.name = "CBCH",
		.out_state_mask = 0
			| S(LCHAN_ST_UNUSED)
			,
	},
	[LCHAN_ST_WAIT_TS_READY] = {
		.name = "WAIT_TS_READY",
		.onenter = lchan_fsm_wait_ts_ready_onenter,
		.action = lchan_fsm_wait_ts_ready,
		.in_event_mask = 0
			| S(LCHAN_EV_TS_READY)
			| S(LCHAN_EV_RTP_ERROR)
			| S(LCHAN_EV_RTP_RELEASED)
			,
		.out_state_mask = 0
			| S(LCHAN_ST_UNUSED)
			| S(LCHAN_ST_WAIT_ACTIV_ACK)
			| S(LCHAN_ST_WAIT_RLL_RTP_RELEASED)
			,
	},
	[LCHAN_ST_WAIT_ACTIV_ACK] = {
		.name = "WAIT_ACTIV_ACK",
		.onenter = lchan_fsm_wait_activ_ack_onenter,
		.action = lchan_fsm_wait_activ_ack,
		.in_event_mask = 0
			| S(LCHAN_EV_RSL_CHAN_ACTIV_ACK)
			| S(LCHAN_EV_RSL_CHAN_ACTIV_NACK)
			| S(LCHAN_EV_RTP_ERROR)
			| S(LCHAN_EV_RTP_RELEASED)
			,
		.out_state_mask = 0
			| S(LCHAN_ST_UNUSED)
			| S(LCHAN_ST_WAIT_RLL_RTP_ESTABLISH)
			| S(LCHAN_ST_BORKEN)
			| S(LCHAN_ST_WAIT_RF_RELEASE_ACK)
			,
	},
	[LCHAN_ST_WAIT_RLL_RTP_ESTABLISH] = {
		.name = "WAIT_RLL_RTP_ESTABLISH",
		.onenter = lchan_fsm_wait_rll_rtp_establish_onenter,
		.action = lchan_fsm_wait_rll_rtp_establish,
		.in_event_mask = 0
			| S(LCHAN_EV_RLL_ESTABLISH_IND)
			| S(LCHAN_EV_RTP_READY)
			| S(LCHAN_EV_RTP_ERROR)
			| S(LCHAN_EV_RTP_RELEASED)
			,
		.out_state_mask = 0
			| S(LCHAN_ST_UNUSED)
			| S(LCHAN_ST_ESTABLISHED)
			| S(LCHAN_ST_WAIT_RF_RELEASE_ACK)
			| S(LCHAN_ST_WAIT_RLL_RTP_RELEASED)
			,
	},
	[LCHAN_ST_WAIT_RR_CHAN_MODE_MODIFY_ACK] = {
		.name = "WAIT_CHAN_RR_MODE_MODIFY_ACK",
		.onenter = lchan_fsm_wait_rr_chan_mode_modify_ack_onenter,
		.action = lchan_fsm_wait_rr_chan_mode_modify_ack,
		.in_event_mask = 0
			| S(LCHAN_EV_RR_CHAN_MODE_MODIFY_ACK)
			| S(LCHAN_EV_RR_CHAN_MODE_MODIFY_ERROR)
			,
		.out_state_mask = 0
			| S(LCHAN_ST_WAIT_RSL_CHAN_MODE_MODIFY_ACK)
			| S(LCHAN_ST_WAIT_RF_RELEASE_ACK)
			| S(LCHAN_ST_BORKEN)
			,
	},
	[LCHAN_ST_WAIT_RSL_CHAN_MODE_MODIFY_ACK] = {
		.name = "WAIT_RSL_CHAN_MODE_MODIFY_ACK",
		.onenter = lchan_fsm_wait_rsl_chan_mode_modify_ack_onenter,
		.action = lchan_fsm_wait_rsl_chan_mode_modify_ack,
		.in_event_mask = 0
			| S(LCHAN_EV_RSL_CHAN_MODE_MODIFY_ACK)
			| S(LCHAN_EV_RSL_CHAN_MODE_MODIFY_NACK)
			,
		.out_state_mask = 0
			| S(LCHAN_ST_ESTABLISHED)
			| S(LCHAN_ST_WAIT_RLL_RTP_ESTABLISH)
			| S(LCHAN_ST_WAIT_RF_RELEASE_ACK)
			| S(LCHAN_ST_BORKEN)
			,
	},
	[LCHAN_ST_ESTABLISHED] = {
		.name = "ESTABLISHED",
		.onenter = lchan_fsm_established_onenter,
		.action = lchan_fsm_established,
		.in_event_mask = 0
			| S(LCHAN_EV_RLL_REL_IND)
			| S(LCHAN_EV_RLL_REL_CONF)
			| S(LCHAN_EV_RLL_ESTABLISH_IND) /* ignored */
			| S(LCHAN_EV_RTP_ERROR)
			| S(LCHAN_EV_RTP_RELEASED)
			| S(LCHAN_EV_REQUEST_MODE_MODIFY)
			,
		.out_state_mask = 0
			| S(LCHAN_ST_UNUSED)
			| S(LCHAN_ST_WAIT_RLL_RTP_RELEASED)
			| S(LCHAN_ST_WAIT_BEFORE_RF_RELEASE)
			| S(LCHAN_ST_WAIT_RF_RELEASE_ACK)
			| S(LCHAN_ST_WAIT_RR_CHAN_MODE_MODIFY_ACK)
			,
	},
	[LCHAN_ST_WAIT_RLL_RTP_RELEASED] = {
		.name = "WAIT_RLL_RTP_RELEASED",
		.onenter = lchan_fsm_wait_rll_rtp_released_onenter,
		.action = lchan_fsm_wait_rll_rtp_released,
		.in_event_mask = 0
			| S(LCHAN_EV_RLL_REL_IND)
			| S(LCHAN_EV_RLL_REL_CONF)
			| S(LCHAN_EV_RTP_ERROR)
			| S(LCHAN_EV_RTP_RELEASED)
			,
		.out_state_mask = 0
			| S(LCHAN_ST_UNUSED)
			| S(LCHAN_ST_WAIT_BEFORE_RF_RELEASE)
			| S(LCHAN_ST_WAIT_RF_RELEASE_ACK)
			,
	},
	[LCHAN_ST_WAIT_BEFORE_RF_RELEASE] = {
		.name = "WAIT_BEFORE_RF_RELEASE",
		.in_event_mask = 0
			| S(LCHAN_EV_RLL_REL_IND) /* allow late REL_IND of SAPI[0] */
			| S(LCHAN_EV_RTP_RELEASED) /* ignore late lchan_rtp_fsm release events */
			,
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
			| S(LCHAN_EV_RLL_REL_IND) /* ignore late REL_IND of SAPI[0] */
			| S(LCHAN_EV_RTP_RELEASED) /* ignore late lchan_rtp_fsm release events */
			,
		.out_state_mask = 0
			| S(LCHAN_ST_UNUSED)
			| S(LCHAN_ST_WAIT_AFTER_ERROR)
			| S(LCHAN_ST_BORKEN)
			,
	},
	[LCHAN_ST_WAIT_AFTER_ERROR] = {
		.name = "WAIT_AFTER_ERROR",
		.onenter = lchan_fsm_wait_after_error_onenter,
		.in_event_mask = 0
			| S(LCHAN_EV_RTP_RELEASED) /* ignore late lchan_rtp_fsm release events */
			,
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
			| S(LCHAN_EV_RTP_ERROR)
			| S(LCHAN_EV_RTP_RELEASED)
			,
		.out_state_mask = 0
			| S(LCHAN_ST_WAIT_RF_RELEASE_ACK)
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
	OSMO_VALUE_STRING(LCHAN_EV_RTP_READY),
	OSMO_VALUE_STRING(LCHAN_EV_RTP_ERROR),
	OSMO_VALUE_STRING(LCHAN_EV_RTP_RELEASED),
	OSMO_VALUE_STRING(LCHAN_EV_RLL_REL_IND),
	OSMO_VALUE_STRING(LCHAN_EV_RLL_REL_CONF),
	OSMO_VALUE_STRING(LCHAN_EV_RSL_RF_CHAN_REL_ACK),
	OSMO_VALUE_STRING(LCHAN_EV_RLL_ERR_IND),
	OSMO_VALUE_STRING(LCHAN_EV_RR_CHAN_MODE_MODIFY_ACK),
	OSMO_VALUE_STRING(LCHAN_EV_RR_CHAN_MODE_MODIFY_ERROR),
	OSMO_VALUE_STRING(LCHAN_EV_RSL_CHAN_MODE_MODIFY_ACK),
	OSMO_VALUE_STRING(LCHAN_EV_RSL_CHAN_MODE_MODIFY_NACK),
	OSMO_VALUE_STRING(LCHAN_EV_REQUEST_MODE_MODIFY),
	{}
};

static void lchan_fsm_allstate_action(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {

	case LCHAN_EV_TS_ERROR:
	{
		struct gsm_lchan *lchan = lchan_fi_lchan(fi);
		if (fi->state == LCHAN_ST_BORKEN) {
			rate_ctr_inc(rate_ctr_group_get_ctr(lchan->ts->trx->bts->bts_ctrs, BTS_CTR_LCHAN_BORKEN_EV_TS_ERROR));
			osmo_stat_item_dec(osmo_stat_item_group_get_item(lchan->ts->trx->bts->bts_statg, BTS_STAT_LCHAN_BORKEN), 1);
		}
		lchan_fail_to(LCHAN_ST_UNUSED, "LCHAN_EV_TS_ERROR");
		return;
	}

	case LCHAN_EV_RLL_ERR_IND:
		/* let's just ignore this.  We are already logging the
		 * fact that this message was received inside
		 * abis_rsl.c.  There can be any number of reasons why the
		 * radio link layer failed */
		return;

	default:
		return;
	}
}

void lchan_fsm_skip_error(struct gsm_lchan *lchan)
{
	struct osmo_fsm_inst *fi = lchan->fi;
	if (fi->state == LCHAN_ST_WAIT_AFTER_ERROR)
		lchan_fsm_state_chg(LCHAN_ST_UNUSED);
}

static int lchan_fsm_timer_cb(struct osmo_fsm_inst *fi)
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
		lchan->release.in_error = true;
		lchan->release.rsl_error_cause = RSL_ERR_INTERWORKING;
		lchan->release.rr_cause = bsc_gsm48_rr_cause_from_rsl_cause(lchan->release.rsl_error_cause);
		lchan_fail("Timeout");
		return 0;
	}
}

void lchan_release(struct gsm_lchan *lchan, bool do_rr_release,
		   bool err, enum gsm48_rr_cause cause_rr,
		   const struct osmo_plmn_id *last_eutran_plmn)
{
	if (!lchan || !lchan->fi || lchan->fi->state == LCHAN_ST_UNUSED)
		return;

	if (lchan->release.in_release_handler)
		return;
	lchan->release.in_release_handler = true;

	struct osmo_fsm_inst *fi = lchan->fi;

	lchan->release.in_error = err;
	lchan->release.do_rr_release = do_rr_release;
	lchan->release.rr_cause = cause_rr;
	if (last_eutran_plmn) {
		lchan->release.last_eutran_plmn_valid = true;
		memcpy(&lchan->release.last_eutran_plmn, last_eutran_plmn, sizeof(*last_eutran_plmn));
	}

	/* States waiting for events will notice the desire to release when done waiting, so it is enough
	 * to mark for release. */
	lchan->release.requested = true;

	/* If we took the RTP over from another lchan, put it back. */
	if (lchan->fi_rtp && lchan->release.in_error)
		osmo_fsm_inst_dispatch(lchan->fi_rtp, LCHAN_RTP_EV_ROLLBACK, 0);

	/* But when in error, don't wait for the next state to pick up release_requested. */
	if (lchan->release.in_error) {
		switch (lchan->fi->state) {
		default:
			/* Normally we signal release in lchan_fsm_wait_rll_rtp_released_onenter(). When
			 * skipping that, do it now. */
			lchan_do_release(lchan);
			/* fall thru */
		case LCHAN_ST_WAIT_RLL_RTP_RELEASED:
			lchan_fsm_state_chg(LCHAN_ST_WAIT_RF_RELEASE_ACK);
			goto exit_release_handler;
		case LCHAN_ST_WAIT_TS_READY:
			lchan_fsm_state_chg(LCHAN_ST_WAIT_RLL_RTP_RELEASED);
			goto exit_release_handler;
		case LCHAN_ST_WAIT_RF_RELEASE_ACK:
		case LCHAN_ST_BORKEN:
			goto exit_release_handler;
		}
	}

	/* The only non-broken state that would stay stuck without noticing the release_requested flag
	 * is: */
	if (fi->state == LCHAN_ST_ESTABLISHED)
		lchan_fsm_state_chg(LCHAN_ST_WAIT_RLL_RTP_RELEASED);

exit_release_handler:
	lchan->release.in_release_handler = false;
}

static void lchan_fsm_cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct gsm_lchan *lchan = lchan_fi_lchan(fi);
	if (lchan->fi->state == LCHAN_ST_BORKEN) {
		rate_ctr_inc(rate_ctr_group_get_ctr(lchan->ts->trx->bts->bts_ctrs, BTS_CTR_LCHAN_BORKEN_EV_TEARDOWN));
		osmo_stat_item_dec(osmo_stat_item_group_get_item(lchan->ts->trx->bts->bts_statg, BTS_STAT_LCHAN_BORKEN), 1);
	}
	lchan_reset(lchan);
	if (lchan->last_error) {
		talloc_free(lchan->last_error);
		lchan->last_error = NULL;
	}
	lchan->fi = NULL;
}

/* The conn is deallocating, just forget all about it */
void lchan_forget_conn(struct gsm_lchan *lchan)
{
	struct gsm_subscriber_connection *conn;
	if (!lchan)
		return;

	lchan->activate.info.for_conn = NULL;

	conn = lchan->conn;
	if (conn) {
		/* Log for both lchan FSM and conn FSM to ease reading the log in case of problems */
		if (lchan->fi)
			LOGPFSML(lchan->fi, LOGL_DEBUG, "lchan detaches from conn %s\n",
				 conn->fi? osmo_fsm_inst_name(conn->fi) : "(conn without FSM)");
		if (conn->fi)
			LOGPFSML(conn->fi, LOGL_DEBUG, "lchan %s detaches from conn\n",
				 lchan->fi? osmo_fsm_inst_name(lchan->fi) : gsm_lchan_name(lchan));
	}

	lchan_forget_mgw_endpoint(lchan);
	lchan->conn = NULL;
}

static struct osmo_fsm lchan_fsm = {
	.name = "lchan",
	.states = lchan_fsm_states,
	.num_states = ARRAY_SIZE(lchan_fsm_states),
	.log_subsys = DCHAN,
	.event_names = lchan_fsm_event_names,
	.allstate_action = lchan_fsm_allstate_action,
	.allstate_event_mask = 0
		| S(LCHAN_EV_TS_ERROR)
		| S(LCHAN_EV_RLL_ERR_IND)
		,
	.timer_cb = lchan_fsm_timer_cb,
	.cleanup = lchan_fsm_cleanup,
};
