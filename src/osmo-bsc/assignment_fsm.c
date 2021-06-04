/* osmo-bsc BSSMAP Assignment procedure implementation.
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

#include <osmocom/core/tdef.h>
#include <osmocom/gsm/gsm0808.h>

#include <osmocom/mgcp_client/mgcp_client_endpoint_fsm.h>

#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/lchan_fsm.h>
#include <osmocom/bsc/bsc_subscr_conn_fsm.h>
#include <osmocom/bsc/osmo_bsc_lcls.h>
#include <osmocom/bsc/bsc_msc_data.h>
#include <osmocom/bsc/gsm_08_08.h>
#include <osmocom/bsc/gsm_04_08_rr.h>
#include <osmocom/bsc/lchan_select.h>
#include <osmocom/bsc/abis_rsl.h>
#include <osmocom/bsc/bts.h>

#include <osmocom/bsc/assignment_fsm.h>

static struct osmo_fsm assignment_fsm;

struct gsm_subscriber_connection *assignment_fi_conn(struct osmo_fsm_inst *fi)
{
	OSMO_ASSERT(fi);
	OSMO_ASSERT(fi->fsm == &assignment_fsm);
	OSMO_ASSERT(fi->priv);
	return fi->priv;
}

static const struct osmo_tdef_state_timeout assignment_fsm_timeouts[32] = {
	[ASSIGNMENT_ST_WAIT_LCHAN_ACTIVE] = { .T=10 },
	[ASSIGNMENT_ST_WAIT_RR_ASS_COMPLETE] = { .keep_timer=true },
	[ASSIGNMENT_ST_WAIT_LCHAN_ESTABLISHED] = { .keep_timer=true },
	[ASSIGNMENT_ST_WAIT_MGW_ENDPOINT_TO_MSC] = { .T=23042 },
};

/* Transition to a state, using the T timer defined in assignment_fsm_timeouts.
 * The actual timeout value is in turn obtained from network->T_defs.
 * Assumes local variable fi exists. */
#define assignment_fsm_state_chg(state) \
	osmo_tdef_fsm_inst_state_chg(fi, state, \
				     assignment_fsm_timeouts, \
				     ((struct gsm_subscriber_connection*)(fi->priv))->network->T_defs, \
				     5)

/* Log failure and transition to ASSIGNMENT_ST_FAILURE, which triggers the appropriate actions. */
#define assignment_fail(cause, fmt, args...) do { \
		struct gsm_subscriber_connection *_conn = fi->priv; \
		_conn->assignment.failure_cause = cause; \
		LOG_ASSIGNMENT(_conn, LOGL_ERROR, "Assignment failed in state %s, cause %s: " fmt "\n", \
			       osmo_fsm_inst_state_name(fi), gsm0808_cause_name(cause), ## args); \
		assignment_count_result(CTR_ASSIGNMENT_ERROR); \
		on_assignment_failure(_conn); \
	} while(0)

/* Assume presence of local var 'conn' as struct gsm_subscriber_connection */
#define assignment_count(counter) do { \
		struct gsm_bts *bts = conn_get_bts(conn); \
		LOG_ASSIGNMENT(conn, LOGL_DEBUG, "incrementing rate counter: %s %s\n", \
			       bsc_ctr_description[BSC_##counter].name, \
			       bsc_ctr_description[BSC_##counter].description); \
		rate_ctr_inc(rate_ctr_group_get_ctr(conn->network->bsc_ctrs, BSC_##counter)); \
		if (bts) { \
			rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_##counter)); \
			switch (gsm48_chan_mode_to_non_vamos(conn->assignment.req.ch_mode_rate_list[0].chan_mode)) { \
			case GSM48_CMODE_SIGN: \
				rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_##counter##_SIGN)); \
				break; \
			case GSM48_CMODE_SPEECH_V1: \
			case GSM48_CMODE_SPEECH_EFR: \
			case GSM48_CMODE_SPEECH_AMR: \
				rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_##counter##_SPEECH)); \
				break; \
			default: \
				break; \
			} \
		} \
	} while(0)

#define assignment_count_result(counter) do { \
		if (!conn->assignment.result_rate_ctr_done) { \
			assignment_count(counter); \
			conn->assignment.result_rate_ctr_done = true; \
		} else \
			LOG_ASSIGNMENT(conn, LOGL_DEBUG, \
				       "result rate counter already recorded, NOT counting as: %s %s\n", \
				       bsc_ctr_description[BSC_##counter].name, \
				       bsc_ctr_description[BSC_##counter].description); \
	} while(0)

void assignment_reset(struct gsm_subscriber_connection *conn)
{
	if (conn->assignment.new_lchan) {
		struct gsm_lchan *lchan = conn->assignment.new_lchan;
		conn->assignment.new_lchan = NULL;
		lchan_release(lchan, false, true, RSL_ERR_EQUIPMENT_FAIL, NULL);
	}

	if (conn->assignment.created_ci_for_msc) {
		gscon_forget_mgw_endpoint_ci(conn, conn->assignment.created_ci_for_msc);
		/* If this is the last endpoint released, the mgw_endpoint_fsm will terminate and tell
		 * the gscon about it. */
		osmo_mgcpc_ep_ci_dlcx(conn->assignment.created_ci_for_msc);
	}

	conn->assignment = (struct assignment_fsm_data){
		.fi = conn->assignment.fi, /* The FSM shall clear itself when it's done. */
	};
}

static void on_assignment_failure(struct gsm_subscriber_connection *conn)
{
	/* Send Assignment Failure to MSC only when the assignment was requested via BSSAP. Do not send anything to the
	 * MSC if re-assignment was requested for congestion resolution, for VAMOS multiplexing, or by VTY. */
	if (conn->assignment.req.assign_for == ASSIGN_FOR_BSSMAP_REQ) {
		struct msgb *resp = gsm0808_create_assignment_failure(conn->assignment.failure_cause, NULL);

		if (!resp) {
			LOG_ASSIGNMENT(conn, LOGL_ERROR, "Unable to compose BSSMAP Assignment Failure message\n");
		} else {
			rate_ctr_inc(rate_ctr_group_get_ctr(conn->sccp.msc->msc_ctrs, MSC_CTR_BSSMAP_TX_DT1_ASSIGMENT_FAILURE));
			gscon_sigtran_send(conn, resp);
		}
	}

	/* If assignment failed as early as in assignment_fsm_start(), there may not be an fi yet. */
	if (conn->assignment.fi) {
		LOG_ASSIGNMENT(conn, LOGL_ERROR, "Assignment failed\n");
		osmo_fsm_inst_term(conn->assignment.fi, OSMO_FSM_TERM_ERROR, 0);
	}
}

static void _gsm0808_ass_compl_extend_osmux(struct msgb *msg, uint8_t cid)
{
	OSMO_ASSERT(msg->l3h[1] == msgb_l3len(msg) - 2); /*TL not in len */
	msgb_tv_put(msg, GSM0808_IE_OSMO_OSMUX_CID, cid);
	msg->l3h[1] = msgb_l3len(msg) - 2;
}

static void send_assignment_complete(struct gsm_subscriber_connection *conn)
{
	int rc;
	struct gsm0808_speech_codec sc;
	struct gsm0808_speech_codec *sc_ptr = NULL;
	struct sockaddr_storage addr_local;
	struct sockaddr_storage *addr_local_p = NULL;
	uint8_t osmux_cid = 0;
	int perm_spch = 0;
	uint8_t chosen_channel;
	struct msgb *resp;
	struct gsm_lchan *lchan = conn->lchan;
	struct osmo_fsm_inst *fi = conn->fi;

	chosen_channel = gsm0808_chosen_channel(lchan->type, lchan->current_ch_mode_rate.chan_mode);
	if (!chosen_channel) {
		assignment_fail(GSM0808_CAUSE_EQUIPMENT_FAILURE,
				"Unable to compose Chosen Channel for mode=%s type=%s",
				get_value_string(gsm48_chan_mode_names, lchan->current_ch_mode_rate.chan_mode),
				gsm_lchant_name(lchan->type));
		return;
	}

	/* Generate voice related fields */
	if (conn->assignment.requires_voice_stream) {
		perm_spch = gsm0808_permitted_speech(lchan->type, lchan->current_ch_mode_rate.chan_mode);

		if (gscon_is_aoip(conn)) {
			if (!osmo_mgcpc_ep_ci_get_crcx_info_to_sockaddr(conn->user_plane.mgw_endpoint_ci_msc,
									&addr_local)) {
				assignment_fail(GSM0808_CAUSE_EQUIPMENT_FAILURE,
						"Unable to compose RTP address of MGW -> MSC");
				return;
			}
			addr_local_p = &addr_local;
		}

		if (gscon_is_aoip(conn) && conn->assignment.req.use_osmux) {
			if (!osmo_mgcpc_ep_ci_get_crcx_info_to_osmux_cid(conn->user_plane.mgw_endpoint_ci_msc,
									 &osmux_cid)) {
				assignment_fail(GSM0808_CAUSE_EQUIPMENT_FAILURE,
						"Unable to compose Osmux CID of MGW -> MSC");
				return;
			}
		}

		/* Only AoIP networks include a speech codec (choosen) in the
		 * assignment complete message. */
		if (gscon_is_aoip(conn)) {
			/* Extrapolate speech codec from speech mode */
			gsm0808_speech_codec_from_chan_type(&sc, perm_spch);
			sc.cfg = conn->lchan->activate.info.ch_mode_rate.s15_s0;
			sc_ptr = &sc;
		}
	}

	resp = gsm0808_create_ass_compl2(lchan->abis_ip.ass_compl.rr_cause,
					 chosen_channel,
					 lchan->encr.alg_id, perm_spch,
					 addr_local_p, sc_ptr, NULL, lcls_get_status(conn));

	if (!resp) {
		assignment_fail(GSM0808_CAUSE_EQUIPMENT_FAILURE,
				"Unable to compose Assignment Complete message");
		return;
	}

	if (gscon_is_aoip(conn) && conn->assignment.requires_voice_stream &&
	    conn->assignment.req.use_osmux)
		_gsm0808_ass_compl_extend_osmux(resp, osmux_cid);

	rate_ctr_inc(rate_ctr_group_get_ctr(conn->sccp.msc->msc_ctrs, MSC_CTR_BSSMAP_TX_DT1_ASSIGMENT_COMPLETE));
	rc = gscon_sigtran_send(conn, resp);
	if (rc) {
		assignment_fail(GSM0808_CAUSE_EQUIPMENT_FAILURE,
				"Unable send Assignment Complete message: rc=%d %s",
				rc, strerror(-rc));
		return;
	}
}

static void assignment_success(struct gsm_subscriber_connection *conn)
{
	struct gsm_bts *bts;
	bool lchan_changed = (conn->assignment.new_lchan != NULL);

	/* Take on the new lchan. If there only was a Channel Mode Modify, then there is no new lchan to take on. */
	if (lchan_changed) {
		gscon_change_primary_lchan(conn, conn->assignment.new_lchan);

		OSMO_ASSERT((bts = conn_get_bts(conn)) != NULL);
		if (is_siemens_bts(bts) && ts_is_tch(conn->lchan->ts)) {
			/* HACK: store the actual Classmark 2 LV from the subscriber and use it here! */
			uint8_t cm2_lv[] = { 0x02, 0x00, 0x00 };
			send_siemens_mrpci(conn->lchan, cm2_lv);
		}

		/* apply LCLS configuration (if any) */
		lcls_apply_config(conn);
	}
	conn->assignment.new_lchan = NULL;

	if (conn->assignment.req.assign_for == ASSIGN_FOR_BSSMAP_REQ) {
		send_assignment_complete(conn);
		/* If something went wrong during send_assignment_complete(), the fi will be gone from
		 * error handling in there. Almost a success, but then again the whole thing failed. */
		if (!conn->assignment.fi) {
			/* The lchan was ready, and we failed to tell the MSC about it. By releasing this lchan,
			 * the conn will notice that its primary lchan is gone and should clean itself up. */
			lchan_release(conn->lchan, true, true, RSL_ERR_EQUIPMENT_FAIL,
				      gscon_last_eutran_plmn(conn));
			return;
		}
	}

	if (lchan_changed) {
		/* Rembered this only for error handling: should assignment fail, assignment_reset() will release
		 * the MGW endpoint right away. If successful, the conn continues to use the endpoint. */
		conn->assignment.created_ci_for_msc = NULL;

		/* New RTP information is now accepted */
		conn->user_plane.msc_assigned_cic = conn->assignment.req.msc_assigned_cic;
		osmo_strlcpy(conn->user_plane.msc_assigned_rtp_addr, conn->assignment.req.msc_rtp_addr,
			     sizeof(conn->user_plane.msc_assigned_rtp_addr));
		conn->user_plane.msc_assigned_rtp_port = conn->assignment.req.msc_rtp_port;
	}

	LOG_ASSIGNMENT(conn, LOGL_DEBUG, "Assignment successful\n");
	osmo_fsm_inst_term(conn->assignment.fi, OSMO_FSM_TERM_REGULAR, 0);

	assignment_count_result(CTR_ASSIGNMENT_COMPLETED);
}

static void assignment_fsm_update_id(struct gsm_subscriber_connection *conn)
{
	/* Assignment can do a new channel activation, in which case new_lchan points at the new lchan.
	 * Or assignment can Channel Mode Modify the already used lchan, in which case new_lchan == NULL. */
	struct gsm_lchan *new_lchan = (conn->assignment.new_lchan ? : conn->lchan);
	if (!new_lchan) {
		osmo_fsm_inst_update_id(conn->assignment.fi, conn->fi->id);
		return;
	}

	osmo_fsm_inst_update_id_f(conn->assignment.fi, "%s_%u-%u-%u-%s%s%s-%u",
				  conn->fi->id,
				  new_lchan->ts->trx->bts->nr, new_lchan->ts->trx->nr, new_lchan->ts->nr,
				  gsm_pchan_id(new_lchan->ts->pchan_on_init),
				  (new_lchan->ts->pchan_on_init == new_lchan->ts->pchan_is)? "" : "as",
				  (new_lchan->ts->pchan_on_init == new_lchan->ts->pchan_is)? ""
					  : gsm_pchan_id(new_lchan->ts->pchan_is),
				  new_lchan->nr);
}

static bool lchan_type_compat_with_mode(enum gsm_chan_t type, const struct channel_mode_and_rate *ch_mode_rate)
{
	enum gsm48_chan_mode chan_mode = ch_mode_rate->chan_mode;
	enum channel_rate chan_rate = ch_mode_rate->chan_rate;

	switch (gsm48_chan_mode_to_non_vamos(chan_mode)) {
	case GSM48_CMODE_SIGN:
		switch (type) {
		case GSM_LCHAN_TCH_F: return chan_rate == CH_RATE_FULL;
		case GSM_LCHAN_TCH_H: return chan_rate == CH_RATE_HALF;
		case GSM_LCHAN_SDCCH: return chan_rate == CH_RATE_SDCCH;
		default: return false;
		}

	case GSM48_CMODE_SPEECH_V1:
	case GSM48_CMODE_SPEECH_AMR:
	case GSM48_CMODE_DATA_3k6:
	case GSM48_CMODE_DATA_6k0:
		/* these services can all run on TCH/H, but we may have
		 * an explicit override by the 'chan_rate' argument */
		switch (type) {
		case GSM_LCHAN_TCH_F:
			return chan_rate == CH_RATE_FULL;
		case GSM_LCHAN_TCH_H:
			return chan_rate == CH_RATE_HALF;
		default:
			return false;
		}

	case GSM48_CMODE_DATA_12k0:
	case GSM48_CMODE_DATA_14k5:
	case GSM48_CMODE_SPEECH_EFR:
		/* these services all explicitly require a TCH/F */
		return type == GSM_LCHAN_TCH_F;

	default:
		return false;
	}
}

void assignment_fsm_init()
{
	OSMO_ASSERT(osmo_fsm_register(&assignment_fsm) == 0);
}

static int check_requires_voice(bool *requires_voice, enum gsm48_chan_mode chan_mode)
{
	*requires_voice = false;

	switch (gsm48_chan_mode_to_non_vamos(chan_mode)) {
	case GSM48_CMODE_SPEECH_V1:
	case GSM48_CMODE_SPEECH_EFR:
	case GSM48_CMODE_SPEECH_AMR:
		*requires_voice = true;
		break;
	case GSM48_CMODE_SIGN:
		*requires_voice = false;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

/* Check if the incoming assignment requests requires a voice stream or not,
 * we will look at the preferred and the alternate channel mode and also make
 * sure that both are consistent. */
static int check_requires_voice_stream(struct gsm_subscriber_connection *conn)
{
	bool requires_voice_pref = false, requires_voice_alt;
	struct assignment_request *req = &conn->assignment.req;
	struct osmo_fsm_inst *fi = conn->fi;
	int i, rc;

	/* When the assignment request indicates that there is an alternate
	 * rate available (e.g. "Full or Half rate channel, Half rate
	 * preferred..."), then both must be either voice or either signalling,
	 * a mismatch is not permitted */

	for (i = 0; i < req->n_ch_mode_rate; i++) {
		rc = check_requires_voice(&requires_voice_alt, req->ch_mode_rate_list[i].chan_mode);
		if (rc < 0) {
			assignment_fail(GSM0808_CAUSE_REQ_CODEC_TYPE_OR_CONFIG_NOT_SUPP,
					"Channel mode not supported (prev level %d): %s", i,
					gsm48_chan_mode_name(req->ch_mode_rate_list[i].chan_mode));
			return -EINVAL;
		}

		if (i==0)
			requires_voice_pref = requires_voice_alt;
		else if (requires_voice_alt != requires_voice_pref) {
			assignment_fail(GSM0808_CAUSE_REQ_CODEC_TYPE_OR_CONFIG_NOT_SUPP,
					"Requested a mix of Signalling and non-Signalling channel modes: %s != %s",
					gsm48_chan_mode_name(req->ch_mode_rate_list[0].chan_mode),
					gsm48_chan_mode_name(req->ch_mode_rate_list[i].chan_mode));
			return -EINVAL;
		}
	}

	conn->assignment.requires_voice_stream = requires_voice_pref;
	return 0;
}

/* Decide if we should re-use an existing lchan. For this we check if the
 * current lchan is compatible with one of the requested modes. */
static bool reuse_existing_lchan(struct gsm_subscriber_connection *conn)
{
	struct assignment_request *req = &conn->assignment.req;
	int i;

	if (!conn->lchan)
		return false;

	/* Check if the currently existing lchan is compatible with the
	 * preferred rate/codec. */
	for (i = 0; i < req->n_ch_mode_rate; i++) {
		if (!lchan_type_compat_with_mode(conn->lchan->type, &req->ch_mode_rate_list[i]))
			continue;
		conn->assignment.selected_ch_mode_rate = req->ch_mode_rate_list[i];
		return true;
	}

	return false;
}

static int _reassignment_request(enum assign_for assign_for, struct gsm_lchan *lchan, struct gsm_lchan *to_lchan,
				 enum gsm_chan_t new_lchan_type, int tsc_set, int tsc)
{
	struct gsm_subscriber_connection *conn = lchan->conn;
	struct assignment_request req = {
		.assign_for = assign_for,
		.aoip = gscon_is_aoip(conn),
		.msc_assigned_cic = conn->user_plane.msc_assigned_cic,
		.msc_rtp_port = conn->user_plane.msc_assigned_rtp_port,
		.n_ch_mode_rate = 1,
		.ch_mode_rate_list = { lchan->current_ch_mode_rate },
		.target_lchan = to_lchan,
		.tsc_set = tsc_set,
		.tsc = tsc,
	};

	if (to_lchan)
		new_lchan_type = to_lchan->type;
	req.ch_mode_rate_list[0].chan_rate = chan_t_to_chan_rate(new_lchan_type);
	/* lchan activation will automatically convert chan_mode to a VAMOS equivalent if required.
	 * So rather always pass the plain non-VAMOS mode. */
	req.ch_mode_rate_list[0].chan_mode = gsm48_chan_mode_to_non_vamos(lchan->current_ch_mode_rate.chan_mode);

	OSMO_STRLCPY_ARRAY(req.msc_rtp_addr, conn->user_plane.msc_assigned_rtp_addr);

	if (conn->user_plane.mgw_endpoint_ci_msc) {
		req.use_osmux = osmo_mgcpc_ep_ci_get_crcx_info_to_osmux_cid(conn->user_plane.mgw_endpoint_ci_msc,
									    &req.osmux_cid);
	}

	return osmo_fsm_inst_dispatch(conn->fi, GSCON_EV_ASSIGNMENT_START, &req);
}

int reassignment_request_to_lchan(enum assign_for assign_for, struct gsm_lchan *lchan, struct gsm_lchan *to_lchan,
				  int tsc_set, int tsc)
{
	return _reassignment_request(assign_for, lchan, to_lchan, 0, tsc_set, tsc);
}

int reassignment_request_to_chan_type(enum assign_for assign_for, struct gsm_lchan *lchan,
				      enum gsm_chan_t new_lchan_type)
{
	return _reassignment_request(assign_for, lchan, NULL, new_lchan_type, -1, -1);
}

void assignment_fsm_start(struct gsm_subscriber_connection *conn, struct gsm_bts *bts,
			  struct assignment_request *req)
{
	static const char *rate_names[] = {
		[CH_RATE_SDCCH] = "SDCCH",
		[CH_RATE_HALF] = "HR",
		[CH_RATE_FULL] = "FR",
	};
	struct osmo_fsm_inst *fi;
	int i;

	OSMO_ASSERT(conn);
	OSMO_ASSERT(conn->fi);
	OSMO_ASSERT(!conn->assignment.fi);
	OSMO_ASSERT(!conn->assignment.new_lchan);

	fi = osmo_fsm_inst_alloc_child(&assignment_fsm, conn->fi, GSCON_EV_ASSIGNMENT_END);
	OSMO_ASSERT(fi);
	conn->assignment.fi = fi;
	fi->priv = conn;

	/* Create a copy of the request data and use that copy from now on. */
	conn->assignment.req = *req;
	req = &conn->assignment.req;

	assignment_count(CTR_ASSIGNMENT_ATTEMPTED);

	/* Check if we need a voice stream. If yes, set the appropriate struct
	 * members in conn */
	if (check_requires_voice_stream(conn) < 0)
		return;

	if (!req->target_lchan && reuse_existing_lchan(conn)) {
		/* The already existing lchan is suitable for this mode */
		conn->assignment.new_lchan = NULL;

		/* If the requested mode and the current TCH mode matches up, just send the
		 * assignment complete directly and be done with the assignment procedure. */
		if (conn->lchan->current_ch_mode_rate.chan_mode == conn->assignment.selected_ch_mode_rate.chan_mode) {
			LOG_ASSIGNMENT(conn, LOGL_DEBUG,
				       "Current lchan mode is compatible with requested chan_mode,"
				       " sending BSSMAP Assignment Complete directly."
				       " requested chan_mode=%s; current lchan is %s\n",
				       gsm48_chan_mode_name(conn->assignment.selected_ch_mode_rate.chan_mode),
				       gsm_lchan_name(conn->lchan));

			if (req->assign_for == ASSIGN_FOR_BSSMAP_REQ)
				send_assignment_complete(conn);
			/* If something went wrong during send_assignment_complete(),
			 * the fi will be gone from error handling in there. */
			if (conn->assignment.fi) {
				assignment_count_result(CTR_ASSIGNMENT_COMPLETED);
				osmo_fsm_inst_term(conn->assignment.fi, OSMO_FSM_TERM_REGULAR, 0);
			}
			return;
		}

		/* The requested mode does not match the current TCH mode but the lchan is
		 * compatible. We will initiate a mode modify procedure. */
		LOG_ASSIGNMENT(conn, LOGL_DEBUG,
			       "Current lchan mode is not compatible with requested chan_mode,"
			       " so we will modify it. requested chan_mode=%s; current lchan is %s\n",
			       gsm48_chan_mode_name(conn->assignment.selected_ch_mode_rate.chan_mode),
			       gsm_lchan_name(conn->lchan));

		assignment_fsm_state_chg(ASSIGNMENT_ST_WAIT_LCHAN_MODIFIED);
		return;
	}

	if (req->target_lchan) {
		bool matching_mode;

		/* The caller already picked a target lchan to assign to. No need to try re-using the current lchan or
		 * picking a new one. */
		if (!lchan_state_is(req->target_lchan, LCHAN_ST_UNUSED)) {
			assignment_fail(GSM0808_CAUSE_NO_RADIO_RESOURCE_AVAILABLE,
					"Assignment to lchan %s requested, but lchan is already in use (state=%s)\n",
					gsm_lchan_name(req->target_lchan),
					osmo_fsm_inst_state_name(req->target_lchan->fi));
			return;
		}

		conn->assignment.new_lchan = req->target_lchan;
		matching_mode = false;
		for (i = 0; i < req->n_ch_mode_rate; i++) {
			if (!lchan_type_compat_with_mode(conn->assignment.new_lchan->type, &req->ch_mode_rate_list[i]))
				continue;
			conn->assignment.selected_ch_mode_rate = req->ch_mode_rate_list[i];
			matching_mode = true;
		}
		if (!matching_mode) {
			assignment_fail(GSM0808_CAUSE_NO_RADIO_RESOURCE_AVAILABLE,
					"Assignment to lchan %s requested, but lchan is not compatible\n",
					gsm_lchan_name(req->target_lchan));
			return;
		}
	} else {
		/* Try to allocate a new lchan in order of preference */
		for (i = 0; i < req->n_ch_mode_rate; i++) {
			conn->assignment.new_lchan = lchan_select_by_chan_mode(bts,
			    req->ch_mode_rate_list[i].chan_mode, req->ch_mode_rate_list[i].chan_rate);
			if (!conn->assignment.new_lchan)
				continue;
			LOG_ASSIGNMENT(conn, LOGL_DEBUG, "selected new lchan %s for mode[%d] = %s channel_rate=%d\n",
				       gsm_lchan_name(conn->assignment.new_lchan),
				       i, gsm48_chan_mode_name(req->ch_mode_rate_list[i].chan_mode),
				       req->ch_mode_rate_list[i].chan_rate);

			conn->assignment.selected_ch_mode_rate = req->ch_mode_rate_list[i];
			break;
		}
	}

	/* Check whether the lchan allocation was successful or not and tear
	 * down the assignment in case of failure. */
	if (!conn->assignment.new_lchan) {
		assignment_count_result(CTR_ASSIGNMENT_NO_CHANNEL);
		assignment_fail(GSM0808_CAUSE_NO_RADIO_RESOURCE_AVAILABLE,
				"BSSMAP Assignment Command:"
				" No lchan available for: pref=%s:%s / alt1=%s:%s / alt2=%s:%s\n",
				gsm48_chan_mode_name(req->ch_mode_rate_list[0].chan_mode),
				rate_names[req->ch_mode_rate_list[0].chan_rate],
				req->n_ch_mode_rate > 1 ? gsm48_chan_mode_name(req->ch_mode_rate_list[1].chan_mode) : "",
				req->n_ch_mode_rate > 1 ? rate_names[req->ch_mode_rate_list[1].chan_rate] : "",
				req->n_ch_mode_rate > 2 ? gsm48_chan_mode_name(req->ch_mode_rate_list[2].chan_mode) : "",
				req->n_ch_mode_rate > 2 ? rate_names[req->ch_mode_rate_list[2].chan_rate] : ""
		);
		return;
	}

	assignment_fsm_update_id(conn);
	LOG_ASSIGNMENT(conn, LOGL_INFO, "Starting Assignment: chan_mode=%s, chan_type=%s,"
		       " aoip=%s MSC-rtp=%s:%u (osmux=%s)\n",
		       gsm48_chan_mode_name(conn->assignment.selected_ch_mode_rate.chan_mode),
		       rate_names[conn->assignment.selected_ch_mode_rate.chan_rate],
		       req->aoip ? "yes" : "no", req->msc_rtp_addr, req->msc_rtp_port,
		       req->use_osmux ? "yes" : "no");

	assignment_fsm_state_chg(ASSIGNMENT_ST_WAIT_LCHAN_ACTIVE);
}

static void assignment_fsm_wait_lchan_active_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct gsm_subscriber_connection *conn = assignment_fi_conn(fi);
	struct assignment_request *req = &conn->assignment.req;
	struct lchan_activate_info activ_info = {
		.activ_for = ACTIVATE_FOR_ASSIGNMENT,
		.for_conn = conn,
		.ch_mode_rate = conn->assignment.selected_ch_mode_rate,
		.encr = conn->lchan->encr,
		.requires_voice_stream = conn->assignment.requires_voice_stream,
		.msc_assigned_cic = req->msc_assigned_cic,
		.re_use_mgw_endpoint_from_lchan = conn->lchan,
		.ta = conn->lchan->last_ta,
		.ta_known = true,
		.tsc_set = req->tsc_set,
		.tsc = req->tsc,
	};
	lchan_activate(conn->assignment.new_lchan, &activ_info);
}

static void assignment_fsm_wait_lchan_active(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_subscriber_connection *conn = assignment_fi_conn(fi);
	switch (event) {

	case ASSIGNMENT_EV_LCHAN_ACTIVE:
		if (data != conn->assignment.new_lchan) {
			LOG_ASSIGNMENT(conn, LOGL_ERROR, "Some unrelated lchan was activated, ignoring: %s\n",
				       gsm_lchan_name(data));
			return;
		}

		/* The TS may have changed its pchan_is */
		assignment_fsm_update_id(conn);

		assignment_fsm_state_chg(ASSIGNMENT_ST_WAIT_RR_ASS_COMPLETE);
		return;

	default:
		OSMO_ASSERT(false);
	}
}

static void assignment_fsm_wait_rr_ass_complete_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	int rc;
	struct gsm_subscriber_connection *conn = assignment_fi_conn(fi);

	rc = gsm48_send_rr_ass_cmd(conn->lchan, conn->assignment.new_lchan,
				   conn->lchan->ms_power);

	if (rc)
		assignment_fail(GSM0808_CAUSE_EQUIPMENT_FAILURE, "Unable to send RR Assignment Command");
}

static uint8_t get_cause(void *data)
{
	if (data)
		return *(uint8_t*)data;
	return GSM0808_CAUSE_EQUIPMENT_FAILURE;
}

static void assignment_fsm_wait_rr_ass_complete(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_subscriber_connection *conn = assignment_fi_conn(fi);
	switch (event) {

	case ASSIGNMENT_EV_RR_ASSIGNMENT_COMPLETE:
		assignment_fsm_state_chg(ASSIGNMENT_ST_WAIT_LCHAN_ESTABLISHED);
		return;

	case ASSIGNMENT_EV_LCHAN_ESTABLISHED:
		LOG_ASSIGNMENT(conn, LOGL_DEBUG, "lchan established, still waiting for RR Assignment Complete\n");
		/* The lchan is already done with all of its RTP setup. We will notice the lchan state
		 * being LCHAN_ST_ESTABLISHED in assignment_fsm_wait_lchan_established_onenter(). */
		return;

	case ASSIGNMENT_EV_RR_ASSIGNMENT_FAIL:
		assignment_count_result(CTR_ASSIGNMENT_FAILED);
		assignment_fail(get_cause(data), "Rx RR Assignment Failure");
		return;

	default:
		OSMO_ASSERT(false);
	}
}

static void assignment_fsm_post_lchan_established(struct osmo_fsm_inst *fi);

static void assignment_fsm_wait_lchan_established_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct gsm_subscriber_connection *conn = assignment_fi_conn(fi);
	/* Do we still need to wait for the RTP stream at all? */
	if (lchan_state_is(conn->assignment.new_lchan, LCHAN_ST_ESTABLISHED)) {
		LOG_ASSIGNMENT(conn, LOGL_DEBUG, "lchan fully established, no need to wait\n");
		assignment_fsm_post_lchan_established(fi);
	}
}

static void assignment_fsm_wait_lchan_established(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {

	case ASSIGNMENT_EV_LCHAN_ESTABLISHED:
		assignment_fsm_post_lchan_established(fi);
		return;

	default:
		OSMO_ASSERT(false);
	}
}

static void assignment_fsm_post_lchan_established(struct osmo_fsm_inst *fi)
{
	struct gsm_subscriber_connection *conn = assignment_fi_conn(fi);
	if (conn->assignment.requires_voice_stream)
		assignment_fsm_state_chg(ASSIGNMENT_ST_WAIT_MGW_ENDPOINT_TO_MSC);
	else
		assignment_success(conn);
}

static void assignment_fsm_wait_mgw_endpoint_to_msc_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct gsm_subscriber_connection *conn = assignment_fi_conn(fi);

	OSMO_ASSERT(conn->assignment.requires_voice_stream);

	LOG_ASSIGNMENT(conn, LOGL_DEBUG,
		       "Connecting MGW endpoint to the MSC's RTP port: %s:%u\n",
		       conn->assignment.req.msc_rtp_addr,
		       conn->assignment.req.msc_rtp_port);

	/* Assignment can do a new channel activation, in which case new_lchan points at the new lchan.
	 * Or assignment can Channel Mode Modify the already used lchan, in which case new_lchan == NULL. */
	if (!gscon_connect_mgw_to_msc(conn,
				      conn->assignment.new_lchan ? : conn->lchan,
				      conn->assignment.req.msc_rtp_addr,
				      conn->assignment.req.msc_rtp_port,
				      fi,
				      ASSIGNMENT_EV_MSC_MGW_OK,
				      ASSIGNMENT_EV_MSC_MGW_FAIL,
				      NULL,
				      &conn->assignment.created_ci_for_msc)) {
		assignment_fail(GSM0808_CAUSE_EQUIPMENT_FAILURE,
				"Unable to connect MGW endpoint to the MSC side");
		return;
	}
}

static void assignment_fsm_wait_mgw_endpoint_to_msc(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_subscriber_connection *conn = assignment_fi_conn(fi);
	switch (event) {

	case ASSIGNMENT_EV_MSC_MGW_OK:
		/* For AoIP, we created the MGW endpoint. Ensure it is really there, and log it. */
		if (gscon_is_aoip(conn)) {
			const struct mgcp_conn_peer *mgw_info;
			mgw_info = osmo_mgcpc_ep_ci_get_rtp_info(conn->user_plane.mgw_endpoint_ci_msc);
			if (!mgw_info) {
				assignment_fail(GSM0808_CAUSE_EQUIPMENT_FAILURE,
						"Unable to retrieve RTP port info allocated by MGW for"
						" the MSC side.");
				return;
			}
			LOG_ASSIGNMENT(conn, LOGL_DEBUG, "MGW's MSC side CI: %s:%u\n",
				       mgw_info->addr, mgw_info->port);
		}
		assignment_success(conn);
		return;

	case ASSIGNMENT_EV_MSC_MGW_FAIL:
		assignment_fail(GSM0808_CAUSE_EQUIPMENT_FAILURE,
				"Unable to connect MGW endpoint to the MSC side");
		return;

	default:
		OSMO_ASSERT(false);
	}
}

static void assignment_fsm_wait_lchan_modified_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct gsm_subscriber_connection *conn = assignment_fi_conn(fi);
	struct gsm_lchan *lchan = conn->lchan;
	struct assignment_request *req = &conn->assignment.req;
	struct lchan_modify_info modif_info = {
		.modify_for = MODIFY_FOR_ASSIGNMENT,
		.ch_mode_rate = conn->assignment.selected_ch_mode_rate,
		.requires_voice_stream = conn->assignment.requires_voice_stream,
		.msc_assigned_cic = req->msc_assigned_cic,
		/* keep previous training sequence code */
		.tsc_set = lchan->tsc_set,
		.tsc = lchan->tsc,
	};
	lchan_mode_modify(lchan, &modif_info);
}

static void assignment_fsm_wait_lchan_modified(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {

	case ASSIGNMENT_EV_LCHAN_MODIFIED:
		assignment_fsm_post_lchan_established(fi);
		return;

	default:
		OSMO_ASSERT(false);
	}
}

#define S(x)	(1 << (x))

static const struct osmo_fsm_state assignment_fsm_states[] = {
	[ASSIGNMENT_ST_WAIT_LCHAN_ACTIVE] = {
		.name = "WAIT_LCHAN_ACTIVE",
		.onenter = assignment_fsm_wait_lchan_active_onenter,
		.action = assignment_fsm_wait_lchan_active,
		.in_event_mask = 0
			| S(ASSIGNMENT_EV_LCHAN_ACTIVE)
			,
		.out_state_mask = 0
			| S(ASSIGNMENT_ST_WAIT_LCHAN_ACTIVE)
			| S(ASSIGNMENT_ST_WAIT_RR_ASS_COMPLETE)
			| S(ASSIGNMENT_ST_WAIT_LCHAN_MODIFIED)
			,
	},
	[ASSIGNMENT_ST_WAIT_RR_ASS_COMPLETE] = {
		.name = "WAIT_RR_ASS_COMPLETE",
		.onenter = assignment_fsm_wait_rr_ass_complete_onenter,
		.action = assignment_fsm_wait_rr_ass_complete,
		.in_event_mask = 0
			| S(ASSIGNMENT_EV_RR_ASSIGNMENT_COMPLETE)
			| S(ASSIGNMENT_EV_RR_ASSIGNMENT_FAIL)
			| S(ASSIGNMENT_EV_LCHAN_ESTABLISHED)
			,
		.out_state_mask = 0
			| S(ASSIGNMENT_ST_WAIT_LCHAN_ESTABLISHED)
			,
	},
	[ASSIGNMENT_ST_WAIT_LCHAN_ESTABLISHED] = {
		.name = "WAIT_LCHAN_ESTABLISHED",
		.onenter = assignment_fsm_wait_lchan_established_onenter,
		.action = assignment_fsm_wait_lchan_established,
		.in_event_mask = 0
			| S(ASSIGNMENT_EV_LCHAN_ESTABLISHED)
			,
		.out_state_mask = 0
			| S(ASSIGNMENT_ST_WAIT_MGW_ENDPOINT_TO_MSC)
			,
	},
	[ASSIGNMENT_ST_WAIT_MGW_ENDPOINT_TO_MSC] = {
		.name = "WAIT_MGW_ENDPOINT_TO_MSC",
		.onenter = assignment_fsm_wait_mgw_endpoint_to_msc_onenter,
		.action = assignment_fsm_wait_mgw_endpoint_to_msc,
		.in_event_mask = 0
			| S(ASSIGNMENT_EV_MSC_MGW_OK)
			| S(ASSIGNMENT_EV_MSC_MGW_FAIL)
			,
	},
	[ASSIGNMENT_ST_WAIT_LCHAN_MODIFIED] = {
		.name = "WAIT_LCHAN_MODIFIED",
		.onenter = assignment_fsm_wait_lchan_modified_onenter,
		.action = assignment_fsm_wait_lchan_modified,
		.in_event_mask = 0
			| S(ASSIGNMENT_EV_LCHAN_MODIFIED)
			,
		.out_state_mask = 0
			| S(ASSIGNMENT_ST_WAIT_MGW_ENDPOINT_TO_MSC)
			,
	},
};

static const struct value_string assignment_fsm_event_names[] = {
	OSMO_VALUE_STRING(ASSIGNMENT_EV_LCHAN_ACTIVE),
	OSMO_VALUE_STRING(ASSIGNMENT_EV_LCHAN_ESTABLISHED),
	OSMO_VALUE_STRING(ASSIGNMENT_EV_LCHAN_MODIFIED),
	OSMO_VALUE_STRING(ASSIGNMENT_EV_LCHAN_ERROR),
	OSMO_VALUE_STRING(ASSIGNMENT_EV_MSC_MGW_OK),
	OSMO_VALUE_STRING(ASSIGNMENT_EV_MSC_MGW_FAIL),
	OSMO_VALUE_STRING(ASSIGNMENT_EV_RR_ASSIGNMENT_COMPLETE),
	OSMO_VALUE_STRING(ASSIGNMENT_EV_RR_ASSIGNMENT_FAIL),
	OSMO_VALUE_STRING(ASSIGNMENT_EV_CONN_RELEASING),
	{}
};

void assignment_fsm_allstate_action(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_subscriber_connection *conn = assignment_fi_conn(fi);

	/* Assignment can do a new channel activation, in which case new_lchan points at the new lchan.
	 * Or assignment can Channel Mode Modify the already used lchan, in which case new_lchan == NULL. */
	struct gsm_lchan *new_lchan = conn->assignment.new_lchan ? : conn->lchan;

	switch (event) {

	case ASSIGNMENT_EV_CONN_RELEASING:
		assignment_count_result(CTR_ASSIGNMENT_STOPPED);
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REQUEST, 0);
		return;

	case ASSIGNMENT_EV_LCHAN_ERROR:
		if (data != new_lchan)
			return;
		assignment_fail(new_lchan->activate.gsm0808_error_cause,
				"Failed to %s lchan %s",
				conn->assignment.new_lchan ? "activate" : "modify",
				gsm_lchan_name(conn->assignment.new_lchan));
		return;

	default:
		return;
	}
}

int assignment_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	struct gsm_subscriber_connection *conn = assignment_fi_conn(fi);
	assignment_count_result(CTR_ASSIGNMENT_TIMEOUT);
	assignment_fail(GSM0808_CAUSE_EQUIPMENT_FAILURE, "Timeout");
	return 0;
}

void assignment_fsm_cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct gsm_subscriber_connection *conn = assignment_fi_conn(fi);
	assignment_reset(conn);
	conn->assignment.fi = NULL;
}

static struct osmo_fsm assignment_fsm = {
	.name = "assignment",
	.states = assignment_fsm_states,
	.num_states = ARRAY_SIZE(assignment_fsm_states),
	.log_subsys = DAS,
	.event_names = assignment_fsm_event_names,
	.allstate_action = assignment_fsm_allstate_action,
	.allstate_event_mask = 0
		| S(ASSIGNMENT_EV_CONN_RELEASING)
		| S(ASSIGNMENT_EV_LCHAN_ERROR)
		,
	.timer_cb = assignment_fsm_timer_cb,
	.cleanup = assignment_fsm_cleanup,
};
