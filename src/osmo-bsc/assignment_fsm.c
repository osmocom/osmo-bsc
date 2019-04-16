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
#include <osmocom/bsc/lchan_select.h>
#include <osmocom/bsc/abis_rsl.h>

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
		assignment_count_result(BSC_CTR_ASSIGNMENT_ERROR); \
		on_assignment_failure(_conn); \
	} while(0)

/* Assume presence of local var 'conn' as struct gsm_subscriber_connection */
#define assignment_count(counter) do { \
		LOG_ASSIGNMENT(conn, LOGL_DEBUG, "incrementing rate counter: %s %s\n", \
			       bsc_ctr_description[counter].name, \
			       bsc_ctr_description[counter].description); \
		rate_ctr_inc(&conn->network->bsc_ctrs->ctr[counter]); \
	} while(0)

#define assignment_count_result(counter) do { \
		if (!conn->assignment.result_rate_ctr_done) { \
			assignment_count(counter); \
			conn->assignment.result_rate_ctr_done = true; \
		} else \
			LOG_ASSIGNMENT(conn, LOGL_DEBUG, \
				       "result rate counter already recorded, NOT counting as: %s %s\n", \
				       bsc_ctr_description[counter].name, \
				       bsc_ctr_description[counter].description); \
	} while(0)

void assignment_reset(struct gsm_subscriber_connection *conn)
{
	if (conn->assignment.new_lchan) {
		struct gsm_lchan *lchan = conn->assignment.new_lchan;
		conn->assignment.new_lchan = NULL;
		lchan_release(lchan, false, true, RSL_ERR_EQUIPMENT_FAIL);
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
	struct msgb *resp = gsm0808_create_assignment_failure(conn->assignment.failure_cause, NULL);

	if (!resp)
		LOG_ASSIGNMENT(conn, LOGL_ERROR, "Unable to compose BSSMAP Assignment Failure message\n");
	else
		gscon_sigtran_send(conn, resp);

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

	chosen_channel = gsm0808_chosen_channel(lchan->type, lchan->tch_mode);
	if (!chosen_channel) {
		assignment_fail(GSM0808_CAUSE_EQUIPMENT_FAILURE,
				"Unable to compose Chosen Channel for mode=%s type=%s",
				get_value_string(gsm48_chan_mode_names, lchan->tch_mode),
				gsm_lchant_name(lchan->type));
		return;
	}

	/* Generate voice related fields */
	if (conn->assignment.requires_voice_stream) {
		perm_spch = gsm0808_permitted_speech(lchan->type, lchan->tch_mode);

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
			sc.cfg = conn->lchan->activate.info.s15_s0;
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
	/* Take on the new lchan */
	gscon_change_primary_lchan(conn, conn->assignment.new_lchan);
	conn->assignment.new_lchan = NULL;

	/* apply LCLS configuration (if any) */
	lcls_apply_config(conn);

	send_assignment_complete(conn);
	/* If something went wrong during send_assignment_complete(), the fi will be gone from
	 * error handling in there. Almost a success, but then again the whole thing failed. */
	if (!conn->assignment.fi) {
		/* The lchan was ready, and we failed to tell the MSC about it. By releasing this lchan,
		 * the conn will notice that its primary lchan is gone and should clean itself up. */
		lchan_release(conn->lchan, true, true, RSL_ERR_EQUIPMENT_FAIL);
		return;
	}

	/* Rembered this only for error handling: should assignment fail, assignment_reset() will release
	 * the MGW endpoint right away. If successful, the conn continues to use the endpoint. */
	conn->assignment.created_ci_for_msc = NULL;

	/* New RTP information is now accepted */
	conn->user_plane.msc_assigned_cic = conn->assignment.req.msc_assigned_cic;
	osmo_strlcpy(conn->user_plane.msc_assigned_rtp_addr, conn->assignment.req.msc_rtp_addr,
		     sizeof(conn->user_plane.msc_assigned_rtp_addr));
	conn->user_plane.msc_assigned_rtp_port = conn->assignment.req.msc_rtp_port;

	LOG_ASSIGNMENT(conn, LOGL_DEBUG, "Assignment successful\n");
	osmo_fsm_inst_term(conn->assignment.fi, OSMO_FSM_TERM_REGULAR, 0);

	assignment_count_result(BSC_CTR_ASSIGNMENT_COMPLETED);
}

static void assignment_fsm_update_id(struct gsm_subscriber_connection *conn)
{
	struct gsm_lchan *new_lchan = conn->assignment.new_lchan;
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

	switch (chan_mode) {
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

	switch (chan_mode) {
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
		rc = check_requires_voice(&requires_voice_alt, req->ch_mode_rate[i].chan_mode);
		if (rc < 0) {
			assignment_fail(GSM0808_CAUSE_REQ_CODEC_TYPE_OR_CONFIG_NOT_SUPP,
					"Channel mode not supported (prev level %d): %s", i,
					gsm48_chan_mode_name(req->ch_mode_rate[i].chan_mode));
			return -EINVAL;
		}

		if (i==0)
			requires_voice_pref = requires_voice_alt;
		else if (requires_voice_alt != requires_voice_pref) {
			assignment_fail(GSM0808_CAUSE_REQ_CODEC_TYPE_OR_CONFIG_NOT_SUPP,
					"Inconsistent channel modes: %s != %s",
					gsm48_chan_mode_name(req->ch_mode_rate[0].chan_mode),
					gsm48_chan_mode_name(req->ch_mode_rate[i].chan_mode));
			return -EINVAL;
		}
	}

	conn->assignment.requires_voice_stream = requires_voice_pref;
	return 0;
}

/* Check if the conn is already associated with an lchan. If yes, we will check
 * if that lchan is compatible with the preferred rate/codec. If the lchan
 * turns out to be incompatible we try with the alternate rate/codec. */
static bool reuse_existing_lchan(struct gsm_subscriber_connection *conn)
{
	struct assignment_request *req = &conn->assignment.req;
	int i;

	if (!conn->lchan)
		return false;

	/* Check if the currently existing lchan is compatible with the
	 * preferred rate/codec. */
	for (i = 0; i < req->n_ch_mode_rate; i++)
		if (lchan_type_compat_with_mode(conn->lchan->type, &req->ch_mode_rate[i])) {
			conn->lchan->ch_mode_rate = req->ch_mode_rate[i];
			break;
		}

	if (i == req->n_ch_mode_rate)
		return false;

	if (conn->lchan->tch_mode != conn->lchan->ch_mode_rate.chan_mode) {
		/* FIXME: send Channel Mode Modify to put the current lchan in the right mode, and kick
		 * off its RTP stream setup code path. See gsm48_lchan_modify() and
		 * gsm48_rx_rr_modif_ack(), and see lchan_fsm.h LCHAN_EV_CHAN_MODE_MODIF_* */
		LOG_ASSIGNMENT(conn, LOGL_DEBUG,
			       "Current lchan would be compatible, but Channel Mode Modify is not implemented\n");
		return false;
	}

	return true;
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
	struct lchan_activate_info info;
	int i;

	OSMO_ASSERT(conn);
	OSMO_ASSERT(conn->fi);
	OSMO_ASSERT(!conn->assignment.fi);
	OSMO_ASSERT(!conn->assignment.new_lchan);

	assignment_count(BSC_CTR_ASSIGNMENT_ATTEMPTED);

	fi = osmo_fsm_inst_alloc_child(&assignment_fsm, conn->fi, GSCON_EV_ASSIGNMENT_END);
	OSMO_ASSERT(fi);
	conn->assignment.fi = fi;
	fi->priv = conn;

	/* Create a copy of the request data and use that copy from now on. */
	conn->assignment.req = *req;
	req = &conn->assignment.req;

	/* Check if we need a voice stream. If yes, set the approriate struct
	 * members in conn */
	if (check_requires_voice_stream(conn) < 0)
		return;

	/* There may be an already existing lchan, if yes, try to work with
	 * the existing lchan */
	if (reuse_existing_lchan(conn)) {
		LOG_ASSIGNMENT(conn, LOGL_DEBUG,
			       "Current lchan is compatible with requested chan_mode,"
			       " sending BSSMAP Assignment Complete directly."
			       " requested chan_mode=%s; current lchan is %s\n",
			       gsm48_chan_mode_name(conn->lchan->ch_mode_rate.chan_mode),
			       gsm_lchan_name(conn->lchan));

		send_assignment_complete(conn);
		/* If something went wrong during send_assignment_complete(), the fi will be gone from
		 * error handling in there. */
		if (conn->assignment.fi) {
			assignment_count_result(BSC_CTR_ASSIGNMENT_COMPLETED);
			osmo_fsm_inst_term(conn->assignment.fi, OSMO_FSM_TERM_REGULAR, 0);
		}
		return;
	}

	/* Try to allocate a new lchan in order of preference */
	for (i = 0; i < req->n_ch_mode_rate; i++) {
		conn->assignment.new_lchan = lchan_select_by_chan_mode(bts,
		    req->ch_mode_rate[i].chan_mode, req->ch_mode_rate[i].chan_rate);
		conn->lchan->ch_mode_rate = req->ch_mode_rate[i];
		if (conn->assignment.new_lchan)
			break;
	}

	/* Check whether the lchan allocation was successful or not and tear
	 * down the assignment in case of failure. */
	if (!conn->assignment.new_lchan) {
		assignment_count_result(BSC_CTR_ASSIGNMENT_NO_CHANNEL);
		assignment_fail(GSM0808_CAUSE_NO_RADIO_RESOURCE_AVAILABLE,
				"BSSMAP Assignment Command:"
				" No lchan available for: pref=%s:%s / alt1=%s:%s / alt2=%s:%s\n",
				gsm48_chan_mode_name(req->ch_mode_rate[0].chan_mode),
				rate_names[req->ch_mode_rate[0].chan_rate],
				req->n_ch_mode_rate >= 1 ? gsm48_chan_mode_name(req->ch_mode_rate[0].chan_mode) : "",
				req->n_ch_mode_rate >= 1 ? rate_names[req->ch_mode_rate[0].chan_rate] : "",
				req->n_ch_mode_rate >= 2 ? gsm48_chan_mode_name(req->ch_mode_rate[0].chan_mode) : "",
				req->n_ch_mode_rate >= 2 ? rate_names[req->ch_mode_rate[0].chan_rate] : ""
		);
		return;
	}

	assignment_fsm_update_id(conn);
	LOG_ASSIGNMENT(conn, LOGL_INFO, "Starting Assignment: chan_mode=%s, chan_type=%s,"
		       " aoip=%s MSC-rtp=%s:%u (osmux=%s)\n",
		       gsm48_chan_mode_name(conn->lchan->ch_mode_rate.chan_mode),
		       rate_names[conn->lchan->ch_mode_rate.chan_rate],
		       req->aoip ? "yes" : "no", req->msc_rtp_addr, req->msc_rtp_port,
		       req->use_osmux ? "yes" : "no");

	assignment_fsm_state_chg(ASSIGNMENT_ST_WAIT_LCHAN_ACTIVE);
	info = (struct lchan_activate_info){
		.activ_for = FOR_ASSIGNMENT,
		.for_conn = conn,
		.chan_mode = conn->lchan->ch_mode_rate.chan_mode,
		.encr = conn->lchan->encr,
		.s15_s0 = conn->lchan->ch_mode_rate.s15_s0,
		.requires_voice_stream = conn->assignment.requires_voice_stream,
		.msc_assigned_cic = req->msc_assigned_cic,
		.re_use_mgw_endpoint_from_lchan = conn->lchan,
	};
	lchan_activate(conn->assignment.new_lchan, &info);
}

static void assignment_fsm_wait_lchan(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_subscriber_connection *conn = assignment_fi_conn(fi);
	switch (event) {

	case ASSIGNMENT_EV_LCHAN_ACTIVE:
		if (data != conn->assignment.new_lchan)
			return;

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
		assignment_count_result(BSC_CTR_ASSIGNMENT_FAILED);
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

	if (!gscon_connect_mgw_to_msc(conn,
				      conn->assignment.new_lchan,
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

#define S(x)	(1 << (x))

static const struct osmo_fsm_state assignment_fsm_states[] = {
	[ASSIGNMENT_ST_WAIT_LCHAN_ACTIVE] = {
		.name = "WAIT_LCHAN_ACTIVE",
		.action = assignment_fsm_wait_lchan,
		.in_event_mask = 0
			| S(ASSIGNMENT_EV_LCHAN_ACTIVE)
			,
		.out_state_mask = 0
			| S(ASSIGNMENT_ST_WAIT_LCHAN_ACTIVE)
			| S(ASSIGNMENT_ST_WAIT_RR_ASS_COMPLETE)
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
};

static const struct value_string assignment_fsm_event_names[] = {
	OSMO_VALUE_STRING(ASSIGNMENT_EV_LCHAN_ACTIVE),
	OSMO_VALUE_STRING(ASSIGNMENT_EV_LCHAN_ESTABLISHED),
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
	switch (event) {

	case ASSIGNMENT_EV_CONN_RELEASING:
		assignment_count_result(BSC_CTR_ASSIGNMENT_STOPPED);
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REQUEST, 0);
		return;

	case ASSIGNMENT_EV_LCHAN_ERROR:
		if (data != conn->assignment.new_lchan)
			return;
		assignment_fail(conn->assignment.new_lchan->activate.gsm0808_error_cause,
				"Failed to activate lchan %s",
				gsm_lchan_name(conn->assignment.new_lchan));
		return;

	default:
		return;
	}
}

int assignment_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	struct gsm_subscriber_connection *conn = assignment_fi_conn(fi);
	assignment_count_result(BSC_CTR_ASSIGNMENT_TIMEOUT);
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
