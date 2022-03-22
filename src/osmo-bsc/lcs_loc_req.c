/* Handle LCS BSSMAP-LE Perform Location Request */
/*
 * (C) 2020 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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


#include <osmocom/bsc/lcs_loc_req.h>

#include <osmocom/bsc/bsc_msc_data.h>
#include <osmocom/bsc/bsc_subscr_conn_fsm.h>
#include <osmocom/bsc/bsc_subscriber.h>
#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/lb.h>
#include <osmocom/core/fsm.h>
#include <osmocom/core/tdef.h>
#include <osmocom/core/utils.h>
#include <osmocom/gsm/gad.h>
#include <osmocom/gsm/bsslap.h>
#include <osmocom/gsm/bssmap_le.h>
#include <osmocom/gsm/gsm0808_lcs.h>
#include <osmocom/bsc/lcs_ta_req.h>
#include <osmocom/bsc/paging.h>
#include <osmocom/bsc/bts_trx.h>
#include <osmocom/bsc/bts.h>

enum lcs_loc_req_fsm_state {
	LCS_LOC_REQ_ST_INIT,
	LCS_LOC_REQ_ST_WAIT_LOCATION_RESPONSE,
	LCS_LOC_REQ_ST_BSSLAP_TA_REQ_ONGOING,
	LCS_LOC_REQ_ST_GOT_LOCATION_RESPONSE,
	LCS_LOC_REQ_ST_FAILED,
};

static const struct value_string lcs_loc_req_fsm_event_names[] = {
	OSMO_VALUE_STRING(LCS_LOC_REQ_EV_RX_LB_PERFORM_LOCATION_RESPONSE),
	OSMO_VALUE_STRING(LCS_LOC_REQ_EV_RX_A_PERFORM_LOCATION_ABORT),
	OSMO_VALUE_STRING(LCS_LOC_REQ_EV_TA_REQ_START),
	OSMO_VALUE_STRING(LCS_LOC_REQ_EV_TA_REQ_END),
	OSMO_VALUE_STRING(LCS_LOC_REQ_EV_HANDOVER_PERFORMED),
	OSMO_VALUE_STRING(LCS_LOC_REQ_EV_CONN_CLEAR),
	{}
};

static struct osmo_fsm lcs_loc_req_fsm;

static const struct osmo_tdef_state_timeout lcs_loc_req_fsm_timeouts[32] = {
	[LCS_LOC_REQ_ST_WAIT_LOCATION_RESPONSE] = { .T = -11 },
};

/* Transition to a state, using the T timer defined in lcs_loc_req_fsm_timeouts.
 * The actual timeout value is in turn obtained from network->T_defs.
 * Assumes local variable fi exists. */
#define lcs_loc_req_fsm_state_chg(FI, STATE) \
	osmo_tdef_fsm_inst_state_chg(FI, STATE, \
				     lcs_loc_req_fsm_timeouts, \
				     (bsc_gsmnet)->T_defs, \
				     5)

#define lcs_loc_req_fail(cause, fmt, args...) do { \
		LOG_LCS_LOC_REQ(lcs_loc_req, LOGL_ERROR, "Perform Location Request failed in state %s: " fmt "\n", \
				lcs_loc_req ? osmo_fsm_inst_state_name(lcs_loc_req->fi) : "NULL", ## args); \
		lcs_loc_req->lcs_cause = (struct lcs_cause_ie){ \
			.present = true, \
			.cause_val = cause, \
		}; \
		lcs_loc_req_fsm_state_chg(lcs_loc_req->fi, LCS_LOC_REQ_ST_FAILED); \
	} while (0)

static struct lcs_loc_req *lcs_loc_req_alloc(struct osmo_fsm_inst *parent_fi, uint32_t parent_event_term)
{
	struct lcs_loc_req *lcs_loc_req;

	struct osmo_fsm_inst *fi = osmo_fsm_inst_alloc_child(&lcs_loc_req_fsm, parent_fi, parent_event_term);
	OSMO_ASSERT(fi);

	lcs_loc_req = talloc(fi, struct lcs_loc_req);
	OSMO_ASSERT(lcs_loc_req);
	fi->priv = lcs_loc_req;
	*lcs_loc_req = (struct lcs_loc_req){
		.fi = fi,
	};

	return lcs_loc_req;
}

static bool parse_bssmap_perf_loc_req(struct lcs_loc_req *lcs_loc_req, struct msgb *msg)
{
	struct tlv_parsed tp_arr[1];
	struct tlv_parsed *tp = &tp_arr[0];
	const struct tlv_p_entry *e;
	int payload_length;

#define PARSE_ERR(ERRMSG) do { \
			lcs_loc_req_fail(LCS_CAUSE_PROTOCOL_ERROR, "rx BSSMAP Perform Location Request: " ERRMSG); \
			return false; \
		} while (0)

	payload_length = msg->tail - msg->l4h;
	if (tlv_parse2(tp_arr, 1, gsm0808_att_tlvdef(), msg->l4h + 1, payload_length - 1, 0, 0) <= 0)
		PARSE_ERR("Failed to parse IEs");

	if (!(e = TLVP_GET(tp, GSM0808_IE_LOCATION_TYPE)))
		PARSE_ERR("Missing Location Type IE");
	if (osmo_bssmap_le_ie_dec_location_type(&lcs_loc_req->req.location_type, -1, -1, NULL, NULL, e->val, e->len))
		PARSE_ERR("Failed to parse Location Type IE");

	if ((e = TLVP_GET(tp, GSM0808_IE_CELL_IDENTIFIER))) {
		if (gsm0808_dec_cell_id(&lcs_loc_req->req.cell_id, e->val, e->len) <= 0)
			PARSE_ERR("Failed to parse Cell Identifier IE");
		lcs_loc_req->req.cell_id_present = true;
	}

	if ((e = TLVP_GET(tp, GSM0808_IE_IMSI))) {
		if (osmo_mobile_identity_decode(&lcs_loc_req->req.imsi, e->val, e->len, false)
		    || lcs_loc_req->req.imsi.type != GSM_MI_TYPE_IMSI)
			PARSE_ERR("Failed to parse IMSI IE");
	}

	if ((e = TLVP_GET(tp, GSM0808_IE_IMEI))) {
		if (osmo_mobile_identity_decode(&lcs_loc_req->req.imei, e->val, e->len, false)
		    || lcs_loc_req->req.imei.type != GSM_MI_TYPE_IMEI)
			PARSE_ERR("Failed to parse IMEI IE");
	}

	// FIXME LCS QoS IE is mandatory for requesting the location

	/* A lot of IEs remain ignored... */

	return true;
#undef PARSE_ERR
}

void lcs_loc_req_start(struct gsm_subscriber_connection *conn, struct msgb *loc_req_msg)
{
	struct lcs_loc_req *lcs_loc_req;

	if (conn->lcs.loc_req) {
		LOG_LCS_LOC_REQ(conn, LOGL_ERROR,
				"Ignoring Perform Location Request, another request is still pending\n");
		return;
	}

	lcs_loc_req = lcs_loc_req_alloc(conn->fi, GSCON_EV_LCS_LOC_REQ_END);

	lcs_loc_req->conn = conn;
	conn->lcs.loc_req = lcs_loc_req;

	if (!parse_bssmap_perf_loc_req(lcs_loc_req, loc_req_msg))
		return;

	if (!conn->bsub) {
		if (lcs_loc_req->req.imsi.type != GSM_MI_TYPE_IMSI) {
			lcs_loc_req_fail(LCS_CAUSE_DATA_MISSING_IN_REQ,
					 "tx Perform Location Request: Missing identity:"
					 " No IMSI included in request, and also no active subscriber");
			return;
		}

		conn->bsub = bsc_subscr_find_or_create_by_mi(bsc_gsmnet->bsc_subscribers, &lcs_loc_req->req.imsi,
							     BSUB_USE_CONN);
		if (!conn->bsub) {
			lcs_loc_req_fail(LCS_CAUSE_SYSTEM_FAILURE,
					 "tx Perform Location Request: Cannot assign subscriber");
			return;
		}
	}

	/* state change to start the timeout */
	lcs_loc_req_fsm_state_chg(lcs_loc_req->fi, LCS_LOC_REQ_ST_WAIT_LOCATION_RESPONSE);
}

static int handle_bssmap_le_conn_oriented_info(struct lcs_loc_req *lcs_loc_req, const struct bssmap_le_pdu *bssmap_le)
{
	switch (bssmap_le->conn_oriented_info.apdu.msg_type) {
	case BSSLAP_MSGT_TA_REQUEST:
		rate_ctr_inc(rate_ctr_group_get_ctr(bsc_gsmnet->smlc->ctrs, SMLC_CTR_BSSMAP_LE_RX_DT1_BSSLAP_TA_REQUEST));
		LOG_LCS_LOC_REQ(lcs_loc_req, LOGL_DEBUG, "rx BSSLAP TA Request\n");
		/* The TA Request message contains only the message type. */
		return lcs_ta_req_start(lcs_loc_req);
	default:
		LOG_LCS_LOC_REQ(lcs_loc_req, LOGL_ERROR, "rx BSSLAP APDU with unsupported message type %d\n",
				bssmap_le->conn_oriented_info.apdu.msg_type);
		return -ENOTSUP;
	};
}

int lcs_loc_req_rx_bssmap_le(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	struct lcs_loc_req *lcs_loc_req = conn->lcs.loc_req;
	struct bssap_le_pdu bssap_le;
	struct osmo_bssap_le_err *err;
	struct rate_ctr_group *ctrg = bsc_gsmnet->smlc->ctrs;

	if (!lcs_loc_req) {
		LOGPFSMSL(conn->fi, DLCS, LOGL_ERROR,
			  "Rx BSSMAP-LE message, but no Location Request is ongoing\n");
		return -EINVAL;
	}

	if (osmo_bssap_le_dec(&bssap_le, &err, msg, msg)) {
		LOG_LCS_LOC_REQ(lcs_loc_req, LOGL_ERROR, "Rx BSSAP-LE message with error: %s\n", err->logmsg);
		rate_ctr_inc(rate_ctr_group_get_ctr(ctrg, SMLC_CTR_BSSMAP_LE_RX_DT1_ERR_INVALID_MSG));
		return -EINVAL;
	}

	if (bssap_le.discr != BSSAP_LE_MSG_DISCR_BSSMAP_LE) {
		LOG_LCS_LOC_REQ(lcs_loc_req, LOGL_ERROR, "Rx BSSAP-LE: discr %d not implemented\n", bssap_le.discr);
		rate_ctr_inc(rate_ctr_group_get_ctr(ctrg, SMLC_CTR_BSSMAP_LE_RX_DT1_ERR_INVALID_MSG));
		return -ENOTSUP;
	}

	LOG_LCS_LOC_REQ(lcs_loc_req, LOGL_DEBUG, "Rx %s\n", osmo_bssap_le_pdu_to_str_c(OTC_SELECT, &bssap_le));

	switch (bssap_le.bssmap_le.msg_type) {
	case BSSMAP_LE_MSGT_PERFORM_LOC_RESP:
		if (bssap_le.bssmap_le.perform_loc_resp.location_estimate_present)
			rate_ctr_inc(rate_ctr_group_get_ctr(ctrg, SMLC_CTR_BSSMAP_LE_RX_DT1_PERFORM_LOCATION_RESPONSE_SUCCESS));
		else
			rate_ctr_inc(rate_ctr_group_get_ctr(ctrg, SMLC_CTR_BSSMAP_LE_RX_DT1_PERFORM_LOCATION_RESPONSE_FAILURE));
		return osmo_fsm_inst_dispatch(lcs_loc_req->fi, LCS_LOC_REQ_EV_RX_LB_PERFORM_LOCATION_RESPONSE,
					      &bssap_le.bssmap_le);

	case BSSMAP_LE_MSGT_CONN_ORIENTED_INFO:
		return handle_bssmap_le_conn_oriented_info(lcs_loc_req, &bssap_le.bssmap_le);

	default:
		LOG_LCS_LOC_REQ(lcs_loc_req, LOGL_ERROR, "Rx BSSMAP-LE from SMLC with unsupported message type: %s\n",
				osmo_bssap_le_pdu_to_str_c(OTC_SELECT, &bssap_le));
		return -ENOTSUP;
	}
}

void lcs_loc_req_reset(struct gsm_subscriber_connection *conn)
{
	struct lcs_loc_req *lcs_loc_req = conn->lcs.loc_req;
	if (!lcs_loc_req)
		return;
	lcs_loc_req_fail(LCS_CAUSE_SYSTEM_FAILURE, "Aborting Location Request due to RESET on Lb");
}

static int lcs_loc_req_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	struct lcs_loc_req *lcs_loc_req = fi->priv;
	lcs_loc_req_fail(LCS_CAUSE_SYSTEM_FAILURE, "Timeout");
	return 1;
}

static int lcs_loc_req_send(struct lcs_loc_req *lcs_loc_req, const struct bssap_le_pdu *bssap_le)
{
	int rc = lb_send(lcs_loc_req->conn, bssap_le);
	if (rc)
		lcs_loc_req_fail(LCS_CAUSE_SYSTEM_FAILURE,
				 "Failed to send %s", osmo_bssap_le_pdu_to_str_c(OTC_SELECT, bssap_le));
	return rc;
}

static void lcs_loc_req_wait_loc_resp_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct lcs_loc_req *lcs_loc_req = fi->priv;
	struct bssap_le_pdu plr;
	struct gsm_lchan *lchan;

	if (prev_state == LCS_LOC_REQ_ST_BSSLAP_TA_REQ_ONGOING) {
		/* LCS_LOC_REQ_ST_BSSLAP_TA_REQ_ONGOING should halt the FSM timeout. As soon as the TA Request is
		 * served, re-entering LCS_LOC_REQ_ST_WAIT_LOCATION_RESPONSE, but of course there is then no need to
		 * send a second BSSMAP-LE Perform Location Request to the SMLC. */
		return;
	}

	if (!lcs_loc_req->req.cell_id_present) {
		lcs_loc_req_fail(LCS_CAUSE_PROTOCOL_ERROR,
				 "Cannot encode BSSMAP-LE Perform Location Request,"
				 " because mandatory Cell Identity is not known");
		return;
	}

	plr = (struct bssap_le_pdu){
		.discr = BSSAP_LE_MSG_DISCR_BSSMAP_LE,
		.bssmap_le = {
			.msg_type = BSSMAP_LE_MSGT_PERFORM_LOC_REQ,
			.perform_loc_req = {
				.location_type = lcs_loc_req->req.location_type,
				.cell_id = lcs_loc_req->req.cell_id,
				.imsi = lcs_loc_req->req.imsi,
				.imei = lcs_loc_req->req.imei,
			},
		},
	};

	/* If we already have an active lchan, send the known TA directly to the SMLC */
	lchan = lcs_loc_req->conn->lchan;
	if (lchan) {
		LOG_LCS_LOC_REQ(lcs_loc_req, LOGL_DEBUG,
				"Active lchan present, including BSSLAP APDU with TA Layer 3\n");
		plr.bssmap_le.perform_loc_req.apdu_present = true;
		plr.bssmap_le.perform_loc_req.apdu = (struct bsslap_pdu){
			.msg_type = BSSLAP_MSGT_TA_LAYER3,
			.ta_layer3 = {
				.ta = lchan->last_ta,
			},
		};
	} else {
		LOG_LCS_LOC_REQ(lcs_loc_req, LOGL_DEBUG,
				"No active lchan, not including BSSLAP APDU\n");
	}

	/* Establish Lb connection to SMLC and send the BSSMAP-LE Perform Location Request */
	lcs_loc_req_send(lcs_loc_req, &plr);
}

static void lcs_loc_req_bssmap_le_abort(struct lcs_loc_req *lcs_loc_req)
{
	struct bssap_le_pdu pla = {
		.discr = BSSAP_LE_MSG_DISCR_BSSMAP_LE,
		.bssmap_le = {
			.msg_type = BSSMAP_LE_MSGT_PERFORM_LOC_ABORT,
			.perform_loc_abort = {
				.present = true,
				.cause_val = LCS_CAUSE_REQUEST_ABORTED,
			},
		},
	};

	lcs_loc_req_send(lcs_loc_req, &pla);
}

/* After a handover, send the new lchan information to the SMLC via a BSSLAP Reset message.
 * See 3GPP TS 48.071 4.2.6 Reset. */
static void lcs_loc_req_handover_performed(struct lcs_loc_req *lcs_loc_req)
{
	struct gsm_lchan *lchan = lcs_loc_req->conn->lchan;
	struct bssap_le_pdu bsslap = {
		.discr = BSSAP_LE_MSG_DISCR_BSSMAP_LE,
		.bssmap_le = {
			.msg_type = BSSMAP_LE_MSGT_CONN_ORIENTED_INFO,
		},
	};
	struct bsslap_pdu *apdu = &bsslap.bssmap_le.conn_oriented_info.apdu;

	if (!lchan) {
		/* The handover was out of this BSS. Abort the location procedure. */
		*apdu = (struct bsslap_pdu){
			.msg_type = BSSLAP_MSGT_ABORT,
			.abort = BSSLAP_CAUSE_INTER_BSS_HO,
		};
	} else {
		*apdu = (struct bsslap_pdu){
			.msg_type = BSSLAP_MSGT_RESET,
			.reset = {
				.cell_id = lchan->ts->trx->bts->cell_identity,
				.ta = lchan->last_ta,
				.cause = BSSLAP_CAUSE_INTRA_BSS_HO,
			},
		};
		if (gsm48_lchan2chan_desc(&apdu->reset.chan_desc, lchan, lchan->tsc, false)) {
			lcs_loc_req_fail(LCS_CAUSE_SYSTEM_FAILURE, "Error encoding Channel Number");
			return;
		}
	}

	lcs_loc_req_send(lcs_loc_req, &bsslap);
}

static void lcs_loc_req_wait_loc_resp_and_ta_req_ongoing_action(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct lcs_loc_req *lcs_loc_req = fi->priv;
	const struct bssmap_le_pdu *bssmap_le;

	switch (event) {

	case LCS_LOC_REQ_EV_RX_LB_PERFORM_LOCATION_RESPONSE:
		bssmap_le = data;
		OSMO_ASSERT(bssmap_le->msg_type == BSSMAP_LE_MSGT_PERFORM_LOC_RESP);
		lcs_loc_req->resp = bssmap_le->perform_loc_resp;
		lcs_loc_req->resp_present = true;
		lcs_loc_req_fsm_state_chg(fi, LCS_LOC_REQ_ST_GOT_LOCATION_RESPONSE);
		break;

	case LCS_LOC_REQ_EV_TA_REQ_START:
		if (fi->state != LCS_LOC_REQ_ST_BSSLAP_TA_REQ_ONGOING)
			lcs_loc_req_fsm_state_chg(fi, LCS_LOC_REQ_ST_BSSLAP_TA_REQ_ONGOING);
		break;

	case LCS_LOC_REQ_EV_TA_REQ_END:
		if (fi->state != LCS_LOC_REQ_ST_WAIT_LOCATION_RESPONSE)
			lcs_loc_req_fsm_state_chg(fi, LCS_LOC_REQ_ST_WAIT_LOCATION_RESPONSE);
		break;

	case LCS_LOC_REQ_EV_HANDOVER_PERFORMED:
		lcs_loc_req_handover_performed(lcs_loc_req);
		break;

	case LCS_LOC_REQ_EV_RX_A_PERFORM_LOCATION_ABORT:
	case LCS_LOC_REQ_EV_CONN_CLEAR:
		if (lcs_loc_req->ta_req)
			osmo_fsm_inst_dispatch(lcs_loc_req->ta_req->fi, LCS_TA_REQ_EV_ABORT, NULL);
		lcs_loc_req_bssmap_le_abort(lcs_loc_req);
		osmo_fsm_inst_term(lcs_loc_req->fi, OSMO_FSM_TERM_REGULAR, NULL);
		break;

	default:
		OSMO_ASSERT(false);
	}
}

static void lcs_loc_req_got_loc_resp_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct lcs_loc_req *lcs_loc_req = fi->priv;
	struct msgb *msg;
	int rc;
	struct gsm0808_perform_location_response plr = {
		.location_estimate_present = lcs_loc_req->resp.location_estimate_present,
		.location_estimate = lcs_loc_req->resp.location_estimate,
		.lcs_cause = lcs_loc_req->resp.lcs_cause,
	};

	if (plr.location_estimate_present) {
		struct osmo_gad gad;
		struct osmo_gad_err *err;
		if (osmo_gad_dec(&gad, &err, OTC_SELECT, &plr.location_estimate))
			LOG_LCS_LOC_REQ(lcs_loc_req, LOGL_ERROR,
					"Perform Location Response contains Location Estimate with error: %s\n",
					err->logmsg);
		else
			LOG_LCS_LOC_REQ(lcs_loc_req, LOGL_INFO,
					"Perform Location Response contains Location Estimate: %s\n",
					osmo_gad_to_str_c(OTC_SELECT, &gad));
	}

	if (plr.lcs_cause.present) {
		LOG_LCS_LOC_REQ(lcs_loc_req, LOGL_ERROR,
				"Perform Location Response contains error cause: %d\n",
				plr.lcs_cause.cause_val);
	}

	msg = gsm0808_create_perform_location_response(&plr);
	if (!msg) {
		LOG_LCS_LOC_REQ(lcs_loc_req, LOGL_ERROR,
				"Failed to encode BSSMAP Perform Location Response (A-interface)\n");
	} else {
		rc = gscon_sigtran_send(lcs_loc_req->conn, msg);
		if (rc < 0)
			LOG_LCS_LOC_REQ(lcs_loc_req, LOGL_ERROR,
					"Failed to send Perform Location Response (A-interface)\n");
		else
			rate_ctr_inc(rate_ctr_group_get_ctr(lcs_loc_req->conn->sccp.msc->msc_ctrs, plr.location_estimate_present ? MSC_CTR_BSSMAP_TX_DT1_PERFORM_LOCATION_RESPONSE_SUCCESS : MSC_CTR_BSSMAP_TX_DT1_PERFORM_LOCATION_RESPONSE_FAILURE));
	}
	osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, NULL);
}

static void lcs_loc_req_failed_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct lcs_loc_req *lcs_loc_req = fi->priv;
	struct msgb *msg;
	int rc;
	struct bssap_le_pdu pla = {
		.discr = BSSAP_LE_MSG_DISCR_BSSMAP_LE,
		.bssmap_le = {
			.msg_type = BSSMAP_LE_MSGT_PERFORM_LOC_ABORT,
			.perform_loc_abort = lcs_loc_req->lcs_cause,
		},
	};
	struct gsm0808_perform_location_response plr = {
		.lcs_cause = lcs_loc_req->lcs_cause,
	};

	/* If we're paging this subscriber for LCS, stop paging. */
	paging_request_cancel(lcs_loc_req->conn->bsub, BSC_PAGING_FOR_LCS);

	/* Send Perform Location Abort to SMLC, only if we got started on the Lb */
	if (lcs_loc_req->conn->lcs.lb.state == SUBSCR_SCCP_ST_CONNECTED)
		lcs_loc_req_send(lcs_loc_req, &pla);

	/* Send Perform Location Result with failure cause to MSC */
	msg = gsm0808_create_perform_location_response(&plr);
	if (!msg) {
		LOG_LCS_LOC_REQ(lcs_loc_req, LOGL_ERROR,
				"Failed to encode BSSMAP Perform Location Response (A-interface)\n");
	} else {
		rc = gscon_sigtran_send(lcs_loc_req->conn, msg);
		if (rc < 0)
			LOG_LCS_LOC_REQ(lcs_loc_req, LOGL_ERROR,
					"Failed to send BSSMAP Perform Location Response (A-interface)\n");
		else
			rate_ctr_inc(rate_ctr_group_get_ctr(lcs_loc_req->conn->sccp.msc->msc_ctrs, MSC_CTR_BSSMAP_TX_DT1_PERFORM_LOCATION_RESPONSE_FAILURE));
	}
	osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, NULL);
}

void lcs_loc_req_fsm_cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct lcs_loc_req *lcs_loc_req = fi->priv;
	if (lcs_loc_req->conn && lcs_loc_req->conn->lcs.loc_req == lcs_loc_req)
		lcs_loc_req->conn->lcs.loc_req = NULL;
	/* FSM termination will dispatch GSCON_EV_LCS_LOC_REQ_END to the conn FSM */
}

#define S(x)    (1 << (x))

static const struct osmo_fsm_state lcs_loc_req_fsm_states[] = {
	[LCS_LOC_REQ_ST_INIT] = {
		.name = "INIT",
		.out_state_mask = 0
			| S(LCS_LOC_REQ_ST_WAIT_LOCATION_RESPONSE)
			| S(LCS_LOC_REQ_ST_FAILED)
			,
	},
	[LCS_LOC_REQ_ST_WAIT_LOCATION_RESPONSE] = {
		.name = "WAIT_LOCATION_RESPONSE",
		.in_event_mask = 0
			| S(LCS_LOC_REQ_EV_RX_LB_PERFORM_LOCATION_RESPONSE)
			| S(LCS_LOC_REQ_EV_RX_A_PERFORM_LOCATION_ABORT)
			| S(LCS_LOC_REQ_EV_TA_REQ_START)
			| S(LCS_LOC_REQ_EV_TA_REQ_END)
			| S(LCS_LOC_REQ_EV_HANDOVER_PERFORMED)
			| S(LCS_LOC_REQ_EV_CONN_CLEAR)
			,
		.out_state_mask = 0
			| S(LCS_LOC_REQ_ST_BSSLAP_TA_REQ_ONGOING)
			| S(LCS_LOC_REQ_ST_GOT_LOCATION_RESPONSE)
			| S(LCS_LOC_REQ_ST_FAILED)
			,
		.onenter = lcs_loc_req_wait_loc_resp_onenter,
		.action = lcs_loc_req_wait_loc_resp_and_ta_req_ongoing_action,
	},
	[LCS_LOC_REQ_ST_BSSLAP_TA_REQ_ONGOING] = {
		.name = "BSSLAP_TA_REQ_ONGOING",
		.in_event_mask = 0
			| S(LCS_LOC_REQ_EV_RX_LB_PERFORM_LOCATION_RESPONSE)
			| S(LCS_LOC_REQ_EV_RX_A_PERFORM_LOCATION_ABORT)
			| S(LCS_LOC_REQ_EV_TA_REQ_END)
			| S(LCS_LOC_REQ_EV_HANDOVER_PERFORMED)
			| S(LCS_LOC_REQ_EV_CONN_CLEAR)
			,
		.out_state_mask = 0
			| S(LCS_LOC_REQ_ST_WAIT_LOCATION_RESPONSE)
			| S(LCS_LOC_REQ_ST_GOT_LOCATION_RESPONSE)
			| S(LCS_LOC_REQ_ST_FAILED)
			,
		.action = lcs_loc_req_wait_loc_resp_and_ta_req_ongoing_action,
	},
	[LCS_LOC_REQ_ST_GOT_LOCATION_RESPONSE] = {
		.name = "GOT_LOCATION_RESPONSE",
		.onenter = lcs_loc_req_got_loc_resp_onenter,
	},
	[LCS_LOC_REQ_ST_FAILED] = {
		.name = "FAILED",
		.onenter = lcs_loc_req_failed_onenter,
	},
};

static struct osmo_fsm lcs_loc_req_fsm = {
	.name = "lcs_loc_req",
	.states = lcs_loc_req_fsm_states,
	.num_states = ARRAY_SIZE(lcs_loc_req_fsm_states),
	.log_subsys = DLCS,
	.event_names = lcs_loc_req_fsm_event_names,
	.timer_cb = lcs_loc_req_fsm_timer_cb,
	.cleanup = lcs_loc_req_fsm_cleanup,
};

static __attribute__((constructor)) void lcs_loc_req_fsm_register(void)
{
	OSMO_ASSERT(osmo_fsm_register(&lcs_loc_req_fsm) == 0);
}
