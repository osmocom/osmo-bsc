/* Handle LCS BSSLAP TA Request */
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

#include <osmocom/bsc/lcs_ta_req.h>

#include <osmocom/bsc/lcs_loc_req.h>
#include <osmocom/bsc/lb.h>
#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/paging.h>
#include <osmocom/bsc/bts.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/fsm.h>
#include <osmocom/core/tdef.h>
#include <osmocom/gsm/bsslap.h>

enum lcs_ta_req_fsm_state {
	LCS_TA_REQ_ST_INIT,
	LCS_TA_REQ_ST_WAIT_TA,
	LCS_TA_REQ_ST_GOT_TA,
	LCS_TA_REQ_ST_FAILED,
};

static const struct value_string lcs_ta_req_fsm_event_names[] = {
	OSMO_VALUE_STRING(LCS_TA_REQ_EV_GOT_TA),
	OSMO_VALUE_STRING(LCS_TA_REQ_EV_ABORT),
	{}
};

static const struct osmo_tdef_state_timeout lcs_ta_req_fsm_timeouts[32] = {
	[LCS_TA_REQ_ST_WAIT_TA] = { .T = -12 },
};

/* Transition to a state, using the T timer defined in lcs_ta_req_fsm_timeouts.
 * The actual timeout value is in turn obtained from network->T_defs.
 * Assumes local variable fi exists. */
#define lcs_ta_req_fsm_state_chg(FI, STATE) \
	osmo_tdef_fsm_inst_state_chg(FI, STATE, \
				     lcs_ta_req_fsm_timeouts, \
				     (bsc_gsmnet)->T_defs, \
				     -1)

#define lcs_ta_req_fail(cause, fmt, args...) do { \
		LOG_LCS_TA_REQ(lcs_ta_req, LOGL_ERROR, "BSSLAP TA Request failed in state %s: " fmt "\n", \
			       lcs_ta_req ? osmo_fsm_inst_state_name(lcs_ta_req->fi) : "NULL", ## args); \
		lcs_ta_req->failure_cause = cause; \
		lcs_ta_req_fsm_state_chg(lcs_ta_req->fi, LCS_TA_REQ_ST_FAILED); \
	} while(0)

static struct osmo_fsm lcs_ta_req_fsm;

static struct lcs_ta_req *lcs_ta_req_alloc(struct osmo_fsm_inst *parent_fi, uint32_t parent_event_term)
{
	struct lcs_ta_req *lcs_ta_req;

	struct osmo_fsm_inst *fi = osmo_fsm_inst_alloc_child(&lcs_ta_req_fsm, parent_fi, parent_event_term);
	OSMO_ASSERT(fi);

	lcs_ta_req = talloc(fi, struct lcs_ta_req);
	OSMO_ASSERT(lcs_ta_req);
	fi->priv = lcs_ta_req;
	*lcs_ta_req = (struct lcs_ta_req){
		.fi = fi,
	};

	return lcs_ta_req;
}

int lcs_ta_req_start(struct lcs_loc_req *lcs_loc_req)
{
	struct lcs_ta_req *lcs_ta_req;
	if (lcs_loc_req->ta_req) {
		LOG_LCS_TA_REQ(lcs_loc_req->ta_req, LOGL_ERROR,
			       "Cannot start anoter TA Request FSM, this TA Request is still active\n");
		return -ENOTSUP;
	}
	lcs_ta_req = lcs_ta_req_alloc(lcs_loc_req->fi, LCS_LOC_REQ_EV_TA_REQ_END);
	if (!lcs_ta_req) {
		LOG_LCS_LOC_REQ(lcs_loc_req, LOGL_ERROR, "Cannot allocate TA Request FSM");
		return -ENOSPC;
	}
	lcs_ta_req->loc_req = lcs_loc_req;
	lcs_loc_req->ta_req = lcs_ta_req;

	return lcs_ta_req_fsm_state_chg(lcs_ta_req->fi, LCS_TA_REQ_ST_WAIT_TA);
}

static int lcs_ta_req_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	struct lcs_ta_req *lcs_ta_req = fi->priv;
	lcs_ta_req_fail(LCS_CAUSE_SYSTEM_FAILURE, "Timeout");
	return 1;
}

void lcs_ta_req_wait_ta_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct lcs_ta_req *lcs_ta_req = fi->priv;
	struct lcs_loc_req *loc_req = lcs_ta_req->loc_req;
	struct gsm_lchan *lchan;
	struct bsc_paging_params paging;

	if (osmo_fsm_inst_dispatch(loc_req->fi, LCS_LOC_REQ_EV_TA_REQ_START, lcs_ta_req)) {
		lcs_ta_req_fail(LCS_CAUSE_SYSTEM_FAILURE, "Failed to dispatch LCS_LOC_REQ_EV_TA_REQ_START");
		return;
	}

	paging = (struct bsc_paging_params){
		.reason = BSC_PAGING_FOR_LCS,
		.msc = loc_req->conn->sccp.msc,
		.bsub = loc_req->conn->bsub,
		.tmsi = GSM_RESERVED_TMSI,
		.imsi = loc_req->req.imsi,
		.chan_needed = RSL_CHANNEED_ANY,
	};
	if (paging.bsub)
		bsc_subscr_get(paging.bsub, BSUB_USE_PAGING_START);

	/* Do we already have an active lchan with knowledge of TA? */
	lchan = loc_req->conn->lchan;
	if (lchan) {
		lcs_ta_req_fsm_state_chg(fi, LCS_TA_REQ_ST_GOT_TA);
		return;
	}

	/* No lchan yet, need to start Paging */
	if (loc_req->req.imsi.type != GSM_MI_TYPE_IMSI) {
		lcs_ta_req_fail(LCS_CAUSE_PROTOCOL_ERROR,
				"No IMSI in BSSMAP Location Request and no active lchan, cannot start Paging");
		return;
	}

	if (!loc_req->req.cell_id_present) {
		LOG_LCS_TA_REQ(lcs_ta_req, LOGL_DEBUG,
			       "No Cell Identity in BSSMAP Location Request, paging entire BSS\n");
		paging.cil = (struct gsm0808_cell_id_list2){
			.id_discr = CELL_IDENT_BSS,
		};
	} else {
		paging.cil = (struct gsm0808_cell_id_list2){
			.id_discr = loc_req->req.cell_id.id_discr,
			.id_list = { loc_req->req.cell_id.id },
			.id_list_len = 1,
		};
	}

	bsc_paging_start(&paging);
}

static void lcs_ta_req_wait_ta_action(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {

	case LCS_TA_REQ_EV_GOT_TA:
		lcs_ta_req_fsm_state_chg(fi, LCS_TA_REQ_ST_GOT_TA);
		break;

	case LCS_TA_REQ_EV_ABORT:
		lcs_ta_req_fsm_state_chg(fi, LCS_TA_REQ_ST_FAILED);
		break;

	default:
		OSMO_ASSERT(false);
	}
}

static int lcs_ta_req_send(struct lcs_ta_req *lcs_ta_req, const struct bssap_le_pdu *bssap_le)
{
	int rc = lb_send(lcs_ta_req->loc_req->conn, bssap_le);
	if (rc)
		lcs_ta_req_fail(LCS_CAUSE_SYSTEM_FAILURE,
				 "Failed to send %s", osmo_bssap_le_pdu_to_str_c(OTC_SELECT, bssap_le));
	return rc;
}

void lcs_ta_req_got_ta_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct lcs_ta_req *lcs_ta_req = fi->priv;
	struct bssap_le_pdu bsslap_ta_resp;
	struct gsm_lchan *lchan = lcs_ta_req->loc_req->conn->lchan;

	if (!lchan) {
		lcs_ta_req_fail(LCS_CAUSE_SYSTEM_FAILURE, "Internal error: no lchan");
		return;
	}

	bsslap_ta_resp = (struct bssap_le_pdu) {
		.discr = BSSAP_LE_MSG_DISCR_BSSMAP_LE,
		.bssmap_le = {
			.msg_type = BSSMAP_LE_MSGT_CONN_ORIENTED_INFO,
			.conn_oriented_info = {
				.apdu = {
					.msg_type = BSSLAP_MSGT_TA_RESPONSE,
					.ta_response = {
						.cell_id = lchan->ts->trx->bts->cell_identity,
						.ta = lchan->last_ta,
					},
				},
			},
		},
	};

	lcs_ta_req_send(lcs_ta_req, &bsslap_ta_resp);
	osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, NULL);
}

void lcs_ta_req_failed_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct lcs_ta_req *lcs_ta_req = fi->priv;
	struct bssap_le_pdu bsslap_abort;

	bsslap_abort = (struct bssap_le_pdu) {
		.discr = BSSAP_LE_MSG_DISCR_BSSMAP_LE,
		.bssmap_le = {
			.msg_type = BSSMAP_LE_MSGT_CONN_ORIENTED_INFO,
			.conn_oriented_info = {
				.apdu = {
					.msg_type = BSSLAP_MSGT_ABORT,
					.abort = BSSLAP_CAUSE_OTHER_RADIO_EVT_FAIL,
				},
			},
		},
	};

	lcs_ta_req_send(lcs_ta_req, &bsslap_abort);
	osmo_fsm_inst_term(fi, OSMO_FSM_TERM_ERROR, NULL);
}

void lcs_ta_req_fsm_cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct lcs_ta_req *lcs_ta_req = fi->priv;
	if (lcs_ta_req->loc_req->ta_req == lcs_ta_req)
		lcs_ta_req->loc_req->ta_req = NULL;
	/* FSM termination will dispatch LCS_LOC_REQ_EV_TA_REQ_END to the lcs_loc_req FSM */
}


#define S(x)    (1 << (x))

static const struct osmo_fsm_state lcs_ta_req_fsm_states[] = {
	[LCS_TA_REQ_ST_INIT] = {
		.name = "init",
		.out_state_mask = 0
			| S(LCS_TA_REQ_ST_WAIT_TA)
			| S(LCS_TA_REQ_ST_GOT_TA)
			,
	},
	[LCS_TA_REQ_ST_WAIT_TA] = {
		.name = "wait_ta",
		.in_event_mask = 0
			| S(LCS_TA_REQ_EV_GOT_TA)
			| S(LCS_TA_REQ_EV_ABORT)
			,
		.out_state_mask = 0
			| S(LCS_TA_REQ_ST_GOT_TA)
			| S(LCS_TA_REQ_ST_FAILED)
			,
		.onenter = lcs_ta_req_wait_ta_onenter,
		.action = lcs_ta_req_wait_ta_action,
	},
	[LCS_TA_REQ_ST_GOT_TA] = {
		.name = "got_ta",
		.in_event_mask = 0
			,
		.out_state_mask = 0
			,
		.onenter = lcs_ta_req_got_ta_onenter,
	},
	[LCS_TA_REQ_ST_FAILED] = {
		.name = "failed",
		.onenter = lcs_ta_req_failed_onenter,
	},
};

static struct osmo_fsm lcs_ta_req_fsm = {
	.name = "lcs_ta_req",
	.states = lcs_ta_req_fsm_states,
	.num_states = ARRAY_SIZE(lcs_ta_req_fsm_states),
	.log_subsys = DLCS,
	.event_names = lcs_ta_req_fsm_event_names,
	.timer_cb = lcs_ta_req_fsm_timer_cb,
	.cleanup = lcs_ta_req_fsm_cleanup,
};

static __attribute__((constructor)) void lcs_ta_req_fsm_register(void)
{
	OSMO_ASSERT(osmo_fsm_register(&lcs_ta_req_fsm) == 0);
}
