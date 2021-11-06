/* Location Services (LCS): BSSLAP TA Request handling in OsmoBSC, API */
#pragma once

#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/gsm_data.h>
#include <osmocom/core/fsm.h>
#include <osmocom/gsm/bssmap_le.h>

#define LOG_LCS_TA_REQ(TA_REQ, level, fmt, args...) do { \
	if (TA_REQ) \
		LOGPFSML((TA_REQ)->fi, level, fmt, ## args); \
	else \
		LOGP(DLCS, level, "LCS TA Req: " fmt, ## args); \
	} while (0)

enum lcs_ta_req_fsm_event {
	LCS_TA_REQ_EV_GOT_TA,
	LCS_TA_REQ_EV_ABORT,
};

struct lcs_ta_req {
	struct osmo_fsm_inst *fi;
	struct lcs_loc_req *loc_req;
	enum lcs_cause failure_cause;
	uint8_t failure_diagnostic_val;
};
int lcs_ta_req_start(struct lcs_loc_req *lcs_loc_req);

void lcs_bsslap_rx(struct gsm_subscriber_connection *conn, struct msgb *msg);
