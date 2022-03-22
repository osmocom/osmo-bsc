/* Location Services (LCS): BSSMAP and BSSMAP-LE Perform Location Request handling in OsmoBSC, API */
#pragma once

#include <osmocom/gsm/bssmap_le.h>

#define LOG_LCS_LOC_REQ(LOC_REQ, level, fmt, args...) do { \
		if (LOC_REQ) \
			LOGPFSML((LOC_REQ)->fi, level, fmt, ## args); \
		else \
			LOGP(DLCS, level, "LCS Perf Loc Req: " fmt, ## args); \
	} while (0)

struct lcs_ta_req;

enum lcs_loc_req_fsm_event {
	LCS_LOC_REQ_EV_RX_LB_PERFORM_LOCATION_RESPONSE,
	LCS_LOC_REQ_EV_RX_A_PERFORM_LOCATION_ABORT,
	LCS_LOC_REQ_EV_TA_REQ_START,
	LCS_LOC_REQ_EV_TA_REQ_END,
	LCS_LOC_REQ_EV_HANDOVER_PERFORMED,
	LCS_LOC_REQ_EV_CONN_CLEAR,
};

struct lcs_loc_req {
	struct osmo_fsm_inst *fi;
	struct gsm_subscriber_connection *conn;

	struct {
		struct bssmap_le_location_type location_type;

		bool cell_id_present;
		struct gsm0808_cell_id cell_id;

		bool client_type_present;
		enum bssmap_le_lcs_client_type client_type;

		struct osmo_mobile_identity imsi;
		struct osmo_mobile_identity imei;
	} req;

	bool resp_present;
	struct bssmap_le_perform_loc_resp resp;

	struct lcs_cause_ie lcs_cause;

	struct lcs_ta_req *ta_req;
};

void lcs_loc_req_start(struct gsm_subscriber_connection *conn, struct msgb *msg);
int lcs_loc_req_rx_bssmap_le(struct gsm_subscriber_connection *conn, struct msgb *msg);
void lcs_loc_req_reset(struct gsm_subscriber_connection *conn);
