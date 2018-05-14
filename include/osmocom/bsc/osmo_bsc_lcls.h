#pragma once
#include <osmocom/core/fsm.h>

enum lcls_fsm_state {
	ST_NO_LCLS,
	ST_NOT_YET_LS,
	ST_NOT_POSSIBLE_LS,
	ST_NO_LONGER_LS,
	ST_REQ_LCLS_NOT_SUPP,
	ST_LOCALLY_SWITCHED,
	/* locally switched; received remote break; wait for "local" break */
	ST_LOCALLY_SWITCHED_WAIT_BREAK,
	/* locally switched; received break; wait for "other" break */
	ST_LOCALLY_SWITCHED_WAIT_OTHER_BREAK,
};

enum lcls_event {
	/* update LCLS config/control based on some BSSMAP signaling */
	LCLS_EV_UPDATE_CFG_CSC,
	/* apply LCLS config/control */
	LCLS_EV_APPLY_CFG_CSC,
	/* we have been identified as the correlation peer of another conn */
	LCLS_EV_CORRELATED,
	/* "other" LCLS connection has enabled local switching */
	LCLS_EV_OTHER_ENABLED,
	/* "other" LCLS connection is breaking local switch */
	LCLS_EV_OTHER_BREAK,
	/* "other" LCLS connection is dying */
	LCLS_EV_OTHER_DEAD,
};

enum gsm0808_lcls_status lcls_get_status(struct gsm_subscriber_connection *conn);

void lcls_update_config(struct gsm_subscriber_connection *conn,
			const uint8_t *config, const uint8_t *control);

void lcls_apply_config(struct gsm_subscriber_connection *conn);

extern struct osmo_fsm lcls_fsm;

void bssmap_add_lcls_status_if_needed(struct gsm_subscriber_connection *conn, struct msgb *msg);
