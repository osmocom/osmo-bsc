/* osmo-bsc API to manage BSSMAP Assignment Command */
#pragma once

#include <osmocom/gsm/protocol/gsm_04_08.h>

#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/lchan.h>

/* This macro automatically includes a final \n, if omitted. */
#define LOG_ASSIGNMENT(conn, level, fmt, args...) do { \
	if (conn->assignment.fi) \
		LOGPFSML(conn->assignment.fi, level, "%s%s" fmt, \
			 conn->assignment.new_lchan ? gsm_lchan_name(conn->assignment.new_lchan) : "", \
			 conn->assignment.new_lchan ? " " : "", \
			 ## args); \
	else \
		LOGP(DMSC, level, "Assignment%s%s: " fmt, \
		     conn->assignment.new_lchan ? " of " : "", \
		     conn->assignment.new_lchan ? gsm_lchan_name(conn->assignment.new_lchan) : "", \
		     ## args); \
	} while (0)

enum assignment_fsm_state {
	ASSIGNMENT_ST_WAIT_LCHAN_ACTIVE,
	ASSIGNMENT_ST_WAIT_RR_ASS_COMPLETE,
	ASSIGNMENT_ST_WAIT_LCHAN_ESTABLISHED,
	ASSIGNMENT_ST_WAIT_MGW_ENDPOINT_TO_MSC,
	ASSIGNMENT_ST_WAIT_LCHAN_MODIFIED,
};

enum assignment_fsm_event {
	ASSIGNMENT_EV_LCHAN_ACTIVE,
	ASSIGNMENT_EV_LCHAN_ESTABLISHED,
	ASSIGNMENT_EV_LCHAN_MODIFIED,
	ASSIGNMENT_EV_LCHAN_ERROR,
	ASSIGNMENT_EV_MSC_MGW_OK,
	ASSIGNMENT_EV_MSC_MGW_FAIL,
	ASSIGNMENT_EV_RR_ASSIGNMENT_COMPLETE,
	ASSIGNMENT_EV_RR_ASSIGNMENT_FAIL,
	ASSIGNMENT_EV_CONN_RELEASING,
};

int reassignment_request_to_lchan(enum assign_for assign_for, struct gsm_lchan *lchan, struct gsm_lchan *to_lchan,
				  int tsc_set, int tsc);
int reassignment_request_to_chan_type(enum assign_for assign_for, struct gsm_lchan *lchan,
				      enum gsm_chan_t new_lchan_type);

void assignment_fsm_start(struct gsm_subscriber_connection *conn, struct gsm_bts *bts,
			  struct assignment_request *req);
void assignment_reset(struct gsm_subscriber_connection *conn);
void assignment_fsm_update_id(struct gsm_subscriber_connection *conn);
