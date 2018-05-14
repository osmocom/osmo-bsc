/* osmo-bsc API to manage BSSMAP Assignment Command */
#pragma once

#include <osmocom/gsm/protocol/gsm_04_08.h>

#include <osmocom/bsc/debug.h>

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
	} while(0)

enum assignment_fsm_state {
	ASSIGNMENT_ST_WAIT_LCHAN_ACTIVE,
	ASSIGNMENT_ST_WAIT_RR_ASS_COMPLETE,
	ASSIGNMENT_ST_WAIT_LCHAN_ESTABLISHED,
	ASSIGNMENT_ST_WAIT_MGW_ENDPOINT_TO_MSC,
};

enum assignment_fsm_event {
	ASSIGNMENT_EV_LCHAN_ACTIVE,
	ASSIGNMENT_EV_LCHAN_ESTABLISHED,
	ASSIGNMENT_EV_LCHAN_ERROR,
	ASSIGNMENT_EV_MSC_MGW_OK,
	ASSIGNMENT_EV_MSC_MGW_FAIL,
	ASSIGNMENT_EV_RR_ASSIGNMENT_COMPLETE,
	ASSIGNMENT_EV_RR_ASSIGNMENT_FAIL,
	ASSIGNMENT_EV_CONN_RELEASING,
};

void assignment_fsm_init();

void assignment_fsm_start(struct gsm_subscriber_connection *conn, struct gsm_bts *bts,
			  struct assignment_request *req);
void assignment_reset(struct gsm_subscriber_connection *conn);
