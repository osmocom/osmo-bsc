#pragma once
#include <osmocom/core/fsm.h>

enum gscon_fsm_event {
	/* local SCCP stack tells us incoming conn from MSC */
	GSCON_EV_A_CONN_IND,
	/* RSL side requests CONNECT to MSC */
	GSCON_EV_A_CONN_REQ,
	/* MSC confirms the SCCP connection */
	GSCON_EV_A_CONN_CFM,
	/* MSC has sent BSSMAP CLEAR CMD */
	GSCON_EV_A_CLEAR_CMD,
	/* MSC SCCP disconnect indication */
	GSCON_EV_A_DISC_IND,

	GSCON_EV_ASSIGNMENT_START,
	GSCON_EV_ASSIGNMENT_END,

	GSCON_EV_HANDOVER_START,
	GSCON_EV_HANDOVER_END,

	/* RSL CONNection FAILure Indication */
	GSCON_EV_RSL_CONN_FAIL,

	/* Mobile-originated DTAP (from MS) */
	GSCON_EV_MO_DTAP,
	/* Mobile-terminated DTAP (from MSC) */
	GSCON_EV_MT_DTAP,

	/* Transmit custom SCCP message */
	GSCON_EV_TX_SCCP,

	/* MDCX response received (MSC) - triggered by LCLS */
	GSCON_EV_MGW_MDCX_RESP_MSC,

	/* LCLS child FSM has terminated due to hard failure */
	GSCON_EV_LCLS_FAIL,

	GSCON_EV_FORGET_LCHAN,
	GSCON_EV_FORGET_MGW_ENDPOINT,
};

struct gsm_subscriber_connection;
struct gsm_network;
struct msgb;
struct osmo_mgcpc_ep_ci;
struct assignment_request;
struct gsm_lchan;

void bsc_subscr_conn_fsm_init();

/* Allocate a subscriber connection and its associated FSM */
struct gsm_subscriber_connection *bsc_subscr_con_allocate(struct gsm_network *net);
void gscon_update_id(struct gsm_subscriber_connection *conn);

void gscon_submit_rsl_dtap(struct gsm_subscriber_connection *conn,
			   struct msgb *msg, int link_id, int allow_sacch);
int gscon_sigtran_send(struct gsm_subscriber_connection *conn, struct msgb *msg);

struct osmo_mgcpc_ep *gscon_ensure_mgw_endpoint(struct gsm_subscriber_connection *conn,
						uint16_t msc_assigned_cic);
bool gscon_connect_mgw_to_msc(struct gsm_subscriber_connection *conn,
			      struct gsm_lchan *for_lchan,
			      const char *addr, uint16_t port,
			      struct osmo_fsm_inst *notify,
			      uint32_t event_success, uint32_t event_failure,
			      void *notify_data,
			      struct osmo_mgcpc_ep_ci **created_ci);

void gscon_start_assignment(struct gsm_subscriber_connection *conn,
			    struct assignment_request *req);

void gscon_change_primary_lchan(struct gsm_subscriber_connection *conn, struct gsm_lchan *new_lchan);
void gscon_release_lchans(struct gsm_subscriber_connection *conn, bool do_rr_release);

void gscon_lchan_releasing(struct gsm_subscriber_connection *conn, struct gsm_lchan *lchan);
void gscon_forget_lchan(struct gsm_subscriber_connection *conn, struct gsm_lchan *lchan);

void gscon_forget_mgw_endpoint_ci(struct gsm_subscriber_connection *conn, struct osmo_mgcpc_ep_ci *ci);

bool gscon_is_aoip(struct gsm_subscriber_connection *conn);
bool gscon_is_sccplite(struct gsm_subscriber_connection *conn);
