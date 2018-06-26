#pragma once
#include <osmocom/core/fsm.h>

enum gscon_fsm_event {
	/* local SCCP stack tells us incoming conn from MSC */
	GSCON_EV_A_CONN_IND,
	/* RSL side requests CONNECT to MSC */
	GSCON_EV_A_CONN_REQ,
	/* MSC confirms the SCCP connection */
	GSCON_EV_A_CONN_CFM,
	/* MSC requests assignment */
	GSCON_EV_A_ASSIGNMENT_CMD,
	/* MSC has sent BSSMAP CLEAR CMD */
	GSCON_EV_A_CLEAR_CMD,
	/* MSC SCCP disconnect indication */
	GSCON_EV_A_DISC_IND,
	/* MSC sends Handover Request (in CR) */
	GSCON_EV_A_HO_REQ,

	/* RR ASSIGNMENT COMPLETE received */
	GSCON_EV_RR_ASS_COMPL,
	/* RR ASSIGNMENT FAIL received */
	GSCON_EV_RR_ASS_FAIL,

	/* RSL RLL Release Indication */
	GSCON_EV_RLL_REL_IND,
	/* RSL CONNection FAILure Indication */
	GSCON_EV_RSL_CONN_FAIL,

	/* RSL/lchan tells us clearing is complete */
	GSCON_EV_RSL_CLEAR_COMPL,

	/* Mobile-originated DTAP (from MS) */
	GSCON_EV_MO_DTAP,
	/* Mobile-terminated DTAP (from MSC) */
	GSCON_EV_MT_DTAP,

	/* Transmit custom SCCP message */
	GSCON_EV_TX_SCCP,

	/* MGW is indicating failure (BTS) */
	GSCON_EV_MGW_FAIL_BTS,
	/* MGW is indicating failure (MSC) */
	GSCON_EV_MGW_FAIL_MSC,
	/* CRCX response received (BTS) */
	GSCON_EV_MGW_CRCX_RESP_BTS,
	/* MDCX response received (BTS) */
	GSCON_EV_MGW_MDCX_RESP_BTS,
	/* CRCX response received (MSC) */
	GSCON_EV_MGW_CRCX_RESP_MSC,
	/* MDCX response received (MSC) - triggered by LCLS */
	GSCON_EV_MGW_MDCX_RESP_MSC,

	/* Internal handover request (intra-BSC handover) */
	GSCON_EV_HO_START,
	/* Handover timed out (T3103 in handover_logic.c) */
	GSCON_EV_HO_TIMEOUT,
	/* Handover failed (handover_logic.c) */
	GSCON_EV_HO_FAIL,
	/* Handover completed successfully (handover_logic.c) */
	GSCON_EV_HO_COMPL,

	/* LCLS child FSM has terminated due to hard failure */
	GSCON_EV_LCLS_FAIL,
};

struct gsm_subscriber_connection;
struct gsm_network;
struct mgcp_conn_peer;

/* Allocate a subscriber connection and its associated FSM */
struct gsm_subscriber_connection *bsc_subscr_con_allocate(struct gsm_network *net);

void bsc_subscr_pick_codec(struct mgcp_conn_peer *conn_peer, struct gsm_subscriber_connection *conn);
