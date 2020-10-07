/* Location Services (LCS): low level Lb/SCCP handling in OsmoBSC, API */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/sigtran/sccp_sap.h>

struct bssap_le_pdu;
struct gsm_subscriber_connection;

enum {
	SMLC_CTR_BSSMAP_LE_RX_UNKNOWN_PEER,
	SMLC_CTR_BSSMAP_LE_RX_UDT_RESET,
	SMLC_CTR_BSSMAP_LE_RX_UDT_RESET_ACK,
	SMLC_CTR_BSSMAP_LE_RX_UDT_ERR_INVALID_MSG,
	SMLC_CTR_BSSMAP_LE_RX_DT1_ERR_INVALID_MSG,
	SMLC_CTR_BSSMAP_LE_RX_DT1_PERFORM_LOCATION_RESPONSE_SUCCESS,
	SMLC_CTR_BSSMAP_LE_RX_DT1_PERFORM_LOCATION_RESPONSE_FAILURE,
	SMLC_CTR_BSSMAP_LE_RX_DT1_BSSLAP_TA_REQUEST,

	SMLC_CTR_BSSMAP_LE_TX_ERR_INVALID_MSG,
	SMLC_CTR_BSSMAP_LE_TX_ERR_CONN_NOT_READY,
	SMLC_CTR_BSSMAP_LE_TX_ERR_SEND,
	SMLC_CTR_BSSMAP_LE_TX_SUCCESS,

	SMLC_CTR_BSSMAP_LE_TX_UDT_RESET,
	SMLC_CTR_BSSMAP_LE_TX_UDT_RESET_ACK,
	SMLC_CTR_BSSMAP_LE_TX_DT1_PERFORM_LOCATION_REQUEST,
	SMLC_CTR_BSSMAP_LE_TX_DT1_PERFORM_LOCATION_ABORT,
	SMLC_CTR_BSSMAP_LE_TX_DT1_BSSLAP_TA_RESPONSE,
	SMLC_CTR_BSSMAP_LE_TX_DT1_BSSLAP_REJECT,
	SMLC_CTR_BSSMAP_LE_TX_DT1_BSSLAP_RESET,
	SMLC_CTR_BSSMAP_LE_TX_DT1_BSSLAP_ABORT,
};

struct smlc_config {
	bool enable;

	uint32_t cs7_instance;
	bool cs7_instance_valid;
	struct osmo_sccp_instance *sccp;
	struct osmo_sccp_user *sccp_user;

	struct osmo_sccp_addr bsc_addr;
	char *bsc_addr_name;

	struct osmo_sccp_addr smlc_addr;
	char *smlc_addr_name;

	/*! Lb link is ready when bssmap_reset_is_conn_ready(bssmap_reset) returns true. */
	struct bssmap_reset *bssmap_reset;

	struct rate_ctr_group *ctrs;
};

extern const struct rate_ctr_desc smlc_ctr_description[];
extern const struct rate_ctr_group_desc smlc_ctrg_desc;

int lb_init();
int lb_start_or_stop();
int lb_send(struct gsm_subscriber_connection *conn, const struct bssap_le_pdu *bssap_le);
void lb_close_conn(struct gsm_subscriber_connection *conn);
