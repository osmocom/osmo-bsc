/* Manage RESET and disconnection detection on BSSMAP and BSSMAP-LE */
#pragma once

enum bssmap_reset_fsm_event {
	BSSMAP_RESET_EV_RX_RESET,
	BSSMAP_RESET_EV_RX_RESET_ACK,
	BSSMAP_RESET_EV_CONN_CFM_SUCCESS,
	BSSMAP_RESET_EV_CONN_CFM_FAILURE,
};

struct bssmap_reset_cfg {
	int conn_cfm_failure_threshold;
	struct {
		void (*tx_reset)(void *data);
		void (*tx_reset_ack)(void *data);
		void (*link_up)(void *data);
		void (*link_lost)(void *data);
	} ops;
	void *data;
};

struct bssmap_reset {
	struct osmo_fsm_inst *fi;
	struct bssmap_reset_cfg cfg;
	int conn_cfm_failures;
};

struct bssmap_reset *bssmap_reset_alloc(void *ctx, const char *label, const struct bssmap_reset_cfg *cfg);
bool bssmap_reset_is_conn_ready(const struct bssmap_reset *bssmap_reset);
