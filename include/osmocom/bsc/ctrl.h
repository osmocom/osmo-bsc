#pragma once

#include <osmocom/ctrl/control_cmd.h>

struct gsm_network;
struct gsm_bts;
struct bsc_msc_data;

struct ctrl_handle *bsc_controlif_setup(struct gsm_network *net, uint16_t port);

/* Used internally in different ctrl source code files: */
int bsc_bts_ctrl_cmds_install(void);
int bsc_bts_trx_ctrl_cmds_install(void);
int bsc_bts_trx_ts_ctrl_cmds_install(void);
void ctrl_generate_bts_location_state_trap(struct gsm_bts *bts, struct bsc_msc_data *msc);
void osmo_bsc_send_trap(struct ctrl_cmd *cmd, struct bsc_msc_data *msc_data);


enum bsc_ctrl_node {
	CTRL_NODE_MSC = _LAST_CTRL_NODE,
	_LAST_CTRL_NODE_BSC
};
