#pragma once

#include <osmocom/ctrl/control_cmd.h>

struct ctrl_handle *bsc_controlif_setup(struct gsm_network *net,
					const char *bind_addr, uint16_t port);

enum bsc_ctrl_node {
	CTRL_NODE_MSC = _LAST_CTRL_NODE,
	_LAST_CTRL_NODE_BSC
};
