#ifndef OPENBSC_VTY_H
#define OPENBSC_VTY_H

#include <osmocom/vty/vty.h>
#include <osmocom/vty/buffer.h>
#include <osmocom/vty/command.h>

struct gsm_network;
struct vty;

void openbsc_vty_print_statistics(struct vty *vty, struct gsm_network *);

struct buffer *vty_argv_to_buffer(int argc, const char *argv[], int base);

enum bsc_vty_node {
	GSMNET_NODE = _LAST_OSMOVTY_NODE + 1,
	BTS_NODE,
	TRX_NODE,
	TS_NODE,
	ACC_RAMP_NODE,
	OML_NODE,
	NAT_NODE,
	NAT_BSC_NODE,
	MSC_NODE,
	OM2K_NODE,
	OM2K_CON_GROUP_NODE,
	BSC_NODE,
	CBC_NODE,
	CBC_SERVER_NODE,
	CBC_CLIENT_NODE,
	SMLC_NODE,
	POWER_CTRL_NODE,
};

struct log_info;
int bsc_vty_init(struct gsm_network *network);
int bsc_vty_init_extra(void);

struct gsm_network *gsmnet_from_vty(struct vty *vty);

enum bsc_vty_cmd_attr {
	BSC_VTY_ATTR_RESTART_ABIS_OML_LINK = 0,
	BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK,
	BSC_VTY_ATTR_NEW_LCHAN,
	BSC_VTY_ATTR_VENDOR_SPECIFIC,
	/* NOTE: up to 32 entries */
};

#endif
