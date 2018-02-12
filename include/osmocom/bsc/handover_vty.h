#pragma once

#include <osmocom/vty/vty.h>
#include <osmocom/bsc/handover_cfg.h>

void ho_vty_init();
void ho_vty_write_net(struct vty *vty, struct gsm_network *net);
void ho_vty_write_bts(struct vty *vty, struct gsm_bts *bts);
