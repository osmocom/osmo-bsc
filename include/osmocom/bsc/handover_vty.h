#pragma once

#include <osmocom/vty/vty.h>
#include <osmocom/bsc/handover_cfg.h>

void ho_vty_init();
void ho_vty_write(struct vty *vty, const char *indent, struct handover_cfg *ho);
