#pragma once

#include <stdint.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>

struct msgb;
struct gsm_network;

struct vty;

#define MAX_A5_KEY_LEN	(128/8)

struct gsm_encr {
	uint8_t alg_id;
	uint8_t key_len;
	uint8_t key[MAX_A5_KEY_LEN];
};

int common_cs_vty_init(struct gsm_network *network,
                 int (* config_write_net )(struct vty *));
struct gsm_network *gsmnet_from_vty(struct vty *v);
