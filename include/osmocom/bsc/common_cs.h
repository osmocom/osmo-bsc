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
