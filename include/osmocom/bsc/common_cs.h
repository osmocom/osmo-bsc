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

struct msgb *gsm48_create_mm_serv_rej(enum gsm48_reject_value value);
int gsm48_extract_mi(uint8_t *classmark2_lv, int length, char *mi_string, uint8_t *mi_type);
int gsm48_paging_extract_mi(struct gsm48_pag_resp *resp, int length,
			    char *mi_string, uint8_t *mi_type);
struct msgb *gsm48_create_loc_upd_rej(uint8_t cause);
