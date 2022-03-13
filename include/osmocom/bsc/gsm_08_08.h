/* GSM 08.08 function declarations for osmo-bsc */

#pragma once

#include <stdint.h>

struct gsm_subscriber_connection;

void bsc_sapi_n_reject(struct gsm_subscriber_connection *conn, uint8_t dlci, enum gsm0808_cause cause);
void bsc_cipher_mode_compl(struct gsm_subscriber_connection *conn, struct msgb *msg, uint8_t chosen_a5_n);
int bsc_compl_l3(struct gsm_lchan *lchan, struct msgb *msg, uint16_t chosen_channel);
void bsc_dtap(struct gsm_subscriber_connection *conn, uint8_t link_id, struct msgb *msg);
void bsc_cm_update(struct gsm_subscriber_connection *conn,
		   const uint8_t *cm2, uint8_t cm2_len,
		   const uint8_t *cm3, uint8_t cm3_len);
