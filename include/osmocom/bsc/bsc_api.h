/* GSM 08.08 like API for OpenBSC */

#ifndef OPENBSC_BSC_API_H
#define OPENBSC_BSC_API_H

#include "gsm_data.h"

#define BSC_API_CONN_POL_ACCEPT	0
#define BSC_API_CONN_POL_REJECT	1

void bsc_sapi_n_reject(struct gsm_subscriber_connection *conn, int dlci);
void bsc_cipher_mode_compl(struct gsm_subscriber_connection *conn, struct msgb *msg, uint8_t chosen_encr);
int bsc_compl_l3(struct gsm_subscriber_connection *conn, struct msgb *msg, uint16_t chosen_channel);
void bsc_dtap(struct gsm_subscriber_connection *conn, uint8_t link_id, struct msgb *msg);
void bsc_assign_compl(struct gsm_subscriber_connection *conn, uint8_t rr_cause);
void bsc_assign_fail(struct gsm_subscriber_connection *conn, uint8_t cause, uint8_t *rr_cause);
int bsc_clear_request(struct gsm_subscriber_connection *conn, uint32_t cause);
void bsc_cm_update(struct gsm_subscriber_connection *conn,
		   const uint8_t *cm2, uint8_t cm2_len,
		   const uint8_t *cm3, uint8_t cm3_len);
void bsc_mr_config(struct gsm_subscriber_connection *conn, struct gsm_lchan *lchan, int full_rate);

int gsm0808_submit_dtap(struct gsm_subscriber_connection *conn, struct msgb *msg, int link_id, int allow_sacch);
int gsm0808_assign_req(struct gsm_subscriber_connection *conn, int chan_mode, int full_rate);
int gsm0808_cipher_mode(struct gsm_subscriber_connection *conn, int cipher,
			const uint8_t *key, int len, int include_imeisv);
int gsm0808_page(struct gsm_bts *bts, unsigned int page_group,
		 unsigned int mi_len, uint8_t *mi, int chan_type);
int gsm0808_clear(struct gsm_subscriber_connection *conn);

#endif
