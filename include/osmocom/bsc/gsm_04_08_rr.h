#pragma once

#include <stdint.h>
#include <osmocom/core/msgb.h>

enum handover_scope;

struct amr_mode;
struct amr_multirate_conf;
struct bsc_subscr;
struct gsm48_chan_desc;
struct gsm48_pag_resp;
struct gsm_lchan;
struct gsm_meas_rep;
struct gsm_network;
struct gsm_subscriber_connection;

void gsm_net_update_ctype(struct gsm_network *network);
enum gsm_chan_t get_ctype_by_chreq(struct gsm_network *network, uint8_t ra);
int get_reason_by_chreq(uint8_t ra, int neci);
int gsm48_send_rr_release(struct gsm_lchan *lchan);
int send_siemens_mrpci(struct gsm_lchan *lchan,
		       uint8_t *classmark2_lv);
int gsm48_send_rr_classmark_enquiry(struct gsm_lchan *lchan);
int gsm48_send_rr_ciph_mode(struct gsm_lchan *lchan, int want_imeisv);
int gsm48_multirate_config(struct msgb *msg,
			   const struct gsm48_multi_rate_conf *mr_conf,
			   const struct amr_mode *modes, unsigned int num_modes);
struct msgb *gsm48_make_ho_cmd(const struct gsm_lchan *new_lchan,
			       enum handover_scope ho_scope,
			       uint8_t power_command, uint8_t ho_ref);
int gsm48_send_rr_ass_cmd(struct gsm_lchan *dest_lchan, struct gsm_lchan *lchan, uint8_t power_command);
int gsm48_send_rr_app_info(struct gsm_lchan *lchan, uint8_t apdu_id, uint8_t apdu_flags,
			   const uint8_t *apdu_data, ssize_t apdu_data_len);
int gsm48_lchan_modify(struct gsm_lchan *lchan, uint8_t mode);
int gsm48_rx_rr_modif_ack(struct msgb *msg);
int gsm48_parse_meas_rep(struct gsm_meas_rep *rep, struct msgb *msg);

struct msgb *gsm48_create_mm_serv_rej(enum gsm48_reject_value value);
struct msgb *gsm48_create_loc_upd_rej(uint8_t cause);

struct msgb *gsm48_create_rr_status(uint8_t cause);
int gsm48_tx_rr_status(struct gsm_subscriber_connection *conn, uint8_t cause);

#define GSM48_ALLOC_SIZE        2048
#define GSM48_ALLOC_HEADROOM    256

static inline struct msgb *gsm48_msgb_alloc_name(const char *name)
{
        return msgb_alloc_headroom(GSM48_ALLOC_SIZE, GSM48_ALLOC_HEADROOM,
                                   name);
}

uint64_t str_to_imsi(const char *imsi_str);

int gsm48_sendmsg(struct msgb *msg);
int gsm0408_rcvmsg(struct msgb *msg, uint8_t link_id);
