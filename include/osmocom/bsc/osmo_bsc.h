#pragma once

#include <osmocom/gsm/protocol/gsm_04_08.h>

#include <osmocom/bsc/bsc_api.h>
#include <osmocom/bsc/bsc_msg_filter.h>

#define BSS_SEND_USSD 1

enum bsc_con {
	BSC_CON_SUCCESS,
	BSC_CON_REJECT_NO_LINK,
	BSC_CON_REJECT_RF_GRACE,
	BSC_CON_NO_MEM,
};

struct bsc_msc_data;
struct gsm0808_channel_type;
struct gsm0808_speech_codec_list;
struct gsm_audio_support;

struct bsc_api *osmo_bsc_api();

int bsc_queue_for_msc(struct gsm_subscriber_connection *conn, struct msgb *msg);
int bsc_open_connection(struct gsm_subscriber_connection *sccp, struct msgb *msg);
enum bsc_con bsc_create_new_connection(struct gsm_subscriber_connection *conn,
				       struct bsc_msc_data *msc, int send_ping);
int bsc_delete_connection(struct gsm_subscriber_connection *sccp);

struct bsc_msc_data *bsc_find_msc(struct gsm_subscriber_connection *conn, struct msgb *);
int bsc_scan_bts_msg(struct gsm_subscriber_connection *conn, struct msgb *msg);
int bsc_scan_msc_msg(struct gsm_subscriber_connection *conn, struct msgb *msg);
int bsc_send_welcome_ussd(struct gsm_subscriber_connection *conn);

int bsc_handle_udt(struct bsc_msc_data *msc, struct msgb *msg, unsigned int length);
int bsc_handle_dt(struct gsm_subscriber_connection *conn, struct msgb *msg, unsigned int len);

int bsc_ctrl_cmds_install();

void bsc_gen_location_state_trap(struct gsm_bts *bts);

struct llist_head *bsc_access_lists(void);
