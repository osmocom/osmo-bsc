/* OpenBSC BSC code */

#ifndef OSMO_BSC_H
#define OSMO_BSC_H

#include "bsc_api.h"
#include "bsc_msg_filter.h"

#define BSS_SEND_USSD 1

enum bsc_con {
	BSC_CON_SUCCESS,
	BSC_CON_REJECT_NO_LINK,
	BSC_CON_REJECT_RF_GRACE,
	BSC_CON_NO_MEM,
};

struct bsc_msc_data;
struct bsc_msc_connection;

struct osmo_bsc_sccp_con {
	struct llist_head entry;

	int ciphering_handled;

	/* for audio handling */
	uint16_t cic;
	uint32_t rtp_ip;
	int rtp_port;

	/* RTP address of the remote end (assigned by MSC through assignment
	 * request) */
	struct sockaddr_storage aoip_rtp_addr_remote;

	/* Local RTP address (reported back to the MSC by us with the
	 * assignment complete message) */
	struct sockaddr_storage aoip_rtp_addr_local;

	/* storage to keep states of the MGCP connection handler, the
	 * handler is created when an assignment request is received
	 * and is terminated when the assignment complete message is
	 * sent */
	struct mgcp_ctx *mgcp_ctx;

	/* for advanced ping/pong */
	int send_ping;

	/* SCCP connection realted */
	struct bsc_msc_data *msc;

	struct llist_head sccp_queue;
	unsigned int sccp_queue_size;

	struct gsm_subscriber_connection *conn;
	uint8_t new_subscriber;

	struct bsc_filter_state filter_state;

	/* Sigtran connection ID */
	int conn_id;
};

struct bsc_api *osmo_bsc_api();

int bsc_queue_for_msc(struct osmo_bsc_sccp_con *conn, struct msgb *msg);
int bsc_open_connection(struct osmo_bsc_sccp_con *sccp, struct msgb *msg);
enum bsc_con bsc_create_new_connection(struct gsm_subscriber_connection *conn,
				       struct bsc_msc_data *msc, int send_ping);
int bsc_delete_connection(struct osmo_bsc_sccp_con *sccp);

struct bsc_msc_data *bsc_find_msc(struct gsm_subscriber_connection *conn, struct msgb *);
int bsc_scan_bts_msg(struct gsm_subscriber_connection *conn, struct msgb *msg);
int bsc_scan_msc_msg(struct gsm_subscriber_connection *conn, struct msgb *msg);
int bsc_send_welcome_ussd(struct gsm_subscriber_connection *conn);

int bsc_handle_udt(struct bsc_msc_data *msc, struct msgb *msg, unsigned int length);
int bsc_handle_dt(struct osmo_bsc_sccp_con *conn, struct msgb *msg, unsigned int len);

int bsc_ctrl_cmds_install();

void bsc_gen_location_state_trap(struct gsm_bts *bts);

struct llist_head *bsc_access_lists(void);

int bssmap_send_aoip_ass_compl(struct gsm_lchan *lchan);

#endif
