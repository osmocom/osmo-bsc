#pragma once
#include <osmocom/bsc/gsm_data.h>

#include <osmocom/core/msgb.h>
#include <osmocom/netif/stream.h>
#include <osmocom/gsm/cbsp.h>

struct bsc_cbc_link;

/* smscb.c */
void bts_smscb_del(struct bts_smscb_message *smscb, struct bts_smscb_chan_state *cstate,
		   const char *reason);
const char *bts_smscb_msg2str(const struct bts_smscb_message *smscb);
struct bts_smscb_chan_state *bts_get_smscb_chan(struct gsm_bts *bts, bool extended);
int cbsp_rx_decoded(struct bsc_cbc_link *cbc, const struct osmo_cbsp_decoded *dec);
int cbsp_tx_restart(struct bsc_cbc_link *cbc, bool is_emerg);
const char *bts_smscb_chan_state_name(const struct bts_smscb_chan_state *cstate);
unsigned int bts_smscb_chan_load_percent(const struct bts_smscb_chan_state *cstate);
unsigned int bts_smscb_chan_page_count(const struct bts_smscb_chan_state *cstate);
void smscb_vty_init(void);

/* cbch_scheduler.c */
int bts_smscb_gen_sched_arr(struct bts_smscb_chan_state *cstate, struct bts_smscb_page ***arr_out);
struct bts_smscb_page *bts_smscb_pull_page(struct bts_smscb_chan_state *cstate);
void bts_smscb_page_done(struct bts_smscb_chan_state *cstate, struct bts_smscb_page *page);
int bts_smscb_rx_cbch_load_ind(struct gsm_bts *bts, bool cbch_extended, bool is_overflow,
			       uint8_t slot_count);
void bts_cbch_timer_schedule(struct gsm_bts *bts);

/* cbsp_link.c */
struct bsc_cbc_link {
	struct gsm_network *net;
	struct {
		/* hostname/IP of CBC */
		char *cbc_hostname;
		/* TCP port (Default: 48049) of CBC */
		int cbc_port;
		/* local listening port (0 for disabling local server) */
		int listen_port;
		/* local listening hostname/IP */
		char *listen_hostname;
	} config;
	/* for handling inbound TCP connections */
	struct {
		struct osmo_stream_srv *srv;
		struct osmo_stream_srv_link *link;
		char *sock_name;
		struct msgb *msg;
	} server;
	/* for handling outbound TCP connections */
	struct {
		struct osmo_stream_cli *cli;
		char *sock_name;
		struct msgb *msg;
	} client;
};
void cbc_vty_init(void);
int bsc_cbc_link_restart(void);
int cbsp_tx_decoded(struct bsc_cbc_link *cbc, struct osmo_cbsp_decoded *decoded);
