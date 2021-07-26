#ifndef OPENBSC_VTY_H
#define OPENBSC_VTY_H

#include <osmocom/vty/vty.h>
#include <osmocom/vty/buffer.h>
#include <osmocom/vty/command.h>

struct gsm_network;
struct gsm_bts;
struct gsm_bts_trx;
struct gsm_bts_trx_ts;
struct gsm_nm_state;
struct pchan_load;
struct gsm_lchan;
struct bsc_subscr;
struct gsm_e1_subslot;
struct e1inp_sign_link;
struct vty;

void openbsc_vty_print_statistics(struct vty *vty, struct gsm_network *);

struct buffer *vty_argv_to_buffer(int argc, const char *argv[], int base);

enum bsc_vty_node {
	GSMNET_NODE = _LAST_OSMOVTY_NODE + 1,
        MGW_NODE,
	BTS_NODE,
	TRX_NODE,
	TS_NODE,
	OML_NODE,
	MSC_NODE,
	OM2K_NODE,
	OM2K_CON_GROUP_NODE,
	BSC_NODE,
	CBC_NODE,
	CBC_SERVER_NODE,
	CBC_CLIENT_NODE,
	SMLC_NODE,
	POWER_CTRL_NODE,
};

struct log_info;
int bsc_vty_init(struct gsm_network *network);
int bsc_vty_init_extra(void);
void net_dump_nmstate(struct vty *vty, struct gsm_nm_state *nms);
int dummy_config_write(struct vty *v);
void dump_pchan_load_vty(struct vty *vty, char *prefix, const struct pchan_load *pl);
void bsc_subscr_dump_vty(struct vty *vty, struct bsc_subscr *bsub);

struct gsm_network *gsmnet_from_vty(struct vty *vty);

int bts_vty_init(void);
void bts_dump_vty(struct vty *vty, struct gsm_bts *bts);
void trx_dump_vty(struct vty *vty, struct gsm_bts_trx *trx, bool print_rsl, bool show_connected);
void ts_dump_vty(struct vty *vty, struct gsm_bts_trx_ts *ts);
void lchan_dump_full_vty(struct vty *vty, struct gsm_lchan *lchan);
void lchan_dump_short_vty(struct vty *vty, struct gsm_lchan *lchan);

int bts_trx_vty_init(void);
void config_write_trx_single(struct vty *vty, struct gsm_bts_trx *trx);
void config_write_e1_link(struct vty *vty, struct gsm_e1_subslot *e1_link,
				 const char *prefix);
void e1isl_dump_vty_tcp(struct vty *vty, const struct e1inp_sign_link *e1l);
void e1isl_dump_vty(struct vty *vty, struct e1inp_sign_link *e1l);
void parse_e1_link(struct gsm_e1_subslot *e1_link, const char *line,
			  const char *ts, const char *ss);

enum bsc_vty_cmd_attr {
	BSC_VTY_ATTR_RESTART_ABIS_OML_LINK = 0,
	BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK,
	BSC_VTY_ATTR_NEW_LCHAN,
	BSC_VTY_ATTR_VENDOR_SPECIFIC,
	/* NOTE: up to 32 entries */
};

#define BTS_NR_STR "BTS Number\n"
#define TRX_NR_STR "TRX Number\n"
#define TS_NR_STR "Timeslot Number\n"
#define SS_NR_STR "Sub-slot Number\n"
#define LCHAN_NR_STR "Logical Channel Number\n"
#define BTS_TRX_STR BTS_NR_STR TRX_NR_STR
#define BTS_TRX_TS_STR BTS_TRX_STR TS_NR_STR
#define BTS_TRX_TS_LCHAN_STR BTS_TRX_TS_STR LCHAN_NR_STR
#define BTS_NR_TRX_TS_STR2 \
	"BTS for manual command\n" BTS_NR_STR \
	"TRX for manual command\n" TRX_NR_STR \
	"Timeslot for manual command\n" TS_NR_STR
#define BTS_NR_TRX_TS_SS_STR2 \
	BTS_NR_TRX_TS_STR2 \
	"Sub-slot for manual command\n" SS_NR_STR

#define TSC_ARGS_OPT "[tsc] [<1-4>] [<0-7>]"
#define TSC_ARGS_DOC \
      "Provide specific TSC Set and Training Sequence Code\n" \
      "TSC Set\n" \
      "Training Sequence Code\n"

#endif
