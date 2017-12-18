#ifndef _GSM_DATA_H
#define _GSM_DATA_H

#include <stdint.h>
#include <regex.h>
#include <sys/types.h>
#include <stdbool.h>

#include <osmocom/core/timer.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/select.h>
#include <osmocom/core/stats.h>

#include <osmocom/crypt/auth.h>
#include <osmocom/sigtran/sccp_sap.h>

#include <osmocom/bsc/common.h>
#include <osmocom/bsc/rest_octets.h>
#include <osmocom/bsc/common_cs.h>


/** annotations for msgb ownership */
#define __uses

#define OBSC_NM_W_ACK_CB(__msgb) (__msgb)->cb[3]

struct bsc_subscr;
struct gprs_ra_id;

#define OBSC_LINKID_CB(__msgb)	(__msgb)->cb[3]

#define tmsi_from_string(str) strtoul(str, NULL, 10)

/* 3-bit long values */
#define EARFCN_PRIO_INVALID 8
#define EARFCN_MEAS_BW_INVALID 8
/* 5-bit long values */
#define EARFCN_QRXLV_INVALID 32
#define EARFCN_THRESH_LOW_INVALID 32

struct msgb;
typedef int gsm_cbfn(unsigned int hooknum,
		     unsigned int event,
		     struct msgb *msg,
		     void *data, void *param);

/* Maximum number of neighbor cells whose average we track */
#define MAX_NEIGH_MEAS		10
/* Maximum size of the averaging window for neighbor cells */
#define MAX_WIN_NEIGH_AVG	10

/* processed neighbor measurements for one cell */
struct neigh_meas_proc {
	uint16_t arfcn;
	uint8_t bsic;
	uint8_t rxlev[MAX_WIN_NEIGH_AVG];
	unsigned int rxlev_cnt;
	uint8_t last_seen_nr;
};

struct gsm_classmark {
	bool classmark1_set;
	struct gsm48_classmark1 classmark1;
	uint8_t classmark2_len;
	uint8_t classmark2[3];
	uint8_t classmark3_len;
	uint8_t classmark3[14]; /* if cm3 gets extended by spec, it will be truncated */
};

/* active radio connection of a mobile subscriber */
struct gsm_subscriber_connection {
	/* global linked list of subscriber_connections */
	struct llist_head entry;

	/* libbsc subscriber information (if available) */
	struct bsc_subscr *bsub;

	/* SCCP connection associatd with this subscriber_connection */
	struct osmo_bsc_sccp_con *sccp_con;

	/* back pointers */
	struct gsm_network *network;

	/* the primary / currently active lchan to the BTS/subscriber */
	struct gsm_lchan *lchan;
	/* the future/allocated but not yet used lchan during HANDOVER */
	struct gsm_lchan *ho_lchan;
	/* a short-hand pointer to the BTS currently serving the subscriber,
	 * points to gsm_subscriber_connection.lchan->ts->trx->bts */
	struct gsm_bts *bts;

	/* timer for assignment handling */
	struct osmo_timer_list T10;
	/* the future allocated but not yet used lchan during ASSIGNMENT */
	struct gsm_lchan *secondary_lchan;

	/* buffer/cache for classmark of the ME of the subscriber */
	struct gsm_classmark classmark;
};


#include "gsm_data_shared.h"

enum {
	BTS_CTR_CHREQ_TOTAL,
	BTS_CTR_CHREQ_NO_CHANNEL,
	BTS_CTR_CHAN_RF_FAIL,
	BTS_CTR_CHAN_RLL_ERR,
	BTS_CTR_BTS_OML_FAIL,
	BTS_CTR_BTS_RSL_FAIL,
	BTS_CTR_CODEC_AMR_F,
	BTS_CTR_CODEC_AMR_H,
	BTS_CTR_CODEC_EFR,
	BTS_CTR_CODEC_V1_FR,
	BTS_CTR_CODEC_V1_HR,
	BTS_CTR_PAGING_ATTEMPTED,
	BTS_CTR_PAGING_ALREADY,
	BTS_CTR_PAGING_RESPONDED,
	BTS_CTR_PAGING_EXPIRED,
	BTS_CTR_CHAN_ACT_TOTAL,
	BTS_CTR_CHAN_ACT_NACK,
	BTS_CTR_RSL_UNKNOWN,
	BTS_CTR_RSL_IPA_NACK,
	BTS_CTR_MODE_MODIFY_NACK,
};

static const struct rate_ctr_desc bts_ctr_description[] = {
	[BTS_CTR_CHREQ_TOTAL] = 		{"chreq:total", "Received channel requests."},
	[BTS_CTR_CHREQ_NO_CHANNEL] = 		{"chreq:no_channel", "Sent to MS no channel available."},
	[BTS_CTR_CHAN_RF_FAIL] = 		{"chan:rf_fail", "Received a RF failure indication from BTS."},
	[BTS_CTR_CHAN_RLL_ERR] = 		{"chan:rll_err", "Received a RLL failure with T200 cause from BTS."},
	[BTS_CTR_BTS_OML_FAIL] = 		{"oml_fail", "Received a TEI down on a OML link."},
	[BTS_CTR_BTS_RSL_FAIL] = 		{"rsl_fail", "Received a TEI down on a OML link."},
	[BTS_CTR_CODEC_AMR_F] =			{"codec:amr_f", "Count the usage of AMR/F codec by channel mode requested."},
	[BTS_CTR_CODEC_AMR_H] =			{"codec:amr_h", "Count the usage of AMR/H codec by channel mode requested."},
	[BTS_CTR_CODEC_EFR] = 			{"codec:efr", "Count the usage of EFR codec by channel mode requested."},
	[BTS_CTR_CODEC_V1_FR] =			{"codec:fr", "Count the usage of FR codec by channel mode requested."},
	[BTS_CTR_CODEC_V1_HR] =			{"codec:hr", "Count the usage of HR codec by channel mode requested."},

	[BTS_CTR_PAGING_ATTEMPTED] = 		{"paging:attempted", "Paging attempts for a subscriber."},
	[BTS_CTR_PAGING_ALREADY] = 		{"paging:already", "Paging attempts ignored as subsciber was already being paged."},
	[BTS_CTR_PAGING_RESPONDED] = 		{"paging:responded", "Paging attempts with successful paging response."},
	[BTS_CTR_PAGING_EXPIRED] = 		{"paging:expired", "Paging Request expired because of timeout T3113."},
	[BTS_CTR_CHAN_ACT_TOTAL] =		{"chan_act:total", "Total number of Channel Activations."},
	[BTS_CTR_CHAN_ACT_NACK] =		{"chan_act:nack", "Number of Channel Activations that the BTS NACKed"},
	[BTS_CTR_RSL_UNKNOWN] =			{"rsl:unknown", "Number of unknown/unsupported RSL messages received from BTS"},
	[BTS_CTR_RSL_IPA_NACK] =		{"rsl:ipa_nack", "Number of IPA (RTP/dyn-PDCH) related NACKs received from BTS"},
	[BTS_CTR_MODE_MODIFY_NACK] =		{"chan:mode_modify_nack", "Number of Channel Mode Modify NACKs received from BTS"},
};

static const struct rate_ctr_group_desc bts_ctrg_desc = {
	"bts",
	"base transceiver station",
	OSMO_STATS_CLASS_GLOBAL,
	ARRAY_SIZE(bts_ctr_description),
	bts_ctr_description,
};

enum {
	BSC_CTR_HANDOVER_ATTEMPTED,
	BSC_CTR_HANDOVER_NO_CHANNEL,
	BSC_CTR_HANDOVER_TIMEOUT,
	BSC_CTR_HANDOVER_COMPLETED,
	BSC_CTR_HANDOVER_FAILED,
	BSC_CTR_PAGING_ATTEMPTED,
	BSC_CTR_PAGING_DETACHED,
	BSC_CTR_PAGING_RESPONDED,
};

static const struct rate_ctr_desc bsc_ctr_description[] = {
	[BSC_CTR_HANDOVER_ATTEMPTED] = 		{"handover:attempted", "Received handover attempts."},
	[BSC_CTR_HANDOVER_NO_CHANNEL] = 	{"handover:no_channel", "Sent no channel available responses."},
	[BSC_CTR_HANDOVER_TIMEOUT] = 		{"handover:timeout", "Count the amount of timeouts of timer T3103."},
	[BSC_CTR_HANDOVER_COMPLETED] = 		{"handover:completed", "Received handover completed."},
	[BSC_CTR_HANDOVER_FAILED] = 		{"handover:failed", "Receive HO FAIL messages."},

	[BSC_CTR_PAGING_ATTEMPTED] = 		{"paging:attempted", "Paging attempts for a subscriber."},
	[BSC_CTR_PAGING_DETACHED] = 		{"paging:detached", "Counts the amount of paging attempts which couldn't sent out any paging request because no responsible bts found."},
	[BSC_CTR_PAGING_RESPONDED] = 		{"paging:responded", "Paging attempts with successful response."},
};



static const struct rate_ctr_group_desc bsc_ctrg_desc = {
	"bsc",
	"base station controller",
	OSMO_STATS_CLASS_GLOBAL,
	ARRAY_SIZE(bsc_ctr_description),
	bsc_ctr_description,
};

#define GSM_T3101_DEFAULT 3	/* s */
#define GSM_T3103_DEFAULT 5	/* s */
#define GSM_T3105_DEFAULT 100	/* ms */
#define GSM_T3107_DEFAULT 5	/* s */
#define GSM_T3109_DEFAULT 19	/* s, must be 2s + radio_link_timeout*0.48 */
#define GSM_T3111_DEFAULT 2	/* s */
#define GSM_T3113_DEFAULT 10	/* s */
#define GSM_T3115_DEFAULT 10
#define GSM_T3117_DEFAULT 10
#define GSM_T3119_DEFAULT 10
#define GSM_T3122_DEFAULT 10
#define GSM_T3141_DEFAULT 10

struct gsm_tz {
	int override; /* if 0, use system's time zone instead. */
	int hr; /* hour */
	int mn; /* minute */
	int dst; /* daylight savings */
};

struct gsm_network {
	/* TODO MSCSPLIT the gsm_network struct is basically a kitchen sink for
	 * global settings and variables, "madly" mixing BSC and MSC stuff. Split
	 * this in e.g. struct osmo_bsc and struct osmo_msc, with the things
	 * these have in common, like country and network code, put in yet
	 * separate structs and placed as members in osmo_bsc and osmo_msc. */

	/* global parameters */
	uint16_t country_code;
	uint16_t network_code;
	int a5_encryption;
	int neci;
	struct {
		int active;
		/* Window RXLEV averaging */
		unsigned int win_rxlev_avg;	/* number of SACCH frames */
		/* Window RXQUAL averaging */
		unsigned int win_rxqual_avg;	/* number of SACCH frames */
		/* Window RXLEV neighbouring cells averaging */
		unsigned int win_rxlev_avg_neigh; /* number of SACCH frames */

		/* how often should we check for power budget HO */
		unsigned int pwr_interval;	/* SACCH frames */
		/* how much better does a neighbor cell have to be ? */
		unsigned int pwr_hysteresis;	/* dBm */
		/* maximum distacne before we try a handover */
		unsigned int max_distance;	/* TA values */
	} handover;

	struct rate_ctr_group *bsc_ctrs;

	/*
	 * TODO: Move the trans_list into the subscriber connection and
	 * create a pending list for MT transactions. These exist before
	 * we have a subscriber connection.
	 */
	struct llist_head trans_list;
	struct bsc_api *bsc_api;

	unsigned int num_bts;
	struct llist_head bts_list;

	/* timer values */
	int T3101;
	int T3103;
	int T3105;
	int T3107;
	int T3109;
	int T3111;
	int T3113;
	int T3115;
	int T3117;
	int T3119;
	int T3122;
	int T3141;

	/* timer to expire old location updates */
	struct osmo_timer_list subscr_expire_timer;

	enum gsm_chan_t ctype_by_chreq[_NUM_CHREQ_T];

	/* Use a TCH for handling requests of type paging any */
	int pag_any_tch;

	/* MSC data in case we are a true BSC */
	struct osmo_bsc_data *bsc_data;

	/* control interface */
	struct ctrl_handle *ctrl;

	/* Allow or disallow TCH/F on dynamic TCH/F_TCH/H_PDCH; OS#1778 */
	bool dyn_ts_allow_tch_f;

	/* all active subscriber connections. */
	struct llist_head subscr_conns;

	/* if override is nonzero, this timezone data is used for all MM
	 * contexts. */
	/* TODO: in OsmoNITB, tz-override used to be BTS-specific. To enable
	 * BTS|RNC specific timezone overrides for multi-tz networks in
	 * OsmoMSC, this should be tied to the location area code (LAC). */
	struct gsm_tz tz;

	/* List of all struct bsc_subscr used in libbsc. This llist_head is
	 * allocated so that the llist_head pointer itself can serve as a
	 * talloc context (useful to not have to pass the entire gsm_network
	 * struct to the bsc_subscr_* API, and for bsc_susbscr unit tests to
	 * not require gsm_data.h). In an MSC-without-BSC environment, this
	 * pointer is NULL to indicate absence of a bsc_subscribers list. */
	struct llist_head *bsc_subscribers;

	/* Periodic location update default value */
	uint8_t t3212;

	struct {
		struct mgcp_client_conf *conf;
		struct mgcp_client *client;
	} mgw;
};

extern void talloc_ctx_init(void *ctx_root);

int gsm_set_bts_type(struct gsm_bts *bts, enum gsm_bts_type type);

enum gsm_bts_type parse_btstype(const char *arg);
const char *btstype2str(enum gsm_bts_type type);
struct gsm_bts *gsm_bts_by_lac(struct gsm_network *net, unsigned int lac,
				struct gsm_bts *start_bts);

extern void *tall_bsc_ctx;
extern int ipacc_rtp_direct;

/* this actaully refers to the IPA transport, not the BTS model */
static inline int is_ipaccess_bts(struct gsm_bts *bts)
{
	switch (bts->type) {
	case GSM_BTS_TYPE_NANOBTS:
	case GSM_BTS_TYPE_OSMOBTS:
		return 1;
	default:
		break;
	}
	return 0;
}

static inline int is_sysmobts_v2(struct gsm_bts *bts)
{
	switch (bts->type) {
	case GSM_BTS_TYPE_OSMOBTS:
		return 1;
	default:
		break;
	}
	return 0;
}

static inline int is_siemens_bts(struct gsm_bts *bts)
{
	switch (bts->type) {
	case GSM_BTS_TYPE_BS11:
		return 1;
	default:
		break;
	}

	return 0;
}

static inline int is_nokia_bts(struct gsm_bts *bts)
{
	switch (bts->type) {
	case GSM_BTS_TYPE_NOKIA_SITE:
		return 1;
	default:
		break;
	}

	return 0;
}

static inline int is_e1_bts(struct gsm_bts *bts)
{
	switch (bts->type) {
	case GSM_BTS_TYPE_BS11:
	case GSM_BTS_TYPE_RBS2000:
	case GSM_BTS_TYPE_NOKIA_SITE:
		return 1;
	default:
		break;
	}

	return 0;
}

enum bts_gprs_mode bts_gprs_mode_parse(const char *arg, int *valid);
const char *bts_gprs_mode_name(enum bts_gprs_mode mode);
int bts_gprs_mode_is_compat(struct gsm_bts *bts, enum bts_gprs_mode mode);

int gsm48_ra_id_by_bts(uint8_t *buf, struct gsm_bts *bts);
void gprs_ra_id_by_bts(struct gprs_ra_id *raid, struct gsm_bts *bts);

int gsm_btsmodel_set_feature(struct gsm_bts_model *model, enum gsm_bts_features feat);
int gsm_bts_model_register(struct gsm_bts_model *model);

struct gsm_subscriber_connection *bsc_subscr_con_allocate(struct gsm_lchan *lchan);
void bsc_subscr_con_free(struct gsm_subscriber_connection *conn);

struct gsm_subscriber_connection *msc_subscr_con_allocate(struct gsm_network *network);
void msc_subscr_con_free(struct gsm_subscriber_connection *conn);

struct gsm_bts *gsm_bts_alloc_register(struct gsm_network *net,
					enum gsm_bts_type type,
					uint8_t bsic);

void set_ts_e1link(struct gsm_bts_trx_ts *ts, uint8_t e1_nr,
		   uint8_t e1_ts, uint8_t e1_ts_ss);

void gsm_trx_lock_rf(struct gsm_bts_trx *trx, bool locked, const char *reason);
bool gsm_btsmodel_has_feature(struct gsm_bts_model *model, enum gsm_bts_features feat);
struct gsm_bts_trx *gsm_bts_trx_by_nr(struct gsm_bts *bts, int nr);
int gsm_bts_trx_set_system_infos(struct gsm_bts_trx *trx);
int gsm_bts_set_system_infos(struct gsm_bts *bts);

/* generic E1 line operations for all ISDN-based BTS. */
extern struct e1inp_line_ops bts_isdn_e1inp_line_ops;

extern const struct value_string bts_type_names[_NUM_GSM_BTS_TYPE+1];
extern const struct value_string bts_type_descs[_NUM_GSM_BTS_TYPE+1];

char *get_model_oml_status(const struct gsm_bts *bts);

unsigned long long bts_uptime(const struct gsm_bts *bts);

/* control interface handling */
int bsc_base_ctrl_cmds_install(void);

/* dependency handling */
void bts_depend_mark(struct gsm_bts *bts, int dep);
void bts_depend_clear(struct gsm_bts *bts, int dep);
int bts_depend_check(struct gsm_bts *bts);
int bts_depend_is_depedency(struct gsm_bts *base, struct gsm_bts *other);

int gsm_bts_get_radio_link_timeout(const struct gsm_bts *bts);
void gsm_bts_set_radio_link_timeout(struct gsm_bts *bts, int value);

bool classmark_is_r99(struct gsm_classmark *cm);

#endif /* _GSM_DATA_H */
