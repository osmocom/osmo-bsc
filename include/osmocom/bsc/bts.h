#pragma once

#include <stdint.h>
#include <sys/types.h>
#include <stdbool.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/bitvec.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/gsm/bts_features.h>

#include <osmocom/abis/e1_input.h>

#include "osmocom/bsc/gsm_data.h"
#include "osmocom/bsc/bts_trx.h"
#include "osmocom/bsc/bts_sm.h"

enum bts_counter_id {
	BTS_CTR_CHREQ_TOTAL,
	BTS_CTR_CHREQ_SUCCESSFUL,
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
	BTS_CTR_PAGING_NO_ACTIVE_PAGING,
	BTS_CTR_PAGING_MSC_FLUSH,
	BTS_CTR_CHAN_ACT_TOTAL,
	BTS_CTR_CHAN_ACT_NACK,
	BTS_CTR_RSL_UNKNOWN,
	BTS_CTR_RSL_IPA_NACK,
	BTS_CTR_RSL_DELETE_IND,
	BTS_CTR_MODE_MODIFY_NACK,
	BTS_CTR_LCHAN_BORKEN_FROM_UNUSED,
	BTS_CTR_LCHAN_BORKEN_FROM_WAIT_ACTIV_ACK,
	BTS_CTR_LCHAN_BORKEN_FROM_WAIT_RF_RELEASE_ACK,
	BTS_CTR_LCHAN_BORKEN_FROM_BORKEN,
	BTS_CTR_LCHAN_BORKEN_FROM_UNKNOWN,
	BTS_CTR_LCHAN_BORKEN_EV_CHAN_ACTIV_ACK,
	BTS_CTR_LCHAN_BORKEN_EV_CHAN_ACTIV_NACK,
	BTS_CTR_LCHAN_BORKEN_EV_RF_CHAN_REL_ACK,
	BTS_CTR_LCHAN_BORKEN_EV_VTY,
	BTS_CTR_LCHAN_BORKEN_EV_TEARDOWN,
	BTS_CTR_LCHAN_BORKEN_FROM_WAIT_RR_CHAN_MODE_MODIFY_ACK,
	BTS_CTR_LCHAN_BORKEN_FROM_WAIT_RSL_CHAN_MODE_MODIFY_ACK,
	BTS_CTR_TS_BORKEN_FROM_NOT_INITIALIZED,
	BTS_CTR_TS_BORKEN_FROM_UNUSED,
	BTS_CTR_TS_BORKEN_FROM_WAIT_PDCH_ACT,
	BTS_CTR_TS_BORKEN_FROM_PDCH,
	BTS_CTR_TS_BORKEN_FROM_WAIT_PDCH_DEACT,
	BTS_CTR_TS_BORKEN_FROM_IN_USE,
	BTS_CTR_TS_BORKEN_FROM_BORKEN,
	BTS_CTR_TS_BORKEN_FROM_UNKNOWN,
	BTS_CTR_TS_BORKEN_EV_PDCH_ACT_ACK_NACK,
	BTS_CTR_TS_BORKEN_EV_PDCH_DEACT_ACK_NACK,
	BTS_CTR_TS_BORKEN_EV_TEARDOWN,
	BTS_CTR_ASSIGNMENT_ATTEMPTED,
	BTS_CTR_ASSIGNMENT_COMPLETED,
	BTS_CTR_ASSIGNMENT_STOPPED,
	BTS_CTR_ASSIGNMENT_NO_CHANNEL,
	BTS_CTR_ASSIGNMENT_TIMEOUT,
	BTS_CTR_ASSIGNMENT_FAILED,
	BTS_CTR_ASSIGNMENT_ERROR,
	BTS_CTR_HANDOVER_ATTEMPTED,
	BTS_CTR_HANDOVER_COMPLETED,
	BTS_CTR_HANDOVER_STOPPED,
	BTS_CTR_HANDOVER_NO_CHANNEL,
	BTS_CTR_HANDOVER_TIMEOUT,
	BTS_CTR_HANDOVER_FAILED,
	BTS_CTR_HANDOVER_ERROR,
	BTS_CTR_INTRA_CELL_HO_ATTEMPTED,
	BTS_CTR_INTRA_CELL_HO_COMPLETED,
	BTS_CTR_INTRA_CELL_HO_STOPPED,
	BTS_CTR_INTRA_CELL_HO_NO_CHANNEL,
	BTS_CTR_INTRA_CELL_HO_TIMEOUT,
	BTS_CTR_INTRA_CELL_HO_FAILED,
	BTS_CTR_INTRA_CELL_HO_ERROR,
	BTS_CTR_INTRA_BSC_HO_ATTEMPTED,
	BTS_CTR_INTRA_BSC_HO_COMPLETED,
	BTS_CTR_INTRA_BSC_HO_STOPPED,
	BTS_CTR_INTRA_BSC_HO_NO_CHANNEL,
	BTS_CTR_INTRA_BSC_HO_TIMEOUT,
	BTS_CTR_INTRA_BSC_HO_FAILED,
	BTS_CTR_INTRA_BSC_HO_ERROR,
	BTS_CTR_INTER_BSC_HO_OUT_ATTEMPTED,
	BTS_CTR_INTER_BSC_HO_OUT_COMPLETED,
	BTS_CTR_INTER_BSC_HO_OUT_STOPPED,
	BTS_CTR_INTER_BSC_HO_OUT_TIMEOUT,
	BTS_CTR_INTER_BSC_HO_OUT_FAILED,
	BTS_CTR_INTER_BSC_HO_OUT_ERROR,
	BTS_CTR_INTER_BSC_HO_IN_ATTEMPTED,
	BTS_CTR_INTER_BSC_HO_IN_COMPLETED,
	BTS_CTR_INTER_BSC_HO_IN_STOPPED,
	BTS_CTR_INTER_BSC_HO_IN_NO_CHANNEL,
	BTS_CTR_INTER_BSC_HO_IN_FAILED,
	BTS_CTR_INTER_BSC_HO_IN_TIMEOUT,
	BTS_CTR_INTER_BSC_HO_IN_ERROR,
};

extern const struct rate_ctr_desc bts_ctr_description[];
extern const struct rate_ctr_group_desc bts_ctrg_desc;

enum {
	BTS_STAT_CHAN_LOAD_AVERAGE,
	BTS_STAT_CHAN_CCCH_SDCCH4_USED,
	BTS_STAT_CHAN_CCCH_SDCCH4_TOTAL,
	BTS_STAT_CHAN_TCH_F_USED,
	BTS_STAT_CHAN_TCH_F_TOTAL,
	BTS_STAT_CHAN_TCH_H_USED,
	BTS_STAT_CHAN_TCH_H_TOTAL,
	BTS_STAT_CHAN_SDCCH8_USED,
	BTS_STAT_CHAN_SDCCH8_TOTAL,
	BTS_STAT_CHAN_TCH_F_PDCH_USED,
	BTS_STAT_CHAN_TCH_F_PDCH_TOTAL,
	BTS_STAT_CHAN_CCCH_SDCCH4_CBCH_USED,
	BTS_STAT_CHAN_CCCH_SDCCH4_CBCH_TOTAL,
	BTS_STAT_CHAN_SDCCH8_CBCH_USED,
	BTS_STAT_CHAN_SDCCH8_CBCH_TOTAL,
	BTS_STAT_CHAN_TCH_F_TCH_H_PDCH_USED,
	BTS_STAT_CHAN_TCH_F_TCH_H_PDCH_TOTAL,
	BTS_STAT_T3122,
	BTS_STAT_RACH_BUSY,
	BTS_STAT_RACH_ACCESS,
	BTS_STAT_OML_CONNECTED,
	BTS_STAT_RSL_CONNECTED,
	BTS_STAT_LCHAN_BORKEN,
	BTS_STAT_TS_BORKEN,
};

extern const struct osmo_stat_item_desc bts_stat_desc[];
extern const struct osmo_stat_item_group_desc bts_statg_desc;

enum gsm_bts_type {
	GSM_BTS_TYPE_UNKNOWN,
	GSM_BTS_TYPE_BS11,
	GSM_BTS_TYPE_NANOBTS,
	GSM_BTS_TYPE_RBS2000,
	GSM_BTS_TYPE_NOKIA_SITE,
	GSM_BTS_TYPE_OSMOBTS,
	_NUM_GSM_BTS_TYPE
};
extern const struct value_string bts_type_names[_NUM_GSM_BTS_TYPE+1];
extern const struct value_string bts_type_descs[_NUM_GSM_BTS_TYPE+1];

enum gsm_bts_type_variant {
	BTS_UNKNOWN,
	BTS_OSMO_LITECELL15,
	BTS_OSMO_OCTPHY,
	BTS_OSMO_SYSMO,
	BTS_OSMO_TRX,
	_NUM_BTS_VARIANT
};

/* Used by OML layer for BTS Attribute reporting */
enum bts_attribute {
	BTS_TYPE_VARIANT,
	BTS_SUB_MODEL,
	TRX_PHY_VERSION,
};

struct vty;

struct gsm_bts_model {
	struct llist_head list;

	enum gsm_bts_type type;
	enum gsm_bts_type_variant variant;
	const char *name;

	bool started;
	int (*start)(struct gsm_network *net);
	int (*oml_rcvmsg)(struct msgb *msg);
	char * (*oml_status)(const struct gsm_bts *bts);

	void (*e1line_bind_ops)(struct e1inp_line *line);

	void (*config_write_bts)(struct vty *vty, struct gsm_bts *bts);
	void (*config_write_trx)(struct vty *vty, struct gsm_bts_trx *trx);
	void (*config_write_ts)(struct vty *vty, struct gsm_bts_trx_ts *ts);

	/* Should SI2bis and SI2ter be disabled by default on this BTS model? */
	bool force_combined_si;

	struct tlv_definition nm_att_tlvdef;

	/* features of a given BTS model set via gsm_bts_model_register() locally */
	struct bitvec features;
	uint8_t _features_data[MAX_BTS_FEATURES/8];
};

struct gsm_gprs_cell {
	struct gsm_abis_mo mo;
	uint16_t bvci;
	uint8_t timer[11];
	struct gprs_rlc_cfg rlc_cfg;
};

/* One BTS */
struct gsm_bts {
	/* list header in net->bts_list */
	struct llist_head list;

	/* Geographical location of the BTS */
	struct llist_head loc_list;

	/* number of this BTS in network */
	uint8_t nr;
	/* human readable name / description */
	char *description;
	/* Cell Identity */
	uint16_t cell_identity;
	/* location area code of this BTS */
	uint16_t location_area_code;
	/* Base Station Identification Code (BSIC), lower 3 bits is BCC,
	 * which is used as TSC for the CCCH */
	uint8_t bsic;
	/* type of BTS */
	enum gsm_bts_type type;
	enum gsm_bts_type_variant variant;
	struct gsm_bts_model *model;
	enum gsm_band band;
	char version[MAX_VERSION_LENGTH];
	char sub_model[MAX_VERSION_LENGTH];

	/* features of a given BTS set/reported via OML */
	struct bitvec features;
	uint8_t _features_data[MAX_BTS_FEATURES/8];

	/* Connected PCU version (if any) */
	char pcu_version[MAX_VERSION_LENGTH];

	/* maximum Tx power that the MS is permitted to use in this cell */
	int ms_max_power;

	/* how do we talk OML with this TRX? */
	struct gsm_e1_subslot oml_e1_link;
	uint8_t oml_tei;
	struct e1inp_sign_link *oml_link;
	/* Timer to use for deferred drop of OML link, see \ref ipaccess_drop_oml_deferred */
	struct osmo_timer_list oml_drop_link_timer;
	/* when OML link was established */
	time_t uptime;

	/* Abis network management O&M handle */
	struct abis_nm_h *nmh;

	struct gsm_abis_mo mo;

	/* number of this BTS on given E1 link */
	uint8_t bts_nr;

	/* DTX features of this BTS */
	enum gsm48_dtx_mode dtxu;
	bool dtxd;

	/* paging state and control */
	struct gsm_bts_paging_state paging;

	/* CCCH is on C0 */
	struct gsm_bts_trx *c0;

	struct gsm_bts_sm *site_mgr; /* backpointer */

	/* bitmask of all SI that are present/valid in si_buf */
	uint32_t si_valid;
	/* 3GPP TS 44.018 Table 10.5.2.33b.1 INDEX and COUNT for SI2quater */
	uint8_t si2q_index; /* distinguish individual SI2quater messages */
	uint8_t si2q_count; /* si2q_index for the last (highest indexed) individual SI2quater message */
	/* buffers where we put the pre-computed SI */
	sysinfo_buf_t si_buf[_MAX_SYSINFO_TYPE][SI2Q_MAX_NUM];
	/* offsets used while generating SI2quater */
	size_t e_offset;
	size_t u_offset;
	/* 3GPP TS 08.58 §8.5.1 BCCH INFORMATION. Some nanoBTS fail upon
	 * receival of empty SI disabling unsupported SI. see OS#3707. */
	bool si_unused_send_empty;

	/* ip.access Unit ID's have Site/BTS/TRX layout */
	union {
		struct {
			uint16_t site_id;
			uint16_t bts_id;
			uint32_t flags;
			uint32_t rsl_ip;
		} ip_access;
		struct {
			struct {
				struct gsm_abis_mo mo;
			} cclk;
			struct {
				struct gsm_abis_mo mo;
			} rack;
			struct gsm_envabtse envabtse[4];
		} bs11;
		struct {
			struct {
				struct om2k_mo om2k_mo;
				struct gsm_abis_mo mo;
				struct llist_head conn_groups;
			} cf;
			struct {
				struct om2k_mo om2k_mo;
				struct gsm_abis_mo mo;
				struct llist_head conn_groups;
			} is;
			struct {
				struct om2k_mo om2k_mo;
				struct gsm_abis_mo mo;
				struct llist_head conn_groups;
			} con;
			struct {
				struct om2k_mo om2k_mo;
				struct gsm_abis_mo mo;
			} dp;
			struct {
				struct om2k_mo om2k_mo;
				struct gsm_abis_mo mo;
			} tf;
			struct {
				struct om2k_mo om2k_mo;
				struct gsm_abis_mo mo;
			} mctr;
			uint32_t use_superchannel:1;
			struct {
				uint16_t limit;
				uint16_t active;
			} om2k_version[16];
		} rbs2000;
		struct {
			uint8_t bts_type;
			unsigned int configured:1,	/* we sent the config data request */
				skip_reset:1,		/* skip reset at bootstrap */
				no_loc_rel_cnf:1,	/* don't wait for RSL REL CONF */
				bts_reset_timer_cnf,	/* timer for BTS RESET */
				did_reset:1,		/* we received a RESET ACK */
				wait_reset:2;		/* we are waiting for reset to complete */
			struct osmo_timer_list reset_timer;
		} nokia;
	};

	/* Not entirely sure how ip.access specific this is */
	struct {
		enum bts_gprs_mode mode;
		struct gsm_gprs_cell cell;
		uint8_t rac;
		uint8_t net_ctrl_ord;
		bool ctrl_ack_type_use_block;
		bool egprs_pkt_chan_request;
	} gprs;

	/* threshold (in percent) when BTS shall send CCCH LOAD IND */
	int ccch_load_ind_thresh;

	/* RACH NM values */
	int rach_b_thresh;
	int rach_ldavg_slots;

	/* transceivers */
	int num_trx;
	struct llist_head trx_list;

	/* SI related items */
	int force_combined_si;
	bool force_combined_si_set;
	int bcch_change_mark;

	/* Abis NM queue */
	struct llist_head abis_queue;
	int abis_nm_pend;

	struct gsm_network *network;

	/* should the channel allocator allocate channels from high TRX to TRX0,
	 * rather than starting from TRX0 and go upwards? */
	int chan_alloc_reverse;

	enum neigh_list_manual_mode neigh_list_manual_mode;
	/* parameters from which we build SYSTEM INFORMATION */
	struct {
		struct gsm48_rach_control rach_control;
		uint8_t ncc_permitted;
		struct gsm48_cell_sel_par cell_sel_par;
		struct gsm48_si_selection_params cell_ro_sel_par; /* rest octet */
		struct gsm48_cell_options cell_options;
		struct gsm48_control_channel_descr chan_desc;
		struct bitvec neigh_list;
		struct bitvec cell_alloc;
		struct bitvec si5_neigh_list;
		struct osmo_earfcn_si2q si2quater_neigh_list;
		size_t uarfcn_length; /* index for uarfcn and scramble lists */
		struct {
			/* bitmask large enough for all possible ARFCN's */
			uint8_t neigh_list[1024/8];
			uint8_t cell_alloc[1024/8];
			/* If the user wants a different neighbor list in SI5 than in SI2 */
			uint8_t si5_neigh_list[1024/8];
			uint8_t meas_bw_list[MAX_EARFCN_LIST];
			uint16_t earfcn_list[MAX_EARFCN_LIST];
			uint16_t uarfcn_list[MAX_EARFCN_LIST];
			uint16_t scramble_list[MAX_EARFCN_LIST];
		} data;
	} si_common;
	bool early_classmark_allowed;
	bool early_classmark_allowed_3g;
	/* for testing only: Have an infinitely long radio link timeout */
	bool infinite_radio_link_timeout;

	/* do we use static (user-defined) system information messages? (bitmask) */
	uint32_t si_mode_static;

	/* access control class ramping */
	struct acc_mgr acc_mgr;
	struct acc_ramp acc_ramp;

	/* exclude the BTS from the global RF Lock handling */
	int excl_from_rf_lock;

	/* supported codecs beside FR */
	struct bts_codec_conf codec;

	/* BTS dependencies bit field */
	uint32_t depends_on[256/(8*4)];

	/* full and half rate multirate config */
	struct amr_multirate_conf mr_full;
	struct amr_multirate_conf mr_half;

	/* PCU socket state */
	char *pcu_sock_path;
	struct pcu_sock_state *pcu_state;

	struct rate_ctr_group *bts_ctrs;
	struct osmo_stat_item_group *bts_statg;

	struct handover_cfg *ho;

	/* A list of struct gsm_bts_ref, indicating neighbors of this BTS.
	 * When the si_common neigh_list is in automatic mode, it is populated from this list as well as
	 * gsm_network->neighbor_bss_cells. */
	struct llist_head local_neighbors;

	/* BTS-specific overrides for timer values from struct gsm_network. */
	uint8_t T3122;	/* ASSIGNMENT REJECT wait indication */
	bool T3113_dynamic; /* Calculate T3113 timeout dynamically based on BTS channel config and load */

	/* Periodic channel load measurements are used to maintain T3122. */
	struct load_counter chan_load_samples[7];
	int chan_load_samples_idx;
	uint8_t chan_load_avg; /* current channel load average in percent (0 - 100). */

	/* cell broadcast system */
	struct osmo_timer_list cbch_timer;
	struct bts_smscb_chan_state cbch_basic;
	struct bts_smscb_chan_state cbch_extended;
	struct osmo_timer_list etws_timer;	/* when to stop ETWS PN */

	struct llist_head oml_fail_rep;
	struct llist_head chan_rqd_queue;

	/* osmocom specific FACCH/SACCH repetition mode flags set by VTY to
	 * enable/disable certain ACCH repeation features individually */
	struct abis_rsl_osmo_rep_acch_cap repeated_acch_policy;
};

#define GSM_BTS_SI2Q(bts, i)   (struct gsm48_system_information_type_2quater *)((bts)->si_buf[SYSINFO_TYPE_2quater][i])
#define GSM_BTS_HAS_SI(bts, i) ((bts)->si_valid & (1 << i))
#define GSM_BTS_SI(bts, i)     (void *)((bts)->si_buf[i][0])

/* this actually refers to the IPA transport, not the BTS model */
static inline int is_ipaccess_bts(const struct gsm_bts *bts)
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

static inline int is_sysmobts_v2(const struct gsm_bts *bts)
{
	switch (bts->type) {
	case GSM_BTS_TYPE_OSMOBTS:
		return 1;
	default:
		break;
	}
	return 0;
}

static inline int is_siemens_bts(const struct gsm_bts *bts)
{
	switch (bts->type) {
	case GSM_BTS_TYPE_BS11:
		return 1;
	default:
		break;
	}

	return 0;
}

static inline int is_nokia_bts(const struct gsm_bts *bts)
{
	switch (bts->type) {
	case GSM_BTS_TYPE_NOKIA_SITE:
		return 1;
	default:
		break;
	}

	return 0;
}

static inline int is_ericsson_bts(const struct gsm_bts *bts)
{
	switch (bts->type) {
	case GSM_BTS_TYPE_RBS2000:
		return 1;
	default:
		break;
	}

	return 0;
}

static inline int is_e1_bts(const struct gsm_bts *bts)
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

static inline const struct osmo_location_area_id *bts_lai(struct gsm_bts *bts)
{
	static struct osmo_location_area_id lai;
	lai = (struct osmo_location_area_id){
		.plmn = bts->network->plmn,
		.lac = bts->location_area_code,
	};
	return &lai;
}

struct gsm_bts *gsm_bts_alloc(struct gsm_network *net, struct gsm_bts_sm *bts_sm, uint8_t bts_num);

char *gsm_bts_name(const struct gsm_bts *bts);

bool gsm_bts_matches_lai(const struct gsm_bts *bts, const struct osmo_location_area_id *lai);
bool gsm_bts_matches_cell_id(const struct gsm_bts *bts, const struct gsm0808_cell_id *cell_id);

int gsm_bts_local_neighbor_add(struct gsm_bts *bts, struct gsm_bts *neighbor);
int gsm_bts_local_neighbor_del(struct gsm_bts *bts, const struct gsm_bts *neighbor);

/* return the gsm_lchan for the CBCH (if it exists at all) */
struct gsm_lchan *gsm_bts_get_cbch(struct gsm_bts *bts);

int gsm_set_bts_type(struct gsm_bts *bts, enum gsm_bts_type type);

struct gsm_bts_trx *gsm_bts_trx_num(const struct gsm_bts *bts, int num);

int bts_gprs_mode_is_compat(struct gsm_bts *bts, enum bts_gprs_mode mode);

unsigned long long bts_uptime(const struct gsm_bts *bts);

char *get_model_oml_status(const struct gsm_bts *bts);
/* reset the state of all MO in the BTS */
void gsm_bts_mo_reset(struct gsm_bts *bts);

/* dependency handling */
void bts_depend_mark(struct gsm_bts *bts, int dep);
void bts_depend_clear(struct gsm_bts *bts, int dep);
int bts_depend_check(struct gsm_bts *bts);
int bts_depend_is_depedency(struct gsm_bts *base, struct gsm_bts *other);

int gsm_bts_get_radio_link_timeout(const struct gsm_bts *bts);
void gsm_bts_set_radio_link_timeout(struct gsm_bts *bts, int value);

void gsm_bts_all_ts_dispatch(struct gsm_bts *bts, uint32_t ts_ev, void *data);

int bts_count_free_ts(struct gsm_bts *bts, enum gsm_phys_chan_config pchan);

int gsm_bts_set_system_infos(struct gsm_bts *bts);

int gsm_bts_model_register(struct gsm_bts_model *model);
struct gsm_bts_model *bts_model_find(enum gsm_bts_type type);

enum gsm_bts_type str2btstype(const char *arg);
const char *btstype2str(enum gsm_bts_type type);

enum bts_attribute str2btsattr(const char *s);
const char *btsatttr2str(enum bts_attribute v);

enum gsm_bts_type_variant str2btsvariant(const char *arg);
const char *btsvariant2str(enum gsm_bts_type_variant v);
