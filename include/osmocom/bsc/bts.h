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

#include "osmocom/bsc/power_control.h"
#include "osmocom/bsc/gsm_data.h"
#include "osmocom/bsc/bts_trx.h"
#include "osmocom/bsc/bts_sm.h"
#include "osmocom/bsc/abis_om2000.h"
#include "osmocom/bsc/paging.h"

enum bts_counter_id {
	BTS_CTR_CHREQ_TOTAL,
	BTS_CTR_CHREQ_ATTEMPTED_EMERG,
	BTS_CTR_CHREQ_ATTEMPTED_CALL,
	BTS_CTR_CHREQ_ATTEMPTED_LOCATION_UPD,
	BTS_CTR_CHREQ_ATTEMPTED_PAG,
	BTS_CTR_CHREQ_ATTEMPTED_PDCH,
	BTS_CTR_CHREQ_ATTEMPTED_OTHER,
	BTS_CTR_CHREQ_ATTEMPTED_UNKNOWN,
	BTS_CTR_CHREQ_SUCCESSFUL,
	BTS_CTR_CHREQ_SUCCESSFUL_EMERG,
	BTS_CTR_CHREQ_SUCCESSFUL_CALL,
	BTS_CTR_CHREQ_SUCCESSFUL_LOCATION_UPD,
	BTS_CTR_CHREQ_SUCCESSFUL_PAG,
	BTS_CTR_CHREQ_SUCCESSFUL_PDCH,
	BTS_CTR_CHREQ_SUCCESSFUL_OTHER,
	BTS_CTR_CHREQ_SUCCESSFUL_UNKNOWN,
	BTS_CTR_CHREQ_NO_CHANNEL,
	BTS_CTR_CHREQ_MAX_DELAY_EXCEEDED,
	BTS_CTR_CHAN_RF_FAIL,
	BTS_CTR_CHAN_RF_FAIL_TCH,
	BTS_CTR_CHAN_RF_FAIL_SDCCH,
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
	BTS_CTR_PAGING_OVERLOAD,
	BTS_CTR_CHAN_ACT_TOTAL,
	BTS_CTR_CHAN_ACT_SDCCH,
	BTS_CTR_CHAN_ACT_TCH,
	BTS_CTR_CHAN_ACT_NACK,
	BTS_CTR_CHAN_TCH_ACTIVE_MILLISECONDS_TOTAL,
	BTS_CTR_CHAN_SDCCH_ACTIVE_MILLISECONDS_TOTAL,
	BTS_CTR_CHAN_TCH_FULLY_ESTABLISHED,
	BTS_CTR_CHAN_SDCCH_FULLY_ESTABLISHED,
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
	BTS_CTR_LCHAN_BORKEN_EV_TS_ERROR,
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
	BTS_CTR_ASSIGNMENT_ATTEMPTED_SIGN,
	BTS_CTR_ASSIGNMENT_ATTEMPTED_SPEECH,
	BTS_CTR_ASSIGNMENT_COMPLETED,
	BTS_CTR_ASSIGNMENT_COMPLETED_SIGN,
	BTS_CTR_ASSIGNMENT_COMPLETED_SPEECH,
	BTS_CTR_ASSIGNMENT_STOPPED,
	BTS_CTR_ASSIGNMENT_STOPPED_SIGN,
	BTS_CTR_ASSIGNMENT_STOPPED_SPEECH,
	BTS_CTR_ASSIGNMENT_NO_CHANNEL,
	BTS_CTR_ASSIGNMENT_NO_CHANNEL_SIGN,
	BTS_CTR_ASSIGNMENT_NO_CHANNEL_SPEECH,
	BTS_CTR_ASSIGNMENT_TIMEOUT,
	BTS_CTR_ASSIGNMENT_TIMEOUT_SIGN,
	BTS_CTR_ASSIGNMENT_TIMEOUT_SPEECH,
	BTS_CTR_ASSIGNMENT_FAILED,
	BTS_CTR_ASSIGNMENT_FAILED_SIGN,
	BTS_CTR_ASSIGNMENT_FAILED_SPEECH,
	BTS_CTR_ASSIGNMENT_ERROR,
	BTS_CTR_ASSIGNMENT_ERROR_SIGN,
	BTS_CTR_ASSIGNMENT_ERROR_SPEECH,
	BTS_CTR_LOCATION_UPDATE_ACCEPT,
	BTS_CTR_LOCATION_UPDATE_REJECT,
	BTS_CTR_LOCATION_UPDATE_DETACH,
	BTS_CTR_LOCATION_UPDATE_UNKNOWN,
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
	BTS_CTR_INCOMING_INTRA_BSC_HO_ATTEMPTED,
	BTS_CTR_INCOMING_INTRA_BSC_HO_COMPLETED,
	BTS_CTR_INCOMING_INTRA_BSC_HO_STOPPED,
	BTS_CTR_INCOMING_INTRA_BSC_HO_NO_CHANNEL,
	BTS_CTR_INCOMING_INTRA_BSC_HO_TIMEOUT,
	BTS_CTR_INCOMING_INTRA_BSC_HO_FAILED,
	BTS_CTR_INCOMING_INTRA_BSC_HO_ERROR,
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
	BTS_CTR_SRVCC_ATTEMPTED,
	BTS_CTR_SRVCC_COMPLETED,
	BTS_CTR_SRVCC_STOPPED,
	BTS_CTR_SRVCC_NO_CHANNEL,
	BTS_CTR_SRVCC_TIMEOUT,
	BTS_CTR_SRVCC_FAILED,
	BTS_CTR_SRVCC_ERROR,
	BTS_CTR_ALL_ALLOCATED_SDCCH,
	BTS_CTR_ALL_ALLOCATED_STATIC_SDCCH,
	BTS_CTR_ALL_ALLOCATED_TCH,
	BTS_CTR_ALL_ALLOCATED_STATIC_TCH,
	BTS_CTR_CM_SERV_REJ,
	BTS_CTR_CM_SERV_REJ_IMSI_UNKNOWN_IN_HLR,
	BTS_CTR_CM_SERV_REJ_ILLEGAL_MS,
	BTS_CTR_CM_SERV_REJ_IMSI_UNKNOWN_IN_VLR,
	BTS_CTR_CM_SERV_REJ_IMEI_NOT_ACCEPTED,
	BTS_CTR_CM_SERV_REJ_ILLEGAL_ME,
	BTS_CTR_CM_SERV_REJ_PLMN_NOT_ALLOWED,
	BTS_CTR_CM_SERV_REJ_LOC_NOT_ALLOWED,
	BTS_CTR_CM_SERV_REJ_ROAMING_NOT_ALLOWED,
	BTS_CTR_CM_SERV_REJ_NETWORK_FAILURE,
	BTS_CTR_CM_SERV_REJ_SYNCH_FAILURE,
	BTS_CTR_CM_SERV_REJ_CONGESTION,
	BTS_CTR_CM_SERV_REJ_SRV_OPT_NOT_SUPPORTED,
	BTS_CTR_CM_SERV_REJ_RQD_SRV_OPT_NOT_SUPPORTED,
	BTS_CTR_CM_SERV_REJ_SRV_OPT_TMP_OUT_OF_ORDER,
	BTS_CTR_CM_SERV_REJ_CALL_CAN_NOT_BE_IDENTIFIED,
	BTS_CTR_CM_SERV_REJ_INCORRECT_MESSAGE,
	BTS_CTR_CM_SERV_REJ_INVALID_MANDANTORY_INF,
	BTS_CTR_CM_SERV_REJ_MSG_TYPE_NOT_IMPLEMENTED,
	BTS_CTR_CM_SERV_REJ_MSG_TYPE_NOT_COMPATIBLE,
	BTS_CTR_CM_SERV_REJ_INF_ELEME_NOT_IMPLEMENTED,
	BTS_CTR_CM_SERV_REJ_CONDTIONAL_IE_ERROR,
	BTS_CTR_CM_SERV_REJ_MSG_NOT_COMPATIBLE,
	BTS_CTR_CM_SERV_REJ_PROTOCOL_ERROR,
	BTS_CTR_CM_SERV_REJ_RETRY_IN_NEW_CELL,
};

extern const struct rate_ctr_desc bts_ctr_description[];
extern const struct rate_ctr_group_desc bts_ctrg_desc;

enum {
	BTS_STAT_UPTIME_SECONDS,
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
	BTS_STAT_CHAN_OSMO_DYN_USED,
	BTS_STAT_CHAN_OSMO_DYN_TOTAL,
	BTS_STAT_T3122,
	BTS_STAT_RACH_BUSY,
	BTS_STAT_RACH_ACCESS,
	BTS_STAT_OML_CONNECTED,
	BTS_STAT_RSL_CONNECTED,
	BTS_STAT_LCHAN_BORKEN,
	BTS_STAT_TS_BORKEN,
	BTS_STAT_NUM_TRX_RSL_CONNECTED,
	BTS_STAT_NUM_TRX_TOTAL,
	BTS_STAT_T3113,
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

enum bts_tch_signalling_policy {
	BTS_TCH_SIGNALLING_NEVER,
	BTS_TCH_SIGNALLING_EMERG,
	BTS_TCH_SIGNALLING_VOICE,
	BTS_TCH_SIGNALLING_ALWAYS,
};

struct vty;

struct gsm_bts_model {
	struct llist_head list;

	enum gsm_bts_type type;
	enum gsm_bts_type_variant variant;
	const char *name;

	bool started;
	/* start the model itself */
	int (*start)(struct gsm_network *net);

	/* initialize a single BTS for this model */
	int (*bts_init)(struct gsm_bts *bts);

	/* initialize a single TRX for this model */
	int (*trx_init)(struct gsm_bts_trx *trx);

	int (*oml_rcvmsg)(struct msgb *msg);
	char * (*oml_status)(const struct gsm_bts *bts);

	void (*e1line_bind_ops)(struct e1inp_line *line);

	/* (Optional) function for encoding MS/BS Power Control paramaters */
	int (*power_ctrl_enc_rsl_params)(struct msgb *msg, const struct gsm_power_ctrl_params *cp);
	/* (Optional) function for sending default MS/BS Power Control paramaters */
	int (*power_ctrl_send_def_params)(const struct gsm_bts_trx *trx);
	/* (Optional) function for toggling BCCH carrier power reduction operation */
	int (*power_ctrl_set_c0_power_red)(const struct gsm_bts *bts, const uint8_t red);

	void (*config_write_bts)(struct vty *vty, struct gsm_bts *bts);
	void (*config_write_trx)(struct vty *vty, struct gsm_bts_trx *trx);
	void (*config_write_ts)(struct vty *vty, struct gsm_bts_trx_ts *ts);

	/* Should SI2bis and SI2ter be disabled by default on this BTS model? */
	bool force_combined_si;

	struct tlv_definition nm_att_tlvdef;

	/* features of a given BTS model set via gsm_bts_model_register()
	 * locally, see doc/bts-features.txt */
	struct bitvec features;
	uint8_t _features_data[MAX_BTS_FEATURES/8];
	/* BTS reports features during OML bring up */
	bool features_get_reported;
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

	/* features of a given BTS either hardcoded or set/reported via OML,
	 * see doc/bts-features.txt */
	struct bitvec features;
	uint8_t _features_data[MAX_BTS_FEATURES/8];
	/* Features have been reported by the BTS or were copied from the BTS
	 * model */
	bool features_known;

	/* Connected PCU version (if any) */
	char pcu_version[MAX_VERSION_LENGTH];
	/* PCU sign_link, over OML line: */
	struct e1inp_sign_link *osmo_link;

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
			struct osmo_fsm_inst *bts_fi;
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
			enum om2k_sync_src sync_src;
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
		struct {
			bool active; /* CCN_ACTIVE */
			bool forced_vty; /* set by VTY ? */
		} ccn; /* TS 44.060 sec 8.8.2 */
		struct {
			uint8_t alpha; /* ALPHA*10, units of 0.1, range <0-10> */
		} pwr_ctrl; /* TS 44.060 Table 12.9.1 */
	} gprs;

	/* CCCH Load Threshold: threshold (in percent) when BTS shall send CCCH LOAD IND */
	uint8_t ccch_load_ind_thresh;
	/* CCCH Load Indication Period: how often (secs) to send CCCH LOAD IND when over CCCH Load Threshold. */
	uint8_t ccch_load_ind_period;

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
	bool chan_alloc_chan_req_reverse;
	bool chan_alloc_assignment_reverse;
	bool chan_alloc_handover_reverse;

	/* Whether to use dynamic allocation mode for assignment */
	bool chan_alloc_assignment_dynamic;
	/* Parameters used for dynamic mode of allocation */
	struct {
		bool sort_by_trx_power;
		uint8_t ul_rxlev_thresh;
		uint8_t ul_rxlev_avg_num;
		uint8_t c0_chan_load_thresh;
	} chan_alloc_dyn_params;

	/* When true, interference measurements from the BTS are used in the channel allocator to favor lchans with less
	 * interference reported in RSL Resource Indication. */
	bool chan_alloc_avoid_interf;

	/* If SDCCHs are exhausted, when can we use TCH for signalling purposes. */
	enum bts_tch_signalling_policy chan_alloc_tch_signalling_policy;

	enum neigh_list_manual_mode neigh_list_manual_mode;
	/* parameters from which we build SYSTEM INFORMATION */
	struct {
		struct gsm48_rach_control rach_control;
		uint8_t ncc_permitted;
		struct gsm48_cell_sel_par cell_sel_par;
		struct osmo_gsm48_si_selection_params cell_ro_sel_par; /* rest octet */
		struct gsm48_cell_options cell_options;
		struct gsm48_control_channel_descr chan_desc;
		struct bitvec neigh_list;
		struct bitvec cell_alloc;
		struct bitvec si5_neigh_list;
		struct osmo_earfcn_si2q si2quater_neigh_list;
		size_t uarfcn_length; /* index for uarfcn and scramble lists */
		size_t cell_chan_num; /* number of channels in Cell Allocation */
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

	/* Local and remote neighbor configuration: a list of neighbors as written in the VTY config, not resolved to
	 * actual cells. Entries may point at non-existing BTS numbers, or yet unconfigured ARFCN+BSIC. The point of
	 * this list is to keep the config as the user entered it: a) to write it back exactly as entered, and b) to
	 * allow adding neighbor cells that will only be configured further down in the config file.
	 * An actual neighbor cell object (local or remote-BSS) is resolved "at runtime" whenever a neighbor is being
	 * looked up. */
	struct llist_head neighbors;

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
	struct bts_etws_state etws;

	struct llist_head oml_fail_rep;
	struct llist_head chan_rqd_queue;

	/* ACCH Repetition capabilities */
	struct abis_rsl_osmo_rep_acch_cap rep_acch_cap;

	/* ACCH Temporary overpower capabilities */
	struct abis_rsl_osmo_temp_ovp_acch_cap top_acch_cap;
	/* Channel mode(s) for which to allow TOP */
	enum {
		TOP_ACCH_CHAN_MODE_ANY = 0,	/* Any kind of channel mode */
		TOP_ACCH_CHAN_MODE_SPEECH_V3,	/* Speech channels using AMR codec */
	} top_acch_chan_mode;

	/* MS/BS Power Control parameters */
	struct gsm_power_ctrl_params ms_power_ctrl;
	struct gsm_power_ctrl_params bs_power_ctrl;

	/* Maximum BCCH carrier power reduction */
	uint8_t c0_max_power_red_db;

	/* Interference Measurement Parameters, as read from VTY */
	struct gsm_interf_meas_params interf_meas_params_cfg;
	/* Interference Measurement Parameters, as last sent via OML */
	struct gsm_interf_meas_params interf_meas_params_used;

	/* We will ignore CHAN RQD with access delay greater than rach_max_delay */
	uint8_t rach_max_delay;

	/* Is Fast return to LTE allowed during Chan Release in this BTS? */
	bool srvcc_fast_return_allowed;

	/* At what point in the channel allocation sequence to dispatch the Immediate Assignment (Abis optimization) */
	enum imm_ass_time imm_ass_time;

	struct chan_counts chan_counts;
	struct all_allocated all_allocated;
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

static inline int is_osmobts(const struct gsm_bts *bts)
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
int gsm_bts_check_cfg(struct gsm_bts *bts);

char *gsm_bts_name(const struct gsm_bts *bts);

bool gsm_bts_matches_lai(const struct gsm_bts *bts, const struct osmo_location_area_id *lai);
bool gsm_bts_matches_cell_id(const struct gsm_bts *bts, const struct gsm0808_cell_id *cell_id);
void gsm_bts_cell_id(struct gsm0808_cell_id *cell_id, const struct gsm_bts *bts);
void gsm_bts_cell_id_list(struct gsm0808_cell_id_list2 *cell_id_list, const struct gsm_bts *bts);

int gsm_bts_local_neighbor_add(struct gsm_bts *bts, struct gsm_bts *neighbor);
int gsm_bts_local_neighbor_del(struct gsm_bts *bts, const struct gsm_bts *neighbor);

/* return the gsm_lchan for the CBCH (if it exists at all) */
struct gsm_lchan *gsm_bts_get_cbch(struct gsm_bts *bts);

int gsm_set_bts_model(struct gsm_bts *bts, struct gsm_bts_model *model);
int gsm_set_bts_type(struct gsm_bts *bts, enum gsm_bts_type type);

struct gsm_bts_trx *gsm_bts_trx_num(const struct gsm_bts *bts, int num);

int bts_gprs_mode_is_compat(struct gsm_bts *bts, enum bts_gprs_mode mode);

#define BTS_STORE_UPTIME_INTERVAL 10 /* in seconds */
void bts_store_uptime(struct gsm_bts *bts);

unsigned long long bts_uptime(const struct gsm_bts *bts);

#define BTS_STORE_LCHAN_DURATIONS_INTERVAL 1 /* in seconds */
void bts_store_lchan_durations(struct gsm_bts *bts);

char *get_model_oml_status(const struct gsm_bts *bts);
/* reset the state of all MO in the BTS */
void gsm_bts_mo_reset(struct gsm_bts *bts);

static inline bool gsm_bts_features_negotiated(struct gsm_bts *bts)
{
	return bts->mo.get_attr_rep_received || bts->mo.nm_state.operational == NM_OPSTATE_ENABLED;
}

/* dependency handling */
void bts_depend_mark(struct gsm_bts *bts, int dep);
void bts_depend_clear(struct gsm_bts *bts, int dep);
int bts_depend_check(struct gsm_bts *bts);
int bts_depend_is_depedency(struct gsm_bts *base, struct gsm_bts *other);

int gsm_bts_get_radio_link_timeout(const struct gsm_bts *bts);
void gsm_bts_set_radio_link_timeout(struct gsm_bts *bts, int value);

void gsm_bts_all_ts_dispatch(struct gsm_bts *bts, uint32_t ts_ev, void *data);

int gsm_bts_set_system_infos(struct gsm_bts *bts);

int gsm_bts_set_c0_power_red(struct gsm_bts *bts, const uint8_t red);

void gsm_bts_stats_reset(struct gsm_bts *bts);

int gsm_bts_model_register(struct gsm_bts_model *model);
struct gsm_bts_model *bts_model_find(enum gsm_bts_type type);

enum gsm_bts_type str2btstype(const char *arg);
const char *btstype2str(enum gsm_bts_type type);

enum bts_attribute str2btsattr(const char *s);
const char *btsatttr2str(enum bts_attribute v);

enum gsm_bts_type_variant str2btsvariant(const char *arg);
const char *btsvariant2str(enum gsm_bts_type_variant v);
