#ifndef _GSM_DATA_H
#define _GSM_DATA_H

#include <stdint.h>
#include <regex.h>
#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>

#include <osmocom/core/timer.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/select.h>
#include <osmocom/core/stats.h>
#include <osmocom/core/stat_item.h>
#include <osmocom/gsm/bts_features.h>
#include <osmocom/gsm/protocol/gsm_08_08.h>
#include <osmocom/gsm/gsm48.h>
#include <osmocom/core/fsm.h>

#include <osmocom/crypt/auth.h>

#include <osmocom/bsc/rest_octets.h>
#include <osmocom/bsc/handover.h>

#include <osmocom/core/bitvec.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/gsm/rxlev_stat.h>
#include <osmocom/gsm/protocol/gsm_08_58.h>
#include <osmocom/gsm/protocol/gsm_12_21.h>
#include <osmocom/abis/e1_input.h>
#include <osmocom/bsc/meas_rep.h>
#include <osmocom/bsc/bsc_msg_filter.h>
#include <osmocom/bsc/acc_ramp.h>

struct mgcp_client_conf;
struct mgcp_client;
struct mgcp_ctx;

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
/* Maximum number of report history we store */
#define MAX_MEAS_REP		10

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

enum subscr_sccp_state {
	SUBSCR_SCCP_ST_NONE,
	SUBSCR_SCCP_ST_WAIT_CONN_CONF,
	SUBSCR_SCCP_ST_CONNECTED
};

/* active radio connection of a mobile subscriber */
struct gsm_subscriber_connection {
	/* global linked list of subscriber_connections */
	struct llist_head entry;

	/* FSM instance to control the subscriber connection state (RTP, A) */
	struct osmo_fsm_inst *fi;

	/* libbsc subscriber information (if available) */
	struct bsc_subscr *bsub;

	/* back pointers */
	struct gsm_network *network;

	/* the primary / currently active lchan to the BTS/subscriber */
	struct gsm_lchan *lchan;

	/* handover information, if a handover is pending for this conn. */
	struct bsc_handover *ho;

	/* timer for assignment handling */
	struct osmo_timer_list T10;
	/* the future allocated but not yet used lchan during ASSIGNMENT */
	struct gsm_lchan *secondary_lchan;

	/* buffer/cache for classmark of the ME of the subscriber */
	struct gsm_classmark classmark;

	/* Cache DTAP messages during handover/assignment (msgb_enqueue()/msgb_dequeue())*/
	struct llist_head ho_dtap_cache;
	unsigned int ho_dtap_cache_len;

	struct {
		int failures;
		struct penalty_timers *penalty_timers;
	} hodec2;

	/* "Codec List (MSC Preferred)" as received by the BSSAP Assignment Request. 3GPP 48.008
	 * 3.2.2.103 says:
	 *         The "Codec List (MSC Preferred)" shall not include codecs
	 *         that are not supported by the MS.
	 * i.e. by heeding the "Codec list (MSC Preferred)", we inherently heed the MS bearer
	 * capabilities, which the MSC is required to translate into the codec list. */
	struct gsm0808_speech_codec_list codec_list;
	bool codec_list_present;

	/* flag to prevent multiple simultaneous ciphering commands */
	int ciphering_handled;

	/* state related to welcome USSD */
	uint8_t new_subscriber;

	/* state related to osmo_bsc_filter.c */
	struct bsc_filter_state filter_state;

	/* SCCP connection associatd with this subscriber_connection */
	struct {
		/* for advanced ping/pong */
		int send_ping;

		/* SCCP connection realted */
		struct bsc_msc_data *msc;

		/* Sigtran connection ID */
		int conn_id;
		enum subscr_sccp_state state;
	} sccp;

	/* for audio handling */
	struct {
		uint16_t cic;
		uint32_t rtp_ip;
		int rtp_port;
		/* RTP address of the remote end (assigned by MSC through assignment request) */
		struct sockaddr_storage aoip_rtp_addr_remote;

		/* Local RTP address (reported back to the MSC by us with the
		 * assignment complete message) */
		struct sockaddr_storage aoip_rtp_addr_local;

		/* FSM instance to control the BTS sided RTP connection */
		struct osmo_fsm_inst *fi_bts;

		/* FSM instance to control the MSC sided RTP connection */
		struct osmo_fsm_inst *fi_msc;

		/* Endpoint identifier of the MGCP endpoint the connection uses */
		char *mgw_endpoint;

		/* Channel rate flag, FR=1, HR=0, Invalid=-1 */
		int full_rate;

		/* Channel mode flag (signaling or voice channel) */
		enum gsm48_chan_mode chan_mode;

	} user_plane;
};


/* 16 is the max. number of SI2quater messages according to 3GPP TS 44.018 Table 10.5.2.33b.1:
   4-bit index is used (2#1111 = 10#15) */
#define SI2Q_MAX_NUM 16
/* length in bits (for single SI2quater message) */
#define SI2Q_MAX_LEN 160
#define SI2Q_MIN_LEN 18

struct osmo_bsc_data;

struct osmo_bsc_sccp_con;

/* Channel Request reason */
enum gsm_chreq_reason_t {
	GSM_CHREQ_REASON_EMERG,
	GSM_CHREQ_REASON_PAG,
	GSM_CHREQ_REASON_CALL,
	GSM_CHREQ_REASON_LOCATION_UPD,
	GSM_CHREQ_REASON_OTHER,
	GSM_CHREQ_REASON_PDCH,
};

/* lchans 0..3 are SDCCH in combined channel configuration,
   use 4 as magic number for BCCH hack - see osmo-bts-../oml.c:opstart_compl() */
#define CCCH_LCHAN 4

#define TRX_NR_TS	8
#define TS_MAX_LCHAN	8

#define HARDCODED_ARFCN 123
#define HARDCODED_BSIC	0x3f	/* NCC = 7 / BCC = 7 */

/* for multi-drop config */
#define HARDCODED_BTS0_TS	1
#define HARDCODED_BTS1_TS	6
#define HARDCODED_BTS2_TS	11

#define MAX_VERSION_LENGTH 64

enum gsm_hooks {
	GSM_HOOK_NM_SWLOAD,
	GSM_HOOK_RR_PAGING,
	GSM_HOOK_RR_SECURITY,
};

enum gsm_paging_event {
	GSM_PAGING_SUCCEEDED,
	GSM_PAGING_EXPIRED,
	GSM_PAGING_OOM,
	GSM_PAGING_BUSY,
};

enum bts_gprs_mode {
	BTS_GPRS_NONE = 0,
	BTS_GPRS_GPRS = 1,
	BTS_GPRS_EGPRS = 2,
};

struct gsm_lchan;
struct osmo_rtp_socket;
struct rtp_socket;
struct bsc_api;

/* Network Management State */
struct gsm_nm_state {
	uint8_t operational;
	uint8_t administrative;
	uint8_t availability;
};

struct gsm_abis_mo {
	uint8_t obj_class;
	uint8_t procedure_pending;
	struct abis_om_obj_inst obj_inst;
	const char *name;
	struct gsm_nm_state nm_state;
	struct tlv_parsed *nm_attr;
	struct gsm_bts *bts;
};

/* Ericsson OM2000 Managed Object */
struct abis_om2k_mo {
	uint8_t class;
	uint8_t bts;
	uint8_t assoc_so;
	uint8_t inst;
} __attribute__ ((packed));

struct om2k_mo {
	struct abis_om2k_mo addr;
	struct osmo_fsm_inst *fsm;
};

#define A38_XOR_MIN_KEY_LEN	12
#define A38_XOR_MAX_KEY_LEN	16
#define A38_COMP128_KEY_LEN	16
#define RSL_ENC_ALG_A5(x)	(x+1)
#define MAX_EARFCN_LIST 32

/* is the data link established? who established it? */
#define LCHAN_SAPI_UNUSED	0
#define LCHAN_SAPI_MS		1
#define LCHAN_SAPI_NET		2
#define LCHAN_SAPI_REL		3

/* state of a logical channel */
enum gsm_lchan_state {
	LCHAN_S_NONE,		/* channel is not active */
	LCHAN_S_ACT_REQ,	/* channel activation requested */
	LCHAN_S_ACTIVE,		/* channel is active and operational */
	LCHAN_S_REL_REQ,	/* channel release has been requested */
	LCHAN_S_REL_ERR,	/* channel is in an error state */
	LCHAN_S_BROKEN,		/* channel is somehow unusable */
	LCHAN_S_INACTIVE,	/* channel is set inactive */
};

/* BTS ONLY */
#define MAX_NUM_UL_MEAS	104
#define LC_UL_M_F_L1_VALID	(1 << 0)
#define LC_UL_M_F_RES_VALID	(1 << 1)

struct bts_ul_meas {
	/* BER in units of 0.01%: 10.000 == 100% ber, 0 == 0% ber */
	uint16_t ber10k;
	/* timing advance offset (in quarter bits) */
	int16_t ta_offs_qbits;
	/* C/I ratio in dB */
	float c_i;
	/* flags */
	uint8_t is_sub:1;
	/* RSSI in dBm * -1 */
	uint8_t inv_rssi;
};

struct bts_codec_conf {
	uint8_t hr;
	uint8_t efr;
	uint8_t amr;
};

struct amr_mode {
	uint8_t mode;
	uint8_t threshold;
	uint8_t hysteresis;
};

struct amr_multirate_conf {
	uint8_t gsm48_ie[2];
	struct amr_mode ms_mode[4];
	struct amr_mode bts_mode[4];
	uint8_t num_modes;
};
/* /BTS ONLY */

enum lchan_csd_mode {
	LCHAN_CSD_M_NT,
	LCHAN_CSD_M_T_1200_75,
	LCHAN_CSD_M_T_600,
	LCHAN_CSD_M_T_1200,
	LCHAN_CSD_M_T_2400,
	LCHAN_CSD_M_T_9600,
	LCHAN_CSD_M_T_14400,
	LCHAN_CSD_M_T_29000,
	LCHAN_CSD_M_T_32000,
};

/* State of the SAPIs in the lchan */
enum lchan_sapi_state {
	LCHAN_SAPI_S_NONE,
	LCHAN_SAPI_S_REQ,
	LCHAN_SAPI_S_ASSIGNED,
	LCHAN_SAPI_S_REL,
	LCHAN_SAPI_S_ERROR,
};

#define MAX_A5_KEY_LEN	(128/8)

struct gsm_encr {
	uint8_t alg_id;
	uint8_t key_len;
	uint8_t key[MAX_A5_KEY_LEN];
};

struct gsm_lchan {
	/* The TS that we're part of */
	struct gsm_bts_trx_ts *ts;
	/* The logical subslot number in the TS */
	uint8_t nr;
	/* The logical channel type */
	enum gsm_chan_t type;
	/* RSL channel mode */
	enum rsl_cmod_spd rsl_cmode;
	/* If TCH, traffic channel mode */
	enum gsm48_chan_mode tch_mode;
	enum lchan_csd_mode csd_mode;
	/* State */
	enum gsm_lchan_state state;
	const char *broken_reason;
	/* Power levels for MS and BTS */
	uint8_t bs_power;
	uint8_t ms_power;
	/* Encryption information */
	struct gsm_encr encr;

	/* AMR bits */
	uint8_t mr_ms_lv[7];
	uint8_t mr_bts_lv[7];

	/* Established data link layer services */
	uint8_t sapis[8];

	struct {
		uint32_t bound_ip;
		uint32_t connect_ip;
		uint16_t bound_port;
		uint16_t connect_port;
		uint16_t conn_id;
		uint8_t rtp_payload;
		uint8_t rtp_payload2;
		uint8_t speech_mode;
		struct rtp_socket *rtp_socket;

		/* info we need to postpone the AoIP
		 * assignment completed message */
		struct {
			uint8_t rr_cause;
			uint8_t chosen_channel;
			uint8_t encr_alg_id;
			uint8_t speech_mode;
			bool valid;
		} ass_compl;
	} abis_ip;

	uint8_t rqd_ta;

	char *name;

	struct osmo_timer_list T3101;
	struct osmo_timer_list T3109;
	struct osmo_timer_list T3111;
	struct osmo_timer_list error_timer;
	struct osmo_timer_list act_timer;
	struct osmo_timer_list rel_work;
	uint8_t error_cause;

	/* table of neighbor cell measurements */
	struct neigh_meas_proc neigh_meas[MAX_NEIGH_MEAS];

	/* cache of last measurement reports on this lchan */
	struct gsm_meas_rep meas_rep[MAX_MEAS_REP];
	int meas_rep_idx;
	int meas_rep_count;
	uint8_t meas_rep_last_seen_nr;

	/* GSM Random Access data */
	struct gsm48_req_ref *rqd_ref;

	struct gsm_subscriber_connection *conn;

	struct {
		/* channel activation type and handover ref */
		uint8_t act_type;
		uint8_t ho_ref;
		struct gsm48_req_ref *rqd_ref;
		uint8_t rqd_ta;
	} dyn;
};

enum {
	TS_F_PDCH_ACTIVE =		0x1000,
	TS_F_PDCH_ACT_PENDING =		0x2000,
	TS_F_PDCH_DEACT_PENDING =	0x4000,
	TS_F_PDCH_PENDING_MASK =	0x6000 /*<
			TS_F_PDCH_ACT_PENDING | TS_F_PDCH_DEACT_PENDING */
} gsm_bts_trx_ts_flags;

/* One Timeslot in a TRX */
struct gsm_bts_trx_ts {
	struct gsm_bts_trx *trx;
	/* number of this timeslot at the TRX */
	uint8_t nr;

	enum gsm_phys_chan_config pchan;

	struct {
		enum gsm_phys_chan_config pchan_is;
		enum gsm_phys_chan_config pchan_want;
		struct msgb *pending_chan_activ;
	} dyn;

	unsigned int flags;
	struct gsm_abis_mo mo;
	struct tlv_parsed nm_attr;
	uint8_t nm_chan_comb;
	int tsc;		/* -1 == use BTS TSC */

	struct {
		/* Parameters below are configured by VTY */
		int enabled;
		uint8_t maio;
		uint8_t hsn;
		struct bitvec arfcns;
		uint8_t arfcns_data[1024/8];
		/* This is the pre-computed MA for channel assignments */
		struct bitvec ma;
		uint8_t ma_len;	/* part of ma_data that is used */
		uint8_t ma_data[8];	/* 10.5.2.21: max 8 bytes value part */
	} hopping;

	/* To which E1 subslot are we connected */
	struct gsm_e1_subslot e1_link;

	union {
		struct {
			struct om2k_mo om2k_mo;
		} rbs2000;
	};

	struct gsm_lchan lchan[TS_MAX_LCHAN];
};

/* One TRX in a BTS */
struct gsm_bts_trx {
	/* list header in bts->trx_list */
	struct llist_head list;

	struct gsm_bts *bts;
	/* number of this TRX in the BTS */
	uint8_t nr;
	/* human readable name / description */
	char *description;
	/* how do we talk RSL with this TRX? */
	struct gsm_e1_subslot rsl_e1_link;
	uint8_t rsl_tei;
	struct e1inp_sign_link *rsl_link;

	/* Timeout for initiating the RSL connection. */
	struct osmo_timer_list rsl_connect_timeout;

	/* Some BTS (specifically Ericsson RBS) have a per-TRX OML Link */
	struct e1inp_sign_link *oml_link;

	struct gsm_abis_mo mo;
	struct tlv_parsed nm_attr;
	struct {
		struct gsm_abis_mo mo;
	} bb_transc;

	uint16_t arfcn;
	int nominal_power;		/* in dBm */
	unsigned int max_power_red;	/* in actual dB */

	union {
		struct {
			struct {
				struct gsm_abis_mo mo;
			} bbsig;
			struct {
				struct gsm_abis_mo mo;
			} pa;
		} bs11;
		struct {
			unsigned int test_state;
			uint8_t test_nr;
			struct rxlev_stats rxlev_stat;
		} ipaccess;
		struct {
			struct {
				struct om2k_mo om2k_mo;
			} trxc;
			struct {
				struct om2k_mo om2k_mo;
			} rx;
			struct {
				struct om2k_mo om2k_mo;
			} tx;
		} rbs2000;
	};
	struct gsm_bts_trx_ts ts[TRX_NR_TS];
};

#define GSM_BTS_SI2Q(bts, i)   (struct gsm48_system_information_type_2quater *)((bts)->si_buf[SYSINFO_TYPE_2quater][i])
#define GSM_BTS_HAS_SI(bts, i) ((bts)->si_valid & (1 << i))
#define GSM_BTS_SI(bts, i)     (void *)((bts)->si_buf[i][0])
#define GSM_LCHAN_SI(lchan, i) (void *)((lchan)->si.buf[i][0])

enum gsm_bts_type {
	GSM_BTS_TYPE_UNKNOWN,
	GSM_BTS_TYPE_BS11,
	GSM_BTS_TYPE_NANOBTS,
	GSM_BTS_TYPE_RBS2000,
	GSM_BTS_TYPE_NOKIA_SITE,
	GSM_BTS_TYPE_OSMOBTS,
	_NUM_GSM_BTS_TYPE
};

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

	struct tlv_definition nm_att_tlvdef;

	/* features of a given BTS model set via gsm_bts_model_register() locally */
	struct bitvec features;
	uint8_t _features_data[MAX_BTS_FEATURES/8];
};



/*
 * This keeps track of the paging status of one BTS. It
 * includes a number of pending requests, a back pointer
 * to the gsm_bts, a timer and some more state.
 */
struct gsm_bts_paging_state {
	/* pending requests */
	struct llist_head pending_requests;
	struct gsm_bts *bts;

	struct osmo_timer_list work_timer;
	struct osmo_timer_list credit_timer;

	/* free chans needed */
	int free_chans_need;

	/* load */
	uint16_t available_slots;
};

struct gsm_envabtse {
	struct gsm_abis_mo mo;
};

struct gsm_bts_gprs_nsvc {
	struct gsm_bts *bts;
	/* data read via VTY config file, to configure the BTS
	 * via OML from BSC */
	int id;
	uint16_t nsvci;
	uint16_t local_port;	/* on the BTS */
	uint16_t remote_port;	/* on the SGSN */
	uint32_t remote_ip;	/* on the SGSN */

	struct gsm_abis_mo mo;
};

enum gprs_rlc_par {
	RLC_T3142,
	RLC_T3169,
	RLC_T3191,
	RLC_T3193,
	RLC_T3195,
	RLC_N3101,
	RLC_N3103,
	RLC_N3105,
	CV_COUNTDOWN,
	T_DL_TBF_EXT,	/* ms */
	T_UL_TBF_EXT,	/* ms */
	_NUM_RLC_PAR
};

enum gprs_cs {
	GPRS_CS1,
	GPRS_CS2,
	GPRS_CS3,
	GPRS_CS4,
	GPRS_MCS1,
	GPRS_MCS2,
	GPRS_MCS3,
	GPRS_MCS4,
	GPRS_MCS5,
	GPRS_MCS6,
	GPRS_MCS7,
	GPRS_MCS8,
	GPRS_MCS9,
	_NUM_GRPS_CS
};

struct gprs_rlc_cfg {
	uint16_t parameter[_NUM_RLC_PAR];
	struct {
		uint16_t repeat_time; /* ms */
		uint8_t repeat_count;
	} paging;
	uint32_t cs_mask; /* bitmask of gprs_cs */
	uint8_t initial_cs;
	uint8_t initial_mcs;
};


enum neigh_list_manual_mode {
	NL_MODE_AUTOMATIC = 0,
	NL_MODE_MANUAL = 1,
	NL_MODE_MANUAL_SI5SEP = 2, /* SI2 and SI5 have separate neighbor lists */
};

enum bts_loc_fix {
	BTS_LOC_FIX_INVALID = 0,
	BTS_LOC_FIX_2D = 1,
	BTS_LOC_FIX_3D = 2,
};

extern const struct value_string bts_loc_fix_names[];

struct bts_location {
	struct llist_head list;
	time_t tstamp;
	enum bts_loc_fix valid;
	double lat;
	double lon;
	double height;
};

/* Channel load counter */
struct load_counter {
	unsigned int total;
	unsigned int used;
};

/* One BTS */
struct gsm_bts {
	/* list header in net->bts_list */
	struct llist_head list;

	/* Geographical location of the BTS */
	struct llist_head loc_list;

	/* number of ths BTS in network */
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

	struct {
		struct gsm_abis_mo mo;
	} site_mgr;

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

	/* ip.accesss Unit ID's have Site/BTS/TRX layout */
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
			uint32_t use_superchannel:1;
		} rbs2000;
		struct {
			uint8_t bts_type;
			unsigned int configured:1,
				skip_reset:1,
				no_loc_rel_cnf:1,
				bts_reset_timer_cnf,
				did_reset:1,
				wait_reset:1;
			struct osmo_timer_list reset_timer;
		} nokia;
	};

	/* Not entirely sure how ip.access specific this is */
	struct {
		uint8_t supports_egprs_11bit_rach;
		enum bts_gprs_mode mode;
		struct {
			struct gsm_abis_mo mo;
			uint16_t nsei;
			uint8_t timer[7];
		} nse;
		struct {
			struct gsm_abis_mo mo;
			uint16_t bvci;
			uint8_t timer[11];
			struct gprs_rlc_cfg rlc_cfg;
		} cell;
		struct gsm_bts_gprs_nsvc nsvc[2];
		uint8_t rac;
		uint8_t net_ctrl_ord;
		bool ctrl_ack_type_use_block;
	} gprs;

	/* RACH NM values */
	int rach_b_thresh;
	int rach_ldavg_slots;

	/* transceivers */
	int num_trx;
	struct llist_head trx_list;

	/* SI related items */
	int force_combined_si;
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

	/* BTS-specific overrides for timer values from struct gsm_network. */
	uint8_t T3122;	/* ASSIGMENT REJECT wait indication */

	/* Periodic channel load measurements are used to maintain T3122. */
	struct load_counter chan_load_samples[7];
	int chan_load_samples_idx;
	uint8_t chan_load_avg; /* current channel load average in percent (0 - 100). */
};


struct gsm_bts *gsm_bts_alloc(struct gsm_network *net, uint8_t bts_num);
struct gsm_bts *gsm_bts_num(struct gsm_network *net, int num);

struct gsm_bts_trx *gsm_bts_trx_alloc(struct gsm_bts *bts);
struct gsm_bts_trx *gsm_bts_trx_num(const struct gsm_bts *bts, int num);

enum gsm_bts_type str2btstype(const char *arg);
const char *btstype2str(enum gsm_bts_type type);

enum bts_attribute str2btsattr(const char *s);
const char *btsatttr2str(enum bts_attribute v);

enum gsm_bts_type_variant str2btsvariant(const char *arg);
const char *btsvariant2str(enum gsm_bts_type_variant v);

extern const struct value_string gsm_chreq_descs[];
const struct value_string gsm_pchant_names[13];
const struct value_string gsm_pchant_descs[13];
const char *gsm_pchan_name(enum gsm_phys_chan_config c);
enum gsm_phys_chan_config gsm_pchan_parse(const char *name);
const char *gsm_lchant_name(enum gsm_chan_t c);
const char *gsm_chreq_name(enum gsm_chreq_reason_t c);
char *gsm_trx_name(const struct gsm_bts_trx *trx);
char *gsm_ts_name(const struct gsm_bts_trx_ts *ts);
char *gsm_ts_and_pchan_name(const struct gsm_bts_trx_ts *ts);
char *gsm_lchan_name_compute(const struct gsm_lchan *lchan);
const char *gsm_lchans_name(enum gsm_lchan_state s);

static inline char *gsm_lchan_name(const struct gsm_lchan *lchan)
{
	return lchan->name;
}

void gsm_abis_mo_reset(struct gsm_abis_mo *mo);

struct gsm_nm_state *
gsm_objclass2nmstate(struct gsm_bts *bts, uint8_t obj_class,
		 const struct abis_om_obj_inst *obj_inst);
void *
gsm_objclass2obj(struct gsm_bts *bts, uint8_t obj_class,
	     const struct abis_om_obj_inst *obj_inst);

/* reset the state of all MO in the BTS */
void gsm_bts_mo_reset(struct gsm_bts *bts);

uint8_t gsm_pchan2chan_nr(enum gsm_phys_chan_config pchan,
			  uint8_t ts_nr, uint8_t lchan_nr);
uint8_t gsm_lchan2chan_nr(const struct gsm_lchan *lchan);
uint8_t gsm_lchan_as_pchan2chan_nr(const struct gsm_lchan *lchan,
				   enum gsm_phys_chan_config as_pchan);

/* return the gsm_lchan for the CBCH (if it exists at all) */
struct gsm_lchan *gsm_bts_get_cbch(struct gsm_bts *bts);

/*
 * help with parsing regexps
 */
int gsm_parse_reg(void *ctx, regex_t *reg, char **str,
		int argc, const char **argv) __attribute__ ((warn_unused_result));

static inline uint8_t gsm_ts_tsc(const struct gsm_bts_trx_ts *ts)
{
	if (ts->tsc != -1)
		return ts->tsc;
	else
		return ts->trx->bts->bsic & 7;
}

struct gsm_lchan *rsl_lchan_lookup(struct gsm_bts_trx *trx, uint8_t chan_nr,
				   int *rc);

enum gsm_phys_chan_config ts_pchan(struct gsm_bts_trx_ts *ts);
uint8_t ts_subslots(struct gsm_bts_trx_ts *ts);
bool ts_is_tch(struct gsm_bts_trx_ts *ts);


static inline struct gsm_bts *conn_get_bts(struct gsm_subscriber_connection *conn) {
	OSMO_ASSERT(conn->lchan);
	return conn->lchan->ts->trx->bts;
}

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
	BTS_STAT_CHAN_LOAD_AVERAGE,
	BTS_STAT_T3122,
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
#define GSM_T3109_DEFAULT 5	/* s, must be 2s + radio_link_timeout*0.48 */
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

	struct osmo_plmn_id plmn;

	/* bit-mask of permitted encryption algorithms. LSB=A5/0, MSB=A5/7 */
	uint8_t a5_encryption_mask;
	int neci;

	struct handover_cfg *ho;
	struct {
		unsigned int congestion_check_interval_s;
		struct osmo_timer_list congestion_check_timer;
	} hodec2;

	struct rate_ctr_group *bsc_ctrs;

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

	/* Timer for periodic channel load measurements to maintain each BTS's T3122. */
	struct osmo_timer_list t3122_chan_load_timer;

	struct {
		struct mgcp_client_conf *conf;
		struct mgcp_client *client;
	} mgw;
};

static inline const struct osmo_location_area_id *bts_lai(struct gsm_bts *bts)
{
	static struct osmo_location_area_id lai;
	lai = (struct osmo_location_area_id){
		.plmn = bts->network->plmn,
		.lac = bts->location_area_code,
	};
	return &lai;
}

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

void gsm48_ra_id_by_bts(struct gsm48_ra_id *buf, struct gsm_bts *bts);
void gprs_ra_id_by_bts(struct gprs_ra_id *raid, struct gsm_bts *bts);

int gsm_bts_model_register(struct gsm_bts_model *model);

struct gsm_subscriber_connection *bsc_subscr_con_allocate(struct gsm_network *network);

struct gsm_subscriber_connection *msc_subscr_con_allocate(struct gsm_network *network);
void msc_subscr_con_free(struct gsm_subscriber_connection *conn);

struct gsm_bts *gsm_bts_alloc_register(struct gsm_network *net,
					enum gsm_bts_type type,
					uint8_t bsic);

void set_ts_e1link(struct gsm_bts_trx_ts *ts, uint8_t e1_nr,
		   uint8_t e1_ts, uint8_t e1_ts_ss);

void gsm_trx_lock_rf(struct gsm_bts_trx *trx, bool locked, const char *reason);
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
