#ifndef _GSM_DATA_H
#define _GSM_DATA_H

#include <stdint.h>
#include <sys/types.h>
#include <stdbool.h>

#include <osmocom/core/timer.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/select.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/stats.h>
#include <osmocom/core/stat_item.h>
#include <osmocom/gsm/bts_features.h>
#include <osmocom/gsm/protocol/gsm_08_08.h>
#include <osmocom/gsm/protocol/gsm_48_049.h>
#include <osmocom/gsm/gsm0808.h>
#include <osmocom/gsm/gsm48.h>
#include <osmocom/core/fsm.h>
#include <osmocom/core/tdef.h>
#include <osmocom/core/time_cc.h>

#include <osmocom/crypt/auth.h>

#include <osmocom/gsm/gsm48_rest_octets.h>

#include <osmocom/core/bitvec.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/gsm/rxlev_stat.h>
#include <osmocom/gsm/protocol/gsm_08_58.h>
#include <osmocom/gsm/protocol/gsm_12_21.h>
#include <osmocom/abis/e1_input.h>
#include <osmocom/bsc/meas_rep.h>
#include <osmocom/bsc/acc.h>
#include <osmocom/bsc/osmux.h>

#define GSM_T3122_DEFAULT 10

struct mgcp_client_conf;
struct mgcp_client;
struct gsm0808_cell_id;
struct osmo_mgcpc_ep;
struct gsm_bts;
struct gsm_bts_trx;

/** annotations for msgb ownership */
#define __uses

#define OBSC_NM_W_ACK_CB(__msgb) (__msgb)->cb[3]

struct bsc_subscr;
struct gprs_ra_id;
struct handover;
struct osmo_sccp_instance;
struct smlc_config;

#define OBSC_LINKID_CB(__msgb)	(__msgb)->cb[3]

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

enum channel_rate {
	CH_RATE_SDCCH,
	CH_RATE_HALF,
	CH_RATE_FULL,
};

enum channel_rate chan_t_to_chan_rate(enum gsm_chan_t chan_t);

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

struct channel_mode_and_rate {
	enum gsm48_chan_mode chan_mode;
	enum channel_rate chan_rate;
	uint16_t s15_s0;
	/* only used for GSM48_CMODE_DATA_* */
	enum lchan_csd_mode csd_mode;
};

enum assign_for {
	ASSIGN_FOR_NONE,
	ASSIGN_FOR_BSSMAP_REQ,
	ASSIGN_FOR_CONGESTION_RESOLUTION,
	ASSIGN_FOR_VTY,
};

extern const struct value_string assign_for_names[];
static inline const char *assign_for_name(enum assign_for assign_for)
{ return get_value_string(assign_for_names, assign_for); }

/* If .present is false, use the default value defined elsewhere. If true, use .val below.
 * (A practical benefit of this is that the default initialization sets .present to false, so that even if a .val == 0
 * is a valid value, a struct containing this as member does not need to explicitly set .val = INVALID_VAL_CONSTANT.) */
struct optional_val {
	bool present;
	int val;
};

/* Information retrieved during an Assignment Request from the MSC. This is storage of the Assignment instructions
 * parsed from the Assignment Request message, to pass on until the gscon and assignment FSMs have decided whether an
 * Assignment is actually going to be carried out. Should remain unchanged after initial decoding. */
struct assignment_request {
	enum assign_for assign_for;

	bool aoip;

	uint16_t msc_assigned_cic;

	char msc_rtp_addr[INET6_ADDRSTRLEN];
	uint16_t msc_rtp_port;
	bool use_osmux;
	uint8_t osmux_cid;

	/* Rate/codec setting in preference order (need at least 1 !) */
	int n_ch_mode_rate;
	struct channel_mode_and_rate ch_mode_rate_list[3];

	/* An assignment request usually requests to assign any available lchan, to match above requirements. This may
	 * also choose to just keep the current lchan and merely modify it as appropriate. In these cases, keep
	 * target_lchan == NULL.
	 * In some situations, an assignment to a specific target lchan is requested (congestion resolution, VAMOS
	 * multiplexing, user request via VTY). In these situations, select a target lchan beforehand and point
	 * target_lchan to it. */
	struct gsm_lchan *target_lchan;

	/* The TSC Set to use if 'use' is true, otherwise automatically determine the TSC Set value to use. Valid range
	 * is 1 to 4, as described in 3GPP TS 45.002. */
	struct optional_val tsc_set;
	/* The TSC to use if 'use' is true, otherwise automatically determine the TSC value to use. Valid range is 0 to
	 * 7, as described in 3GPP TS 45.002. */
	struct optional_val tsc;
};

/* State of an ongoing Assignment, while the assignment_fsm is still busy. This serves as state separation to keep the
 * currently used lchan and gscon unmodified until the outcome of an Assignment is known. If the Assignment fails, this
 * state is simply discarded, and the gscon carries on with the original lchan remaining unchanged. */
struct assignment_fsm_data {
	/* The request as made by the caller, see GSCON_EV_ASSIGNMENT_START or reassignment_request_to_lchan() /
	 * reassignment_request_to_chan_type().
	 * conn->assignment.req is treated immutable: remains unchanged throughout the Assignment. The mutable fields
	 * are below: choices and automatic adjustments are stored in conn->assignment.*, not conn->assignment.req.
	 */
	struct assignment_request req;

	bool requires_voice_stream;
	struct channel_mode_and_rate selected_ch_mode_rate;

	struct osmo_fsm_inst *fi;
	struct gsm_lchan *new_lchan;

	/* Whether this assignment triggered creation of the MGW endpoint: if the assignment
	 * fails, we will release that again as soon as possible. (If false, the endpoint already
	 * existed before or isn't needed at all.)*/
	struct osmo_mgcpc_ep_ci *created_ci_for_msc;

	enum gsm0808_cause failure_cause;
	enum gsm48_rr_cause rr_cause;

	bool result_rate_ctr_done;
};

enum hodec_id {
	HODEC_NONE,
	HODEC1 = 1,
	HODEC2 = 2,
	HODEC_USER,
	HODEC_REMOTE,
};

/* For example, to count specific kinds of ongoing handovers, it is useful to be able to OR-combine
 * scopes. */
enum handover_scope {
	HO_NO_HANDOVER = 0,
	HO_INTRA_CELL = 0x1,
	HO_INTRA_BSC = 0x2,
	HO_INTER_BSC_OUT = 0x4,
	HO_INTER_BSC_IN = 0x8,
	HO_SCOPE_ALL = 0xffff,
};

extern const struct value_string handover_scope_names[];
inline static const char *handover_scope_name(enum handover_scope val)
{ return get_value_string(handover_scope_names, val); }

/* Cell ARFCN + BSIC. */
struct cell_ab {
	uint16_t arfcn;
	uint8_t bsic;
};

struct handover_out_req {
	enum hodec_id from_hodec_id;
	struct gsm_lchan *old_lchan;
	struct cell_ab target_cell_ab;
	enum gsm_chan_t new_lchan_type; /*< leave GSM_LCHAN_NONE to use same as old_lchan */
};

struct handover_in_req {
	struct gsm0808_channel_type ct;
	struct gsm0808_speech_codec_list scl;
	struct gsm0808_encrypt_info ei;
	/* The same information as in 'ei' but as the handy bitmask as on the wire. */
	uint8_t ei_as_bitmask;
	bool kc128_present;
	uint8_t kc128[16];
	struct gsm_classmark classmark;
	/* chosen_encr_alg reflects the encoded value as in RSL_ENC_ALG_A5(a5_numer):
	 * chosen_encr_alg == 1 means A5/0 i.e. no encryption, chosen_encr_alg == 4 means A5/3.
	 * chosen_encr_alg == 0 means no such IE was present. */
	uint8_t chosen_encr_alg;
	struct gsm0808_cell_id cell_id_serving;
	char cell_id_serving_name[64];
	struct gsm0808_cell_id cell_id_target;
	char cell_id_target_name[64];
	uint16_t msc_assigned_cic;
	char msc_assigned_rtp_addr[INET6_ADDRSTRLEN];
	uint16_t msc_assigned_rtp_port;
	bool last_eutran_plmn_valid;
	struct osmo_plmn_id last_eutran_plmn;
};

struct handover {
	struct osmo_fsm_inst *fi;

	enum hodec_id from_hodec_id;
	enum handover_scope scope;
	enum gsm_chan_t new_lchan_type;
	struct cell_ab target_cell_ab;

	/* For inter-BSC handover, this may reflect more than one Cell ID. Must also be set for intra-BSC handover,
	 * because it is used as key for penalty timers (e.g. in handover decision 2). */
	struct gsm0808_cell_id_list2 target_cell_ids;

	uint8_t ho_ref;
	struct gsm_bts *new_bts;
	struct gsm_lchan *new_lchan;
	bool async;
	struct handover_in_req inter_bsc_in;
	struct osmo_mgcpc_ep_ci *created_ci_for_msc;
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

	/* the primary / currently active lchan to the BTS/subscriber. During Assignment and Handover, separate lchans
	 * are kept in the .assignment or .handover sub-structs, respectively, so that this lchan remains unaffected
	 * until Assignment or Handover have actually succeeded. */
	struct gsm_lchan *lchan;

	/* Only valid during an ongoing Assignment; might be overwritten at any time by a failed Assignment attempt.
	 * Once an Assignment was successful, all relevant state must be copied out of this sub-struct. */
	struct assignment_fsm_data assignment;

	/* handover information, if a handover is pending for this conn. Valid only during an ongoing Handover
	 * operation. If a Handover was successful, all relevant state must be copied out of this sub-struct. */
	struct handover ho;

	/* Queue DTAP messages during handover/assignment (msgb_enqueue()/msgb_dequeue())*/
	struct llist_head dtap_queue;
	unsigned int dtap_queue_len;

	struct {
		int failures;
		struct llist_head penalty_timers;
	} hodec2;

	/* "Codec List (MSC Preferred)" as received by the BSSAP Assignment Request. 3GPP 48.008
	 * 3.2.2.103 says:
	 *         The "Codec List (MSC Preferred)" shall not include codecs
	 *         that are not supported by the MS.
	 * i.e. by heeding the "Codec list (MSC Preferred)", we inherently heed the MS bearer
	 * capabilities, which the MSC is required to translate into the codec list. */
	struct gsm0808_speech_codec_list codec_list;

	/* flag to prevent multiple simultaneous ciphering commands */
	int ciphering_handled;

	/* SCCP connection associatd with this subscriber_connection */
	struct {
		/* SCCP connection related */
		struct bsc_msc_data *msc;

		/* Sigtran connection ID */
		int conn_id;
		enum subscr_sccp_state state;
	} sccp;

	/* for audio handling */
	struct {
		uint16_t msc_assigned_cic;

		/* RTP address where the MSC expects us to send the RTP stream coming from the BTS. */
		char msc_assigned_rtp_addr[INET6_ADDRSTRLEN];
		uint16_t msc_assigned_rtp_port;

		/* The endpoint at the MGW used to join both BTS and MSC side connections, e.g.
		 * "rtpbridge/23@mgw". */
		struct osmo_mgcpc_ep *mgw_endpoint;

		/* The connection identifier of the osmo_mgcpc_ep used to transceive RTP towards the MSC.
		 * (The BTS side CI is handled by struct gsm_lchan and the lchan_fsm.) */
		struct osmo_mgcpc_ep_ci *mgw_endpoint_ci_msc;
	} user_plane;

	/* LCLS (local call, local switch) related state */
	struct {
		uint8_t global_call_ref[15];
		uint8_t global_call_ref_len; /* length of global_call_ref */
		enum gsm0808_lcls_config config;	/* TS 48.008 3.2.2.116 */
		enum gsm0808_lcls_control control;	/* TS 48.008 3.2.2.117 */
		/* LCLS FSM */
		struct osmo_fsm_inst *fi;
		/* pointer to "other" connection, if Call Leg Relocation was successful */
		struct gsm_subscriber_connection *other;
	} lcls;

	/* MS Power Class, TS 05.05 sec 4.1.1 "Mobile station". 0 means unset. */
	uint8_t ms_power_class:3;

	bool rx_clear_command;

	/* Location Services handling for this subscriber */
	struct {
		/* FSM to handle Perform Location Request coming in from the MSC via A interface,
		 * and receive BSSMAP-LE responses from the SMLC. */
		struct lcs_loc_req *loc_req;

		/* FSM to handle BSSLAP requests coming in from the SMLC via Lb interface.
		 * BSSLAP APDU are encapsulated in BSSMAP-LE Connection Oriented Information messages. */
		struct lcs_bsslap *bsslap;

		/* Lb interface to the SMLC: BSSMAP-LE/SCCP connection associated with this subscriber */
		struct {
			int conn_id;
			enum subscr_sccp_state state;
		} lb;
	} lcs;

	struct gsm48_classmark3 cm3;
	bool cm3_valid;

	struct {
		bool allowed; /* Is fast return to LTE allowed once the conn is released? */
		bool last_eutran_plmn_valid; /* Is information stored in field below available? */
		struct osmo_plmn_id last_eutran_plmn;
	} fast_return;

	enum gsm0808_cause clear_cause;
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

static inline bool gsm_chreq_reason_is_voicecall(enum gsm_chreq_reason_t reason)
{
	return reason == GSM_CHREQ_REASON_EMERG || reason == GSM_CHREQ_REASON_CALL;
}

/* lchans 0..3 are SDCCH in combined channel configuration,
   use 4 as magic number for BCCH hack - see osmo-bts-../oml.c:opstart_compl() */
#define CCCH_LCHAN 4

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

enum bts_gprs_mode {
	BTS_GPRS_NONE = 0,
	BTS_GPRS_GPRS = 1,
	BTS_GPRS_EGPRS = 2,
};

struct gsm_lchan;
struct osmo_rtp_socket;
struct rtp_socket;

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
	struct osmo_fsm_inst *fi;
	bool opstart_sent;
	bool adm_unlock_sent;
	bool get_attr_sent;
	bool get_attr_rep_received;
	bool set_attr_sent;
	bool set_attr_ack_received;
	bool force_rf_lock;
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

/* There are these representations of A5/n:
 *
 * - (uint8_t)(1<<n), either as a single bit, or combined as a list of
 *   permitted algorithms.
 *   A5/0 == 0x01, A5/3 == 0x08, none = 0
 *
 * - n+1, used on the RSL wire.
 *   A5/0 == 1, A5/3 == 4, none = 0
 *
 * - n, used for human interaction and returned by select_best_cipher().
 *   A5/0 == 0, A5/3 == 3, none <= -1
 *
 * These macros convert from n to the other representations:
 */
#define ALG_A5_NR_TO_RSL(A5_N) ((A5_N) >= 0 ? (A5_N)+1 : 0)
#define ALG_A5_NR_TO_PERM_ALG_BITS(A5_N) ((A5_N) >= 0 ? 1<<(A5_N) : 0)

/* Up to 16 SI2quater are multiplexed; each fits 3 EARFCNS, so the practical maximum is 3*16.
 * The real maximum that fits in a total of 16 SI2quater rest octets also depends on the bits left by other SI2quater
 * rest octets elements, so to really fit 48 EARFCNs most other SI2quater elements need to be omitted. */
#define MAX_EARFCN_LIST (3*16)

/* is the data link established? who established it? */
#define LCHAN_SAPI_UNUSED	0
#define LCHAN_SAPI_MS		1
#define LCHAN_SAPI_NET		2

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
	bool kc128_present;
	uint8_t kc128[16];
};

#define LOGPLCHAN(lchan, ss, level, fmt, args...) \
	LOGP(ss, level, "%s (ss=%d,%s) (%s) " fmt, \
	     lchan ? gsm_ts_and_pchan_name(lchan->ts) : "-", \
	     lchan ? lchan->nr : 0, \
	     lchan ? gsm_lchant_name(lchan->type) : "-", \
	     bsc_subscr_name(lchan && lchan->conn ? lchan->conn->bsub : NULL), \
	     ## args)

/* Iterate at most N lchans of the given timeslot.
 * usage:
 * struct gsm_lchan *lchan;
 * struct gsm_bts_trx_ts *ts = get_some_timeslot();
 * ts_for_n_lchans(lchan, ts, 3) {
 *         LOG_LCHAN(lchan, LOGL_DEBUG, "hello world\n");
 * }
 */
#define ts_for_n_lchans(lchan, ts, N) \
	for (lchan = (ts)->lchan; \
	     ((lchan - (ts)->lchan) < ARRAY_SIZE((ts)->lchan)) \
	     && lchan->fi \
	     && ((lchan - (ts)->lchan) < (N)); \
	     lchan++)

enum lchan_activate_for {
	ACTIVATE_FOR_NONE,
	ACTIVATE_FOR_MS_CHANNEL_REQUEST,
	ACTIVATE_FOR_ASSIGNMENT,
	ACTIVATE_FOR_HANDOVER,
	ACTIVATE_FOR_VTY,
	ACTIVATE_FOR_MODE_MODIFY_RTP,
};

extern const struct value_string lchan_activate_mode_names[];
static inline const char *lchan_activate_mode_name(enum lchan_activate_for activ_for)
{ return get_value_string(lchan_activate_mode_names, activ_for); }

enum imm_ass_time {
	IMM_ASS_TIME_POST_CHAN_ACK = 0,
	IMM_ASS_TIME_PRE_CHAN_ACK,
	IMM_ASS_TIME_PRE_TS_ACK,
};

struct lchan_activate_info {
	enum lchan_activate_for activ_for;
	/* If activ_for == ACTIVATE_FOR_MS_CHANNEL_REQUEST, the original CHREQ reason. */
	enum gsm_chreq_reason_t chreq_reason;
	struct gsm_subscriber_connection *for_conn;
	struct channel_mode_and_rate ch_mode_rate;
	struct gsm_encr encr;
	bool requires_voice_stream;
	bool wait_before_switching_rtp; /*< true = requires LCHAN_EV_READY_TO_SWITCH_RTP */
	uint16_t msc_assigned_cic;
	/* During intra-BSC handover, we keep the MGW endpoint intact and just re-route to the new lchan. This
	 * activate_info is for the new lchan, the re_use_mgw_endpoint_from_lchan points at the old lchan. */
	struct gsm_lchan *re_use_mgw_endpoint_from_lchan;
	bool ta_known;
	uint8_t ta;

	/* The TSC Set to use if 'use' is true, otherwise automatically determine the TSC Set value to use. Valid range
	 * is 1 to 4, as described in 3GPP TS 45.002. */
	struct optional_val tsc_set;
	/* The TSC to use if 'use' is true, otherwise automatically determine the TSC value to use. Valid range is 0 to
	 * 7, as described in 3GPP TS 45.002. */
	struct optional_val tsc;

	bool vamos;

	/* A copy of bts->imm_ass_time at the time where Channel Activation was requested. A change in the VTY
	 * configuration has immediate effect on the value, so make sure we don't get mixed up when it gets changed
	 * while a channel activation is in progress. */
	enum imm_ass_time imm_ass_time;
};

enum lchan_modify_for {
	MODIFY_FOR_NONE,
	MODIFY_FOR_ASSIGNMENT,
	MODIFY_FOR_VTY,
};

extern const struct value_string lchan_modify_for_names[];
static inline const char *lchan_modify_for_name(enum lchan_modify_for modify_for)
{ return get_value_string(lchan_modify_for_names, modify_for); }

struct lchan_modify_info {
	enum lchan_modify_for modify_for;
	struct channel_mode_and_rate ch_mode_rate;
	bool requires_voice_stream;
	uint16_t msc_assigned_cic;

	/* The TSC Set to use if 'use' is true, otherwise automatically determine the TSC Set value to use. Valid range
	 * is 1 to 4, as described in 3GPP TS 45.002. */
	struct optional_val tsc_set;
	/* The TSC to use if 'use' is true, otherwise automatically determine the TSC value to use. Valid range is 0 to
	 * 7, as described in 3GPP TS 45.002. */
	struct optional_val tsc;

	bool vamos;
};

#define INTERF_DBM_UNKNOWN 0
#define INTERF_BAND_UNKNOWN 0xff

/* Measurement pre-processing state */
struct gsm_power_ctrl_meas_proc_state {
	/* Number of measurements processed */
	unsigned int meas_num;
	/* Algorithm specific data */
	union {
		struct {
			/* Scaled up 100 times average value */
			int Avg100;
		} ewma;
	};
};

struct lchan_power_ctrl_state {
	/* Measurement pre-processing state (for dynamic mode) */
	struct gsm_power_ctrl_meas_proc_state rxlev_meas_proc;
	struct gsm_power_ctrl_meas_proc_state rxqual_meas_proc;
	/* Number of SACCH blocks to skip (for dynamic mode) */
	int skip_block_num;
};

struct gsm_lchan {
	/* The TS that we're part of */
	struct gsm_bts_trx_ts *ts;
	/* The logical subslot number in the TS */
	uint8_t nr;
	char *name;

	char *last_error;

	struct osmo_fsm_inst *fi;
	struct osmo_fsm_inst *fi_rtp;
	struct osmo_mgcpc_ep_ci *mgw_endpoint_ci_bts;

	struct {
		/* The request as made by the caller, see lchan_activate().
		 * lchan->activate.info is treated immutable: remains unchanged throughout the Activation.
		 * The mutable versions are below: some values need automatic adjustments, in which case they are copied
		 * from immutable lchan->activate.info.* to lchan->activate.*, for example lchan->activate.ch_mode_rate
		 * is initially a copy of lchan->activate.info.ch_mode_rate, and is possibly adjusted afterwards. */
		struct lchan_activate_info info;

		struct channel_mode_and_rate ch_mode_rate;
		struct gsm48_multi_rate_conf mr_conf_filtered;
		bool activ_ack; /*< true as soon as RSL Chan Activ Ack is received */
		bool immediate_assignment_sent;
		/*! This flag ensures that when an lchan activation has succeeded, and we have already
		 * sent ACKs like Immediate Assignment or BSSMAP Assignment Complete, and if other errors
		 * occur later, e.g. during release, that we don't send a NACK out of context. */
		bool concluded;
		enum gsm0808_cause gsm0808_error_cause;
		/* Actually used TSC Set. */
		int tsc_set;
		/* Actually used TSC. */
		uint8_t tsc;
	} activate;

	struct {
		/* The request as made by the caller, see lchan_mode_modify().
		 * lchan->modify.info is treated immutable: remains unchanged throughout the Mode Modify.
		 * The mutable versions are below: some values need automatic adjustments, in which case they are copied
		 * from immutable lchan->modify.info.* to lchan->modify.*, for example lchan->modify.ch_mode_rate
		 * is initially a copy of lchan->modify.info.ch_mode_rate, and is possibly adjusted afterwards. */
		struct lchan_modify_info info;

		struct channel_mode_and_rate ch_mode_rate;
		struct gsm48_multi_rate_conf mr_conf_filtered;
		/* Actually used TSC Set. */
		int tsc_set;
		/* Actually used TSC. */
		uint8_t tsc;
		bool concluded;
	} modify;

	struct {
		/* If an event to release the lchan comes in while still waiting for responses, just mark this
		 * flag, so that the lchan will gracefully release at the next sensible junction. */
		bool requested;
		bool do_rr_release;
		enum gsm48_rr_cause rr_cause;
		bool last_eutran_plmn_valid;
		struct osmo_plmn_id last_eutran_plmn;

		/* There is an RSL error cause of value 0, so we need a separate flag. */
		bool in_error;
		/* RSL error code, RSL_ERR_* */
		uint8_t rsl_error_cause;

		/* If a release event is being handled, ignore other ricocheting release events until that
		 * release handling has concluded. */
		bool in_release_handler;
	} release;

	/* The logical channel type */
	enum gsm_chan_t type;
	/* Power levels for MS and BTS */
	uint8_t bs_power_db;
	uint8_t ms_power;
	/* Encryption information */
	struct gsm_encr encr;

	/* Established data link layer services */
	uint8_t sapis[8];

	struct {
		uint32_t bound_ip; /*< where the BTS receives RTP */
		uint16_t bound_port;
		uint32_t connect_ip; /*< where the BTS sends RTP to (MGW) */
		uint16_t connect_port;
		uint16_t conn_id;
		uint8_t rtp_payload;
		uint8_t rtp_payload2;
		uint8_t speech_mode;

		/* info we need to postpone the AoIP
		 * assignment completed message */
		struct {
			uint8_t rr_cause;
			bool valid;
		} ass_compl;
	} abis_ip;

	/* At first, the Timing Advance from the initial Channel Request. Later, the Timing Advance value received from
	 * the most recent Measurement Report. */
	uint8_t last_ta;

	/* table of neighbor cell measurements */
	struct neigh_meas_proc neigh_meas[MAX_NEIGH_MEAS];

	/* cache of last measurement reports on this lchan */
	struct gsm_meas_rep meas_rep[MAX_MEAS_REP];
	int meas_rep_idx;
	int meas_rep_count;
	uint8_t meas_rep_last_seen_nr;

	/* GSM Random Access data */
	/* TODO: don't allocate this, rather keep an "is_present" flag */
	struct gsm48_req_ref *rqd_ref;

	struct gsm_subscriber_connection *conn;

	/* After the Channel Activation ACK or RSL Mode Modify ACK is received, this reflects the actually used
	 * channel_mode_and_rate. */
	struct channel_mode_and_rate current_ch_mode_rate;
	struct gsm48_multi_rate_conf current_mr_conf;

	/* Circuit-Switched TSC Set in use, or -1 if no specific TSC Set was requested. The valid range is 1-4 as
	 * described in the spec 3GPP TS 45.002. */
	int tsc_set;
	/* Training Sequence Code in use. The valid range is 0-7 as described in the spec 3GPP TS 45.002. */
	uint8_t tsc;

	struct {
		/* Whether this lchan represents a secondary "shadow" lchan to multiplex a second MS onto a primary
		 * "normal" lchan */
		bool is_secondary;

		/* Whether this lchan is activated/modified into a mode that allows VAMOS multiplexing at this moment */
		bool enabled;
	} vamos;

	/* dBm value of interference level as reported in the most recent Resource Indication, if any for this lchan. Or
	 * INTERF_DBM_UNKNOWN if this lchan was not included in the most recent Resource Indication.
	 * The range is typically -115 to -85 dBm, here stored 1:1 as a signed integer, to ease comparison. */
	int16_t interf_dbm;
	/* Actual reported interference band index, or INTERF_BAND_UNKNOWN if this lchan was not included in the most
	 * recent Resource Indication. */
	uint8_t interf_band;
	/* MS power control state */
	struct lchan_power_ctrl_state ms_power_ctrl;
};

/* One Timeslot in a TRX */
struct gsm_bts_trx_ts {
	struct gsm_bts_trx *trx;
	/* number of this timeslot at the TRX */
	uint8_t nr;

	struct osmo_fsm_inst *fi;
	char *last_errmsg;

	/* vty phys_chan_config setting, not necessarily in effect in case it was changed in the telnet
	 * vty after OML activation. Gets written on vty 'write file'. */
	enum gsm_phys_chan_config pchan_from_config;
	/* When the timeslot OML is established, pchan_from_config is copied here. This is the pchan
	 * currently in effect; for dynamic ts, this is the dyn kind (GSM_PCHAN_OSMO_DYN or
	 * GSM_PCHAN_TCH_F_PDCH) and does not show the pchan type currently active. */
	enum gsm_phys_chan_config pchan_on_init;
	/* This is the *actual* pchan type currently active. For dynamic timeslots, this reflects either
	 * GSM_PCHAN_NONE or one of the standard GSM_PCHAN_TCH_F, GSM_PCHAN_TCH_H, GSM_PCHAN_PDCH.
	 * Callers can use this transparently without being aware of dyn ts. */
	enum gsm_phys_chan_config pchan_is;

	/* After a PDCH ACT NACK, we shall not infinitely loop to try and ACT again.
	 * Also marks a timeslot where PDCH was deactivated by VTY. This is cleared whenever a timeslot
	 * enters IN_USE state, i.e. after each TCH use we try to PDCH ACT once again. */
	bool pdch_act_allowed;

	/* Whether TS_EV_OML_READY was received */
	bool is_oml_ready;
	/* Whether TS_EV_RSL_READY was received */
	bool is_rsl_ready;

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

	/* Maximum BCCH carrier power reduction */
	uint8_t c0_max_power_red_db;

	/* Maximum number of lchans that could become usable, for example by switching a dynamic timeslot's type or by
	 * enabling VAMOS secondary lchans. This does include the maximum count of possible VAMOS secondary lchans. */
	uint8_t max_lchans_possible;
	/* Currently usable lchans, according to the current pchan mode (for dynamic timeslots, this may change).
	 * Does not include count of secondary VAMOS lchans. */
	uint8_t max_primary_lchans;
	struct gsm_lchan lchan[TS_MAX_LCHAN];
};

#define GSM_LCHAN_SI(lchan, i) (void *)((lchan)->si.buf[i][0])

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

/* A single Page of a SMSCB message */
struct bts_smscb_page {
	/* SMSCB message we're part of */
	struct bts_smscb_message *msg;
	/* Page Number within message (1 to 15) */
	uint8_t nr;
	/* number of valid blocks in data (up to 4) */
	uint8_t num_blocks;
	/* up to four blocks of 22 bytes each */
	uint8_t data[88];
};

/* A SMSCB message (received from CBSP) */
struct bts_smscb_message {
	/* entry in bts_smscb_chan_state.messages */
	struct llist_head list;
	struct {
		/* input data from CBSP (CBC) side */
		uint16_t msg_id;
		uint16_t serial_nr;
		enum cbsp_category category;
		uint16_t rep_period;
		uint16_t num_bcast_req;
		uint8_t dcs;
	} input;
	/* how often have all pages of this message been broadcast? */
	uint32_t bcast_count;
	/* actual page data of this message */
	uint8_t num_pages; /* up to 15 */
	struct bts_smscb_page page[15];
};

/* per-channel (basic/extended) CBCH state for a single BTS */
struct bts_smscb_chan_state {
	/* back-pointer to BTS */
	struct gsm_bts *bts;
	/* list of bts_smscb_message */
	struct llist_head messages;
	/* scheduling array; pointer of SMSCB pages */
	struct bts_smscb_page **sched_arr;
	size_t sched_arr_size;
	/* index of the next to be transmitted page into the scheduler array */
	size_t next_idx;
	/* number of messages we have to pause due to overflow */
	uint8_t overflow;
};

struct bts_oml_fail_rep {
	struct llist_head list;
	time_t time;
	struct msgb *mb;
};

/* One rejected BTS */
struct gsm_bts_rejected {
	/* list header in net->bts_rejected */
	struct llist_head list;

	uint16_t site_id;
	uint16_t bts_id;
	char ip[INET6_ADDRSTRLEN];
	time_t time;
};

extern struct osmo_tdef_group bsc_tdef_group[];

struct gsm_network *gsm_network_init(void *ctx);

struct gsm_bts *gsm_bts_num(const struct gsm_network *net, int num);
struct gsm_bts *gsm_bts_by_cell_id(const struct gsm_network *net,
				   const struct gsm0808_cell_id *cell_id,
				   int match_idx);

extern const struct value_string gsm_chreq_descs[];
extern const struct value_string gsm_pchant_names[];
extern const struct value_string gsm_pchant_descs[];
extern const struct value_string gsm_pchan_ids[];
const char *gsm_pchan_name(enum gsm_phys_chan_config c);
static inline const char *gsm_pchan_id(enum gsm_phys_chan_config c)
{ return get_value_string(gsm_pchan_ids, c); }
enum gsm_phys_chan_config gsm_pchan_parse(const char *name);
const char *gsm_lchant_name(enum gsm_chan_t c);
const char *gsm_chreq_name(enum gsm_chreq_reason_t c);
char *gsm_ts_name(const struct gsm_bts_trx_ts *ts);
char *gsm_ts_and_pchan_name(const struct gsm_bts_trx_ts *ts);
void lchan_update_name(struct gsm_lchan *lchan);

static inline char *gsm_lchan_name(const struct gsm_lchan *lchan)
{
	OSMO_ASSERT(lchan);
	return lchan->name;
}

void gsm_abis_mo_reset(struct gsm_abis_mo *mo);
void gsm_mo_init(struct gsm_abis_mo *mo, struct gsm_bts *bts,
		 uint8_t obj_class, uint8_t p1, uint8_t p2, uint8_t p3);

struct gsm_nm_state *
gsm_objclass2nmstate(struct gsm_bts *bts, uint8_t obj_class,
		 const struct abis_om_obj_inst *obj_inst);
void *
gsm_objclass2obj(struct gsm_bts *bts, uint8_t obj_class,
	     const struct abis_om_obj_inst *obj_inst);

int gsm_pchan2chan_nr(enum gsm_phys_chan_config pchan,
		      uint8_t ts_nr, uint8_t lchan_nr, bool vamos_is_secondary);
int gsm_lchan2chan_nr(const struct gsm_lchan *lchan, bool allow_osmo_cbits);
int gsm_lchan_and_pchan2chan_nr(const struct gsm_lchan *lchan, enum gsm_phys_chan_config pchan, bool allow_osmo_cbits);

int gsm48_lchan2chan_desc(struct gsm48_chan_desc *cd,
			  const struct gsm_lchan *lchan,
			  uint8_t tsc, bool allow_osmo_cbits);
int gsm48_lchan_and_pchan2chan_desc(struct gsm48_chan_desc *cd,
				    const struct gsm_lchan *lchan,
				    enum gsm_phys_chan_config pchan,
				    uint8_t tsc, bool allow_osmo_cbits);

uint8_t gsm_ts_tsc(const struct gsm_bts_trx_ts *ts);

uint8_t pchan_subslots(enum gsm_phys_chan_config pchan);
uint8_t pchan_subslots_vamos(enum gsm_phys_chan_config pchan);
bool ts_is_tch(struct gsm_bts_trx_ts *ts);

struct gsm_lchan *gsm_lchan_vamos_to_primary(const struct gsm_lchan *lchan_vamos);
struct gsm_lchan *gsm_lchan_primary_to_vamos(const struct gsm_lchan *lchan_primary);

struct gsm_bts *conn_get_bts(struct gsm_subscriber_connection *conn);

void conn_update_ms_power_class(struct gsm_subscriber_connection *conn, uint8_t power_class);
void lchan_update_ms_power_ctrl_level(struct gsm_lchan *lchan, int ms_power_dbm);

struct gsm_tz {
	int override; /* if 0, use system's time zone instead. */
	int hr; /* hour */
	int mn; /* minute */
	int dst; /* daylight savings */
};

struct gsm_network {
	struct osmo_plmn_id plmn;

	/* bit-mask of permitted encryption algorithms. LSB=A5/0, MSB=A5/7 */
	uint8_t a5_encryption_mask;
	int neci;

	struct handover_cfg *ho;
	struct {
		unsigned int congestion_check_interval_s;
		struct osmo_timer_list congestion_check_timer;
	} hodec2;

	/* structures for keeping rate counters and gauge stats */
	struct rate_ctr_group *bsc_ctrs;
	struct osmo_stat_item_group *bsc_statg;

	unsigned int num_bts;
	struct llist_head bts_list;
	struct llist_head bts_rejected;

        /* BTS-based counters when we can't find the actual BTS
         * e.g. when conn->lchan is NULL */
        struct rate_ctr_group *bts_unknown_ctrs;
        struct osmo_stat_item_group *bts_unknown_statg;

	/* see gsm_network_T_defs */
	struct osmo_tdef *T_defs;

	enum gsm_chan_t ctype_by_chreq[_NUM_CHREQ_T];

	/* Use a TCH for handling requests of type paging any */
	int pag_any_tch;

	/* msc configuration */
	struct llist_head mscs;
	uint8_t mscs_round_robin_next_nr;
	/* Emergency calls potentially select a different set of MSCs, so to not mess up the normal round-robin
	 * behavior, emergency calls need a separate round-robin counter. */
	uint8_t mscs_round_robin_next_emerg_nr;

	/* rf ctl related bits */
	int mid_call_timeout;
	char *rf_ctrl_name;
	struct osmo_bsc_rf *rf_ctrl;
	int auto_off_timeout;

	struct bsc_cbc_link *cbc;

	/* control interface */
	struct ctrl_handle *ctrl;

	/* Allow or disallow TCH/F on dynamic TCH/F_TCH/H_SDCCH8_PDCH; OS#1778 */
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

	/* Timer for periodic channel load measurements to maintain each BTS's T3122. */
	struct osmo_timer_list t3122_chan_load_timer;

	/* Timer to write each BTS's uptime counter state to the stats system. */
	struct osmo_timer_list bts_store_uptime_timer;

	struct {
		/* Single MGCP client configuration under msc node (also required for
		 * MGCP proxy when sccp-lite is used) */
		struct mgcp_client_conf *conf;

		/* MGW pool, also includes the single MGCP client as fallback if no
		 * pool is configured. */
		struct mgcp_client_pool *mgw_pool;

		/* Timer definitions, the same for all MGW pool members */
		struct osmo_tdef *tdefs;
	} mgw;

	/* Remote BSS resolution sevice (CTRL iface) */
	struct {
		char *addr;
		uint16_t port;
		struct ctrl_handle *handle;
	} neigh_ctrl;

	/* Don't refuse to start with mutually exclusive codec settings */
	bool allow_unusable_timeslots;

	uint8_t nri_bitlen;
	struct osmo_nri_ranges *null_nri_ranges;

	struct smlc_config *smlc;

	struct osmo_time_cc all_allocated_sdcch;
	struct osmo_time_cc all_allocated_static_sdcch;
	struct osmo_time_cc all_allocated_tch;
	struct osmo_time_cc all_allocated_static_tch;
};

struct gsm_audio_support {
        uint8_t hr  : 1,
                ver : 7;
};

extern void talloc_ctx_init(void *ctx_root);

enum gsm_bts_type parse_btstype(const char *arg);
const char *btstype2str(enum gsm_bts_type type);
struct gsm_bts *gsm_bts_by_lac(struct gsm_network *net, unsigned int lac,
				struct gsm_bts *start_bts);

extern void *tall_bsc_ctx;

extern struct gsm_network *bsc_gsmnet;

enum bts_gprs_mode bts_gprs_mode_parse(const char *arg, int *valid);
const char *bts_gprs_mode_name(enum bts_gprs_mode mode);

void gsm48_ra_id_by_bts(struct gsm48_ra_id *buf, struct gsm_bts *bts);
void gprs_ra_id_by_bts(struct gprs_ra_id *raid, struct gsm_bts *bts);

struct gsm_subscriber_connection *bsc_subscr_con_allocate(struct gsm_network *network);

struct gsm_bts *gsm_bts_alloc_register(struct gsm_network *net, enum gsm_bts_type type, uint8_t bsic);
struct gsm_bts *bsc_bts_alloc_register(struct gsm_network *net, enum gsm_bts_type type, uint8_t bsic);

void set_ts_e1link(struct gsm_bts_trx_ts *ts, uint8_t e1_nr,
		   uint8_t e1_ts, uint8_t e1_ts_ss);

/* generic E1 line operations for all ISDN-based BTS. */
extern struct e1inp_line_ops bts_isdn_e1inp_line_ops;

/* control interface handling */
int bsc_base_ctrl_cmds_install(void);

bool ts_is_usable(const struct gsm_bts_trx_ts *ts);

int gsm_lchan_type_by_pchan(enum gsm_phys_chan_config pchan);
enum gsm_phys_chan_config gsm_pchan_by_lchan_type(enum gsm_chan_t type);

enum gsm48_rr_cause bsc_gsm48_rr_cause_from_gsm0808_cause(enum gsm0808_cause c);
enum gsm48_rr_cause bsc_gsm48_rr_cause_from_rsl_cause(uint8_t c);

int bsc_sccp_inst_next_conn_id(struct osmo_sccp_instance *sccp);

/* MS/BS Power related measurement averaging algo */
enum gsm_power_ctrl_meas_avg_algo {
	GSM_PWR_CTRL_MEAS_AVG_ALGO_NONE			= 0x00,
	GSM_PWR_CTRL_MEAS_AVG_ALGO_UNWEIGHTED		= 0x01,
	GSM_PWR_CTRL_MEAS_AVG_ALGO_WEIGHTED		= 0x02,
	GSM_PWR_CTRL_MEAS_AVG_ALGO_MOD_MEDIAN		= 0x03,
	/* EWMA is an Osmocom specific algo */
	GSM_PWR_CTRL_MEAS_AVG_ALGO_OSMO_EWMA		= 0x04,
};

/* MS/BS Power related measurement parameters */
struct gsm_power_ctrl_meas_params {
	/* Are these measurement paremeters to be taken into account by loop? */
	bool enabled;

	/* Thresholds (see 3GPP TS 45.008, section A.3.2.1) */
	uint8_t lower_thresh; /* lower (decreasing) direction */
	uint8_t upper_thresh; /* upper (increasing) direction */

	/* Threshold Comparators for lower (decreasing) direction */
	uint8_t lower_cmp_p; /* P1 for RxLev, P3 for RxQual */
	uint8_t lower_cmp_n; /* N1 for RxLev, N3 for RxQual */
	/* Threshold Comparators for upper (increasing) direction */
	uint8_t upper_cmp_p; /* P2 for RxLev, P4 for RxQual */
	uint8_t upper_cmp_n; /* N2 for RxLev, N4 for RxQual */

	/* Hreqave and Hreqt (see 3GPP TS 45.008, Annex A) */
	uint8_t h_reqave;
	uint8_t h_reqt;

	/* AVG algorithm and its specific parameters */
	enum gsm_power_ctrl_meas_avg_algo algo;
	union {
		/* Exponentially Weighted Moving Average */
		struct {
			/* Smoothing factor: higher the value - less smoothing */
			uint8_t alpha; /* 1 .. 99 (in %) */
		} ewma;
	};
};

enum gsm_power_ctrl_dir {
	GSM_PWR_CTRL_DIR_UL, /* MS Power Control */
	GSM_PWR_CTRL_DIR_DL, /* BS Power Control */
};

enum gsm_power_ctrl_mode {
	/* Do not send MS/BS Power Control IEs */
	GSM_PWR_CTRL_MODE_NONE = 0,
	/* Send MS/BS Power IE only (with target level) */
	GSM_PWR_CTRL_MODE_STATIC,
	/* Send MS/BS Power [Parameters] IEs (dynamic mode) */
	GSM_PWR_CTRL_MODE_DYN_BTS,
	/* Do not send MS/BS Power IEs and use BSC Power Loop */
	GSM_PWR_CTRL_MODE_DYN_BSC,

};

/* MS/BS Power Control Parameters */
struct gsm_power_ctrl_params {
	/* Power Control direction: Uplink or Downlink */
	enum gsm_power_ctrl_dir dir;
	/* Power Control mode to be used by the BTS */
	enum gsm_power_ctrl_mode mode;

	/* BS Power reduction value / maximum (in dB) */
	uint8_t bs_power_val_db; /* for static mode */
	uint8_t bs_power_max_db; /* for dynamic mode */

	/* Power change step size (dynamic mode only) */
	uint8_t inc_step_size_db; /* increasing direction */
	uint8_t red_step_size_db; /* reducing direction */

	/* Minimum interval between power level changes */
	uint8_t ctrl_interval; /* 1 step is 2 SACCH periods */

	/* Measurement averaging parameters for RxLev & RxQual */
	struct gsm_power_ctrl_meas_params rxqual_meas;
	struct gsm_power_ctrl_meas_params rxlev_meas;
	/* Measurement averaging parameters for C/I: */
	struct gsm_power_ctrl_meas_params ci_fr_meas;
	struct gsm_power_ctrl_meas_params ci_hr_meas;
	struct gsm_power_ctrl_meas_params ci_amr_fr_meas;
	struct gsm_power_ctrl_meas_params ci_amr_hr_meas;
	struct gsm_power_ctrl_meas_params ci_sdcch_meas;
	struct gsm_power_ctrl_meas_params ci_gprs_meas;
};

extern const struct gsm_power_ctrl_params power_ctrl_params_def;
void power_ctrl_params_def_reset(struct gsm_power_ctrl_params *params,
				 enum gsm_power_ctrl_dir dir);

/* Interference Measurement Parameters */
struct gsm_interf_meas_params {
	/* Intave: Interference Averaging period (see 3GPP TS 45.008, table A.1) */
	uint8_t avg_period; /* number of SACCH multiframes, 1 .. 31 */
	/* Interference level Boundaries (see 3GPP TS 52.021, section 9.4.25) */
	uint8_t bounds_dbm[6]; /* -x dBm values for boundaries 0 .. X5 */
};

extern const struct gsm_interf_meas_params interf_meas_params_def;

enum rsl_cmod_spd chan_mode_to_rsl_cmod_spd(enum gsm48_chan_mode chan_mode);

int select_best_cipher(uint8_t msc_mask, uint8_t bsc_mask);

#endif /* _GSM_DATA_H */
