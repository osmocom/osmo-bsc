#pragma once

#include <stdint.h>
#include <stdbool.h>

#include <osmocom/core/utils.h>

#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gsm/protocol/gsm_08_08.h>
#include <osmocom/gsm/protocol/gsm_08_58.h>
#include <osmocom/gsm/gsm23003.h>

#include <osmocom/bsc/meas_rep.h>

/* If .present is false, use the default value defined elsewhere. If true, use .val below.
 * (A practical benefit of this is that the default initialization sets .present to false, so that even if a .val == 0
 * is a valid value, a struct containing this as member does not need to explicitly set .val = INVALID_VAL_CONSTANT.) */
struct optional_val {
	bool present;
	int val;
};

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

enum channel_rate {
	CH_RATE_SDCCH,
	CH_RATE_HALF,
	CH_RATE_FULL,
};

enum channel_rate chan_t_to_chan_rate(enum gsm_chan_t chan_t);

struct channel_mode_and_rate {
	enum gsm48_chan_mode chan_mode;
	enum channel_rate chan_rate;
	uint16_t s15_s0;
	/* only used for GSM48_CMODE_DATA_* */
	bool data_transparent;
	union {
		enum rsl_cmod_csd_t t;
		enum rsl_cmod_csd_nt nt;
	} data_rate;
};

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

/* State of the SAPIs in the lchan */
enum lchan_sapi_state {
	LCHAN_SAPI_S_NONE,
	LCHAN_SAPI_S_REQ,
	LCHAN_SAPI_S_ASSIGNED,
	LCHAN_SAPI_S_REL,
	LCHAN_SAPI_S_ERROR,
};

/* is the data link established? who established it? */
#define LCHAN_SAPI_UNUSED	0
#define LCHAN_SAPI_MS		1
#define LCHAN_SAPI_NET		2

#define MAX_A5_KEY_LEN	(128/8)

struct gsm_encr {
	uint8_t alg_a5_n; /* N: 0 (A5/0), 1 (A5/1), ... 7 (A5/7) */
	uint8_t key_len;
	uint8_t key[MAX_A5_KEY_LEN];
	bool kc128_present;
	uint8_t kc128[16];
};

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
	enum gsm0808_chan_indicator ch_indctr;
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
	enum gsm0808_chan_indicator ch_indctr;
	uint16_t msc_assigned_cic;

	/* The TSC Set to use if 'use' is true, otherwise automatically determine the TSC Set value to use. Valid range
	 * is 1 to 4, as described in 3GPP TS 45.002. */
	struct optional_val tsc_set;
	/* The TSC to use if 'use' is true, otherwise automatically determine the TSC value to use. Valid range is 0 to
	 * 7, as described in 3GPP TS 45.002. */
	struct optional_val tsc;

	bool vamos;
};

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
		enum gsm0808_chan_indicator ch_indctr;
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
		enum gsm0808_chan_indicator ch_indctr;
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
		uint8_t rtp_csd_fmt;
		uint8_t speech_mode;

		/* info we need to postpone the AoIP
		 * assignment completed message */
		struct {
			uint8_t rr_cause;
			bool valid;
		} ass_compl;

		struct {
			bool use;
			uint8_t local_cid;
			bool remote_cid_present;
			uint8_t remote_cid;
		} osmux;
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
	enum gsm0808_chan_indicator current_ch_indctr;

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
	/* Timestamps and markers to track active state duration. */
	struct timespec active_start;
	struct timespec active_stored;
};

#define GSM_LCHAN_SI(lchan, i) (void *)((lchan)->si.buf[i][0])

void lchan_init(struct gsm_lchan *lchan, struct gsm_bts_trx_ts *ts, unsigned int nr);

void lchan_update_name(struct gsm_lchan *lchan);
uint64_t gsm_lchan_active_duration_ms(const struct gsm_lchan *lchan);

static inline char *gsm_lchan_name(const struct gsm_lchan *lchan)
{
	OSMO_ASSERT(lchan);
	return lchan->name;
}

struct gsm_lchan *gsm_lchan_vamos_to_primary(const struct gsm_lchan *lchan_vamos);
struct gsm_lchan *gsm_lchan_primary_to_vamos(const struct gsm_lchan *lchan_primary);

void lchan_update_ms_power_ctrl_level(struct gsm_lchan *lchan, int ms_power_dbm);

#define LOGPLCHAN(lchan, ss, level, fmt, args...) \
	LOGP(ss, level, "%s (ss=%d,%s) (%s) " fmt, \
	     lchan ? gsm_ts_and_pchan_name(lchan->ts) : "-", \
	     lchan ? lchan->nr : 0, \
	     lchan ? gsm_chan_t_name(lchan->type) : "-", \
	     bsc_subscr_name(lchan && lchan->conn ? lchan->conn->bsub : NULL), \
	     ## args)
