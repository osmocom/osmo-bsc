#ifndef _GSM_04_08_H
#define _GSM_04_08_H

/* GSM TS 04.08  definitions */
struct gsm_lchan;

struct gsm48_classmark1 {
	u_int8_t spare:1,
		 rev_level:2,
		 es_ind:1,
		 a5_1:1,
		 pwr_lev:3;
} __attribute__ ((packed));

/* Chapter 10.5.2.5 */
struct gsm48_chan_desc {
	u_int8_t chan_nr;
	union {
		struct {
			u_int8_t maio_high:4,
				 h:1,
				 tsc:3;
			u_int8_t hsn:6,
				 maio_low:2;
		} h1;
		struct {
			u_int8_t arfcn_high:2,
				 spare:2,
				 h:1,
				 tsc:3;
			u_int8_t arfcn_low;
		} h0;
	};
} __attribute__ ((packed));

/* Chapter 10.5.2.21aa */
struct gsm48_multi_rate_conf {
	u_int8_t smod : 2,
		 spare: 1,
		 icmi : 1,
		 nscb : 1,
		 ver : 3;
	u_int8_t m4_75 : 1,
		 m5_15 : 1,
		 m5_90 : 1,
		 m6_70 : 1,
		 m7_40 : 1,
		 m7_95 : 1,
		 m10_2 : 1,
		 m12_2 : 1;
} __attribute__((packed));

/* Chapter 10.5.2.30 */
struct gsm48_req_ref {
	u_int8_t ra;
	u_int8_t t3_high:3,
		 t1_:5;
	u_int8_t t2:5,
		 t3_low:3;
} __attribute__ ((packed));

/*
 * Chapter 9.1.5/9.1.6
 *
 * For 9.1.6 the chan_desc has the meaning of 10.5.2.5a
 */
struct gsm48_chan_mode_modify {
	struct gsm48_chan_desc chan_desc;
	u_int8_t mode;
} __attribute__ ((packed));

enum gsm48_chan_mode {
	GSM48_CMODE_SIGN	= 0x00,
	GSM48_CMODE_SPEECH_V1	= 0x01,
	GSM48_CMODE_SPEECH_EFR	= 0x21,
	GSM48_CMODE_SPEECH_AMR	= 0x41,
	GSM48_CMODE_DATA_14k5	= 0x0f,
	GSM48_CMODE_DATA_12k0	= 0x03,
	GSM48_CMODE_DATA_6k0	= 0x0b,
	GSM48_CMODE_DATA_3k6	= 0x23,
};

/* Chapter 9.1.2 */
struct gsm48_ass_cmd {
	/* Semantic is from 10.5.2.5a */
	struct gsm48_chan_desc chan_desc;
	u_int8_t power_command;
	u_int8_t data[0];
} __attribute__((packed));


/* Chapter 9.1.18 */
struct gsm48_imm_ass {
	u_int8_t l2_plen;
	u_int8_t proto_discr;
	u_int8_t msg_type;
	u_int8_t page_mode;
	struct gsm48_chan_desc chan_desc;
	struct gsm48_req_ref req_ref;
	u_int8_t timing_advance;
	u_int8_t mob_alloc_len;
	u_int8_t mob_alloc[0];
} __attribute__ ((packed));

/* Chapter 10.5.1.3 */
struct gsm48_loc_area_id {
	u_int8_t digits[3];	/* BCD! */
	u_int16_t lac;
} __attribute__ ((packed));

/* Section 9.2.2 */
struct gsm48_auth_req {
	u_int8_t key_seq:4,
	         spare:4;
	u_int8_t rand[16];
} __attribute__ ((packed));

/* Section 9.2.15 */
struct gsm48_loc_upd_req {
	u_int8_t type:4,
		 key_seq:4;
	struct gsm48_loc_area_id lai;
	struct gsm48_classmark1 classmark1;
	u_int8_t mi_len;
	u_int8_t mi[0];
} __attribute__ ((packed));

/* Section 10.1 */
struct gsm48_hdr {
	u_int8_t proto_discr;
	u_int8_t msg_type;
	u_int8_t data[0];
} __attribute__ ((packed));

/* Section 9.1.3x System information Type header */
struct gsm48_system_information_type_header {
	u_int8_t l2_plen;
	u_int8_t rr_protocol_discriminator :4,
		skip_indicator:4; 
	u_int8_t system_information;
} __attribute__ ((packed));

struct gsm48_rach_control {
	u_int8_t re :1,
		 cell_bar :1,
		 tx_integer :4,
		 max_trans :2;
	u_int8_t t2;
	u_int8_t t3;
} __attribute__ ((packed));

/* Section 10.5.2.4 Cell Selection Parameters */
struct gsm48_cell_sel_par {
	u_int8_t ms_txpwr_max_ccch:5,	/* GSM 05.08 MS-TXPWR-MAX-CCCH */
		 cell_resel_hyst:3;	/* GSM 05.08 CELL-RESELECT-HYSTERESIS */
	u_int8_t rxlev_acc_min:6,	/* GSM 05.08 RXLEV-ACCESS-MIN */
		 neci:1,
		 acs:1;
} __attribute__ ((packed));

/* Section 10.5.2.11 Control Channel Description , Figure 10.5.33 */
struct gsm48_control_channel_descr {
	u_int8_t ccch_conf :3,
		bs_ag_blks_res :3,
		att :1,
		spare1 :1;
	u_int8_t bs_pa_mfrms : 3,
		spare2 :5;
	u_int8_t t3212;
} __attribute__ ((packed));

/* Section 9.2.9 CM service request */
struct gsm48_service_request {
	u_int8_t cm_service_type : 4,
		 cipher_key_seq  : 4;
	/* length + 3 bytes */
	u_int32_t classmark;
	u_int8_t mi_len;
	u_int8_t mi[0];
	/* optional priority level */
} __attribute__ ((packed));

/* Section 9.1.31 System information Type 1 */
struct gsm48_system_information_type_1 {
	struct gsm48_system_information_type_header header;
	u_int8_t cell_channel_description[16];
	struct gsm48_rach_control rach_control;
	u_int8_t s1_reset;
} __attribute__ ((packed));

/* Section 9.1.32 System information Type 2 */
struct gsm48_system_information_type_2 {
	struct gsm48_system_information_type_header header;
	u_int8_t bcch_frequency_list[16];
	u_int8_t ncc_permitted;
	struct gsm48_rach_control rach_control;
} __attribute__ ((packed));

/* Section 9.1.35 System information Type 3 */
struct gsm48_system_information_type_3 {
	struct gsm48_system_information_type_header header;
	u_int16_t cell_identity;
	struct gsm48_loc_area_id lai;
	struct gsm48_control_channel_descr control_channel_desc;
	u_int8_t cell_options;
	struct gsm48_cell_sel_par cell_sel_par;
	struct gsm48_rach_control rach_control;
	u_int8_t s3_reset_octets[4];
} __attribute__ ((packed));

/* Section 9.1.36 System information Type 4 */
struct gsm48_system_information_type_4 {
	struct gsm48_system_information_type_header header;
	struct gsm48_loc_area_id lai;
	struct gsm48_cell_sel_par cell_sel_par;
	struct gsm48_rach_control rach_control;
	/*	optional CBCH conditional CBCH... followed by
		mandantory SI 4 Reset Octets
	 */
	u_int8_t data[0];
} __attribute__ ((packed));

/* Section 9.1.37 System information Type 5 */
struct gsm48_system_information_type_5 {
	u_int8_t rr_protocol_discriminator :4,
		skip_indicator:4; 
	u_int8_t system_information;
	u_int8_t bcch_frequency_list[16];
} __attribute__ ((packed));

/* Section 9.1.40 System information Type 6 */
struct gsm48_system_information_type_6 {
	u_int8_t rr_protocol_discriminator :4,
		skip_indicator:4; 
	u_int8_t system_information;
	u_int16_t cell_identity;
	struct gsm48_loc_area_id lai;
	u_int8_t cell_options;
	u_int8_t ncc_permitted;
	u_int8_t si_6_reset[0];
} __attribute__ ((packed));

/* Section 9.2.12 IMSI Detach Indication */
struct gsm48_imsi_detach_ind {
	struct gsm48_classmark1 classmark1;
	u_int8_t mi_len;
	u_int8_t mi[0];
} __attribute__ ((packed));

/* Section 10.2 + GSM 04.07 12.2.3.1.1 */
#define GSM48_PDISC_GROUP_CC	0x00
#define GSM48_PDISC_BCAST_CC	0x01
#define GSM48_PDISC_PDSS1	0x02
#define GSM48_PDISC_CC		0x03
#define GSM48_PDISC_PDSS2	0x04
#define GSM48_PDISC_MM		0x05
#define GSM48_PDISC_RR		0x06
#define GSM48_PDISC_MM_GPRS	0x08
#define GSM48_PDISC_SMS		0x09
#define GSM48_PDISC_SM_GPRS	0x0a
#define GSM48_PDISC_NC_SS	0x0b
#define GSM48_PDISC_LOC		0x0c
#define GSM48_PDISC_MASK	0x0f
#define GSM48_PDISC_USSD	0x11

/* Section 10.4 */
#define GSM48_MT_RR_INIT_REQ		0x3c
#define GSM48_MT_RR_ADD_ASS		0x3b
#define GSM48_MT_RR_IMM_ASS		0x3f
#define GSM48_MT_RR_IMM_ASS_EXT		0x39
#define GSM48_MT_RR_IMM_ASS_REJ		0x3a

#define GSM48_MT_RR_CIPH_M_CMD		0x35
#define GSM48_MT_RR_CIPH_M_COMPL	0x32

#define GSM48_MT_RR_CFG_CHG_CMD		0x30
#define GSM48_MT_RR_CFG_CHG_ACK		0x31
#define GSM48_MT_RR_CFG_CHG_REJ		0x33

#define GSM48_MT_RR_ASS_CMD		0x2e
#define GSM48_MT_RR_ASS_COMPL		0x29
#define GSM48_MT_RR_ASS_FAIL		0x2f
#define GSM48_MT_RR_HANDO_CMD		0x2b
#define GSM48_MT_RR_HANDO_COMPL		0x2c
#define GSM48_MT_RR_HANDO_FAIL		0x28
#define GSM48_MT_RR_HANDO_INFO		0x2d

#define GSM48_MT_RR_CELL_CHG_ORDER	0x08
#define GSM48_MT_RR_PDCH_ASS_CMD	0x23

#define GSM48_MT_RR_CHAN_REL		0x0d
#define GSM48_MT_RR_PART_REL		0x0a
#define GSM48_MT_RR_PART_REL_COMP	0x0f

#define GSM48_MT_RR_PAG_REQ_1		0x21
#define GSM48_MT_RR_PAG_REQ_2		0x22
#define GSM48_MT_RR_PAG_REQ_3		0x24
#define GSM48_MT_RR_PAG_RESP		0x27
#define GSM48_MT_RR_NOTIF_NCH		0x20
#define GSM48_MT_RR_NOTIF_FACCH		0x25
#define GSM48_MT_RR_NOTIF_RESP		0x26

#define GSM48_MT_RR_SYSINFO_8		0x18
#define GSM48_MT_RR_SYSINFO_1		0x19
#define GSM48_MT_RR_SYSINFO_2		0x1a
#define GSM48_MT_RR_SYSINFO_3		0x1b
#define GSM48_MT_RR_SYSINFO_4		0x1c
#define GSM48_MT_RR_SYSINFO_5		0x1d
#define GSM48_MT_RR_SYSINFO_6		0x1e
#define GSM48_MT_RR_SYSINFO_7		0x1f

#define GSM48_MT_RR_SYSINFO_2bis	0x02
#define GSM48_MT_RR_SYSINFO_2ter	0x03
#define GSM48_MT_RR_SYSINFO_5bis	0x05
#define GSM48_MT_RR_SYSINFO_5ter	0x06
#define GSM48_MT_RR_SYSINFO_9		0x04
#define GSM48_MT_RR_SYSINFO_13		0x00

#define GSM48_MT_RR_SYSINFO_16		0x3d
#define GSM48_MT_RR_SYSINFO_17		0x3e

#define GSM48_MT_RR_CHAN_MODE_MODIF	0x10
#define GSM48_MT_RR_STATUS		0x12
#define GSM48_MT_RR_CHAN_MODE_MODIF_ACK	0x17
#define GSM48_MT_RR_FREQ_REDEF		0x14
#define GSM48_MT_RR_MEAS_REP		0x15
#define GSM48_MT_RR_CLSM_CHG		0x16
#define GSM48_MT_RR_CLSM_ENQ		0x13
#define GSM48_MT_RR_EXT_MEAS_REP	0x36
#define GSM48_MT_RR_EXT_MEAS_REP_ORD	0x37
#define GSM48_MT_RR_GPRS_SUSP_REQ	0x34

#define GSM48_MT_RR_VGCS_UPL_GRANT	0x08
#define GSM48_MT_RR_UPLINK_RELEASE	0x0e
#define GSM48_MT_RR_UPLINK_FREE		0x0c
#define GSM48_MT_RR_UPLINK_BUSY		0x2a
#define GSM48_MT_RR_TALKER_IND		0x11

#define GSM48_MT_RR_APP_INFO		0x38

/* Table 10.2/3GPP TS 04.08 */
#define GSM48_MT_MM_IMSI_DETACH_IND	0x01
#define GSM48_MT_MM_LOC_UPD_ACCEPT	0x02
#define GSM48_MT_MM_LOC_UPD_REJECT	0x04
#define GSM48_MT_MM_LOC_UPD_REQUEST	0x08

#define GSM48_MT_MM_AUTH_REJ		0x11
#define GSM48_MT_MM_AUTH_REQ		0x12
#define GSM48_MT_MM_AUTH_RESP		0x14
#define GSM48_MT_MM_ID_REQ		0x18
#define GSM48_MT_MM_ID_RESP		0x19
#define GSM48_MT_MM_TMSI_REALL_CMD	0x1a
#define GSM48_MT_MM_TMSI_REALL_COMPL	0x1b

#define GSM48_MT_MM_CM_SERV_ACC		0x21
#define GSM48_MT_MM_CM_SERV_REJ		0x22
#define GSM48_MT_MM_CM_SERV_ABORT	0x23
#define GSM48_MT_MM_CM_SERV_REQ		0x24
#define GSM48_MT_MM_CM_SERV_PROMPT	0x25
#define GSM48_MT_MM_CM_REEST_REQ	0x28
#define GSM48_MT_MM_ABORT		0x29

#define GSM48_MT_MM_NULL		0x30
#define GSM48_MT_MM_STATUS		0x31
#define GSM48_MT_MM_INFO		0x32

/* Table 10.3/3GPP TS 04.08 */
#define GSM48_MT_CC_ALERTING		0x01
#define GSM48_MT_CC_CALL_CONF		0x08
#define GSM48_MT_CC_CALL_PROC		0x02
#define GSM48_MT_CC_CONNECT		0x07
#define GSM48_MT_CC_CONNECT_ACK		0x0f
#define GSM48_MT_CC_EMERG_SETUP		0x0e
#define GSM48_MT_CC_PROGRESS		0x03
#define GSM48_MT_CC_ESTAB		0x04
#define GSM48_MT_CC_ESTAB_CONF		0x06
#define GSM48_MT_CC_RECALL		0x0b
#define GSM48_MT_CC_START_CC		0x09
#define GSM48_MT_CC_SETUP		0x05

#define GSM48_MT_CC_MODIFY		0x17
#define GSM48_MT_CC_MODIFY_COMPL	0x1f
#define GSM48_MT_CC_MODIFY_REJECT	0x13
#define GSM48_MT_CC_USER_INFO		0x10
#define GSM48_MT_CC_HOLD		0x18
#define GSM48_MT_CC_HOLD_ACK		0x19
#define GSM48_MT_CC_HOLD_REJ		0x1a
#define GSM48_MT_CC_RETR		0x1c
#define GSM48_MT_CC_RETR_ACK		0x1d
#define GSM48_MT_CC_RETR_REJ		0x1e

#define GSM48_MT_CC_DISCONNECT		0x25
#define GSM48_MT_CC_RELEASE		0x2d
#define GSM48_MT_CC_RELEASE_COMPL	0x2a

#define GSM48_MT_CC_CONG_CTRL		0x39
#define GSM48_MT_CC_NOTIFY		0x3e
#define GSM48_MT_CC_STATUS		0x3d
#define GSM48_MT_CC_STATUS_ENQ		0x34
#define GSM48_MT_CC_START_DTMF		0x35
#define GSM48_MT_CC_STOP_DTMF		0x31
#define GSM48_MT_CC_STOP_DTMF_ACK	0x32
#define GSM48_MT_CC_START_DTMF_ACK	0x36
#define GSM48_MT_CC_START_DTMF_REJ	0x37
#define GSM48_MT_CC_FACILITY		0x3a

/* FIXME: Table 10.4 / 10.4a (GPRS) */

/* Section 10.5.2.26, Table 10.5.64 */
#define GSM48_PM_MASK		0x03
#define GSM48_PM_NORMAL		0x00
#define GSM48_PM_EXTENDED	0x01
#define GSM48_PM_REORG		0x02
#define GSM48_PM_SAME		0x03

/* Chapter 10.5.3.5 / Table 10.5.93 */
#define GSM48_LUPD_NORMAL	0x0
#define GSM48_LUPD_PERIODIC	0x1
#define GSM48_LUPD_IMSI_ATT	0x2
#define GSM48_LUPD_RESERVED	0x3

/* Table 10.5.4 */
#define GSM_MI_TYPE_MASK	0x07
#define GSM_MI_TYPE_NONE	0x00
#define GSM_MI_TYPE_IMSI	0x01
#define GSM_MI_TYPE_IMEI	0x02
#define GSM_MI_TYPE_IMEISV	0x03
#define GSM_MI_TYPE_TMSI	0x04
#define GSM_MI_ODD		0x08

#define GSM48_IE_MUL_RATE_CFG	0x03	/* 10.5.2.21aa */
#define GSM48_IE_MOBILE_ID	0x17
#define GSM48_IE_NAME_LONG	0x43	/* 10.5.3.5a */
#define GSM48_IE_NAME_SHORT	0x45	/* 10.5.3.5a */
#define GSM48_IE_UTC		0x46	/* 10.5.3.8 */
#define GSM48_IE_NET_TIME_TZ	0x47	/* 10.5.3.9 */
#define GSM48_IE_LSA_IDENT	0x48	/* 10.5.3.11 */

#define GSM48_IE_BEARER_CAP	0x04	/* 10.5.4.5 */
#define GSM48_IE_CAUSE		0x08	/* 10.5.4.11 */
#define GSM48_IE_CC_CAP		0x15	/* 10.5.4.5a */
#define GSM48_IE_ALERT		0x19	/* 10.5.4.26 */
#define GSM48_IE_FACILITY	0x1c	/* 10.5.4.15 */
#define GSM48_IE_PROGR_IND	0x1e	/* 10.5.4.21 */
#define GSM48_IE_AUX_STATUS	0x24	/* 10.5.4.4 */
#define GSM48_IE_NOTIFY		0x27	/* 10.5.4.20 */
#define GSM48_IE_KPD_FACILITY	0x2c	/* 10.5.4.17 */
#define GSM48_IE_SIGNAL		0x34	/* 10.5.4.23 */
#define GSM48_IE_CONN_BCD	0x4c	/* 10.5.4.13 */
#define GSM48_IE_CONN_SUB	0x4d	/* 10.5.4.14 */
#define GSM48_IE_CALLING_BCD	0x5c	/* 10.5.4.9 */
#define GSM48_IE_CALLING_SUB	0x5d	/* 10.5.4.10 */
#define GSM48_IE_CALLED_BCD	0x5e	/* 10.5.4.7 */
#define GSM48_IE_CALLED_SUB	0x6d	/* 10.5.4.8 */
#define GSM48_IE_REDIR_BCD	0x74	/* 10.5.4.21a */
#define GSM48_IE_REDIR_SUB	0x75	/* 10.5.4.21b */
#define GSM48_IE_LOWL_COMPAT	0x7c	/* 10.5.4.18 */
#define GSM48_IE_HIGHL_COMPAT	0x7d	/* 10.5.4.16 */
#define GSM48_IE_USER_USER	0x7e	/* 10.5.4.25 */
#define GSM48_IE_SS_VERS	0x7f	/* 10.5.4.24 */
#define GSM48_IE_MORE_DATA	0xa0	/* 10.5.4.19 */
#define GSM48_IE_CLIR_SUPP	0xa1	/* 10.5.4.11a */
#define GSM48_IE_CLIR_INVOC	0xa2	/* 10.5.4.11b */
#define GSM48_IE_REV_C_SETUP	0xa3	/* 10.5.4.22a */
#define GSM48_IE_REPEAT_CIR	0xd1	/* 10.5.4.22 */
#define GSM48_IE_REPEAT_SEQ	0xd3	/* 10.5.4.22 */

/* Section 10.5.4.11 / Table 10.5.122 */
#define GSM48_CAUSE_CS_GSM	0x60

/* Section 9.1.2 / Table 9.3 */
#define GSM48_IE_FRQLIST_AFTER	0x05
#define GSM48_IE_CELL_CH_DESC	0x62
#define GSM48_IE_MSLOT_DESC	0x10
#define GSM48_IE_CHANMODE_1	0x63
#define GSM48_IE_CHANMODE_2	0x11
#define GSM48_IE_CHANMODE_3	0x13
#define GSM48_IE_CHANMODE_4	0x14
#define GSM48_IE_CHANMODE_5	0x15
#define GSM48_IE_CHANMODE_6	0x16
#define GSM48_IE_CHANMODE_7	0x17
#define GSM48_IE_CHANMODE_8	0x18
#define GSM48_IE_CHANDESC_2	0x64
/* FIXME */

/* Section 10.5.4.23 / Table 10.5.130 */
enum gsm48_signal_val {
	GSM48_SIGNAL_DIALTONE	= 0x00,
	GSM48_SIGNAL_RINGBACK	= 0x01,
	GSM48_SIGNAL_INTERCEPT	= 0x02,
	GSM48_SIGNAL_NET_CONG	= 0x03,
	GSM48_SIGNAL_BUSY	= 0x04,
	GSM48_SIGNAL_CONFIRM	= 0x05,
	GSM48_SIGNAL_ANSWER	= 0x06,
	GSM48_SIGNAL_CALL_WAIT	= 0x07,
	GSM48_SIGNAL_OFF_HOOK	= 0x08,
	GSM48_SIGNAL_OFF	= 0x3f,
	GSM48_SIGNAL_ALERT_OFF	= 0x4f,
};

enum gsm48_cause_loc {
	GSM48_CAUSE_LOC_USER		= 0x00,
	GSM48_CAUSE_LOC_PRN_S_LU	= 0x01,
	GSM48_CAUSE_LOC_PUN_S_LU	= 0x02,
	GSM48_CAUSE_LOC_TRANS_NET	= 0x03,
	GSM48_CAUSE_LOC_PUN_S_RU	= 0x04,
	GSM48_CAUSE_LOC_PRN_S_RU	= 0x05,
	/* not defined */
	GSM48_CAUSE_LOC_INN_NET		= 0x07,
	GSM48_CAUSE_LOC_NET_BEYOND	= 0x0a,
};

/* Section 10.5.2.31 RR Cause / Table 10.5.70 */
enum gsm48_rr_cause {
	GSM48_RR_CAUSE_NORMAL		= 0x00,
	GSM48_RR_CAUSE_ABNORMAL_UNSPEC	= 0x01,
	GSM48_RR_CAUSE_ABNORMAL_UNACCT	= 0x02,
	GSM48_RR_CAUSE_ABNORMAL_TIMER	= 0x03,
	GSM48_RR_CAUSE_ABNORMAL_NOACT	= 0x04,
	GSM48_RR_CAUSE_PREMPTIVE_REL	= 0x05,
	GSM48_RR_CAUSE_HNDOVER_IMP	= 0x06,
	GSM48_RR_CAUSE_CHAN_MODE_UNACCT	= 0x07,
	GSM48_RR_CAUSE_FREQ_NOT_IMPL	= 0x08,
	GSM48_RR_CAUSE_CALL_CLEARED	= 0x41,
	GSM48_RR_CAUSE_SEMANT_INCORR	= 0x5f,
	GSM48_RR_CAUSE_INVALID_MAND_INF = 0x60,
	GSM48_RR_CAUSE_MSG_TYPE_N	= 0x61,
	GSM48_RR_CAUSE_MSG_TYPE_N_COMPAT= 0x62,
	GSM48_RR_CAUSE_COND_IE_ERROR	= 0x64,
	GSM48_RR_CAUSE_NO_CELL_ALLOC_A	= 0x65,
	GSM48_RR_CAUSE_PROT_ERROR_UNSPC = 0x6f,
};

/* Section 10.5.4.11 CC Cause / Table 10.5.123 */
enum gsm48_cc_cause {
	GSM48_CC_CAUSE_UNASSIGNED_NR	= 1,
	GSM48_CC_CAUSE_NO_ROUTE		= 3,
	GSM48_CC_CAUSE_CHAN_UNACCEPT	= 6,
	GSM48_CC_CAUSE_OP_DET_BARRING	= 8,
	GSM48_CC_CAUSE_NORM_CALL_CLEAR	= 16,
	GSM48_CC_CAUSE_USER_BUSY	= 17,
	GSM48_CC_CAUSE_USER_NOTRESPOND	= 18,
	GSM48_CC_CAUSE_USER_ALERTING_NA	= 19,
	GSM48_CC_CAUSE_CALL_REJECTED	= 21,
	GSM48_CC_CAUSE_NUMBER_CHANGED	= 22,
	GSM48_CC_CAUSE_PRE_EMPTION	= 25,
	GSM48_CC_CAUSE_NONSE_USER_CLR	= 26,
	GSM48_CC_CAUSE_DEST_OOO		= 27,
	GSM48_CC_CAUSE_INV_NR_FORMAT	= 28,
	GSM48_CC_CAUSE_FACILITY_REJ	= 29,
	GSM48_CC_CAUSE_RESP_STATUS_INQ	= 30,
	GSM48_CC_CAUSE_NORMAL_UNSPEC	= 31,
	GSM48_CC_CAUSE_NO_CIRCUIT_CHAN	= 34,
	GSM48_CC_CAUSE_NETWORK_OOO	= 38,
	GSM48_CC_CAUSE_TEMP_FAILURE	= 41,
	GSM48_CC_CAUSE_SWITCH_CONG	= 42,
	GSM48_CC_CAUSE_ACC_INF_DISCARD	= 43,
	GSM48_CC_CAUSE_REQ_CHAN_UNAVAIL	= 44,
	GSM48_CC_CAUSE_RESOURCE_UNAVAIL	= 47,
	GSM48_CC_CAUSE_QOS_UNAVAIL	= 49,
	GSM48_CC_CAUSE_REQ_FAC_NOT_SUBSC= 50,
	GSM48_CC_CAUSE_INC_BARRED_CUG	= 55,
	GSM48_CC_CAUSE_BEARER_CAP_UNAUTH= 57,
	GSM48_CC_CAUSE_BEARER_CA_UNAVAIL= 58,
	GSM48_CC_CAUSE_SERV_OPT_UNAVAIL	= 63,
	GSM48_CC_CAUSE_BEARERSERV_UNIMPL= 65,
	GSM48_CC_CAUSE_ACM_GE_ACM_MAX	= 68,
	GSM48_CC_CAUSE_REQ_FAC_NOTIMPL	= 69,
	GSM48_CC_CAUSE_RESTR_BCAP_AVAIL	= 70,
	GSM48_CC_CAUSE_SERV_OPT_UNIMPL	= 79,
	GSM48_CC_CAUSE_INVAL_TRANS_ID	= 81,
	GSM48_CC_CAUSE_USER_NOT_IN_CUG	= 87,
	GSM48_CC_CAUSE_INCOMPAT_DEST	= 88,
	GSM48_CC_CAUSE_INVAL_TRANS_NET	= 91,
	GSM48_CC_CAUSE_SEMANTIC_INCORR	= 95,
	GSM48_CC_CAUSE_INVAL_MAND_INF	= 96,
	GSM48_CC_CAUSE_MSGTYPE_NOTEXIST	= 97,
	GSM48_CC_CAUSE_MSGTYPE_INCOMPAT	= 98,
	GSM48_CC_CAUSE_IE_NOTEXIST	= 99,
	GSM48_CC_CAUSE_COND_IE_ERR	= 100,
	GSM48_CC_CAUSE_MSG_INCOMP_STATE	= 101,
	GSM48_CC_CAUSE_RECOVERY_TIMER	= 102,
	GSM48_CC_CAUSE_PROTO_ERR	= 111,
	GSM48_CC_CAUSE_INTERWORKING	= 127,
};

/* Annex G, GSM specific cause values for mobility management */
enum gsm48_reject_value {
	GSM48_REJECT_IMSI_UNKNOWN_IN_HLR	= 2,
	GSM48_REJECT_ILLEGAL_MS			= 3,
	GSM48_REJECT_IMSI_UNKNOWN_IN_VLR	= 4,
	GSM48_REJECT_IMEI_NOT_ACCEPTED		= 5,
	GSM48_REJECT_ILLEGAL_ME			= 6,
	GSM48_REJECT_PLMN_NOT_ALLOWED		= 11,
	GSM48_REJECT_LOC_NOT_ALLOWED		= 12,
	GSM48_REJECT_ROAMING_NOT_ALLOWED	= 13,
	GSM48_REJECT_NETWORK_FAILURE		= 17,
	GSM48_REJECT_CONGESTION			= 22,
	GSM48_REJECT_SRV_OPT_NOT_SUPPORTED	= 32,
	GSM48_REJECT_RQD_SRV_OPT_NOT_SUPPORTED	= 33,
	GSM48_REJECT_SRV_OPT_TMP_OUT_OF_ORDER	= 34,
	GSM48_REJECT_CALL_CAN_NOT_BE_IDENTIFIED	= 38,
	GSM48_REJECT_INCORRECT_MESSAGE		= 95,
	GSM48_REJECT_INVALID_MANDANTORY_INF	= 96,
	GSM48_REJECT_MSG_TYPE_NOT_IMPLEMENTED	= 97,
	GSM48_REJECT_MSG_TYPE_NOT_COMPATIBLE	= 98,
	GSM48_REJECT_INF_ELEME_NOT_IMPLEMENTED	= 99,
	GSM48_REJECT_CONDTIONAL_IE_ERROR	= 100,
	GSM48_REJECT_MSG_NOT_COMPATIBLE		= 101,
	GSM48_REJECT_PROTOCOL_ERROR		= 111,

	/* according to G.6 Additional cause codes for GMM */
	GSM48_REJECT_GPRS_NOT_ALLOWED		= 7,
	GSM48_REJECT_SERVICES_NOT_ALLOWED	= 8,
	GSM48_REJECT_MS_IDENTITY_NOT_DERVIVABLE = 9,
	GSM48_REJECT_IMPLICITLY_DETACHED	= 10,
	GSM48_REJECT_GPRS_NOT_ALLOWED_IN_PLMN	= 14,
	GSM48_REJECT_MSC_TMP_NOT_REACHABLE	= 16,
};


/* extracted from a L3 measurement report IE */
struct gsm_meas_rep_cell {
	u_int8_t rxlev;
	u_int8_t bcch_freq;	/* fixme: translate to ARFCN */
	u_int8_t bsic;
};

struct gsm_meas_rep {
	unsigned int flags;
	u_int8_t rxlev_full;
	u_int8_t rxqual_full;
	u_int8_t rxlev_sub;
	u_int8_t rxqual_sub;
	int num_cell;
	struct gsm_meas_rep_cell cell[6];
};
#define MEAS_REP_F_DTX		0x01
#define MEAS_REP_F_VALID	0x02
#define MEAS_REP_F_BA1		0x04

void gsm48_parse_meas_rep(struct gsm_meas_rep *rep, const u_int8_t *data,
			  int len);

enum chreq_type {
	CHREQ_T_EMERG_CALL,
	CHREQ_T_CALL_REEST_TCH_F,
	CHREQ_T_CALL_REEST_TCH_H,
	CHREQ_T_CALL_REEST_TCH_H_DBL,
	CHREQ_T_SDCCH,
	CHREQ_T_TCH_F,
	CHREQ_T_VOICE_CALL_TCH_H,
	CHREQ_T_DATA_CALL_TCH_H,
	CHREQ_T_LOCATION_UPD,
	CHREQ_T_PAG_R_ANY_NECI0,
	CHREQ_T_PAG_R_ANY_NECI1,
	CHREQ_T_PAG_R_TCH_F,
	CHREQ_T_PAG_R_TCH_FH,
	CHREQ_T_LMU,
	CHREQ_T_RESERVED_SDCCH,
	CHREQ_T_RESERVED_IGNORE,
};

/* Chapter 11.3 */
#define GSM48_T301	180, 0
#define GSM48_T303	30, 0
#define GSM48_T305	30, 0
#define GSM48_T306	30, 0
#define GSM48_T308	10, 0
#define GSM48_T310	180, 0
#define GSM48_T313	30, 0
#define GSM48_T323	30, 0
#define GSM48_T331	30, 0
#define GSM48_T333	30, 0
#define GSM48_T334	25, 0 /* min 15 */
#define GSM48_T338	30, 0

/* Chapter 5.1.2.2 */
#define	GSM_CSTATE_NULL			0
#define	GSM_CSTATE_INITIATED		1
#define	GSM_CSTATE_MO_CALL_PROC		3
#define	GSM_CSTATE_CALL_DELIVERED	4
#define	GSM_CSTATE_CALL_PRESENT		6
#define	GSM_CSTATE_CALL_RECEIVED	7
#define	GSM_CSTATE_CONNECT_REQUEST	8
#define	GSM_CSTATE_MO_TERM_CALL_CONF	9
#define	GSM_CSTATE_ACTIVE		10
#define	GSM_CSTATE_DISCONNECT_REQ	12
#define	GSM_CSTATE_DISCONNECT_IND	12
#define	GSM_CSTATE_RELEASE_REQ		19
#define	GSM_CSTATE_MO_ORIG_MODIFY	26
#define	GSM_CSTATE_MO_TERM_MODIFY	27
#define	GSM_CSTATE_CONNECT_IND		28

#define SBIT(a) (1 << a)
#define ALL_STATES 0xffffffff

/* Table 10.5.3/3GPP TS 04.08: Location Area Identification information element */
#define GSM_LAC_RESERVED_DETACHED       0x0
#define GSM_LAC_RESERVED_ALL_BTS        0xfffe

/* GSM 04.08 Bearer Capability: Information Transfer Capability */
enum gsm48_bcap_itcap {
	GSM48_BCAP_ITCAP_SPEECH		= 0,
	GSM48_BCAP_ITCAP_UNR_DIG_INF	= 1,
	GSM48_BCAP_ITCAP_3k1_AUDIO	= 2,
	GSM48_BCAP_ITCAP_FAX_G3		= 3,
	GSM48_BCAP_ITCAP_OTHER		= 5,
	GSM48_BCAP_ITCAP_RESERVED	= 7,
};

/* GSM 04.08 Bearer Capability: Transfer Mode */
enum gsm48_bcap_tmod {
	GSM48_BCAP_TMOD_CIRCUIT		= 0,
	GSM48_BCAP_TMOD_PACKET		= 1,
};

/* GSM 04.08 Bearer Capability: Coding Standard */
enum gsm48_bcap_coding {
	GSM48_BCAP_CODING_GSM_STD	= 0,
};

/* GSM 04.08 Bearer Capability: Radio Channel Requirements */
enum gsm48_bcap_rrq {
	GSM48_BCAP_RRQ_FR_ONLY	= 1,
	GSM48_BCAP_RRQ_DUAL_HR	= 2,
	GSM48_BCAP_RRQ_DUAL_FR	= 3,
};


#define GSM48_TMSI_LEN	5
#define GSM48_MID_TMSI_LEN	(GSM48_TMSI_LEN + 2)
#define GSM48_MI_SIZE 32


struct msgb;
struct gsm_bts;
struct gsm_subscriber;
struct gsm_network;
struct gsm_trans;

/* config options controlling the behaviour of the lower leves */
void gsm0408_allow_everyone(int allow);
void gsm0408_set_reject_cause(int cause);

int gsm0408_rcvmsg(struct msgb *msg, u_int8_t link_id);
void gsm0408_generate_lai(struct gsm48_loc_area_id *lai48, u_int16_t mcc, 
		u_int16_t mnc, u_int16_t lac);
enum gsm_chan_t get_ctype_by_chreq(struct gsm_bts *bts, u_int8_t ra, int neci);
enum gsm_chreq_reason_t get_reason_by_chreq(struct gsm_bts *bts, u_int8_t ra, int neci);

int gsm48_tx_mm_info(struct gsm_lchan *lchan);
int gsm48_tx_mm_auth_req(struct gsm_lchan *lchan, u_int8_t *rand);
int gsm48_tx_mm_auth_rej(struct gsm_lchan *lchan);
struct msgb *gsm48_msgb_alloc(void);
int gsm48_sendmsg(struct msgb *msg, struct gsm_trans *trans);
int gsm48_generate_mid_from_tmsi(u_int8_t *buf, u_int32_t tmsi);
int gsm48_generate_mid_from_imsi(u_int8_t *buf, const char* imsi);
int gsm48_mi_to_string(char *string, const int str_len, const u_int8_t *mi, const int mi_len);

int gsm48_send_rr_release(struct gsm_lchan *lchan);
int gsm48_send_rr_ciph_mode(struct gsm_lchan *lchan, int want_imeisv);
int gsm48_send_rr_app_info(struct gsm_lchan *lchan, u_int8_t apdu_id,
			   u_int8_t apdu_len, const u_int8_t *apdu);
int gsm48_send_rr_ass_cmd(struct gsm_lchan *lchan, u_int8_t power_class);

int bsc_upqueue(struct gsm_network *net);

int mncc_send(struct gsm_network *net, int msg_type, void *arg);

/* convert a ASCII phone number to call-control BCD */
int encode_bcd_number(u_int8_t *bcd_lv, u_int8_t max_len,
		      int h_len, const char *input);
int decode_bcd_number(char *output, int output_len, const u_int8_t *bcd_lv,
		      int h_len);

extern const char *gsm0408_cc_msg_names[];

int send_siemens_mrpci(struct gsm_lchan *lchan, u_int8_t *classmark2_lv);
int gsm48_paging_extract_mi(struct msgb *msg, char *mi_string, u_int8_t *mi_type);
int gsm48_handle_paging_resp(struct msgb *msg, struct gsm_subscriber *subscr);

int gsm48_lchan_modify(struct gsm_lchan *lchan, u_int8_t lchan_mode);
int gsm48_rx_rr_modif_ack(struct msgb *msg);

#endif
