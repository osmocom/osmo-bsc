/* Generic signalling/notification infrastructure */
/* (C) 2009-2010, 2015 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009 by Harald Welte <laforge@gnumonks.org>
 * (C) 2010 by On-Waves
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef OPENBSC_SIGNAL_H
#define OPENBSC_SIGNAL_H

#include <stdlib.h>
#include <errno.h>

#include <osmocom/bsc/gsm_data.h>

#include <osmocom/core/signal.h>

/*
 * Signalling subsystems
 */
enum signal_subsystems {
	SS_PAGING,
	SS_ABISIP,
	SS_NM,
	SS_LCHAN,
	SS_CHALLOC,
	SS_IPAC_NWL,
	SS_RF,
	SS_MSC,
	SS_HO,
	SS_CCCH,
};

/* SS_PAGING signals */
enum signal_paging {
	S_PAGING_SUCCEEDED,
	S_PAGING_EXPIRED,
};

/* SS_ABISIP signals */
enum signal_abisip {
	S_ABISIP_CRCX_ACK,
	S_ABISIP_MDCX_ACK,
	S_ABISIP_DLCX_IND,
};

/* SS_NM signals */
enum signal_nm {
	S_NM_SW_ACTIV_REP,	/* GSM 12.21 software activated report */
	S_NM_FAIL_REP,		/* GSM 12.21 failure event report */
	S_NM_NACK,		/* GSM 12.21 various NM_MT_*_NACK happened */
	S_NM_IPACC_NACK,	/* GSM 12.21 nanoBTS extensions NM_MT_IPACC_*_*_NACK happened */
	S_NM_IPACC_ACK,		/* GSM 12.21 nanoBTS extensions NM_MT_IPACC_*_*_ACK happened */
	S_NM_IPACC_SET_ATTR_ACK,/* GSM 12.21 nanoBTS extensions NM_MT_IPACC_SET_ATTR_ACK happened */
	S_NM_IPACC_RESTART_ACK, /* nanoBTS has send a restart ack */
	S_NM_IPACC_RESTART_NACK,/* nanoBTS has send a restart ack */
	S_NM_TEST_REP,		/* GSM 12.21 Test Report */
	S_NM_STATECHG_OPER,	/* Operational State changed*/
	S_NM_STATECHG_ADM,	/* Administrative State changed */
	S_NM_OM2K_CONF_RES,	/* OM2K Configuration Result */
	S_NM_OPSTART_ACK,	/* Received OPSTART ACK, arg is struct msgb *oml_msg */
	S_NM_OPSTART_NACK,	/* Received OPSTART NACK, arg is struct msgb *oml_msg */
	S_NM_GET_ATTR_REP,	/* Received Get Attributes Response, arg is struct msgb *oml_msg */
	S_NM_SET_RADIO_ATTR_ACK, /* Received Set Radio Carrier Attributes Ack, arg is struct msgb *oml_msg */
	S_NM_SET_CHAN_ATTR_ACK, /* Received Set Radio Channel Attributes Ack, arg is struct msgb *oml_msg */
	S_NM_SET_BTS_ATTR_ACK,  /* Received Set BTS Attributes Ack, arg is struct msgb *oml_msg */
};

/* SS_LCHAN signals */
enum signal_lchan {
	/*
	 * The lchan got freed with an use_count != 0 and error
	 * recovery needs to be carried out from within the
	 * signal handler.
	 */
	S_LCHAN_UNEXPECTED_RELEASE,
	S_LCHAN_ACTIVATE_ACK,		/* 08.58 Channel Activate ACK */
	S_LCHAN_ACTIVATE_NACK,		/* 08.58 Channel Activate NACK */
	S_LCHAN_HANDOVER_COMPL,		/* 04.08 Handover Completed */
	S_LCHAN_HANDOVER_FAIL,		/* 04.08 Handover Failed */
	S_LCHAN_ASSIGNMENT_COMPL,	/* 04.08 Assignment Completed */
	S_LCHAN_ASSIGNMENT_FAIL,	/* 04.08 Assignment Failed */
	S_LCHAN_HANDOVER_DETECT,	/* 08.58 Handover Detect */
	S_LCHAN_MEAS_REP,		/* 08.58 Measurement Report */
};

/* SS_CHALLOC signals */
enum signal_challoc {
	S_CHALLOC_ALLOC_FAIL,	/* allocation of lchan has failed */
	S_CHALLOC_FREED,	/* lchan has been successfully freed */
};

/* SS_IPAC_NWL signals */
enum signal_ipaccess {
	S_IPAC_NWL_COMPLETE,
};

enum signal_global {
	S_GLOBAL_BTS_CLOSE_OM,
};

/* SS_RF signals */
enum signal_rf {
	S_RF_OFF,
	S_RF_ON,
	S_RF_GRACE,
};

struct ipacc_ack_signal_data {
	struct gsm_bts_trx *trx;
	uint8_t msg_type;
};

struct abis_om2k_mo;

struct nm_statechg_signal_data {
	struct gsm_bts *bts;
	uint8_t obj_class;
	void *obj;
	struct gsm_nm_state *old_state;
	struct gsm_nm_state *new_state;

	/* This pointer is vaold for TS 12.21 MO */
	struct abis_om_obj_inst *obj_inst;
	/* This pointer is vaold for RBS2000 MO */
	struct abis_om2k_mo *om2k_mo;
};

struct nm_om2k_signal_data {
	struct gsm_bts *bts;
	void *obj;
	struct abis_om2k_mo *om2k_mo;

	uint8_t accordance_ind;
};

struct nm_nack_signal_data {
	struct msgb *msg;
	struct gsm_bts *bts;
	uint8_t mt;
};

struct nm_fail_rep_signal_data {
	struct gsm_bts *bts;
	/* raw data */
	struct msgb *msg;
	struct tlv_parsed tp;
	/* parsed data */
	struct {
		const char *event_type;
		const char *severity;
		const char *additional_text;
		const uint8_t *probable_cause;
	} parsed;
};

struct challoc_signal_data {
	struct gsm_bts *bts;
	struct gsm_lchan *lchan;
	enum gsm_chan_t type;
};

struct rf_signal_data {
	struct gsm_network *net;
};

struct lchan_signal_data {
	/* The lchan the signal happened on */
	struct gsm_lchan *lchan;
	/* Measurement reports on this lchan */
	struct gsm_meas_rep *mr;
};

/* MSC signals */
enum signal_msc {
	S_MSC_LOST,
	S_MSC_CONNECTED,
	S_MSC_AUTHENTICATED,
};

struct bsc_msc_data;
struct msc_signal_data {
	struct bsc_msc_data *data;
};

/* SS_CCCH signals */
enum signal_ccch {
	S_CCCH_PAGING_LOAD,
	S_CCCH_RACH_LOAD,
};

struct ccch_signal_data {
	struct gsm_bts *bts;
	uint16_t pg_buf_space;
	uint16_t rach_slot_count;
	uint16_t rach_busy_count;
	uint16_t rach_access_count;
};

#endif
