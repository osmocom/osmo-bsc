/* Header for all NM FSM. Following 3GPP TS 12.21 Figure 2/GSM 12.21:
  GSM 12.21 Objects' Operational state and availability status behaviour during initialization */

/* (C) 2020 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * Author: Pau Espin Pedrol <pespin@sysmocom.de>
 *
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
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#pragma once

#include <osmocom/core/fsm.h>
#include <osmocom/core/utils.h>
#include <osmocom/gsm/protocol/gsm_12_21.h>

struct gsm_bts;

/* Common */
enum nm_fsm_events {
	NM_EV_SW_ACT_REP,
	NM_EV_STATE_CHG_REP,
	NM_EV_GET_ATTR_REP,
	NM_EV_SET_ATTR_ACK,
	NM_EV_OPSTART_ACK,
	NM_EV_OPSTART_NACK,
	NM_EV_OML_DOWN,
	NM_EV_SETUP_RAMP_READY, /* BTS setup ramp allow to continue to configure */
	NM_EV_FORCE_LOCK, /* Only supported by RadioCarrier so far */
	NM_EV_FEATURE_NEGOTIATED, /* Sent by BTS to NSVC MO */
	NM_EV_RSL_CONNECT_ACK, /* Sent by BTS to BBTRANSC MO */
	NM_EV_RSL_CONNECT_NACK, /* Sent by BTS to BBTRANSC MO */
};
extern const struct value_string nm_fsm_event_names[];

/* BTS SiteManager */
enum nm_bts_sm_op_fsm_states {
	NM_BTS_SM_ST_OP_DISABLED_NOTINSTALLED,
	NM_BTS_SM_ST_OP_DISABLED_DEPENDENCY,
	NM_BTS_SM_ST_OP_DISABLED_OFFLINE,
	NM_BTS_SM_ST_OP_ENABLED,
};
extern struct osmo_fsm nm_bts_sm_fsm;

/* BTS */
enum nm_bts_op_fsm_states {
	NM_BTS_ST_OP_DISABLED_NOTINSTALLED,
	NM_BTS_ST_OP_DISABLED_DEPENDENCY,
	NM_BTS_ST_OP_DISABLED_OFFLINE,
	NM_BTS_ST_OP_ENABLED,
};
extern struct osmo_fsm nm_bts_fsm;

/* BaseBand Transceiver */
enum nm_bb_transc_op_fsm_states {
	NM_BB_TRANSC_ST_OP_DISABLED_NOTINSTALLED,
	NM_BB_TRANSC_ST_OP_DISABLED_DEPENDENCY,
	NM_BB_TRANSC_ST_OP_DISABLED_OFFLINE,
	NM_BB_TRANSC_ST_OP_ENABLED,
};
extern struct osmo_fsm nm_bb_transc_fsm;

/* Radio Carrier */
enum nm_rcarrier_op_fsm_states {
	NM_RCARRIER_ST_OP_DISABLED_NOTINSTALLED,
	NM_RCARRIER_ST_OP_DISABLED_DEPENDENCY,
	NM_RCARRIER_ST_OP_DISABLED_OFFLINE,
	NM_RCARRIER_ST_OP_ENABLED,
};
extern struct osmo_fsm nm_rcarrier_fsm;

/* Radio Channel */
enum nm_chan_op_fsm_states {
	NM_CHAN_ST_OP_DISABLED_NOTINSTALLED,
	NM_CHAN_ST_OP_DISABLED_DEPENDENCY,
	NM_CHAN_ST_OP_DISABLED_OFFLINE,
	NM_CHAN_ST_OP_ENABLED,
};
extern struct osmo_fsm nm_chan_fsm;

/* GPRS NSE */
enum nm_gprs_op_nse_states {
	NM_GPRS_NSE_ST_OP_DISABLED_NOTINSTALLED,
	NM_GPRS_NSE_ST_OP_DISABLED_DEPENDENCY,
	NM_GPRS_NSE_ST_OP_DISABLED_OFFLINE,
	NM_GPRS_NSE_ST_OP_ENABLED,
};
extern struct osmo_fsm nm_gprs_nse_fsm;

/* GPRS Cell */
enum nm_gprs_op_cell_states {
	NM_GPRS_CELL_ST_OP_DISABLED_NOTINSTALLED,
	NM_GPRS_CELL_ST_OP_DISABLED_DEPENDENCY,
	NM_GPRS_CELL_ST_OP_DISABLED_OFFLINE,
	NM_GPRS_CELL_ST_OP_ENABLED,
};
extern struct osmo_fsm nm_gprs_cell_fsm;

/* GPRS NSVC */
enum nm_gprs_op_nsvc_fsm_states {
	NM_GPRS_NSVC_ST_OP_DISABLED_NOTINSTALLED,
	NM_GPRS_NSVC_ST_OP_DISABLED_DEPENDENCY,
	NM_GPRS_NSVC_ST_OP_DISABLED_OFFLINE,
	NM_GPRS_NSVC_ST_OP_ENABLED,
};
extern struct osmo_fsm nm_gprs_nsvc_fsm;

void nm_obj_fsm_becomes_enabled_disabled(struct gsm_bts *bts, void *obj,
					 enum abis_nm_obj_class obj_class,
					 bool running);

void nm_fsm_dispatch_all_configuring(struct gsm_bts *bts, uint32_t event, void *data);
