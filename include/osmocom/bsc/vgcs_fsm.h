/* Handle a call via VGCS/VBCS (Voice Group/Broadcast Call Service). */
/*
 * (C) 2023 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * SPDX-License-Identifier: AGPL-3.0+
 *
 * Author: Andreas Eversberg
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
 */
#pragma once

/* Events for both VGCS/VBS state machines. */
enum vgcs_fsm_event {
	/* The BSC sets up a VGCS/VBS call. */
	VGCS_EV_SETUP,
	/* The BSC wants to assign a VGCS/VBS channel. */
	VGCS_EV_ASSIGN_REQ,
	/* The BTS detects a talker on a channel. */
	VGCS_EV_TALKER_DET,
	/* The BTS detects a listener on a channel. */
	VGCS_EV_LISTENER_DET,
	/* The MSC accepts a talker. */
	VGCS_EV_MSC_ACK,
	/* The MSC rejects a talker. */
	VGCS_EV_MSC_REJECT,
	/* The MSC seizes all channels. (blocking for calls) */
	VGCS_EV_MSC_SEIZE,
	/* The MSC releases all channels. (unblocking for calls) */
	VGCS_EV_MSC_RELEASE,
	/* The MSC sends message to talker. (E.g. CONNECT) */
	VGCS_EV_MSC_DTAP,
	/* Channel is now active. Waiting for Talker. */
	VGCS_EV_LCHAN_ACTIVE,
	/* Channel activation error. */
	VGCS_EV_LCHAN_ERROR,
	/* MGW connection is now active. Waiting for Talker. */
	VGCS_EV_MGW_OK,
	/* MGW connection error. */
	VGCS_EV_MGW_FAIL,
	/* Channel link established. (Talker establised.) */
	VGCS_EV_TALKER_EST,
	/* Channel link data. (Talker sends data.) */
	VGCS_EV_TALKER_DATA,
	/* Channel link released. (Talker released.) */
	VGCS_EV_TALKER_REL,
	/* Channel link failed. (Talker failed.) */
	VGCS_EV_TALKER_FAIL,
	/* Channel is blocked by BSC. */
	VGCS_EV_BLOCK,
	/* Channel is rejected by BSC. */
	VGCS_EV_REJECT,
	/* Channel is unblocked by BSC. */
	VGCS_EV_UNBLOCK,
	/* The connection will be destroyed. (free VGCS resources) */
	VGCS_EV_CLEANUP,
	/* The calling subscriber has been assigned to the group channel. */
	VGCS_EV_CALLING_ASSIGNED,
};


/* States of the VGCS/VBS call state machine */
enum vgcs_call_fsm_state {
	/* Call is not setup. Initial state when instance is created. */
	VGCS_CALL_ST_NULL = 0,
	/* Call is idle. */
	VGCS_CALL_ST_IDLE,
	/* Call is busy, due to a talker in this BSC. */
	VGCS_CALL_ST_BUSY,
	/* Call is blocked, due to a talker in a different BSC. */
	VGCS_CALL_ST_BLOCKED,
};

/* States of the VGCS/VBS channel state machine */
enum vgcs_chan_fsm_state {
	/* Channel not assigned. Initial state when instance is created. */
	VGCS_CHAN_ST_NULL = 0,
	/* Wait for establishment of VGCS/VBS channel at BTS. */
	VGCS_CHAN_ST_WAIT_EST,
	/* Channel active and idle. Channel is marked as uplink busy. */
	VGCS_CHAN_ST_ACTIVE_BLOCKED,
	/* Channel active and idle. Channel is marked as uplink free. */
	VGCS_CHAN_ST_ACTIVE_FREE,
	/* Channel active and talker was detected, L2 must be established. */
	VGCS_CHAN_ST_ACTIVE_INIT,
	/* Channel active and talker established L2. */
	VGCS_CHAN_ST_ACTIVE_EST,
	/* Channel active and wait for talker to release L2. */
	VGCS_CHAN_ST_ACTIVE_REL,
};

int vgcs_vbs_chan_start(struct gsm_subscriber_connection *conn, struct msgb *msg);
int vgcs_vbs_call_start(struct gsm_subscriber_connection *conn, struct msgb *msg);

int bssmap_handle_ass_req_ct_speech(struct gsm_subscriber_connection *conn, struct gsm_bts *bts,
				    struct tlv_parsed *tp, struct gsm0808_channel_type *ct,
				    struct assignment_request *req, uint8_t *cause);
void bsc_tx_setup_ack(struct gsm_subscriber_connection *conn, struct gsm0808_vgcs_feature_flags *ff);
void bsc_tx_setup_refuse(struct gsm_subscriber_connection *conn, uint8_t cause);
void bsc_tx_vgcs_vbs_assignment_result(struct gsm_subscriber_connection *conn, struct gsm0808_channel_type *ct,
				       struct gsm0808_cell_id *ci, uint32_t call_id);
void bsc_tx_vgcs_vbs_assignment_fail(struct gsm_subscriber_connection *conn, uint8_t cause);
void bsc_tx_uplink_req(struct gsm_subscriber_connection *conn);
void bsc_tx_uplink_req_conf(struct gsm_subscriber_connection *conn, struct gsm0808_cell_id *ci, uint8_t *l3_info,
			    uint8_t length);
void bsc_tx_uplink_app_data(struct gsm_subscriber_connection *conn, struct gsm0808_cell_id *ci, uint8_t *l3_info,
			    uint8_t length);
void bsc_tx_uplink_release_ind(struct gsm_subscriber_connection *conn, uint8_t cause);
struct gsm_lchan *vgcs_vbs_find_lchan(struct gsm_bts *bts, struct gsm0808_group_callref *gc);
