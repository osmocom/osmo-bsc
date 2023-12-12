/* Handle VGCS/VBCS calls. (Voice Group/Broadcast Call Service). */
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

/* The process consists of two state machnes:
 *
 * The VGCS call state machine handles the voice group/broadcast call control.
 * There is one instance for every call. It controls the uplink states of the
 * call. They will be reported to the MSC or can be changed by the MSC.
 * One SCCP connection for is associated with the state machine. This is used
 * to talk to the MSC about state changes.
 *
 * The VGCS channel state machine handles the channel states in each cell.
 * There is one instance for every cell and every call. The instances are
 * linked to the call state process. It controls the uplink states of the
 * channel. They will be reported to the call state machine or can be changed
 * by the call state machine.
 * One SCCP connection for every cell is associated with the state machine.
 * It is used to perform VGCS channel assignment.
 *
 */

#include <osmocom/mgcp_client/mgcp_client_endpoint_fsm.h>
#include <osmocom/bsc/osmo_bsc.h>
#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/vgcs_fsm.h>
#include <osmocom/bsc/handover_fsm.h>
#include <osmocom/bsc/abis_rsl.h>
#include <osmocom/bsc/lchan_fsm.h>
#include <osmocom/bsc/lchan_select.h>
#include <osmocom/bsc/bsc_subscr_conn_fsm.h>
#include <osmocom/bsc/assignment_fsm.h>
#include <osmocom/bsc/gsm_08_08.h>
#include <osmocom/bsc/gsm_04_08_rr.h>
#include <osmocom/bsc/bts_trx.h>
#include <osmocom/bsc/bts.h>
#include <osmocom/bsc/system_information.h>

#define S(x)	(1 << (x))

#define LOG_CALL(conn, level, fmt, args...) \
	LOGP(DASCI, level, \
	     (conn->vgcs_call.sf == GSM0808_SF_VGCS) ? ("VGCS callref %s: " fmt) : ("VBS callref %s: " fmt), \
	     gsm44068_group_id_string(conn->vgcs_call.call_ref), ##args)
#define LOG_CHAN(conn, level, fmt, args...) \
	LOGP(DASCI, level, \
	     (conn->vgcs_chan.sf == GSM0808_SF_VGCS) ? ("VGCS callref %s, cell %s: " fmt) \
						     : ("VBS callref %s, cell %s: " fmt), \
	     gsm44068_group_id_string(conn->vgcs_chan.call_ref), conn->vgcs_chan.ci_str, ##args)

const char *gsm44068_group_id_string(uint32_t callref)
{
	static char string[9];

	snprintf(string, sizeof(string), "%08u", callref);

	return string;
}

static struct osmo_fsm vgcs_call_fsm;
static struct osmo_fsm vgcs_chan_fsm;

static __attribute__((constructor)) void vgcs_fsm_init(void)
{
	OSMO_ASSERT(osmo_fsm_register(&vgcs_call_fsm) == 0);
	OSMO_ASSERT(osmo_fsm_register(&vgcs_chan_fsm) == 0);
}

static const struct value_string vgcs_fsm_event_names[] = {
	OSMO_VALUE_STRING(VGCS_EV_SETUP),
	OSMO_VALUE_STRING(VGCS_EV_ASSIGN_REQ),
	OSMO_VALUE_STRING(VGCS_EV_TALKER_DET),
	OSMO_VALUE_STRING(VGCS_EV_LISTENER_DET),
	OSMO_VALUE_STRING(VGCS_EV_MSC_ACK),
	OSMO_VALUE_STRING(VGCS_EV_MSC_REJECT),
	OSMO_VALUE_STRING(VGCS_EV_MSC_SEIZE),
	OSMO_VALUE_STRING(VGCS_EV_MSC_RELEASE),
	OSMO_VALUE_STRING(VGCS_EV_MSC_DTAP),
	OSMO_VALUE_STRING(VGCS_EV_LCHAN_ACTIVE),
	OSMO_VALUE_STRING(VGCS_EV_LCHAN_ERROR),
	OSMO_VALUE_STRING(VGCS_EV_MGW_OK),
	OSMO_VALUE_STRING(VGCS_EV_MGW_FAIL),
	OSMO_VALUE_STRING(VGCS_EV_TALKER_EST),
	OSMO_VALUE_STRING(VGCS_EV_TALKER_DATA),
	OSMO_VALUE_STRING(VGCS_EV_TALKER_REL),
	OSMO_VALUE_STRING(VGCS_EV_TALKER_FAIL),
	OSMO_VALUE_STRING(VGCS_EV_BLOCK),
	OSMO_VALUE_STRING(VGCS_EV_REJECT),
	OSMO_VALUE_STRING(VGCS_EV_UNBLOCK),
	OSMO_VALUE_STRING(VGCS_EV_CLEANUP),
	OSMO_VALUE_STRING(VGCS_EV_CALLING_ASSIGNED),
	{ }
};

static struct gsm_subscriber_connection *find_calling_subscr_conn(struct gsm_subscriber_connection *conn)
{
	struct gsm_subscriber_connection *c;

	llist_for_each_entry(c, &conn->network->subscr_conns, entry) {
		if (!c->assignment.fi)
			continue;
		if (c->assignment.req.target_lchan != conn->lchan)
			continue;
		return c;
	}

	return NULL;
}

/*
 * VGCS call FSM
 */

/* Add/update SI10. It must be called whenever a channel is activated or failed. */
static void si10_update(struct gsm_subscriber_connection *conn)
{
	struct gsm_subscriber_connection *c;
	uint8_t si10[SI10_LENGTH];
	int rc;

	/* Skip SI10 update, if not all channels have been activated or failed. */
	llist_for_each_entry(c, &conn->vgcs_call.chan_list, vgcs_chan.list) {
		if (c->vgcs_chan.fi->state == VGCS_CHAN_ST_WAIT_EST) {
			LOG_CALL(conn, LOGL_DEBUG, "There is a channel, not yet active. No SI10 update now.\n");
			return;
		}
	}

	LOG_CALL(conn, LOGL_DEBUG, "New channel(s) added, updating SI10 for all channels.\n");

	/* Go through all channels. */
	llist_for_each_entry(c, &conn->vgcs_call.chan_list, vgcs_chan.list) {
		/* Skip all channels that failed to activate or have not been aktivated yet.
		 * There shouldn't be any channel in that state now. */
		if (!c->lchan)
			continue;
		/* Encode SI 10 for this channel. Skip, if it fails. */
		rc = gsm_generate_si10((struct gsm48_system_information_type_10 *)si10, sizeof(si10), c);
		if (rc < 0)
			continue;
		/* Add SI 10 to SACCH of this channel c. */
		rsl_sacch_info_modify(c->lchan, RSL_SYSTEM_INFO_10, si10, sizeof(si10));
	}
}

static void vgcs_call_detach_and_destroy(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct gsm_subscriber_connection *conn = fi->priv, *c;
	struct msgb *msg;

	/* Flush message queue. */
	while ((msg = msgb_dequeue(&conn->vgcs_call.l3_queue)))
		msgb_free(msg);

	/* Detach all cell instances. */
	while (!llist_empty(&conn->vgcs_call.chan_list)) {
		c = llist_entry(conn->vgcs_call.chan_list.next, struct gsm_subscriber_connection, vgcs_chan.list);
		c->vgcs_chan.call = NULL;
		llist_del(&c->vgcs_chan.list);
	}

	/* No Talker. */
	conn->vgcs_call.talker = NULL;

	/* Remove pointer of FSM. */
	conn->vgcs_call.fi = NULL;
}

static void vgcs_call_fsm_null(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_subscriber_connection *conn = fi->priv;

	switch (event) {
	case VGCS_EV_SETUP:
		LOG_CALL(conn, LOGL_DEBUG, "VGCS/VBS SETUP from MSC.\n");
		/* MSC sends VGCS/VBS SETUP for a new call. */
		osmo_fsm_inst_state_chg(fi, VGCS_CALL_ST_IDLE, 0, 0);
		/* Remove unsupported features. */
		conn->vgcs_call.ff.tp_ind = 0;
		conn->vgcs_call.ff.as_ind_circuit = 0;
		conn->vgcs_call.ff.as_ind_link = 0;
		conn->vgcs_call.ff.bss_res = 0;
		conn->vgcs_call.ff.tcp = 0;
		/* Acknowlege the call. */
		bsc_tx_setup_ack(conn, &conn->vgcs_call.ff);
		break;
	default:
		OSMO_ASSERT(false);
	}
}

static void vgcs_call_fsm_idle(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_subscriber_connection *conn = fi->priv, *c;
	struct handover_rr_detect_data *d = data;
	struct msgb *msg;

	switch (event) {
	case VGCS_EV_TALKER_DET:
		LOG_CALL(conn, LOGL_DEBUG, "Talker detected.\n");
		/* Talker detected on a channel, call becomes busy. */
		osmo_fsm_inst_state_chg(fi, VGCS_CALL_ST_BUSY, 0, 0);
		conn->vgcs_call.talker = d->msg->lchan->conn;
		/* Reset pending states. */
		while ((msg = msgb_dequeue(&conn->vgcs_call.l3_queue)))
			msgb_free(msg);
		conn->vgcs_call.msc_ack = false;
		conn->vgcs_call.talker_rel = false;
		/* Report busy uplink to the MSC. */
		bsc_tx_uplink_req(conn);
		/* Block all other channels. */
		llist_for_each_entry(c, &conn->vgcs_call.chan_list, vgcs_chan.list) {
			if (c == conn->vgcs_call.talker)
				continue;
			osmo_fsm_inst_dispatch(c->vgcs_chan.fi, VGCS_EV_BLOCK, NULL);
		}
		break;
	case VGCS_EV_LISTENER_DET:
		LOG_CALL(conn, LOGL_DEBUG, "Listener detected.\n");
		// Listener detection not supported.
		break;
	case VGCS_EV_MSC_SEIZE:
		LOG_CALL(conn, LOGL_DEBUG, "MSC seizes all channels.\n");
		/* MSC seizes call (talker on a different BSS), call becomes blocked. */
		osmo_fsm_inst_state_chg(fi, VGCS_CALL_ST_BLOCKED, 0, 0);
		/* Block all channels. */
		llist_for_each_entry(c, &conn->vgcs_call.chan_list, vgcs_chan.list)
			osmo_fsm_inst_dispatch(c->vgcs_chan.fi, VGCS_EV_BLOCK, NULL);
		break;
	case VGCS_EV_MSC_RELEASE:
		/* Ignore, because there is no blocked channel in this state. */
		break;
	case VGCS_EV_MSC_REJECT:
		LOG_CALL(conn, LOGL_DEBUG, "MSC rejects talker on uplink.\n");
		/* Race condition: Talker released before the MSC rejects the talker. Ignore! */
		break;
	case VGCS_EV_CLEANUP:
		LOG_CALL(conn, LOGL_DEBUG, "SCCP connection clearing.\n");
		osmo_fsm_inst_term(conn->vgcs_call.fi, 0, NULL);
		break;
	default:
		OSMO_ASSERT(false);
	}
}

/* Get L3 info from message, if exists. Return the length or otherwise return 0. */
int l3_data_from_msg(struct msgb *msg, uint8_t **l3_info)
{
	struct abis_rsl_rll_hdr *rllh = msgb_l2(msg);

	/* No space for L3 info */
	if (msgb_l2len(msg) < sizeof(*rllh) + 3 || rllh->data[0] != RSL_IE_L3_INFO)
		return 0;

	*l3_info = msg->l3h = &rllh->data[3];
	return msgb_l3len(msg);
}

static void vgcs_call_fsm_busy(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_subscriber_connection *conn = fi->priv, *c;
	struct msgb *msg = data;
	uint8_t cause = (data) ? *(uint8_t *)data : 0;
	uint8_t *l3_info;
	int l3_len;
	int rc;

	switch (event) {
	case VGCS_EV_TALKER_EST:
		LOG_CALL(conn, LOGL_DEBUG, "Talker established uplink.\n");
		/* Talker established L2 connection. Sent L3 info to MSC, if MSC already acked, otherwise enqueue. */
		if (conn->vgcs_call.msc_ack) {
			LOG_CALL(conn, LOGL_DEBUG, "Sending establishment messages to MSC.\n");
			l3_len = l3_data_from_msg(msg, &l3_info);
			if (conn->vgcs_call.talker)
				bsc_tx_uplink_req_conf(conn, &conn->vgcs_call.talker->vgcs_chan.ci, l3_info, l3_len);
			else
				LOG_CALL(conn, LOGL_ERROR, "Talker establishes, but talker not set, please fix!\n");
		} else {
			LOG_CALL(conn, LOGL_DEBUG, "No uplink request ack from MSC yet, queue message.\n");
			msg = msgb_copy(msg, "Queued Talker establishment");
			if (msg)
				msgb_enqueue(&conn->vgcs_call.l3_queue, msg);
		}
		break;
	case VGCS_EV_TALKER_DATA:
		LOG_CALL(conn, LOGL_DEBUG, "Talker sent data on uplink.\n");
		/* Talker sends data. Sent L3 info to MSC, if MSC already acked, otherwise enqueue. */
		if (conn->vgcs_call.msc_ack) {
			LOG_CALL(conn, LOGL_DEBUG, "Sending data messages to MSC.\n");
			bsc_dtap(conn, 0, msg);
		} else {
			LOG_CALL(conn, LOGL_DEBUG, "No uplink request ack from MSC yet, queue message.\n");
			msg = msgb_copy(msg, "Queued DTAP");
			if (msg)
				msgb_enqueue(&conn->vgcs_call.l3_queue, msg);
		}
		break;
	case VGCS_EV_MSC_DTAP:
		LOG_CALL(conn, LOGL_DEBUG, "MSC sends DTAP message to talker.\n");
		if (!conn->vgcs_call.talker) {
			msgb_free(data);
			break;
		}
		rc = osmo_fsm_inst_dispatch(conn->vgcs_call.talker->vgcs_chan.fi, VGCS_EV_MSC_DTAP, data);
		if (rc < 0)
			msgb_free(data);
		break;
	case VGCS_EV_TALKER_REL:
		LOG_CALL(conn, LOGL_DEBUG, "Talker released on uplink.\n");
		if (!conn->vgcs_call.msc_ack) {
			LOG_CALL(conn, LOGL_DEBUG, "Talker released before MSC acknowleded or rejected.\n");
			conn->vgcs_call.talker_rel = true;
			conn->vgcs_call.talker_cause = cause;
			break;
		}
talker_released:
		/* Talker released channel, call becomes idle. */
		osmo_fsm_inst_state_chg(fi, VGCS_CALL_ST_IDLE, 0, 0);
		conn->vgcs_call.talker = NULL;
		/* Report free uplink to the MSC. */
		bsc_tx_uplink_release_ind(conn, cause);
		/* Unblock all other channels. */
		llist_for_each_entry(c, &conn->vgcs_call.chan_list, vgcs_chan.list) {
			if (c == conn->vgcs_call.talker)
				continue;
			osmo_fsm_inst_dispatch(c->vgcs_chan.fi, VGCS_EV_UNBLOCK, NULL);
		}
		break;
	case VGCS_EV_MSC_SEIZE:
		LOG_CALL(conn, LOGL_DEBUG, "MSC seizes all channels. (channels are blocked)\n");
		/* Race condition: MSC seizes call (talker on a different BSS), call becomes blocked. */
		osmo_fsm_inst_state_chg(fi, VGCS_CALL_ST_BLOCKED, 0, 0);
		/* Reject talker. (Forward to chan FSM.) */
		if (conn->vgcs_call.talker) {
			osmo_fsm_inst_dispatch(conn->vgcs_call.talker->vgcs_chan.fi, VGCS_EV_REJECT, NULL);
			conn->vgcs_call.talker = NULL;
		}
		/* Block all channels. */
		llist_for_each_entry(c, &conn->vgcs_call.chan_list, vgcs_chan.list)
			osmo_fsm_inst_dispatch(c->vgcs_chan.fi, VGCS_EV_BLOCK, NULL);
		break;
	case VGCS_EV_MSC_ACK:
		LOG_CALL(conn, LOGL_DEBUG, "MSC acks talker on uplink.\n");
		/* MSC acknowledges uplink. Send L3 info to MSC, if talker already established. */
		conn->vgcs_call.msc_ack = true;
		/* Send establish message via UPLINK REQUEST CONFIRM, if already received. */
		msg = msgb_dequeue(&conn->vgcs_call.l3_queue);
		if (msg) {
			LOG_CALL(conn, LOGL_DEBUG, "Sending queued establishment messages to MSC.\n");
			l3_len = l3_data_from_msg(msg, &l3_info);
			if (conn->vgcs_call.talker)
				bsc_tx_uplink_req_conf(conn, &conn->vgcs_call.talker->vgcs_chan.ci, l3_info, l3_len);
			else
				LOG_CALL(conn, LOGL_ERROR, "MSC acks taker, but talker not set, please fix!\n");
			msgb_free(msg);
		}
		/* Send data messages via UPLINK APPLICATION DATA, if already received. */
		while ((msg = msgb_dequeue(&conn->vgcs_call.l3_queue))) {
			LOG_CALL(conn, LOGL_DEBUG, "Sending queued DTAP messages to MSC.\n");
			bsc_dtap(conn, 0, msg);
			msgb_free(msg);
		}
		/* If there is a pending talker release. */
		if (conn->vgcs_call.talker_rel) {
			LOG_CALL(conn, LOGL_DEBUG, "Sending queued talker release messages to MSC.\n");
			cause = conn->vgcs_call.talker_cause;
			goto talker_released;
		}
		break;
	case VGCS_EV_MSC_REJECT:
		LOG_CALL(conn, LOGL_DEBUG, "MSC rejects talker on uplink.\n");
		/* MSC rejects talker, call becomes idle. */
		osmo_fsm_inst_state_chg(fi, VGCS_CALL_ST_IDLE, 0, 0);
		/* Reject talker. (Forward to chan FSM.) */
		if (conn->vgcs_call.talker)
			osmo_fsm_inst_dispatch(conn->vgcs_call.talker->vgcs_chan.fi, VGCS_EV_REJECT, NULL);
		else
			LOG_CALL(conn, LOGL_ERROR, "MSC rejects, but talker not set, please fix!\n");
		conn->vgcs_call.talker = NULL;
		/* Unblock all other channels. */
		llist_for_each_entry(c, &conn->vgcs_call.chan_list, vgcs_chan.list) {
			if (c == conn->vgcs_call.talker)
				continue;
			osmo_fsm_inst_dispatch(c->vgcs_chan.fi, VGCS_EV_UNBLOCK, NULL);
		}
		break;
	case VGCS_EV_CLEANUP:
		LOG_CALL(conn, LOGL_DEBUG, "SCCP connection clearing.\n");
		osmo_fsm_inst_term(conn->vgcs_call.fi, 0, NULL);
		break;
	default:
		OSMO_ASSERT(false);
	}
}

static void vgcs_call_fsm_blocked(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_subscriber_connection *conn = fi->priv, *c;
	struct msgb *msg;

	switch (event) {
	case VGCS_EV_CALLING_ASSIGNED:
		LOG_CALL(conn, LOGL_DEBUG, "Calling subscriber assigned and now on uplink.\n");
		/* Talker detected on a channel, call becomes busy. */
		osmo_fsm_inst_state_chg(fi, VGCS_CALL_ST_BUSY, 0, 0);
		conn->vgcs_call.talker = data;
		/* Reset pending states, but imply that MSC acked this uplink session. */
		while ((msg = msgb_dequeue(&conn->vgcs_call.l3_queue)))
			msgb_free(msg);
		conn->vgcs_call.msc_ack = true;
		break;
	case VGCS_EV_TALKER_REL:
		LOG_CALL(conn, LOGL_DEBUG, "Talker released on uplink.\n");
		/* Talker release was complete. Ignore. */
		break;
	case VGCS_EV_MSC_RELEASE:
		LOG_CALL(conn, LOGL_DEBUG, "MSC releases all channels. (channels are free)\n");
		/* MSC releases call (no mor talker on a different BSS), call becomes idle */
		osmo_fsm_inst_state_chg(fi, VGCS_CALL_ST_IDLE, 0, 0);
		/* Unblock all channels. */
		llist_for_each_entry(c, &conn->vgcs_call.chan_list, vgcs_chan.list)
			osmo_fsm_inst_dispatch(c->vgcs_chan.fi, VGCS_EV_UNBLOCK, NULL);
		break;
	case VGCS_EV_CLEANUP:
		LOG_CALL(conn, LOGL_DEBUG, "SCCP connection clearing.\n");
		osmo_fsm_inst_term(conn->vgcs_call.fi, 0, NULL);
		break;
	default:
		OSMO_ASSERT(false);
	}
}

static const struct osmo_fsm_state vgcs_call_fsm_states[] = {
	[VGCS_CALL_ST_NULL] = {
		.name = "NULL",
		.in_event_mask = S(VGCS_EV_SETUP),
		.out_state_mask = S(VGCS_CALL_ST_IDLE),
		.action = vgcs_call_fsm_null,
	},
	[VGCS_CALL_ST_IDLE] = {
		.name = "IDLE",
		.in_event_mask = S(VGCS_EV_TALKER_DET) |
				 S(VGCS_EV_MSC_SEIZE) |
				 S(VGCS_EV_MSC_RELEASE) |
				 S(VGCS_EV_MSC_REJECT) |
				 S(VGCS_EV_CLEANUP),
		.out_state_mask = S(VGCS_CALL_ST_BUSY) |
				  S(VGCS_CALL_ST_BLOCKED) |
				  S(VGCS_CALL_ST_NULL),
		.action = vgcs_call_fsm_idle,
	},
	[VGCS_CALL_ST_BUSY] = {
		.name = "BUSY",
		.in_event_mask = S(VGCS_EV_TALKER_EST) |
				 S(VGCS_EV_TALKER_DATA) |
				 S(VGCS_EV_MSC_DTAP) |
				 S(VGCS_EV_TALKER_REL) |
				 S(VGCS_EV_MSC_SEIZE) |
				 S(VGCS_EV_MSC_ACK) |
				 S(VGCS_EV_MSC_REJECT) |
				 S(VGCS_EV_CLEANUP),
		.out_state_mask = S(VGCS_CALL_ST_IDLE) |
				  S(VGCS_CALL_ST_BLOCKED) |
				  S(VGCS_CALL_ST_NULL),
		.action = vgcs_call_fsm_busy,
	},
	[VGCS_CALL_ST_BLOCKED] = {
		.name = "BLOCKED",
		.in_event_mask = S(VGCS_EV_CALLING_ASSIGNED) |
				 S(VGCS_EV_TALKER_REL) |
				 S(VGCS_EV_MSC_RELEASE) |
				 S(VGCS_EV_CLEANUP),
		.out_state_mask = S(VGCS_CALL_ST_IDLE) |
				  S(VGCS_CALL_ST_BUSY) |
				  S(VGCS_CALL_ST_NULL),
		.action = vgcs_call_fsm_blocked,
	},
};

static struct osmo_fsm vgcs_call_fsm = {
	.name = "vgcs_call",
	.states = vgcs_call_fsm_states,
	.num_states = ARRAY_SIZE(vgcs_call_fsm_states),
	.log_subsys = DASCI,
	.event_names = vgcs_fsm_event_names,
	.cleanup = vgcs_call_detach_and_destroy,
};

/* Handle VGCS/VBS SETUP message.
 *
 * See 3GPP TS 48.008 §3.2.1.50
 */
int vgcs_vbs_call_start(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	int payload_length = msg->tail - msg->l4h;
	struct tlv_parsed tp;
	struct gsm_subscriber_connection *c;
	struct gsm0808_group_callref *gc = &conn->vgcs_call.gc_ie;
	int rc;
	uint8_t cause;

	if (osmo_bssap_tlv_parse(&tp, msg->l4h + 1, payload_length - 1) < 0) {
		LOGPFSML(conn->fi, LOGL_ERROR, "%s(): tlv_parse() failed\n", __func__);
		cause = GSM0808_CAUSE_INVALID_MESSAGE_CONTENTS;
		goto reject;
	}

	/* Check for mandatory Group Call Reference. */
	if (!TLVP_PRESENT(&tp, GSM0808_IE_GROUP_CALL_REFERENCE)) {
		LOGPFSML(conn->fi, LOGL_ERROR, "Mandatory group call reference not present.\n");
		cause = GSM0808_CAUSE_INFORMATION_ELEMENT_OR_FIELD_MISSING;
		goto reject;
	}

	/* Decode Group Call Reference. */
	rc = gsm0808_dec_group_callref(gc, TLVP_VAL(&tp, GSM0808_IE_GROUP_CALL_REFERENCE),
				       TLVP_LEN(&tp, GSM0808_IE_GROUP_CALL_REFERENCE));
	if (rc < 0) {
		LOGPFSML(conn->fi, LOGL_ERROR, "Unable to decode group call reference.\n");
		cause = GSM0808_CAUSE_INCORRECT_VALUE;
		goto reject;
	}
	conn->vgcs_call.sf = gc->sf;
	conn->vgcs_call.call_ref = (osmo_load32be_ext_2(gc->call_ref_hi, 3) << 3) | gc->call_ref_lo;

	/* Check for duplicated callref. */
	llist_for_each_entry(c, &conn->network->subscr_conns, entry) {
		if (!c->vgcs_call.fi)
			continue;
		if (c == conn)
			continue;
		if (conn->vgcs_call.sf == c->vgcs_call.sf
		 && conn->vgcs_call.call_ref == c->vgcs_call.call_ref) {
			LOG_CALL(conn, LOGL_ERROR, "A %s call with callref %s already exists.\n",
			     (conn->vgcs_call.sf == GSM0808_SF_VGCS) ? "VGCS" : "VBS",
			     gsm44068_group_id_string(conn->vgcs_call.call_ref));
			cause = GSM0808_CAUSE_INCORRECT_VALUE;
			goto reject;
		}
	}

	/* Decode VGCS Feature Flags */
	if (TLVP_PRESENT(&tp, GSM0808_IE_VGCS_FEATURE_FLAGS)) {
		rc = gsm0808_dec_vgcs_feature_flags(&conn->vgcs_call.ff,
						    TLVP_VAL(&tp, GSM0808_IE_VGCS_FEATURE_FLAGS),
						    TLVP_LEN(&tp, GSM0808_IE_VGCS_FEATURE_FLAGS));
		if (rc < 0) {
			LOG_CALL(conn, LOGL_ERROR, "Unable to decode feature flags.\n");
			cause = GSM0808_CAUSE_INCORRECT_VALUE;
			goto reject;
		}
		conn->vgcs_call.ff_present = true;
	}

	/* Create VGCS FSM. */
	conn->vgcs_call.fi = osmo_fsm_inst_alloc(&vgcs_call_fsm, conn->network, conn, LOGL_DEBUG, NULL);
	if (!conn->vgcs_call.fi) {
		cause = GSM0808_CAUSE_INCORRECT_VALUE;
		goto reject;
	}

	/* Init list of cells that are used by the call. */
	INIT_LLIST_HEAD(&conn->vgcs_call.chan_list);

	/* Init L3 queue. */
	INIT_LLIST_HEAD(&conn->vgcs_call.l3_queue);

	osmo_fsm_inst_dispatch(conn->vgcs_call.fi, VGCS_EV_SETUP, NULL);
	return 0;
reject:
	bsc_tx_setup_refuse(conn, cause);
	return -EINVAL;
}

/*
 * VGCS chan FSM
 */

static void vgcs_chan_detach_and_destroy(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct gsm_subscriber_connection *conn = fi->priv;

	if (conn->vgcs_chan.fi->state != VGCS_CHAN_ST_WAIT_EST) {
		/* Remove call from notification channel. */
		if (conn->lchan)
			rsl_notification_cmd(conn->lchan->ts->trx->bts, NULL, &conn->vgcs_chan.gc_ie, NULL);
		else
			LOG_CHAN(conn, LOGL_ERROR, "Unable to remove notification, lchan is already gone.\n");
	}

	/* Detach from call, if not already. */
	if (conn->vgcs_chan.call) {
		llist_del(&conn->vgcs_chan.list);
		conn->vgcs_chan.call = NULL;
	}

	/* Remove pointer of FSM. */
	conn->vgcs_chan.fi = NULL;
}

static void uplink_released(struct gsm_subscriber_connection *conn)
{
	LOG_CHAN(conn, LOGL_DEBUG, "Uplink is now released.\n");
	/* Go into blocked or free state. */
	if (conn->vgcs_chan.call && conn->vgcs_chan.call->vgcs_call.fi
	 && conn->vgcs_chan.call->vgcs_call.fi->state == VGCS_CALL_ST_IDLE)
		osmo_fsm_inst_state_chg(conn->vgcs_chan.fi, VGCS_CHAN_ST_ACTIVE_FREE, 0, 0);
	else
		osmo_fsm_inst_state_chg(conn->vgcs_chan.fi, VGCS_CHAN_ST_ACTIVE_BLOCKED, 0, 0);
}

static void vgcs_chan_fsm_null(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_subscriber_connection *conn = fi->priv;
	struct lchan_activate_info info;

	switch (event) {
	case VGCS_EV_ASSIGN_REQ:
		LOG_CHAN(conn, LOGL_DEBUG, "MSC assigns channel.\n");
		/* MSC requests channel assignment. */
		osmo_fsm_inst_state_chg(fi, VGCS_CHAN_ST_WAIT_EST, 0, 0);
		/* Requesting channel from BTS. */
		info = (struct lchan_activate_info){
			.activ_for = ACTIVATE_FOR_VGCS_CHANNEL,
			.for_conn = conn,
			.chreq_reason = GSM_CHREQ_REASON_OTHER,
			.ch_mode_rate = conn->vgcs_chan.ch_mode_rate,
			.ch_indctr = conn->vgcs_chan.ct.ch_indctr,
			/* TSC is used from TS config. */
			.encr = conn->vgcs_chan.new_lchan->encr,
			/* Timing advance of 0 is used until channel is activated for uplink. */
			.ta_known = true,
			.ta = 0,
		};
		if (conn->vgcs_chan.call->vgcs_call.sf == GSM0808_SF_VGCS)
			info.type_for = LCHAN_TYPE_FOR_VGCS;
		else
			info.type_for = LCHAN_TYPE_FOR_VBS;
		/* Activate lchan. If an error occurs, this the function call may trigger VGCS_EV_LCHAN_ERROR event.
		 * This means that this must be the last action in this handler. */
		lchan_activate(conn->vgcs_chan.new_lchan, &info);
		break;
	default:
		OSMO_ASSERT(false);
	}
}

static void vgcs_chan_fsm_wait_est(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_subscriber_connection *conn = fi->priv;
	const struct mgcp_conn_peer *mgw_info;

	switch (event) {
	case VGCS_EV_LCHAN_ACTIVE:
		LOG_CHAN(conn, LOGL_DEBUG, "lchan is active.\n");
		/* If no MGW is used. */
		if (!gscon_is_aoip(conn)) {
			LOG_CHAN(conn, LOGL_DEBUG, "Not connecting MGW endpoint, no AoIP connection.\n");
			goto no_aoip;
		}
		/* Send activation to MGW. */
		LOG_CHAN(conn, LOGL_DEBUG, "Connecting MGW endpoint to the MSC's RTP port: %s:%u\n",
		     conn->vgcs_chan.msc_rtp_addr, conn->vgcs_chan.msc_rtp_port);
		/* Connect MGW. The function call may trigger VGCS_EV_MGW_OK event.
		 * This means that this must be the last action in this handler.
		 * If this function fails, VGCS_EV_MGW_FAIL will not trigger. */
		if (!gscon_connect_mgw_to_msc(conn,
					      conn->vgcs_chan.new_lchan,
					      conn->vgcs_chan.msc_rtp_addr,
					      conn->vgcs_chan.msc_rtp_port,
					      fi,
					      VGCS_EV_MGW_OK,
					      VGCS_EV_MGW_FAIL,
					      NULL,
					      NULL)) {
			/* Report failure to MSC. */
			bsc_tx_vgcs_vbs_assignment_fail(conn, GSM0808_CAUSE_EQUIPMENT_FAILURE);
			break;
		}
		break;
	case VGCS_EV_LCHAN_ERROR:
		LOG_CHAN(conn, LOGL_DEBUG, "lchan failed.\n");
		/* BTS reports failure on channel request. */
		osmo_fsm_inst_state_chg(fi, VGCS_CHAN_ST_NULL, 0, 0);
		/* Add/update SI10. */
		if (conn->vgcs_chan.call)
			si10_update(conn->vgcs_chan.call);
		/* Report failure to MSC. */
		bsc_tx_vgcs_vbs_assignment_fail(conn, GSM0808_CAUSE_EQUIPMENT_FAILURE);
		break;
	case VGCS_EV_MGW_OK:
		LOG_CHAN(conn, LOGL_DEBUG, "MGW endpoint connected.\n");
		/* MGW reports success. */
		mgw_info = osmo_mgcpc_ep_ci_get_rtp_info(conn->user_plane.mgw_endpoint_ci_msc);
		if (!mgw_info) {
			LOG_CHAN(conn, LOGL_ERROR, "Unable to retrieve RTP port info allocated by MGW for"
						   " the MSC side.");
			/* Report failure to MSC. */
			bsc_tx_vgcs_vbs_assignment_fail(conn, GSM0808_CAUSE_EQUIPMENT_FAILURE);
			break;
		}
		LOG_CHAN(conn, LOGL_DEBUG, "MGW's MSC side CI: %s:%u\n", mgw_info->addr, mgw_info->port);
no_aoip:
		/* Channel established from BTS. */
		gscon_change_primary_lchan(conn, conn->vgcs_chan.new_lchan);
		/* Change state according to call state. */
		if (conn->vgcs_chan.call && conn->vgcs_chan.call->vgcs_call.fi
		 && conn->vgcs_chan.call->vgcs_call.fi->state == VGCS_CALL_ST_IDLE)
			osmo_fsm_inst_state_chg(fi, VGCS_CHAN_ST_ACTIVE_FREE, 0, 0);
		else
			osmo_fsm_inst_state_chg(fi, VGCS_CHAN_ST_ACTIVE_BLOCKED, 0, 0);
		if (conn->vgcs_chan.call) {
			/* Add call to notification channel. */
			rsl_notification_cmd(conn->lchan->ts->trx->bts, conn->lchan, &conn->vgcs_chan.gc_ie, NULL);
			/* Add/update SI10. */
			si10_update(conn->vgcs_chan.call);
		}
		/* Report result to MSC. */
		bsc_tx_vgcs_vbs_assignment_result(conn, &conn->vgcs_chan.ct, &conn->vgcs_chan.ci,
						  conn->vgcs_chan.call_id);
		break;
	case VGCS_EV_MGW_FAIL:
		LOG_CHAN(conn, LOGL_DEBUG, "MGW endpoint failed.\n");
		/* MGW reports failure. */
		osmo_fsm_inst_state_chg(fi, VGCS_CHAN_ST_NULL, 0, 0);
		/* Add/update SI10. */
		if (conn->vgcs_chan.call)
			si10_update(conn->vgcs_chan.call);
		/* Report failure to MSC. */
		bsc_tx_vgcs_vbs_assignment_fail(conn, GSM0808_CAUSE_EQUIPMENT_FAILURE);
		break;
	case VGCS_EV_CLEANUP:
		LOG_CHAN(conn, LOGL_DEBUG, "SCCP connection clearing.\n");
		/* MSC wants to terminate. */
		osmo_fsm_inst_term(conn->vgcs_chan.fi, 0, NULL);
		break;
	case VGCS_EV_BLOCK:
	case VGCS_EV_UNBLOCK:
		/* Ignore, because channel is not yet ready. */
		break;
	default:
		OSMO_ASSERT(false);
	}
}

static void vgcs_chan_fsm_active_blocked(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_subscriber_connection *conn = fi->priv, *cc;

	switch (event) {
	case VGCS_EV_UNBLOCK:
		LOG_CHAN(conn, LOGL_DEBUG, "Unblocking channel.\n");
		/* No uplink is used in other cell. */
		osmo_fsm_inst_state_chg(fi, VGCS_CHAN_ST_ACTIVE_FREE, 0, 0);
		break;
	case VGCS_EV_TALKER_DET:
		LOG_CHAN(conn, LOGL_DEBUG, "Talker detected on blocked channel.\n");
		if (conn->vgcs_chan.call->vgcs_call.sf == GSM0808_SF_VBS)
			LOG_CHAN(conn, LOGL_ERROR, "Talker detection not allowed on VBS channel.\n");
		/* Race condition: BTS detected a talker. Waiting for talker to establish or fail. */
		osmo_fsm_inst_state_chg(fi, VGCS_CHAN_ST_ACTIVE_REL, 0, 0);
		break;
	case VGCS_EV_TALKER_EST:
		cc = find_calling_subscr_conn(conn);
		if (!cc) {
			LOG_CHAN(conn, LOGL_ERROR, "No assignment requested from MSC!\n");
			/* Uplink is used while blocked. Waiting for channel to be release. */
			osmo_fsm_inst_state_chg(fi, VGCS_CHAN_ST_ACTIVE_REL, 0, 0);
			/* Send UPLINK RELEASE to MS. */
			gsm48_send_uplink_release(conn->lchan, GSM48_RR_CAUSE_NORMAL);
			/* Go into blocked or free state. */
			uplink_released(conn);
			break;
		}
		/* Talker is assigning to this channel. */
		osmo_fsm_inst_state_chg(fi, VGCS_CHAN_ST_ACTIVE_EST, 0, 0);
		/* Report talker detection to call state machine. */
		if (conn->vgcs_chan.call)
			osmo_fsm_inst_dispatch(conn->vgcs_chan.call->vgcs_call.fi, VGCS_EV_CALLING_ASSIGNED, conn);
		/* Repeat notification for the MS that has been assigned. */
		rsl_notification_cmd(conn->lchan->ts->trx->bts, conn->lchan, &conn->vgcs_chan.gc_ie, NULL);
		break;
	case VGCS_EV_CLEANUP:
		LOG_CHAN(conn, LOGL_DEBUG, "SCCP connection clearing.\n");
		/* MSC wants to terminate. */
		osmo_fsm_inst_term(conn->vgcs_chan.fi, 0, NULL);
		break;
	default:
		OSMO_ASSERT(false);
	}
}

static void vgcs_chan_fsm_enter_active_free(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct gsm_subscriber_connection *conn = fi->priv;

	/* Send UPLINK FREE message to BTS. This hits on every state change (and or timer start). */
	LOG_CHAN(conn, LOGL_DEBUG, "Sending UPLINK FREE message to channel.\n");
	gsm48_send_uplink_free(conn->lchan, 0, NULL);
}

static void vgcs_chan_fsm_active_free(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_subscriber_connection *conn = fi->priv;

	switch (event) {
	case VGCS_EV_BLOCK:
		LOG_CHAN(conn, LOGL_DEBUG, "Blocking channel.\n");
		/* Uplink is used in other cell. */
		osmo_fsm_inst_state_chg(fi, VGCS_CHAN_ST_ACTIVE_BLOCKED, 0, 0);
		/* Send UPLINK BUSY to MS. */
		LOG_CHAN(conn, LOGL_DEBUG, "Sending UPLINK BUSY message to channel.\n");
		gsm48_send_uplink_busy(conn->lchan);
		break;
	case VGCS_EV_TALKER_DET:
		LOG_CHAN(conn, LOGL_DEBUG, "Talker detected on free channel.\n");
		/* BTS detected a talker. */
		osmo_fsm_inst_state_chg(fi, VGCS_CHAN_ST_ACTIVE_INIT, 0, 0);
		/* Report talker detection to call state machine. */
		if (conn->vgcs_chan.call)
			osmo_fsm_inst_dispatch(conn->vgcs_chan.call->vgcs_call.fi, VGCS_EV_TALKER_DET, data);
		break;
	case VGCS_EV_CLEANUP:
		LOG_CHAN(conn, LOGL_DEBUG, "SCCP connection clearing.\n");
		/* MSC wants to terminate. */
		osmo_fsm_inst_term(conn->vgcs_chan.fi, 0, NULL);
		break;
	default:
		OSMO_ASSERT(false);
	}
}

static void vgcs_chan_fsm_active_init(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_subscriber_connection *conn = fi->priv;
	uint8_t cause = (data) ? *(uint8_t *)data : 0;

	switch (event) {
	case VGCS_EV_BLOCK:
	case VGCS_EV_REJECT:
		LOG_CHAN(conn, LOGL_DEBUG, "Blocking/rejecting channel.\n");
		/* Uplink is used in other cell. Waiting for channel to be established and then released. */
		osmo_fsm_inst_state_chg(fi, VGCS_CHAN_ST_ACTIVE_REL, 0, 0);
		break;
	case VGCS_EV_TALKER_EST:
		LOG_CHAN(conn, LOGL_DEBUG, "Talker established uplink.\n");
		/* Uplink has been established */
		osmo_fsm_inst_state_chg(fi, VGCS_CHAN_ST_ACTIVE_EST, 0, 0);
		/* Report talker establishment to call state machine. */
		if (conn->vgcs_chan.call)
			osmo_fsm_inst_dispatch(conn->vgcs_chan.call->vgcs_call.fi, VGCS_EV_TALKER_EST, data);
		break;
	case VGCS_EV_TALKER_FAIL:
		LOG_CHAN(conn, LOGL_NOTICE, "Uplink failed, establishment timeout.\n");
		/* Release datalink */
		rsl_release_request(conn->lchan, 0, RSL_REL_LOCAL_END);
		/* fall thru */
	case VGCS_EV_TALKER_REL:
		LOG_CHAN(conn, LOGL_DEBUG, "Uplink is now released.\n");
		/* Uplink establishment failed. */
		osmo_fsm_inst_state_chg(fi, VGCS_CHAN_ST_ACTIVE_FREE, 0, 0);
		/* Report release indication to call state machine. */
		if (conn->vgcs_chan.call)
			osmo_fsm_inst_dispatch(conn->vgcs_chan.call->vgcs_call.fi, VGCS_EV_TALKER_REL, &cause);
		break;
	case VGCS_EV_CLEANUP:
		LOG_CHAN(conn, LOGL_DEBUG, "SCCP connection clearing.\n");
		/* MSC wants to terminate. */
		osmo_fsm_inst_term(conn->vgcs_chan.fi, 0, NULL);
		break;
	default:
		OSMO_ASSERT(false);
	}
}

static void vgcs_chan_fsm_active_est(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_subscriber_connection *conn = fi->priv;
	uint8_t cause = (data) ? *(uint8_t *)data : 0;
	struct msgb *msg = data;

	switch (event) {
	case VGCS_EV_BLOCK:
	case VGCS_EV_REJECT:
		LOG_CHAN(conn, LOGL_DEBUG, "Blocking/rejecting channel.\n");
		/* Uplink is used in other cell. Waiting for channel to be release. */
		osmo_fsm_inst_state_chg(fi, VGCS_CHAN_ST_ACTIVE_REL, 0, 0);
		/* Send UPLINK RELEASE to MS. */
		gsm48_send_uplink_release(conn->lchan, GSM48_RR_CAUSE_NORMAL);
		/* Go into blocked or free state. */
		uplink_released(conn);
		break;
	case VGCS_EV_TALKER_DATA:
		LOG_CHAN(conn, LOGL_DEBUG, "Talker sends data on uplink.\n");
		if (msg) {
			struct gsm48_hdr *gh;
			uint8_t pdisc;
			uint8_t msg_type;
			if (msgb_l3len(msg) < sizeof(*gh)) {
				LOG_LCHAN(msg->lchan, LOGL_ERROR,
					  "Message too short for a GSM48 header (%u)\n", msgb_l3len(msg));
				break;
			}
			gh = msgb_l3(msg);
			pdisc = gsm48_hdr_pdisc(gh);
			msg_type = gsm48_hdr_msg_type(gh);
			if (pdisc == GSM48_PDISC_RR && msg_type == GSM48_MT_RR_UPLINK_RELEASE) {
				LOG_CHAN(conn, LOGL_DEBUG, "Uplink is released by UPLINK RELEASE message.\n");
				/* Release datalink */
				rsl_release_request(conn->lchan, 0, RSL_REL_LOCAL_END);
				/* Talker released the uplink. */
				osmo_fsm_inst_state_chg(fi, VGCS_CHAN_ST_ACTIVE_FREE, 0, 0);
				/* Report talker release to call state machine. */
				if (conn->vgcs_chan.call) {
					cause = GSM0808_CAUSE_CALL_CONTROL;
					osmo_fsm_inst_dispatch(conn->vgcs_chan.call->vgcs_call.fi, VGCS_EV_TALKER_REL,
							       &cause);
				}
				break;
			}
			if (pdisc == GSM48_PDISC_RR && msg_type == GSM48_MT_RR_ASS_COMPL) {
				LOG_CHAN(conn, LOGL_DEBUG, "Asssignment complete.\n");
				struct gsm_subscriber_connection *cc;
				cc = find_calling_subscr_conn(conn);
				if (!cc) {
					LOG_CHAN(conn, LOGL_ERROR, "No assignment requested from MSC!\n");
					break;
				}
				LOG_CHAN(conn, LOGL_DEBUG, "Trigger State machine.\n");
				osmo_fsm_inst_dispatch(cc->assignment.fi, ASSIGNMENT_EV_RR_ASSIGNMENT_COMPLETE, msg);
				break;
			}
		}
		/* Report talker data to call state machine. */
		if (conn->vgcs_chan.call)
			osmo_fsm_inst_dispatch(conn->vgcs_chan.call->vgcs_call.fi, VGCS_EV_TALKER_DATA, data);
		break;
	case VGCS_EV_MSC_DTAP:
		LOG_CHAN(conn, LOGL_DEBUG, "MSC sends DTAP message to talker.\n");
		osmo_fsm_inst_dispatch(conn->fi, GSCON_EV_MT_DTAP, data);
		break;
	case VGCS_EV_TALKER_FAIL:
		LOG_CHAN(conn, LOGL_NOTICE, "Uplink failed after establishment.\n");
		/* Release datalink */
		rsl_release_request(conn->lchan, 0, RSL_REL_LOCAL_END);
		/* fall thru */
	case VGCS_EV_TALKER_REL:
		LOG_CHAN(conn, LOGL_DEBUG, "Uplink is now released.\n");
		/* Talker released the uplink. */
		osmo_fsm_inst_state_chg(fi, VGCS_CHAN_ST_ACTIVE_FREE, 0, 0);
		/* Report talker release to call state machine. */
		if (conn->vgcs_chan.call)
			osmo_fsm_inst_dispatch(conn->vgcs_chan.call->vgcs_call.fi, VGCS_EV_TALKER_REL, &cause);
		break;
	case VGCS_EV_CLEANUP:
		LOG_CHAN(conn, LOGL_DEBUG, "SCCP connection clearing.\n");
		/* MSC wants to terminate. */
		osmo_fsm_inst_term(conn->vgcs_chan.fi, 0, NULL);
		break;
	default:
		OSMO_ASSERT(false);
	}
}

static void vgcs_chan_fsm_active_rel(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_subscriber_connection *conn = fi->priv;

	switch (event) {
	case VGCS_EV_BLOCK:
	case VGCS_EV_REJECT:
		LOG_CHAN(conn, LOGL_DEBUG, "Blocking/rejecting channel.\n");
		/* Race condition: Uplink is used in other cell, we are already releasing. */
		break;
	case VGCS_EV_TALKER_EST:
		LOG_CHAN(conn, LOGL_DEBUG, "Talker established uplink, releasing.\n");
		/* Finally the talker established the connection. Send UPLINK RELEASE to MS. */
		gsm48_send_uplink_release(conn->lchan, GSM48_RR_CAUSE_NORMAL);
		/* Release datalink */
		rsl_release_request(conn->lchan, 0, RSL_REL_LOCAL_END);
		/* fall thru */
	case VGCS_EV_TALKER_FAIL:
		/* Release datalink */
		rsl_release_request(conn->lchan, 0, RSL_REL_LOCAL_END);
		/* fall thru */
	case VGCS_EV_TALKER_REL:
		/* Go into blocked or free state. */
		uplink_released(conn);
		break;
	case VGCS_EV_CLEANUP:
		LOG_CHAN(conn, LOGL_DEBUG, "SCCP connection clearing.\n");
		/* MSC wants to terminate. */
		osmo_fsm_inst_term(conn->vgcs_chan.fi, 0, NULL);
		break;
	default:
		OSMO_ASSERT(false);
	}
}

static const struct osmo_fsm_state vgcs_chan_fsm_states[] = {
	[VGCS_CHAN_ST_NULL] = {
		.name = "NULL",
		.in_event_mask = S(VGCS_EV_ASSIGN_REQ),
		.out_state_mask = S(VGCS_CHAN_ST_WAIT_EST),
		.action = vgcs_chan_fsm_null,
	},
	[VGCS_CHAN_ST_WAIT_EST] = {
		.name = "WAIT_EST",
		.in_event_mask = S(VGCS_EV_LCHAN_ACTIVE) |
				 S(VGCS_EV_LCHAN_ERROR) |
				 S(VGCS_EV_MGW_OK) |
				 S(VGCS_EV_MGW_FAIL) |
				 S(VGCS_EV_CLEANUP) |
				 S(VGCS_EV_BLOCK) |
				 S(VGCS_EV_UNBLOCK),
		.out_state_mask = S(VGCS_CHAN_ST_NULL) |
				  S(VGCS_CHAN_ST_ACTIVE_BLOCKED) |
				  S(VGCS_CHAN_ST_ACTIVE_FREE),
		.action = vgcs_chan_fsm_wait_est,
	},
	[VGCS_CHAN_ST_ACTIVE_BLOCKED] = {
		.name = "ACTIVE/BLOCKED",
		.in_event_mask = S(VGCS_EV_UNBLOCK) |
				 S(VGCS_EV_TALKER_DET) |
				 S(VGCS_EV_TALKER_EST) |
				 S(VGCS_EV_CLEANUP),
		.out_state_mask = S(VGCS_CHAN_ST_NULL) |
				  S(VGCS_CHAN_ST_ACTIVE_EST) |
				  S(VGCS_CHAN_ST_ACTIVE_FREE) |
				  S(VGCS_CHAN_ST_ACTIVE_REL),
		.action = vgcs_chan_fsm_active_blocked,
	},
	[VGCS_CHAN_ST_ACTIVE_FREE] = {
		.name = "ACTIVE/FREE",
		.in_event_mask = S(VGCS_EV_BLOCK) |
				 S(VGCS_EV_TALKER_DET) |
				 S(VGCS_EV_CLEANUP),
		.out_state_mask = S(VGCS_CHAN_ST_NULL) |
				  S(VGCS_CHAN_ST_ACTIVE_BLOCKED) |
				  S(VGCS_CHAN_ST_ACTIVE_INIT) |
				  S(VGCS_CHAN_ST_ACTIVE_FREE),
		.action = vgcs_chan_fsm_active_free,
		.onenter = vgcs_chan_fsm_enter_active_free,
	},
	[VGCS_CHAN_ST_ACTIVE_INIT] = {
		.name = "ACTIVE/INIT",
		.in_event_mask = S(VGCS_EV_BLOCK) |
				 S(VGCS_EV_REJECT) |
				 S(VGCS_EV_TALKER_EST) |
				 S(VGCS_EV_TALKER_FAIL) |
				 S(VGCS_EV_CLEANUP),
		.out_state_mask = S(VGCS_CHAN_ST_NULL) |
				  S(VGCS_CHAN_ST_ACTIVE_EST) |
				  S(VGCS_CHAN_ST_ACTIVE_REL) |
				  S(VGCS_CHAN_ST_ACTIVE_FREE),
		.action = vgcs_chan_fsm_active_init,
	},
	[VGCS_CHAN_ST_ACTIVE_EST] = {
		.name = "ACTIVE/ESTABLISHED",
		.in_event_mask = S(VGCS_EV_BLOCK) |
				 S(VGCS_EV_REJECT) |
				 S(VGCS_EV_TALKER_DATA) |
				 S(VGCS_EV_MSC_DTAP) |
				 S(VGCS_EV_TALKER_REL) |
				 S(VGCS_EV_TALKER_FAIL) |
				 S(VGCS_EV_CLEANUP),
		.out_state_mask = S(VGCS_CHAN_ST_NULL) |
				  S(VGCS_CHAN_ST_ACTIVE_FREE) |
				  S(VGCS_CHAN_ST_ACTIVE_REL),
		.action = vgcs_chan_fsm_active_est,
	},
	[VGCS_CHAN_ST_ACTIVE_REL] = {
		.name = "ACTIVE/RELEASE",
		.in_event_mask = S(VGCS_EV_BLOCK) |
				 S(VGCS_EV_REJECT) |
				 S(VGCS_EV_TALKER_EST) |
				 S(VGCS_EV_TALKER_REL) |
				 S(VGCS_EV_TALKER_FAIL) |
				 S(VGCS_EV_CLEANUP),
		.out_state_mask = S(VGCS_CHAN_ST_NULL) |
				  S(VGCS_CHAN_ST_ACTIVE_BLOCKED) |
				  S(VGCS_CHAN_ST_ACTIVE_FREE),
		.action = vgcs_chan_fsm_active_rel,
	},
};

static struct osmo_fsm vgcs_chan_fsm = {
	.name = "vgcs_chan",
	.states = vgcs_chan_fsm_states,
	.num_states = ARRAY_SIZE(vgcs_chan_fsm_states),
	.log_subsys = DASCI,
	.event_names = vgcs_fsm_event_names,
	.cleanup = vgcs_chan_detach_and_destroy,
};

/* Handle VGCS/VBS ASSIGNMENT REQUEST message.
 *
 * See 3GPP TS 48.008 §3.2.1.53
 */
int vgcs_vbs_chan_start(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	int payload_length = msg->tail - msg->l4h;
	struct tlv_parsed tp;
	struct gsm_subscriber_connection *c;
	struct gsm0808_group_callref *gc = &conn->vgcs_chan.gc_ie;
	struct assignment_request req = {
		.aoip = gscon_is_aoip(conn),
	};
	uint8_t cause;
	struct gsm_bts *bts;
	struct gsm_lchan *lchan = NULL;
	int rc;
	int i;

	if (osmo_bssap_tlv_parse(&tp, msg->l4h + 1, payload_length - 1) < 0) {
		LOGPFSML(conn->fi, LOGL_ERROR, "%s(): tlv_parse() failed\n", __func__);
		cause = GSM0808_CAUSE_INVALID_MESSAGE_CONTENTS;
		goto reject;
	}

	/* Check for mandatory IEs. */
	if (!TLVP_PRESENT(&tp, GSM0808_IE_CHANNEL_TYPE)
	 || !TLVP_PRESENT(&tp, GSM0808_IE_ASSIGNMENT_REQUIREMENT)
	 || !TLVP_PRESENT(&tp, GSM0808_IE_CELL_IDENTIFIER)
	 || !TLVP_PRESENT(&tp, GSM0808_IE_GROUP_CALL_REFERENCE)) {
		LOGPFSML(conn->fi, LOGL_ERROR, "Mandatory IE not present.\n");
		cause = GSM0808_CAUSE_INFORMATION_ELEMENT_OR_FIELD_MISSING;
		goto reject;
	}

	/* Decode Channel Type element. */
	rc = gsm0808_dec_channel_type(&conn->vgcs_chan.ct,  TLVP_VAL(&tp, GSM0808_IE_CHANNEL_TYPE),
				      TLVP_LEN(&tp, GSM0808_IE_CHANNEL_TYPE));
	if (rc < 0) {
		LOGPFSML(conn->fi, LOGL_ERROR, "Unable to decode Channel Type.\n");
		cause = GSM0808_CAUSE_INCORRECT_VALUE;
		goto reject;
	}

	/* Only speech is supported. */
	if (conn->vgcs_chan.ct.ch_indctr != GSM0808_CHAN_SPEECH) {
		cause = GSM0808_CAUSE_INVALID_MESSAGE_CONTENTS;
		goto reject;
	}

	/* Decode Assignment Requirement element. */
	rc = gsm0808_dec_assign_req(&conn->vgcs_chan.ar, TLVP_VAL(&tp, GSM0808_IE_ASSIGNMENT_REQUIREMENT),
				    TLVP_LEN(&tp, GSM0808_IE_ASSIGNMENT_REQUIREMENT));
	if (rc < 0) {
		LOGPFSML(conn->fi, LOGL_ERROR, "Unable to decode Assignment Requirement.\n");
		cause = GSM0808_CAUSE_INCORRECT_VALUE;
		goto reject;
	}

	/* Decode Cell Identifier element. */
	rc = gsm0808_dec_cell_id(&conn->vgcs_chan.ci, TLVP_VAL(&tp, GSM0808_IE_CELL_IDENTIFIER),
				 TLVP_LEN(&tp, GSM0808_IE_CELL_IDENTIFIER));
	if (rc < 0) {
		LOGPFSML(conn->fi, LOGL_ERROR, "Unable to decode Cell Identifier.\n");
		cause = GSM0808_CAUSE_INCORRECT_VALUE;
		goto reject;
	}
	gsm0808_cell_id_u_name(conn->vgcs_chan.ci_str, sizeof(conn->vgcs_chan.ci_str), conn->vgcs_chan.ci.id_discr,
			       &conn->vgcs_chan.ci.id);

	/* Decode Group Call Reference element. */
	rc = gsm0808_dec_group_callref(gc, TLVP_VAL(&tp, GSM0808_IE_GROUP_CALL_REFERENCE),
				       TLVP_LEN(&tp, GSM0808_IE_GROUP_CALL_REFERENCE));
	if (rc < 0) {
		LOGPFSML(conn->fi, LOGL_ERROR, "Unable to decode Group Call Reference.\n");
		cause = GSM0808_CAUSE_INCORRECT_VALUE;
		goto reject;
	}
	conn->vgcs_chan.sf = gc->sf;
	conn->vgcs_chan.call_ref = (osmo_load32be_ext_2(gc->call_ref_hi, 3) << 3) | gc->call_ref_lo;

	/* Find BTS from Cell Identity. */
	bts = gsm_bts_by_cell_id(conn->network, &conn->vgcs_chan.ci, 0);
	if (!bts) {
		LOG_CHAN(conn, LOGL_ERROR, "No cell found that matches the given Cell Identifier.\n");
		cause = GSM0808_CAUSE_RQSTED_TERRESTRIAL_RESOURCE_UNAVAILABLE;
		goto reject;
	}

	/* If Cell Identity is ambiguous. */
	if (gsm_bts_by_cell_id(conn->network, &conn->vgcs_chan.ci, 1))
		LOG_CHAN(conn, LOGL_NOTICE, "More thant one cell found that match the given Cell Identifier.\n");

	/* Decode channel related elements.
	 * This must be done after selecting the BTS, because codec selection requires relation to BTS. */
	rc = bssmap_handle_ass_req_ct_speech(conn, bts, &tp, &conn->vgcs_chan.ct, &req, &cause);
	if (rc < 0)
		goto reject;

	/* Store AoIP elements. */
	osmo_strlcpy(conn->vgcs_chan.msc_rtp_addr, req.msc_rtp_addr, sizeof(conn->vgcs_chan.msc_rtp_addr));
	conn->vgcs_chan.msc_rtp_port = req.msc_rtp_port;
	if (TLVP_PRESENT(&tp, GSM0808_IE_CALL_ID)) {
		/* Decode Call Identifier element. */
		rc = gsm0808_dec_call_id(&conn->vgcs_chan.call_id, TLVP_VAL(&tp, GSM0808_IE_CALL_ID),
					 TLVP_LEN(&tp, GSM0808_IE_CALL_ID));
		if (rc < 0) {
			LOG_CHAN(conn, LOGL_ERROR, "Unable to decode Call Identifier.\n");
			cause = GSM0808_CAUSE_INCORRECT_VALUE;
			goto reject;
		}
	}

	/* Try to allocate a new lchan in order of preference. */
	for (i = 0; i < req.n_ch_mode_rate; i++) {
		lchan = lchan_select_by_chan_mode(bts,
						  req.ch_mode_rate_list[i].chan_mode,
						  req.ch_mode_rate_list[i].chan_rate,
						  SELECT_FOR_VGCS, NULL);
		if (!lchan)
			continue;
		LOG_CHAN(conn, LOGL_DEBUG, "Selected new lchan %s for mode[%d] = %s channel_rate=%d\n",
			 gsm_lchan_name(lchan), i, gsm48_chan_mode_name(req.ch_mode_rate_list[i].chan_mode),
			 req.ch_mode_rate_list[i].chan_rate);

		conn->vgcs_chan.ch_mode_rate = req.ch_mode_rate_list[i];
		break;
	}
	if (!lchan) {
		LOG_CHAN(conn, LOGL_ERROR, "Requested lchan not available.\n");
		cause = GSM0808_CAUSE_NO_RADIO_RESOURCE_AVAILABLE;
		goto reject;
	}
	conn->vgcs_chan.new_lchan = lchan;

	/* Create VGCS FSM. */
	conn->vgcs_chan.fi = osmo_fsm_inst_alloc(&vgcs_chan_fsm, conn->network, conn, LOGL_DEBUG, NULL);
	if (!conn->vgcs_chan.fi)
		goto reject;

	/* Attach to call control instance, if a call with same callref exists. */
	llist_for_each_entry(c, &conn->network->subscr_conns, entry) {
		if (!c->vgcs_call.fi)
			continue;
		if (c->vgcs_call.sf == conn->vgcs_chan.sf
		 && c->vgcs_call.call_ref == conn->vgcs_chan.call_ref) {
			llist_add_tail(&conn->vgcs_chan.list, &c->vgcs_call.chan_list);
			conn->vgcs_chan.call = c;
			break;
		}
	}
	if (!conn->vgcs_chan.call) {
		LOG_CHAN(conn, LOGL_ERROR, "A %s call with callref %s does not exist.\n",
			 (conn->vgcs_chan.sf == GSM0808_SF_VGCS) ? "VGCS" : "VBS",
			 gsm44068_group_id_string(conn->vgcs_chan.call_ref));
		cause = GSM0808_CAUSE_VGCS_VBS_CALL_NON_EXISTENT;
		osmo_fsm_inst_term(conn->vgcs_chan.fi, 0, NULL);
		goto reject;
	}

	osmo_fsm_inst_dispatch(conn->vgcs_chan.fi, VGCS_EV_ASSIGN_REQ, NULL);
	return 0;
reject:
	bsc_tx_vgcs_vbs_assignment_fail(conn, cause);
	return -EINVAL;
}

/* Return lchan of group call that exists in the same BTS. */
struct gsm_lchan *vgcs_vbs_find_lchan(struct gsm_bts *bts, struct gsm0808_group_callref *gc)
{
	struct gsm_subscriber_connection *call = NULL, *c;
	struct gsm_lchan *lchan = NULL;
	uint32_t call_ref = (osmo_load32be_ext_2(gc->call_ref_hi, 3) << 3) | gc->call_ref_lo;

	/* Find group call. */
	llist_for_each_entry(c, &bts->network->subscr_conns, entry) {
		if (!c->vgcs_call.fi)
			continue;
		if (c->vgcs_call.sf == gc->sf
		 && c->vgcs_call.call_ref == call_ref) {
			call = c;
			break;
		}
	}
	if (!call) {
		LOGP(DASCI, LOGL_ERROR, "Cannot assign to channel, %s channel with callref %s does not exist.\n",
		     (gc->sf == GSM0808_SF_VGCS) ? "VGCS" : "VBS", gsm44068_group_id_string(call_ref));
		return NULL;
	}

	/* Find channel in same BTS. */
	llist_for_each_entry(c, &call->vgcs_call.chan_list, vgcs_chan.list) {
		if (c->lchan && c->lchan->ts->trx->bts == bts)
			lchan = c->lchan;
	}
	if (!call) {
		LOGP(DASCI, LOGL_ERROR, "Cannot assign to channel, caller's BTS has no %s channel with callref %s.\n",
		     (gc->sf == GSM0808_SF_VGCS) ? "VGCS" : "VBS", gsm44068_group_id_string(call_ref));
		return NULL;
	}

	return lchan;
}
