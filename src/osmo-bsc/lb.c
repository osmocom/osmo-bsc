/* Lb interface low level SCCP handling */
/*
 * (C) 2020 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 *
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr <neels@hofmeyr.de>
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

#include <osmocom/bsc/lb.h>

#include <osmocom/gsm/bssmap_le.h>
#include <osmocom/sigtran/sccp_helpers.h>
#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/vty.h>
#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/osmo_bsc_sigtran.h>
#include <osmocom/bsc/lcs_loc_req.h>
#include <osmocom/bsc/bssmap_reset.h>

static struct gsm_subscriber_connection *get_bsc_conn_by_lb_conn_id(int conn_id)
{
	struct gsm_subscriber_connection *conn;

	llist_for_each_entry(conn, &bsc_gsmnet->subscr_conns, entry) {
		if (conn->lcs.lb.state != SUBSCR_SCCP_ST_NONE
		    && conn->lcs.lb.conn_id == conn_id)
			return conn;
	}

	return NULL;
}

/* Send reset to SMLC */
int bssmap_le_tx_reset()
{
	struct osmo_ss7_instance *ss7;
	struct msgb *msg;
	struct bssap_le_pdu reset = {
		.discr = BSSAP_LE_MSG_DISCR_BSSMAP_LE,
		.bssmap_le = {
			.msg_type = BSSMAP_LE_MSGT_RESET,
			.reset = GSM0808_CAUSE_EQUIPMENT_FAILURE,
		},
	};

	ss7 = osmo_ss7_instance_find(bsc_gsmnet->smlc->cs7_instance);
	OSMO_ASSERT(ss7);
	LOGP(DRESET, LOGL_INFO, "Sending RESET to SMLC: %s\n", osmo_sccp_addr_name(ss7, &bsc_gsmnet->smlc->smlc_addr));
	msg = osmo_bssap_le_enc(&reset);

	rate_ctr_inc(&bsc_gsmnet->smlc->ctrs->ctr[SMLC_CTR_BSSMAP_LE_TX_UDT_RESET]);
	return osmo_sccp_tx_unitdata_msg(bsc_gsmnet->smlc->sccp_user, &bsc_gsmnet->smlc->bsc_addr,
					 &bsc_gsmnet->smlc->smlc_addr, msg);
}

/* Send reset-ack to SMLC */
int bssmap_le_tx_reset_ack()
{
	struct osmo_ss7_instance *ss7;
	struct msgb *msg;
	struct bssap_le_pdu reset_ack = {
		.discr = BSSAP_LE_MSG_DISCR_BSSMAP_LE,
		.bssmap_le = {
			.msg_type = BSSMAP_LE_MSGT_RESET_ACK,
		},
	};

	ss7 = osmo_ss7_instance_find(bsc_gsmnet->smlc->cs7_instance);
	OSMO_ASSERT(ss7);
	LOGP(DRESET, LOGL_NOTICE, "Sending RESET ACK to SMLC: %s\n", osmo_sccp_addr_name(ss7, &bsc_gsmnet->smlc->smlc_addr));
	msg = osmo_bssap_le_enc(&reset_ack);

	rate_ctr_inc(&bsc_gsmnet->smlc->ctrs->ctr[SMLC_CTR_BSSMAP_LE_TX_UDT_RESET_ACK]);
	return osmo_sccp_tx_unitdata_msg(bsc_gsmnet->smlc->sccp_user, &bsc_gsmnet->smlc->bsc_addr,
					 &bsc_gsmnet->smlc->smlc_addr, msg);
}

static int handle_unitdata_from_smlc(const struct osmo_sccp_addr *smlc_addr, struct msgb *msg,
				     const struct osmo_sccp_user *scu)
{
	struct osmo_ss7_instance *ss7;
	struct bssap_le_pdu bssap_le;
	struct osmo_bssap_le_err *err;
	struct rate_ctr *ctr = bsc_gsmnet->smlc->ctrs->ctr;

	ss7 = osmo_sccp_get_ss7(osmo_sccp_get_sccp(scu));
	OSMO_ASSERT(ss7);

	if (osmo_sccp_addr_cmp(smlc_addr, &bsc_gsmnet->smlc->smlc_addr, OSMO_SCCP_ADDR_T_MASK)) {
		LOGP(DLCS, LOGL_ERROR, "Rx BSSMAP-LE UnitData from unknown remote address: %s\n",
		     osmo_sccp_addr_name(ss7, smlc_addr));
		rate_ctr_inc(&ctr[SMLC_CTR_BSSMAP_LE_RX_UNKNOWN_PEER]);
		return -EINVAL;
	}

	if (osmo_bssap_le_dec(&bssap_le, &err, msg, msg)) {
		LOGP(DLCS, LOGL_ERROR, "Rx BSSAP-LE UnitData with error: %s\n", err->logmsg);
		rate_ctr_inc(&ctr[SMLC_CTR_BSSMAP_LE_RX_UDT_ERR_INVALID_MSG]);
		return -EINVAL;
	}

	if (bssap_le.discr != BSSAP_LE_MSG_DISCR_BSSMAP_LE) {
		LOGP(DLCS, LOGL_ERROR, "Rx BSSAP-LE: discr %d not implemented\n", bssap_le.discr);
		return -ENOTSUP;
	}

	switch (bssap_le.bssmap_le.msg_type) {
	case BSSMAP_LE_MSGT_RESET:
		rate_ctr_inc(&ctr[SMLC_CTR_BSSMAP_LE_RX_UDT_RESET]);
		LOGP(DLCS, LOGL_NOTICE, "RESET from SMLC: %s\n", osmo_sccp_addr_name(ss7, smlc_addr));
		return osmo_fsm_inst_dispatch(bsc_gsmnet->smlc->bssmap_reset->fi, BSSMAP_RESET_EV_RX_RESET, NULL);

	case BSSMAP_LE_MSGT_RESET_ACK:
		rate_ctr_inc(&ctr[SMLC_CTR_BSSMAP_LE_RX_UDT_RESET_ACK]);
		LOGP(DLCS, LOGL_NOTICE, "RESET-ACK from SMLC: %s\n", osmo_sccp_addr_name(ss7, smlc_addr));
		return osmo_fsm_inst_dispatch(bsc_gsmnet->smlc->bssmap_reset->fi, BSSMAP_RESET_EV_RX_RESET_ACK, NULL);

	default:
		rate_ctr_inc(&ctr[SMLC_CTR_BSSMAP_LE_RX_UDT_ERR_INVALID_MSG]);
		LOGP(DLCS, LOGL_ERROR, "Rx unimplemented UDT message type %s\n",
		     osmo_bssap_le_pdu_to_str_c(OTC_SELECT, &bssap_le));
		return -EINVAL;
	}
}

static int sccp_sap_up(struct osmo_prim_hdr *oph, void *_scu)
{
	struct osmo_scu_prim *scu_prim = (struct osmo_scu_prim *)oph;
	struct osmo_sccp_user *scu = _scu;
	struct gsm_subscriber_connection *conn;
	int rc = 0;

	switch (OSMO_PRIM_HDR(&scu_prim->oph)) {
	case OSMO_PRIM(OSMO_SCU_PRIM_N_UNITDATA, PRIM_OP_INDICATION):
		/* Handle inbound UnitData */
		DEBUGP(DLCS, "N-UNITDATA.ind(%s)\n", osmo_hexdump(msgb_l2(oph->msg), msgb_l2len(oph->msg)));
		rc = handle_unitdata_from_smlc(&scu_prim->u.unitdata.calling_addr, oph->msg, scu);
		break;

	case OSMO_PRIM(OSMO_SCU_PRIM_N_CONNECT, PRIM_OP_INDICATION):
		/* Handle inbound connections. A Location Request is always started on the A interface, and OsmoBSC
		 * forwards this to the SMLC by performing an N-CONNECT from BSC -> SMLC. This is the reverse
		 * direction: N-CONNECT from SMLC -> BSC, which should never happen. */
		LOGP(DLCS, LOGL_ERROR, "N-CONNECT.ind(X->%u): inbound connect from SMLC is not expected to happen\n",
		     scu_prim->u.connect.conn_id);
		rc = osmo_sccp_tx_disconn(scu, scu_prim->u.connect.conn_id, &scu_prim->u.connect.called_addr, 0);
		break;

	case OSMO_PRIM(OSMO_SCU_PRIM_N_CONNECT, PRIM_OP_CONFIRM):
		/* Handle inbound confirmation of outbound connection */
		DEBUGP(DLCS, "N-CONNECT.cnf(%u)\n", scu_prim->u.connect.conn_id);
		conn = get_bsc_conn_by_lb_conn_id(scu_prim->u.connect.conn_id);
		if (conn) {
			conn->lcs.lb.state = SUBSCR_SCCP_ST_CONNECTED;
			if (msgb_l2len(oph->msg) > 0) {
				rc = lcs_loc_req_rx_bssmap_le(conn, oph->msg);
			}
		} else {
			LOGP(DLCS, LOGL_ERROR, "N-CONNECT.cfm(%u) for unknown conn\n", scu_prim->u.connect.conn_id);
			rc = -EINVAL;
		}
		break;

	case OSMO_PRIM(OSMO_SCU_PRIM_N_DATA, PRIM_OP_INDICATION):
		/* Handle incoming connection oriented data */
		DEBUGP(DLCS, "N-DATA.ind(%u)\n", scu_prim->u.data.conn_id);

		conn = get_bsc_conn_by_lb_conn_id(scu_prim->u.data.conn_id);
		if (!conn) {
			LOGP(DLCS, LOGL_ERROR, "N-DATA.ind(%u) for unknown conn_id\n", scu_prim->u.data.conn_id);
			rc = -EINVAL;
		} else if (conn->lcs.lb.state != SUBSCR_SCCP_ST_CONNECTED) {
			LOGP(DLCS, LOGL_ERROR, "N-DATA.ind(%u) for conn that is not confirmed\n",
			     scu_prim->u.data.conn_id);
			rc = -EINVAL;
		} else {
			rc = lcs_loc_req_rx_bssmap_le(conn, oph->msg);
		}
		break;

	case OSMO_PRIM(OSMO_SCU_PRIM_N_DISCONNECT, PRIM_OP_INDICATION):
		DEBUGP(DLCS, "N-DISCONNECT.ind(%u, %s, cause=%i)\n", scu_prim->u.disconnect.conn_id,
		       osmo_hexdump(msgb_l2(oph->msg), msgb_l2len(oph->msg)),
		       scu_prim->u.disconnect.cause);
		/* indication of disconnect */
		conn = get_bsc_conn_by_lb_conn_id(scu_prim->u.disconnect.conn_id);
		if (!conn) {
			LOGP(DLCS, LOGL_ERROR, "N-DISCONNECT.ind for unknown conn_id %u\n",
			     scu_prim->u.disconnect.conn_id);
			rc = -EINVAL;
		} else {
			conn->lcs.lb.state = SUBSCR_SCCP_ST_NONE;
			if (msgb_l2len(oph->msg) > 0) {
				rc = lcs_loc_req_rx_bssmap_le(conn, oph->msg);
			}
		}
		break;

	default:
		LOGP(DLCS, LOGL_ERROR, "Unhandled SIGTRAN operation %s on primitive %u\n",
		     get_value_string(osmo_prim_op_names, oph->operation), oph->primitive);
		break;
	}

	msgb_free(oph->msg);
	return rc;
}

static int lb_open_conn(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	struct osmo_ss7_instance *ss7;
	int conn_id;
	int rc;

	OSMO_ASSERT(conn);
	OSMO_ASSERT(msg);

	if (conn->lcs.lb.state != SUBSCR_SCCP_ST_NONE) {
		LOGPFSMSL(conn->fi, DLCS, LOGL_ERROR,
			  "Cannot open BSSMAP-LE conn to SMLC, another conn is still active for this subscriber\n");
		return -EINVAL;
	}

	conn_id = bsc_sccp_inst_next_conn_id(bsc_gsmnet->smlc->sccp);
	if (conn_id < 0) {
		LOGPFSMSL(conn->fi, DLCS, LOGL_ERROR, "Unable to allocate SCCP Connection ID for BSSMAP-LE to SMLC\n");
		return -ENOSPC;
	}
	conn->lcs.lb.conn_id = conn_id;
	ss7 = osmo_ss7_instance_find(bsc_gsmnet->smlc->cs7_instance);
	OSMO_ASSERT(ss7);
	LOGPFSMSL(conn->fi, DLCS, LOGL_INFO, "Opening new SCCP connection (id=%i) to SMLC: %s\n", conn_id,
		  osmo_sccp_addr_name(ss7, &bsc_gsmnet->smlc->smlc_addr));

	rc = osmo_sccp_tx_conn_req_msg(bsc_gsmnet->smlc->sccp_user, conn_id, &bsc_gsmnet->smlc->bsc_addr,
				       &bsc_gsmnet->smlc->smlc_addr, msg);
	if (rc >= 0)
		rate_ctr_inc(&bsc_gsmnet->smlc->ctrs->ctr[SMLC_CTR_BSSMAP_LE_TX_SUCCESS]);
	else
		rate_ctr_inc(&bsc_gsmnet->smlc->ctrs->ctr[SMLC_CTR_BSSMAP_LE_TX_ERR_SEND]);
	if (rc >= 0)
		conn->lcs.lb.state = SUBSCR_SCCP_ST_WAIT_CONN_CONF;

	return rc;
}

void lb_close_conn(struct gsm_subscriber_connection *conn)
{
	if (conn->lcs.lb.state == SUBSCR_SCCP_ST_NONE)
		return;
	osmo_sccp_tx_disconn(bsc_gsmnet->smlc->sccp_user, conn->lcs.lb.conn_id, &bsc_gsmnet->smlc->bsc_addr, 0);
	conn->lcs.lb.state = SUBSCR_SCCP_ST_NONE;
}

/* Send data to SMLC, take ownership of *msg */
int lb_send(struct gsm_subscriber_connection *conn, const struct bssap_le_pdu *bssap_le)
{
	int rc;
	struct msgb *msg;

	OSMO_ASSERT(conn);

	if (!bssmap_reset_is_conn_ready(bsc_gsmnet->smlc->bssmap_reset)) {
		LOGPFSMSL(conn->fi, DLCS, LOGL_ERROR, "Lb link to SMLC is not ready (no RESET-ACK), cannot send %s\n",
			  osmo_bssap_le_pdu_to_str_c(OTC_SELECT, bssap_le));
		/* If the remote side was lost, make sure that the SCCP conn is discarded in the local state and towards
		 * the STP. */
		lb_close_conn(conn);
		return -EINVAL;
	}

	msg = osmo_bssap_le_enc(bssap_le);
	if (!msg) {
		LOGPFSMSL(conn->fi, DLCS, LOGL_ERROR, "Failed to encode %s\n",
			  osmo_bssap_le_pdu_to_str_c(OTC_SELECT, bssap_le));
		return -EINVAL;
	}

	if (conn->lcs.lb.state == SUBSCR_SCCP_ST_NONE) {
		rc = lb_open_conn(conn, msg);
		goto count_tx;
	}

	LOGPFSMSL(conn->fi, DLCS, LOGL_DEBUG, "Tx %s\n", osmo_bssap_le_pdu_to_str_c(OTC_SELECT, bssap_le));
	rc = osmo_sccp_tx_data_msg(bsc_gsmnet->smlc->sccp_user, conn->lcs.lb.conn_id, msg);
	if (rc >= 0)
		rate_ctr_inc(&bsc_gsmnet->smlc->ctrs->ctr[SMLC_CTR_BSSMAP_LE_TX_SUCCESS]);
	else
		rate_ctr_inc(&bsc_gsmnet->smlc->ctrs->ctr[SMLC_CTR_BSSMAP_LE_TX_ERR_SEND]);

count_tx:
	if (rc < 0)
		return rc;

	switch (bssap_le->bssmap_le.msg_type) {
	case BSSMAP_LE_MSGT_PERFORM_LOC_REQ:
		rate_ctr_inc(&bsc_gsmnet->smlc->ctrs->ctr[SMLC_CTR_BSSMAP_LE_TX_DT1_PERFORM_LOCATION_REQUEST]);
		break;
	case BSSMAP_LE_MSGT_PERFORM_LOC_ABORT:
		rate_ctr_inc(&bsc_gsmnet->smlc->ctrs->ctr[SMLC_CTR_BSSMAP_LE_TX_DT1_PERFORM_LOCATION_ABORT]);
		break;
	case BSSMAP_LE_MSGT_CONN_ORIENTED_INFO:
		switch (bssap_le->bssmap_le.conn_oriented_info.apdu.msg_type) {
		case BSSLAP_MSGT_TA_RESPONSE:
			rate_ctr_inc(&bsc_gsmnet->smlc->ctrs->ctr[SMLC_CTR_BSSMAP_LE_TX_DT1_BSSLAP_TA_RESPONSE]);
			break;
		case BSSLAP_MSGT_REJECT:
			rate_ctr_inc(&bsc_gsmnet->smlc->ctrs->ctr[SMLC_CTR_BSSMAP_LE_TX_DT1_BSSLAP_REJECT]);
			break;
		case BSSLAP_MSGT_RESET:
			rate_ctr_inc(&bsc_gsmnet->smlc->ctrs->ctr[SMLC_CTR_BSSMAP_LE_TX_DT1_BSSLAP_RESET]);
			break;
		case BSSLAP_MSGT_ABORT:
			rate_ctr_inc(&bsc_gsmnet->smlc->ctrs->ctr[SMLC_CTR_BSSMAP_LE_TX_DT1_BSSLAP_ABORT]);
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}
	return 0;
}

/* Default point-code to be used as local address (BSC) */
#define BSC_DEFAULT_PC "0.23.3"

/* Default point-code to be used as remote address (SMLC) */
#define SMLC_DEFAULT_PC "0.23.6"

#define DEFAULT_ASP_LOCAL_IP "localhost"
#define DEFAULT_ASP_REMOTE_IP "localhost"

void lb_cancel_all()
{
	struct gsm_subscriber_connection *conn;
	llist_for_each_entry(conn, &bsc_gsmnet->subscr_conns, entry)
		lcs_loc_req_reset(conn);
};

void lb_reset_link_up(void *data)
{
	LOGP(DLCS, LOGL_INFO, "Lb link ready\n");
}

void lb_reset_link_lost(void *data)
{
	struct gsm_subscriber_connection *conn;
	LOGP(DLCS, LOGL_INFO, "Lb link down\n");

	/* Abort all ongoing Location Requests */
	llist_for_each_entry(conn, &bsc_gsmnet->subscr_conns, entry)
		lcs_loc_req_reset(conn);
};

void lb_reset_tx_reset(void *data)
{
	bssmap_le_tx_reset();
}

void lb_reset_tx_reset_ack(void *data)
{
	bssmap_le_tx_reset_ack();
}

static void lb_start_reset_fsm()
{
	struct bssmap_reset_cfg cfg = {
		.conn_cfm_failure_threshold = 3,
		.ops = {
			.tx_reset = lb_reset_tx_reset,
			.tx_reset_ack = lb_reset_tx_reset_ack,
			.link_up = lb_reset_link_up,
			.link_lost = lb_reset_link_lost,
		},
	};

	if (bsc_gsmnet->smlc->bssmap_reset) {
		LOGP(DLCS, LOGL_ERROR, "will not allocate a second reset FSM for Lb\n");
		return;
	}

	bsc_gsmnet->smlc->bssmap_reset = bssmap_reset_alloc(bsc_gsmnet, "Lb", &cfg);
}

static int lb_start()
{
	uint32_t default_pc;
	struct osmo_ss7_instance *cs7_inst = NULL;
	struct osmo_sccp_instance *sccp;
	enum osmo_ss7_asp_protocol used_proto = OSMO_SS7_ASP_PROT_M3UA;
	char inst_name[32];
	const char *smlc_name = "smlc";

	/* Already set up? */
	if (bsc_gsmnet->smlc->sccp_user)
		return -EALREADY;

	LOGP(DLCS, LOGL_INFO, "Starting Lb link\n");

	if (!bsc_gsmnet->smlc->cs7_instance_valid) {
		bsc_gsmnet->smlc->cs7_instance = 0;
	}
	cs7_inst = osmo_ss7_instance_find_or_create(tall_bsc_ctx, bsc_gsmnet->smlc->cs7_instance);
	OSMO_ASSERT(cs7_inst);

	/* If unset, use default SCCP address for the SMLC */
	if (!bsc_gsmnet->smlc->smlc_addr.presence)
		osmo_sccp_make_addr_pc_ssn(&bsc_gsmnet->smlc->smlc_addr,
					   osmo_ss7_pointcode_parse(NULL, SMLC_DEFAULT_PC),
					   OSMO_SCCP_SSN_SMLC_BSSAP_LE);

	/* Set up SCCP user and one ASP+AS */
	snprintf(inst_name, sizeof(inst_name), "Lb-%u-%s", cs7_inst->cfg.id, osmo_ss7_asp_protocol_name(used_proto));
	LOGP(DLCS, LOGL_NOTICE, "Initializing SCCP connection for Lb/%s on cs7 instance %u\n",
	     osmo_ss7_asp_protocol_name(used_proto), cs7_inst->cfg.id);

	/* SS7 Protocol stack */
	default_pc = osmo_ss7_pointcode_parse(NULL, BSC_DEFAULT_PC);
	sccp = osmo_sccp_simple_client_on_ss7_id(tall_bsc_ctx, cs7_inst->cfg.id, inst_name,
						 default_pc, used_proto,
						 0, DEFAULT_ASP_LOCAL_IP,
						 0, DEFAULT_ASP_REMOTE_IP);
	if (!sccp)
		return -EINVAL;
	bsc_gsmnet->smlc->sccp = sccp;

	/* If unset, use default local SCCP address */
	if (!bsc_gsmnet->smlc->bsc_addr.presence)
		osmo_sccp_local_addr_by_instance(&bsc_gsmnet->smlc->bsc_addr, sccp,
						 OSMO_SCCP_SSN_BSC_BSSAP_LE);

	if (!osmo_sccp_check_addr(&bsc_gsmnet->smlc->bsc_addr, OSMO_SCCP_ADDR_T_SSN | OSMO_SCCP_ADDR_T_PC)) {
		LOGP(DLCS, LOGL_ERROR,
		     "%s %s: invalid local (BSC) SCCP address: %s\n",
		     inst_name, smlc_name, osmo_sccp_inst_addr_name(sccp, &bsc_gsmnet->smlc->bsc_addr));
		return -EINVAL;
	}

	if (!osmo_sccp_check_addr(&bsc_gsmnet->smlc->smlc_addr, OSMO_SCCP_ADDR_T_SSN | OSMO_SCCP_ADDR_T_PC)) {
		LOGP(DLCS, LOGL_ERROR,
		     "%s %s: invalid remote (SMLC) SCCP address: %s\n",
		     inst_name, smlc_name, osmo_sccp_inst_addr_name(sccp, &bsc_gsmnet->smlc->smlc_addr));
		return -EINVAL;
	}

	LOGP(DLCS, LOGL_NOTICE, "Lb: %s %s: local (BSC) SCCP address: %s\n",
	     inst_name, smlc_name, osmo_sccp_inst_addr_name(sccp, &bsc_gsmnet->smlc->bsc_addr));
	LOGP(DLCS, LOGL_NOTICE, "Lb: %s %s: remote (SMLC) SCCP address: %s\n",
	     inst_name, smlc_name, osmo_sccp_inst_addr_name(sccp, &bsc_gsmnet->smlc->smlc_addr));

	/* Bind SCCP user. */
	bsc_gsmnet->smlc->sccp_user = osmo_sccp_user_find(sccp, bsc_gsmnet->smlc->bsc_addr.ssn, bsc_gsmnet->smlc->bsc_addr.pc);
	LOGP(DLCS, LOGL_NOTICE, "%s %s: %s\n", inst_name, smlc_name,
	     bsc_gsmnet->smlc->sccp_user ? "user already bound for this SCCP instance" : "binding SCCP user");
	if (!bsc_gsmnet->smlc->sccp_user)
		bsc_gsmnet->smlc->sccp_user = osmo_sccp_user_bind(sccp, smlc_name, sccp_sap_up, bsc_gsmnet->smlc->bsc_addr.ssn);
	if (!bsc_gsmnet->smlc->sccp_user)
		return -EINVAL;

	lb_start_reset_fsm();
	return 0;
}

static int lb_stop()
{
	/* Not set up? */
	if (!bsc_gsmnet->smlc->sccp_user)
		return -EALREADY;

	LOGP(DLCS, LOGL_INFO, "Shutting down Lb link\n");

	lb_cancel_all();
	osmo_sccp_user_unbind(bsc_gsmnet->smlc->sccp_user);
	bsc_gsmnet->smlc->sccp_user = NULL;
	return 0;
}

int lb_start_or_stop()
{
	int rc;
	if (bsc_gsmnet->smlc->enable) {
		rc = lb_start();
		switch (rc) {
		case 0:
			/* all is fine */
			break;
		case -EALREADY:
			/* no need to log about anything */
			break;
		default:
			LOGP(DLCS, LOGL_ERROR, "Failed to start Lb interface (rc=%d)\n", rc);
			break;
		}
	} else {
		rc = lb_stop();
		switch (rc) {
		case 0:
			/* all is fine */
			break;
		case -EALREADY:
			/* no need to log about anything */
			break;
		default:
			LOGP(DLCS, LOGL_ERROR, "Failed to stop Lb interface (rc=%d)\n", rc);
			break;
		}
	}
	return rc;
}

static void smlc_vty_init(void);

int lb_init()
{
	OSMO_ASSERT(!bsc_gsmnet->smlc);
	bsc_gsmnet->smlc = talloc_zero(bsc_gsmnet, struct smlc_config);
	OSMO_ASSERT(bsc_gsmnet->smlc);
	bsc_gsmnet->smlc->ctrs = rate_ctr_group_alloc(bsc_gsmnet, &smlc_ctrg_desc, 0);

	smlc_vty_init();
	return 0;
}

/*********************************************************************************
 * VTY Interface (Configuration + Introspection)
 *********************************************************************************/

DEFUN(cfg_smlc, cfg_smlc_cmd,
	"smlc", "Configure Lb Link to Serving Mobile Location Centre\n")
{
	vty->node = SMLC_NODE;
	return CMD_SUCCESS;
}

static struct cmd_node smlc_node = {
	SMLC_NODE,
	"%s(config-smlc)# ",
	1,
};

DEFUN(cfg_smlc_enable, cfg_smlc_enable_cmd,
	"enable",
	"Start up Lb interface connection to the remote SMLC\n")
{
	bsc_gsmnet->smlc->enable = true;
	if (vty->type != VTY_FILE) {
		if (lb_start_or_stop())
			vty_out(vty, "%% Error: failed to enable Lb interface%s", VTY_NEWLINE);
	}
	return CMD_SUCCESS;
}

DEFUN(cfg_smlc_no_enable, cfg_smlc_no_enable_cmd,
	"no enable",
	NO_STR "Stop Lb interface connection to the remote SMLC\n")
{
	bsc_gsmnet->smlc->enable = false;
	if (vty->type != VTY_FILE) {
		if (lb_start_or_stop())
			vty_out(vty, "%% Error: failed to disable Lb interface%s", VTY_NEWLINE);
	}
	return CMD_SUCCESS;
}

static void enforce_ssn(struct vty *vty, struct osmo_sccp_addr *addr, enum osmo_sccp_ssn want_ssn)
{
	if (addr->presence & OSMO_SCCP_ADDR_T_SSN) {
		if (addr->ssn != want_ssn)
			vty_out(vty,
				"setting an SSN (%u) different from the standard (%u) is not allowed, will use standard SSN for address: %s%s",
				addr->ssn, want_ssn, osmo_sccp_addr_dump(addr), VTY_NEWLINE);
	}

	addr->presence |= OSMO_SCCP_ADDR_T_SSN;
	addr->ssn = want_ssn;
}

DEFUN(cfg_smlc_cs7_bsc_addr,
      cfg_smlc_cs7_bsc_addr_cmd,
      "bsc-addr NAME",
      "Local SCCP address of this BSC towards the SMLC\n" "Name of cs7 addressbook entry\n")
{
	const char *bsc_addr_name = argv[0];
	struct osmo_ss7_instance *ss7;

	ss7 = osmo_sccp_addr_by_name(&bsc_gsmnet->smlc->bsc_addr, bsc_addr_name);
	if (!ss7) {
		vty_out(vty, "Error: No such SCCP addressbook entry: '%s'%s", bsc_addr_name, VTY_NEWLINE);
		return CMD_ERR_INCOMPLETE;
	}

	/* Prevent mixing addresses from different CS7 instances */
	if (bsc_gsmnet->smlc->cs7_instance_valid
	    && bsc_gsmnet->smlc->cs7_instance != ss7->cfg.id) {
		vty_out(vty,
			"Error: SCCP addressbook entry from mismatching CS7 instance: '%s'%s",
			bsc_addr_name, VTY_NEWLINE);
		return CMD_WARNING;
	}

	bsc_gsmnet->smlc->cs7_instance = ss7->cfg.id;
	bsc_gsmnet->smlc->cs7_instance_valid = true;
	enforce_ssn(vty, &bsc_gsmnet->smlc->bsc_addr, OSMO_SCCP_SSN_BSC_BSSAP_LE);
	bsc_gsmnet->smlc->bsc_addr_name = talloc_strdup(bsc_gsmnet, bsc_addr_name);
	return CMD_SUCCESS;
}

DEFUN(cfg_smlc_cs7_smlc_addr,
      cfg_smlc_cs7_smlc_addr_cmd,
      "smlc-addr NAME",
      "Remote SCCP address of the SMLC\n" "Name of cs7 addressbook entry\n")
{
	const char *smlc_addr_name = argv[0];
	struct osmo_ss7_instance *ss7;

	ss7 = osmo_sccp_addr_by_name(&bsc_gsmnet->smlc->smlc_addr, smlc_addr_name);
	if (!ss7) {
		vty_out(vty, "Error: No such SCCP addressbook entry: '%s'%s", smlc_addr_name, VTY_NEWLINE);
		return CMD_ERR_INCOMPLETE;
	}

	/* Prevent mixing addresses from different CS7/SS7 instances */
	if (bsc_gsmnet->smlc->cs7_instance_valid) {
		if (bsc_gsmnet->smlc->cs7_instance != ss7->cfg.id) {
			vty_out(vty,
				"Error: SCCP addressbook entry from mismatching CS7 instance: '%s'%s",
				smlc_addr_name, VTY_NEWLINE);
			return CMD_ERR_INCOMPLETE;
		}
	}

	bsc_gsmnet->smlc->cs7_instance = ss7->cfg.id;
	bsc_gsmnet->smlc->cs7_instance_valid = true;
	enforce_ssn(vty, &bsc_gsmnet->smlc->smlc_addr, OSMO_SCCP_SSN_SMLC_BSSAP_LE);
	bsc_gsmnet->smlc->smlc_addr_name = talloc_strdup(bsc_gsmnet, smlc_addr_name);
	return CMD_SUCCESS;
}

static int config_write_smlc(struct vty *vty)
{
	/* Nothing to write? */
	if (!(bsc_gsmnet->smlc->enable
	      || bsc_gsmnet->smlc->bsc_addr_name
	      || bsc_gsmnet->smlc->smlc_addr_name))
		return 0;

	vty_out(vty, "smlc%s", VTY_NEWLINE);

	if (bsc_gsmnet->smlc->enable)
		vty_out(vty, " enable%s", VTY_NEWLINE);

	if (bsc_gsmnet->smlc->bsc_addr_name) {
		vty_out(vty, " bsc-addr %s%s",
			bsc_gsmnet->smlc->bsc_addr_name, VTY_NEWLINE);
	}
	if (bsc_gsmnet->smlc->smlc_addr_name) {
		vty_out(vty, " smlc-addr %s%s",
			bsc_gsmnet->smlc->smlc_addr_name, VTY_NEWLINE);
	}

	return 0;
}

DEFUN(show_smlc, show_smlc_cmd,
	"show smlc",
	SHOW_STR "Display state of SMLC / Lb\n")
{
	vty_out(vty, "not implemented%s", VTY_NEWLINE);
	return CMD_SUCCESS;
}

void smlc_vty_init(void)
{
	install_element_ve(&show_smlc_cmd);

	install_element(CONFIG_NODE, &cfg_smlc_cmd);
	install_node(&smlc_node, config_write_smlc);
	install_element(SMLC_NODE, &cfg_smlc_enable_cmd);
	install_element(SMLC_NODE, &cfg_smlc_no_enable_cmd);
	install_element(SMLC_NODE, &cfg_smlc_cs7_bsc_addr_cmd);
	install_element(SMLC_NODE, &cfg_smlc_cs7_smlc_addr_cmd);
}

const struct rate_ctr_desc smlc_ctr_description[] = {
	[SMLC_CTR_BSSMAP_LE_RX_UNKNOWN_PEER] = {
		"bssmap_le:rx:unknown_peer",
		"Number of received BSSMAP-LE messages from an unknown Calling SCCP address"
	},
	[SMLC_CTR_BSSMAP_LE_RX_UDT_RESET] = {
		"bssmap_le:rx:udt:reset:request",
		"Number of received BSSMAP-LE UDT RESET messages"
	},
	[SMLC_CTR_BSSMAP_LE_RX_UDT_RESET_ACK] = {
		"bssmap_le:rx:udt:reset:ack",
		"Number of received BSSMAP-LE UDT RESET ACKNOWLEDGE messages"
	},
	[SMLC_CTR_BSSMAP_LE_RX_UDT_ERR_INVALID_MSG] = {
		"bssmap_le:rx:udt:err:inval",
		"Number of received invalid BSSMAP-LE UDT messages"
	},
	[SMLC_CTR_BSSMAP_LE_RX_DT1_ERR_INVALID_MSG] = {
		"bssmap_le:rx:dt1:err:inval",
		"Number of received invalid BSSMAP-LE"
	},
	[SMLC_CTR_BSSMAP_LE_RX_DT1_PERFORM_LOCATION_RESPONSE_SUCCESS] = {
		"bssmap_le:rx:dt1:location:response_success",
		"Number of received BSSMAP-LE Perform Location Response messages containing a location estimate"
	},
	[SMLC_CTR_BSSMAP_LE_RX_DT1_PERFORM_LOCATION_RESPONSE_FAILURE] = {
		"bssmap_le:rx:dt1:location:response_failure",
		"Number of received BSSMAP-LE Perform Location Response messages containing a failure cause"
	},

	[SMLC_CTR_BSSMAP_LE_TX_ERR_INVALID_MSG] = {
		"bssmap_le:tx:err:inval",
		"Number of outgoing BSSMAP-LE messages that are invalid (a bug?)"
	},
	[SMLC_CTR_BSSMAP_LE_TX_ERR_CONN_NOT_READY] = {
		"bssmap_le:tx:err:conn_not_ready",
		"Number of BSSMAP-LE messages we tried to send when the connection was not ready yet"
	},
	[SMLC_CTR_BSSMAP_LE_TX_ERR_SEND] = {
		"bssmap_le:tx:err:send",
		"Number of socket errors while sending BSSMAP-LE messages"
	},
	[SMLC_CTR_BSSMAP_LE_TX_SUCCESS] = {
		"bssmap_le:tx:success",
		"Number of successfully sent BSSMAP-LE messages"
	},

	[SMLC_CTR_BSSMAP_LE_TX_UDT_RESET] = {
		"bssmap_le:tx:udt:reset:request",
		"Number of transmitted BSSMAP-LE UDT RESET messages"
	},
	[SMLC_CTR_BSSMAP_LE_TX_UDT_RESET_ACK] = {
		"bssmap_le:tx:udt:reset:ack",
		"Number of transmitted BSSMAP-LE UDT RESET ACK messages"
	},
	[SMLC_CTR_BSSMAP_LE_TX_DT1_PERFORM_LOCATION_REQUEST] = {
		"bssmap_le:tx:dt1:location:response",
		"Number of transmitted BSSMAP-LE DT1 Perform Location Request messages"
	},
	[SMLC_CTR_BSSMAP_LE_TX_DT1_PERFORM_LOCATION_ABORT] = {
		"bssmap_le:rx:dt1:location:abort",
		"Number of received BSSMAP-LE Perform Location Abort messages"
	},

	[SMLC_CTR_BSSMAP_LE_RX_DT1_BSSLAP_TA_REQUEST] = {
		"bssmap_le:rx:dt1:bsslap:ta_request",
		"Number of received BSSMAP-LE Connection Oriented Information messages"
		" with BSSLAP APDU containing TA Request"
	},

	[SMLC_CTR_BSSMAP_LE_TX_DT1_BSSLAP_TA_RESPONSE] = {
		"bssmap_le:tx:dt1:bsslap:ta_response",
		"Number of sent BSSMAP-LE Connection Oriented Information messages"
		" with BSSLAP APDU containing TA Response"
	},
	[SMLC_CTR_BSSMAP_LE_TX_DT1_BSSLAP_REJECT] = {
		"bssmap_le:tx:dt1:bsslap:reject",
		"Number of sent BSSMAP-LE Connection Oriented Information messages"
		" with BSSLAP APDU containing Reject"
	},
	[SMLC_CTR_BSSMAP_LE_TX_DT1_BSSLAP_RESET] = {
		"bssmap_le:tx:dt1:bsslap:reset",
		"Number of sent BSSMAP-LE Connection Oriented Information messages"
		" with BSSLAP APDU containing Reset"
	},
	[SMLC_CTR_BSSMAP_LE_TX_DT1_BSSLAP_ABORT] = {
		"bssmap_le:tx:dt1:bsslap:abort",
		"Number of sent BSSMAP-LE Connection Oriented Information messages"
		" with BSSLAP APDU containing Abort"
	},

};

const struct rate_ctr_group_desc smlc_ctrg_desc = {
	"smlc",
	"serving mobile location centre",
	OSMO_STATS_CLASS_GLOBAL,
	ARRAY_SIZE(smlc_ctr_description),
	smlc_ctr_description,
};
