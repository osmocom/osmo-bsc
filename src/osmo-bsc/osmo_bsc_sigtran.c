/* (C) 2017 by sysmocom s.f.m.c. GmbH, Author: Philipp Maier
 * (C) 2017-2018 by Harald Welte <laforge@gnumonks.org>
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

#include <osmocom/core/utils.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/fsm.h>
#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/gsm/gsm0808.h>
#include <osmocom/gsm/protocol/ipaccess.h>
#include <osmocom/core/msgb.h>
#include <osmocom/bsc/bsc_msc_data.h>
#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/osmo_bsc.h>
#include <osmocom/bsc/osmo_bsc_grace.h>
#include <osmocom/bsc/osmo_bsc_sigtran.h>
#include <osmocom/bsc/a_reset.h>
#include <osmocom/bsc/bsc_subscr_conn_fsm.h>
#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/bts.h>
#include <osmocom/bsc/paging.h>
#include <osmocom/bsc/bssmap_reset.h>
#include <osmocom/mgcp_client/mgcp_common.h>
#include <osmocom/netif/ipa.h>

/* A pointer to a list with all involved MSCs
 * (a copy of the pointer location submitted with osmo_bsc_sigtran_init() */
static struct llist_head *msc_list;

#define DEFAULT_ASP_LOCAL_IP "localhost"
#define DEFAULT_ASP_REMOTE_IP "localhost"

/* Patch regular BSSMAP RESET to add extra T to announce Osmux support (osmocom extension) */
static void _gsm0808_extend_announce_osmux(struct msgb *msg)
{
	OSMO_ASSERT(msg->l3h[1] == msgb_l3len(msg) - 2); /*TL not in len */
	msgb_put_u8(msg, GSM0808_IE_OSMO_OSMUX_SUPPORT);
	msg->l3h[1] = msgb_l3len(msg) - 2;
}

/* Send reset to MSC */
void osmo_bsc_sigtran_tx_reset(const struct bsc_msc_data *msc)
{
	struct osmo_ss7_instance *ss7;
	struct msgb *msg;

	ss7 = osmo_ss7_instance_find(msc->a.cs7_instance);
	OSMO_ASSERT(ss7);
	LOGP(DRESET, LOGL_INFO, "Sending RESET to MSC: %s\n", osmo_sccp_addr_name(ss7, &msc->a.msc_addr));
	msg = gsm0808_create_reset();

	if (msc_is_aoip(msc) && msc->use_osmux != OSMUX_USAGE_OFF)
		_gsm0808_extend_announce_osmux(msg);

	rate_ctr_inc(rate_ctr_group_get_ctr(msc->msc_ctrs, MSC_CTR_BSSMAP_TX_UDT_RESET));
	osmo_sccp_tx_unitdata_msg(msc->a.sccp_user, &msc->a.bsc_addr,
				  &msc->a.msc_addr, msg);
}

/* Send reset-ack to MSC */
void osmo_bsc_sigtran_tx_reset_ack(const struct bsc_msc_data *msc)
{
	struct osmo_ss7_instance *ss7;
	struct msgb *msg;
	OSMO_ASSERT(msc);

	ss7 = osmo_ss7_instance_find(msc->a.cs7_instance);
	OSMO_ASSERT(ss7);
	LOGP(DRESET, LOGL_NOTICE, "Sending RESET ACK to MSC: %s\n", osmo_sccp_addr_name(ss7, &msc->a.msc_addr));
	msg = gsm0808_create_reset_ack();

	if (msc_is_aoip(msc) && msc->use_osmux != OSMUX_USAGE_OFF)
		_gsm0808_extend_announce_osmux(msg);

	rate_ctr_inc(rate_ctr_group_get_ctr(msc->msc_ctrs, MSC_CTR_BSSMAP_TX_UDT_RESET_ACK));
	osmo_sccp_tx_unitdata_msg(msc->a.sccp_user, &msc->a.bsc_addr,
				  &msc->a.msc_addr, msg);
}

/* Find an MSC by its remote SCCP address */
static struct bsc_msc_data *get_msc_by_addr(const struct osmo_sccp_addr *msc_addr)
{
	struct bsc_msc_data *msc;
	llist_for_each_entry(msc, msc_list, entry) {
		if (memcmp(msc_addr, &msc->a.msc_addr, sizeof(*msc_addr)) == 0)
			return msc;
	}
	LOGP(DMSC, LOGL_ERROR, "Unable to find MSC data under address: %s\n",
	     osmo_sccp_addr_dump(msc_addr));
	return NULL;
}

/* Find an MSC by its remote sigtran point code on a given cs7 instance. */
static struct bsc_msc_data *get_msc_by_pc(struct osmo_ss7_instance *cs7, uint32_t pc)
{
	struct bsc_msc_data *msc;
	uint32_t cs7_id = osmo_ss7_instance_get_id(cs7);
	llist_for_each_entry(msc, msc_list, entry) {
		if (msc->a.cs7_instance != cs7_id)
			continue;
		if ((msc->a.msc_addr.presence & OSMO_SCCP_ADDR_T_PC) == 0)
			continue;
		if (msc->a.msc_addr.pc == pc)
			return msc;
	}
	return NULL;
}

/* Received data from MSC, use the connection id which MSC it is */
static int handle_data_from_msc(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	msg->l3h = msgb_l2(msg);
	return bsc_handle_dt(conn, msg, msgb_l2len(msg));
}

/* Received unitdata from MSC, use the point code to determine which MSC it is */
static int handle_unitdata_from_msc(const struct osmo_sccp_addr *msc_addr, struct msgb *msg,
				    const struct osmo_sccp_user *scu)
{
	struct osmo_ss7_instance *ss7;
	struct bsc_msc_data *msc = get_msc_by_addr(msc_addr);
	int rc = -EINVAL;

	if (msc) {
		msg->l3h = msgb_l2(msg);
		rc = bsc_handle_udt(msc, msg, msgb_l2len(msg));
	} else {
		ss7 = osmo_sccp_get_ss7(osmo_sccp_get_sccp(scu));
		OSMO_ASSERT(ss7);
		LOGP(DMSC, LOGL_NOTICE, "incoming unitdata data from unknown remote address: %s\n",
		     osmo_sccp_addr_name(ss7, msc_addr));
	}
	return rc;
}

static int handle_n_connect_from_msc(struct osmo_sccp_user *scu, struct osmo_scu_prim *scu_prim)
{
	struct bsc_msc_data *msc = get_msc_by_addr(&scu_prim->u.connect.calling_addr);
	struct osmo_sccp_instance *sccp = osmo_sccp_get_sccp(scu);
	struct bsc_sccp_inst *bsc_sccp = osmo_sccp_get_priv(sccp);
	struct gsm_subscriber_connection *conn;
	int rc = 0;

	conn = bsc_sccp_inst_get_gscon_by_conn_id(bsc_sccp, scu_prim->u.connect.conn_id);
	if (conn) {
		LOGP(DMSC, LOGL_NOTICE,
		     "(calling_addr=%s conn_id=%u) N-CONNECT.ind with already used conn_id, ignoring\n",
		     osmo_sccp_addr_dump(&scu_prim->u.connect.calling_addr),
		     scu_prim->u.connect.conn_id);
		/* The situation is illogical. A conn was already established with this conn id, if we
		 * would like to reply with a disconn onto this conn id, we would close the existing
		 * conn. So just ignore this impossible N-CONNECT completely (including the BSSMAP PDU). */
		return -EINVAL;
	}

	if (!msc) {
		LOGP(DMSC, LOGL_NOTICE, "(calling_addr=%s conn_id=%u) N-CONNECT.ind from unknown MSC\n",
		     osmo_sccp_addr_dump(&scu_prim->u.connect.calling_addr),
		     scu_prim->u.connect.conn_id);
		rc = -ENOENT;
		goto refuse;
	}

	LOGP(DMSC, LOGL_DEBUG, "(calling_addr=%s conn_id=%u) N-CONNECT.ind from MSC %d\n",
	     osmo_sccp_addr_dump(&scu_prim->u.connect.calling_addr),
	     scu_prim->u.connect.conn_id, msc->nr);

	conn = bsc_subscr_con_allocate(bsc_gsmnet);
	if (!conn)
		return -ENOMEM;
	conn->sccp.msc = msc;
	conn->sccp.conn.conn_id = scu_prim->u.connect.conn_id;
	if (bsc_sccp_inst_register_gscon(bsc_sccp, &conn->sccp.conn) < 0) {
		LOGP(DMSC, LOGL_NOTICE, "(calling_addr=%s conn_id=%u) N-CONNECT.ind failed registering conn\n",
		     osmo_sccp_addr_dump(&scu_prim->u.connect.calling_addr), scu_prim->u.connect.conn_id);
		osmo_fsm_inst_term(conn->fi, OSMO_FSM_TERM_REQUEST, NULL);
		rc = -ENOENT;
		goto refuse;
	}

	/* Take actions asked for by the enclosed PDU */
	osmo_fsm_inst_dispatch(conn->fi, GSCON_EV_A_CONN_IND, scu_prim);

	return 0;
refuse:
	osmo_sccp_tx_disconn(scu, scu_prim->u.connect.conn_id, &scu_prim->u.connect.called_addr, 0);
	return rc;
}

static void handle_pcstate_ind(struct osmo_ss7_instance *cs7, const struct osmo_scu_pcstate_param *pcst)
{
	struct bsc_msc_data *msc;
	bool connected;
	bool disconnected;

	LOGP(DMSC, LOGL_DEBUG, "N-PCSTATE ind: affected_pc=%u=%s sp_status=%s remote_sccp_status=%s\n",
	     pcst->affected_pc, osmo_ss7_pointcode_print(cs7, pcst->affected_pc),
	     osmo_sccp_sp_status_name(pcst->sp_status),
	     osmo_sccp_rem_sccp_status_name(pcst->remote_sccp_status));

	/* If we don't care about that point-code, ignore PCSTATE. */
	msc = get_msc_by_pc(cs7, pcst->affected_pc);
	if (!msc)
		return;

	/* See if this marks the point code to have become available, or to have been lost.
	 *
	 * I want to detect two events:
	 * - connection event (both indicators say PC is reachable).
	 * - disconnection event (at least one indicator says the PC is not reachable).
	 *
	 * There are two separate incoming indicators with various possible values -- the incoming events can be:
	 *
	 * - neither connection nor disconnection indicated -- just indicating congestion
	 *   connected == false, disconnected == false --> do nothing.
	 * - both incoming values indicate that we are connected
	 *   --> trigger connected
	 * - both indicate we are disconnected
	 *   --> trigger disconnected
	 * - one value indicates 'connected', the other indicates 'disconnected'
	 *   --> trigger disconnected
	 *
	 * Congestion could imply that we're connected, but it does not indicate that a PC's reachability changed, so no need to
	 * trigger on that.
	 */
	connected = false;
	disconnected = false;

	switch (pcst->sp_status) {
	case OSMO_SCCP_SP_S_ACCESSIBLE:
		connected = true;
		break;
	case OSMO_SCCP_SP_S_INACCESSIBLE:
		disconnected = true;
		break;
	default:
	case OSMO_SCCP_SP_S_CONGESTED:
		/* Neither connecting nor disconnecting */
		break;
	}

	switch (pcst->remote_sccp_status) {
	case OSMO_SCCP_REM_SCCP_S_AVAILABLE:
		if (!disconnected)
			connected = true;
		break;
	case OSMO_SCCP_REM_SCCP_S_UNAVAILABLE_UNKNOWN:
	case OSMO_SCCP_REM_SCCP_S_UNEQUIPPED:
	case OSMO_SCCP_REM_SCCP_S_INACCESSIBLE:
		disconnected = true;
		connected = false;
		break;
	default:
	case OSMO_SCCP_REM_SCCP_S_CONGESTED:
		/* Neither connecting nor disconnecting */
		break;
	}

	if (disconnected && a_reset_conn_ready(msc)) {
		LOGP(DMSC, LOGL_NOTICE,
		     "(msc%d) now unreachable: N-PCSTATE ind: pc=%u=%s sp_status=%s remote_sccp_status=%s\n",
		     msc->nr, pcst->affected_pc, osmo_ss7_pointcode_print(cs7, pcst->affected_pc),
		     osmo_sccp_sp_status_name(pcst->sp_status),
		     osmo_sccp_rem_sccp_status_name(pcst->remote_sccp_status));
		/* A previously usable MSC has disconnected. Kick the BSSMAP back to DISC state. */
		bssmap_reset_set_disconnected(msc->a.bssmap_reset);
	} else if (connected && !a_reset_conn_ready(msc)) {
		LOGP(DMSC, LOGL_NOTICE,
		     "(msc%d) now available: N-PCSTATE ind: pc=%u=%s sp_status=%s remote_sccp_status=%s\n",
		     msc->nr, pcst->affected_pc, osmo_ss7_pointcode_print(cs7, pcst->affected_pc),
		     osmo_sccp_sp_status_name(pcst->sp_status),
		     osmo_sccp_rem_sccp_status_name(pcst->remote_sccp_status));
		/* A previously unusable MSC has become reachable. Trigger immediate BSSMAP RESET -- we would resend a
		 * RESET either way, but we might as well do it now to speed up connecting. */
		bssmap_reset_resend_reset(msc->a.bssmap_reset);
	}
}

/* Callback function, called by the SCCP stack when data arrives */
static int sccp_sap_up(struct osmo_prim_hdr *oph, void *_scu)
{
	struct osmo_scu_prim *scu_prim = (struct osmo_scu_prim *)oph;
	struct osmo_sccp_user *scu = _scu;
	struct osmo_sccp_instance *sccp = osmo_sccp_get_sccp(scu);
	struct bsc_sccp_inst *bsc_sccp = osmo_sccp_get_priv(sccp);
	struct gsm_subscriber_connection *conn;
	int rc = 0;

	switch (OSMO_PRIM_HDR(&scu_prim->oph)) {
	case OSMO_PRIM(OSMO_SCU_PRIM_N_UNITDATA, PRIM_OP_INDICATION):
		/* Handle inbound UNITDATA */
		DEBUGP(DMSC, "N-UNITDATA.ind(%s)\n", osmo_hexdump(msgb_l2(oph->msg), msgb_l2len(oph->msg)));
		rc = handle_unitdata_from_msc(&scu_prim->u.unitdata.calling_addr, oph->msg, scu);
		break;

	case OSMO_PRIM(OSMO_SCU_PRIM_N_CONNECT, PRIM_OP_INDICATION):
		/* Handle inbound connections */
		DEBUGP(DMSC, "N-CONNECT.ind(X->%u)\n", scu_prim->u.connect.conn_id);
		rc = handle_n_connect_from_msc(scu, scu_prim);
		break;

	case OSMO_PRIM(OSMO_SCU_PRIM_N_CONNECT, PRIM_OP_CONFIRM):
		/* Handle outbound connection confirmation */
		DEBUGP(DMSC, "N-CONNECT.cnf(%u, %s)\n", scu_prim->u.connect.conn_id,
		       osmo_hexdump(msgb_l2(oph->msg), msgb_l2len(oph->msg)));
		conn = bsc_sccp_inst_get_gscon_by_conn_id(bsc_sccp, scu_prim->u.connect.conn_id);
		if (conn) {
			osmo_fsm_inst_dispatch(conn->fi, GSCON_EV_A_CONN_CFM, scu_prim);
			conn->sccp.state = SUBSCR_SCCP_ST_CONNECTED;
			if (msgb_l2len(oph->msg) > 0)
				handle_data_from_msc(conn, oph->msg);
		} else {
			LOGP(DMSC, LOGL_ERROR, "N-CONNECT.cfm(%u, %s) for unknown conn?!?\n",
				scu_prim->u.connect.conn_id, osmo_hexdump(msgb_l2(oph->msg),
				msgb_l2len(oph->msg)));
		}
		break;

	case OSMO_PRIM(OSMO_SCU_PRIM_N_DATA, PRIM_OP_INDICATION):
		/* Handle incoming connection oriented data */
		DEBUGP(DMSC, "N-DATA.ind(%u, %s)\n", scu_prim->u.data.conn_id,
		       osmo_hexdump(msgb_l2(oph->msg), msgb_l2len(oph->msg)));

		/* Incoming data is a sign of a vital connection */
		conn = bsc_sccp_inst_get_gscon_by_conn_id(bsc_sccp, scu_prim->u.data.conn_id);
		if (conn) {
			a_reset_conn_success(conn->sccp.msc);
			handle_data_from_msc(conn, oph->msg);
		}
		break;

	case OSMO_PRIM(OSMO_SCU_PRIM_N_DISCONNECT, PRIM_OP_INDICATION):
		DEBUGP(DMSC, "N-DISCONNECT.ind(%u, %s, cause=%i)\n", scu_prim->u.disconnect.conn_id,
		       osmo_hexdump(msgb_l2(oph->msg), msgb_l2len(oph->msg)),
		       scu_prim->u.disconnect.cause);
		/* indication of disconnect */
		conn = bsc_sccp_inst_get_gscon_by_conn_id(bsc_sccp, scu_prim->u.disconnect.conn_id);
		if (conn) {
			conn->sccp.state = SUBSCR_SCCP_ST_NONE;
			if (msgb_l2len(oph->msg) > 0)
				handle_data_from_msc(conn, oph->msg);
			osmo_fsm_inst_dispatch(conn->fi, GSCON_EV_A_DISC_IND, scu_prim);
		}
		break;

	case OSMO_PRIM(OSMO_SCU_PRIM_N_PCSTATE, PRIM_OP_INDICATION):
		handle_pcstate_ind(osmo_sccp_get_ss7(sccp), &scu_prim->u.pcstate);
		break;

	case OSMO_PRIM(OSMO_SCU_PRIM_N_STATE, PRIM_OP_INDICATION):
		LOGP(DMSC, LOGL_DEBUG, "SCCP-User-SAP: Ignoring %s.%s\n",
		     osmo_scu_prim_type_name(oph->primitive),
		     get_value_string(osmo_prim_op_names, oph->operation));
		break;

	default:
		LOGP(DMSC, LOGL_ERROR, "SCCP-User-SAP: Unhandled %s.%s\n",
		     osmo_scu_prim_type_name(oph->primitive),
		     get_value_string(osmo_prim_op_names, oph->operation));
		break;
	}

	msgb_free(oph->msg);
	return rc;
}

/* Allocate resources to make a new connection oriented sigtran connection
 * (not the connection ittself!) */
enum bsc_con osmo_bsc_sigtran_new_conn(struct gsm_subscriber_connection *conn, struct bsc_msc_data *msc)
{
	struct osmo_ss7_instance *ss7;
	struct gsm_bts *bts = conn_get_bts(conn);

	OSMO_ASSERT(conn);
	OSMO_ASSERT(msc);

	ss7 = osmo_ss7_instance_find(msc->a.cs7_instance);
	OSMO_ASSERT(ss7);
	LOGP(DMSC, LOGL_INFO, "Initializing resources for new SCCP connection to MSC %d: %s...\n",
	     msc->nr, osmo_sccp_addr_name(ss7, &msc->a.msc_addr));

	if (a_reset_conn_ready(msc) == false) {
		LOGP(DMSC, LOGL_ERROR, "MSC %d is not connected. Dropping.\n", msc->nr);
		return BSC_CON_REJECT_NO_LINK;
	}

	if (bts && !bsc_grace_allow_new_connection(bts->network, bts)) {
		LOGP(DMSC, LOGL_NOTICE, "BSC in grace period. No new connections.\n");
		return BSC_CON_REJECT_RF_GRACE;
	}

	conn->sccp.msc = msc;

	return BSC_CON_SUCCESS;
}

/* Open a new connection oriented sigtran connection */
/* Allow test to overwrite it */
__attribute__((weak)) int osmo_bsc_sigtran_open_conn(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	struct osmo_ss7_instance *ss7;
	struct bsc_msc_data *msc;
	struct bsc_sccp_inst *bsc_sccp;
	uint32_t conn_id;
	int rc;

	OSMO_ASSERT(conn);
	OSMO_ASSERT(msg);
	OSMO_ASSERT(conn->sccp.msc);
	OSMO_ASSERT(conn->sccp.conn.conn_id == SCCP_CONN_ID_UNSET);

	msc = conn->sccp.msc;

	if (a_reset_conn_ready(msc) == false) {
		LOGP(DMSC, LOGL_ERROR, "MSC is not connected. Dropping.\n");
		return -EINVAL;
	}

	bsc_sccp = osmo_sccp_get_priv(msc->a.sccp);
	conn->sccp.conn.conn_id = conn_id = bsc_sccp_inst_next_conn_id(bsc_sccp);
	if (conn->sccp.conn.conn_id == SCCP_CONN_ID_UNSET) {
		LOGP(DMSC, LOGL_ERROR, "Unable to allocate SCCP Connection ID\n");
		return -1;
	}
	if (bsc_sccp_inst_register_gscon(bsc_sccp, &conn->sccp.conn) < 0) {
		LOGP(DMSC, LOGL_ERROR, "Unable to register SCCP connection (id=%u)\n", conn->sccp.conn.conn_id);
		return -1;
	}
	LOGP(DMSC, LOGL_DEBUG, "Allocated new connection id: %u\n", conn->sccp.conn.conn_id);
	ss7 = osmo_ss7_instance_find(msc->a.cs7_instance);
	OSMO_ASSERT(ss7);
	LOGP(DMSC, LOGL_INFO, "Opening new SCCP connection (id=%u) to MSC %d: %s\n", conn_id,
	     msc->nr, osmo_sccp_addr_name(ss7, &msc->a.msc_addr));

	rc = osmo_sccp_tx_conn_req_msg(msc->a.sccp_user, conn_id, &msc->a.bsc_addr,
				       &msc->a.msc_addr, msg);
	if (rc >= 0)
		conn->sccp.state = SUBSCR_SCCP_ST_WAIT_CONN_CONF;

	return rc;
}

/* Send data to MSC, the function will take ownership of *msg */
int osmo_bsc_sigtran_send(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	struct osmo_ss7_instance *ss7;
	int conn_id;
	int rc;
	struct bsc_msc_data *msc;

	OSMO_ASSERT(conn);
	OSMO_ASSERT(msg);

	if (!conn->sccp.msc) {
		LOGP(DMSC, LOGL_ERROR, "MSC is not connected. Dropping.\n");
		msgb_free(msg);
		return -EINVAL;
	}

	msc = conn->sccp.msc;

	/* Log the type of the message we are sending. This is just
	 * informative, do not stop if detecting the type fails */
	if (msg->len >= 3) {
		switch (msg->data[0]) {
		case BSSAP_MSG_BSS_MANAGEMENT:
			rate_ctr_inc(rate_ctr_group_get_ctr(msc->msc_ctrs, MSC_CTR_BSSMAP_TX_BSS_MANAGEMENT));
			LOGP(DMSC, LOGL_INFO, "Tx MSC: BSSMAP: %s\n",
			     gsm0808_bssmap_name(msg->data[2]));
			break;
		case BSSAP_MSG_DTAP:
			rate_ctr_inc(rate_ctr_group_get_ctr(msc->msc_ctrs, MSC_CTR_BSSMAP_TX_DTAP));
			LOGP(DMSC, LOGL_INFO, "Tx MSC: DTAP\n");
			break;
		default:
			rate_ctr_inc(rate_ctr_group_get_ctr(msc->msc_ctrs, MSC_CTR_BSSMAP_TX_UNKNOWN));
			LOGP(DMSC, LOGL_ERROR, "Tx MSC: unknown message type: 0x%x\n",
			     msg->data[0]);
		}
	} else {
		rate_ctr_inc(rate_ctr_group_get_ctr(msc->msc_ctrs, MSC_CTR_BSSMAP_TX_SHORT));
		LOGP(DMSC, LOGL_ERROR, "Tx MSC: message too short: %u\n", msg->len);
	}

	if (a_reset_conn_ready(msc) == false) {
		rate_ctr_inc(rate_ctr_group_get_ctr(msc->msc_ctrs, MSC_CTR_BSSMAP_TX_ERR_CONN_NOT_READY));
		LOGP(DMSC, LOGL_ERROR, "MSC is not connected. Dropping.\n");
		msgb_free(msg);
		return -EINVAL;
	}

	conn_id = conn->sccp.conn.conn_id;

	ss7 = osmo_ss7_instance_find(msc->a.cs7_instance);
	OSMO_ASSERT(ss7);
	LOGP(DMSC, LOGL_DEBUG, "Sending connection (id=%i) oriented data to MSC: %s (%s)\n",
	     conn_id, osmo_sccp_addr_name(ss7, &msc->a.msc_addr), osmo_hexdump(msg->data, msg->len));

	rc = osmo_sccp_tx_data_msg(msc->a.sccp_user, conn_id, msg);
	if (rc >= 0)
		rate_ctr_inc(rate_ctr_group_get_ctr(msc->msc_ctrs, MSC_CTR_BSSMAP_TX_SUCCESS));
	else
		rate_ctr_inc(rate_ctr_group_get_ctr(msc->msc_ctrs, MSC_CTR_BSSMAP_TX_ERR_SEND));

	return rc;
}

/* Close all open sigtran connections and channels */
void osmo_bsc_sigtran_reset(struct bsc_msc_data *msc)
{
	struct gsm_subscriber_connection *conn, *conn_temp;
	OSMO_ASSERT(msc);

	/* Drop all ongoing paging requests that this MSC has created on any BTS */
	paging_flush_network(msc->network, msc);

	/* Close all open connections */
	llist_for_each_entry_safe(conn, conn_temp, &bsc_gsmnet->subscr_conns, entry) {

		/* We only may close connections which actually belong to this
		 * MSC. All other open connections are left untouched */
		if (conn->sccp.msc == msc) {
			/* Take down all occopied RF channels */
			/* Disconnect all Sigtran connections */
			/* Delete subscriber connection */
			osmo_fsm_inst_term(conn->fi, OSMO_FSM_TERM_REQUEST, NULL);
		}
	}
}

/* Default point-code to be used as local address (BSC) */
#define BSC_DEFAULT_PC "0.23.3"

/* Default point-code to be used as remote address (MSC) */
#define MSC_DEFAULT_PC "0.23.1"

/* Default point-code to be used as remote address (MSC) */
#define MSC_DEFAULT_ADDR_NAME "addr-dyn-msc-default"

static int asp_rx_unknown(struct osmo_ss7_asp *asp, int ppid_mux, struct msgb *msg);

/* Initialize osmo sigtran backhaul */
int osmo_bsc_sigtran_init(struct llist_head *mscs)
{
	struct bsc_msc_data *msc;
	uint32_t default_pc;
	struct llist_head *ll_it;
	int rc;

	osmo_ss7_register_rx_unknown_cb(&asp_rx_unknown);

	OSMO_ASSERT(mscs);
	msc_list = mscs;

	/* Apply default address on each MSC and validate which ss7 instance it runs on. */
	llist_for_each_entry(msc, msc_list, entry) {
		struct osmo_ss7_instance *s7i;

		/* An MSC with invalid cs7 instance defaults to cs7 instance 0 */
		if (!msc->a.cs7_instance_valid) {
			s7i = osmo_ss7_instance_find(0);
			if (!s7i) {
				LOGP(DMSC, LOGL_NOTICE, "To auto-configure msc %d, creating cs7 instance 0 implicitly\n",
				     msc->nr);
				s7i = osmo_ss7_instance_find_or_create(tall_bsc_ctx, 0);
				OSMO_ASSERT(s7i);
			}
			msc->a.cs7_instance = osmo_ss7_instance_get_id(s7i);
			msc->a.cs7_instance_valid = true;
		} else {
			s7i = osmo_ss7_instance_find(msc->a.cs7_instance);
		}

		/* User didn't configure an 'msc-addr' in VTY for this msc, add
		 * default SCCP address for the MSC to the address book */
		if (!msc->a.msc_addr_name) {
			msc->a.msc_addr_name = talloc_strdup(msc, MSC_DEFAULT_ADDR_NAME);
			LOGP(DMSC, LOGL_NOTICE, "To auto-configure msc %d, adding address '%s' to cs7 instance 0 address-book implicitly\n",
			     msc->nr, msc->a.msc_addr_name);
		}
		if (!msc->a.msc_addr.presence) {
			struct osmo_ss7_instance *ss7;
			ss7 = osmo_sccp_addr_by_name(&msc->a.msc_addr, msc->a.msc_addr_name);
			if (!ss7) {
				osmo_sccp_make_addr_pc_ssn(&msc->a.msc_addr,
							   osmo_ss7_pointcode_parse(s7i, MSC_DEFAULT_PC),
							   OSMO_SCCP_SSN_BSSAP);
				rc = osmo_sccp_addr_create(s7i, msc->a.msc_addr_name, &msc->a.msc_addr);
				if (rc < 0)
					return -EINVAL;
			} else {
				OSMO_ASSERT(s7i == ss7);
				osmo_sccp_make_addr_pc_ssn(&msc->a.msc_addr,
							   osmo_ss7_pointcode_parse(s7i, MSC_DEFAULT_PC),
							   OSMO_SCCP_SSN_BSSAP);
				rc = osmo_sccp_addr_update(s7i, msc->a.msc_addr_name, &msc->a.msc_addr);
				if (rc < 0)
					return -EINVAL;
			}
		}
	}

	/* Guard against multiple MSCs with identical config */
	/* (more optimally, we'd only iterate the remaining other mscs after this msc, but this happens only
	 * during startup, so nevermind that complexity and rather check each pair twice. That also ensures to
	 * compare all MSCs that have no explicit msc_addr set, see osmo_sccp_make_addr_pc_ssn() above.) */
	llist_for_each_entry(msc, msc_list, entry) {
		struct bsc_msc_data *msc2;
		llist_for_each_entry(msc2, msc_list, entry) {
			if (msc2 == msc)
				continue;
			if (msc->a.cs7_instance != msc2->a.cs7_instance)
				continue;
			if (osmo_sccp_addr_cmp(&msc->a.msc_addr, &msc2->a.msc_addr, OSMO_SCCP_ADDR_T_PC) == 0) {
				LOGP(DMSC, LOGL_ERROR, "'msc %d' and 'msc %d' cannot use the same remote PC"
					" %s on the same cs7 instance %u\n",
					msc->nr, msc2->nr, osmo_sccp_addr_dump(&msc->a.msc_addr), msc->a.cs7_instance);
				return -EINVAL;
			}
		}
	}

	/* Set up exactly one SCCP user and one ASP+AS per cs7 instance.
	 * Iterate cs7 instance indexes and see for each one whether an MSC is configured for it.
	 * The 'msc' / 'msc-addr' command selects the cs7 instance used for an MSC.
	 */
	llist_for_each(ll_it, &osmo_ss7_instances) {
		struct osmo_ss7_instance *inst = osmo_ss7_instances_llist_entry(ll_it);
		char inst_name[32];
		enum osmo_ss7_asp_protocol used_proto = OSMO_SS7_ASP_PROT_NONE;
		int prev_msc_nr;
		uint32_t inst_id = osmo_ss7_instance_get_id(inst);

		struct osmo_sccp_instance *sccp;
		struct bsc_sccp_inst *bsc_sccp;

		llist_for_each_entry(msc, msc_list, entry) {
			/* An MSC with invalid cs7 instance id defaults to cs7 instance 0 */
			if (inst_id != msc->a.cs7_instance)
				continue;

			/* This msc runs on this cs7 inst. Check the asp_proto. */
			if (used_proto != OSMO_SS7_ASP_PROT_NONE
			    && used_proto != msc->a.asp_proto) {
				LOGP(DMSC, LOGL_ERROR, "'msc %d' and 'msc %d' with differing ASP protocols"
				     " %s and %s cannot use the same cs7 instance %u\n",
				     prev_msc_nr, msc->nr,
				     osmo_ss7_asp_protocol_name(used_proto),
				     osmo_ss7_asp_protocol_name(msc->a.asp_proto),
				     inst_id);
				return -EINVAL;
			}

			used_proto = msc->a.asp_proto;
			prev_msc_nr = msc->nr;
			/* still run through the other MSCs to catch asp_proto mismatches */
		}

		if (used_proto == OSMO_SS7_ASP_PROT_NONE) {
			/* This instance has no MSC associated with it */
			LOGP(DMSC, LOGL_ERROR, "cs7 instance %u has no MSCs configured to run on it\n", inst_id);
			continue;
		}

		snprintf(inst_name, sizeof(inst_name), "A-%u-%s", inst_id, osmo_ss7_asp_protocol_name(used_proto));
		LOGP(DMSC, LOGL_NOTICE, "Initializing SCCP connection for A/%s on cs7 instance %u\n",
		     osmo_ss7_asp_protocol_name(used_proto), inst_id);

		/* SS7 Protocol stack */
		default_pc = osmo_ss7_pointcode_parse(NULL, BSC_DEFAULT_PC);
		sccp = osmo_sccp_simple_client_on_ss7_id(tall_bsc_ctx, inst_id, inst_name,
							 default_pc, used_proto,
							 0, DEFAULT_ASP_LOCAL_IP,
							 0, DEFAULT_ASP_REMOTE_IP);
		if (!sccp)
			return -EINVAL;

		bsc_sccp = bsc_sccp_inst_alloc(tall_bsc_ctx);
		bsc_sccp->sccp = sccp;
		osmo_sccp_set_priv(sccp, bsc_sccp);

		/* Now that the SCCP client is set up, configure all MSCs on this cs7 instance to use it */
		llist_for_each_entry(msc, msc_list, entry) {
			char msc_name[32];

			/* Skip MSCs that don't run on this cs7 instance */
			if (inst_id != msc->a.cs7_instance)
				continue;

			snprintf(msc_name, sizeof(msc_name), "msc-%d", msc->nr);

			msc->a.sccp = sccp;

			/* In SCCPlite, the MSC side of the MGW endpoint is configured by the MSC. Since we have
			 * no way to figure out which CallID ('C:') the MSC will issue in its CRCX command, set
			 * an X-Osmo-IGN flag telling osmo-mgw to ignore CallID mismatches for this endpoint.
			 * If an explicit VTY command has already indicated whether or not to send X-Osmo-IGN, do
			 * not overwrite that setting. */
			if (msc_is_sccplite(msc) && !msc->x_osmo_ign_configured)
				msc->x_osmo_ign |= MGCP_X_OSMO_IGN_CALLID;

			/* If unset, use default local SCCP address */
			if (!msc->a.bsc_addr.presence)
				osmo_sccp_local_addr_by_instance(&msc->a.bsc_addr, sccp,
								 OSMO_SCCP_SSN_BSSAP);

			if (!osmo_sccp_check_addr(&msc->a.bsc_addr, OSMO_SCCP_ADDR_T_SSN | OSMO_SCCP_ADDR_T_PC)) {
				LOGP(DMSC, LOGL_ERROR,
				     "%s %s: invalid local (BSC) SCCP address: %s\n",
				     inst_name, msc_name, osmo_sccp_inst_addr_name(sccp, &msc->a.bsc_addr));
				return -EINVAL;
			}

			if (!osmo_sccp_check_addr(&msc->a.msc_addr, OSMO_SCCP_ADDR_T_SSN | OSMO_SCCP_ADDR_T_PC)) {
				LOGP(DMSC, LOGL_ERROR,
				     "%s %s: invalid remote (MSC) SCCP address: %s\n",
				     inst_name, msc_name, osmo_sccp_inst_addr_name(sccp, &msc->a.msc_addr));
				return -EINVAL;
			}

			LOGP(DMSC, LOGL_NOTICE, "%s %s: local (BSC) SCCP address: %s\n",
			     inst_name, msc_name, osmo_sccp_inst_addr_name(sccp, &msc->a.bsc_addr));
			LOGP(DMSC, LOGL_NOTICE, "%s %s: remote (MSC) SCCP address: %s\n",
			     inst_name, msc_name, osmo_sccp_inst_addr_name(sccp, &msc->a.msc_addr));

			/* Bind SCCP user. Bind only one user per sccp_instance and bsc_addr. */
			msc->a.sccp_user = osmo_sccp_user_find(sccp, msc->a.bsc_addr.ssn, msc->a.bsc_addr.pc);
			LOGP(DMSC, LOGL_NOTICE, "%s %s: %s\n", inst_name, msc_name,
			     msc->a.sccp_user ? "user already bound for this SCCP instance" : "binding SCCP user");
			if (!msc->a.sccp_user)
				msc->a.sccp_user = osmo_sccp_user_bind(sccp, msc_name, sccp_sap_up, msc->a.bsc_addr.ssn);
			if (!msc->a.sccp_user)
				return -EINVAL;

			/* Start MSC-Reset procedure */
			a_reset_alloc(msc, msc_name);
		}
	}

	return 0;
}

/* this function receives all messages received on an ASP for a PPID / StreamID that
 * libosmo-sigtran doesn't know about, such as piggy-backed CTRL and/or MGCP */
static int asp_rx_unknown(struct osmo_ss7_asp *asp, int ppid_mux, struct msgb *msg)
{
	if (osmo_ss7_asp_get_proto(asp) != OSMO_SS7_ASP_PROT_IPA) {
		msgb_free(msg);
		return 0;
	}

	switch (ppid_mux) {
	case IPAC_PROTO_OSMO:
		switch (osmo_ipa_msgb_cb_proto_ext(msg)) {
		case IPAC_PROTO_EXT_CTRL:
			return bsc_sccplite_rx_ctrl(asp, msg);
		case IPAC_PROTO_EXT_MGCP:
			return bsc_sccplite_rx_mgcp(asp, msg);
		}
		break;
	case IPAC_PROTO_MGCP_OLD:
		return bsc_sccplite_rx_mgcp(asp, msg);
	default:
		break;
	}
	msgb_free(msg);
	return 0; /* OSMO_SS7_UNKNOWN? */
}
