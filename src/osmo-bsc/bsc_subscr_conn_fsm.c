/* (C) 2017 by Harald Welte <laforge@gnumonks.org>
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

#include <limits.h>

#include <osmocom/core/fsm.h>
#include <osmocom/core/logging.h>
#include <osmocom/gsm/gsm0808.h>
#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/gsm/gsm0808_utils.h>

#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/a_reset.h>
#include <osmocom/bsc/gsm_08_08.h>
#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/bts.h>
#include <osmocom/bsc/handover_fsm.h>
#include <osmocom/bsc/lchan_fsm.h>
#include <osmocom/bsc/lchan_rtp_fsm.h>
#include <osmocom/bsc/bsc_subscriber.h>
#include <osmocom/bsc/osmo_bsc_sigtran.h>
#include <osmocom/bsc/osmo_bsc_lcls.h>
#include <osmocom/bsc/bsc_subscr_conn_fsm.h>
#include <osmocom/bsc/osmo_bsc.h>
#include <osmocom/bsc/penalty_timers.h>
#include <osmocom/bsc/bsc_rll.h>
#include <osmocom/bsc/abis_rsl.h>
#include <osmocom/core/tdef.h>
#include <osmocom/bsc/gsm_04_08_rr.h>
#include <osmocom/bsc/assignment_fsm.h>
#include <osmocom/bsc/codec_pref.h>
#include <osmocom/mgcp_client/mgcp_client_endpoint_fsm.h>
#include <osmocom/core/byteswap.h>

#define S(x)	(1 << (x))

#define MGCP_MGW_TIMEOUT 4	/* in seconds */
#define MGCP_MGW_TIMEOUT_TIMER_NR 1

#define MGCP_MGW_HO_TIMEOUT 4	/* in seconds */
#define MGCP_MGW_HO_TIMEOUT_TIMER_NR 2

enum gscon_fsm_states {
	ST_INIT,
	/* waiting for CC from MSC */
	ST_WAIT_CC,
	/* active connection */
	ST_ACTIVE,
	ST_ASSIGNMENT,
	ST_HANDOVER,
	/* BSSMAP CLEAR has been received */
	ST_CLEARING,
};

static const struct value_string gscon_fsm_event_names[] = {
	{GSCON_EV_A_CONN_IND, "MT-CONNECT.ind"},
	{GSCON_EV_A_CONN_REQ, "MO-CONNECT.req"},
	{GSCON_EV_A_CONN_CFM, "MO-CONNECT.cfm"},
	{GSCON_EV_A_CLEAR_CMD, "CLEAR_CMD"},
	{GSCON_EV_A_DISC_IND, "DISCONNET.ind"},
	{GSCON_EV_A_COMMON_ID_IND, "COMMON_ID.ind"},
	{GSCON_EV_ASSIGNMENT_START, "ASSIGNMENT_START"},
	{GSCON_EV_ASSIGNMENT_END, "ASSIGNMENT_END"},
	{GSCON_EV_HANDOVER_START, "HANDOVER_START"},
	{GSCON_EV_HANDOVER_END, "HANDOVER_END"},
	{GSCON_EV_RSL_CONN_FAIL, "RSL_CONN_FAIL"},
	{GSCON_EV_MO_DTAP, "MO_DTAP"},
	{GSCON_EV_MT_DTAP, "MT_DTAP"},
	{GSCON_EV_TX_SCCP, "TX_SCCP"},
	{GSCON_EV_MGW_MDCX_RESP_MSC, "MGW_MDCX_RESP_MSC"},
	{GSCON_EV_LCLS_FAIL, "LCLS_FAIL"},
	{GSCON_EV_FORGET_LCHAN, "FORGET_LCHAN"},
	{GSCON_EV_FORGET_MGW_ENDPOINT, "FORGET_MGW_ENDPOINT"},
	{}
};

struct osmo_tdef_state_timeout conn_fsm_timeouts[32] = {
	[ST_WAIT_CC] = { .T = 993210 },
	[ST_CLEARING] = { .T = 999 },
};

/* Transition to a state, using the T timer defined in conn_fsm_timeouts.
 * The actual timeout value is in turn obtained from network->T_defs.
 * Assumes local variable 'conn' exists. */
#define conn_fsm_state_chg(state) \
	osmo_tdef_fsm_inst_state_chg(conn->fi, state, \
				     conn_fsm_timeouts, \
				     conn->network->T_defs, \
				     -1)

/* forward MT DTAP from BSSAP side to RSL side */
static inline void submit_dtap(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	OSMO_ASSERT(msg);
	OSMO_ASSERT(conn);
	gscon_submit_rsl_dtap(conn, msg, OBSC_LINKID_CB(msg), 1);
}

static void gscon_dtap_queue_flush(struct gsm_subscriber_connection *conn, int send);

int gscon_sigtran_send(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	int rc;

	if (!msg)
		return -ENOMEM;

	/* Make sure that we only attempt to send SCCP messages if we have
	 * a live SCCP connection. Otherwise drop the message. */
	if (conn->fi->state == ST_INIT || conn->fi->state == ST_WAIT_CC) {
		LOGPFSML(conn->fi, LOGL_ERROR, "No active SCCP connection, dropping message\n");
		msgb_free(msg);
		return -ENODEV;
	}

	rc = osmo_bsc_sigtran_send(conn, msg);
	if (rc < 0)
		LOGPFSML(conn->fi, LOGL_ERROR, "Unable to deliver SCCP message\n");
	return rc;
}

static void gscon_bssmap_clear(struct gsm_subscriber_connection *conn,
			       enum gsm0808_cause cause)
{

	struct msgb *resp;
	int rc;

	LOGPFSML(conn->fi, LOGL_DEBUG, "Tx BSSMAP CLEAR REQUEST(%s) to MSC\n", gsm0808_cause_name(cause));
	resp = gsm0808_create_clear_rqst(cause);
	if (!resp) {
		LOGPFSML(conn->fi, LOGL_ERROR, "Unable to compose BSSMAP Clear Request message\n");
		return;
	}
	rate_ctr_inc(&conn->sccp.msc->msc_ctrs->ctr[MSC_CTR_BSSMAP_TX_DT1_CLEAR_RQST]);
	rc = osmo_bsc_sigtran_send(conn, resp);
	if (rc < 0)
		LOGPFSML(conn->fi, LOGL_ERROR, "Unable to deliver BSSMAP Clear Request message\n");
}

/* forward MO DTAP from RSL side to BSSAP side */
static void forward_dtap(struct gsm_subscriber_connection *conn, struct msgb *msg, struct osmo_fsm_inst *fi)
{
	struct msgb *resp = NULL;

	OSMO_ASSERT(msg);
	OSMO_ASSERT(conn);

	resp = gsm0808_create_dtap(msg, OBSC_LINKID_CB(msg));
	rate_ctr_inc(&conn->sccp.msc->msc_ctrs->ctr[MSC_CTR_BSSMAP_TX_DT1_DTAP]);
	gscon_sigtran_send(conn, resp);
}


/* Release an lchan in such a way that it doesn't fire events back to the conn. */
static void gscon_release_lchan(struct gsm_subscriber_connection *conn, struct gsm_lchan *lchan,
				bool do_rr_release, bool err, enum gsm48_rr_cause cause_rr)
{
	if (!lchan || !conn)
		return;
	if (lchan->conn == conn)
		lchan_forget_conn(lchan);
	if (conn->lchan == lchan)
		conn->lchan = NULL;
	if (conn->ho.fi && conn->ho.new_lchan == lchan)
		conn->ho.new_lchan = NULL;
	if (conn->assignment.new_lchan == lchan)
		conn->assignment.new_lchan = NULL;
	lchan_release(lchan, do_rr_release, err, cause_rr);
}

void gscon_release_lchans(struct gsm_subscriber_connection *conn, bool do_rr_release, enum gsm48_rr_cause cause_rr)
{
	if (conn->ho.fi)
		handover_end(conn, HO_RESULT_CONN_RELEASE);

	assignment_reset(conn);

	gscon_release_lchan(conn, conn->lchan, do_rr_release, false, cause_rr);
}

static void handle_bssap_n_connect(struct osmo_fsm_inst *fi, struct osmo_scu_prim *scu_prim)
{
	struct gsm_subscriber_connection *conn = fi->priv;
	struct msgb *msg = scu_prim->oph.msg;
	struct bssmap_header *bs;
	uint8_t bssmap_type;

	msg->l3h = msgb_l2(msg);
	if (!msgb_l3(msg)) {
		LOGPFSML(fi, LOGL_ERROR, "internal error: no l3 in msg\n");
		goto refuse;
	}

	if (msgb_l3len(msg) < sizeof(*bs)) {
		LOGPFSML(fi, LOGL_NOTICE, "message too short for BSSMAP header (%u < %zu)\n",
			 msgb_l3len(msg), sizeof(*bs));
		goto refuse;
	}

	bs = (struct bssmap_header*)msgb_l3(msg);
	if (msgb_l3len(msg) < (bs->length + sizeof(*bs))) {
		LOGPFSML(fi, LOGL_NOTICE,
			 "message too short for length indicated in BSSMAP header (%u < %u)\n",
			 msgb_l3len(msg), bs->length);
		goto refuse;
	}

	switch (bs->type) {
	case BSSAP_MSG_BSS_MANAGEMENT:
		break;
	default:
		LOGPFSML(fi, LOGL_NOTICE,
			 "message type not allowed for N-CONNECT: %s\n", gsm0808_bssap_name(bs->type));
		goto refuse;
	}

	msg->l4h = &msg->l3h[sizeof(*bs)];
	bssmap_type = msg->l4h[0];

	LOGPFSML(fi, LOGL_DEBUG, "Rx N-CONNECT: %s: %s\n", gsm0808_bssap_name(bs->type),
		 gsm0808_bssmap_name(bssmap_type));

	switch (bssmap_type) {
	case BSS_MAP_MSG_HANDOVER_RQST:
		/* First off, accept the new conn. */
		osmo_sccp_tx_conn_resp(conn->sccp.msc->a.sccp_user, scu_prim->u.connect.conn_id,
				       &scu_prim->u.connect.called_addr, NULL, 0);

		/* Make sure the conn FSM will osmo_sccp_tx_disconn() on term */
		conn->sccp.state = SUBSCR_SCCP_ST_CONNECTED;

		/* Inter-BSC MT Handover Request, another BSS is handovering to us. */
		handover_start_inter_bsc_in(conn, msg);
		return;
	default:
		break;
	}

	LOGPFSML(fi, LOGL_NOTICE, "No support for N-CONNECT: %s: %s\n",
		 gsm0808_bssap_name(bs->type), gsm0808_bssmap_name(bssmap_type));
refuse:
	osmo_sccp_tx_disconn(conn->sccp.msc->a.sccp_user, scu_prim->u.connect.conn_id,
			     &scu_prim->u.connect.called_addr, 0);
	osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, NULL);
}

static void gscon_fsm_init(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_subscriber_connection *conn = fi->priv;
	struct osmo_scu_prim *scu_prim = NULL;
	struct msgb *msg = NULL;
	int rc;
	enum handover_result ho_result;

	switch (event) {
	case GSCON_EV_A_CONN_REQ:
		/* RLL ESTABLISH IND with initial L3 Message */
		msg = data;
		/* FIXME: Extract Mobile ID and update FSM using osmo_fsm_inst_set_id()
		 * i.e. we will probably extract the mobile identity earlier, where the
		 * imsi filter code is. Then we could just use it here.
		 * related: OS#2969 */

		rc = osmo_bsc_sigtran_open_conn(conn, msg);
		if (rc < 0) {
			osmo_fsm_inst_term(fi, OSMO_FSM_TERM_ERROR, NULL);
		} else {
			/* SCCP T(conn est) is 1-2 minutes, way too long. The MS will timeout
			 * using T3210 (20s), T3220 (5s) or T3230 (10s) */
			conn_fsm_state_chg(ST_WAIT_CC);
		}
		gscon_update_id(conn);
		break;
	case GSCON_EV_A_CONN_IND:
		gscon_update_id(conn);
		scu_prim = data;
		if (!conn->sccp.msc) {
			LOGPFSML(fi, LOGL_NOTICE, "N-CONNECT.ind from unknown MSC %s\n",
				 osmo_sccp_addr_dump(&scu_prim->u.connect.calling_addr));
			/* We cannot find a way to the sccp_user without the MSC, so we cannot
			 * use osmo_sccp_tx_disconn() :( */
			//osmo_sccp_tx_disconn(conn->sccp.msc->a.sccp_user, scu_prim->u.connect.conn_id, &scu_prim->u.connect.called_addr, 0);
			osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, NULL);
			return;
		}
		/* FIXME: Extract optional IMSI and update FSM using osmo_fsm_inst_set_id()
		 * related: OS2969 (same as above) */

		handle_bssap_n_connect(fi, scu_prim);
		break;
	case GSCON_EV_HANDOVER_END:
		ho_result = HO_RESULT_ERROR;
		if (data)
			ho_result = *(enum handover_result*)data;
		LOGPFSML(fi, LOGL_DEBUG, "Handover result: %s\n", handover_result_name(ho_result));
		if (ho_result == HO_RESULT_OK) {
			/* In this case the ho struct should still be populated. */
			if (conn->ho.scope & HO_INTER_BSC_IN) {
				/* Done with establishing a conn where we accept another BSC's MS via
				 * inter-BSC handover */

				osmo_fsm_inst_state_chg(fi, ST_ACTIVE, 0, 0);
				gscon_dtap_queue_flush(conn, 1);
				return;
			}
			LOG_HO(conn, LOGL_ERROR,
			       "Conn is in state %s, the only accepted handover kind is inter-BSC MT\n",
			       osmo_fsm_inst_state_name(conn->fi));
		}
		gscon_bssmap_clear(conn, GSM0808_CAUSE_EQUIPMENT_FAILURE);
		if (conn->fi->state != ST_CLEARING)
			osmo_fsm_inst_state_chg(fi, ST_CLEARING, 60, 999);
		return;
	default:
		OSMO_ASSERT(false);
	}
}

/* We've sent the CONNECTION.req to the SCCP provider and are waiting for CC from MSC */
static void gscon_fsm_wait_cc(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_subscriber_connection *conn = fi->priv;
	switch (event) {
	case GSCON_EV_A_CONN_CFM:
		/* MSC has confirmed the connection */

		if (!conn->lchan) {
			/* If associated lchan was released while we were waiting for the
			   confirmed connection, then instead simply drop the connection */
			LOGPFSML(fi, LOGL_INFO,
				 "Connection confirmed but lchan was dropped previously, clearing conn\n");
			osmo_fsm_inst_state_chg(conn->fi, ST_CLEARING, 60, 999);
			gscon_bssmap_clear(conn, GSM0808_CAUSE_EQUIPMENT_FAILURE);
			break;
		}

		/* We now change into the active state and wait there for further operations. */
		conn_fsm_state_chg(ST_ACTIVE);
		/* if there's user payload, forward it just like EV_MT_DTAP */
		/* FIXME: Question: if there's user payload attached to the CC, forward it like EV_MT_DTAP? */
		break;
	default:
		OSMO_ASSERT(false);
	}
}

/* We're on an active subscriber connection, passing DTAP back and forth */
static void gscon_fsm_active(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_subscriber_connection *conn = fi->priv;
	struct gsm_bts *bts;

	switch (event) {

	case GSCON_EV_ASSIGNMENT_START:
		bts = conn->lchan? conn->lchan->ts->trx->bts : NULL;

		if (!bts) {
			LOGPFSML(fi, LOGL_ERROR, "Cannot do assignment, no active BTS\n");
			return;
		}

		/* Rely on assignment_fsm timeout */
		osmo_fsm_inst_state_chg(fi, ST_ASSIGNMENT, 0, 0);
		assignment_fsm_start(conn, bts, data);
		return;

	case GSCON_EV_HANDOVER_START:
		bts = conn_get_bts(conn);
		rate_ctr_inc(&conn->network->bsc_ctrs->ctr[BSC_CTR_HANDOVER_ATTEMPTED]);
		if (bts)
			rate_ctr_inc(&bts->bts_ctrs->ctr[BTS_CTR_HANDOVER_ATTEMPTED]);
		else
			rate_ctr_inc(&conn->network->bts_unknown_ctrs->ctr[BTS_CTR_HANDOVER_ATTEMPTED]);

		/* Rely on handover_fsm timeout */
		if (osmo_fsm_inst_state_chg(fi, ST_HANDOVER, 0, 0))
			LOGPFSML(fi, LOGL_ERROR, "Cannot transition to HANDOVER state, discarding\n");
		else
			handover_start(data);
		break;

	case GSCON_EV_MO_DTAP:
		forward_dtap(conn, (struct msgb *)data, fi);
		break;
	case GSCON_EV_MT_DTAP:
		submit_dtap(conn, (struct msgb *)data);
		break;
	case GSCON_EV_TX_SCCP:
		gscon_sigtran_send(conn, (struct msgb *)data);
		break;
	default:
		OSMO_ASSERT(false);
	}
}

static void gscon_fsm_assignment(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_subscriber_connection *conn = fi->priv;

	switch (event) {
	case GSCON_EV_ASSIGNMENT_END:
		osmo_fsm_inst_state_chg(fi, ST_ACTIVE, 0, 0);
		gscon_dtap_queue_flush(conn, 1);
		return;

	case GSCON_EV_MO_DTAP:
		forward_dtap(conn, (struct msgb *)data, fi);
		break;
	case GSCON_EV_MT_DTAP:
		submit_dtap(conn, (struct msgb *)data);
		break;
	case GSCON_EV_TX_SCCP:
		gscon_sigtran_send(conn, (struct msgb *)data);
		break;
	default:
		OSMO_ASSERT(false);
	}
}

static void gscon_fsm_handover(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_subscriber_connection *conn = fi->priv;

	switch (event) {
	case GSCON_EV_HANDOVER_END:
		osmo_fsm_inst_state_chg(fi, ST_ACTIVE, 0, 0);
		gscon_dtap_queue_flush(conn, 1);
		return;

	case GSCON_EV_MO_DTAP:
		forward_dtap(conn, (struct msgb *)data, fi);
		break;
	case GSCON_EV_MT_DTAP:
		/* cache until handover is done */
		submit_dtap(conn, (struct msgb *)data);
		break;
	case GSCON_EV_TX_SCCP:
		gscon_sigtran_send(conn, (struct msgb *)data);
		break;
	default:
		OSMO_ASSERT(false);
	}
}

static bool same_mgw_info(const struct mgcp_conn_peer *a, const struct mgcp_conn_peer *b)
{
	if (!a || !b)
		return false;
	if (a == b)
		return true;
	if (strcmp(a->addr, b->addr))
		return false;
	if (a->port != b->port)
		return false;
	if (a->call_id != b->call_id)
		return false;
	return true;
}

/* Make sure a conn->user_plane.mgw_endpoint is allocated with the proper mgw endpoint name.  For
 * SCCPlite, pass in msc_assigned_cic the CIC received upon BSSMAP Assignment Command or BSSMAP Handover
 * Request form the MSC (which is only stored in conn->user_plane after success). Ignored for AoIP. */
struct osmo_mgcpc_ep *gscon_ensure_mgw_endpoint(struct gsm_subscriber_connection *conn,
						uint16_t msc_assigned_cic, struct gsm_lchan *for_lchan)
{
	const char *epname;

	if (conn->user_plane.mgw_endpoint)
		return conn->user_plane.mgw_endpoint;

	if (gscon_is_sccplite(conn)) {
		/* derive endpoint name from CIC on A interface side */
		conn->user_plane.mgw_endpoint =
			osmo_mgcpc_ep_alloc(conn->fi, GSCON_EV_FORGET_MGW_ENDPOINT,
					    conn->network->mgw.client,
					    conn->network->mgw.tdefs,
					    conn->fi->id,
					    "%x@%s", msc_assigned_cic,
					    mgcp_client_endpoint_domain(conn->network->mgw.client));
		LOGPFSML(conn->fi, LOGL_DEBUG, "MGW endpoint name derived from CIC 0x%x: %s\n",
			 msc_assigned_cic, osmo_mgcpc_ep_name(conn->user_plane.mgw_endpoint));

	} else if (gscon_is_aoip(conn)) {

		if (is_ipaccess_bts(for_lchan->ts->trx->bts))
			/* use dynamic RTPBRIDGE endpoint allocation in MGW */
			epname = mgcp_client_rtpbridge_wildcard(conn->network->mgw.client);
		else {
			epname = mgcp_client_e1_epname(conn, conn->network->mgw.client, for_lchan->ts->e1_link.e1_nr,
						       for_lchan->ts->e1_link.e1_ts, 16,
						       for_lchan->ts->e1_link.e1_ts_ss*2);
		}

		conn->user_plane.mgw_endpoint =
			osmo_mgcpc_ep_alloc(conn->fi, GSCON_EV_FORGET_MGW_ENDPOINT,
					    conn->network->mgw.client,
					    conn->network->mgw.tdefs,
					    conn->fi->id,
					    "%s", epname);
	} else {
		LOGPFSML(conn->fi, LOGL_ERROR, "Conn is neither SCCPlite nor AoIP!?\n");
		return NULL;
	}

	return conn->user_plane.mgw_endpoint;
}

bool gscon_connect_mgw_to_msc(struct gsm_subscriber_connection *conn,
			      struct gsm_lchan *for_lchan,
			      const char *addr, uint16_t port,
			      struct osmo_fsm_inst *notify,
			      uint32_t event_success, uint32_t event_failure,
			      void *notify_data,
			      struct osmo_mgcpc_ep_ci **created_ci)
{
	int rc;
	struct osmo_mgcpc_ep_ci *ci;
	struct mgcp_conn_peer mgw_info;
	enum mgcp_verb verb;

	if (created_ci)
		*created_ci = NULL;

	if (gscon_is_sccplite(conn)) {
		/* SCCPlite connection uses an MGW endpoint created by the MSC, so there is nothing to do
		 * here. */
		if (notify)
			osmo_fsm_inst_dispatch(notify, event_success, notify_data);
		return true;
	}

	mgw_info = (struct mgcp_conn_peer){
		.port = port,
		.call_id = conn->sccp.conn_id,
		.ptime = 20,
		.x_osmo_osmux_use = conn->assignment.req.use_osmux,
		.x_osmo_osmux_cid = conn->assignment.req.osmux_cid,
	};
	mgcp_pick_codec(&mgw_info, for_lchan, false);

	rc = osmo_strlcpy(mgw_info.addr, addr, sizeof(mgw_info.addr));
	if (rc <= 0 || rc >= sizeof(mgw_info.addr)) {
		LOGPFSML(conn->fi, LOGL_ERROR, "Failed to compose MGW endpoint address for MGW -> MSC\n");
		return false;
	}

	ci = conn->user_plane.mgw_endpoint_ci_msc;
	if (ci) {
		const struct mgcp_conn_peer *prev_crcx_info = osmo_mgcpc_ep_ci_get_rtp_info(ci);

		if (!conn->user_plane.mgw_endpoint) {
			LOGPFSML(conn->fi, LOGL_ERROR, "Internal error: conn has a CI but no endpoint\n");
			return false;
		}

		if (!prev_crcx_info) {
			LOGPFSML(conn->fi, LOGL_ERROR, "There already is an MGW connection for the MSC side,"
				 " but it seems to be broken. Will not CRCX another one (%s)\n",
				 osmo_mgcpc_ep_ci_name(ci));
			return false;
		}

		if (same_mgw_info(&mgw_info, prev_crcx_info)) {
			LOGPFSML(conn->fi, LOGL_DEBUG,
				 "MSC side MGW endpoint ci is already configured to %s\n",
				 osmo_mgcpc_ep_ci_name(ci));
			return true;
		}

		verb = MGCP_VERB_MDCX;
	} else
		verb = MGCP_VERB_CRCX;

	gscon_ensure_mgw_endpoint(conn, for_lchan->activate.info.msc_assigned_cic, for_lchan);

	if (!conn->user_plane.mgw_endpoint) {
		LOGPFSML(conn->fi, LOGL_ERROR, "Unable to allocate endpoint info\n");
		return false;
	}

	if (!ci) {
		ci = osmo_mgcpc_ep_ci_add(conn->user_plane.mgw_endpoint, "to-MSC");
		if (created_ci)
			*created_ci = ci;
		conn->user_plane.mgw_endpoint_ci_msc = ci;
	}
	if (!ci) {
		LOGPFSML(conn->fi, LOGL_ERROR, "Unable to allocate endpoint CI info\n");
		return false;
	}

	osmo_mgcpc_ep_ci_request(ci, verb, &mgw_info, notify, event_success, event_failure, notify_data);
	return true;
}

#define EV_TRANSPARENT_SCCP S(GSCON_EV_TX_SCCP) | S(GSCON_EV_MO_DTAP) | S(GSCON_EV_MT_DTAP)

static const struct osmo_fsm_state gscon_fsm_states[] = {
	[ST_INIT] = {
		.name = "INIT",
		.in_event_mask = S(GSCON_EV_A_CONN_REQ) | S(GSCON_EV_A_CONN_IND)
			| S(GSCON_EV_HANDOVER_END),
		.out_state_mask = S(ST_WAIT_CC) | S(ST_ACTIVE) | S(ST_CLEARING),
		.action = gscon_fsm_init,
	 },
	[ST_WAIT_CC] = {
		.name = "WAIT_CC",
		.in_event_mask = S(GSCON_EV_A_CONN_CFM),
		.out_state_mask = S(ST_ACTIVE) | S(ST_CLEARING),
		.action = gscon_fsm_wait_cc,
	},
	[ST_ACTIVE] = {
		.name = "ACTIVE",
		.in_event_mask = EV_TRANSPARENT_SCCP | S(GSCON_EV_ASSIGNMENT_START) |
				 S(GSCON_EV_HANDOVER_START),
		.out_state_mask = S(ST_CLEARING) | S(ST_ASSIGNMENT) |
				  S(ST_HANDOVER),
		.action = gscon_fsm_active,
	},
	[ST_ASSIGNMENT] = {
		.name = "ASSIGNMENT",
		.in_event_mask = EV_TRANSPARENT_SCCP | S(GSCON_EV_ASSIGNMENT_END),
		.out_state_mask = S(ST_ACTIVE) | S(ST_CLEARING),
		.action = gscon_fsm_assignment,
	},
	[ST_HANDOVER] = {
		.name = "HANDOVER",
		.in_event_mask = EV_TRANSPARENT_SCCP | S(GSCON_EV_HANDOVER_END),
		.out_state_mask = S(ST_ACTIVE) | S(ST_CLEARING),
		.action = gscon_fsm_handover,
	},
	[ST_CLEARING] = {
		.name = "CLEARING",
		/* dead end state */
	 },
};

void gscon_change_primary_lchan(struct gsm_subscriber_connection *conn, struct gsm_lchan *new_lchan)
{
	/* On release, do not receive release events that look like the primary lchan is gone. */
	struct gsm_lchan *old_lchan = conn->lchan;

	conn->lchan = new_lchan;
	conn->lchan->conn = conn;

	if (conn->lchan->fi_rtp)
		osmo_fsm_inst_dispatch(conn->lchan->fi_rtp, LCHAN_RTP_EV_ESTABLISHED, 0);

	if (old_lchan && (old_lchan != new_lchan))
		gscon_release_lchan(conn, old_lchan, false, false, GSM48_RR_CAUSE_NORMAL);
}

void gscon_lchan_releasing(struct gsm_subscriber_connection *conn, struct gsm_lchan *lchan)
{
	if (!lchan)
		return;
	if (conn->assignment.new_lchan == lchan) {
		if (conn->assignment.fi)
			osmo_fsm_inst_dispatch(conn->assignment.fi, ASSIGNMENT_EV_LCHAN_ERROR, lchan);
		lchan_forget_conn(conn->assignment.new_lchan);
		conn->assignment.new_lchan = NULL;
	}
	if (conn->ho.new_lchan == lchan) {
		if (conn->ho.fi)
			osmo_fsm_inst_dispatch(conn->ho.fi, HO_EV_LCHAN_ERROR, lchan);
	}
	if (conn->lchan == lchan) {
		lchan_forget_conn(conn->lchan);
		conn->lchan = NULL;
	}
	/* If the conn has no lchan anymore, it was released by the BTS and needs to Clear towards MSC. */
	if (!conn->lchan) {
		switch (conn->fi->state) {
		case ST_WAIT_CC:
			/* The SCCP connection was not yet confirmed by a CC, the BSSAP is not fully established
			   yet so we cannot release it. First wait for the CC, and release in gscon_fsm_wait_cc(). */
			break;
		default:
			/* Ensure that the FSM is in ST_CLEARING. */
			osmo_fsm_inst_state_chg(conn->fi, ST_CLEARING, 60, 999);
			/* fall thru, omit an error log if already in ST_CLEARING */
		case ST_CLEARING:
			/* Request a Clear Command from the MSC. */
			gscon_bssmap_clear(conn, GSM0808_CAUSE_EQUIPMENT_FAILURE);
			break;
		}
	}
}

/* An lchan was deallocated. */
void gscon_forget_lchan(struct gsm_subscriber_connection *conn, struct gsm_lchan *lchan)
{
	const char *detach_label = NULL;
	if (!conn)
		return;
	if (!lchan)
		return;

	if (conn->assignment.new_lchan == lchan) {
		conn->assignment.new_lchan = NULL;
		detach_label = "assignment.new_lchan";
	}
	if (conn->ho.new_lchan == lchan) {
		conn->ho.new_lchan = NULL;
		detach_label = "ho.new_lchan";
	}
	if (conn->lchan == lchan) {
		conn->lchan = NULL;
		detach_label = "primary lchan";
	}

	/* Log for both lchan FSM and conn FSM to ease reading the log in case of problems */
	if (detach_label) {
		LOGPFSML(conn->fi, LOGL_DEBUG, "conn detaches lchan %s\n",
			 lchan->fi? osmo_fsm_inst_name(lchan->fi) : gsm_lchan_name(lchan));

		if (lchan->fi)
			LOGPFSML(lchan->fi, LOGL_DEBUG, "conn %s detaches lchan (%s)\n",
				 osmo_fsm_inst_name(conn->fi), detach_label);
	}

	if ((conn->fi && conn->fi->state != ST_CLEARING)
	    && !conn->lchan
	    && !conn->ho.new_lchan
	    && !conn->assignment.new_lchan)
		gscon_bssmap_clear(conn, GSM0808_CAUSE_EQUIPMENT_FAILURE);
}

static void gscon_forget_mgw_endpoint(struct gsm_subscriber_connection *conn)
{
	conn->user_plane.mgw_endpoint = NULL;
	conn->user_plane.mgw_endpoint_ci_msc = NULL;
	conn->ho.created_ci_for_msc = NULL;
	lchan_forget_mgw_endpoint(conn->lchan);
	lchan_forget_mgw_endpoint(conn->assignment.new_lchan);
	lchan_forget_mgw_endpoint(conn->ho.new_lchan);
}

void gscon_forget_mgw_endpoint_ci(struct gsm_subscriber_connection *conn, struct osmo_mgcpc_ep_ci *ci)
{
	if (conn->ho.created_ci_for_msc == ci)
		conn->ho.created_ci_for_msc = NULL;

	if (conn->user_plane.mgw_endpoint_ci_msc == ci)
		conn->user_plane.mgw_endpoint_ci_msc = NULL;
}

static void gscon_fsm_allstate(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_subscriber_connection *conn = fi->priv;
	const struct gscon_clear_cmd_data *ccd;
	struct osmo_mobile_identity *mi_imsi;

	/* Regular allstate event processing */
	switch (event) {
	case GSCON_EV_A_CLEAR_CMD:
		OSMO_ASSERT(data);
		ccd = data;
		if (conn->lchan)
			conn->lchan->release.is_csfb = ccd->is_csfb;
		/* MSC tells us to cleanly shut down */
		if (conn->fi->state != ST_CLEARING)
			osmo_fsm_inst_state_chg(fi, ST_CLEARING, 60, 999);
		LOGPFSML(fi, LOGL_DEBUG, "Releasing all lchans (if any) after BSSMAP Clear Command\n");
		gscon_release_lchans(conn, true, bsc_gsm48_rr_cause_from_gsm0808_cause(ccd->cause_0808));
		/* FIXME: Release all terestrial resources in ST_CLEARING */
		/* According to 3GPP 48.008 3.1.9.1. "The BSS need not wait for the radio channel
		 * release to be completed or for the guard timer to expire before returning the
		 * CLEAR COMPLETE message" */

		/* Close MGCP connections */
		osmo_mgcpc_ep_clear(conn->user_plane.mgw_endpoint);

		rate_ctr_inc(&conn->sccp.msc->msc_ctrs->ctr[MSC_CTR_BSSMAP_TX_DT1_CLEAR_COMPLETE]);
		gscon_sigtran_send(conn, gsm0808_create_clear_complete());
		break;
	case GSCON_EV_A_DISC_IND:
		/* MSC or SIGTRAN network has hard-released SCCP connection,
		 * terminate the FSM now. */
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, data);
		break;
	case GSCON_EV_FORGET_MGW_ENDPOINT:
		gscon_forget_mgw_endpoint(conn);
		break;
	case GSCON_EV_RSL_CONN_FAIL:
		if (conn->lchan) {
			conn->lchan->release.in_error = true;
			conn->lchan->release.rsl_error_cause = data ? *(uint8_t*)data : RSL_ERR_IE_ERROR;
			conn->lchan->release.rr_cause =
				bsc_gsm48_rr_cause_from_rsl_cause(conn->lchan->release.rsl_error_cause);
		}
		gscon_bssmap_clear(conn, GSM0808_CAUSE_RADIO_INTERFACE_FAILURE);
		break;
	case GSCON_EV_MGW_MDCX_RESP_MSC:
		LOGPFSML(fi, LOGL_DEBUG, "Rx MDCX of MSC side (LCLS?)\n");
		break;
	case GSCON_EV_LCLS_FAIL:
		break;
	case GSCON_EV_A_COMMON_ID_IND:
		OSMO_ASSERT(data);
		mi_imsi = data;
		if (!conn->bsub)
			conn->bsub = bsc_subscr_find_or_create_by_imsi(conn->network->bsc_subscribers, mi_imsi->imsi);
		else {
			/* we already have a bsc_subscr associated; maybe that subscriber has no IMSI yet? */
			if (!conn->bsub->imsi[0])
				bsc_subscr_set_imsi(conn->bsub, mi_imsi->imsi);
		}
		gscon_update_id(conn);
		break;
	default:
		OSMO_ASSERT(false);
		break;
	}
}

static void gscon_cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct gsm_subscriber_connection *conn = fi->priv;

	lchan_forget_conn(conn->lchan);
	lchan_forget_conn(conn->assignment.new_lchan);
	lchan_forget_conn(conn->ho.new_lchan);

	if (conn->sccp.state != SUBSCR_SCCP_ST_NONE) {
		LOGPFSML(fi, LOGL_DEBUG, "Disconnecting SCCP\n");
		struct bsc_msc_data *msc = conn->sccp.msc;
		/* FIXME: include a proper cause value / error message? */
		osmo_sccp_tx_disconn(msc->a.sccp_user, conn->sccp.conn_id, &msc->a.bsc_addr, 0);
		conn->sccp.state = SUBSCR_SCCP_ST_NONE;
	}

	if (conn->bsub) {
		LOGPFSML(fi, LOGL_DEBUG, "Putting bsc_subscr\n");
		bsc_subscr_put(conn->bsub);
		conn->bsub = NULL;
	}

	llist_del(&conn->entry);
	talloc_free(conn);
}

static void gscon_pre_term(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct gsm_subscriber_connection *conn = fi->priv;

	osmo_mgcpc_ep_clear(conn->user_plane.mgw_endpoint);

	if (conn->lcls.fi) {
		/* request termination of LCLS FSM */
		osmo_fsm_inst_term(conn->lcls.fi, cause, NULL);
		conn->lcls.fi = NULL;
	}

	LOGPFSML(fi, LOGL_DEBUG, "Releasing all lchans (if any) because this conn is terminating\n");
	/* when things go smoothly, the lchan should have been released before FSM instance termination. So if this is
	 * necessary it's probably "abnormal". */
	gscon_release_lchans(conn, true, GSM48_RR_CAUSE_ABNORMAL_UNSPEC);

	/* drop pending messages */
	gscon_dtap_queue_flush(conn, 0);

	penalty_timers_free(&conn->hodec2.penalty_timers);
}

static int gscon_timer_cb(struct osmo_fsm_inst *fi)
{
	struct gsm_subscriber_connection *conn = fi->priv;

	switch (fi->T) {
	case 993210:
		gscon_release_lchan(conn, conn->lchan, true, true, GSM48_RR_CAUSE_ABNORMAL_TIMER);

		/* MSC has not responded/confirmed connection with CC, this
		 * could indicate a bad SCCP connection. We now inform the the
		 * FSM that controls the BSSMAP reset about the event. Maybe
		 * a BSSMAP reset is necessary. */
		a_reset_conn_fail(conn->sccp.msc);

		/* Since we could not reach the MSC, we give up and terminate
		 * the FSM instance now (N-DISCONNET.req is sent in
		 * gscon_cleanup() above) */
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, NULL);
		break;
	case 999:
		/* The MSC has sent a BSSMAP Clear Command, we acknowledged that, but the conn was never
		 * disconnected. */
		LOGPFSML(fi, LOGL_ERROR, "Long after a BSSMAP Clear Command, the conn is still not"
			 " released. For sanity, discarding this conn now.\n");
		a_reset_conn_fail(conn->sccp.msc);
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_ERROR, NULL);
		break;
	default:
		LOGPFSML(fi, LOGL_ERROR, "Unknown timer %d expired\n", fi->T);
		OSMO_ASSERT(false);
	}
	return 0;
}

static struct osmo_fsm gscon_fsm = {
	.name = "SUBSCR_CONN",
	.states = gscon_fsm_states,
	.num_states = ARRAY_SIZE(gscon_fsm_states),
	.allstate_event_mask = S(GSCON_EV_A_DISC_IND) | S(GSCON_EV_A_CLEAR_CMD) | S(GSCON_EV_A_COMMON_ID_IND) |
	    S(GSCON_EV_RSL_CONN_FAIL) |
	    S(GSCON_EV_LCLS_FAIL) |
	    S(GSCON_EV_FORGET_LCHAN) |
	    S(GSCON_EV_FORGET_MGW_ENDPOINT),
	.allstate_action = gscon_fsm_allstate,
	.cleanup = gscon_cleanup,
	.pre_term = gscon_pre_term,
	.timer_cb = gscon_timer_cb,
	.log_subsys = DMSC,
	.event_names = gscon_fsm_event_names,
};

void bsc_subscr_conn_fsm_init()
{
	OSMO_ASSERT(osmo_fsm_register(&gscon_fsm) == 0);
	OSMO_ASSERT(osmo_fsm_register(&lcls_fsm) == 0);
}

/* Allocate a subscriber connection and its associated FSM */
struct gsm_subscriber_connection *bsc_subscr_con_allocate(struct gsm_network *net)
{
	struct gsm_subscriber_connection *conn;

	conn = talloc_zero(net, struct gsm_subscriber_connection);
	if (!conn)
		return NULL;

	conn->network = net;
	INIT_LLIST_HEAD(&conn->dtap_queue);
	/* BTW, penalty timers will be initialized on-demand. */
	conn->sccp.conn_id = -1;

	/* don't allocate from 'conn' context, as gscon_cleanup() will call talloc_free(conn) before
	 * libosmocore will call talloc_free(conn->fi), i.e. avoid use-after-free during cleanup */
	conn->fi = osmo_fsm_inst_alloc(&gscon_fsm, net, conn, LOGL_DEBUG, NULL);
	if (!conn->fi) {
		talloc_free(conn);
		return NULL;
	}

	/* indicate "IE not [yet] received" */
	conn->lcls.config = GSM0808_LCLS_CFG_NA;
	conn->lcls.control = GSM0808_LCLS_CSC_NA;
	conn->lcls.fi = osmo_fsm_inst_alloc_child(&lcls_fsm, conn->fi, GSCON_EV_LCLS_FAIL);
	if (!conn->lcls.fi) {
		osmo_fsm_inst_term(conn->fi, OSMO_FSM_TERM_ERROR, NULL);
		return NULL;
	}
	conn->lcls.fi->priv = conn;

	llist_add_tail(&conn->entry, &net->subscr_conns);
	return conn;
}

static void gsm0808_send_rsl_dtap(struct gsm_subscriber_connection *conn,
				  struct msgb *msg, int link_id, int allow_sacch);

#define GSCON_DTAP_QUEUE_MSGB_CB_LINK_ID 0
#define GSCON_DTAP_QUEUE_MSGB_CB_ALLOW_SACCH 1

static void gscon_dtap_queue_add(struct gsm_subscriber_connection *conn, struct msgb *msg,
				 int link_id, bool allow_sacch)
{
	if (conn->dtap_queue_len >= 8) {
		LOGP(DMSC, LOGL_ERROR, "%s: Cannot queue more DTAP messages,"
		     " already reached sane maximum of %u queued messages\n",
		     bsc_subscr_name(conn->bsub), conn->dtap_queue_len);
		msgb_free(msg);
		return;
	}
	conn->dtap_queue_len ++;
	LOGP(DMSC, LOGL_DEBUG, "%s: Queueing DTAP message during handover/assignment (%u)\n",
	     bsc_subscr_name(conn->bsub), conn->dtap_queue_len);
	msg->cb[GSCON_DTAP_QUEUE_MSGB_CB_LINK_ID] = (unsigned long)link_id;
	msg->cb[GSCON_DTAP_QUEUE_MSGB_CB_ALLOW_SACCH] = allow_sacch ? 1 : 0;
	msgb_enqueue(&conn->dtap_queue, msg);
}

static void gscon_dtap_queue_flush(struct gsm_subscriber_connection *conn, int send)
{
	struct msgb *msg;
	unsigned int flushed_count = 0;

	while ((msg = msgb_dequeue(&conn->dtap_queue))) {
		conn->dtap_queue_len --;
		flushed_count ++;
		if (send) {
			int link_id = (int)msg->cb[GSCON_DTAP_QUEUE_MSGB_CB_LINK_ID];
			bool allow_sacch = !!msg->cb[GSCON_DTAP_QUEUE_MSGB_CB_ALLOW_SACCH];
			LOGPFSML(conn->fi, LOGL_DEBUG,
				 "%s: Sending queued DTAP message after handover/assignment (%u/%u)\n",
				 bsc_subscr_name(conn->bsub), flushed_count, conn->dtap_queue_len);
			gsm0808_send_rsl_dtap(conn, msg, link_id, allow_sacch);
		} else
			msgb_free(msg);
	}
}

static void rll_ind_cb(struct gsm_lchan *lchan, uint8_t link_id, void *_data, enum bsc_rllr_ind rllr_ind)
{
	struct msgb *msg = _data;

	/*
	 * There seems to be a small window that the RLL timer can
	 * fire after a lchan_release call and before the S_CHALLOC_FREED
	 * is called. Check if a conn is set before proceeding.
	 */
	if (!lchan->conn) {
		msgb_free(msg);
		return;
	}

	switch (rllr_ind) {
	case BSC_RLLR_IND_EST_CONF:
		rsl_data_request(msg, OBSC_LINKID_CB(msg));
		break;
	case BSC_RLLR_IND_REL_IND:
		bsc_sapi_n_reject(lchan->conn, OBSC_LINKID_CB(msg),
				  GSM0808_CAUSE_MS_NOT_EQUIPPED);
		msgb_free(msg);
		break;
	case BSC_RLLR_IND_ERR_IND:
	case BSC_RLLR_IND_TIMEOUT:
		bsc_sapi_n_reject(lchan->conn, OBSC_LINKID_CB(msg),
				  GSM0808_CAUSE_BSS_NOT_EQUIPPED);
		msgb_free(msg);
		break;
	}
}

/*! \brief process incoming 08.08 DTAP from MSC (send via BTS to MS) */
static void gsm0808_send_rsl_dtap(struct gsm_subscriber_connection *conn,
				  struct msgb *msg, int link_id, int allow_sacch)
{
	uint8_t sapi;
	int rc;

	if (!conn->lchan) {
		LOGP(DMSC, LOGL_ERROR,
		     "%s Called submit dtap without an lchan.\n",
		     bsc_subscr_name(conn->bsub));
		msgb_free(msg);
		rc = -EINVAL;
		goto failed_to_send;
	}

	sapi = link_id & 0x7;
	msg->lchan = conn->lchan;
	msg->dst = msg->lchan->ts->trx->rsl_link;

	/* If we are on a TCH and need to submit a SMS (on SAPI=3) we need to use the SACH */
	if (allow_sacch && sapi != 0) {
		if (conn->lchan->type == GSM_LCHAN_TCH_F || conn->lchan->type == GSM_LCHAN_TCH_H)
			link_id |= 0x40;
	}

	msg->l3h = msg->data;
	/* is requested SAPI already up? */
	if (conn->lchan->sapis[sapi] == LCHAN_SAPI_UNUSED) {
		/* Establish L2 for additional SAPI */
		OBSC_LINKID_CB(msg) = link_id;
		rc = rll_establish(msg->lchan, sapi, rll_ind_cb, msg);
		if (rc) {
			msgb_free(msg);
			bsc_sapi_n_reject(conn, link_id, GSM0808_CAUSE_BSS_NOT_EQUIPPED);
			goto failed_to_send;
		}
		return;
	} else {
		/* Directly forward via RLL/RSL to BTS */
		rc = rsl_data_request(msg, link_id);
		if (rc)
			goto failed_to_send;
	}
	return;

failed_to_send:
	LOGPFSML(conn->fi, LOGL_ERROR, "Tx BSSMAP CLEAR REQUEST to MSC\n");
	gscon_bssmap_clear(conn, GSM0808_CAUSE_EQUIPMENT_FAILURE);
	osmo_fsm_inst_state_chg(conn->fi, ST_ACTIVE, 0, 0);
}

void gscon_submit_rsl_dtap(struct gsm_subscriber_connection *conn,
			   struct msgb *msg, int link_id, int allow_sacch)
{
	/* buffer message during assignment / handover */
	if (conn->fi->state != ST_ACTIVE) {
		gscon_dtap_queue_add(conn, msg, link_id, !! allow_sacch);
		return;
	}

	gsm0808_send_rsl_dtap(conn, msg, link_id, allow_sacch);
}

/* Compose an FSM ID, if possible from the current subscriber information */
void gscon_update_id(struct gsm_subscriber_connection *conn)
{
	osmo_fsm_inst_update_id_f(conn->fi, "msc%u-conn%u%s%s",
				  conn->sccp.msc ? conn->sccp.msc->nr : UINT_MAX,
				  conn->sccp.conn_id,
				  conn->bsub? "_" : "",
				  conn->bsub? bsc_subscr_id(conn->bsub) : "");
}

bool gscon_is_aoip(struct gsm_subscriber_connection *conn)
{
	if (!conn || !conn->sccp.msc)
		return false;

	return msc_is_aoip(conn->sccp.msc);
}

bool gscon_is_sccplite(struct gsm_subscriber_connection *conn)
{
	if (!conn || !conn->sccp.msc)
		return false;

	return msc_is_sccplite(conn->sccp.msc);
}
