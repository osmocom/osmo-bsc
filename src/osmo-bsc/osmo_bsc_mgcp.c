/* (C) 2017 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Philipp Maier
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

#include <osmocom/mgcp_client/mgcp_client.h>
#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/osmo_bsc_mgcp.h>
#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/osmo_bsc.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/fsm.h>
#include <osmocom/bsc/osmo_bsc_sigtran.h>
#include <osmocom/core/byteswap.h>
#include <arpa/inet.h>

#define CONN_ID_BTS 1
#define CONN_ID_NET 2

#define MGCP_MGW_TIMEOUT 4	/* in seconds */
#define MGCP_MGW_TIMEOUT_TIMER_NR 1
#define MGCP_BSS_TIMEOUT 4	/* in seconds */
#define MGCP_BSS_TIMEOUT_TIMER_NR 2

#define MGCP_ENDPOINT_FORMAT "%i@mgw"

/* Some internal cause codes to indicate fault
 * condition inside the FSM */
enum int_cause_code {
	MGCP_ERR_MGW_FAIL,
	MGCP_ERR_MGW_INVAL_RESP,
	MGCP_ERR_MGW_TX_FAIL,
	MGCP_ERR_UNEXP_TEARDOWN,
	MGCP_ERR_ASSGMNT_FAIL,
	MGCP_ERR_UNSUPP_ADDR_FMT,
	MGCP_ERR_BSS_TIMEOUT,
	MGCP_ERR_NOMEM
};

/* Human readable respresentation of the faul codes,
 * will be displayed by handle_error() */
static const struct value_string int_cause_codes_str[] = {
	{MGCP_ERR_MGW_FAIL, "operation failed on MGW"},
	{MGCP_ERR_MGW_INVAL_RESP, "invalid / unparseable response from MGW"},
	{MGCP_ERR_MGW_TX_FAIL, "failed to transmit MGCP message to MGW"},
	{MGCP_ERR_UNEXP_TEARDOWN, "unexpected connection teardown (BSS)"},
	{MGCP_ERR_ASSGMNT_FAIL, "assignment failure (BSS)"},
	{MGCP_ERR_UNSUPP_ADDR_FMT, "unsupported network address format used (MSC)"},
	{MGCP_ERR_BSS_TIMEOUT, "assignment could not be completed in time (BSS)"},
	{MGCP_ERR_NOMEM, "out of memory"},
	{0, NULL}
};

enum fsm_bsc_mgcp_states {
	ST_CRCX_BTS,
	ST_ASSIGN_PROC,
	ST_MDCX_BTS,
	ST_CRCX_NET,
	ST_ASSIGN_COMPL,
	ST_CALL,
	ST_MDCX_BTS_HO,
	ST_HALT
};

static const struct value_string fsm_bsc_mgcp_state_names[] = {
	{ST_CRCX_BTS, "ST_CRCX_BTS (send CRCX for BTS)"},
	{ST_ASSIGN_PROC, "ST_ASSIGN_PROC (continue assignment)"},
	{ST_MDCX_BTS, "ST_MDCX_BTS (send MDCX for BTS)"},
	{ST_CRCX_NET, "ST_CRCX_NET (send CRCX for NET)"},
	{ST_ASSIGN_COMPL, "ST_ASSIGN_COMPL (complete assignment)"},
	{ST_CALL, "ST_CALL (call in progress)"},
	{ST_MDCX_BTS_HO, "ST_MDCX_BTS_HO (handover to new BTS)"},
	{ST_HALT, "ST_HALT (destroy state machine)"},
	{0, NULL}
};

enum fsm_evt {
	/* Initial event: start off the state machine */
	EV_INIT,

	/* External event: Assignment complete, event is issued shortly before
	 * the assignment complete message is sent via the A-Interface */
	EV_ASS_COMPLETE,

	/* External event: Teardown event, this event is used to notify the end
	 * of a call. It is also issued in case of errors to teardown a half
	 * open connection. */
	EV_TEARDOWN,

	/* External event: Handover event, this event notifies the FSM that a
	 * handover is required. The FSM will then perform an extra MDCX to
	 * configure the new connection data at the MGW. The only valid state
	 * where a Handover event can be received is ST_CALL. */
	EV_HANDOVER,

	/* Internal event: The mgcp_gw has sent its CRCX response for
	 * the BTS side */
	EV_CRCX_BTS_RESP,

	/* Internal event: The mgcp_gw has sent its MDCX response for
	 * the BTS side */
	EV_MDCX_BTS_RESP,

	/* Internal event: The mgcp_gw has sent its CRCX response for
	 * the NET side */
	EV_CRCX_NET_RESP,

	/* Internal event: The mgcp_gw has sent its DLCX response for
	 * the NET and BTS side */
	EV_DLCX_ALL_RESP,

	/* Internal event: The mgcp_gw has responded to the (Handover-)
	   MDCX that has been send to update the BTS connection. */
	EV_MDCX_BTS_HO_RESP,
};

static const struct value_string fsm_evt_names[] = {
	{EV_INIT, "EV_INIT (start state machine, send CRCX for BTS)"},
	{EV_ASS_COMPLETE, "EV_ASS_COMPLETE (assignment complete)"},
	{EV_TEARDOWN, "EV_TEARDOWN (teardown all connections)"},
	{EV_HANDOVER, "EV_HANDOVER (handover bts connection)"},
	{EV_CRCX_BTS_RESP, "EV_CRCX_BTS_RESP (got CRCX reponse for BTS)"},
	{EV_MDCX_BTS_RESP, "EV_MDCX_BTS_RESP (got MDCX reponse for BTS)"},
	{EV_CRCX_NET_RESP, "EV_CRCX_NET_RESP (got CRCX reponse for NET)"},
	{EV_DLCX_ALL_RESP, "EV_DLCX_ALL_RESP (got DLCX reponse for BTS/NET)"},
	{EV_MDCX_BTS_HO_RESP, "EV_MDCX_BTS_HO_RESP (got MDCX reponse for BTS Handover)"},
	{0, NULL}
};

/* A general error handler function. On error we still have an interest to
 * remove a half open connection (if possible). This function will execute
 * a controlled jump to the DLCX phase. From there, the FSM will then just
 * continue like the call were ended normally */
static void handle_error(struct mgcp_ctx *mgcp_ctx, enum int_cause_code cause)
{
	struct osmo_fsm_inst *fi;
	struct osmo_bsc_sccp_con *conn;

	OSMO_ASSERT(mgcp_ctx);
	conn = mgcp_ctx->conn;
	OSMO_ASSERT(conn);

	fi = mgcp_ctx->fsm;
	OSMO_ASSERT(fi);

	LOGPFSML(mgcp_ctx->fsm, LOGL_DEBUG, "fsm-state: %s\n", get_value_string(fsm_bsc_mgcp_state_names, fi->state));

	LOGPFSML(mgcp_ctx->fsm, LOGL_ERROR, "%s -- graceful shutdown...\n",
		 get_value_string(int_cause_codes_str, cause));

	/* Set the VM into the state where it waits for the call end */
	osmo_fsm_inst_state_chg(fi, ST_CALL, 0, 0);

	/* Simulate the call end by sending a teardown event, so that
	 * the FSM proceeds directly with the DLCX */
	osmo_fsm_inst_dispatch(mgcp_ctx->fsm, EV_TEARDOWN, mgcp_ctx);
}

static void crcx_for_bts_resp_cb(struct mgcp_response *r, void *priv);

/* Callback for ST_CRCX_BTS: startup state machine send out CRCX for BTS side */
static void fsm_crcx_bts_cb(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct mgcp_ctx *mgcp_ctx = (struct mgcp_ctx *)data;
	struct osmo_bsc_sccp_con *conn;
	struct msgb *msg;
	struct mgcp_msg mgcp_msg;
	struct mgcp_client *mgcp;
	uint16_t rtp_endpoint;
	int rc;

	OSMO_ASSERT(mgcp_ctx);
	conn = mgcp_ctx->conn;
	OSMO_ASSERT(conn);
	mgcp = mgcp_ctx->mgcp;
	OSMO_ASSERT(mgcp);

	LOGPFSML(mgcp_ctx->fsm, LOGL_DEBUG,
		 "fsm-state: %s, fsm-event: %s\n",
		 get_value_string(fsm_bsc_mgcp_state_names, fi->state), get_value_string(fsm_evt_names, event));

	rtp_endpoint = mgcp_client_next_endpoint(mgcp);
	mgcp_ctx->rtp_endpoint = rtp_endpoint;

	LOGPFSML(mgcp_ctx->fsm, LOGL_DEBUG,
		 "creating connection for the BTS side on " "MGW endpoint:%x...\n", rtp_endpoint);

	/* Generate MGCP message string */
	mgcp_msg = (struct mgcp_msg) {
		.verb = MGCP_VERB_CRCX,
		.presence = (MGCP_MSG_PRESENCE_ENDPOINT | MGCP_MSG_PRESENCE_CALL_ID | MGCP_MSG_PRESENCE_CONN_ID |
			     MGCP_MSG_PRESENCE_CONN_MODE),
		.call_id = conn->conn_id,
		.conn_id = CONN_ID_BTS,
		.conn_mode = MGCP_CONN_LOOPBACK
	};
	if (snprintf(mgcp_msg.endpoint, MGCP_ENDPOINT_MAXLEN, MGCP_ENDPOINT_FORMAT, rtp_endpoint) >=
	    MGCP_ENDPOINT_MAXLEN) {
		handle_error(mgcp_ctx, MGCP_ERR_NOMEM);
		return;
	}
	msg = mgcp_msg_gen(mgcp, &mgcp_msg);
	OSMO_ASSERT(msg);

	/* Transmit MGCP message to MGW */
	LOGPFSML(mgcp_ctx->fsm, LOGL_DEBUG, "CRCX/BTS: transmitting MGCP message to MGW...\n");
	rc = mgcp_client_tx(mgcp, msg, crcx_for_bts_resp_cb, mgcp_ctx);
	if (rc < 0) {
		handle_error(mgcp_ctx, MGCP_ERR_MGW_TX_FAIL);
		return;
	}

	osmo_fsm_inst_state_chg(mgcp_ctx->fsm, ST_ASSIGN_PROC, MGCP_MGW_TIMEOUT, MGCP_MGW_TIMEOUT_TIMER_NR);
}

/* Callback for MGCP-Client: handle response for BTS associated CRCX */
static void crcx_for_bts_resp_cb(struct mgcp_response *r, void *priv)
{
	struct mgcp_ctx *mgcp_ctx = priv;
	int rc;
	struct osmo_bsc_sccp_con *conn;

	OSMO_ASSERT(mgcp_ctx);
	conn = mgcp_ctx->conn;
	OSMO_ASSERT(conn);

	if (mgcp_ctx->fsm == NULL) {
		LOGP(DMGCP, LOGL_ERROR,
		     "CRCX/BTS: late MGW response, FSM already terminated -- ignoring...\n");
		return;
	}

	if (r->head.response_code != 200) {
		LOGPFSML(mgcp_ctx->fsm, LOGL_ERROR,
			 "CRCX/BTS: response yields error: %d %s\n", r->head.response_code, r->head.comment);
		handle_error(mgcp_ctx, MGCP_ERR_MGW_FAIL);
		return;
	}

	rc = mgcp_response_parse_params(r);
	if (rc) {
		LOGPFSML(mgcp_ctx->fsm, LOGL_ERROR, "CRCX/BTS: Cannot parse response\n");
		handle_error(mgcp_ctx, MGCP_ERR_MGW_INVAL_RESP);
		return;
	}

	LOGPFSML(mgcp_ctx->fsm, LOGL_DEBUG, "CRCX/BTS: MGW responded with address %s:%u\n", r->audio_ip, r->audio_port);

	/* Set the connection details in the conn struct. The code that
	 * controls the BTS via RSL will take these values and signal them
	 * to the BTS via RSL/IPACC */
	conn->rtp_port = r->audio_port;
	conn->rtp_ip = osmo_ntohl(inet_addr(r->audio_ip));

	/* Notify the FSM that we got the response. */
	osmo_fsm_inst_dispatch(mgcp_ctx->fsm, EV_CRCX_BTS_RESP, mgcp_ctx);
}

/* Callback for ST_ASSIGN_PROC: An mgcp response has been received, proceed
 * with the assignment request */
static void fsm_proc_assignmnent_req_cb(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct mgcp_ctx *mgcp_ctx = (struct mgcp_ctx *)data;
	struct osmo_bsc_sccp_con *conn;
	enum gsm48_chan_mode chan_mode;
	bool full_rate;
	int rc;

	OSMO_ASSERT(mgcp_ctx);
	conn = mgcp_ctx->conn;
	OSMO_ASSERT(conn);

	LOGPFSML(mgcp_ctx->fsm, LOGL_DEBUG,
		 "fsm-state: %s, fsm-event: %s\n",
		 get_value_string(fsm_bsc_mgcp_state_names, fi->state), get_value_string(fsm_evt_names, event));

	switch (event) {
	case EV_CRCX_BTS_RESP:
		break;
	default:
		handle_error(mgcp_ctx, MGCP_ERR_UNEXP_TEARDOWN);
		return;
	}

	OSMO_ASSERT(conn->conn);
	chan_mode = mgcp_ctx->chan_mode;
	full_rate = mgcp_ctx->full_rate;

	LOGPFSML(mgcp_ctx->fsm, LOGL_DEBUG, "MGW proceeding assignment request...\n");
	rc = gsm0808_assign_req(conn->conn, chan_mode, full_rate);

	if (rc < 0) {
		handle_error(mgcp_ctx, MGCP_ERR_ASSGMNT_FAIL);
		return;
	}

	osmo_fsm_inst_state_chg(fi, ST_MDCX_BTS, MGCP_BSS_TIMEOUT, MGCP_BSS_TIMEOUT_TIMER_NR);
}

static void mdcx_for_bts_resp_cb(struct mgcp_response *r, void *priv);

/* Callback for ST_MDCX_BTS: When the BSS has completed the assignment,
 * proceed with updating the connection for the BTS side */
static void fsm_mdcx_bts_cb(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct mgcp_ctx *mgcp_ctx = (struct mgcp_ctx *)data;
	struct osmo_bsc_sccp_con *conn;
	struct gsm_lchan *lchan;
	struct msgb *msg;
	struct mgcp_msg mgcp_msg;
	struct mgcp_client *mgcp;
	uint16_t rtp_endpoint;
	struct in_addr addr;
	int rc;

	OSMO_ASSERT(mgcp_ctx);
	conn = mgcp_ctx->conn;
	OSMO_ASSERT(conn);

	LOGPFSML(mgcp_ctx->fsm, LOGL_DEBUG,
		 "fsm-state: %s, fsm-event: %s\n",
		 get_value_string(fsm_bsc_mgcp_state_names, fi->state), get_value_string(fsm_evt_names, event));

	switch (event) {
	case EV_ASS_COMPLETE:
		break;
	default:
		handle_error(mgcp_ctx, MGCP_ERR_UNEXP_TEARDOWN);
		return;
	}

	mgcp = mgcp_ctx->mgcp;
	OSMO_ASSERT(mgcp);
	lchan = mgcp_ctx->lchan;
	OSMO_ASSERT(lchan);

	LOGPFSML(mgcp_ctx->fsm, LOGL_DEBUG, "BSS has completed the assignment, now prceed with MDCX towards BTS...\n");

	rtp_endpoint = mgcp_ctx->rtp_endpoint;

	LOGPFSML(mgcp_ctx->fsm, LOGL_DEBUG,
		 "completing connection for the BTS side on " "MGW endpoint:%x...\n", rtp_endpoint);

	addr.s_addr = osmo_ntohl(lchan->abis_ip.bound_ip);
	LOGPFSML(mgcp_ctx->fsm, LOGL_DEBUG,
		 "BTS expects RTP input on address %s:%u\n", inet_ntoa(addr), lchan->abis_ip.bound_port);

	/* Generate MGCP message string */
	mgcp_msg = (struct mgcp_msg) {
		.verb = MGCP_VERB_MDCX,
		.presence = (MGCP_MSG_PRESENCE_ENDPOINT | MGCP_MSG_PRESENCE_CALL_ID | MGCP_MSG_PRESENCE_CONN_ID |
			     MGCP_MSG_PRESENCE_CONN_MODE | MGCP_MSG_PRESENCE_AUDIO_IP | MGCP_MSG_PRESENCE_AUDIO_PORT),
		.call_id = conn->conn_id,
		.conn_id = CONN_ID_BTS,
		.conn_mode = MGCP_CONN_RECV_SEND,
		.audio_ip = inet_ntoa(addr),
		.audio_port = lchan->abis_ip.bound_port
	};
	if (snprintf(mgcp_msg.endpoint, sizeof(mgcp_msg.endpoint), MGCP_ENDPOINT_FORMAT, rtp_endpoint) >=
	    sizeof(mgcp_msg.endpoint)) {
		handle_error(mgcp_ctx, MGCP_ERR_NOMEM);
		return;
	}
	msg = mgcp_msg_gen(mgcp, &mgcp_msg);
	OSMO_ASSERT(msg);

	/* Transmit MGCP message to MGW */
	LOGPFSML(mgcp_ctx->fsm, LOGL_DEBUG, "MDCX/BTS: transmitting MGCP message to MGW...\n");
	rc = mgcp_client_tx(mgcp, msg, mdcx_for_bts_resp_cb, mgcp_ctx);
	if (rc < 0) {
		handle_error(mgcp_ctx, MGCP_ERR_MGW_TX_FAIL);
		return;
	}

	osmo_fsm_inst_state_chg(mgcp_ctx->fsm, ST_CRCX_NET, MGCP_MGW_TIMEOUT, MGCP_MGW_TIMEOUT_TIMER_NR);
}

/* Callback for MGCP-Client: handle response for BTS associated MDCX */
static void mdcx_for_bts_resp_cb(struct mgcp_response *r, void *priv)
{
	struct mgcp_ctx *mgcp_ctx = priv;
	int rc;
	struct in_addr addr;
	struct gsm_lchan *lchan;

	OSMO_ASSERT(mgcp_ctx);
	lchan = mgcp_ctx->lchan;
	OSMO_ASSERT(lchan);

	if (mgcp_ctx->fsm == NULL) {
		LOGP(DMGCP, LOGL_ERROR,
		     "MDCX/BTS: late MGW response, FSM already terminated -- ignoring...\n");
		return;
	}

	if (r->head.response_code != 200) {
		LOGPFSML(mgcp_ctx->fsm, LOGL_ERROR,
			 "MDCX/BTS: response yields error: %d %s\n", r->head.response_code, r->head.comment);
		handle_error(mgcp_ctx, MGCP_ERR_MGW_FAIL);
		return;
	}

	rc = mgcp_response_parse_params(r);
	if (rc) {
		LOGPFSML(mgcp_ctx->fsm, LOGL_ERROR, "MDCX/BTS: Cannot parse MDCX response\n");
		handle_error(mgcp_ctx, MGCP_ERR_MGW_INVAL_RESP);
		return;
	}

	LOGPFSML(mgcp_ctx->fsm, LOGL_DEBUG, "MDCX/BTS: MGW responded with address %s:%u\n", r->audio_ip, r->audio_port);

	addr.s_addr = lchan->abis_ip.bound_ip;
	LOGPFSML(mgcp_ctx->fsm, LOGL_DEBUG,
		 "MDCX/BTS: corresponding lchan has been bound to address %s:%u\n",
		 inet_ntoa(addr), lchan->abis_ip.bound_port);

	/* Notify the FSM that we got the response. */
	osmo_fsm_inst_dispatch(mgcp_ctx->fsm, EV_MDCX_BTS_RESP, mgcp_ctx);
}

static void crcx_for_net_resp_cb(struct mgcp_response *r, void *priv);

/* Callback for ST_CRCX_NET: An mgcp response has been received, proceed... */
static void fsm_crcx_net_cb(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct mgcp_ctx *mgcp_ctx = (struct mgcp_ctx *)data;
	struct osmo_bsc_sccp_con *conn;
	struct msgb *msg;
	struct mgcp_msg mgcp_msg;
	struct mgcp_client *mgcp;
	uint16_t rtp_endpoint;
	struct sockaddr_in *sin;
	char *addr;
	uint16_t port;
	int rc;

	OSMO_ASSERT(mgcp_ctx);
	conn = mgcp_ctx->conn;
	OSMO_ASSERT(conn);
	mgcp = mgcp_ctx->mgcp;
	OSMO_ASSERT(mgcp);

	LOGPFSML(mgcp_ctx->fsm, LOGL_DEBUG,
		 "fsm-state: %s, fsm-event: %s\n",
		 get_value_string(fsm_bsc_mgcp_state_names, fi->state), get_value_string(fsm_evt_names, event));

	rtp_endpoint = mgcp_ctx->rtp_endpoint;

	LOGPFSML(mgcp_ctx->fsm, LOGL_DEBUG,
		 "creating connection for the NET side on " "MGW endpoint:%x...\n", rtp_endpoint);

	/* Currently we only have support for IPv4 in our MGCP software, the
	 * AoIP part is ready to support IPv6 in theory, because the IE
	 * parser/generator uses sockaddr_storage for the AoIP transport
	 * identifier. However, the MGCP-GW does not support IPv6 yet. This is
	 * why we stop here in case some MSC tries to signal IPv6 AoIP
	 * transport identifiers */
	if (conn->aoip_rtp_addr_remote.ss_family != AF_INET) {
		LOGPFSML(mgcp_ctx->fsm, LOGL_ERROR,
			 "endpoint:%x MSC uses unsupported address format in AoIP transport identifier -- aborting...\n",
			 rtp_endpoint);
		handle_error(mgcp_ctx, MGCP_ERR_UNSUPP_ADDR_FMT);
		return;
	}

	sin = (struct sockaddr_in *)&conn->aoip_rtp_addr_remote;
	addr = inet_ntoa(sin->sin_addr);
	port = osmo_ntohs(sin->sin_port);
	LOGPFSML(mgcp_ctx->fsm, LOGL_DEBUG, "MSC expects RTP input on address %s:%u\n", addr, port);

	/* Generate MGCP message string */
	mgcp_msg = (struct mgcp_msg) {
		.verb = MGCP_VERB_CRCX,
		.presence = (MGCP_MSG_PRESENCE_ENDPOINT | MGCP_MSG_PRESENCE_CALL_ID | MGCP_MSG_PRESENCE_CONN_ID |
			     MGCP_MSG_PRESENCE_CONN_MODE | MGCP_MSG_PRESENCE_AUDIO_IP | MGCP_MSG_PRESENCE_AUDIO_PORT),
		.call_id = conn->conn_id,
		.conn_id = CONN_ID_NET,
		.conn_mode = MGCP_CONN_RECV_SEND,
		.audio_ip = addr,
		.audio_port = port
	};
	if (snprintf(mgcp_msg.endpoint, sizeof(mgcp_msg.endpoint), MGCP_ENDPOINT_FORMAT, rtp_endpoint) >=
	    sizeof(mgcp_msg.endpoint)) {
		handle_error(mgcp_ctx, MGCP_ERR_NOMEM);
		return;
	}
	msg = mgcp_msg_gen(mgcp, &mgcp_msg);
	OSMO_ASSERT(msg);

	/* Transmit MGCP message to MGW */
	LOGPFSML(mgcp_ctx->fsm, LOGL_DEBUG, "CRCX/NET: transmitting MGCP message to MGW...\n");
	rc = mgcp_client_tx(mgcp, msg, crcx_for_net_resp_cb, mgcp_ctx);
	if (rc < 0) {
		handle_error(mgcp_ctx, MGCP_ERR_MGW_TX_FAIL);
		return;
	}

	osmo_fsm_inst_state_chg(mgcp_ctx->fsm, ST_ASSIGN_COMPL, MGCP_MGW_TIMEOUT, MGCP_MGW_TIMEOUT_TIMER_NR);
}

/* Callback for MGCP-Client: handle response for NET associated CRCX */
static void crcx_for_net_resp_cb(struct mgcp_response *r, void *priv)
{
	struct mgcp_ctx *mgcp_ctx = priv;
	int rc;
	struct osmo_bsc_sccp_con *conn;
	struct gsm_lchan *lchan;
	struct sockaddr_in *sin;

	OSMO_ASSERT(mgcp_ctx);
	conn = mgcp_ctx->conn;
	OSMO_ASSERT(conn);
	lchan = mgcp_ctx->lchan;
	OSMO_ASSERT(lchan);

	if (mgcp_ctx->fsm == NULL) {
		LOGP(DMGCP, LOGL_ERROR,
		     "CRCX/NET: late MGW response, FSM already terminated -- ignoring...\n");
		return;
	}

	if (r->head.response_code != 200) {
		LOGPFSML(mgcp_ctx->fsm, LOGL_ERROR,
			 "CRCX/NET: response yields error: %d %s\n", r->head.response_code, r->head.comment);
		handle_error(mgcp_ctx, MGCP_ERR_MGW_FAIL);
		return;
	}

	rc = mgcp_response_parse_params(r);
	if (rc) {
		LOGPFSML(mgcp_ctx->fsm, LOGL_ERROR, "CRCX/NET: Cannot parse CRCX response\n");
		handle_error(mgcp_ctx, MGCP_ERR_MGW_INVAL_RESP);
		return;
	}

	LOGPFSML(mgcp_ctx->fsm, LOGL_DEBUG, "CRCX/NET: MGW responded with address %s:%u\n", r->audio_ip, r->audio_port);

	/* Store address */
	sin = (struct sockaddr_in *)&conn->aoip_rtp_addr_local;
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = inet_addr(r->audio_ip);
	sin->sin_port = osmo_ntohs(r->audio_port);

	/* Notify the FSM that we got the response. */
	osmo_fsm_inst_dispatch(mgcp_ctx->fsm, EV_CRCX_NET_RESP, mgcp_ctx);
}

/* Callback for ST_ASSIGN_COMPL: Send back assignment complete and wait until the call ends */
static void fsm_send_assignment_complete(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct mgcp_ctx *mgcp_ctx = (struct mgcp_ctx *)data;
	struct gsm_lchan *lchan;

	OSMO_ASSERT(mgcp_ctx);

	LOGPFSML(mgcp_ctx->fsm, LOGL_DEBUG,
		 "fsm-state: %s, fsm-event: %s\n",
		 get_value_string(fsm_bsc_mgcp_state_names, fi->state), get_value_string(fsm_evt_names, event));

	switch (event) {
	case EV_CRCX_NET_RESP:
		break;
	default:
		handle_error(mgcp_ctx, MGCP_ERR_UNEXP_TEARDOWN);
		return;
	}

	lchan = mgcp_ctx->lchan;
	OSMO_ASSERT(lchan);

	/* Send assignment completion message via AoIP, this will complete
	 * the circuit. The message will also contain the port and IP-Address
	 * where the MGW expects the RTP input from the MSC side */
	bssmap_send_aoip_ass_compl(lchan);

	LOGPFSML(mgcp_ctx->fsm, LOGL_DEBUG, "call in progress, waiting for call end...\n");

	osmo_fsm_inst_state_chg(mgcp_ctx->fsm, ST_CALL, 0, 0);
}

static void dlcx_for_all_resp_cb(struct mgcp_response *r, void *priv);
static void mdcx_for_bts_ho_resp_cb(struct mgcp_response *r, void *priv);

/* Helper function to perform a connection teardown. This function may be
 * called from ST_CALL and ST_MDCX_BTS_HO only. It will perform a state
 * change to ST_HALT when teardown is done. */
static void handle_teardown(struct mgcp_ctx *mgcp_ctx)
{
	struct osmo_bsc_sccp_con *conn;
	struct msgb *msg;
	struct mgcp_msg mgcp_msg;
	struct mgcp_client *mgcp;
	uint16_t rtp_endpoint;
	int rc;

	OSMO_ASSERT(mgcp_ctx);
	conn = mgcp_ctx->conn;
	OSMO_ASSERT(conn);
	mgcp = mgcp_ctx->mgcp;
	OSMO_ASSERT(mgcp);

	rtp_endpoint = mgcp_ctx->rtp_endpoint;

	LOGPFSML(mgcp_ctx->fsm, LOGL_DEBUG,
		 "DLCX: removing connection for the BTS and NET side on MGW endpoint:%x...\n", rtp_endpoint);

	/* We now relase the endpoint back to the pool in order to allow
	 * other connections to use this endpoint */
	mgcp_client_release_endpoint(rtp_endpoint, mgcp);

	/* Generate MGCP message string */
	mgcp_msg = (struct mgcp_msg) {
		.verb = MGCP_VERB_DLCX,
		.presence = (MGCP_MSG_PRESENCE_ENDPOINT | MGCP_MSG_PRESENCE_CALL_ID),
		.call_id = conn->conn_id
	};
	if (snprintf(mgcp_msg.endpoint, sizeof(mgcp_msg.endpoint), MGCP_ENDPOINT_FORMAT, rtp_endpoint) >=
	    sizeof(mgcp_msg.endpoint)) {
		handle_error(mgcp_ctx, MGCP_ERR_NOMEM);
		return;
	}
	msg = mgcp_msg_gen(mgcp, &mgcp_msg);
	OSMO_ASSERT(msg);

	/* Transmit MGCP message to MGW */
	LOGPFSML(mgcp_ctx->fsm, LOGL_DEBUG, "DLCX: transmitting MGCP message to MGW...\n");
	rc = mgcp_client_tx(mgcp, msg, dlcx_for_all_resp_cb, mgcp_ctx);
	if (rc < 0) {
		handle_error(mgcp_ctx, MGCP_ERR_MGW_TX_FAIL);
		return;
	}

	osmo_fsm_inst_state_chg(mgcp_ctx->fsm, ST_HALT, MGCP_MGW_TIMEOUT, MGCP_MGW_TIMEOUT_TIMER_NR);
}

/* Helper function to perform a handover (MDCX). This function may be
 * called from ST_CALL and ST_MDCX_BTS_HO only. It will perform a state
 * change to ST_CALL when teardown is done. */
static void handle_handover(struct mgcp_ctx *mgcp_ctx)
{
	struct osmo_bsc_sccp_con *conn;
	struct msgb *msg;
	struct mgcp_msg mgcp_msg;
	struct mgcp_client *mgcp;
	struct gsm_lchan *ho_lchan;
	uint16_t rtp_endpoint;
	struct in_addr addr;
	int rc;

	OSMO_ASSERT(mgcp_ctx);
	conn = mgcp_ctx->conn;
	OSMO_ASSERT(conn);
	mgcp = mgcp_ctx->mgcp;
	OSMO_ASSERT(mgcp);
	ho_lchan = mgcp_ctx->ho_lchan;
	OSMO_ASSERT(ho_lchan);

	rtp_endpoint = mgcp_ctx->rtp_endpoint;

	LOGPFSML(mgcp_ctx->fsm, LOGL_DEBUG,
		 "MDCX/BTS/HO: handover connection from old BTS to new BTS side on MGW endpoint:%x...\n", rtp_endpoint);

	addr.s_addr = osmo_ntohl(ho_lchan->abis_ip.bound_ip);
	LOGPFSML(mgcp_ctx->fsm, LOGL_DEBUG,
		 "MDCX/BTS/HO: new BTS expects RTP input on address %s:%u\n", inet_ntoa(addr),
		 ho_lchan->abis_ip.bound_port);

	/* Generate MGCP message string */
	mgcp_msg = (struct mgcp_msg) {
		.verb = MGCP_VERB_MDCX,
		.presence = (MGCP_MSG_PRESENCE_ENDPOINT | MGCP_MSG_PRESENCE_CALL_ID | MGCP_MSG_PRESENCE_CONN_ID |
			     MGCP_MSG_PRESENCE_CONN_MODE | MGCP_MSG_PRESENCE_AUDIO_IP |
			     MGCP_MSG_PRESENCE_AUDIO_PORT),.call_id = conn->conn_id,.conn_id = CONN_ID_BTS,
		.conn_mode = MGCP_CONN_RECV_SEND,
		.audio_ip = inet_ntoa(addr),
		.audio_port = ho_lchan->abis_ip.bound_port};
	if (snprintf(mgcp_msg.endpoint, sizeof(mgcp_msg.endpoint), MGCP_ENDPOINT_FORMAT, rtp_endpoint) >=
	    sizeof(mgcp_msg.endpoint)) {
		handle_error(mgcp_ctx, MGCP_ERR_NOMEM);
		return;
	}
	msg = mgcp_msg_gen(mgcp, &mgcp_msg);
	OSMO_ASSERT(msg);

	LOGPFSML(mgcp_ctx->fsm, LOGL_DEBUG, "MDCX/BTS/HO: transmitting MGCP message to MGW...\n");
	rc = mgcp_client_tx(mgcp, msg, mdcx_for_bts_ho_resp_cb, mgcp_ctx);
	if (rc < 0) {
		handle_error(mgcp_ctx, MGCP_ERR_MGW_TX_FAIL);
		return;
	}

	osmo_fsm_inst_state_chg(mgcp_ctx->fsm, ST_MDCX_BTS_HO, MGCP_MGW_TIMEOUT, MGCP_MGW_TIMEOUT_TIMER_NR);
}

/* Callback for ST_CALL: Handle call teardown and Handover */
static void fsm_active_call_cb(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct mgcp_ctx *mgcp_ctx = data;

	OSMO_ASSERT(mgcp_ctx);

	LOGPFSML(mgcp_ctx->fsm, LOGL_DEBUG,
		 "fsm-state: %s, fsm-event: %s\n",
		 get_value_string(fsm_bsc_mgcp_state_names, fi->state), get_value_string(fsm_evt_names, event));

	switch (event) {
	case EV_TEARDOWN:
		handle_teardown(mgcp_ctx);
		break;
	case EV_HANDOVER:
		handle_handover(mgcp_ctx);
		break;
	}

}

/* Callback for MGCP-Client: handle response for BTS/Handover associated MDCX */
static void mdcx_for_bts_ho_resp_cb(struct mgcp_response *r, void *priv)
{
	struct mgcp_ctx *mgcp_ctx = priv;

	OSMO_ASSERT(mgcp_ctx);

	if (mgcp_ctx->fsm == NULL) {
		LOGP(DMGCP, LOGL_ERROR, "MDCX/BTS/HO: late MGW response, FSM already terminated -- ignoring...\n");
		return;
	}

	if (r->head.response_code != 200) {
		LOGPFSML(mgcp_ctx->fsm, LOGL_ERROR,
			 "MDCX/BTS/HO: response yields error: %d %s\n", r->head.response_code, r->head.comment);
		handle_error(mgcp_ctx, MGCP_ERR_MGW_FAIL);
		return;
	}

	/* Notify the FSM that we got the response. */
	osmo_fsm_inst_dispatch(mgcp_ctx->fsm, EV_MDCX_BTS_HO_RESP, mgcp_ctx);
}

/* Callback for ST_MDCX_BTS_HO: Complete updating the connection data after
 * handoverin the call to another BTS */
static void fsm_complete_handover(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct mgcp_ctx *mgcp_ctx = (struct mgcp_ctx *)data;

	OSMO_ASSERT(mgcp_ctx);

	LOGPFSML(mgcp_ctx->fsm, LOGL_DEBUG,
		 "fsm-state: %s, fsm-event: %s\n",
		 get_value_string(fsm_bsc_mgcp_state_names, fi->state), get_value_string(fsm_evt_names, event));

	switch (event) {
	case EV_MDCX_BTS_HO_RESP:
		/* The response from the MGW arrived, the connection pointing
		 * towards the BTS is now updated, so we now change back to
		 * ST_CALL, where we will wait for the call-end (or another
		 * handover) */
		LOGPFSML(mgcp_ctx->fsm, LOGL_DEBUG, "MDCX/BTS/HO: handover done, waiting for call end...\n");
		osmo_fsm_inst_state_chg(mgcp_ctx->fsm, ST_CALL, 0, 0);
		break;
	case EV_HANDOVER:
		/* This handles the rare, but possible situation where another
		 * handover is happening while we still wait for the the MGW to
		 * complete the current one. In this case we will stop waiting
		 * for the response and directly move on with that second
		 * handover */
		handle_handover(mgcp_ctx);
		break;
	case EV_TEARDOWN:
		/* It may happen that the BSS wants to teardown all connections
		 * while we are still waiting for the MGW to respond. In this
		 * case we start to teard down the connection immediately */
		handle_teardown(mgcp_ctx);
		break;
	}
}

/* Callback for MGCP-Client: handle response for NET associated CRCX */
static void dlcx_for_all_resp_cb(struct mgcp_response *r, void *priv)
{
	struct mgcp_ctx *mgcp_ctx = priv;
	struct osmo_bsc_sccp_con *conn;
	struct mgcp_client *mgcp;

	OSMO_ASSERT(mgcp_ctx);
	conn = mgcp_ctx->conn;
	OSMO_ASSERT(conn);
	mgcp = mgcp_ctx->mgcp;
	OSMO_ASSERT(mgcp);

	if (mgcp_ctx->fsm == NULL) {
		LOGP(DMGCP, LOGL_ERROR,
		     "DLCX: late MGW response, FSM already terminated -- ignoring...\n");
		return;
	}

	/* Note: We check the return code, but in case of an error there is
	 * not much that can be done to recover. However, at least we tryed
	 * to remove the connection (if there was even any) */
	if (r->head.response_code != 200) {
		LOGPFSML(mgcp_ctx->fsm, LOGL_ERROR,
			 "DLCX: response yields error: %d %s\n", r->head.response_code, r->head.comment);
	}

	LOGPFSML(mgcp_ctx->fsm, LOGL_ERROR, "DLCX: MGW has acknowledged the removal of the connections\n");

	/* Notify the FSM that we got the response. */
	osmo_fsm_inst_dispatch(mgcp_ctx->fsm, EV_DLCX_ALL_RESP, mgcp_ctx);
}

/* Callback for ST_HALT: Terminate the state machine */
static void fsm_halt_cb(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct mgcp_ctx *mgcp_ctx = (struct mgcp_ctx *)data;
	struct osmo_bsc_sccp_con *conn;

	OSMO_ASSERT(mgcp_ctx);
	conn = mgcp_ctx->conn;
	OSMO_ASSERT(conn);

	LOGPFSML(mgcp_ctx->fsm, LOGL_DEBUG,
		 "fsm-state: %s, fsm-event: %s\n",
		 get_value_string(fsm_bsc_mgcp_state_names, fi->state), get_value_string(fsm_evt_names, event));

	/* Send pending sigtran message */
	if (mgcp_ctx->resp) {
		LOGPFSML(mgcp_ctx->fsm, LOGL_DEBUG, "sending pending sigtran response message...\n");
		osmo_bsc_sigtran_send(conn, mgcp_ctx->resp);
		mgcp_ctx->resp = NULL;
	}

	LOGPFSML(mgcp_ctx->fsm, LOGL_DEBUG, "state machine halted\n");

	/* Destroy the state machine and all context information */
	osmo_fsm_inst_free(mgcp_ctx->fsm);
	mgcp_ctx->fsm = NULL;
}

/* Timer callback to shut down in case of connectivity problems */
static int fsm_timeout_cb(struct osmo_fsm_inst *fi)
{
	struct mgcp_ctx *mgcp_ctx = fi->priv;
	struct mgcp_client *mgcp;

	OSMO_ASSERT(mgcp_ctx);
	mgcp = mgcp_ctx->mgcp;
	OSMO_ASSERT(mgcp);

	LOGPFSML(mgcp_ctx->fsm, LOGL_ERROR,
		 "timeout (T%i) in state %s, attempting graceful teardown...\n",
		 fi->T, get_value_string(fsm_bsc_mgcp_state_names, fi->state));

	/* Ensure that no sigtran response, is present. Otherwiese we might try
	 * to send a sigtran response when the sccp connection is already freed. */
	mgcp_ctx->resp = NULL;

	if (fi->T == MGCP_MGW_TIMEOUT_TIMER_NR) {
		/* Note: We were unable to communicate with the MGCP-GW,
		 * unfortunately there is no meaningful action we can take
		 * now other than giving up. */
		LOGPFSML(mgcp_ctx->fsm, LOGL_ERROR, "graceful teardown not possible, terminating...\n");

		/* At least release the occupied endpoint ID */
		mgcp_client_release_endpoint(mgcp_ctx->rtp_endpoint, mgcp);

		/* Initiate self destruction of the FSM */
		osmo_fsm_inst_state_chg(fi, ST_HALT, 0, 0);
		osmo_fsm_inst_dispatch(mgcp_ctx->fsm, EV_TEARDOWN, mgcp_ctx);
	} else if (fi->T == MGCP_BSS_TIMEOUT_TIMER_NR)
		/* Note: If the logic that controls the BSS is unable to
		 * negotiate a connection, we presumably still have a
		 * working connection to the MGCP-GW, we will try to
		 * shut down gracefully. */
		handle_error(mgcp_ctx, MGCP_ERR_BSS_TIMEOUT);
	else {
		/* Note: Ther must not be any unsolicited timers
		 * in this FSM. If so, we have serious problem. */
		OSMO_ASSERT(false);
	}

	return 0;
}

static struct osmo_fsm_state fsm_bsc_mgcp_states[] = {

	/* Startup state machine, send CRCX to BTS. */
	[ST_CRCX_BTS] = {
			 .in_event_mask = (1 << EV_INIT),
			 .out_state_mask = (1 << ST_HALT) | (1 << ST_ASSIGN_PROC),
			 .name = "ST_CRCX_BTS",
			 .action = fsm_crcx_bts_cb,
			 },

	/* When the CRCX response for the BTS side is received, then
	 * proceed the assignment on the BSS side. */
	[ST_ASSIGN_PROC] = {
			    .in_event_mask = (1 << EV_TEARDOWN) | (1 << EV_CRCX_BTS_RESP),
			    .out_state_mask = (1 << ST_HALT) | (1 << ST_CALL) | (1 << ST_MDCX_BTS),
			    .name = "ST_ASSIGN_PROC",
			    .action = fsm_proc_assignmnent_req_cb,
			    },

	/* When the BSS has processed the assignment request,
	 * then send the MDCX command for the BTS side in order to
	 * update the connections with the actual PORT/IP where the
	 * BTS expects the RTP input. */
	[ST_MDCX_BTS] = {
			 .in_event_mask = (1 << EV_TEARDOWN) | (1 << EV_ASS_COMPLETE),
			 .out_state_mask = (1 << ST_HALT) | (1 << ST_CALL) | (1 << ST_CRCX_NET),
			 .name = "ST_MDCX_BTS",
			 .action = fsm_mdcx_bts_cb,
			 },

	/* When the MDCX response for the BTS siede is received, then
	 * directly proceed with sending the CRCX command to connect the
	 * network side. This is done in one phase (no MDCX needed). */
	[ST_CRCX_NET] = {
			 .in_event_mask = (1 << EV_TEARDOWN) | (1 << EV_MDCX_BTS_RESP),
			 .out_state_mask = (1 << ST_HALT) | (1 << ST_CALL) | (1 << ST_ASSIGN_COMPL),
			 .name = "ST_CRCX_NET",
			 .action = fsm_crcx_net_cb,
			 },

	/* When the CRCX response for the NET side is received. Then
	 * send the assignment complete message via the A-Interface and
	 * enter wait state in order to wait for the end of the call. */
	[ST_ASSIGN_COMPL] = {
			     .in_event_mask = (1 << EV_TEARDOWN) | (1 << EV_CRCX_NET_RESP),
			     .out_state_mask = (1 << ST_HALT) | (1 << ST_CALL),
			     .name = "ST_ASSIGN_COMPL",
			     .action = fsm_send_assignment_complete,
			     },

	/* When the call ends, remove all RTP connections from the
	 * MGCP-GW by sending a wildcarded DLCX. In case of a handover,
	 * go for an extra MDCX to update the connection and land in
	 * this state again when done. */
	[ST_CALL] = {
		     .in_event_mask = (1 << EV_TEARDOWN) | (1 << EV_HANDOVER),
		     .out_state_mask = (1 << ST_HALT) | (1 << ST_MDCX_BTS_HO),
		     .name = "ST_CALL",
		     .action = fsm_active_call_cb,
		     },

	/* A handover is in progress. When the response to the respective
	 * MDCX is received, then go back to ST_CALL and wait for the
	 * call end */
	[ST_MDCX_BTS_HO] = {
			    .in_event_mask = (1 << EV_TEARDOWN) | (1 << EV_HANDOVER) | (1 << EV_MDCX_BTS_HO_RESP),
			    .out_state_mask = (1 << ST_HALT) | (1 << ST_CALL),
			    .name = "ST_MDCX_BTS_HO",
			    .action = fsm_complete_handover,
			    },

	/* When the MGCP_GW confirms that the connections are terminated,
	 * then halt the state machine. */
	[ST_HALT] = {
		     .in_event_mask = (1 << EV_TEARDOWN) | (1 << EV_DLCX_ALL_RESP),
		     .out_state_mask = 0,
		     .name = "ST_HALT",
		     .action = fsm_halt_cb,
		     },
};

/* State machine definition */
static struct osmo_fsm fsm_bsc_mgcp = {
	.name = "MGW",
	.states = fsm_bsc_mgcp_states,
	.num_states = ARRAY_SIZE(fsm_bsc_mgcp_states),
	.log_subsys = DMGCP,
	.timer_cb = fsm_timeout_cb,
};

/* Notify that the a new call begins. This will create a connection for the
 * BTS on the MGCP-GW and set up the port numbers in struct osmo_bsc_sccp_con.
 * After that gsm0808_assign_req() to proceed.
 * Parameter:
 * ctx: talloc context
 * network: associated gsm network
 * conn: associated sccp connection
 * chan_mode: channel mode (system data, passed through)
 * full_rate: full rate flag (system data, passed through)
 * Returns an mgcp_context that contains system data and the OSMO-FSM */
struct mgcp_ctx *mgcp_assignm_req(void *ctx, struct mgcp_client *mgcp, struct osmo_bsc_sccp_con *conn,
				  enum gsm48_chan_mode chan_mode, bool full_rate)
{
	struct mgcp_ctx *mgcp_ctx;
	char name[32];
	static bool fsm_registered = false;

	OSMO_ASSERT(mgcp);
	OSMO_ASSERT(conn);

	if(snprintf(name, sizeof(name), "MGW_%i", conn->conn_id) >= sizeof(name))
		return NULL;

	/* Register the fsm description (if not already done) */
	if (fsm_registered == false) {
		osmo_fsm_register(&fsm_bsc_mgcp);
		fsm_registered = true;
	}

	/* Allocate and configure a new fsm instance */
	mgcp_ctx = talloc_zero(ctx, struct mgcp_ctx);
	OSMO_ASSERT(mgcp_ctx);

	mgcp_ctx->fsm = osmo_fsm_inst_alloc(&fsm_bsc_mgcp, NULL, ctx, LOGL_DEBUG, name);
	OSMO_ASSERT(mgcp_ctx->fsm);
	mgcp_ctx->fsm->priv = mgcp_ctx;
	LOGPFSML(mgcp_ctx->fsm, LOGL_DEBUG, "MGW handler fsm created\n");
	mgcp_ctx->mgcp = mgcp;
	mgcp_ctx->conn = conn;
	mgcp_ctx->chan_mode = chan_mode;
	mgcp_ctx->full_rate = full_rate;

	/* start state machine */
	OSMO_ASSERT(mgcp_ctx->fsm->state == ST_CRCX_BTS);
	osmo_fsm_inst_dispatch(mgcp_ctx->fsm, EV_INIT, mgcp_ctx);

	return mgcp_ctx;
}

/* Notify that the call has ended, remove all connections from the MGCP-GW,
 * then send the clear complete message and destroy the FSM instance
 * Parameter:
 * mgcp_ctx: context information (FSM, and pointer to external system data)
 * respmgcp_ctx: pending clear complete message to send via A-Interface */
void mgcp_clear_complete(struct mgcp_ctx *mgcp_ctx, struct msgb *resp)
{
	struct osmo_bsc_sccp_con *conn;

	OSMO_ASSERT(mgcp_ctx);
	OSMO_ASSERT(resp);
	conn = mgcp_ctx->conn;
	OSMO_ASSERT(conn);

	if (mgcp_ctx->fsm == NULL) {
		LOGP(DMGCP, LOGL_ERROR,
		     "clear completion attemted on already terminated FSM -- forwarding directly...\n");
		osmo_bsc_sigtran_send(conn, resp);
		mgcp_ctx->resp = NULL;
		return;
	}

	LOGPFSML(mgcp_ctx->fsm, LOGL_DEBUG, "bss is indicating call end...\n");

	mgcp_ctx->resp = resp;

	osmo_fsm_inst_dispatch(mgcp_ctx->fsm, EV_TEARDOWN, mgcp_ctx);
}

/* Notify that the BSS ready, send the assingnment complete message when the
 * mgcp connection is completed
 * Parameter:
 * mgcp_ctx: context information (FSM, and pointer to external system data)
 * lchan: needed for sending the assignment complete message via A-Interface */
void mgcp_ass_complete(struct mgcp_ctx *mgcp_ctx, struct gsm_lchan *lchan)
{
	OSMO_ASSERT(mgcp_ctx);
	OSMO_ASSERT(lchan);

	if (mgcp_ctx->fsm == NULL) {
		LOGP(DMGCP, LOGL_ERROR, "assignment completion attemted on already terminated FSM -- ignored\n");
		mgcp_ctx->lchan = NULL;
		return;
	}

	LOGPFSML(mgcp_ctx->fsm, LOGL_DEBUG, "bss is indicating assignment completion...\n");

	mgcp_ctx->lchan = lchan;

	osmo_fsm_inst_dispatch(mgcp_ctx->fsm, EV_ASS_COMPLETE, mgcp_ctx);

	return;
}

/* Notify that the call got handovered to another BTS, update the connection
 * that is pointing to the BTS side with the connection data for the new bts.
 * Parameter:
 * mgcp_ctx: context information (FSM, and pointer to external system data)
 * ho_lchan: the lchan on the new BTS */
void mgcp_handover(struct mgcp_ctx *mgcp_ctx, struct gsm_lchan *ho_lchan)
{
	OSMO_ASSERT(mgcp_ctx);
	OSMO_ASSERT(ho_lchan);

	if (mgcp_ctx->fsm == NULL) {
		LOGP(DMGCP, LOGL_ERROR, "handover attemted on already terminated FSM -- ignored\n");
		mgcp_ctx->ho_lchan = NULL;
		return;
	}

	LOGPFSML(mgcp_ctx->fsm, LOGL_DEBUG, "bss is indicating handover...\n");

	mgcp_ctx->ho_lchan = ho_lchan;

	osmo_fsm_inst_dispatch(mgcp_ctx->fsm, EV_HANDOVER, mgcp_ctx);

	return;
}

/* Free an existing mgcp context gracefully
 * Parameter:
 * mgcp_ctx: context information (FSM, and pointer to external system data) */
void mgcp_free_ctx(struct mgcp_ctx *mgcp_ctx)
{
	OSMO_ASSERT(mgcp_ctx);

	if (mgcp_ctx->fsm == NULL) {
		LOGP(DMGCP, LOGL_DEBUG, "fsm already terminated, freeing only related context information...\n");
		talloc_free(mgcp_ctx);
		return;
	}

	LOGPFSML(mgcp_ctx->fsm, LOGL_DEBUG, "terminating fsm and freeing related context information...\n");

	osmo_fsm_inst_free(mgcp_ctx->fsm);
	talloc_free(mgcp_ctx);
}
