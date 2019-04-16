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
#include <osmocom/bsc/gsm_04_80.h>
#include <osmocom/bsc/bsc_subscr_conn_fsm.h>
#include <osmocom/bsc/gsm_data.h>
#include <osmocom/mgcp_client/mgcp_common.h>

/* A pointer to a list with all involved MSCs
 * (a copy of the pointer location submitted with osmo_bsc_sigtran_init() */
static struct llist_head *msc_list;

#define RESET_INTERVAL 1	/* sek */
#define SCCP_MSG_MAXSIZE 1024
#define CS7_POINTCODE_DEFAULT_OFFSET 2

/* The SCCP stack will not assign connection IDs to us automatically, we
 * will do this ourselves using a counter variable, that counts one up
 * for every new connection */
static uint32_t conn_id_counter;

/* Helper function to Check if the given connection id is already assigned */
static struct gsm_subscriber_connection *get_bsc_conn_by_conn_id(int conn_id)
{
	conn_id &= 0xFFFFFF;
	struct gsm_subscriber_connection *conn;

	llist_for_each_entry(conn, &bsc_gsmnet->subscr_conns, entry) {
		if (conn->sccp.conn_id == conn_id)
			return conn;
	}

	return NULL;
}

/* Pick a free connection id */
static int pick_free_conn_id(const struct bsc_msc_data *msc)
{
	int conn_id = conn_id_counter;
	int i;

	for (i = 0; i < 0xFFFFFF; i++) {
		conn_id++;
		conn_id &= 0xFFFFFF;
		if (get_bsc_conn_by_conn_id(conn_id) == false) {
			conn_id_counter = conn_id;
			return conn_id;
		}
	}

	return -1;
}

/* Patch regular BSSMAP RESET to add extra T to announce Osmux support (osmocom extension) */
static void _gsm0808_extend_announce_osmux(struct msgb *msg)
{
	OSMO_ASSERT(msg->l3h[1] == msgb_l3len(msg) - 2); /*TL not in len */
	msgb_put_u8(msg, GSM0808_IE_OSMO_OSMUX_SUPPORT);
	msg->l3h[1] = msgb_l3len(msg) - 2;
}

/* Send reset to MSC */
static void osmo_bsc_sigtran_tx_reset(const struct bsc_msc_data *msc)
{
	struct osmo_ss7_instance *ss7;
	struct msgb *msg;

	ss7 = osmo_ss7_instance_find(msc->a.cs7_instance);
	OSMO_ASSERT(ss7);
	LOGP(DMSC, LOGL_NOTICE, "Sending RESET to MSC: %s\n", osmo_sccp_addr_name(ss7, &msc->a.msc_addr));
	msg = gsm0808_create_reset();

	if (msc->use_osmux != OSMUX_USAGE_OFF)
		_gsm0808_extend_announce_osmux(msg);

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
	LOGP(DMSC, LOGL_NOTICE, "Sending RESET ACK to MSC: %s\n", osmo_sccp_addr_name(ss7, &msc->a.msc_addr));
	msg = gsm0808_create_reset_ack();

	if (msc->use_osmux != OSMUX_USAGE_OFF)
		_gsm0808_extend_announce_osmux(msg);

	osmo_sccp_tx_unitdata_msg(msc->a.sccp_user, &msc->a.bsc_addr,
				  &msc->a.msc_addr, msg);
}

/* Find an MSC by its sigtran point code */
static struct bsc_msc_data *get_msc_by_addr(const struct osmo_sccp_addr *msc_addr)
{
	struct osmo_ss7_instance *ss7;
	struct bsc_msc_data *msc;
	llist_for_each_entry(msc, msc_list, entry) {
		if (memcmp(msc_addr, &msc->a.msc_addr, sizeof(*msc_addr)) == 0)
			return msc;
	}

	ss7 = osmo_ss7_instance_find(msc->a.cs7_instance);
	LOGP(DMSC, LOGL_ERROR, "Unable to find MSC data under address: %s\n", osmo_sccp_addr_name(ss7, msc_addr));
	return NULL;
}

/* Send data to MSC, use the connection id which MSC it is */
static int handle_data_from_msc(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	msg->l3h = msgb_l2(msg);
	return bsc_handle_dt(conn, msg, msgb_l2len(msg));
}

/* Sent unitdata to MSC, use the point code to determine which MSC it is */
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
	struct gsm_subscriber_connection *conn;
	int rc = 0;

	conn = get_bsc_conn_by_conn_id(scu_prim->u.connect.conn_id);
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
	conn->sccp.conn_id = scu_prim->u.connect.conn_id;

	/* Take actions asked for by the enclosed PDU */
	osmo_fsm_inst_dispatch(conn->fi, GSCON_EV_A_CONN_IND, scu_prim);

	return 0;
refuse:
	osmo_sccp_tx_disconn(scu, scu_prim->u.connect.conn_id, &scu_prim->u.connect.called_addr, 0);
	return rc;
}

/* Callback function, called by the SSCP stack when data arrives */
static int sccp_sap_up(struct osmo_prim_hdr *oph, void *_scu)
{
	struct osmo_scu_prim *scu_prim = (struct osmo_scu_prim *)oph;
	struct osmo_sccp_user *scu = _scu;
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
		conn = get_bsc_conn_by_conn_id(scu_prim->u.connect.conn_id);
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
		conn = get_bsc_conn_by_conn_id(scu_prim->u.data.conn_id);
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
		conn = get_bsc_conn_by_conn_id(scu_prim->u.disconnect.conn_id);
		if (conn) {
			conn->sccp.state = SUBSCR_SCCP_ST_NONE;
			if (msgb_l2len(oph->msg) > 0)
				handle_data_from_msc(conn, oph->msg);
			osmo_fsm_inst_dispatch(conn->fi, GSCON_EV_A_DISC_IND, scu_prim);
		}
		break;

	default:
		LOGP(DMSC, LOGL_ERROR, "Unhandled SIGTRAN operation %s on primitive %u\n",
		     get_value_string(osmo_prim_op_names, oph->operation), oph->primitive);
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
	LOGP(DMSC, LOGL_NOTICE, "Initializing resources for new SIGTRAN connection to MSC: %s...\n",
	     osmo_sccp_addr_name(ss7, &msc->a.msc_addr));

	if (a_reset_conn_ready(msc) == false) {
		LOGP(DMSC, LOGL_ERROR, "MSC is not connected. Dropping.\n");
		return BSC_CON_REJECT_NO_LINK;
	}

	if (!bsc_grace_allow_new_connection(bts->network, bts)) {
		LOGP(DMSC, LOGL_NOTICE, "BSC in grace period. No new connections.\n");
		return BSC_CON_REJECT_RF_GRACE;
	}

	conn->sccp.msc = msc;

	return BSC_CON_SUCCESS;
}

/* Open a new connection oriented sigtran connection */
int osmo_bsc_sigtran_open_conn(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	struct osmo_ss7_instance *ss7;
	struct bsc_msc_data *msc;
	int conn_id;
	int rc;

	OSMO_ASSERT(conn);
	OSMO_ASSERT(msg);
	OSMO_ASSERT(conn->sccp.msc);
	OSMO_ASSERT(conn->sccp.conn_id == -1);

	msc = conn->sccp.msc;

	if (a_reset_conn_ready(msc) == false) {
		LOGP(DMSC, LOGL_ERROR, "MSC is not connected. Dropping.\n");
		return -EINVAL;
	}

	conn->sccp.conn_id = conn_id = pick_free_conn_id(msc);
	if (conn->sccp.conn_id < 0) {
		LOGP(DMSC, LOGL_ERROR, "Unable to allocate SCCP Connection ID\n");
		return -1;
	}
	LOGP(DMSC, LOGL_DEBUG, "Allocated new connection id: %d\n", conn->sccp.conn_id);
	ss7 = osmo_ss7_instance_find(msc->a.cs7_instance);
	OSMO_ASSERT(ss7);
	LOGP(DMSC, LOGL_NOTICE, "Opening new SIGTRAN connection (id=%i) to MSC: %s\n", conn_id,
	     osmo_sccp_addr_name(ss7, &msc->a.msc_addr));

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
			LOGP(DMSC, LOGL_INFO, "Tx MSC: BSSMAP: %s\n",
			     gsm0808_bssmap_name(msg->data[2]));
			break;
		case BSSAP_MSG_DTAP:
			LOGP(DMSC, LOGL_INFO, "Tx MSC: DTAP\n");
			break;
		default:
			LOGP(DMSC, LOGL_ERROR, "Tx MSC: unknown message type: 0x%x\n",
			     msg->data[0]);
		}
	} else
		LOGP(DMSC, LOGL_ERROR, "Tx MSC: message too short: %u\n", msg->len);

	if (a_reset_conn_ready(msc) == false) {
		LOGP(DMSC, LOGL_ERROR, "MSC is not connected. Dropping.\n");
		msgb_free(msg);
		return -EINVAL;
	}

	conn_id = conn->sccp.conn_id;

	ss7 = osmo_ss7_instance_find(msc->a.cs7_instance);
	OSMO_ASSERT(ss7);
	LOGP(DMSC, LOGL_DEBUG, "Sending connection (id=%i) oriented data to MSC: %s (%s)\n",
	     conn_id, osmo_sccp_addr_name(ss7, &msc->a.msc_addr), osmo_hexdump(msg->data, msg->len));

	rc = osmo_sccp_tx_data_msg(msc->a.sccp_user, conn_id, msg);

	return rc;
}

/* Send an USSD notification in case we loose the connection to the MSC */
static void bsc_notify_msc_lost(struct gsm_subscriber_connection *conn)
{
	/* Check if sccp conn is still present */
	if (!conn)
		return;

	/* check for config string */
	if (!conn->sccp.msc->ussd_msc_lost_txt)
		return;
	if (conn->sccp.msc->ussd_msc_lost_txt[0] == '\0')
		return;

	/* send USSD notification */
	bsc_send_ussd_notify(conn, 1, conn->sccp.msc->ussd_msc_lost_txt);
	bsc_send_ussd_release_complete(conn);
}

/* Close all open sigtran connections and channels */
void osmo_bsc_sigtran_reset(const struct bsc_msc_data *msc)
{
	struct gsm_subscriber_connection *conn, *conn_temp;
	OSMO_ASSERT(msc);

	/* Close all open connections */
	llist_for_each_entry_safe(conn, conn_temp, &bsc_gsmnet->subscr_conns, entry) {

		/* We only may close connections which actually belong to this
		 * MSC. All other open connections are left untouched */
		if (conn->sccp.msc == msc) {
			/* Notify active connection users via USSD that the MSC is down */
			bsc_notify_msc_lost(conn);

			/* Take down all occopied RF channels */
			/* Disconnect all Sigtran connections */
			/* Delete subscriber connection */
			osmo_fsm_inst_term(conn->fi, OSMO_FSM_TERM_REQUEST, NULL);
		}
	}
}

/* Callback function: Close all open connections */
static void osmo_bsc_sigtran_reset_cb(const void *priv)
{
	struct bsc_msc_data *msc = (struct bsc_msc_data*) priv;

	/* Shut down all ongoing traffic */
	osmo_bsc_sigtran_reset(msc);

	/* Send reset to MSC */
	osmo_bsc_sigtran_tx_reset(msc);
}

/* Default point-code to be used as local address (BSC) */
#define BSC_DEFAULT_PC "0.23.3"

/* Default point-code to be used as remote address (MSC) */
#define MSC_DEFAULT_PC "0.23.1"

static int asp_rx_unknown(struct osmo_ss7_asp *asp, int ppid_mux, struct msgb *msg);

/* Initalize osmo sigtran backhaul */
int osmo_bsc_sigtran_init(struct llist_head *mscs)
{
	bool free_attempt_used = false;
	bool fail_on_next_invalid_cfg = false;

	struct bsc_msc_data *msc;
	char msc_name[32];
	uint32_t default_pc;

	osmo_ss7_register_rx_unknown_cb(&asp_rx_unknown);

	OSMO_ASSERT(mscs);
	msc_list = mscs;

	llist_for_each_entry(msc, msc_list, entry) {
		snprintf(msc_name, sizeof(msc_name), "msc-%u", msc->nr);
		LOGP(DMSC, LOGL_NOTICE, "Initializing SCCP connection to MSC %s\n", msc_name);

		/* Check if the VTY could determine a valid CS7 instance,
		 * use safe default in case none is set */
		if (msc->a.cs7_instance_valid == false) {
			msc->a.cs7_instance = 0;
			if (fail_on_next_invalid_cfg)
				goto fail_auto_cofiguration;
			free_attempt_used = true;
		}
		LOGP(DMSC, LOGL_NOTICE, "CS7 Instance identifier, A-Interface: %u\n", msc->a.cs7_instance);

		/* Pre-Check if there is an ss7 instance present */
		if (osmo_ss7_instance_find(msc->a.cs7_instance) == NULL) {
			if (fail_on_next_invalid_cfg)
				goto fail_auto_cofiguration;
			free_attempt_used = true;
		}

		/* SS7 Protocol stack */
		default_pc = osmo_ss7_pointcode_parse(NULL, BSC_DEFAULT_PC);
		msc->a.sccp =
		    osmo_sccp_simple_client_on_ss7_id(msc, msc->a.cs7_instance, msc_name, default_pc,
						      msc->a.asp_proto, 0, NULL, 0, NULL);
		if (!msc->a.sccp)
			return -EINVAL;

		/* In SCCPlite, the MSC side of the MGW endpoint is configured by the MSC. Since we have
		 * no way to figure out which CallID ('C:') the MSC will issue in its CRCX command, set
		 * an X-Osmo-IGN flag telling osmo-mgw to ignore CallID mismatches for this endpoint.
		 * If an explicit VTY command has already indicated whether or not to send X-Osmo-IGN, do
		 * not overwrite that setting. */
		if (msc->a.asp_proto == OSMO_SS7_ASP_PROT_IPA
		    && !msc->x_osmo_ign_configured)
			msc->x_osmo_ign |= MGCP_X_OSMO_IGN_CALLID;

		/* If unset, use default local SCCP address */
		if (!msc->a.bsc_addr.presence)
			osmo_sccp_local_addr_by_instance(&msc->a.bsc_addr, msc->a.sccp,
							 OSMO_SCCP_SSN_BSSAP);

		if (!osmo_sccp_check_addr(&msc->a.bsc_addr, OSMO_SCCP_ADDR_T_SSN | OSMO_SCCP_ADDR_T_PC)) {
			LOGP(DMSC, LOGL_ERROR,
			     "(%s) A-interface: invalid local (BSC) SCCP address: %s\n",
			     msc_name, osmo_sccp_inst_addr_name(msc->a.sccp, &msc->a.bsc_addr));
			return -EINVAL;
		}

		/* If unset, use default SCCP address for the MSC */
		if (!msc->a.msc_addr.presence)
			osmo_sccp_make_addr_pc_ssn(&msc->a.msc_addr,
						   osmo_ss7_pointcode_parse(NULL, MSC_DEFAULT_PC),
						   OSMO_SCCP_SSN_BSSAP);

		if (!osmo_sccp_check_addr(&msc->a.msc_addr, OSMO_SCCP_ADDR_T_SSN | OSMO_SCCP_ADDR_T_PC)) {
			LOGP(DMSC, LOGL_ERROR,
			     "(%s) A-interface: invalid remote (MSC) SCCP address: %s\n",
			     msc_name, osmo_sccp_inst_addr_name(msc->a.sccp, &msc->a.msc_addr));
			return -EINVAL;
		}

		LOGP(DMSC, LOGL_NOTICE, "(%s) A-interface: local (BSC) SCCP address: %s\n",
		     msc_name, osmo_sccp_inst_addr_name(msc->a.sccp, &msc->a.bsc_addr));
		LOGP(DMSC, LOGL_NOTICE, "(%s) A-interface: remote (MSC) SCCP address: %s\n",
		     msc_name, osmo_sccp_inst_addr_name(msc->a.sccp, &msc->a.msc_addr));

		/* Bind SCCP user */
		msc->a.sccp_user = osmo_sccp_user_bind(msc->a.sccp, msc_name, sccp_sap_up, msc->a.bsc_addr.ssn);
		if (!msc->a.sccp_user)
			return -EINVAL;

		/* Start MSC-Reset procedure */
		a_reset_alloc(msc, msc_name, osmo_bsc_sigtran_reset_cb);

		/* If we have detected that the SS7 configuration of the MSC we have just initalized
		 * was incomplete or completely missing, we can not tolerate another incomplete
		 * configuration. The reson for this is that we do only specify exactly one default
		 * pointcode pair. We also specify localhost as default IP-Address. If we have wanted
		 * to support multiple MSCs with automatic configuration we would be forced to invent
		 * a complex ruleset how to allocate the pointcodes and respective IP-Addresses.
		 * Furthermore, the situation where a single BSC is connected to multiple MSCs
		 * is a very rare situation anyway. In this case we expect the user to experienced
		 * enough to create a valid SS7/CS7 VTY configuration that does not lack any
		 * components */
		if (free_attempt_used)
			fail_on_next_invalid_cfg = true;
	}

	return 0;

fail_auto_cofiguration:
	LOGP(DMSC, LOGL_ERROR,
	     "A-interface: More than one invalid/inclomplete configuration detected, unable to revover - check config file!\n");
	return -EINVAL;
}

/* this function receives all messages received on an ASP for a PPID / StreamID that
 * libosmo-sigtran doesn't know about, such as piggy-backed CTRL and/or MGCP */
static int asp_rx_unknown(struct osmo_ss7_asp *asp, int ppid_mux, struct msgb *msg)
{
	struct ipaccess_head *iph;
	struct ipaccess_head_ext *iph_ext;

	if (asp->cfg.proto != OSMO_SS7_ASP_PROT_IPA) {
		msgb_free(msg);
		return 0;
	}

	switch (ppid_mux) {
	case IPAC_PROTO_OSMO:
		if (msg->len < sizeof(*iph) + sizeof(*iph_ext)) {
			LOGP(DMSC, LOGL_ERROR, "The message is too short.\n");
			msgb_free(msg);
			return -EINVAL;
		}
		iph = (struct ipaccess_head *) msg->data;
		iph_ext = (struct ipaccess_head_ext *) iph->data;
		msg->l2h = iph_ext->data;
		switch (iph_ext->proto) {
		case IPAC_PROTO_EXT_CTRL:
			return bsc_sccplite_rx_ctrl(asp, msg);
		}
		break;
	default:
		break;
	}
	msgb_free(msg);
	return 0; /* OSMO_SS7_UNKNOWN? */
}
