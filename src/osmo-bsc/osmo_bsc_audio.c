/*
 * ipaccess audio handling
 *
 * (C) 2009-2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009-2010 by On-Waves
 * (C) 2018 by Harald Welte <laforge@gnumonks.org>
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

#include <osmocom/bsc/bsc_msc_data.h>
#include <osmocom/bsc/osmo_bsc.h>
#include <osmocom/bsc/abis_rsl.h>
#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/signal.h>
#include <osmocom/gsm/gsm0808.h>
#include <osmocom/gsm/gsm0808_utils.h>
#include <osmocom/gsm/ipa.h>
#include <osmocom/gsm/protocol/ipaccess.h>
#include <osmocom/bsc/osmo_bsc_sigtran.h>
#include <osmocom/bsc/bsc_subscr_conn_fsm.h>
#include <osmocom/bsc/bsc_subscriber.h>

#include <arpa/inet.h>

static int handle_abisip_signal(unsigned int subsys, unsigned int signal,
				 void *handler_data, void *signal_data)
{
	struct gsm_subscriber_connection *con;
	struct gsm_lchan *lchan = signal_data;
	int rc;
	uint32_t rtp_ip;

	if (subsys != SS_ABISIP)
		return 0;

	con = lchan->conn;
	if (!con)
		return 0;

	switch (signal) {
	case S_ABISIP_CRCX_ACK:
		/* we can ask it to connect now */
		LOGP(DMSC, LOGL_DEBUG, "Connecting BTS to port: %d conn: %d\n",
		     con->user_plane.rtp_port, lchan->abis_ip.conn_id);

		/* If AoIP is in use, the rtp_ip, which has been communicated
		 * via the A interface as connect_ip */
		if(con->user_plane.rtp_ip)
			rtp_ip = con->user_plane.rtp_ip;
		else
			rtp_ip = ntohl(INADDR_ANY);

		rc = rsl_ipacc_mdcx(lchan, rtp_ip,
				    con->user_plane.rtp_port,
				    lchan->abis_ip.rtp_payload2);
		if (rc < 0) {
			LOGP(DMSC, LOGL_ERROR, "Failed to send MDCX: %d\n", rc);
			return rc;
		}
		break;

	case S_ABISIP_MDCX_ACK:
		if (con->ho) {
			LOGPHO(con->ho, LOGL_DEBUG, "BTS sent MDCX ACK\n");
			/* No need to do anything for handover here. As soon as a HANDOVER DETECT
			 * happens, handover_logic.c and bsc_subscr_conn_fsm.c  will trigger the
			 * MGCP MDCX towards MGW by receiving an S_LCHAN_HANDOVER_DETECT signal. */
		} else if (is_ipaccess_bts(conn_get_bts(con)) && con->user_plane.rtp_ip) {
			/* NOTE: This is only relevant on AoIP networks with
			 * IPA based base stations. See also osmo_bsc_api.c,
			 * function bsc_assign_compl() */
			LOGP(DMSC, LOGL_INFO, "Tx MSC ASSIGN COMPL (POSTPONED)\n");
			osmo_fsm_inst_dispatch(con->fi, GSCON_EV_RR_ASS_COMPL, NULL);

		}
		break;
	}

	return 0;
}

int osmo_bsc_audio_init(struct gsm_network *net)
{
	osmo_signal_register_handler(SS_ABISIP, handle_abisip_signal, net);
	return 0;
}

/* Determine MSC based on the ASP over which the message was received */
static struct bsc_msc_data *msc_from_asp(struct osmo_ss7_asp *asp)
{
	int msc_nr;
	/* this is rather ugly, as we of course have MTP-level routing between
	 * the local SCCP user (BSC) and the AS/ASPs.  However, for the most simple
	 * SCCPlite case, there is a 1:1 mapping between ASP and AS, and using
	 * the libosmo-sigtran "simple client", the names are "as[p]-clnt-msc-%u",
	 * as set in osmo_bsc_sigtran_init() */
	if (sscanf(asp->cfg.name, "asp-clnt-msc-%u", &msc_nr) != 1) {
		LOGP(DMSC, LOGL_ERROR, "Cannot find to which MSC the ASP %s belongs\n", asp->cfg.name);
		return NULL;
	}
	return osmo_msc_data_find(bsc_gsmnet, msc_nr);
}

/* We received an IPA-encapsulated MGCP message from a MSC. Transfers msg ownership. */
int bsc_sccplite_rx_mgcp(struct osmo_ss7_asp *asp, struct msgb *msg)
{
	struct bsc_msc_data *msc;
	int rc;

	LOGP(DMSC, LOGL_NOTICE, "%s: Received IPA-encapsulated MGCP: %s\n", asp->cfg.name, msg->l2h);
	msc = msc_from_asp(asp);
	if (msc) {
		/* we don't have a write queue here as we simply expect the socket buffers
		 * to be large enouhg to deal with whatever small/infrequent MGCP messages */
		rc = send(msc->mgcp_ipa.ofd.fd, msgb_l2(msg), msgb_l2len(msg), 0);
	} else
		rc = 0;

	msgb_free(msg);
	return rc;
}

/* we received some data on the UDP proxy socket from the MGW. Pass it to MSC via IPA */
int bsc_sccplite_mgcp_proxy_cb(struct osmo_fd *ofd, unsigned int what)
{
	struct bsc_msc_data *msc = ofd->data;
	struct msgb *msg;
	int rc;

	if (!(what & BSC_FD_READ))
		return 0;

	msg = msgb_alloc_headroom(1024, 16, "MGCP->IPA");
	OSMO_ASSERT(msg);
	rc = recv(ofd->fd, msg->data, msgb_tailroom(msg), 0);
	if (rc <= 0) {
		LOGP(DMSC, LOGL_ERROR, "error receiving data from MGCP<-> IPA proxy UDP socket: "
			"%s\n", strerror(errno));
		msgb_free(msg);
		return rc;
	}
	msg->l2h = msgb_put(msg, rc);
	LOGP(DMSC, LOGL_NOTICE, "Received MGCP on UDP proxy socket: %s\n", msg->l2h);

	ipa_prepend_header(msg, IPAC_PROTO_MGCP_OLD);
	return bsc_sccplite_msc_send(msc, msg);
}
