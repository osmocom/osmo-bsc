/*
 * ipaccess audio handling
 *
 * (C) 2009-2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009-2010 by On-Waves
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
#include <osmocom/bsc/osmo_bsc_sigtran.h>
#include <osmocom/bsc/osmo_bsc_mgcp.h>

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
	if (!con || !con->sccp_con)
		return 0;

	switch (signal) {
	case S_ABISIP_CRCX_ACK:
		/* we can ask it to connect now */
		LOGP(DMSC, LOGL_DEBUG, "Connecting BTS to port: %d conn: %d\n",
		     con->sccp_con->user_plane.rtp_port, lchan->abis_ip.conn_id);

		/* If AoIP is in use, the rtp_ip, which has been communicated
		 * via the A interface as connect_ip */
		if(con->sccp_con->user_plane.rtp_ip)
			rtp_ip = con->sccp_con->user_plane.rtp_ip;
		else
			rtp_ip = ntohl(INADDR_ANY);

		rc = rsl_ipacc_mdcx(lchan, rtp_ip,
				    con->sccp_con->user_plane.rtp_port,
				    lchan->abis_ip.rtp_payload2);
		if (rc < 0) {
			LOGP(DMSC, LOGL_ERROR, "Failed to send MDCX: %d\n", rc);
			return rc;
		}
		break;

	case S_ABISIP_MDCX_ACK:
		if (con->ho_lchan) {
			LOGP(DHO, LOGL_DEBUG, "%s -> %s BTS sent MDCX ACK\n", gsm_lchan_name(lchan),
			     gsm_lchan_name(con->ho_lchan));
			/* No need to do anything for handover here. As soon as a HANDOVER DETECT
			 * happens, osmo_bsc_mgcp.c will trigger the MGCP MDCX towards MGW by
			 * receiving an S_LCHAN_HANDOVER_DETECT signal. */
		} else if (is_ipaccess_bts(conn_get_bts(con)) && con->sccp_con->user_plane.rtp_ip) {
			/* NOTE: This is only relevant on AoIP networks with
			 * IPA based base stations. See also osmo_bsc_api.c,
			 * function bsc_assign_compl() */
			LOGP(DMSC, LOGL_INFO, "Tx MSC ASSIGN COMPL (POSTPONED)\n");
			mgcp_ass_complete(con->sccp_con->user_plane.mgcp_ctx, lchan);
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
