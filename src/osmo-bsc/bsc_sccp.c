/* Generic SCCP handling across all OsmoBSC users */
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

#include <osmocom/core/utils.h>

#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/bsc_msc_data.h>
#include <osmocom/bsc/lb.h>

/* We need an unused SCCP conn_id across all SCCP users. */
uint32_t bsc_sccp_inst_next_conn_id(struct osmo_sccp_instance *sccp)
{
	static uint32_t next_id = 1;
	int i;

	/* SUA: RFC3868 sec 3.10.4:
	*    The source reference number is a 4 octet long integer.
	*    This is allocated by the source SUA instance.
	* M3UA/SCCP: ITU-T Q.713 sec 3.3:
	*    The "source local reference" parameter field is a three-octet field containing a
	*    reference number which is generated and used by the local node to identify the
	*    connection section after the connection section is set up.
	*    The coding "all ones" is reserved for future use.
	* Hence, let's simply use 24 bit ids to fit all link types (excluding 0x00ffffff).
	*/

	/* This looks really suboptimal, but in most cases the static next_id should indicate exactly the next unused
	 * conn_id, and we only iterate all conns once to make super sure that it is not already in use. */

	for (i = 0; i < SCCP_CONN_ID_MAX; i++) {
		struct gsm_subscriber_connection *conn;
		uint32_t conn_id = next_id;
		bool conn_id_already_used = false;

		/* Optimized modulo operation (% SCCP_CONN_ID_MAX) using bitwise AND plus CMP: */
		next_id = (next_id + 1) & 0x00FFFFFF;
		if (OSMO_UNLIKELY(next_id == 0x00FFFFFF))
			next_id = 0;

		llist_for_each_entry(conn, &bsc_gsmnet->subscr_conns, entry) {
			if (conn->sccp.msc && conn->sccp.msc->a.sccp == sccp) {
				if (conn_id == conn->sccp.conn_id) {
					conn_id_already_used = true;
					break;
				}
			}

			if (bsc_gsmnet->smlc->sccp == sccp
			    && conn->lcs.lb.state != SUBSCR_SCCP_ST_NONE) {
				if (conn_id == conn->lcs.lb.conn_id) {
					conn_id_already_used = true;
					break;
				}
			}
		}

		if (!conn_id_already_used)
			return conn_id;
	}
	return SCCP_CONN_ID_UNSET;
}
