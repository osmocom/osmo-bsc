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

#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/bsc_msc_data.h>
#include <osmocom/bsc/lb.h>

/* We need an unused SCCP conn_id across all SCCP users. */
int bsc_sccp_inst_next_conn_id(struct osmo_sccp_instance *sccp)
{
	static uint32_t next_id = 1;
	int i;

	/* This looks really suboptimal, but in most cases the static next_id should indicate exactly the next unused
	 * conn_id, and we only iterate all conns once to make super sure that it is not already in use. */

	for (i = 0; i < 0xFFFFFF; i++) {
		struct gsm_subscriber_connection *conn;
		uint32_t conn_id = next_id;
		bool conn_id_already_used = false;
		next_id = (next_id + 1) & 0xffffff;

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
	return -1;
}
