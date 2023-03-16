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

void bscp_sccp_conn_node_init(struct bscp_sccp_conn_node *sccp_conn, struct gsm_subscriber_connection *gscon)
{
	sccp_conn->conn_id = SCCP_CONN_ID_UNSET;
	sccp_conn->gscon = gscon;
}

struct bsc_sccp_inst *bsc_sccp_inst_alloc(void *ctx)
{
	struct bsc_sccp_inst *bsc_sccp;

	bsc_sccp = talloc_zero(ctx, struct bsc_sccp_inst);
	OSMO_ASSERT(bsc_sccp);
	bsc_sccp->next_id = 1;

	return bsc_sccp;
}

int bsc_sccp_inst_register_gscon(struct bsc_sccp_inst *bsc_sccp, struct bscp_sccp_conn_node *sccp_conn)
{
	struct rb_node **n = &(bsc_sccp->connections.rb_node);
	struct rb_node *parent = NULL;
	uint32_t conn_id = sccp_conn->conn_id;

	OSMO_ASSERT(conn_id != SCCP_CONN_ID_UNSET);

	while (*n) {
		struct bscp_sccp_conn_node *it = container_of(*n, struct bscp_sccp_conn_node, node);

		parent = *n;
		if (conn_id < it->conn_id) {
			n = &((*n)->rb_left);
		} else if (conn_id > it->conn_id) {
			n = &((*n)->rb_right);
		} else {
			LOGP(DMSC, LOGL_ERROR,
			     "Trying to reserve already reserved conn_id %u\n", conn_id);
			return -EEXIST;
		}
	}

	rb_link_node(&sccp_conn->node, parent, n);
	rb_insert_color(&sccp_conn->node, &bsc_sccp->connections);
	return 0;
}

void bsc_sccp_inst_unregister_gscon(struct bsc_sccp_inst *bsc_sccp, struct bscp_sccp_conn_node *sccp_conn)
{
	OSMO_ASSERT(sccp_conn->conn_id != SCCP_CONN_ID_UNSET);
	rb_erase(&sccp_conn->node, &bsc_sccp->connections);
}

/* Helper function to Check if the given connection id is already assigned */
struct gsm_subscriber_connection *bsc_sccp_inst_get_gscon_by_conn_id(const struct bsc_sccp_inst *bsc_sccp, uint32_t conn_id)
{
	const struct rb_node *node = bsc_sccp->connections.rb_node;

	OSMO_ASSERT(conn_id != SCCP_CONN_ID_UNSET);
	/* Range (0..SCCP_CONN_ID_MAX) expected, see bsc_sccp_inst_next_conn_id() */
	OSMO_ASSERT(conn_id <= SCCP_CONN_ID_MAX);

	while (node) {
		struct bscp_sccp_conn_node *sccp_conn = container_of(node, struct bscp_sccp_conn_node, node);
		if (conn_id < sccp_conn->conn_id)
			node = node->rb_left;
		else if (conn_id > sccp_conn->conn_id)
			node = node->rb_right;
		else
			return sccp_conn->gscon;
	}

	return NULL;
}

/* We need an unused SCCP conn_id across all SCCP users. */
uint32_t bsc_sccp_inst_next_conn_id(struct bsc_sccp_inst *bsc_sccp)
{
	uint32_t first_id, test_id;

	first_id = test_id = bsc_sccp->next_id;

	/* SUA: RFC3868 sec 3.10.4:
	*    The source reference number is a 4 octet long integer.
	*    This is allocated by the source SUA instance.
	* M3UA/SCCP: ITU-T Q.713 sec 3.3:
	*    The "source local reference" parameter field is a three-octet field containing a
	*    reference number which is generated and used by the local node to identify the
	*    connection section after the connection section is set up.
	*    The coding "all ones" is reserved for future use.
	*Hence, as we currently use the connection ID also as local reference,
	*let's simply use 24 bit ids to fit all link types (excluding 0x00ffffff).
	*/

	while (bsc_sccp_inst_get_gscon_by_conn_id(bsc_sccp, test_id)) {
		/* Optimized modulo operation (% SCCP_CONN_ID_MAX) using bitwise AND plus CMP: */
		test_id = (test_id + 1) & 0x00FFFFFF;
		if (OSMO_UNLIKELY(test_id == 0x00FFFFFF))
			test_id = 0;

		/* Did a whole loop, all used, fail */
		if (OSMO_UNLIKELY(test_id == first_id))
			return SCCP_CONN_ID_UNSET;
	}

	bsc_sccp->next_id = test_id;
	/* Optimized modulo operation (% SCCP_CONN_ID_MAX) using bitwise AND plus CMP: */
	bsc_sccp->next_id = (bsc_sccp->next_id + 1) & 0x00FFFFFF;
	if (OSMO_UNLIKELY(bsc_sccp->next_id == 0x00FFFFFF))
		bsc_sccp->next_id = 0;

	return test_id;
}
