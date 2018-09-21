/* Copyright (C) 2018 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 *
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr <neels@hofmeyr.de>
 *
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

/* This file implements iteration of both local and remote neighbors, which has dependencies to both
 * gsm_data.c as well as neighbor_ident.c. Placing this in gsm_data.c would require various tools to
 * include the neighbor_ident.c implementations. In turn, neighbor_ident.c is gsm_data.c agnostic. */

#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/neighbor_ident.h>

static int bts_local_neighbors_find_by_cell_id(struct gsm_bts *for_bts,
					       const struct gsm0808_cell_id *id,
					       neighbors_find_by_cell_id_cb_t cb,
					       void *cb_data)
{
	int count = 0;
	struct gsm_bts_ref *ref, *ref_next;
	llist_for_each_entry_safe(ref, ref_next, &for_bts->local_neighbors, entry) {
		if (!id || gsm_bts_matches_cell_id(ref->bts, id)) {
			if (cb)
				cb(for_bts, ref->bts, NULL, NULL, -1, cb_data);
			count ++;
		}
	}
	return count;
}

static int all_local_neighbors_find_by_cell_id(struct gsm_network *net,
					       const struct gsm0808_cell_id *id,
					       neighbors_find_by_cell_id_cb_t cb,
					       void *cb_data)
{
	struct gsm_bts *bts, *bts_next;
	int count = 0;
	llist_for_each_entry_safe(bts, bts_next, &net->bts_list, list) {
		count += bts_local_neighbors_find_by_cell_id(bts, id, cb, cb_data);
	}
	return count;
}

struct neighbors_find_by_cell_id_iter_cb_data {
	struct gsm_network *net;
	const struct gsm0808_cell_id *id;
	bool all_matches;
	neighbors_find_by_cell_id_cb_t cb;
	void *cb_data;
	int count;
};

static bool neighbors_find_by_cell_id_iter_cb(const struct neighbor_ident_key *key,
					      const struct gsm0808_cell_id_list2 *val,
					      void *cb_data)
{
	struct neighbors_find_by_cell_id_iter_cb_data *d = cb_data;
	unsigned int match_nr;
	int match_idx;

	for (match_nr = 0; ; match_nr ++) {
		/* On mismatch, just continue iterating. */
		match_idx = gsm0808_cell_id_matches_list(d->id, val, match_nr);
		if (match_idx < 0)
			return true;

		/* Match! */
		if (d->cb)
			d->cb(d->net ? gsm_bts_num(d->net, key->from_bts) : NULL,
			      NULL,
			      key, val,
			      match_idx,
			      d->cb_data);
		d->count ++;

		/* If neighbors_find_by_cell_id() was invoked with remote_neighbors_all_matches == false,
		 * stop looking after the first match in this list. */
		if (!d->all_matches)
			return true;
	}
	return true;
}

/* Find all neighbors that match a given Cell Identifier.
 * If 'for_bts' is given, only neighbors for that cell are returned; NULL matches all cells' neighbors.
 * If 'neighbor_bss_cells' is NULL, no remote neighbors are returned.
 * If 'id' is NULL, all neighbors are returned. The id restricts the matches, where a CGI type is most
 * restrictive, and a LAC type might still match a neighbor with LAC+CI or a neighbor with full CGI that
 * contains this LAC.
 * Results are returned by calling the cb(). If cb() returns false, further iteration is stopped.
 * It is safe to remove any neighbor entries, except the neighbor entry *following* the one passed to
 * cb(), i.e. you may remove the neighbor passed to cb(), but not the adjacent following llist entry.
 *
 * With remote_neighbors_exact_match == true, ignore remote-BSS neighbors with a cell id list that have a
 * CELL_IDENT that differs from the id->id_discr. With false, any matching cell id item counts, e.g. a
 * LAC of 23 matches a CGI that contains a LAC = 23.
 *
 * With remote_neighbors_all_matches == false, return only the first match in each cell id list of a
 * remote neighbor. With true, cb() will be invoked for each matching val_idx in the given cell id list.
 */
int neighbors_find_by_cell_id(struct gsm_network *net,
			      struct gsm_bts *for_bts,
			      struct neighbor_ident_list *neighbor_bss_cells,
			      const struct gsm0808_cell_id *id,
			      bool remote_neighbors_exact_match,
			      bool remote_neighbors_all_matches,
			      neighbors_find_by_cell_id_cb_t cb,
			      void *cb_data)
{
	int count = 0;

	/* Local neighbors */
	if (for_bts) {
		count += bts_local_neighbors_find_by_cell_id(for_bts, id, cb, cb_data);
		if (!net)
			net = for_bts->network;
	} else if (net)
		count += all_local_neighbors_find_by_cell_id(net, id, cb, cb_data);

	/* Remote neighbors */
	if (neighbor_bss_cells) {
		struct neighbors_find_by_cell_id_iter_cb_data d = {
			.net = net,
			.id = id,
			.all_matches = remote_neighbors_all_matches,
			.cb = cb,
			.cb_data = cb_data,
		};

		neighbor_ident_iter(neighbor_bss_cells,
				    neighbors_find_by_cell_id_iter_cb,
				    &d);
		count += d.count;
	}
	return count;
}
