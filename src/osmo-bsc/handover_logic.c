/* Handover Logic for Inter-BTS (Intra-BSC) Handover.  This does not
 * actually implement the handover algorithm/decision, but executes a
 * handover decision */

/* (C) 2009 by Harald Welte <laforge@gnumonks.org>
 *
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <netinet/in.h>

#include <osmocom/core/msgb.h>
#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/gsm_data.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/bsc/abis_rsl.h>
#include <osmocom/bsc/lchan_select.h>
#include <osmocom/bsc/signal.h>
#include <osmocom/core/talloc.h>
#include <osmocom/bsc/bsc_subscriber.h>
#include <osmocom/bsc/gsm_04_08_rr.h>
#include <osmocom/bsc/handover.h>
#include <osmocom/bsc/handover_cfg.h>
#include <osmocom/bsc/bsc_subscr_conn_fsm.h>
#include <osmocom/bsc/neighbor_ident.h>
#include <osmocom/bsc/abis_nm.h>
#include <osmocom/gsm/gsm0808.h>
#include <osmocom/gsm/gsm0808_utils.h>

const struct value_string handover_scope_names[] = {
	{ HO_NO_HANDOVER, "HO-none" },
	{ HO_INTRA_CELL, "AS" },
	{ HO_INTRA_BSC, "HO-intraBSC" },
	{ HO_INTER_BSC_OUT, "HO-interBSC-Out" },
	{ HO_INTER_BSC_IN, "HO-interBSC-In" },
	{ HO_SCOPE_ALL, "HO-any" },
	{}
};

const struct value_string handover_result_names[] = {
	{ HO_RESULT_OK, "Complete" },
	{ HO_RESULT_FAIL_NO_CHANNEL, "Failure (no channel could be allocated)" },
	{ HO_RESULT_FAIL_RR_HO_FAIL, "Failure (MS sent RR Handover Failure)" },
	{ HO_RESULT_FAIL_TIMEOUT, "Failure (timeout)" },
	{ HO_RESULT_CONN_RELEASE, "Connection released" },
	{ HO_RESULT_ERROR, "Failure" },
	{}
};

static LLIST_HEAD(handover_decision_callbacks);

void handover_decision_callbacks_register(struct handover_decision_callbacks *hdc)
{
	llist_add_tail(&hdc->entry, &handover_decision_callbacks);
}

struct handover_decision_callbacks *handover_decision_callbacks_get(int hodec_id)
{
	struct handover_decision_callbacks *hdc;
	llist_for_each_entry(hdc, &handover_decision_callbacks, entry) {
		if (hdc->hodec_id == hodec_id)
			return hdc;
	}
	return NULL;
}

static void ho_meas_rep(struct gsm_meas_rep *mr)
{
	struct handover_decision_callbacks *hdc;
	enum hodec_id hodec_id = ho_get_algorithm(mr->lchan->ts->trx->bts->ho);

	hdc = handover_decision_callbacks_get(hodec_id);
	if (!hdc || !hdc->on_measurement_report)
		return;
	hdc->on_measurement_report(mr);
}

/* Count ongoing handovers within the given BTS.
 * ho_scopes is an OR'd combination of enum handover_scope values to include in the count. */
int bts_handover_count(struct gsm_bts *bts, int ho_scopes)
{
	struct gsm_bts_trx *trx;
	int count = 0;

	llist_for_each_entry(trx, &bts->trx_list, list) {
		int i;
		for (i = 0; i < ARRAY_SIZE(trx->ts); i++) {
			struct gsm_bts_trx_ts *ts = &trx->ts[i];
			struct gsm_lchan *lchan;

			/* skip administratively deactivated timeslots */
			if (!nm_is_running(&ts->mo.nm_state))
				continue;

			ts_for_each_lchan(lchan, ts) {
				if (!lchan->conn)
					continue;
				if (!lchan->conn->ho.fi)
					continue;
				if (lchan->conn->ho.scope & ho_scopes)
					count++;
			}
		}
	}

	return count;
}

/* Find out a handover target cell for the given neighbor_ident_key,
 * and make sure there are no ambiguous matches.
 * Given a source BTS and a target ARFCN+BSIC, find which cell is the right handover target.
 * ARFCN+BSIC may be re-used within and/or across BSS, so make sure that only those cells that are explicitly
 * listed as neighbor of the source cell are viable handover targets.
 * The (legacy) default configuration is that, when no explicit neighbors are listed, that all local cells are
 * neighbors, in which case each ARFCN+BSIC must exist at most once.
 * If there is more than one viable handover target cell found for the given ARFCN+BSIC, that constitutes a
 * configuration error and should not result in handover, so that the system's misconfiguration is more likely
 * to be found.
 */
int find_handover_target_cell(struct gsm_bts **local_target_cell_p,
			      const struct gsm0808_cell_id_list2 **remote_target_cell_p,
			      struct gsm_subscriber_connection *conn, const struct neighbor_ident_key *search_for,
			      bool log_errors)
{
	struct gsm_network *net = conn->network;
	struct gsm_bts *from_bts;
	struct gsm_bts *local_target_cell = NULL;
	const struct gsm0808_cell_id_list2 *remote_target_cell = NULL;
	struct gsm_bts_ref *neigh;
	bool ho_active;
	bool as_active;

	if (local_target_cell_p)
		*local_target_cell_p = NULL;
	if (remote_target_cell_p)
		*remote_target_cell_p = NULL;

	if (!search_for) {
		if (log_errors)
			LOG_HO(conn, LOGL_ERROR, "Handover without target cell\n");
		return -EINVAL;
	}

	from_bts = gsm_bts_num(net, search_for->from_bts);
	if (!from_bts) {
		if (log_errors)
			LOG_HO(conn, LOGL_ERROR, "Handover without source cell\n");
		return -EINVAL;
	}

	ho_active = ho_get_ho_active(from_bts->ho);
	as_active = (ho_get_algorithm(from_bts->ho) == 2)
		&& ho_get_hodec2_as_active(from_bts->ho);
	if (!ho_active && !as_active) {
		if (log_errors)
			LOG_HO(conn, LOGL_ERROR, "Cannot start Handover: Handover and Assignment disabled for this source cell (%s)\n",
			       neighbor_ident_key_name(search_for));
		return -EINVAL;
	}

	if (llist_empty(&from_bts->local_neighbors)
	    && !neighbor_ident_bts_entry_exists(from_bts->nr)) {
		/* No explicit neighbor entries exist for this BTS. Hence apply the legacy default behavior that all
		 * local cells are neighbors. */
		struct gsm_bts *bts;
		struct gsm_bts *wildcard_match = NULL;

		LOG_HO(conn, LOGL_DEBUG, "No explicit neighbors, regarding all local cells as neighbors\n");

		llist_for_each_entry(bts, &net->bts_list, list) {
			struct neighbor_ident_key bts_key = *bts_ident_key(bts);
			if (neighbor_ident_key_match(&bts_key, search_for, true)) {
				if (local_target_cell) {
					if (log_errors)
						LOG_HO(conn, LOGL_ERROR,
						       "NEIGHBOR CONFIGURATION ERROR: Multiple local cells match %s"
						       " (BTS %d and BTS %d)."
						       " Aborting Handover because of ambiguous network topology.\n",
						       neighbor_ident_key_name(search_for),
						       local_target_cell->nr, bts->nr);
					return -EINVAL;
				}
				local_target_cell = bts;
			}
			if (neighbor_ident_key_match(&bts_key, search_for, false))
				wildcard_match = bts;
		}

		if (!local_target_cell)
			local_target_cell = wildcard_match;

		if (!local_target_cell) {
			if (log_errors)
				LOG_HO(conn, LOGL_ERROR, "Cannot Handover, no cell matches %s\n",
				       neighbor_ident_key_name(search_for));
			return -EINVAL;
		}

		if (local_target_cell == from_bts && !as_active) {
			if (log_errors)
				LOG_HO(conn, LOGL_ERROR,
				       "Cannot start re-assignment, Assignment disabled for this cell (%s)\n",
				       neighbor_ident_key_name(search_for));
			return -EINVAL;
		}
		if (local_target_cell != from_bts && !ho_active) {
			if (log_errors)
				LOG_HO(conn, LOGL_ERROR,
				       "Cannot start Handover, Handover disabled for this cell (%s)\n",
				       neighbor_ident_key_name(search_for));
			return -EINVAL;
		}

		if (local_target_cell_p)
			*local_target_cell_p = local_target_cell;
		return 0;
	}

	/* One or more local- or remote-BSS cell neighbors are configured. Find a match among those, but also detect
	 * ambiguous matches (if multiple cells match, it is a configuration error). */

	LOG_HO(conn, LOGL_DEBUG, "There are explicit neighbors configured for this cell\n");

	/* Iterate explicit local neighbor cells */
	llist_for_each_entry(neigh, &from_bts->local_neighbors, entry) {
		struct gsm_bts *neigh_bts = neigh->bts;
		struct neighbor_ident_key neigh_bts_key = *bts_ident_key(neigh_bts);
		neigh_bts_key.from_bts = from_bts->nr;

		LOG_HO(conn, LOGL_DEBUG, "Local neighbor %s\n", neighbor_ident_key_name(&neigh_bts_key));

		if (!neighbor_ident_key_match(&neigh_bts_key, search_for, true)) {
			LOG_HO(conn, LOGL_DEBUG, "Doesn't match %s\n", neighbor_ident_key_name(search_for));
			continue;
		}

		if (local_target_cell) {
			if (log_errors)
				LOG_HO(conn, LOGL_ERROR,
				       "NEIGHBOR CONFIGURATION ERROR: Multiple BTS match %s (BTS %d and BTS %d)."
				       " Aborting Handover because of ambiguous network topology.\n",
				       neighbor_ident_key_name(search_for), local_target_cell->nr, neigh_bts->nr);
			return -EINVAL;
		}

		local_target_cell = neigh_bts;
	}

	/* Any matching remote-BSS neighbor cell? */
	remote_target_cell = neighbor_ident_get(net->neighbor_bss_cells, search_for);

	if (remote_target_cell)
		LOG_HO(conn, LOGL_DEBUG, "Found remote target cell %s\n",
		       gsm0808_cell_id_list_name(remote_target_cell));

	if (local_target_cell && remote_target_cell) {
		if (log_errors)
			LOG_HO(conn, LOGL_ERROR, "NEIGHBOR CONFIGURATION ERROR: Both a local and a remote-BSS cell match %s"
			       " (BTS %d and remote %s)."
			       " Aborting Handover because of ambiguous network topology.\n",
			       neighbor_ident_key_name(search_for), local_target_cell->nr,
			       gsm0808_cell_id_list_name(remote_target_cell));
		return -EINVAL;
	}

	if (local_target_cell == from_bts && !as_active) {
		if (log_errors)
			LOG_HO(conn, LOGL_ERROR,
			       "Cannot start re-assignment, Assignment disabled for this cell (%s)\n",
			       neighbor_ident_key_name(search_for));
		return -EINVAL;
	}

	if (((local_target_cell && local_target_cell != from_bts)
	     || remote_target_cell)
	    && !ho_active) {
		if (log_errors)
			LOG_HO(conn, LOGL_ERROR,
			       "Cannot start Handover, Handover disabled for this cell (%s)\n",
			       neighbor_ident_key_name(search_for));
		return -EINVAL;
	}

	if (local_target_cell) {
		if (local_target_cell_p)
			*local_target_cell_p = local_target_cell;
		return 0;
	}

	if (remote_target_cell) {
		if (remote_target_cell_p)
			*remote_target_cell_p = remote_target_cell;
		return 0;
	}

	if (log_errors)
		LOG_HO(conn, LOGL_ERROR, "Cannot handover %s: neighbor unknown\n",
		       neighbor_ident_key_name(search_for));

	return -ENODEV;
}

struct neighbor_ident_key *bts_ident_key(const struct gsm_bts *bts)
{
	static struct neighbor_ident_key key;
	key = (struct neighbor_ident_key){
		.from_bts = NEIGHBOR_IDENT_KEY_ANY_BTS,
		.arfcn = bts->c0->arfcn,
		.bsic = bts->bsic,
	};
	return &key;
}

static int ho_logic_sig_cb(unsigned int subsys, unsigned int signal,
			   void *handler_data, void *signal_data)
{
	struct lchan_signal_data *lchan_data;
	struct gsm_lchan *lchan;

	lchan_data = signal_data;
	switch (subsys) {
	case SS_LCHAN:
		OSMO_ASSERT(lchan_data);
		lchan = lchan_data->lchan;
		OSMO_ASSERT(lchan);

		switch (signal) {
		case S_LCHAN_MEAS_REP:
			ho_meas_rep(lchan_data->mr);
			break;
		}

	default:
		break;
	}
	return 0;
}

static __attribute__((constructor)) void on_dso_load_ho_logic(void)
{
	osmo_signal_register_handler(SS_LCHAN, ho_logic_sig_cb, NULL);
}
