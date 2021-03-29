/* Manage identity of neighboring BSS cells for inter-BSC handover.
 *
 * Measurement reports tell us about neighbor ARFCN and BSIC. If that ARFCN and BSIC is not managed by
 * this local BSS, we need to tell the MSC a cell identity, like CGI, LAC+CI, etc. -- hence we need a
 * mapping from ARFCN+BSIC to Cell Identifier List, which needs to be configured by the user.
 */
/* (C) 2018 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 *
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr <nhofmeyr@sysmocom.de>
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

#include <errno.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/utils.h>
#include <osmocom/gsm/gsm0808.h>

#include <osmocom/bsc/neighbor_ident.h>

#include <osmocom/ctrl/control_cmd.h>
#include <osmocom/ctrl/control_if.h>

#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/bts.h>
#include <osmocom/bsc/debug.h>

void bts_cell_ab(struct cell_ab *arfcn_bsic, const struct gsm_bts *bts)
{
	*arfcn_bsic = (struct cell_ab){
		.arfcn = bts->c0->arfcn,
		.bsic = bts->bsic,
	};
}

/* Find the local gsm_bts pointer that a specific other BTS' neighbor config refers to. Return NULL if there is no such
 * local cell in this BSS.
 */
int resolve_local_neighbor(struct gsm_bts **local_neighbor_p, const struct gsm_bts *from_bts,
			   const struct neighbor *neighbor)
{
	struct gsm_bts *bts;
	struct gsm_bts *bts_exact = NULL;
	struct gsm_bts *bts_wildcard = NULL;
	*local_neighbor_p = NULL;

	switch (neighbor->type) {
	case NEIGHBOR_TYPE_BTS_NR:
		bts = gsm_bts_num(bsc_gsmnet, neighbor->bts_nr);
		goto check_bts;

	case NEIGHBOR_TYPE_CELL_ID:
		/* Find cell id below */
		break;

	default:
		return -ENOTSUP;
	}

	/* NEIGHBOR_TYPE_CELL_ID */
	llist_for_each_entry(bts, &bsc_gsmnet->bts_list, list) {
		struct gsm0808_cell_id cell_id;
		gsm_bts_cell_id(&cell_id, bts);

		if (gsm0808_cell_ids_match(&cell_id, &neighbor->cell_id.id, true)) {
			if (bts_exact) {
				LOGP(DHO, LOGL_ERROR,
				     "Neighbor config error: Multiple BTS match %s (BTS %u and BTS %u)\n",
				     gsm0808_cell_id_name_c(OTC_SELECT, &neighbor->cell_id.id),
				     bts_exact->nr, bts->nr);
				return -EINVAL;
			} else {
				bts_exact = bts;
			}
		}

		if (!bts_wildcard && gsm0808_cell_ids_match(&cell_id, &neighbor->cell_id.id, false))
			bts_wildcard = bts;
	}

	bts = (bts_exact ? : bts_wildcard);

check_bts:
	/* A cell cannot be its own neighbor */
	if (bts == from_bts) {
		LOGP(DHO, LOGL_ERROR,
		     "Neighbor config error: BTS %u -> %s: this cell is configured as its own neighbor\n",
		     from_bts->nr, neighbor_to_str_c(OTC_SELECT, neighbor));
		return -EINVAL;
	}

	if (!bts)
		return -ENOENT;

	/* Double check whether ARFCN + BSIC config matches, if present. */
	if (neighbor->cell_id.ab_present) {
		struct cell_ab cell_ab;
		bts_cell_ab(&cell_ab, bts);
		if (!cell_ab_match(&cell_ab, &neighbor->cell_id.ab, false)) {
			LOGP(DHO, LOGL_ERROR, "Neighbor config error: Local BTS %d matches %s, but not ARFCN+BSIC %s\n",
			     bts->nr, gsm0808_cell_id_name_c(OTC_SELECT, &neighbor->cell_id.id),
			     cell_ab_to_str_c(OTC_SELECT, &cell_ab));
			return -EINVAL;
		}
	}

	*local_neighbor_p = bts;
	return 0;
}

int resolve_neighbors(struct gsm_bts **local_neighbor_p, struct gsm0808_cell_id_list2 *remote_neighbors,
		      struct gsm_bts *from_bts, const struct cell_ab *target_ab, bool log_errors)
{
	struct neighbor *n;
	struct gsm_bts *local_neighbor = NULL;
	struct gsm0808_cell_id_list2 remotes = {};

	if (local_neighbor_p)
		*local_neighbor_p = NULL;
	if (remote_neighbors)
		*remote_neighbors = (struct gsm0808_cell_id_list2){ 0 };

	llist_for_each_entry(n, &from_bts->neighbors, entry) {
		struct gsm_bts *neigh_bts;
		if (resolve_local_neighbor(&neigh_bts, from_bts, n) == 0) {
			/* This neighbor entry is a local cell neighbor. Do ARFCN and BSIC match? */
			struct cell_ab ab;
			bts_cell_ab(&ab, neigh_bts);
			if (!cell_ab_match(&ab, target_ab, false))
				continue;

			/* Found a local cell neighbor that matches the target_ab */

			/* If we already found one, these are ambiguous local neighbors */
			if (local_neighbor) {
				if (log_errors)
					LOGP(DHO, LOGL_ERROR, "Neighbor config error:"
					     " Local BTS %d -> %s resolves to local neighbor BTSes %u *and* %u\n",
					     from_bts->nr, cell_ab_to_str_c(OTC_SELECT, target_ab), local_neighbor->nr,
					     neigh_bts->nr);
				return -ENOTSUP;
			}
			local_neighbor = neigh_bts;

		} else if (n->type == NEIGHBOR_TYPE_CELL_ID && n->cell_id.ab_present) {
			/* This neighbor entry is a remote-BSS neighbor. There may be multiple remote neighbors,
			 * collect those in a gsm0808_cell_id_list2 (remote_target_cells). A limitation is that all of
			 * them need to be of the same cell id type. */
			struct gsm0808_cell_id_list2 add_item;
			int rc;

			if (!cell_ab_match(&n->cell_id.ab, target_ab, false))
				continue;

			/* Convert the gsm0808_cell_id to a list, so that we can use gsm0808_cell_id_list_add(). */
			gsm0808_cell_id_to_list(&add_item, &n->cell_id.id);
			rc = gsm0808_cell_id_list_add(&remotes, &add_item);
			if (rc < 0) {
				if (log_errors)
					LOGP(DHO, LOGL_ERROR, "Neighbor config error:"
					     " Local BTS %d -> %s resolves to remote-BSS neighbor %s;"
					     " Could not store this in neighbors list %s\n",
					     from_bts->nr, cell_ab_to_str_c(OTC_SELECT, target_ab),
					     gsm0808_cell_id_name_c(OTC_SELECT, &n->cell_id.id),
					     gsm0808_cell_id_list_name_c(OTC_SELECT, &remotes));
				return rc;
			}
		}
		/* else: neighbor entry that does not resolve to anything. */
	}

	if (local_neighbor_p)
		*local_neighbor_p = local_neighbor;
	if (remote_neighbors)
		*remote_neighbors = remotes;

	if (!local_neighbor && !remotes.id_list_len)
		return -ENOENT;
	return 0;
}

int cell_ab_to_str_buf(char *buf, size_t buflen, const struct cell_ab *cell)
{
	struct osmo_strbuf sb = { .buf = buf, .len = buflen };
	OSMO_STRBUF_PRINTF(sb, "ARFCN-BSIC:%u", cell->arfcn);
	if (cell->bsic == BSIC_ANY)
		OSMO_STRBUF_PRINTF(sb, "-any");
	else {
		OSMO_STRBUF_PRINTF(sb, "-%u", cell->bsic);
		if (cell->bsic > 0x3f)
			OSMO_STRBUF_PRINTF(sb, "[ERANGE>63]");
	}
	return sb.chars_needed;
}

char *cell_ab_to_str_c(void *ctx, const struct cell_ab *cell)
{
	OSMO_NAME_C_IMPL(ctx, 64, "ERROR", cell_ab_to_str_buf, cell)
}

int neighbor_to_str_buf(char *buf, size_t buflen, const struct neighbor *n)
{
	struct osmo_strbuf sb = { .buf = buf, .len = buflen };
	switch (n->type) {
	case NEIGHBOR_TYPE_BTS_NR:
		OSMO_STRBUF_PRINTF(sb, "BTS %u", n->bts_nr);
		break;
	case NEIGHBOR_TYPE_CELL_ID:
		OSMO_STRBUF_APPEND_NOLEN(sb, gsm0808_cell_id_name_buf, &n->cell_id.id);
		if (n->cell_id.ab_present) {
			OSMO_STRBUF_PRINTF(sb, " ");
			OSMO_STRBUF_APPEND(sb, cell_ab_to_str_buf, &n->cell_id.ab);
		}
		break;
	case NEIGHBOR_TYPE_UNSET:
		OSMO_STRBUF_PRINTF(sb, "UNSET");
		break;
	default:
		OSMO_STRBUF_PRINTF(sb, "INVALID");
		break;
	}
	return sb.chars_needed;
}

char *neighbor_to_str_c(void *ctx, const struct neighbor *n)
{
	OSMO_NAME_C_IMPL(ctx, 64, "ERROR", neighbor_to_str_buf, n);
}

bool neighbor_same(const struct neighbor *a, const struct neighbor *b, bool check_cell_ab)
{
	if (a == b)
		return true;
	if (a->type != b->type)
		return false;

	switch (a->type) {
	case NEIGHBOR_TYPE_BTS_NR:
		return a->bts_nr == b->bts_nr;

	case NEIGHBOR_TYPE_CELL_ID:
		if (check_cell_ab
		    && (a->cell_id.ab_present != b->cell_id.ab_present
			|| !cell_ab_match(&a->cell_id.ab, &b->cell_id.ab, true)))
			return false;
		return gsm0808_cell_ids_match(&a->cell_id.id, &b->cell_id.id, true);
	default:
		return a->type == b->type;
	}
}

/* Return true when the entry matches the search_for requirements.
 * If exact_match is false, a BSIC_ANY entry acts as wildcard to match any search_for on that ARFCN,
 * and a BSIC_ANY in search_for likewise returns any one entry that matches the ARFCN.
 * If exact_match is true, only identical bsic values return a match.
 * Note, typically wildcard BSICs are only in entry, e.g. the user configured list, and search_for
 * contains a specific BSIC, e.g. as received from a Measurement Report. */
bool cell_ab_match(const struct cell_ab *entry,
		   const struct cell_ab *search_for,
		   bool exact_match)
{
	if (entry->arfcn != search_for->arfcn)
		return false;

	if (exact_match && entry->bsic != search_for->bsic)
		return false;

	if (entry->bsic == BSIC_ANY || search_for->bsic == BSIC_ANY)
		return true;

	return entry->bsic == search_for->bsic;
}

bool cell_ab_valid(const struct cell_ab *cell)
{
	if (cell->bsic != BSIC_ANY && cell->bsic > 0x3f)
		return false;
	return true;
}

int neighbors_check_cfg()
{
	/* A local neighbor can be configured by BTS number, or by a cell ID. A local neighbor can omit the ARFCN+BSIC,
	 * in which case those are taken from that local BTS config. If a local neighbor has ARFCN+BSIC configured, it
	 * must match the local cell's configuration.
	 *
	 * A remote neighbor must always be a cell ID *and* ARFCN+BSIC.
	 *
	 * Hence any cell ID with ARFCN+BSIC where the cell ID is not found among the local cells is a remote-BSS
	 * neighbor.
	 */
	struct gsm_bts *bts;
	bool ok = true;

	llist_for_each_entry(bts, &bsc_gsmnet->bts_list, list) {
		struct neighbor *neighbor;
		struct gsm_bts *local_neighbor;
		llist_for_each_entry(neighbor, &bts->neighbors, entry) {
			switch (neighbor->type) {

			case NEIGHBOR_TYPE_BTS_NR:
				if (!gsm_bts_num(bsc_gsmnet, neighbor->bts_nr)) {
					LOGP(DHO, LOGL_ERROR, "Neighbor Configuration Error:"
					     " BTS %u -> BTS %u: There is no BTS nr %u\n",
					     bts->nr, neighbor->bts_nr, neighbor->bts_nr);
					ok = false;
				}
				break;

			default:
				switch (resolve_local_neighbor(&local_neighbor, bts, neighbor)) {
				case 0:
					break;
				case -ENOENT:
					if (!neighbor->cell_id.ab_present) {
						LOGP(DHO, LOGL_ERROR, "Neighbor Configuration Error:"
						     " BTS %u -> %s: There is no such local neighbor\n",
						     bts->nr, neighbor_to_str_c(OTC_SELECT, neighbor));
						ok = false;
					}
					break;
				default:
					/* Error already logged in resolve_local_neighbor() */
					ok = false;
					break;
				}
				break;
			}
		}
	}

	if (!ok)
		return -EINVAL;
	return 0;
}

/* Neighbor Resolution CTRL iface */

CTRL_CMD_DEFINE_RO(neighbor_resolve_cgi_ps_from_lac_ci, "neighbor_resolve_cgi_ps_from_lac_ci");

static int gsm_bts_get_cgi_ps(const struct gsm_bts *bts, struct osmo_cell_global_id_ps *cgi_ps)
{
	if (bts->gprs.mode == BTS_GPRS_NONE)
		return -ENOTSUP;

	cgi_ps->rai.lac.plmn = bts->network->plmn;
	cgi_ps->rai.lac.lac = bts->location_area_code;
	cgi_ps->rai.rac = bts->gprs.rac;
	cgi_ps->cell_identity = bts->cell_identity;

	return 0;
}

static int get_neighbor_resolve_cgi_ps_from_lac_ci(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_network *net = (struct gsm_network *)data;
	struct gsm_bts *bts_tmp, *bts_found = NULL;
	char *tmp = NULL, *tok, *saveptr;
	struct cell_ab ab;
	unsigned lac, cell_id;
	struct osmo_cell_global_id_ps local_cgi_ps;
	const struct osmo_cell_global_id_ps *cgi_ps = NULL;
	struct gsm_bts *local_neighbor = NULL;
	struct gsm0808_cell_id_list2 remote_neighbors = { 0 };

	if (!cmd->variable)
		goto fmt_err;

	tmp = talloc_strdup(cmd, cmd->variable);
	if (!tmp) {
		cmd->reply = "OOM";
		return CTRL_CMD_ERROR;
	}

	if (!(tok = strtok_r(tmp, ".", &saveptr)))
		goto fmt_err;
	OSMO_ASSERT(strcmp(tok, "neighbor_resolve_cgi_ps_from_lac_ci") == 0);

	if (!(tok = strtok_r(NULL, ".", &saveptr)))
		goto fmt_err;
	lac = atoi(tok);

	if (!(tok = strtok_r(NULL, ".", &saveptr)))
		goto fmt_err;
	cell_id = atoi(tok);

	if (!(tok = strtok_r(NULL, ".", &saveptr)))
		goto fmt_err;
	ab.arfcn = atoi(tok);

	if (!(tok = strtok_r(NULL, "\0", &saveptr)))
		goto fmt_err;
	ab.bsic = atoi(tok);

	llist_for_each_entry(bts_tmp, &net->bts_list, list) {
		if (bts_tmp->location_area_code != lac)
			continue;
		if (bts_tmp->cell_identity != cell_id)
			continue;
		bts_found = bts_tmp;
		break;
	}

	if (!bts_found)
		goto notfound_err;

	LOG_BTS(bts_found, DLINP, LOGL_DEBUG, "Resolving neighbor BTS %u -> %s\n", bts_found->nr,
		cell_ab_to_str_c(OTC_SELECT, &ab));

	if (!cell_ab_valid(&ab))
		goto fmt_err;

	if (resolve_neighbors(&local_neighbor, &remote_neighbors, bts_found, &ab, true))
		goto notfound_err;

	/* resolve_neighbors() returns either a local_neighbor or remote_neighbors.
	 * Local-BSS neighbor? */
	if (local_neighbor) {
		/* Supporting GPRS? */
		if (gsm_bts_get_cgi_ps(local_neighbor, &local_cgi_ps) >= 0)
			cgi_ps = &local_cgi_ps;
	}

	/* Remote-BSS neighbor?
	 * By spec, there can be multiple remote neighbors for a given ARFCN+BSIC, but so far osmo-bsc enforces only a
	 * single remote neighbor. */
	if (remote_neighbors.id_list_len
	    && remote_neighbors.id_discr == CELL_IDENT_WHOLE_GLOBAL_PS) {
		cgi_ps = &remote_neighbors.id_list[0].global_ps;
	}

	/* No neighbor found */
	if (!cgi_ps)
		goto notfound_err;

	ctrl_cmd_reply_printf(cmd, "%s", osmo_cgi_ps_name(cgi_ps));
	talloc_free(tmp);
	return CTRL_CMD_REPLY;

notfound_err:
	talloc_free(tmp);
	cmd->reply = talloc_strdup(cmd, "No target CGI PS found");
	return CTRL_CMD_ERROR;
fmt_err:
	talloc_free(tmp);
	cmd->reply = talloc_strdup(cmd, "The format is <src_lac>,<src_cell_id>,<dst_arfcn>,<dst_bsic>");
	return CTRL_CMD_ERROR;
}

int neighbor_ctrl_cmds_install(struct gsm_network *net)
{
	int rc;

	rc = ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_neighbor_resolve_cgi_ps_from_lac_ci);
	return rc;
}

struct ctrl_handle *neighbor_controlif_setup(struct gsm_network *net)
{
	return ctrl_interface_setup_dynip2(net, net->neigh_ctrl.addr, net->neigh_ctrl.port,
					   NULL, _LAST_CTRL_NODE_NEIGHBOR);
}
