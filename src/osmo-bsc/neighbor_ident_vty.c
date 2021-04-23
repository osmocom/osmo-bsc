/* Quagga VTY implementation to manage identity of neighboring BSS cells for inter-BSC handover. */
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

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>

#include <osmocom/ctrl/ports.h>

#include <osmocom/vty/command.h>
#include <osmocom/gsm/gsm0808.h>

#include <osmocom/bsc/vty.h>
#include <osmocom/bsc/neighbor_ident.h>
#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/bts.h>

#define NEIGHBOR_ADD_CMD "neighbor "
#define NEIGHBOR_DEL_CMD "no neighbor "
#define NEIGHBOR_DOC "Manage local and remote-BSS neighbor cells\n"
#define NEIGHBOR_ADD_DOC NEIGHBOR_DOC "Add "
#define NEIGHBOR_DEL_DOC NO_STR "Remove local or remote-BSS neighbor cell\n"

#define LAC_PARAMS "lac <0-65535>"
#define LAC_ARGC 1
#define LAC_DOC "Neighbor cell by LAC\n" "LAC\n"

#define LAC_CI_PARAMS "lac-ci <0-65535> <0-65535>"
#define LAC_CI_ARGC 2
#define LAC_CI_DOC "Neighbor cell by LAC and CI\n" "LAC\n" "CI\n"

#define CGI_PARAMS "cgi <0-999> <0-999> <0-65535> <0-65535>"
#define CGI_ARGC 4
#define CGI_DOC "Neighbor cell by cgi\n" "MCC\n" "MNC\n" "LAC\n" "CI\n"

#define CGI_PS_PARAMS "cgi-ps <0-999> <0-999> <0-65535> <0-255> <0-65535>"
#define CGI_PS_ARGC 5
#define CGI_PS_DOC "Neighbor cell by cgi (Packet Switched, with RAC)\n" "MCC\n" "MNC\n" "LAC\n" "RAC\n" "CI\n"

#define LOCAL_BTS_PARAMS "bts <0-255>"
#define LOCAL_BTS_DOC "Neighbor cell by local BTS number\n" "BTS number\n"

static int neighbor_ident_vty_parse_lac(struct vty *vty, struct gsm0808_cell_id *cell_id, const char **argv)
{
	*cell_id = (struct gsm0808_cell_id){
		.id_discr = CELL_IDENT_LAC,
		.id.lac = atoi(argv[0]),
	};
	return 0;
}

static int neighbor_ident_vty_parse_lac_ci(struct vty *vty, struct gsm0808_cell_id *cell_id, const char **argv)
{
	*cell_id = (struct gsm0808_cell_id){
		.id_discr = CELL_IDENT_LAC_AND_CI,
		.id.lac_and_ci = {
			.lac = atoi(argv[0]),
			.ci = atoi(argv[1]),
		},
	};
	return 0;
}

static int neighbor_ident_vty_parse_cgi(struct vty *vty, struct gsm0808_cell_id *cell_id, const char **argv)
{
	*cell_id = (struct gsm0808_cell_id){
		.id_discr = CELL_IDENT_WHOLE_GLOBAL,
	};
	struct osmo_cell_global_id *cgi = &cell_id->id.global;
	const char *mcc = argv[0];
	const char *mnc = argv[1];
	const char *lac = argv[2];
	const char *ci = argv[3];

	if (osmo_mcc_from_str(mcc, &cgi->lai.plmn.mcc)) {
		vty_out(vty, "%% Error decoding MCC: %s%s", mcc, VTY_NEWLINE);
		return -1;
	}

	if (osmo_mnc_from_str(mnc, &cgi->lai.plmn.mnc, &cgi->lai.plmn.mnc_3_digits)) {
		vty_out(vty, "%% Error decoding MNC: %s%s", mnc, VTY_NEWLINE);
		return -1;
	}

	cgi->lai.lac = atoi(lac);
	cgi->cell_identity = atoi(ci);
	return 0;
}

static int neighbor_ident_vty_parse_cgi_ps(struct vty *vty, struct gsm0808_cell_id *cell_id, const char **argv)
{
	*cell_id = (struct gsm0808_cell_id){
		.id_discr = CELL_IDENT_WHOLE_GLOBAL_PS,
	};
	struct osmo_cell_global_id_ps *cgi_ps = &cell_id->id.global_ps;
	const char *mcc = argv[0];
	const char *mnc = argv[1];
	const char *lac = argv[2];
	const char *rac = argv[3];
	const char *ci = argv[4];

	if (osmo_mcc_from_str(mcc, &cgi_ps->rai.lac.plmn.mcc)) {
		vty_out(vty, "%% Error decoding MCC: %s%s", mcc, VTY_NEWLINE);
		return -1;
	}

	if (osmo_mnc_from_str(mnc, &cgi_ps->rai.lac.plmn.mnc, &cgi_ps->rai.lac.plmn.mnc_3_digits)) {
		vty_out(vty, "%% Error decoding MNC: %s%s", mnc, VTY_NEWLINE);
		return -1;
	}

	cgi_ps->rai.lac.lac = atoi(lac);
	cgi_ps->rai.rac = atoi(rac);
	cgi_ps->cell_identity = atoi(ci);
	return 0;
}

void neighbor_ident_vty_parse_arfcn_bsic(struct cell_ab *ab, const char **argv)
{
	const char *arfcn_str = argv[0];
	const char *bsic_str = argv[1];

	*ab = (struct cell_ab){
		.arfcn = atoi(arfcn_str),
		.bsic = (!strcmp(bsic_str, "any")) ? BSIC_ANY : atoi(bsic_str),
	};
}

static int add_neighbor(struct vty *vty, struct neighbor *n)
{
	struct gsm_bts *bts = vty->index;
	struct neighbor *neighbor;

	OSMO_ASSERT((vty->node == BTS_NODE) && bts);

	llist_for_each_entry(neighbor, &bts->neighbors, entry) {
		/* Check against duplicates */
		if (neighbor_same(neighbor, n, false)) {
			/* Found a match on Cell ID or BTS number, without ARFCN+BSIC. If they are fully identical, ignore the
			 * duplicate. If the ARFCN+BSIC part differs, it's an error. */
			vty_out(vty, "%% BTS %u already had neighbor %s%s", bts->nr, neighbor_to_str_c(OTC_SELECT, neighbor),
				VTY_NEWLINE);
			if (!neighbor_same(neighbor, n, true)) {
				vty_out(vty, "%% ERROR: duplicate Cell ID in neighbor config, with differing ARFCN+BSIC: %s%s",
					neighbor_to_str_c(OTC_SELECT, n), VTY_NEWLINE);
				return CMD_WARNING;
			}
			/* Exact same neighbor again, just ignore. */
			return CMD_SUCCESS;
		}

		/* Allow only one cell ID per remote-BSS neighbor, see OS#3656 */
		if (n->type == NEIGHBOR_TYPE_CELL_ID
		    && n->cell_id.ab_present && neighbor->cell_id.ab_present
		    && cell_ab_match(&n->cell_id.ab, &neighbor->cell_id.ab, true)) {
			vty_out(vty, "%% Error: only one Cell Identifier entry is allowed per remote neighbor."
				" Already have: BTS %u -> %s%s", bts->nr,
				neighbor_to_str_c(OTC_SELECT, neighbor), VTY_NEWLINE);
			return CMD_WARNING;
		}
	}

	neighbor = talloc_zero(bts, struct neighbor);
	*neighbor = *n;
	llist_add_tail(&neighbor->entry, &bts->neighbors);
	return CMD_SUCCESS;
}

static int del_neighbor(struct vty *vty, struct neighbor *n)
{
	struct gsm_bts *bts = vty->index;
	struct neighbor *neighbor;

	OSMO_ASSERT((vty->node == BTS_NODE) && bts);

	llist_for_each_entry(neighbor, &bts->neighbors, entry) {
		if (neighbor->type != n->type)
			continue;

		switch (n->type) {
		case NEIGHBOR_TYPE_BTS_NR:
			if (neighbor->bts_nr == n->bts_nr)
				break;
			continue;

		case NEIGHBOR_TYPE_CELL_ID:
			if (gsm0808_cell_ids_match(&neighbor->cell_id.id, &n->cell_id.id, true))
				break;
			continue;
		default:
			continue;
		}

		llist_del(&neighbor->entry);
		talloc_free(neighbor);
		return CMD_SUCCESS;
	}

	vty_out(vty, "%% Error: no such neighbor on BTS %d: %s%s",
		bts->nr, neighbor_to_str_c(OTC_SELECT, n), VTY_NEWLINE);
	return CMD_WARNING;
}

static int del_neighbor_by_cell_ab(struct vty *vty, const struct cell_ab *cell_ab)
{
	struct gsm_bts *bts = vty->index;
	struct neighbor *neighbor, *safe;
	struct gsm_bts *neighbor_bts;
	struct cell_ab neighbor_ab;
	int count = 0;

	OSMO_ASSERT((vty->node == BTS_NODE) && bts);

	llist_for_each_entry_safe(neighbor, safe, &bts->neighbors, entry) {
		switch (neighbor->type) {
		case NEIGHBOR_TYPE_BTS_NR:
			if (resolve_local_neighbor(&neighbor_bts, bts, neighbor))
				continue;
			bts_cell_ab(&neighbor_ab, neighbor_bts);
			if (!cell_ab_match(&neighbor_ab, cell_ab, false))
				continue;
			break;

		case NEIGHBOR_TYPE_CELL_ID:
			if (!neighbor->cell_id.ab_present)
				continue;
			if (!cell_ab_match(&neighbor->cell_id.ab, cell_ab, false))
				continue;
			break;
		default:
			continue;
		}

		llist_del(&neighbor->entry);
		talloc_free(neighbor);
		count++;
	}
	if (count)
		return CMD_SUCCESS;

	vty_out(vty, "%% Cannot remove: no such neighbor on BTS %u: %s%s",
		bts->nr, cell_ab_to_str_c(OTC_SELECT, cell_ab), VTY_NEWLINE);
	return CMD_WARNING;
}

DEFUN(cfg_neighbor_add_bts_nr, cfg_neighbor_add_bts_nr_cmd,
	NEIGHBOR_ADD_CMD LOCAL_BTS_PARAMS,
	NEIGHBOR_ADD_DOC LOCAL_BTS_DOC)
{
	struct neighbor n = {
		.type = NEIGHBOR_TYPE_BTS_NR,
		.bts_nr = atoi(argv[0]),
	};
	return add_neighbor(vty, &n);
}

DEFUN(cfg_neighbor_add_lac, cfg_neighbor_add_lac_cmd,
	NEIGHBOR_ADD_CMD LAC_PARAMS,
	NEIGHBOR_ADD_DOC LAC_DOC)
{
	struct neighbor n = {
		.type = NEIGHBOR_TYPE_CELL_ID,
	};
	if (neighbor_ident_vty_parse_lac(vty, &n.cell_id.id, argv))
		return CMD_WARNING;
	return add_neighbor(vty, &n);
}

DEFUN(cfg_neighbor_add_lac_ci, cfg_neighbor_add_lac_ci_cmd,
	NEIGHBOR_ADD_CMD LAC_CI_PARAMS,
	NEIGHBOR_ADD_DOC LAC_CI_DOC)
{
	struct neighbor n = {
		.type = NEIGHBOR_TYPE_CELL_ID,
	};
	if (neighbor_ident_vty_parse_lac_ci(vty, &n.cell_id.id, argv))
		return CMD_WARNING;
	return add_neighbor(vty, &n);
}

DEFUN(cfg_neighbor_add_cgi, cfg_neighbor_add_cgi_cmd,
	NEIGHBOR_ADD_CMD CGI_PARAMS,
	NEIGHBOR_ADD_DOC CGI_DOC)
{
	struct neighbor n = {
		.type = NEIGHBOR_TYPE_CELL_ID,
	};
	if (neighbor_ident_vty_parse_cgi(vty, &n.cell_id.id, argv))
		return CMD_WARNING;
	return add_neighbor(vty, &n);
}

DEFUN(cfg_neighbor_add_cgi_ps, cfg_neighbor_add_cgi_ps_cmd,
	NEIGHBOR_ADD_CMD CGI_PS_PARAMS,
	NEIGHBOR_ADD_DOC CGI_PS_DOC)
{
	struct neighbor n = {
		.type = NEIGHBOR_TYPE_CELL_ID,
	};
	if (neighbor_ident_vty_parse_cgi_ps(vty, &n.cell_id.id, argv))
		return CMD_WARNING;
	return add_neighbor(vty, &n);
}

static int neighbor_del_all(struct vty *vty)
{
	struct gsm_bts *bts = vty->index;
	struct neighbor *n;
	OSMO_ASSERT((vty->node == BTS_NODE) && bts);

	if (llist_empty(&bts->neighbors)) {
		vty_out(vty, "%% No neighbors configured%s", VTY_NEWLINE);
		return CMD_SUCCESS;
	}

	/* Remove all local neighbors and print to VTY for the user to know what changed */
	while ((n = llist_first_entry_or_null(&bts->neighbors, struct neighbor, entry))) {
		vty_out(vty, "%% Removed neighbor: BTS %u to %s%s",
			bts->nr, neighbor_to_str_c(OTC_SELECT, n), VTY_NEWLINE);
		llist_del(&n->entry);
		talloc_free(n);
	}
	return CMD_SUCCESS;
}

DEFUN(cfg_neighbor_add_lac_arfcn_bsic, cfg_neighbor_add_lac_arfcn_bsic_cmd,
	NEIGHBOR_ADD_CMD LAC_PARAMS " " CELL_AB_VTY_PARAMS,
	NEIGHBOR_ADD_DOC LAC_DOC CELL_AB_VTY_DOC)
{
	struct neighbor n = {
		.type = NEIGHBOR_TYPE_CELL_ID,
		.cell_id.ab_present = true,
	};
	if (neighbor_ident_vty_parse_lac(vty, &n.cell_id.id, argv))
		return CMD_WARNING;
	neighbor_ident_vty_parse_arfcn_bsic(&n.cell_id.ab, argv + LAC_ARGC);
	return add_neighbor(vty, &n);
}

DEFUN(cfg_neighbor_add_lac_ci_arfcn_bsic, cfg_neighbor_add_lac_ci_arfcn_bsic_cmd,
	NEIGHBOR_ADD_CMD LAC_CI_PARAMS " " CELL_AB_VTY_PARAMS,
	NEIGHBOR_ADD_DOC LAC_CI_DOC CELL_AB_VTY_DOC)
{
	struct neighbor n = {
		.type = NEIGHBOR_TYPE_CELL_ID,
		.cell_id.ab_present = true,
	};
	if (neighbor_ident_vty_parse_lac_ci(vty, &n.cell_id.id, argv))
		return CMD_WARNING;
	neighbor_ident_vty_parse_arfcn_bsic(&n.cell_id.ab, argv + LAC_CI_ARGC);
	return add_neighbor(vty, &n);
}

DEFUN(cfg_neighbor_add_cgi_arfcn_bsic, cfg_neighbor_add_cgi_arfcn_bsic_cmd,
	NEIGHBOR_ADD_CMD CGI_PARAMS " " CELL_AB_VTY_PARAMS,
	NEIGHBOR_ADD_DOC CGI_DOC CELL_AB_VTY_DOC)
{
	struct neighbor n = {
		.type = NEIGHBOR_TYPE_CELL_ID,
		.cell_id.ab_present = true,
	};
	if (neighbor_ident_vty_parse_cgi(vty, &n.cell_id.id, argv))
		return CMD_WARNING;
	neighbor_ident_vty_parse_arfcn_bsic(&n.cell_id.ab, argv + CGI_ARGC);
	return add_neighbor(vty, &n);
}

DEFUN(cfg_neighbor_add_cgi_ps_arfcn_bsic, cfg_neighbor_add_cgi_ps_arfcn_bsic_cmd,
	NEIGHBOR_ADD_CMD CGI_PS_PARAMS " " CELL_AB_VTY_PARAMS,
	NEIGHBOR_ADD_DOC CGI_PS_DOC CELL_AB_VTY_DOC)
{
	struct neighbor n = {
		.type = NEIGHBOR_TYPE_CELL_ID,
		.cell_id.ab_present = true,
	};
	if (neighbor_ident_vty_parse_cgi_ps(vty, &n.cell_id.id, argv))
		return CMD_WARNING;
	neighbor_ident_vty_parse_arfcn_bsic(&n.cell_id.ab, argv + CGI_PS_ARGC);
	return add_neighbor(vty, &n);
}

DEFUN(cfg_neighbor_del_bts_nr, cfg_neighbor_del_bts_nr_cmd,
	NEIGHBOR_DEL_CMD LOCAL_BTS_PARAMS,
	NEIGHBOR_DEL_DOC LOCAL_BTS_DOC)
{
	struct neighbor n = {
		.type = NEIGHBOR_TYPE_BTS_NR,
		.bts_nr = atoi(argv[0]),
	};
	return del_neighbor(vty, &n);
}

DEFUN(cfg_neighbor_del_lac, cfg_neighbor_del_lac_cmd,
	NEIGHBOR_DEL_CMD LAC_PARAMS,
	NEIGHBOR_DEL_DOC LAC_DOC)
{
	struct neighbor n = {
		.type = NEIGHBOR_TYPE_CELL_ID,
	};
	if (neighbor_ident_vty_parse_lac(vty, &n.cell_id.id, argv))
		return CMD_WARNING;
	return del_neighbor(vty, &n);
}

DEFUN(cfg_neighbor_del_lac_ci, cfg_neighbor_del_lac_ci_cmd,
	NEIGHBOR_DEL_CMD LAC_CI_PARAMS,
	NEIGHBOR_DEL_DOC LAC_CI_DOC)
{
	struct neighbor n = {
		.type = NEIGHBOR_TYPE_CELL_ID,
	};
	if (neighbor_ident_vty_parse_lac_ci(vty, &n.cell_id.id, argv))
		return CMD_WARNING;
	return del_neighbor(vty, &n);
}

DEFUN(cfg_neighbor_del_cgi, cfg_neighbor_del_cgi_cmd,
	NEIGHBOR_DEL_CMD CGI_PARAMS,
	NEIGHBOR_DEL_DOC CGI_DOC)
{
	struct neighbor n = {
		.type = NEIGHBOR_TYPE_CELL_ID,
	};
	if (neighbor_ident_vty_parse_cgi(vty, &n.cell_id.id, argv))
		return CMD_WARNING;
	return del_neighbor(vty, &n);
}

DEFUN(cfg_neighbor_del_cgi_ps, cfg_neighbor_del_cgi_ps_cmd,
	NEIGHBOR_DEL_CMD CGI_PS_PARAMS,
	NEIGHBOR_DEL_DOC CGI_PS_DOC)
{
	struct neighbor n = {
		.type = NEIGHBOR_TYPE_CELL_ID,
	};
	if (neighbor_ident_vty_parse_cgi_ps(vty, &n.cell_id.id, argv))
		return CMD_WARNING;
	return del_neighbor(vty, &n);
}

DEFUN(cfg_neighbor_del_arfcn_bsic, cfg_neighbor_del_arfcn_bsic_cmd,
	NEIGHBOR_DEL_CMD CELL_AB_VTY_PARAMS,
	NEIGHBOR_DEL_DOC CELL_AB_VTY_DOC)
{
	struct cell_ab ab;
	neighbor_ident_vty_parse_arfcn_bsic(&ab, argv);
	return del_neighbor_by_cell_ab(vty, &ab);
}

DEFUN(cfg_neighbor_del_all, cfg_neighbor_del_all_cmd,
	"no neighbors",
	NO_STR
	"Remove all local and remote-BSS neighbor config for this cell."
	" Note that this falls back to the legacy behavior of regarding all local cells as neighbors.\n")
{
	return neighbor_del_all(vty);
}

DEFUN(cfg_neighbor_bind, cfg_neighbor_bind_cmd,
	"neighbor-resolution bind " VTY_IPV46_CMD " [<0-65535>]",
	NEIGHBOR_DOC "Bind Neighbor Resolution Service (CTRL interface) to given ip and port\n"
	IP_STR IPV6_STR "Port to bind the service to [defaults to 4248 if not provided]\n")
{
	osmo_talloc_replace_string(bsc_gsmnet, &bsc_gsmnet->neigh_ctrl.addr, argv[0]);
	if (argc > 1)
		bsc_gsmnet->neigh_ctrl.port = atoi(argv[1]);
	else
		bsc_gsmnet->neigh_ctrl.port = OSMO_CTRL_PORT_BSC_NEIGH;
	return CMD_SUCCESS;
}

void neighbor_ident_vty_write_network(struct vty *vty, const char *indent)
{
	if (bsc_gsmnet->neigh_ctrl.addr)
		vty_out(vty, "%sneighbor-resolution bind %s %" PRIu16 "%s", indent, bsc_gsmnet->neigh_ctrl.addr,
			bsc_gsmnet->neigh_ctrl.port, VTY_NEWLINE);
}

static int vty_write_cell_id_u(struct vty *vty, enum CELL_IDENT id_discr, const union gsm0808_cell_id_u *cell_id_u)
{
	const struct osmo_cell_global_id *cgi;
	const struct osmo_cell_global_id_ps *cgi_ps;

	switch (id_discr) {
	case CELL_IDENT_LAC:
		vty_out(vty, "lac %u", cell_id_u->lac);
		break;
	case CELL_IDENT_LAC_AND_CI:
		vty_out(vty, "lac-ci %u %u", cell_id_u->lac_and_ci.lac, cell_id_u->lac_and_ci.ci);
		break;
	case CELL_IDENT_WHOLE_GLOBAL:
		cgi = &cell_id_u->global;
		vty_out(vty, "cgi %s %s %u %u",
			osmo_mcc_name(cgi->lai.plmn.mcc),
			osmo_mnc_name(cgi->lai.plmn.mnc, cgi->lai.plmn.mnc_3_digits),
			cgi->lai.lac, cgi->cell_identity);
		break;
	case CELL_IDENT_WHOLE_GLOBAL_PS:
		cgi_ps = &cell_id_u->global_ps;
		vty_out(vty, "cgi-ps %s %s %u %u %u",
			osmo_mcc_name(cgi_ps->rai.lac.plmn.mcc),
			osmo_mnc_name(cgi_ps->rai.lac.plmn.mnc, cgi_ps->rai.lac.plmn.mnc_3_digits),
			cgi_ps->rai.lac.lac, cgi_ps->rai.rac,
			cgi_ps->cell_identity);
		break;
	default:
		return -1;
	}
	return 0;
}

void neighbor_ident_vty_write_bts(struct vty *vty, const char *indent, struct gsm_bts *bts)
{
	struct neighbor *n;

	llist_for_each_entry(n, &bts->neighbors, entry) {
		switch (n->type) {
		case NEIGHBOR_TYPE_BTS_NR:
			vty_out(vty, "%sneighbor bts %u%s", indent, n->bts_nr, VTY_NEWLINE);
			break;

		case NEIGHBOR_TYPE_CELL_ID:
			vty_out(vty, "%sneighbor ", indent);
			if (vty_write_cell_id_u(vty, n->cell_id.id.id_discr, &n->cell_id.id.id)) {
				vty_out(vty, "[Unsupported Cell Identity]%s", VTY_NEWLINE);
				continue;
			}

			if (n->cell_id.ab_present) {
				vty_out(vty, " arfcn %u ", n->cell_id.ab.arfcn);
				if (n->cell_id.ab.bsic == BSIC_ANY)
					vty_out(vty, "bsic any");
				else
					vty_out(vty, "bsic %u", n->cell_id.ab.bsic & 0x3f);
			}
			vty_out(vty, "%s", VTY_NEWLINE);
			break;

		default:
			/* Ignore anything invalid */
			break;
		}
	}
}

DEFUN(show_bts_neighbor, show_bts_neighbor_cmd,
      "show bts <0-255> neighbor " CELL_AB_VTY_PARAMS,
      SHOW_STR "Display information about a BTS\n" "BTS number\n"
      "Query which cell would be the target for this neighbor ARFCN+BSIC\n"
      CELL_AB_VTY_DOC)
{
	struct cell_ab ab;
	struct gsm_bts *local_neighbor = NULL;
	struct gsm0808_cell_id_list2 remote_neighbors = { 0 };
	struct gsm_bts *bts = gsm_bts_num(bsc_gsmnet, atoi(argv[0]));

	if (!bts) {
		vty_out(vty, "%% Error: cannot find BTS '%s'%s", argv[0],
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	neighbor_ident_vty_parse_arfcn_bsic(&ab, &argv[1]);

	switch (resolve_neighbors(&local_neighbor, &remote_neighbors, bts, &ab, true)) {
	case 0:
		break;
	case -ENOENT:
		vty_out(vty, "%% No entry for BTS %u -> %s%s", bts->nr, cell_ab_to_str_c(OTC_SELECT, &ab), VTY_NEWLINE);
		return CMD_WARNING;
	default:
		vty_out(vty, "%% Error while resolving neighbors BTS %u -> %s%s", bts->nr,
			cell_ab_to_str_c(OTC_SELECT, &ab), VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* From successful rc == 0, there is exactly either a local_neighbor or a nonempty remote_neighbors list. */

	vty_out(vty, "%% BTS %u -> %s resolves to", bts->nr, cell_ab_to_str_c(OTC_SELECT, &ab));
	if (local_neighbor) {
		vty_out(vty, " local BTS %u lac-ci %u %u%s",
			local_neighbor->nr,
			local_neighbor->location_area_code,
			local_neighbor->cell_identity, VTY_NEWLINE);
	}

	if (remote_neighbors.id_list_len) {
		vty_out(vty, " remote-BSS neighbors: %s%s",
			gsm0808_cell_id_list_name_c(OTC_SELECT, &remote_neighbors),
			VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}

void neighbor_ident_vty_init()
{
	install_element(GSMNET_NODE, &cfg_neighbor_bind_cmd);

	install_element(BTS_NODE, &cfg_neighbor_add_bts_nr_cmd);
	install_element(BTS_NODE, &cfg_neighbor_add_lac_cmd);
	install_element(BTS_NODE, &cfg_neighbor_add_lac_ci_cmd);
	install_element(BTS_NODE, &cfg_neighbor_add_cgi_cmd);
	install_element(BTS_NODE, &cfg_neighbor_add_cgi_ps_cmd);
	install_element(BTS_NODE, &cfg_neighbor_add_lac_arfcn_bsic_cmd);
	install_element(BTS_NODE, &cfg_neighbor_add_lac_ci_arfcn_bsic_cmd);
	install_element(BTS_NODE, &cfg_neighbor_add_cgi_arfcn_bsic_cmd);
	install_element(BTS_NODE, &cfg_neighbor_add_cgi_ps_arfcn_bsic_cmd);
	install_element(BTS_NODE, &cfg_neighbor_del_bts_nr_cmd);
	install_element(BTS_NODE, &cfg_neighbor_del_lac_cmd);
	install_element(BTS_NODE, &cfg_neighbor_del_lac_ci_cmd);
	install_element(BTS_NODE, &cfg_neighbor_del_cgi_cmd);
	install_element(BTS_NODE, &cfg_neighbor_del_cgi_ps_cmd);
	install_element(BTS_NODE, &cfg_neighbor_del_arfcn_bsic_cmd);
	install_element(BTS_NODE, &cfg_neighbor_del_all_cmd);
	install_element_ve(&show_bts_neighbor_cmd);
}
