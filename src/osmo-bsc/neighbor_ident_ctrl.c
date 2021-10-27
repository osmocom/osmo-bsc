/* CTRL interface implementation to manage identity of neighboring BSS cells for inter-BSC handover. */
/* (C) 2021 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 *
 * All Rights Reserved
 *
 * Author: Philipp Maier <pmaier@sysmocom.de>
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
#include <time.h>

#include <osmocom/ctrl/control_cmd.h>
#include <osmocom/bsc/neighbor_ident.h>
#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/bsc_msc_data.h>
#include <osmocom/bsc/bts.h>
#include <osmocom/bsc/vty.h>

/* Continue to parse ARFCN and BSIC, which are optional parameters at the end of the parameter string in most of the
 * commands. The result is ignored when parameter n is set to NULL. */
static int continue_parse_arfcn_and_bsic(char **saveptr, struct neighbor *n)
{
	int arfcn;
	int bsic;
	char *tok;

	tok = strtok_r(NULL, "-", saveptr);

	/* No ARFCN and BSIC persent - stop */
	if (!tok)
		return 0;

	if (osmo_str_to_int(&arfcn, tok, 10, 0, 1023) < 0)
		return -EINVAL;

	tok = strtok_r(NULL, "-", saveptr);

	/* When an ARFCN is given, then the BSIC parameter is
	 * mandatory */
	if (!tok)
		return -EINVAL;

	if (strcmp(tok, "any") == 0) {
		bsic = BSIC_ANY;
	} else {
		if (osmo_str_to_int(&bsic, tok, 10, 0, 63) < 0)
			return 1;
	}

	/* Make sure there are no excess parameters */
	if (strtok_r(NULL, "-", saveptr))
		return -EINVAL;

	if (n) {
		n->cell_id.ab_present = true;
		n->cell_id.ab.arfcn = arfcn;
		n->cell_id.ab.bsic = bsic;
	}

	return 0;
}

/* This and the following: Add/Remove a BTS as neighbor */
static int verify_neighbor_bts(struct ctrl_cmd *cmd, const char *value, void *_data)
{
	struct gsm_bts *bts = cmd->node;
	const int neigh_bts_nr = atoi(value);
	struct gsm_bts *neigh_bts = gsm_bts_num(bts->network, neigh_bts_nr);

	if (!neigh_bts) {
		cmd->reply = "Invalid Neighbor BTS number - no such BTS";
		return 1;
	}

	return 0;
}

static int verify_neighbor_bts_add(struct ctrl_cmd *cmd, const char *value, void *_data)
{
	return verify_neighbor_bts(cmd, value, _data);
}

static int set_neighbor_bts_add(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_bts *bts = cmd->node;
	const int bts_nr = atoi(cmd->value);
	int rc;

	struct neighbor n = {
		.type = NEIGHBOR_TYPE_BTS_NR,
		.bts_nr = bts_nr,
	};
	rc = neighbor_ident_add_neighbor(NULL, bts, &n);
	if (rc != CMD_SUCCESS) {
		cmd->reply = "Failed to add neighbor";
		return CTRL_CMD_ERROR;
	}

	cmd->reply = "OK";
	return CTRL_CMD_REPLY;
}

/* Parameter format: "<num>"
 * num: BTS number (0-255) */
CTRL_CMD_DEFINE_WO(neighbor_bts_add, "neighbor-bts add");

static int verify_neighbor_bts_del(struct ctrl_cmd *cmd, const char *value, void *_data)
{
	return verify_neighbor_bts(cmd, value, _data);
}

static int set_neighbor_bts_del(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_bts *bts = cmd->node;
	const int bts_nr = atoi(cmd->value);
	int rc;

	struct neighbor n = {
		.type = NEIGHBOR_TYPE_BTS_NR,
		.bts_nr = bts_nr,
	};
	rc = neighbor_ident_del_neighbor(NULL, bts, &n);
	if (rc != CMD_SUCCESS) {
		cmd->reply = "Failed to delete neighbor";
		return CTRL_CMD_ERROR;
	}

	cmd->reply = "OK";
	return CTRL_CMD_REPLY;
}

/* Parameter format: (see "add" command above) */
CTRL_CMD_DEFINE_WO(neighbor_bts_del, "neighbor-bts del");

/* This and the following: Add/Remove a LAC as neighbor */
static int parse_lac(void *ctx, struct neighbor *n, const char *value)
{
	char *tmp = NULL, *tok, *saveptr;
	int rc = 0;
	int lac;

	if (n)
		memset(n, 0, sizeof(*n));

	tmp = talloc_strdup(ctx, value);
	if (!tmp)
		return -EINVAL;

	/* Parse LAC */
	tok = strtok_r(tmp, "-", &saveptr);
	if (tok) {
		if (osmo_str_to_int(&lac, tok, 10, 0, 65535) < 0) {
			rc = -EINVAL;
			goto exit;
		}
	} else {
		rc = -EINVAL;
		goto exit;
	}

	/* Optional parameters: ARFCN and BSIC */
	if (continue_parse_arfcn_and_bsic(&saveptr, n)) {
		rc = -EINVAL;
		goto exit;
	}

	if (n) {
		n->type = NEIGHBOR_TYPE_CELL_ID;
		n->cell_id.id.id_discr = CELL_IDENT_LAC;
		n->cell_id.id.id.lac = lac;
	}

exit:
	talloc_free(tmp);
	return rc;
}

static int verify_neighbor_lac_add(struct ctrl_cmd *cmd, const char *value, void *_data)
{
	if (parse_lac(cmd, NULL, value))
		return 1;
	return 0;
}

static int set_neighbor_lac_add(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_bts *bts = cmd->node;
	int rc;

	struct neighbor n;

	parse_lac(cmd, &n, cmd->value);
	rc = neighbor_ident_add_neighbor(NULL, bts, &n);
	if (rc != CMD_SUCCESS) {
		cmd->reply = "Failed to add neighbor";
		return CTRL_CMD_ERROR;
	}

	cmd->reply = "OK";
	return CTRL_CMD_REPLY;
}

/* Parameter format: "<lac>[-<arfcn>-<bsic>]"
 * lac: Location area of neighbor cell (0-65535)
 * arfcn: ARFCN of neighbor cell (0-1023)
 * bsic: BSIC of neighbor cell */
CTRL_CMD_DEFINE_WO(neighbor_lac_add, "neighbor-lac add");

static int verify_neighbor_lac_del(struct ctrl_cmd *cmd, const char *value, void *_data)
{
	if (parse_lac(cmd, NULL, value))
		return 1;
	return 0;
}

static int set_neighbor_lac_del(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_bts *bts = cmd->node;
	int rc;

	struct neighbor n;
	parse_lac(cmd, &n, cmd->value);
	rc = neighbor_ident_del_neighbor(NULL, bts, &n);
	if (rc != CMD_SUCCESS) {
		cmd->reply = "Failed to delete neighbor";
		return CTRL_CMD_ERROR;
	}

	cmd->reply = "OK";
	return CTRL_CMD_REPLY;
}

/* Parameter format: (see "add" command above) */
CTRL_CMD_DEFINE_WO(neighbor_lac_del, "neighbor-lac del");

/* This and the following: Add/Remove a LAC-CI as neighbor */
static int parse_lac_ci(void *ctx, struct neighbor *n, const char *value)
{
	char *tmp = NULL, *tok, *saveptr;
	int rc = 0;
	int lac;
	int ci;

	if (n)
		memset(n, 0, sizeof(*n));

	tmp = talloc_strdup(ctx, value);
	if (!tmp)
		return -EINVAL;

	/* Parse LAC */
	tok = strtok_r(tmp, "-", &saveptr);
	if (tok) {
		if (osmo_str_to_int(&lac, tok, 10, 0, 65535) < 0) {
			rc = -EINVAL;
			goto exit;
		}
	} else {
		rc = -EINVAL;
		goto exit;
	}

	/* Parse CI */
	tok = strtok_r(NULL, "-", &saveptr);
	if (tok) {
		if (osmo_str_to_int(&ci, tok, 10, 0, 65535) < 0) {
			rc = -EINVAL;
			goto exit;
		}
	} else {
		rc = -EINVAL;
		goto exit;
	}

	/* Optional parameters: ARFCN and BSIC */
	if (continue_parse_arfcn_and_bsic(&saveptr, n)) {
		rc = -EINVAL;
		goto exit;
	}

	if (n) {
		n->type = NEIGHBOR_TYPE_CELL_ID;
		n->cell_id.id.id_discr = CELL_IDENT_LAC_AND_CI;
		n->cell_id.id.id.lac = lac;
		n->cell_id.id.id.ci = ci;
	}

exit:
	talloc_free(tmp);
	return rc;
}

static int verify_neighbor_lac_ci_add(struct ctrl_cmd *cmd, const char *value, void *_data)
{
	if (parse_lac_ci(cmd, NULL, value))
		return 1;
	return 0;
}

static int set_neighbor_lac_ci_add(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_bts *bts = cmd->node;
	int rc;

	struct neighbor n;

	parse_lac_ci(cmd, &n, cmd->value);
	rc = neighbor_ident_add_neighbor(NULL, bts, &n);
	if (rc != CMD_SUCCESS) {
		cmd->reply = "Failed to add neighbor";
		return CTRL_CMD_ERROR;
	}

	cmd->reply = "OK";
	return CTRL_CMD_REPLY;
}

/* Parameter format: "<lac>-<ci>[-<arfcn>-<bsic>]"
 * lac: Location area of neighbor cell (0-65535)
 * ci: Cell ID of neighbor cell (0-65535)
 * arfcn: ARFCN of neighbor cell (0-1023)
 * bsic: BSIC of neighbor cell */
CTRL_CMD_DEFINE_WO(neighbor_lac_ci_add, "neighbor-lac-ci add");

static int verify_neighbor_lac_ci_del(struct ctrl_cmd *cmd, const char *value, void *_data)
{
	if (parse_lac_ci(cmd, NULL, value))
		return 1;
	return 0;
}

static int set_neighbor_lac_ci_del(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_bts *bts = cmd->node;
	int rc;

	struct neighbor n;
	parse_lac_ci(cmd, &n, cmd->value);
	rc = neighbor_ident_del_neighbor(NULL, bts, &n);
	if (rc != CMD_SUCCESS) {
		cmd->reply = "Failed to delete neighbor";
		return CTRL_CMD_ERROR;
	}

	cmd->reply = "OK";
	return CTRL_CMD_REPLY;
}

/* Parameter format: (see "add" command above) */
CTRL_CMD_DEFINE_WO(neighbor_lac_ci_del, "neighbor-lac-ci del");

/* This and the following: Add/Remove a CGI as neighbor */
static int parse_cgi(void *ctx, struct neighbor *n, const char *value)
{
	char *tmp = NULL, *tok, *saveptr;
	int rc = 0;
	uint16_t mcc;
	uint16_t mnc;
	bool mnc_3_digits;
	int lac;
	int ci;

	if (n)
		memset(n, 0, sizeof(*n));

	tmp = talloc_strdup(ctx, value);
	if (!tmp)
		return -EINVAL;

	/* Parse MCC */
	tok = strtok_r(tmp, "-", &saveptr);
	if (tok) {
		if (osmo_mcc_from_str(tok, &mcc)) {
			rc = -EINVAL;
			goto exit;
		}
	} else {
		rc = -EINVAL;
		goto exit;
	}

	/* Parse MNC */
	tok = strtok_r(NULL, "-", &saveptr);
	if (tok) {
		if (osmo_mnc_from_str(tok, &mnc, &mnc_3_digits)) {
			rc = -EINVAL;
			goto exit;
		}
	} else {
		rc = -EINVAL;
		goto exit;
	}

	/* Parse LAC */
	tok = strtok_r(NULL, "-", &saveptr);
	if (tok) {
		if (osmo_str_to_int(&lac, tok, 10, 0, 65535) < 0) {
			rc = -EINVAL;
			goto exit;
		}
	} else {
		rc = -EINVAL;
		goto exit;
	}

	/* Parse CI */
	tok = strtok_r(NULL, "-", &saveptr);
	if (tok) {
		if (osmo_str_to_int(&ci, tok, 10, 0, 65535) < 0) {
			rc = -EINVAL;
			goto exit;
		}
	} else {
		rc = -EINVAL;
		goto exit;
	}

	/* Optional parameters: ARFCN and BSIC */
	if (continue_parse_arfcn_and_bsic(&saveptr, n)) {
		rc = -EINVAL;
		goto exit;
	}

	if (n) {
		n->type = NEIGHBOR_TYPE_CELL_ID;
		n->cell_id.id.id_discr = CELL_IDENT_WHOLE_GLOBAL;
		n->cell_id.id.id.global.lai.lac = lac;
		n->cell_id.id.id.global.lai.plmn.mcc = mcc;
		n->cell_id.id.id.global.lai.plmn.mnc = mnc;
		n->cell_id.id.id.global.lai.plmn.mnc_3_digits = mnc_3_digits;
		n->cell_id.id.id.global.cell_identity = ci;
	}

exit:
	talloc_free(tmp);
	return rc;
}

static int verify_neighbor_cgi_add(struct ctrl_cmd *cmd, const char *value, void *_data)
{
	if (parse_cgi(cmd, NULL, value))
		return 1;
	return 0;
}

static int set_neighbor_cgi_add(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_bts *bts = cmd->node;
	int rc;

	struct neighbor n;

	parse_cgi(cmd, &n, cmd->value);
	rc = neighbor_ident_add_neighbor(NULL, bts, &n);
	if (rc != CMD_SUCCESS) {
		cmd->reply = "Failed to add neighbor";
		return CTRL_CMD_ERROR;
	}

	cmd->reply = "OK";
	return CTRL_CMD_REPLY;
}

/* Parameter format: "<mcc>-<mnc>-<lac>-<ci>[-<arfcn>-<bsic>]"
 * mcc: Mobile country code of neighbor cell (0-999)
 * mnc: Mobile network code of neighbor cell (0-999)
 * lac: Location area of neighbor cell (0-65535)
 * ci: Cell ID of neighbor cell (0-65535)
 * arfcn: ARFCN of neighbor cell (0-1023)
 * bsic: BSIC of neighbor cell */
CTRL_CMD_DEFINE_WO(neighbor_cgi_add, "neighbor-cgi add");

static int verify_neighbor_cgi_del(struct ctrl_cmd *cmd, const char *value, void *_data)
{
	if (parse_cgi(cmd, NULL, value))
		return 1;
	return 0;
}

static int set_neighbor_cgi_del(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_bts *bts = cmd->node;
	int rc;

	struct neighbor n;
	parse_cgi(cmd, &n, cmd->value);
	rc = neighbor_ident_del_neighbor(NULL, bts, &n);
	if (rc != CMD_SUCCESS) {
		cmd->reply = "Failed to delete neighbor";
		return CTRL_CMD_ERROR;
	}

	cmd->reply = "OK";
	return CTRL_CMD_REPLY;
}

/* Parameter format: (see "add" command above) */
CTRL_CMD_DEFINE_WO(neighbor_cgi_del, "neighbor-cgi del");

/* This and the following: Add/Remove a CGI-PS as neighbor */
static int parse_cgi_ps(void *ctx, struct neighbor *n, const char *value)
{
	char *tmp = NULL, *tok, *saveptr;
	int rc = 0;
	uint16_t mcc;
	uint16_t mnc;
	bool mnc_3_digits;
	int lac;
	int rac;
	int ci;

	if (n)
		memset(n, 0, sizeof(*n));

	tmp = talloc_strdup(ctx, value);
	if (!tmp)
		return -EINVAL;

	/* Parse MCC */
	tok = strtok_r(tmp, "-", &saveptr);
	if (tok) {
		if (osmo_mcc_from_str(tok, &mcc)) {
			rc = -EINVAL;
			goto exit;
		}
	} else {
		rc = -EINVAL;
		goto exit;
	}

	/* Parse MNC */
	tok = strtok_r(NULL, "-", &saveptr);
	if (tok) {
		if (osmo_mnc_from_str(tok, &mnc, &mnc_3_digits)) {
			rc = -EINVAL;
			goto exit;
		}
	} else {
		rc = -EINVAL;
		goto exit;
	}

	/* Parse LAC */
	tok = strtok_r(NULL, "-", &saveptr);
	if (tok) {
		if (osmo_str_to_int(&lac, tok, 10, 0, 65535) < 0) {
			rc = -EINVAL;
			goto exit;
		}
	} else {
		rc = -EINVAL;
		goto exit;
	}

	/* Parse RAC */
	tok = strtok_r(NULL, "-", &saveptr);
	if (tok) {
		if (osmo_str_to_int(&rac, tok, 10, 0, 255) < 0) {
			rc = -EINVAL;
			goto exit;
		}
	} else {
		rc = -EINVAL;
		goto exit;
	}

	/* Parse CI */
	tok = strtok_r(NULL, "-", &saveptr);
	if (tok) {
		if (osmo_str_to_int(&ci, tok, 10, 0, 65535) < 0) {
			rc = -EINVAL;
			goto exit;
		}
	} else {
		rc = -EINVAL;
		goto exit;
	}

	/* Optional parameters: ARFCN and BSIC */
	if (continue_parse_arfcn_and_bsic(&saveptr, n)) {
		rc = -EINVAL;
		goto exit;
	}

	if (n) {
		n->type = NEIGHBOR_TYPE_CELL_ID;
		n->cell_id.id.id_discr = CELL_IDENT_WHOLE_GLOBAL_PS;
		n->cell_id.id.id.global_ps.rai.lac.lac = lac;
		n->cell_id.id.id.global_ps.rai.rac = lac;
		n->cell_id.id.id.global_ps.rai.lac.plmn.mcc = mcc;
		n->cell_id.id.id.global_ps.rai.lac.plmn.mnc = mnc;
		n->cell_id.id.id.global_ps.rai.lac.plmn.mnc_3_digits = mnc_3_digits;
		n->cell_id.id.id.global_ps.cell_identity = ci;
	}

exit:
	talloc_free(tmp);
	return rc;
}

static int verify_neighbor_cgi_ps_add(struct ctrl_cmd *cmd, const char *value, void *_data)
{
	if (parse_cgi_ps(cmd, NULL, value))
		return 1;
	return 0;
}

static int set_neighbor_cgi_ps_add(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_bts *bts = cmd->node;
	int rc;

	struct neighbor n;

	parse_cgi_ps(cmd, &n, cmd->value);
	rc = neighbor_ident_add_neighbor(NULL, bts, &n);
	if (rc != CMD_SUCCESS) {
		cmd->reply = "Failed to add neighbor";
		return CTRL_CMD_ERROR;
	}

	cmd->reply = "OK";
	return CTRL_CMD_REPLY;
}

/* Parameter format: "<mcc>-<mnc>-<lac>-<rac>-<ci>[-<arfcn>-<bsic>]"
 * mcc: Mobile country code of neighbor cell (0-999)
 * mnc: Mobile network code of neighbor cell (0-999)
 * lac: Location area of neighbor cell (0-65535)
 * rac: Routing area of neighbor cell (0-65535)
 * ci: Cell ID of neighbor cell (0-65535)
 * arfcn: ARFCN of neighbor cell (0-1023)
 * bsic: BSIC of neighbor cell */
CTRL_CMD_DEFINE_WO(neighbor_cgi_ps_add, "neighbor-cgi-ps add");

static int verify_neighbor_cgi_ps_del(struct ctrl_cmd *cmd, const char *value, void *_data)
{
	if (parse_cgi_ps(cmd, NULL, value))
		return 1;
	return 0;
}

static int set_neighbor_cgi_ps_del(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_bts *bts = cmd->node;
	int rc;

	struct neighbor n;
	parse_cgi_ps(cmd, &n, cmd->value);
	rc = neighbor_ident_del_neighbor(NULL, bts, &n);
	if (rc != CMD_SUCCESS) {
		cmd->reply = "Failed to delete neighbor";
		return CTRL_CMD_ERROR;
	}

	cmd->reply = "OK";
	return CTRL_CMD_REPLY;
}

/* Parameter format: (see "add" command above) */
CTRL_CMD_DEFINE_WO(neighbor_cgi_ps_del, "neighbor-cgi-ps del");

/* This and the following: clear all neighbor cell information */
static int set_neighbor_clear(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_bts *bts = cmd->node;
	struct neighbor *neighbor;
	struct neighbor *neighbor_tmp;

	llist_for_each_entry_safe(neighbor, neighbor_tmp, &bts->neighbors, entry) {
		llist_del(&neighbor->entry);
		talloc_free(neighbor);
	}

	cmd->reply = "OK";
	return CTRL_CMD_REPLY;
}

CTRL_CMD_DEFINE_WO_NOVRF(neighbor_clear, "neighbor-clear");

/* Register control interface commands implemented above */
int neighbor_ident_ctrl_init(void)
{
	int rc = 0;

	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_neighbor_bts_add);
	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_neighbor_bts_del);
	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_neighbor_lac_add);
	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_neighbor_lac_del);
	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_neighbor_lac_ci_add);
	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_neighbor_lac_ci_del);
	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_neighbor_cgi_add);
	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_neighbor_cgi_del);
	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_neighbor_cgi_ps_add);
	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_neighbor_cgi_ps_del);
	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_neighbor_clear);

	return rc;
}
