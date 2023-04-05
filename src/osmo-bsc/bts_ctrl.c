/*
 * (C) 2013-2015 by Holger Hans Peter Freyther
 * (C) 2013-2022 by sysmocom s.f.m.c. GmbH
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

#include <errno.h>
#include <time.h>

#include <osmocom/ctrl/control_cmd.h>

#include <osmocom/vty/command.h>
#include <osmocom/vty/misc.h>

#include <osmocom/bsc/ctrl.h>
#include <osmocom/bsc/osmo_bsc_rf.h>
#include <osmocom/bsc/bts.h>
#include <osmocom/bsc/ipaccess.h>
#include <osmocom/bsc/chan_alloc.h>
#include <osmocom/bsc/abis_nm.h>
#include <osmocom/bsc/neighbor_ident.h>
#include <osmocom/bsc/system_information.h>

static int location_equal(struct bts_location *a, struct bts_location *b)
{
	return ((a->tstamp == b->tstamp) && (a->valid == b->valid) && (a->lat == b->lat) &&
		(a->lon == b->lon) && (a->height == b->height));
}

static void cleanup_locations(struct llist_head *locations)
{
	struct bts_location *myloc, *tmp;
	int invalpos = 0, i = 0;

	LOGP(DCTRL, LOGL_DEBUG, "Checking position list.\n");
	llist_for_each_entry_safe(myloc, tmp, locations, list) {
		i++;
		if (i > 3) {
			LOGP(DCTRL, LOGL_DEBUG, "Deleting old position.\n");
			llist_del(&myloc->list);
			talloc_free(myloc);
		} else if (myloc->valid == BTS_LOC_FIX_INVALID) {
			/* Only capture the newest of subsequent invalid positions */
			invalpos++;
			if (invalpos > 1) {
				LOGP(DCTRL, LOGL_DEBUG, "Deleting subsequent invalid position.\n");
				invalpos--;
				i--;
				llist_del(&myloc->list);
				talloc_free(myloc);
			}
		} else {
			invalpos = 0;
		}
	}
	LOGP(DCTRL, LOGL_DEBUG, "Found %d positions.\n", i);
}

static int get_bts_loc(struct ctrl_cmd *cmd, void *data);

void ctrl_generate_bts_location_state_trap(struct gsm_bts *bts, struct bsc_msc_data *msc)
{
	struct ctrl_cmd *cmd;
	const char *oper, *admin, *policy;

	cmd = ctrl_cmd_create(msc, CTRL_TYPE_TRAP);
	if (!cmd) {
		LOGP(DCTRL, LOGL_ERROR, "Failed to create TRAP command.\n");
		return;
	}

	cmd->id = "0";
	cmd->variable = talloc_asprintf(cmd, "bts.%d.location-state", bts->nr);

	/* Prepare the location reply */
	cmd->node = bts;
	get_bts_loc(cmd, NULL);

	oper = osmo_bsc_rf_get_opstate_name(osmo_bsc_rf_get_opstate_by_bts(bts));
	admin = osmo_bsc_rf_get_adminstate_name(osmo_bsc_rf_get_adminstate_by_bts(bts));
	policy = osmo_bsc_rf_get_policy_name(osmo_bsc_rf_get_policy_by_bts(bts));

	cmd->reply = talloc_asprintf_append(cmd->reply,
				",%s,%s,%s,%s,%s",
				oper, admin, policy,
				osmo_mcc_name(bts->network->plmn.mcc),
				osmo_mnc_name(bts->network->plmn.mnc,
					      bts->network->plmn.mnc_3_digits));

	osmo_bsc_send_trap(cmd, msc);
	talloc_free(cmd);
}

void bsc_gen_location_state_trap(struct gsm_bts *bts)
{
	struct bsc_msc_data *msc;

	llist_for_each_entry(msc, &bts->network->mscs, entry)
		ctrl_generate_bts_location_state_trap(bts, msc);
}

CTRL_CMD_DEFINE(bts_loc, "location");
static int get_bts_loc(struct ctrl_cmd *cmd, void *data)
{
	struct bts_location *curloc;
	struct gsm_bts *bts = (struct gsm_bts *) cmd->node;
	if (!bts) {
		cmd->reply = "bts not found.";
		return CTRL_CMD_ERROR;
	}

	if (llist_empty(&bts->loc_list)) {
		cmd->reply = talloc_asprintf(cmd, "0,invalid,0,0,0");
		return CTRL_CMD_REPLY;
	}

	curloc = llist_entry(bts->loc_list.next, struct bts_location, list);

	cmd->reply = talloc_asprintf(cmd, "%lu,%s,%f,%f,%f", curloc->tstamp,
			get_value_string(bts_loc_fix_names, curloc->valid), curloc->lat, curloc->lon, curloc->height);
	if (!cmd->reply) {
		cmd->reply = "OOM";
		return CTRL_CMD_ERROR;
	}

	return CTRL_CMD_REPLY;
}

static int set_bts_loc(struct ctrl_cmd *cmd, void *data)
{
	char *saveptr, *lat, *lon, *height, *tstamp, *valid, *tmp;
	struct bts_location *curloc, *lastloc;
	int ret;
	struct gsm_bts *bts = (struct gsm_bts *) cmd->node;
	if (!bts) {
		cmd->reply = "bts not found.";
		return CTRL_CMD_ERROR;
	}

	tmp = talloc_strdup(cmd, cmd->value);
	if (!tmp)
		goto oom;

	tstamp = strtok_r(tmp, ",", &saveptr);
	valid = strtok_r(NULL, ",", &saveptr);
	lat = strtok_r(NULL, ",", &saveptr);
	lon = strtok_r(NULL, ",", &saveptr);
	height = strtok_r(NULL, "\0", &saveptr);

	/* Check if one of the strtok results was NULL. This will probably never occur since we will only see verified
	 * input in this code path */
	if ((tstamp == NULL) || (valid == NULL) || (lat == NULL) || (lon == NULL) || (height == NULL)) {
		talloc_free(tmp);
		cmd->reply = "parse error";
		return CTRL_CMD_ERROR;
	}

	curloc = talloc_zero(tall_bsc_ctx, struct bts_location);
	if (!curloc) {
		talloc_free(tmp);
		goto oom;
	}
	INIT_LLIST_HEAD(&curloc->list);

	curloc->tstamp = atol(tstamp);
	curloc->valid = get_string_value(bts_loc_fix_names, valid);
	curloc->lat = atof(lat);
	curloc->lon = atof(lon);
	curloc->height = atof(height);
	talloc_free(tmp);

	lastloc = llist_entry(bts->loc_list.next, struct bts_location, list);

	/* Add location to the end of the list */
	llist_add(&curloc->list, &bts->loc_list);

	ret = get_bts_loc(cmd, data);

	if (!location_equal(curloc, lastloc))
		bsc_gen_location_state_trap(bts);

	cleanup_locations(&bts->loc_list);

	return ret;

oom:
	cmd->reply = "OOM";
	return CTRL_CMD_ERROR;
}

static int verify_bts_loc(struct ctrl_cmd *cmd, const char *value, void *data)
{
	char *saveptr, *latstr, *lonstr, *heightstr, *tstampstr, *validstr, *tmp;
	time_t tstamp;
	int valid;
	double lat, lon, height __attribute__((unused));

	tmp = talloc_strdup(cmd, value);
	if (!tmp)
		return 1;

	tstampstr = strtok_r(tmp, ",", &saveptr);
	validstr = strtok_r(NULL, ",", &saveptr);
	latstr = strtok_r(NULL, ",", &saveptr);
	lonstr = strtok_r(NULL, ",", &saveptr);
	heightstr = strtok_r(NULL, "\0", &saveptr);

	if ((tstampstr == NULL) || (validstr == NULL) || (latstr == NULL) ||
			(lonstr == NULL) || (heightstr == NULL))
		goto err;

	tstamp = atol(tstampstr);
	valid = get_string_value(bts_loc_fix_names, validstr);
	lat = atof(latstr);
	lon = atof(lonstr);
	height = atof(heightstr);
	talloc_free(tmp);
	tmp = NULL;

	if (((tstamp == 0) && (valid != BTS_LOC_FIX_INVALID)) || (lat < -90) || (lat > 90) ||
			(lon < -180) || (lon > 180) || (valid < 0)) {
		goto err;
	}

	return 0;

err:
	talloc_free(tmp);
	cmd->reply = talloc_strdup(cmd, "The format is <unixtime>,(invalid|fix2d|fix3d),<lat>,<lon>,<height>");
	return 1;
}

/* BTS related commands below */
CTRL_CMD_DEFINE_RANGE(bts_lac, "location-area-code", struct gsm_bts, location_area_code, 0, 65535);
CTRL_CMD_DEFINE_RANGE(bts_ci, "cell-identity", struct gsm_bts, cell_identity, 0, 65535);

static int set_bts_apply_config(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_bts *bts = cmd->node;

	if (!is_ipaccess_bts(bts)) {
		cmd->reply = "BTS is not IP based";
		return CTRL_CMD_ERROR;
	}

	ipaccess_drop_oml(bts, "ctrl bts.apply-configuration");
	cmd->reply = "Tried to drop the BTS";
	return CTRL_CMD_REPLY;
}

CTRL_CMD_DEFINE_WO_NOVRF(bts_apply_config, "apply-configuration");

static int set_bts_si(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_bts *bts = cmd->node;
	int rc;

	rc = gsm_bts_set_system_infos(bts);
	if (rc != 0) {
		cmd->reply = "Failed to generate SI";
		return CTRL_CMD_ERROR;
	}

	cmd->reply = "Generated new System Information";
	return CTRL_CMD_REPLY;
}
CTRL_CMD_DEFINE_WO_NOVRF(bts_si, "send-new-system-informations");

static int set_bts_power_ctrl_defs(struct ctrl_cmd *cmd, void *data)
{
	const struct gsm_bts *bts = cmd->node;
	const struct gsm_bts_trx *trx;

	if (bts->ms_power_ctrl.mode != GSM_PWR_CTRL_MODE_DYN_BTS) {
		cmd->reply = "BTS is not using dyn-bts mode";
		return CTRL_CMD_ERROR;
	}

	if (bts->model->power_ctrl_send_def_params == NULL) {
		cmd->reply = "Not implemented for this BTS model";
		return CTRL_CMD_ERROR;
	}

	llist_for_each_entry(trx, &bts->trx_list, list) {
		if (bts->model->power_ctrl_send_def_params(trx) != 0) {
			cmd->reply = "power_ctrl_send_def_params() failed";
			return CTRL_CMD_ERROR;
		}
	}

	cmd->reply = "Default power control parameters have been sent";
	return CTRL_CMD_REPLY;
}
CTRL_CMD_DEFINE_WO_NOVRF(bts_power_ctrl_defs, "send-power-control-defaults");

static int get_bts_chan_load(struct ctrl_cmd *cmd, void *data)
{
	int i;
	struct pchan_load pl;
	struct gsm_bts *bts;
	const char *space = "";

	bts = cmd->node;
	memset(&pl, 0, sizeof(pl));
	bts_chan_load(&pl, bts);

	cmd->reply = talloc_strdup(cmd, "");

	for (i = 0; i < ARRAY_SIZE(pl.pchan); ++i) {
		const struct load_counter *lc = &pl.pchan[i];

		/* These can never have user load */
		if (i == GSM_PCHAN_NONE)
			continue;
		if (i == GSM_PCHAN_CCCH)
			continue;
		if (i == GSM_PCHAN_PDCH)
			continue;
		if (i == GSM_PCHAN_UNKNOWN)
			continue;

		cmd->reply = talloc_asprintf_append(cmd->reply,
					"%s%s,%u,%u",
					space, gsm_pchan_name(i), lc->used, lc->total);
		if (!cmd->reply)
			goto error;
		space = " ";
	}

	return CTRL_CMD_REPLY;

error:
	cmd->reply = "Memory allocation failure";
	return CTRL_CMD_ERROR;
}

CTRL_CMD_DEFINE_RO(bts_chan_load, "channel-load");

static int get_bts_oml_conn(struct ctrl_cmd *cmd, void *data)
{
	const struct gsm_bts *bts = cmd->node;

	cmd->reply = get_model_oml_status(bts);

	return CTRL_CMD_REPLY;
}

CTRL_CMD_DEFINE_RO(bts_oml_conn, "oml-connection-state");

static int get_bts_oml_up(struct ctrl_cmd *cmd, void *data)
{
	const struct gsm_bts *bts = cmd->node;

	cmd->reply = talloc_asprintf(cmd, "%llu", bts_uptime(bts));
	if (!cmd->reply) {
		cmd->reply = "OOM";
		return CTRL_CMD_ERROR;
	}

	return CTRL_CMD_REPLY;
}

CTRL_CMD_DEFINE_RO(bts_oml_up, "oml-uptime");

static int verify_bts_gprs_mode(struct ctrl_cmd *cmd, const char *value, void *_data)
{
	int valid;
	enum bts_gprs_mode mode;
	struct gsm_bts *bts = cmd->node;

	mode = bts_gprs_mode_parse(value, &valid);
	if (!valid) {
		cmd->reply = "Mode is not known";
		return 1;
	}

	if (!bts_gprs_mode_is_compat(bts, mode)) {
		cmd->reply = "bts does not support this mode";
		return 1;
	}

	return 0;
}

static int get_bts_gprs_mode(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_bts *bts = cmd->node;

	cmd->reply = talloc_strdup(cmd, bts_gprs_mode_name(bts->gprs.mode));
	return CTRL_CMD_REPLY;
}

static int set_bts_gprs_mode(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_bts *bts = cmd->node;

	bts->gprs.mode = bts_gprs_mode_parse(cmd->value, NULL);
	return get_bts_gprs_mode(cmd, data);
}

CTRL_CMD_DEFINE(bts_gprs_mode, "gprs-mode");

static int get_bts_rf_state(struct ctrl_cmd *cmd, void *data)
{
	const char *oper, *admin, *policy;
	struct gsm_bts *bts = cmd->node;

	if (!bts) {
		cmd->reply = "bts not found.";
		return CTRL_CMD_ERROR;
	}

	oper = osmo_bsc_rf_get_opstate_name(osmo_bsc_rf_get_opstate_by_bts(bts));
	admin = osmo_bsc_rf_get_adminstate_name(osmo_bsc_rf_get_adminstate_by_bts(bts));
	policy = osmo_bsc_rf_get_policy_name(osmo_bsc_rf_get_policy_by_bts(bts));

	cmd->reply = talloc_asprintf(cmd, "%s,%s,%s", oper, admin, policy);
	if (!cmd->reply) {
		cmd->reply = "OOM.";
		return CTRL_CMD_ERROR;
	}

	return CTRL_CMD_REPLY;
}
CTRL_CMD_DEFINE_RO(bts_rf_state, "rf_state");

/* Return a list of the states of each TRX for a given BTS.
 * <bts_nr>,<trx_nr>,<opstate>,<adminstate>,<rf_policy>,<rsl_status>;<bts_nr>,<trx_nr>,...;...;
 * For details on the string, see bsc_rf_states_c();
 */
static int get_bts_rf_states(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_bts *bts = cmd->node;

	if (!bts) {
		cmd->reply = "bts not found.";
		return CTRL_CMD_ERROR;
	}

	cmd->reply = bsc_rf_states_of_bts_c(cmd, bts);
	if (!cmd->reply) {
		cmd->reply = "OOM.";
		return CTRL_CMD_ERROR;
	}

	return CTRL_CMD_REPLY;
}
CTRL_CMD_DEFINE_RO(bts_rf_states, "rf_states");

static int verify_bts_c0_power_red(struct ctrl_cmd *cmd, const char *value, void *_data)
{
	const int red = atoi(value);

	if (red < 0 || red > 6) {
		cmd->reply = "Value is out of range";
		return 1;
	} else if (red % 2 != 0) {
		cmd->reply = "Value must be even";
		return 1;
	}

	return 0;
}

static int get_bts_c0_power_red(struct ctrl_cmd *cmd, void *data)
{
	const struct gsm_bts *bts = cmd->node;

	cmd->reply = talloc_asprintf(cmd, "%u", bts->c0_max_power_red_db);
	if (!cmd->reply) {
		cmd->reply = "OOM.";
		return CTRL_CMD_ERROR;
	}

	return CTRL_CMD_REPLY;
}

static int set_bts_c0_power_red(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_bts *bts = cmd->node;
	const int red = atoi(cmd->value);
	int rc;

	rc = gsm_bts_set_c0_power_red(bts, red);
	if (rc == -ENOTSUP) {
		cmd->reply = "BCCH carrier power reduction is not supported";
		return CTRL_CMD_ERROR;
	} else if (rc != 0) {
		cmd->reply = "Failed to enable BCCH carrier power reduction";
		return CTRL_CMD_ERROR;
	}

	return get_bts_c0_power_red(cmd, data);
}

CTRL_CMD_DEFINE(bts_c0_power_red, "c0-power-reduction");

static int verify_bts_neighbor_list_add_del(struct ctrl_cmd *cmd, const char *value, void *_data)
{
	int arfcn;

	if (osmo_str_to_int(&arfcn, value, 10, 0, 1023) < 0) {
		cmd->reply = "Invalid ARFCN value";
		return 1;
	}

	return 0;
}

static int set_bts_neighbor_list_add_del(struct ctrl_cmd *cmd, void *data, bool add)
{
	struct gsm_bts *bts = cmd->node;
	struct bitvec *bv = &bts->si_common.neigh_list;
	int arfcn_int;
	uint16_t arfcn;
	enum gsm_band unused;

	if (osmo_str_to_int(&arfcn_int, cmd->value, 10, 0, 1023) < 0) {
		cmd->reply = "Failed to parse ARFCN value";
		return CTRL_CMD_ERROR;
	}
	arfcn = (uint16_t) arfcn_int;

	if (bts->neigh_list_manual_mode == NL_MODE_AUTOMATIC) {
		cmd->reply = "Neighbor list not in manual mode";
		return CTRL_CMD_ERROR;
	}

	if (gsm_arfcn2band_rc(arfcn, &unused) < 0) {
		cmd->reply = "Invalid arfcn detected";
		return CTRL_CMD_ERROR;
	}

	if (add)
		bitvec_set_bit_pos(bv, arfcn, 1);
	else
		bitvec_set_bit_pos(bv, arfcn, 0);

	cmd->reply = "OK";
	return CTRL_CMD_REPLY;
}

static int verify_bts_neighbor_list_add(struct ctrl_cmd *cmd, const char *value, void *_data)
{
	return verify_bts_neighbor_list_add_del(cmd, value, _data);
}

static int set_bts_neighbor_list_add(struct ctrl_cmd *cmd, void *data)
{
	return set_bts_neighbor_list_add_del(cmd, data, true);
}

CTRL_CMD_DEFINE_WO(bts_neighbor_list_add, "neighbor-list add");

static int verify_bts_neighbor_list_del(struct ctrl_cmd *cmd, const char *value, void *_data)
{
	return verify_bts_neighbor_list_add_del(cmd, value, _data);
}

static int set_bts_neighbor_list_del(struct ctrl_cmd *cmd, void *data)
{
	return set_bts_neighbor_list_add_del(cmd, data, false);
}

CTRL_CMD_DEFINE_WO(bts_neighbor_list_del, "neighbor-list del");

static int verify_bts_neighbor_list_mode(struct ctrl_cmd *cmd, const char *value, void *_data)
{
	if (!strcmp(value, "automatic"))
		return 0;
	if (!strcmp(value, "manual"))
		return 0;
	if (!strcmp(value, "manual-si5"))
		return 0;

	cmd->reply = "Invalid mode";
	return 1;
}

static int set_bts_neighbor_list_mode(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_bts *bts = cmd->node;
	int mode = NL_MODE_AUTOMATIC;

	if (!strcmp(cmd->value, "automatic"))
		mode = NL_MODE_AUTOMATIC;
	else if (!strcmp(cmd->value, "manual"))
		mode = NL_MODE_MANUAL;
	else if (!strcmp(cmd->value, "manual-si5"))
		mode = NL_MODE_MANUAL_SI5SEP;

	switch (mode) {
	case NL_MODE_MANUAL_SI5SEP:
	case NL_MODE_MANUAL:
		/* make sure we clear the current list when switching to
		 * manual mode */
		if (bts->neigh_list_manual_mode == 0)
			memset(&bts->si_common.data.neigh_list, 0, sizeof(bts->si_common.data.neigh_list));
		break;
	default:
		break;
	}

	bts->neigh_list_manual_mode = mode;

	cmd->reply = "OK";
	return CTRL_CMD_REPLY;
}

CTRL_CMD_DEFINE_WO(bts_neighbor_list_mode, "neighbor-list mode");

/* si2quater neighbor management: delete an EARFCN.
 * Format: bts.<0-255>.si2quater-neighbor-list.del.earfcn EARFCN
 * EARFCN is in range 0..65535 */
static int set_bts_si2quater_neighbor_list_del_earfcn(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_bts *bts = (struct gsm_bts *)cmd->node;
	struct osmo_earfcn_si2q *e = &bts->si_common.si2quater_neigh_list;
	int earfcn;

	if (osmo_str_to_int(&earfcn, cmd->value, 10, 0, 65535) < 0) {
		cmd->reply = "Failed to parse neighbor EARFCN value";
		return CTRL_CMD_ERROR;
	}

	if (osmo_earfcn_del(e, earfcn) < 0) {
		cmd->reply = "Failed to delete a (not existent?) neighbor EARFCN";
		return CTRL_CMD_ERROR;
	}

	cmd->reply = "OK";
	return CTRL_CMD_REPLY;
}

CTRL_CMD_DEFINE_WO_NOVRF(bts_si2quater_neighbor_list_del_earfcn,
			 "si2quater-neighbor-list del earfcn");

/* si2quater neighbor management: delete an UARFCN
 * Format: bts.<0-255>.si2quater-neighbor-list.del.uarfcn UARFCN,SCRAMBLE
 * UARFCN is in range 0..16383, SCRAMBLE is in range 0..511 */
static int set_bts_si2quater_neighbor_list_del_uarfcn(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_bts *bts = (struct gsm_bts *)cmd->node;
	char *uarfcn_str, *scramble_str;
	char *tmp, *saveptr;
	int uarfcn, scramble;

	tmp = talloc_strdup(OTC_SELECT, cmd->value);
	if (!tmp) {
		cmd->reply = "OOM";
		return CTRL_CMD_ERROR;
	}

	uarfcn_str = strtok_r(tmp, ",", &saveptr);
	scramble_str = strtok_r(NULL, ",", &saveptr);

	if (!uarfcn_str || osmo_str_to_int(&uarfcn, uarfcn_str, 10, 0, 16383) < 0) {
		cmd->reply = "Failed to parse neighbor UARFCN value";
		return CTRL_CMD_ERROR;
	}

	if (!scramble_str || osmo_str_to_int(&scramble, scramble_str, 10, 0, 511) < 0) {
		cmd->reply = "Failed to parse neighbor scrambling code";
		return CTRL_CMD_ERROR;
	}

	if (bts_uarfcn_del(bts, uarfcn, scramble) < 0) {
		cmd->reply = "Failed to delete a (not existent?) neighbor UARFCN";
		return CTRL_CMD_ERROR;
	}

	cmd->reply = "OK";
	return CTRL_CMD_REPLY;
}

CTRL_CMD_DEFINE_WO_NOVRF(bts_si2quater_neighbor_list_del_uarfcn,
			 "si2quater-neighbor-list del uarfcn");

/* TODO: si2quater neighbor management: add EARFCN */
/* TODO: si2quater neighbor management: add UARFCN */

int bsc_bts_ctrl_cmds_install(void)
{
	int rc = 0;

	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_bts_loc);
	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_bts_lac);
	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_bts_ci);
	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_bts_apply_config);
	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_bts_si);
	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_bts_power_ctrl_defs);
	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_bts_chan_load);
	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_bts_oml_conn);
	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_bts_oml_up);
	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_bts_gprs_mode);
	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_bts_rf_state);
	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_bts_rf_states);
	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_bts_c0_power_red);
	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_bts_neighbor_list_add);
	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_bts_neighbor_list_del);
	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_bts_neighbor_list_mode);
	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_bts_si2quater_neighbor_list_del_earfcn);
	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_bts_si2quater_neighbor_list_del_uarfcn);

	rc |= neighbor_ident_ctrl_init();

	rc = bsc_bts_trx_ctrl_cmds_install();

	return rc;
}
