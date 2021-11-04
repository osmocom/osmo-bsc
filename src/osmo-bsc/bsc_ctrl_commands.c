/*
 * (C) 2013-2015 by Holger Hans Peter Freyther
 * (C) 2013-2015 by sysmocom s.f.m.c. GmbH
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

#include <osmocom/gsm/gsm48.h>
#include <osmocom/bsc/ipaccess.h>
#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/abis_nm.h>
#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/chan_alloc.h>
#include <osmocom/bsc/osmo_bsc_rf.h>
#include <osmocom/bsc/bsc_msc_data.h>
#include <osmocom/bsc/bts.h>
#include <osmocom/bsc/neighbor_ident.h>

static int verify_net_apply_config_file(struct ctrl_cmd *cmd, const char *value, void *_data)
{
	FILE *cfile;

	if (!cmd->value || cmd->value[0] == '\0')
		return -1;

	cfile = fopen(cmd->value, "r");
	if (!cfile)
		return -1;

	fclose(cfile);

	return 0;
}
static int set_net_apply_config_file(struct ctrl_cmd *cmd, void *_data)
{
	int rc;
	FILE *cfile;
	unsigned cmd_ret = CTRL_CMD_ERROR;

	LOGP(DCTRL, LOGL_NOTICE, "Applying VTY snippet from %s...\n", cmd->value);
	cfile = fopen(cmd->value, "r");
	if (!cfile) {
		LOGP(DCTRL, LOGL_NOTICE, "Applying VTY snippet from %s: fopen() failed: %d\n",
		     cmd->value, errno);
		cmd->reply = "NoFile";
		return cmd_ret;
	}

	rc = vty_read_config_filep(cfile, NULL);
	LOGP(DCTRL, LOGL_NOTICE, "Applying VTY snippet from %s returned %d\n", cmd->value, rc);
	if (rc) {
		cmd->reply = talloc_asprintf(cmd, "ParseError=%d", rc);
		if (!cmd->reply)
			cmd->reply = "OOM";
		goto close_ret;
	}

	cmd->reply = "OK";
	cmd_ret = CTRL_CMD_REPLY;
close_ret:
	fclose(cfile);
	return cmd_ret;
}
CTRL_CMD_DEFINE_WO(net_apply_config_file, "apply-config-file");

static int verify_net_write_config_file(struct ctrl_cmd *cmd, const char *value, void *_data)
{
	return 0;
}
static int set_net_write_config_file(struct ctrl_cmd *cmd, void *_data)
{
	const char *cfile_name;
	unsigned cmd_ret = CTRL_CMD_ERROR;

	if (strcmp(cmd->value, "overwrite"))
		host_config_set(cmd->value);

	cfile_name = host_config_file();

	LOGP(DCTRL, LOGL_NOTICE, "Writing VTY config to file %s...\n", cfile_name);
	if (osmo_vty_write_config_file(cfile_name) < 0)
		goto ret;

	cmd->reply = "OK";
	cmd_ret = CTRL_CMD_REPLY;
ret:
	return cmd_ret;
}
CTRL_CMD_DEFINE_WO(net_write_config_file, "write-config-file");

CTRL_CMD_DEFINE(net_mcc, "mcc");
static int get_net_mcc(struct ctrl_cmd *cmd, void *_data)
{
	struct gsm_network *net = cmd->node;
	cmd->reply = talloc_asprintf(cmd, "%s", osmo_mcc_name(net->plmn.mcc));
	if (!cmd->reply) {
		cmd->reply = "OOM";
		return CTRL_CMD_ERROR;
	}
	return CTRL_CMD_REPLY;
}
static int set_net_mcc(struct ctrl_cmd *cmd, void *_data)
{
	struct gsm_network *net = cmd->node;
	uint16_t mcc;
	if (osmo_mcc_from_str(cmd->value, &mcc))
		return -1;
	net->plmn.mcc = mcc;
	return get_net_mcc(cmd, _data);
}
static int verify_net_mcc(struct ctrl_cmd *cmd, const char *value, void *_data)
{
	if (osmo_mcc_from_str(value, NULL))
		return -1;
	return 0;
}

CTRL_CMD_DEFINE(net_mnc, "mnc");
static int get_net_mnc(struct ctrl_cmd *cmd, void *_data)
{
	struct gsm_network *net = cmd->node;
	cmd->reply = talloc_asprintf(cmd, "%s", osmo_mnc_name(net->plmn.mnc, net->plmn.mnc_3_digits));
	if (!cmd->reply) {
		cmd->reply = "OOM";
		return CTRL_CMD_ERROR;
	}
	return CTRL_CMD_REPLY;
}
static int set_net_mnc(struct ctrl_cmd *cmd, void *_data)
{
	struct gsm_network *net = cmd->node;
	struct osmo_plmn_id plmn = net->plmn;
	if (osmo_mnc_from_str(cmd->value, &plmn.mnc, &plmn.mnc_3_digits)) {
		cmd->reply = "Error while decoding MNC";
		return CTRL_CMD_ERROR;
	}
	net->plmn = plmn;
	return get_net_mnc(cmd, _data);
}
static int verify_net_mnc(struct ctrl_cmd *cmd, const char *value, void *_data)
{
	if (osmo_mnc_from_str(value, NULL, NULL))
		return -1;
	return 0;
}

static int set_net_apply_config(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_network *net = cmd->node;
	struct gsm_bts *bts;

	llist_for_each_entry(bts, &net->bts_list, list) {
		if (!is_ipaccess_bts(bts))
			continue;

		/*
		 * The ip.access nanoBTS seems to be unrelaible on BSSGP
		 * so let's us just reboot it. For the sysmoBTS we can just
		 * restart the process as all state is gone.
		 */
		if (!is_osmobts(bts) && strcmp(cmd->value, "restart") == 0) {
			struct gsm_bts_trx *trx;
			llist_for_each_entry_reverse(trx, &bts->trx_list, list)
				abis_nm_ipaccess_restart(trx);
		} else
			ipaccess_drop_oml(bts, "ctrl net.apply-configuration");
	}

	cmd->reply = "Tried to drop the BTS";
	return CTRL_CMD_REPLY;
}

CTRL_CMD_DEFINE_WO_NOVRF(net_apply_config, "apply-configuration");

static int verify_net_mcc_mnc_apply(struct ctrl_cmd *cmd, const char *value, void *d)
{
	char *tmp, *saveptr, *mcc, *mnc;
	int rc = 0;

	tmp = talloc_strdup(cmd, value);
	if (!tmp)
		return 1;

	mcc = strtok_r(tmp, ",", &saveptr);
	mnc = strtok_r(NULL, ",", &saveptr);

	if (osmo_mcc_from_str(mcc, NULL) || osmo_mnc_from_str(mnc, NULL, NULL))
		rc = -1;

	talloc_free(tmp);
	return rc;
}

static int set_net_mcc_mnc_apply(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_network *net = cmd->node;
	char *tmp, *saveptr, *mcc_str, *mnc_str;
	struct osmo_plmn_id plmn;

	tmp = talloc_strdup(cmd, cmd->value);
	if (!tmp)
		goto oom;

	mcc_str = strtok_r(tmp, ",", &saveptr);
	mnc_str = strtok_r(NULL, ",", &saveptr);

	if (osmo_mcc_from_str(mcc_str, &plmn.mcc)) {
		cmd->reply = "Error while decoding MCC";
		talloc_free(tmp);
		return CTRL_CMD_ERROR;
	}

	if (osmo_mnc_from_str(mnc_str, &plmn.mnc, &plmn.mnc_3_digits)) {
		cmd->reply = "Error while decoding MNC";
		talloc_free(tmp);
		return CTRL_CMD_ERROR;
	}

	talloc_free(tmp);

	if (!osmo_plmn_cmp(&net->plmn, &plmn)) {
		cmd->reply = "Nothing changed";
		return CTRL_CMD_REPLY;
	}

	net->plmn = plmn;

	return set_net_apply_config(cmd, data);

oom:
	cmd->reply = "OOM";
	return CTRL_CMD_ERROR;
}
CTRL_CMD_DEFINE_WO(net_mcc_mnc_apply, "mcc-mnc-apply");

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

/* Return a list of the states of each TRX for all BTS:
 * <bts_nr>,<trx_nr>,<opstate>,<adminstate>,<rf_policy>,<rsl_status>;<bts_nr>,<trx_nr>,...;...;
 * For details on the string, see bsc_rf_states_c();
 */
static int get_net_rf_states(struct ctrl_cmd *cmd, void *data)
{
	cmd->reply = bsc_rf_states_c(cmd);
	if (!cmd->reply) {
		cmd->reply = "OOM.";
		return CTRL_CMD_ERROR;
	}
	return CTRL_CMD_REPLY;
}
CTRL_CMD_DEFINE_RO(net_rf_states, "rf_states");

static int get_net_rf_lock(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_network *net = cmd->node;
	struct gsm_bts *bts;
	const char *policy_name;

	policy_name = osmo_bsc_rf_get_policy_name(net->rf_ctrl->policy);

	llist_for_each_entry(bts, &net->bts_list, list) {
		struct gsm_bts_trx *trx;

		/* Exclude the BTS from the global lock */
		if (bts->excl_from_rf_lock)
			continue;

		llist_for_each_entry(trx, &bts->trx_list, list) {
			if (trx->mo.nm_state.availability == NM_AVSTATE_OK &&
			    trx->mo.nm_state.operational != NM_OPSTATE_DISABLED) {
				cmd->reply = talloc_asprintf(cmd,
						"state=on,policy=%s,bts=%u,trx=%u",
						policy_name, bts->nr, trx->nr);
				return CTRL_CMD_REPLY;
			}
		}
	}

	cmd->reply = talloc_asprintf(cmd, "state=off,policy=%s",
			policy_name);
	return CTRL_CMD_REPLY;
}

#define TIME_FORMAT_RFC2822 "%a, %d %b %Y %T %z"

static int set_net_rf_lock(struct ctrl_cmd *cmd, void *data)
{
	int locked = atoi(cmd->value);
	struct gsm_network *net = cmd->node;
	time_t now = time(NULL);
	char now_buf[64];
	struct osmo_bsc_rf *rf;

	if (!net) {
		cmd->reply = "net not found.";
		return CTRL_CMD_ERROR;
	}

	rf = net->rf_ctrl;

	if (!rf) {
		cmd->reply = "RF Ctrl is not enabled in the BSC Configuration";
		return CTRL_CMD_ERROR;
	}

	talloc_free(rf->last_rf_lock_ctrl_command);
	strftime(now_buf, sizeof(now_buf), TIME_FORMAT_RFC2822, gmtime(&now));
	rf->last_rf_lock_ctrl_command =
		talloc_asprintf(rf, "rf_locked %u (%s)", locked, now_buf);

	osmo_bsc_rf_schedule_lock(rf, locked == 1 ? '0' : '1');

	cmd->reply = talloc_asprintf(cmd, "%u", locked);
	if (!cmd->reply) {
		cmd->reply = "OOM.";
		return CTRL_CMD_ERROR;
	}

	return CTRL_CMD_REPLY;
}

static int verify_net_rf_lock(struct ctrl_cmd *cmd, const char *value, void *data)
{
	int locked = atoi(cmd->value);

	if ((locked != 0) && (locked != 1))
		return 1;

	return 0;
}
CTRL_CMD_DEFINE(net_rf_lock, "rf_locked");

static int get_trx_rf_locked(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_bts_trx *trx = cmd->node;
	/* Return rf_locked = 1 only if it is explicitly locked. If it is in shutdown or null state, do not "trick" the
	 * caller into thinking that sending "rf_locked 0" is necessary to bring the TRX up. */
	cmd->reply = (trx->mo.nm_state.administrative == NM_STATE_LOCKED) ? "1" : "0";
	return CTRL_CMD_REPLY;
}

static int set_trx_rf_locked(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_bts_trx *trx = cmd->node;
	int locked;
	if (osmo_str_to_int(&locked, cmd->value, 10, 0, 1)) {
		cmd->reply = "Invalid value";
		return CTRL_CMD_ERROR;
	}

	gsm_trx_lock_rf(trx, locked, "ctrl");

	/* Let's not assume the nm FSM has already switched its state, just return the intended rf_locked value. */
	cmd->reply = locked ? "1" : "0";
	return CTRL_CMD_REPLY;
}

static int verify_trx_rf_locked(struct ctrl_cmd *cmd, const char *value, void *data)
{
	return osmo_str_to_int(NULL, value, 10, 0, 1);
}
CTRL_CMD_DEFINE(trx_rf_locked, "rf_locked");

static int get_net_bts_num(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_network *net = cmd->node;

	cmd->reply = talloc_asprintf(cmd, "%u", net->num_bts);
	return CTRL_CMD_REPLY;
}
CTRL_CMD_DEFINE_RO(net_bts_num, "number-of-bts");

/* TRX related commands below here */
CTRL_HELPER_GET_INT(trx_max_power, struct gsm_bts_trx, max_power_red);
static int verify_trx_max_power(struct ctrl_cmd *cmd, const char *value, void *_data)
{
	int tmp = atoi(value);

	if (tmp < 0 || tmp > 22) {
		cmd->reply = "Value must be between 0 and 22";
		return -1;
	}

	if (tmp & 1) {
		cmd->reply = "Value must be even";
		return -1;
	}

	return 0;
}
CTRL_CMD_DEFINE_RANGE(trx_arfcn, "arfcn", struct gsm_bts_trx, arfcn, 0, 1023);

static int set_trx_max_power(struct ctrl_cmd *cmd, void *_data)
{
	struct gsm_bts_trx *trx = cmd->node;
	int old_power;

	/* remember the old value, set the new one */
	old_power = trx->max_power_red;
	trx->max_power_red = atoi(cmd->value);

	/* Maybe update the value */
	if (old_power != trx->max_power_red) {
		LOGP(DCTRL, LOGL_NOTICE,
			"%s updating max_pwr_red(%d)\n",
			gsm_trx_name(trx), trx->max_power_red);
		abis_nm_update_max_power_red(trx);
	}

	return get_trx_max_power(cmd, _data);
}
CTRL_CMD_DEFINE(trx_max_power, "max-power-reduction");

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

int bsc_base_ctrl_cmds_install(void)
{
	int rc = 0;
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_apply_config_file);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_write_config_file);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_mnc);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_mcc);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_apply_config);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_mcc_mnc_apply);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_rf_lock);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_bts_num);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_rf_states);

	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_bts_lac);
	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_bts_ci);
	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_bts_apply_config);
	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_bts_si);
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

	rc |= neighbor_ident_ctrl_init();

	rc |= ctrl_cmd_install(CTRL_NODE_TRX, &cmd_trx_max_power);
	rc |= ctrl_cmd_install(CTRL_NODE_TRX, &cmd_trx_arfcn);
	rc |= ctrl_cmd_install(CTRL_NODE_TRX, &cmd_trx_rf_locked);

	return rc;
}
