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

#include <osmocom/ctrl/control_cmd.h>

#include <osmocom/bsc/ctrl.h>
#include <osmocom/bsc/bts.h>
#include <osmocom/bsc/abis_nm.h>

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

char *trx_lchan_dump_full_ctrl(const void *t, struct gsm_bts_trx *trx)
{
	int ts_nr;
	bool first_ts = true;
	char *ts_dump, *dump;

	dump = talloc_strdup(t, "");
	if (!dump)
		return NULL;

	for (ts_nr = 0; ts_nr < TRX_NR_TS; ts_nr++) {
		ts_dump = ts_lchan_dump_full_ctrl(t, &trx->ts[ts_nr]);
		if (!ts_dump)
			return NULL;
		if (!strlen(ts_dump))
			continue;
		dump = talloc_asprintf_append(dump, first_ts ? "%s" : "\n%s", ts_dump);
		if (!dump)
			return NULL;
		first_ts = false;
	}

	return dump;
}

/* Return full information about all logical channels in a TRX.
 * format: bts.<0-255>.trx.<0-255>.show-lchan.full
 * result format: New line delimited list of <bts>,<trx>,<ts>,<lchan>,<type>,<connection>,<state>,<last error>,<bs power>,
 *  <ms power>,<interference dbm>, <interference band>,<channel mode>,<imsi>,<tmsi>,<ipa bound ip>,<ipa bound port>,
 *  <ipa bound conn id>,<ipa conn ip>,<ipa conn port>,<ipa conn speech mode>
 */
static int get_trx_show_lchan_full(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_bts_trx *trx = cmd->node;

	cmd->reply = trx_lchan_dump_full_ctrl(cmd, trx);
	if (!cmd->reply) {
		cmd->reply = "OOM";
		return CTRL_CMD_ERROR;
	}

	return CTRL_CMD_REPLY;
}
CTRL_CMD_DEFINE_RO(trx_show_lchan_full, "show-lchan full");

int bsc_bts_trx_ctrl_cmds_install(void)
{
	int rc = 0;

	rc |= ctrl_cmd_install(CTRL_NODE_TRX, &cmd_trx_max_power);
	rc |= ctrl_cmd_install(CTRL_NODE_TRX, &cmd_trx_arfcn);
	rc |= ctrl_cmd_install(CTRL_NODE_TRX, &cmd_trx_rf_locked);
	rc |= ctrl_cmd_install(CTRL_NODE_TRX, &cmd_trx_show_lchan_full);

	rc |= bsc_bts_trx_ts_ctrl_cmds_install();

	return rc;
}
