/*
 * Copyright (C) 2024 by sysmocom s.f.m.c. GmbH
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Affero General Public License
 * as published by the Free Software Foundation; either version 3
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <osmocom/ctrl/control_cmd.h>

#include <osmocom/bsc/ctrl.h>
#include <osmocom/bsc/bts.h>
#include <osmocom/bsc/system_information.h>
#include <osmocom/bsc/abis_rsl.h>

static int verify_lchan_ms_power(struct ctrl_cmd *cmd, const char *value, void *_data)
{
	int ms_power = atoi(cmd->value);

	if (ms_power < 0 || ms_power > 40) {
		cmd->reply = "Value is out of range";
		return 1;
	}

	return 0;
}

/* power control management: Get lchan's ms power in dBm
 * format: bts.<0-255>.trx.<0-255>.ts.<0-8>.lchan.<0-8>.ms-power */
static int get_lchan_ms_power(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_lchan *lchan = cmd->node;

	cmd->reply = talloc_asprintf(cmd, "%u", ms_pwr_dbm(lchan->ts->trx->bts->band, lchan->ms_power));
	if (!cmd->reply) {
		cmd->reply = "OOM";
		return CTRL_CMD_ERROR;
	}

	return CTRL_CMD_REPLY;
}

/* power control management: Set lchan's ms power in dBm.
 * For static ms power control it will change the ms tx power.
 * For dynamic ms power control it will limit the maximum power level.
 * format: bts.<0-255>.trx.<0-255>.ts.<0-8>.lchan.<0-8>.ms-power <ms power>
 * ms power is in range 0..40 */
static int set_lchan_ms_power(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_lchan *lchan = cmd->node;

	lchan->ms_power = ms_pwr_ctl_lvl(lchan->ts->trx->bts->band, atoi(cmd->value));
	rsl_chan_ms_power_ctrl(lchan);
	cmd->reply = "OK";
	return CTRL_CMD_REPLY;
}

CTRL_CMD_DEFINE(lchan_ms_power, "ms-power");

int bsc_bts_trx_ts_lchan_ctrl_cmds_install(void)
{
	int rc = 0;

	rc |= ctrl_cmd_install(CTRL_NODE_LCHAN, &cmd_lchan_ms_power);

	return rc;
}
