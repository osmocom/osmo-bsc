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
#include <osmocom/bsc/lchan_fsm.h>

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
 * format: bts.<0-65535>.trx.<0-255>.ts.<0-8>.lchan.<0-8>.ms-power */
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
 * format: bts.<0-65535>.trx.<0-255>.ts.<0-8>.lchan.<0-8>.ms-power <ms power>
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


char *lchan_dump_full_ctrl(const void *t, struct gsm_lchan *lchan)
{
	struct in_addr ia;
	char *interference = ",", *tmsi = "", *ipa_bound = ",,", *ipa_conn = ",,";

	if (lchan->interf_dbm != INTERF_DBM_UNKNOWN) {
		interference = talloc_asprintf(t, "%d,%u", lchan->interf_dbm, lchan->interf_band);
		if (!interference)
			return NULL;
	}

	if (lchan->conn && lchan->conn->bsub && lchan->conn->bsub->tmsi != GSM_RESERVED_TMSI) {
		tmsi = talloc_asprintf(t, "0x%08x", lchan->conn->bsub->tmsi);
		if (!tmsi)
			return NULL;
	}

	if (is_ipa_abisip_bts(lchan->ts->trx->bts) && lchan->abis_ip.bound_ip) {
		ia.s_addr = htonl(lchan->abis_ip.bound_ip);
		ipa_bound = talloc_asprintf(t, "%s,%u,%u", inet_ntoa(ia), lchan->abis_ip.bound_port,
								lchan->abis_ip.conn_id);
		if (!ipa_bound)
			return NULL;
	}

	if (is_ipa_abisip_bts(lchan->ts->trx->bts) && lchan->abis_ip.connect_ip) {
		ia.s_addr = htonl(lchan->abis_ip.connect_ip);
		ipa_conn = talloc_asprintf(t, "%s,%u,0x%02x", inet_ntoa(ia), lchan->abis_ip.connect_port,
								lchan->abis_ip.speech_mode);
		if (!ipa_conn)
			return NULL;
	}

	return talloc_asprintf(t, "%u,%u,%u,%u,%s,%u,%s,%s,%u,%u,%s,%s,%s,%s,%s,%s",
		lchan->ts->trx->bts->nr,
		lchan->ts->trx->nr,
		lchan->ts->nr,
		lchan->nr,
		gsm_chan_t_name(lchan->type),
		lchan->conn ? 1 : 0, lchan_state_name(lchan),
		lchan->fi && lchan->fi->state == LCHAN_ST_BORKEN ? lchan->last_error : "",
		lchan->ts->trx->nominal_power - lchan->ts->trx->max_power_red - lchan->bs_power_db,
		ms_pwr_dbm(lchan->ts->trx->bts->band, lchan->ms_power),
		interference,
		gsm48_chan_mode_name(lchan->current_ch_mode_rate.chan_mode),
		lchan->conn && lchan->conn->bsub && strlen(lchan->conn->bsub->imsi) ? lchan->conn->bsub->imsi : "",
		tmsi,
		ipa_bound,
		ipa_conn
	);
}

/* Return full information about a logical channel.
 * format: bts.<0-65535>.trx.<0-255>.ts.<0-8>.lchan.<0-8>.show.full
 * result format: <bts>,<trx>,<ts>,<lchan>,<type>,<connection>,<state>,<last error>,<bs power>,<ms power>,<interference dbm>,
 *	<interference band>,<channel mode>,<imsi>,<tmsi>,<ipa bound ip>,<ipa bound port>,<ipa bound conn id>,<ipa conn ip>,
 *	<ipa conn port>,<ipa conn speech mode>
 */
static int get_lchan_show_full(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_lchan *lchan = cmd->node;
	cmd->reply = lchan_dump_full_ctrl(cmd, lchan);
	if (!cmd->reply) {
		cmd->reply = "OOM";
		return CTRL_CMD_ERROR;
	}

	return CTRL_CMD_REPLY;
}
CTRL_CMD_DEFINE_RO(lchan_show_full, "show full");


int bsc_bts_trx_ts_lchan_ctrl_cmds_install(void)
{
	int rc = 0;

	rc |= ctrl_cmd_install(CTRL_NODE_LCHAN, &cmd_lchan_ms_power);
	rc |= ctrl_cmd_install(CTRL_NODE_LCHAN, &cmd_lchan_show_full);

	return rc;
}
