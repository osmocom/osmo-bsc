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
#include <osmocom/bsc/system_information.h>

static int verify_ts_hopping_arfcn_add(struct ctrl_cmd *cmd, const char *value, void *_data)
{
	int64_t arfcn;
	enum gsm_band unused;
	if (osmo_str_to_int64(&arfcn, value, 10, 0, 1024) < 0)
		return 1;
	if (gsm_arfcn2band_rc(arfcn, &unused) < 0)
		return 1;
	return 0;
}
static int set_ts_hopping_arfcn_add(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_bts_trx_ts *ts = cmd->node;
	int arfcn = atoi(cmd->value);

	bitvec_set_bit_pos(&ts->hopping.arfcns, arfcn, ONE);

	/* Update Cell Allocation (list of all the frequencies allocated to a cell) */
	if (generate_cell_chan_alloc(ts->trx->bts) != 0) {
		bitvec_set_bit_pos(&ts->hopping.arfcns, arfcn, ZERO); /* roll-back */
		cmd->reply = "Failed to re-generate Cell Allocation";
		return CTRL_CMD_ERROR;
	}

	cmd->reply = "OK";
	return CTRL_CMD_REPLY;
}
/* Parameter format: "<arfcn>" */
CTRL_CMD_DEFINE_WO(ts_hopping_arfcn_add, "hopping-arfcn-add");

static int verify_ts_hopping_arfcn_del(struct ctrl_cmd *cmd, const char *value, void *_data)
{
	int64_t arfcn;
	enum gsm_band unused;
	if (strcmp(value, "all") == 0)
		return 0;
	if (osmo_str_to_int64(&arfcn, value, 10, 0, 1024) < 0)
		return 1;
	if (gsm_arfcn2band_rc(arfcn, &unused) < 0)
		return 1;
	return 0;
}
static int set_ts_hopping_arfcn_del(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_bts_trx_ts *ts = cmd->node;
	bool all = (strcmp(cmd->value, "all") == 0);
	int arfcn;

	if (all) {
		bitvec_zero(&ts->hopping.arfcns);
	} else {
		arfcn = atoi(cmd->value);
		bitvec_set_bit_pos(&ts->hopping.arfcns, arfcn, ZERO);
	}

	/* Update Cell Allocation (list of all the frequencies allocated to a cell) */
	if (generate_cell_chan_alloc(ts->trx->bts) != 0) {
		if (!all)
			bitvec_set_bit_pos(&ts->hopping.arfcns, arfcn, ONE); /* roll-back */
		cmd->reply = "Failed to re-generate Cell Allocation";
		return CTRL_CMD_ERROR;
	}

	cmd->reply = "OK";
	return CTRL_CMD_REPLY;
}
/* Parameter format: "(<arfcn>|all)" */
CTRL_CMD_DEFINE_WO(ts_hopping_arfcn_del, "hopping-arfcn-del");

char *ts_lchan_dump_full_ctrl(const void *t, struct gsm_bts_trx_ts *ts)
{
	bool first_lchan = true;
	char *lchan_dump, *dump;
	struct gsm_lchan *lchan;

	dump = talloc_strdup(t, "");
	if (!dump)
		return NULL;

	ts_for_n_lchans(lchan, ts, ts->max_lchans_possible) {
		lchan_dump = lchan_dump_full_ctrl(t, lchan);
		if (!lchan_dump)
			return NULL;
		dump = talloc_asprintf_append(dump, first_lchan ? "%s" : "\n%s", lchan_dump);
		if (!dump)
			return NULL;
		first_lchan = false;
	}

	return dump;
}

/* Return full information about all logical channels in a timeslot.
 * format: bts.<0-255>.trx.<0-255>.ts.<0-8>.show-lchan.full
 * result format: New line delimited list of <bts>,<trx>,<ts>,<lchan>,<type>,<connection>,<state>,<last error>,<bs power>,
 *  <ms power>,<interference dbm>, <interference band>,<channel mode>,<imsi>,<tmsi>,<ipa bound ip>,<ipa bound port>,
 *  <ipa bound conn id>,<ipa conn ip>,<ipa conn port>,<ipa conn speech mode>
 */
static int get_ts_show_lchan_full(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_bts_trx_ts *ts = cmd->node;

	cmd->reply = ts_lchan_dump_full_ctrl(cmd, ts);
	if (!cmd->reply) {
		cmd->reply = "OOM";
		return CTRL_CMD_ERROR;
	}

	return CTRL_CMD_REPLY;
}
CTRL_CMD_DEFINE_RO(ts_show_lchan_full, "show-lchan full");

int bsc_bts_trx_ts_ctrl_cmds_install(void)
{
	int rc = 0;

	rc |= ctrl_cmd_install(CTRL_NODE_TS, &cmd_ts_hopping_arfcn_add);
	rc |= ctrl_cmd_install(CTRL_NODE_TS, &cmd_ts_hopping_arfcn_del);
	rc |= ctrl_cmd_install(CTRL_NODE_TS, &cmd_ts_show_lchan_full);

	rc |= bsc_bts_trx_ts_lchan_ctrl_cmds_install();

	return rc;
}
