/* OsmoBSC handover control interface implementation */
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

#include <stdbool.h>
#include <talloc.h>
#include <osmocom/bsc/vty.h>
#include <osmocom/bsc/handover_cfg.h>
#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/bts.h>
#include <osmocom/bsc/handover_decision_2.h>
#include <osmocom/ctrl/control_cmd.h>

/* In handover_cfg.h the config items are described in VTY syntax. To be able to
 * use those here in the CTRL interface, we parse the config arguments like the
 * VTY would. (the value specification may be in the form of "<from-to>" or
 * "A|B|C|..." */
static bool verify_vty_cmd_arg(void *ctx, const char *range, const char *value)
{
	bool success;
	char *range_tok;
	char *valid_val;

	/* "default" value is always a valid value */
	if (strcmp(value, "default") == 0)
		return true;

	/* Try to check for a range first since it is the most common case */
	if (range[0] == '<') {
		if (vty_cmd_range_match(range, value))
			return true;
		else
			return false;
	}

	/* Try to tokenize the string to check for distintinct values */
	success = false;
	range_tok = talloc_zero_size(ctx, strlen(range) + 1);
	memcpy(range_tok, range, strlen(range));
	valid_val = strtok(range_tok, "|");
	while (valid_val != NULL) {
		if (strcmp(valid_val, value) == 0) {
			success = true;
			break;
		}
		valid_val = strtok(NULL, "|");
	}

	talloc_free(range_tok);
	return success;
}

/* NOTE: The following macro scheme has been designed for using it in the VTY
 * code. However, for the most part it also works for CTRL interface code as
 * well. */
#define HO_CFG_ONE_MEMBER(TYPE, NAME, DEFAULT_VAL, VTY_CMD_PREFIX, VTY_CMD, VTY_CMD_ARG, VTY_ARG_EVAL, VTY_WRITE_FMT, VTY_WRITE_CONV, VTY6) \
CTRL_CMD_DEFINE(NAME, VTY_CMD_PREFIX VTY_CMD); \
static int get_##NAME(struct ctrl_cmd *cmd, void *_data) \
{ \
	struct gsm_network *net = cmd->node; \
	struct handover_cfg *ho = net->ho; \
	TYPE val; \
	if (ho_isset_##NAME(ho)) { \
		val = ho_get_##NAME(ho); \
		cmd->reply = talloc_asprintf(cmd, VTY_WRITE_FMT, VTY_WRITE_CONV(val)); \
	} else \
		cmd->reply = talloc_asprintf(cmd, "%s", #DEFAULT_VAL); \
	return CTRL_CMD_REPLY; \
} \
static int set_##NAME(struct ctrl_cmd *cmd, void *_data) \
{ \
	struct gsm_network *net = cmd->node; \
	struct handover_cfg *ho = net->ho; \
	TYPE value; \
	if (strcmp(cmd->value, "default") == 0) \
		value = VTY_ARG_EVAL(#DEFAULT_VAL); \
	else \
		value = VTY_ARG_EVAL(cmd->value); \
	ho_set_##NAME(ho, value); \
	return get_##NAME(cmd, _data); \
} \
static int verify_##NAME(struct ctrl_cmd *cmd, const char *value, void *_data) \
{ \
	if (verify_vty_cmd_arg(cmd, VTY_CMD_ARG, value) != true) \
		return -1; \
	return 0; \
} \
CTRL_CMD_DEFINE(bts_##NAME, VTY_CMD_PREFIX VTY_CMD); \
static int get_bts_##NAME(struct ctrl_cmd *cmd, void *_data) \
{ \
        struct gsm_bts *bts = cmd->node; \
	struct handover_cfg *ho = bts->ho; \
	TYPE val; \
	if (ho_isset_##NAME(ho)) { \
		val = ho_get_##NAME(ho); \
		cmd->reply = talloc_asprintf(cmd, VTY_WRITE_FMT, VTY_WRITE_CONV(val)); \
	} else { \
		cmd->reply = talloc_asprintf(cmd, "%s", #DEFAULT_VAL); \
	} \
	return CTRL_CMD_REPLY; \
} \
static int set_bts_##NAME(struct ctrl_cmd *cmd, void *_data) \
{ \
	struct gsm_bts *bts = cmd->node; \
	struct handover_cfg *ho = bts->ho; \
	TYPE value; \
	if (strcmp(cmd->value, "default") == 0) \
		value = VTY_ARG_EVAL(#DEFAULT_VAL); \
	else \
		value = VTY_ARG_EVAL(cmd->value); \
	ho_set_##NAME(ho, value); \
	return get_bts_##NAME(cmd, _data); \
} \
static int verify_bts_##NAME(struct ctrl_cmd *cmd, const char *value, void *_data) \
{ \
	return verify_##NAME(cmd, value, _data); \
} \

/* Expand the above macro using the definitions from handover_cfg.h */
HO_CFG_ALL_MEMBERS
#undef HO_CFG_ONE_MEMBER

CTRL_CMD_DEFINE(congestion_check_interval, "handover2 congestion-check");
static int get_congestion_check_interval(struct ctrl_cmd *cmd, void *_data)
{
	struct gsm_network *net = cmd->node;
	if (net->hodec2.congestion_check_interval_s > 0)
		cmd->reply = talloc_asprintf(cmd, "%u", net->hodec2.congestion_check_interval_s);
	else
		cmd->reply = "disabled";
	return CTRL_CMD_REPLY;
}

static int set_congestion_check_interval(struct ctrl_cmd *cmd, void *_data)
{
	struct gsm_network *net = cmd->node;
	int value;

	/* Trigger congestion check and leave without changing anything */
	if (strcmp(cmd->value, "now") == 0) {
		hodec2_congestion_check(net);
		return get_congestion_check_interval(cmd, _data);
	}

	if (strcmp(cmd->value, "disabled") == 0)
		value = 0;
	else
		value = atoi(cmd->value);
	hodec2_on_change_congestion_check_interval(net, value);
	return get_congestion_check_interval(cmd, _data);
}

static int verify_congestion_check_interval(struct ctrl_cmd *cmd, const char *value, void *_data)
{
	if (strcmp(value, "disabled") == 0)
		return 0;
	if (strcmp(value, "now") == 0)
		return 0;
	if (verify_vty_cmd_arg(cmd, "<1-999>", value))
		return 0;
	return -1;
}

/* Filter name member in cmd for illegal '/' characters */
static struct ctrl_cmd_element *filter_name(void *ctx,
					    struct ctrl_cmd_element *cmd)
{
	unsigned int i;
	char *name;

	if (osmo_separated_identifiers_valid(cmd->name, " -"))
		return cmd;

	name = talloc_strdup(ctx, cmd->name);
	for (i = 0; i < strlen(name); i++) {
		if (name[i] == '/')
			name[i] = '-';
	}

	cmd->name = name;
	return cmd;
}

int bsc_ho_ctrl_cmds_install(void *ctx)
{
	int rc = 0;

	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_congestion_check_interval);

#define HO_CFG_ONE_MEMBER(TYPE, NAME, DEFAULT_VAL, VTY0, VTY1, VTY2, VTY_ARG_EVAL, VTY4, VTY5, VTY6) \
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, filter_name(ctx, &cmd_##NAME)); \
	rc |= ctrl_cmd_install(CTRL_NODE_BTS, filter_name(ctx, &cmd_bts_##NAME)); \

HO_CFG_ALL_MEMBERS
#undef HO_CFG_ONE_MEMBER

	return rc;
}
