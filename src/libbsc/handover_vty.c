/* OsmoBSC interface to quagga VTY for handover parameters */
/* (C) 2017 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * (C) 2009-2010 by Harald Welte <laforge@gnumonks.org>
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

#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/vty.h>
#include <osmocom/bsc/handover_cfg.h>
#include <osmocom/bsc/handover_decision_2.h>

static struct handover_cfg *ho_cfg_from_vty(struct vty *vty)
{
	switch (vty->node) {
	case GSMNET_NODE:
		return gsmnet_from_vty(vty)->ho;
	case BTS_NODE:
		OSMO_ASSERT(vty->index);
		return ((struct gsm_bts *)vty->index)->ho;
	default:
		OSMO_ASSERT(false);
	}
}


#define HO_CFG_ONE_MEMBER(TYPE, NAME, DEFAULT_VAL, \
			  VTY_CMD, VTY_CMD_ARG, VTY_ARG_EVAL, \
			  VTY_WRITE_FMT, VTY_WRITE_CONV, \
			  VTY_DOC) \
DEFUN(cfg_ho_##NAME, cfg_ho_##NAME##_cmd, \
      VTY_CMD " (" VTY_CMD_ARG "|default)", \
      VTY_DOC \
      "Use default (" #DEFAULT_VAL "), remove explicit setting on this node\n") \
{ \
	struct handover_cfg *ho = ho_cfg_from_vty(vty); \
	const char *val = argv[0]; \
	if (!strcmp(val, "default")) { \
		const char *msg; \
		if (ho_isset_##NAME(ho)) {\
			ho_clear_##NAME(ho); \
			msg = "setting removed, now is"; \
		} else \
			msg = "already was unset, still is"; \
		vty_out(vty, "%% '" VTY_CMD "' %s " VTY_WRITE_FMT "%s%s", \
			msg, VTY_WRITE_CONV( ho_get_##NAME(ho) ), \
			ho_isset_on_parent_##NAME(ho)? " (set on higher level node)" : "", \
			VTY_NEWLINE); \
	} \
	else \
		ho_set_##NAME(ho, VTY_ARG_EVAL(val)); \
	return CMD_SUCCESS; \
}

HO_CFG_ALL_MEMBERS
#undef HO_CFG_ONE_MEMBER


static inline const int a2congestion_check_interval(const char *arg)
{
	if (!strcmp(arg, "disabled"))
		return 0;
	return atoi(arg);
}

static inline const char *congestion_check_interval2a(int val)
{
	static char str[9];
	if (val < 1
	    || snprintf(str, sizeof(str), "%d", val) >= sizeof(str))
		return "disabled";
	return str;
}

DEFUN(cfg_net_ho_congestion_check_interval, cfg_net_ho_congestion_check_interval_cmd,
      "handover2 congestion-check (disabled|<1-999>|now)",
      HO_CFG_STR_HANDOVER2
      "Configure congestion check interval" HO_CFG_STR_2
      "Disable congestion checking, do not handover based on cell overload\n"
      "Congestion check interval in seconds (default "
      OSMO_STRINGIFY_VAL(HO_CFG_CONGESTION_CHECK_DEFAULT) ")\n"
      "Manually trigger a congestion check to run right now\n")
{
	if (!strcmp(argv[0], "now")) {
		hodec2_congestion_check(gsmnet_from_vty(vty));
		return CMD_SUCCESS;
	}

	hodec2_on_change_congestion_check_interval(gsmnet_from_vty(vty),
								a2congestion_check_interval(argv[0]));
	return CMD_SUCCESS;
}

static void ho_vty_write(struct vty *vty, const char *indent, struct handover_cfg *ho)
{
#define HO_CFG_ONE_MEMBER(TYPE, NAME, DEFAULT_VAL, \
			  VTY_CMD, VTY_CMD_ARG, VTY_ARG_EVAL, \
			  VTY_WRITE_FMT, VTY_WRITE_CONV, \
			  VTY_DOC) \
	if (ho_isset_##NAME(ho)) \
		vty_out(vty, "%s" VTY_CMD " " VTY_WRITE_FMT "%s", indent, \
			VTY_WRITE_CONV( ho_get_##NAME(ho) ), VTY_NEWLINE);

	HO_CFG_ALL_MEMBERS
#undef HO_CFG_ONE_MEMBER
}

void ho_vty_write_bts(struct vty *vty, struct gsm_bts *bts)
{
	ho_vty_write(vty, "  ", bts->ho);
}

void ho_vty_write_net(struct vty *vty, struct gsm_network *net)
{
	ho_vty_write(vty, " ", net->ho);

	if (net->hodec2.congestion_check_interval_s != HO_CFG_CONGESTION_CHECK_DEFAULT)
		vty_out(vty, " handover congestion-check %s%s",
			congestion_check_interval2a(net->hodec2.congestion_check_interval_s),
			VTY_NEWLINE);
}

static void ho_vty_init_cmds(int parent_node)
{
#define HO_CFG_ONE_MEMBER(TYPE, NAME, DEFAULT_VAL, VTY1, VTY2, VTY3, VTY4, VTY5, VTY6) \
	install_element(parent_node, &cfg_ho_##NAME##_cmd);

	HO_CFG_ALL_MEMBERS
#undef HO_CFG_ONE_MEMBER
}

void ho_vty_init()
{
	ho_vty_init_cmds(GSMNET_NODE);
	install_element(GSMNET_NODE, &cfg_net_ho_congestion_check_interval_cmd);

	ho_vty_init_cmds(BTS_NODE);
}

