/* Implementation to configure Tnnn timers in VTY */
/* (C) 2018 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 *
 * Author: Neels Hofmeyr <neels@hofmeyr.de>
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

#include <string.h>

#include <osmocom/vty/vty.h>
#include <osmocom/vty/command.h>

#include <osmocom/bsc/gsm_timers.h>

/* Global singleton list used for the VTY configuration. See T_defs_vty_init(). */
static struct T_def *g_vty_T_defs = NULL;

/* Parse an argument like "T1234", "t1234" or "1234" and return the corresponding T_def entry from
 * g_vty_T_defs, if any. */
static struct T_def *parse_T_arg(struct vty *vty, const char *T_str)
{
	int T;
	struct T_def *d;

	if (T_str[0] == 't' || T_str[0] == 'T')
		T_str++;
	T = atoi(T_str);

	d = T_def_get_entry(g_vty_T_defs, T);
	if (!d)
		vty_out(vty, "No such timer: T%d%s", T, VTY_NEWLINE);
	return d;
}

/* Installed in the VTY on T_defs_vty_init(). */
DEFUN(cfg_timer, cfg_timer_cmd,
      "timer TNNNN (default|<1-65535>)",
      "Configure GSM Timers\n"
      "T-number, optionally preceded by 't' or 'T'."
      "See also 'show timer' for a list of available timers.\n"
      "Set to default timer value\n" "Timer value\n")
{
	const char *val_str = argv[1];
	struct T_def *d;

	d = parse_T_arg(vty, argv[0]);
	if (!d)
		return CMD_WARNING;

	if (!strcmp(val_str, "default"))
		d->val = d->default_val;
	else
		d->val = atoi(val_str);
	vty_out(vty, "T%d = %u %s (%s)%s", d->T, d->val, T_unit_name(d->unit), d->desc, VTY_NEWLINE);
	return CMD_SUCCESS;
}

/* Print a T_def to the VTY. */
static void show_one_timer(struct vty *vty, struct T_def *d)
{
	vty_out(vty, "T%d = %u %s (default = %u %s) \t%s%s",
		d->T, d->val, T_unit_name(d->unit),
		d->default_val, T_unit_name(d->unit), d->desc, VTY_NEWLINE);
}

/* Installed in the VTY on T_defs_vty_init(). */
DEFUN(show_timer, show_timer_cmd,
      "show timer [TNNNN]",
      SHOW_STR "GSM Timers\n"
      "Specific timer to show, or all timers if omitted.\n")
{
	struct T_def *d;

	if (argc) {
		d = parse_T_arg(vty, argv[0]);
		if (!d)
			return CMD_WARNING;
		show_one_timer(vty, d);
		return CMD_SUCCESS;
	}

	for_each_T_def(d, g_vty_T_defs)
		show_one_timer(vty, d);
	return CMD_SUCCESS;
}

/* Install GSM timer configuration commands in the VTY. */
void T_defs_vty_init(struct T_def *T_defs, int cfg_parent_node)
{
	g_vty_T_defs = T_defs;
	install_element_ve(&show_timer_cmd);
	install_element(cfg_parent_node, &cfg_timer_cmd);
}

/* Write GSM timer configuration to the vty. */
void T_defs_vty_write(struct vty *vty, const char *indent)
{
	struct T_def *d;
	for_each_T_def(d, g_vty_T_defs) {
		if (d->val != d->default_val)
			vty_out(vty, "%stimer t%d %u%s", indent, d->T, d->val, VTY_NEWLINE);
	}
}
