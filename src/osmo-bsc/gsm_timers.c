/* Implementation to define Tnnn timers globally and use for FSM state changes. */
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

#include <osmocom/core/fsm.h>

#include <osmocom/bsc/gsm_timers.h>

/* a = return_val * b. Return 0 if factor is below 1. */
static int T_factor(enum T_unit a, enum T_unit b)
{
	if (b == a
	    || b == T_CUSTOM || a == T_CUSTOM)
		return 1;

	switch (b) {
	case T_MS:
		switch (a) {
		case T_S:
			return 1000;
		case T_M:
			return 60*1000;
		default:
			return 0;
		}
	case T_S:
		switch (a) {
		case T_M:
			return 60;
		default:
			return 0;
		}
	default:
		return 0;
	}
}

static int T_round(int val, enum T_unit from_unit, enum T_unit to_unit)
{
	int f;
	if (!val)
		return 0;

	f = T_factor(from_unit, to_unit);
	if (f < 1) {
		f = T_factor(to_unit, from_unit);
		return (val / f) + (val % f? 1 : 0);
	}
	return val * f;
}

/* Return the value of a T timer from a list of T_defs.
 * Any value is rounded up to match as_unit: 1100 ms as T_S becomes 2 seconds, as T_M becomes one minute.
 * If no such timer is defined, return the default value passed, or abort the program if default < 0.
 *
 * Usage examples:
 *
 * - Initialization:
 *
 * 	struct T_def global_T_defs[] = {
 * 		{ .T=7, .default_val=50, .desc="Water Boiling Timeout" },  // default is .unit=T_S == 0
 * 		{ .T=8, .default_val=300, .desc="Tea brewing" },
 * 		{ .T=9, .default_val=5, .unit=T_M, .desc="Let tea cool down before drinking" },
 * 		{ .T=10, .default_val=20, .unit=T_M, .desc="Forgot to drink tea while it's warm" },
 * 		{}  //  <-- important! last entry shall be zero
 * 	};
 * 	T_defs_reset(global_T_defs); // make all values the default
 * 	T_defs_vty_init(global_T_defs, CONFIG_NODE);
 *
 * 	val = T_def_get(global_T_defs, 7, T_S, -1); // -> 50
 * 	sleep(val);
 *
 * 	val = T_def_get(global_T_defs, 7, T_M, -1); // 50 seconds becomes 1 minute -> 1
 * 	sleep_minutes(val);
 *
 * 	val = T_def_get(global_T_defs, 99, T_S, -1); // not defined, program aborts!
 *
 * 	val = T_def_get(global_T_defs, 99, T_S, 3); // not defined, returns 3
 */
int T_def_get(struct T_def *T_defs, int T, enum T_unit as_unit, int val_if_not_present)
{
	struct T_def *d = T_def_get_entry(T_defs, T);
	if (!d) {
		OSMO_ASSERT(val_if_not_present >= 0);
		return val_if_not_present;
	}
	return T_round(d->val, d->unit, as_unit);
}

/* Set all T_def values to the default_val. */
void T_defs_reset(struct T_def *T_defs)
{
	struct T_def *d;
	for_each_T_def(d, T_defs)
		d->val = d->default_val;
}

/* Return a pointer to a T_def from an array, or NULL. */
struct T_def *T_def_get_entry(struct T_def *T_defs, int T)
{
	struct T_def *d;
	for_each_T_def(d, T_defs) {
		if (d->T == T)
			return d;
	}
	return NULL;
}

/* Return a state_timeout entry from an array, or return NULL if the entry is zero.
 *
 * The timeouts_array shall contain exactly 32 elements, which corresponds to the number of states
 * allowed by osmo_fsm_*. Lookup is by array index.
 *
 * For example:
 * 	struct state_timeout my_fsm_timeouts[32] = {
 * 		[MY_FSM_STATE_3] = { .T = 423 },
 * 		[MY_FSM_STATE_7] = { .T = 235 },
 * 		[MY_FSM_STATE_8] = { .keep_timer = true },
 * 		// any state that is omitted will remain zero == no timeout
 *	};
 *	get_state_timeout(MY_FSM_STATE_0, &my_fsm_timeouts) -> NULL,
 *	get_state_timeout(MY_FSM_STATE_7, &my_fsm_timeouts) -> { .T = 235 }
 *
 * The intention is then to obtain the timer like T_def_get(global_T_defs, T=235); see also
 * fsm_inst_state_chg_T() below.
 */
struct state_timeout *get_state_timeout(uint32_t state, struct state_timeout *timeouts_array)
{
	struct state_timeout *t;
	OSMO_ASSERT(state < 32);
	t = &timeouts_array[state];
	if (!t->keep_timer && !t->T)
		return NULL;
	return t;
}

/* Call osmo_fsm_inst_state_chg() or osmo_fsm_inst_state_chg_keep_timer(), depending on the T value
 * defined for this state in the timeouts_array, and obtaining the actual timeout value from T_defs.
 * A T timer configured in sub-second precision is rounded up to the next full second.
 *
 * See get_state_timeout() and T_def_get().
 *
 * Should a T number be defined in timeouts_array that is not defined in T_defs, use default_timeout.
 * This is best used by wrapping this function call in a macro suitable for a specific FSM
 * implementation, which can become as short as: my_fsm_state_chg(fi, NEXT_STATE):
 *
 * #define my_fsm_state_chg(fi, NEXT_STATE) \
 * 	fsm_inst_state_chg_T(fi, NEXT_STATE, my_fsm_timeouts, global_T_defs, 5)
 *
 * my_fsm_state_chg(fi, MY_FSM_STATE_1);
 * // -> No timeout configured, will enter state without timeout.
 *
 * my_fsm_state_chg(fi, MY_FSM_STATE_3);
 * // T423 configured for this state, will look up T423 in T_defs, or use 5 seconds if unset.
 *
 * my_fsm_state_chg(fi, MY_FSM_STATE_8);
 * // keep_timer configured for this state, will invoke osmo_fsm_inst_state_chg_keep_timer().
 *
 */
int _fsm_inst_state_chg_T(struct osmo_fsm_inst *fi, uint32_t state,
			  struct state_timeout *timeouts_array,
			  struct T_def *T_defs, int default_timeout,
			  const char *file, int line)
{
	struct state_timeout *t = get_state_timeout(state, timeouts_array);
	int val;

	/* No timeout defined for this state? */
	if (!t)
		return _osmo_fsm_inst_state_chg(fi, state, 0, 0, file, line);

	if (t->keep_timer) {
		int rc = _osmo_fsm_inst_state_chg_keep_timer(fi, state, file, line);
		if (t->T && !rc)
			fi->T = t->T;
		return rc;
	}

	val = T_def_get(T_defs, t->T, T_S, default_timeout);
	return _osmo_fsm_inst_state_chg(fi, state, val, t->T, file, line);
}

const struct value_string T_unit_names[] = {
	{ T_S, "s" },
	{ T_MS, "ms" },
	{ T_CUSTOM, "(custom)" },
	{ 0, NULL }
};
