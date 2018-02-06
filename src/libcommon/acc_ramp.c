/* (C) 2018 Stefan Sperling <ssperling@sysmocom.de>
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

#include <assert.h>
#include <strings.h>
#include <errno.h>

#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/acc_ramp.h>
#include <osmocom/bsc/gsm_data.h>

static void deny_all_accs(struct acc_ramp *acc_ramp)
{
	LOGP(DRLL, LOGL_DEBUG, "(bts=%d) ACC RAMP: denying all Access Control Classes 0-9\n", acc_ramp->bts->nr);
	acc_ramp->barred_t2 = 0x03; /* ACC8, ACC9 barred */
	acc_ramp->barred_t3 = 0xff; /* ACC0 - ACC7 barred */
}

static void allow_all_accs(struct acc_ramp *acc_ramp)
{
	LOGP(DRLL, LOGL_DEBUG, "(bts=%d) ACC RAMP: allowing all Access Control Classes 0-9\n", acc_ramp->bts->nr);
	acc_ramp->barred_t2 = 0x00; /* ACC8, ACC9 allowed */
	acc_ramp->barred_t3 = 0x00; /* ACC0 - ACC7 allowed */
}

static void allow_one_acc(struct acc_ramp *acc_ramp, unsigned int acc)
{
	LOGP(DRLL, LOGL_DEBUG, "(bts=%d) ACC RAMP: allowing Access Control Class %u\n", acc_ramp->bts->nr, acc);
	assert(acc >= 0 && acc <= 9);
	if (acc == 8 || acc == 9)
		acc_ramp->barred_t2 &= (1 << (acc - 8));
	else
		acc_ramp->barred_t3 &= (1 << acc);
}

static unsigned int get_next_step_interval(struct acc_ramp *acc_ramp)
{
	struct gsm_bts *bts = acc_ramp->bts;

	if (acc_ramp->step_interval_is_fixed)
		return acc_ramp->step_interval_sec;

	if (bts->chan_load_avg == 0) {
		acc_ramp->step_interval_sec = ACC_RAMP_STEP_INTERVAL_MIN;
	} else {
		/* Scale the step interval to current channel load average. */
		uint64_t load = (bts->chan_load_avg << 8); /* convert to fixed-point */
		acc_ramp->step_interval_sec = ((load * ACC_RAMP_STEP_INTERVAL_MAX) / 100) >> 8;
		if (acc_ramp->step_interval_sec < ACC_RAMP_STEP_SIZE_MIN)
			acc_ramp->step_interval_sec = ACC_RAMP_STEP_INTERVAL_MIN;
		else if (acc_ramp->step_interval_sec > ACC_RAMP_STEP_INTERVAL_MAX)
			acc_ramp->step_interval_sec = ACC_RAMP_STEP_INTERVAL_MAX;
	}

	LOGP(DRLL, LOGL_DEBUG, "(bts=%d) ACC RAMP: step interval set to %u sec based on %u%% load average\n",
	     bts->nr, acc_ramp->step_interval_sec, bts->chan_load_avg);
	return acc_ramp->step_interval_sec;
}

static void do_ramp_step(void *data)
{
	struct acc_ramp *acc_ramp = data;
	int i;

	/* Shortcut in case we only do one ramping step. */
	if (acc_ramp->step_size == ACC_RAMP_STEP_SIZE_MAX) {
		allow_all_accs(acc_ramp);
		return;
	}

	/* Allow 'step_size' ACCs, starting from ACC0. ACC9 will be allowed last. */
	for (i = 0; i < acc_ramp->step_size; i++) {
		int c = ffs(acc_ramp->barred_t3);
		if (c <= 0) {
			c = ffs(acc_ramp->barred_t2);
			if (c == 1 || c == 2) /* ACC8 or ACC9 */
				allow_one_acc(acc_ramp, c - 1 + 8);
			else
				break; /* all ACCs are now allowed */
		} else
			allow_one_acc(acc_ramp, c - 1); /* ACC0-ACC7 */
	}

	/* If we have not allowed all ACCs yet, schedule another ramping step. */
	if (acc_ramp_get_barred_t2(acc_ramp) != 0x00 ||
	    acc_ramp_get_barred_t3(acc_ramp) != 0x00)
		osmo_timer_schedule(&acc_ramp->step_timer, get_next_step_interval(acc_ramp), 0);
}

void acc_ramp_init(struct acc_ramp *acc_ramp, struct gsm_bts *bts)
{
	acc_ramp->bts = bts;
	allow_all_accs(acc_ramp);
	acc_ramp->step_size = ACC_RAMP_STEP_SIZE_DEFAULT;
	acc_ramp->step_interval_sec = ACC_RAMP_STEP_INTERVAL_DEFAULT;
	acc_ramp->step_interval_is_fixed = false;
	osmo_timer_setup(&acc_ramp->step_timer, do_ramp_step, acc_ramp);
}

int acc_ramp_set_step_size(struct acc_ramp *acc_ramp, enum acc_ramp_step_size step_size)
{
	if (step_size < ACC_RAMP_STEP_SIZE_MIN || step_size > ACC_RAMP_STEP_SIZE_MAX)
		return -ERANGE;

	acc_ramp->step_size = step_size;
	return 0;
}

int acc_ramp_set_step_interval(struct acc_ramp *acc_ramp, unsigned int step_interval)
{
	if (step_interval < ACC_RAMP_STEP_INTERVAL_MIN || step_interval > ACC_RAMP_STEP_INTERVAL_MAX)
		return -ERANGE;

	acc_ramp->step_interval_sec = step_interval;
	acc_ramp->step_interval_is_fixed = true;
	return 0;
}

void acc_ramp_set_step_interval_dynamic(struct acc_ramp *acc_ramp)
{
	acc_ramp->step_interval_is_fixed = false;
}

void acc_ramp_start(struct acc_ramp *acc_ramp)
{
	/* Abort any previously running ramping process. */
	acc_ramp_abort(acc_ramp);

	/* Set all ACCs to denied and start ramping up. */
	deny_all_accs(acc_ramp);
	do_ramp_step(acc_ramp);
}

void acc_ramp_abort(struct acc_ramp *acc_ramp)
{
	if (osmo_timer_pending(&acc_ramp->step_timer))
		osmo_timer_del(&acc_ramp->step_timer);
}
