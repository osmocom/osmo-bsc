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

/*
 * Check if an ACC has been permanently barred for a BTS,
 * e.g. with the 'rach access-control-class' VTY command.
 */
static bool bts_allows_acc(struct gsm_bts *bts, unsigned int acc)
{
	assert(acc >= 0 && acc <= 9);
	if (acc == 8 || acc == 9)
		return (bts->si_common.rach_control.t2 & (1 << (acc - 8))) == 0;
	return (bts->si_common.rach_control.t3 & (1 << (acc))) == 0;
}

static void allow_one_acc(struct acc_ramp *acc_ramp, unsigned int acc)
{
	assert(acc >= 0 && acc <= 9);
	LOGP(DRLL, LOGL_DEBUG, "(bts=%d) ACC RAMP: allowing Access Control Class %u\n", acc_ramp->bts->nr, acc);
	if (acc == 8 || acc == 9)
		acc_ramp->barred_t2 &= ~(1 << (acc - 8));
	else
		acc_ramp->barred_t3 &= ~(1 << acc);
}

static void barr_one_acc(struct acc_ramp *acc_ramp, unsigned int acc)
{
	assert(acc >= 0 && acc <= 9);
	LOGP(DRLL, LOGL_DEBUG, "(bts=%d) ACC RAMP: barring Access Control Class %u\n", acc_ramp->bts->nr, acc);
	if (acc == 8 || acc == 9)
		acc_ramp->barred_t2 |= (1 << (acc - 8));
	else
		acc_ramp->barred_t3 |= (1 << acc);
}

static void barr_all_allowed_accs(struct acc_ramp *acc_ramp)
{
	unsigned int acc;
	for (acc = 0; acc < 10; acc++) {
		if (bts_allows_acc(acc_ramp->bts, acc))
			barr_one_acc(acc_ramp, acc);
	}
}

static void allow_all_allowed_accs(struct acc_ramp *acc_ramp)
{
	unsigned int acc;
	for (acc = 0; acc < 10; acc++) {
		if (bts_allows_acc(acc_ramp->bts, acc))
			allow_one_acc(acc_ramp, acc);
	}
}

static unsigned int get_next_step_interval(struct acc_ramp *acc_ramp)
{
	struct gsm_bts *bts = acc_ramp->bts;

	if (acc_ramp->step_interval_is_fixed)
		return acc_ramp->step_interval_sec;

	if (bts->chan_load_avg == 0) {
		acc_ramp->step_interval_sec = ACC_RAMP_STEP_INTERVAL_DEFAULT;
	} else {
		/* Scale the step interval to current channel load average. */
		uint64_t load = (bts->chan_load_avg << 8); /* convert to fixed-point */
		acc_ramp->step_interval_sec = ((load * ACC_RAMP_STEP_INTERVAL_MAX) / 100) >> 8;
		if (acc_ramp->step_interval_sec < ACC_RAMP_STEP_SIZE_MIN)
			acc_ramp->step_interval_sec = ACC_RAMP_STEP_INTERVAL_MIN;
		else if (acc_ramp->step_interval_sec > ACC_RAMP_STEP_INTERVAL_MAX)
			acc_ramp->step_interval_sec = ACC_RAMP_STEP_INTERVAL_MAX;
	}

	LOGP(DRLL, LOGL_DEBUG, "(bts=%d) ACC RAMP: step interval set to %u seconds based on %u%% channel load average\n",
	     bts->nr, acc_ramp->step_interval_sec, bts->chan_load_avg);
	return acc_ramp->step_interval_sec;
}

static void send_bts_system_info(struct gsm_bts *bts)
{
	struct gsm_bts_trx *trx;

	/* Send updated system information to all TRX. */
	llist_for_each_entry_reverse(trx, &bts->trx_list, list)
		gsm_bts_trx_set_system_infos(trx);
}

static void do_ramping_step(void *data)
{
	struct acc_ramp *acc_ramp = data;
	int i;

	/* Shortcut in case we only do one ramping step. */
	if (acc_ramp->step_size == ACC_RAMP_STEP_SIZE_MAX) {
		allow_all_allowed_accs(acc_ramp);
		send_bts_system_info(acc_ramp->bts);
		return;
	}

	/* Allow 'step_size' ACCs, starting from ACC0. ACC9 will be allowed last. */
	for (i = 0; i < acc_ramp->step_size; i++) {
		int idx = ffs(acc_ramp->barred_t3);
		if (idx > 0) {
			unsigned int acc = idx - 1;
			/* one of ACC0-ACC7 is still bared */
			if (bts_allows_acc(acc_ramp->bts, acc))
				allow_one_acc(acc_ramp, acc);
		} else {
			idx = ffs(acc_ramp->barred_t2);
			if (idx == 1 || idx == 2) {
				unsigned int acc = idx - 1 + 8;
				/* ACC8 or ACC9 is still barred */
				if (bts_allows_acc(acc_ramp->bts, acc))
					allow_one_acc(acc_ramp, acc);
			} else {
				/* all ACCs are now allowed */
				break;
			}
		}
	}

	send_bts_system_info(acc_ramp->bts);

	/* If we have not allowed all ACCs yet, schedule another ramping step. */
	if (acc_ramp_get_barred_t2(acc_ramp) != 0x00 ||
	    acc_ramp_get_barred_t3(acc_ramp) != 0x00)
		osmo_timer_schedule(&acc_ramp->step_timer, get_next_step_interval(acc_ramp), 0);
}

void acc_ramp_init(struct acc_ramp *acc_ramp, struct gsm_bts *bts)
{
	acc_ramp->bts = bts;
	acc_ramp->step_size = ACC_RAMP_STEP_SIZE_DEFAULT;
	acc_ramp->step_interval_sec = ACC_RAMP_STEP_INTERVAL_DEFAULT;
	acc_ramp->step_interval_is_fixed = false;
	osmo_timer_setup(&acc_ramp->step_timer, do_ramping_step, acc_ramp);

	if (bts->acc_ramping_enabled)
		barr_all_allowed_accs(acc_ramp);
	else
		allow_all_allowed_accs(acc_ramp);
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

	/* Set all availble ACCs to barred and start ramping up. */
	barr_all_allowed_accs(acc_ramp);
	do_ramping_step(acc_ramp);
}

void acc_ramp_abort(struct acc_ramp *acc_ramp)
{
	if (osmo_timer_pending(&acc_ramp->step_timer))
		osmo_timer_del(&acc_ramp->step_timer);
}
