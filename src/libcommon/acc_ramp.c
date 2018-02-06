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

#include <osmocom/bsc/acc_ramp.h>

static void acc_ramp_timer_step(void *data)
{
	struct acc_ramp *acc_ramp = data;
}

void acc_ramp_init(struct acc_ramp *acc_ramp)
{
	acc_ramp->barred_t2 = 0x03; /* AC8, AC9 barred */
	acc_ramp->barred_t3 = 0xff; /* AC0 - AC7 barred */

	acc_ramp->step_size = ACC_RAMP_STEP_SIZE_DEFAULT;
	acc_ramp->step_interval_sec = ACC_RAMP_STEP_INTERVAL_DEFAULT;
	acc_ramp->step_interval_is_fixed = false;
	osmo_timer_setup(&acc_ramp->step_timer, acc_ramp_timer_step, acc_ramp);
}

void acc_ramp_start(struct acc_ramp *acc_ramp)
{
	acc_ramp_stop(acc_ramp);
	osmo_timer_schedule(&acc_ramp->step_timer, acc_ramp->step_interval_sec, 0);
}

void acc_ramp_stop(struct acc_ramp *acc_ramp)
{
	if (osmo_timer_pending(&acc_ramp->step_timer))
		osmo_timer_del(&acc_ramp->step_timer);
}
