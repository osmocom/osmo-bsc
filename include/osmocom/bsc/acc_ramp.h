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

#ifndef _ACC_RAMP_H_
#define _ACC_RAMP_H_

#include <stdbool.h>
#include <stdint.h>

#include <osmocom/core/timer.h>

/*
 * Access control class (ACC) ramping is used to slowly make the cell available to
 * an increasing number of MS. This avoids overload at startup time in cases where
 * a lot of MS would discover the new cell and try to connect to it all at once.
 */

enum acc_ramp_step_size {
	ACC_RAMP_STEP_SIZE_MIN = 1, /* allow at most 1 new ACC per ramp step */
	ACC_RAMP_STEP_SIZE_DEFAULT = ACC_RAMP_STEP_SIZE_MIN,
	ACC_RAMP_STEP_SIZE_MAX = 10, /* allow all ACC in one step (disables ramping) */
};

enum acc_ramp_step_interval {
	ACC_RAMP_STEP_INTERVAL_MIN = 30,	/* 30 seconds */
	ACC_RAMP_STEP_INTERVAL_DEFAULT = 60,	/* 1 minute */
	ACC_RAMP_STEP_INTERVAL_MAX = 600,	/* 10 minutes */
};

struct acc_ramp {
	struct gsm_bts *bts; /* backpointer to BTS using this ACC ramp */

	/*
	 * Bitmasks which keep track of access control classes that are currently denied
	 * access. These masks should be used to modulate bits from octets 2 and 3 of
	 * the RACH Control Parameters (see 3GPP 44.018 10.5.2.29).
	 * While a bit in these masks is set, the corresponding ACC is barred.
	 * Note that t2 contains bits for classes 11-15 which should always be allowed,
	 * and a bit which denies emergency calls for all ACCs from 0-9 inclusive.
	 * Ramping is only concerned with those bits which control access for ACCs 0-9.
	 */
	uint8_t barred_t2;
	uint8_t barred_t3;

	/*
	 * This controls the maximum number of ACCs to allow per ramping step (1 - 10).
	 * The compile-time default value is ACC_RAMP_STEP_SIZE_DEFAULT.
	 * This value can be changed by VTY configuration.
	 * A value of ACC_RAMP_STEP_SIZE_MAX effectively disables ramping.
	 */
	enum acc_ramp_step_size step_size;

	/*
	 * Ramping step interval in seconds.
	 * This value depends on the current BTS channel load average, unless
	 * it has been overriden by VTY configuration.
	 */
	unsigned int step_interval_sec;
	bool step_interval_is_fixed;
	struct osmo_timer_list step_timer;
};

/*
 * Initialize the acc_ramp data structure.
 * Storage for this structure must be provided by the caller.
 *
 * The BTS which uses this ACC ramp must be provided as well.
 *
 * If 'bts->acc_ramping_enabled' is true, all ACCs are denied by default.
 * A subsequent call to acc_ramp_start() will begin the ramping process.
 *
 * If 'bts->acc_ramping_enabled' is false, all ACCs will be allowed by default,
 * and there is no need to do anything else.
 */
void acc_ramp_init(struct acc_ramp *acc_ramp, struct gsm_bts *bts);

/* Change the ramping step size. Returns negative on error (step_size out of range), else zero. */
int acc_ramp_set_step_size(struct acc_ramp *acc_ramp, enum acc_ramp_step_size step_size);

/*
 * Change the ramping step interval to a fixed value. Unless this function is called,
 * the interval is automatically scaled to the BTS channel load average.
 */
int acc_ramp_set_step_interval(struct acc_ramp *acc_ramp, unsigned int step_interval);

/*
 * Clear a previously set fixed ramping step interval, so that the interval
 * is again automatically scaled to the BTS channel load average.
 */
void acc_ramp_set_step_interval_dynamic(struct acc_ramp *acc_ramp);

/*
 * Begin the ramping process. This initially sets all ACCs to denied, and then
 * performs at least one ramping step to allow 'step_size' ACCs.
 * If 'step_size' is ACC_RAMP_STEP_SIZE_MAX, all ACCs will be allowed immediately,
 * i.e. ACC ramping becomes a no-op.
 */
void acc_ramp_start(struct acc_ramp *acc_ramp);

/* Abort the ramping process. If the process has already finished, this function has no effect. */
void acc_ramp_abort(struct acc_ramp *acc_ramp);

/*
 * Return bitmasks which correspond to access control classes which are currently
 * denied access. Ramping is only concerned with those bits which control access
 * for ACCs 0-9, and any of the other bits will always be set to zero in these masks, i.e.
 * it is safe to OR these bitmasks with the corresponding fields in struct gsm48_rach_control.
 */
static inline uint8_t acc_ramp_get_barred_t2(struct acc_ramp *acc_ramp)
{
	return (acc_ramp->barred_t2 & 0x03);
};

static inline uint8_t acc_ramp_get_barred_t3(struct acc_ramp *acc_ramp)
{
	return acc_ramp->barred_t3;
}

#endif /* _ACC_RAMP_H_ */
