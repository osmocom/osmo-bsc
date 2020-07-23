/* (C) 2018 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 *
 * Author: Stefan Sperling <ssperling@sysmocom.de>
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

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <osmocom/core/timer.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>

#define ACC_MGR_QUANTUM_DEFAULT 20	/* 20 seconds */

/* Manage rotating subset of allowed Access Class as per configuration */
struct acc_mgr {
	struct gsm_bts *bts; /*!< backpointer to BTS using this ACC manager */
	/* Administrative Maximum Number of ACC 0-9 to be allowed at the same time.
	   Configurable through VTY cmd "access-control-class-roundrobin",
	   defaults to all allowed (10) */
	uint8_t len_allowed_adm;
	/* Further limiting the number of ACC to use. It may be lower due
	   to ramping, based for instance on channel or system load. */
	uint8_t len_allowed_ramp;

	/* Time until next subset is generated */
	uint32_t rotation_time_sec;
	struct osmo_timer_list rotate_timer;

	/* Bitmask containing subset of allowed ACC 0-9 on current rotation iteration */
	uint16_t allowed_subset_mask;
	/* Number of bits (ACC) set in allowed_subset_mask: 0->min(len_allowed_ramp, len_allowed_adm) */
	uint8_t allowed_subset_mask_count;
	/* Number of ACC 0-9 allowed as per adminsitrative (permanent) config. */
	uint8_t allowed_permanent_count;
};

void acc_mgr_init(struct acc_mgr *acc_mgr, struct gsm_bts *bts);
uint8_t acc_mgr_get_len_allowed_adm(struct acc_mgr *acc_mgr);
uint8_t acc_mgr_get_len_allowed_ramp(struct acc_mgr *acc_mgr);
void acc_mgr_set_len_allowed_adm(struct acc_mgr *acc_mgr, uint8_t len_allowed_adm);
void acc_mgr_set_len_allowed_ramp(struct acc_mgr *acc_mgr, uint8_t len_allowed_ramp);
void acc_mgr_set_rotation_time(struct acc_mgr *acc_mgr, uint32_t rotation_time_sec);
void acc_mgr_perm_subset_changed(struct acc_mgr *acc_mgr, struct gsm48_rach_control *rach_control);
void acc_mgr_apply_acc(struct acc_mgr *acc_mgr, struct gsm48_rach_control *rach_control);

/*!
 * Access control class (ACC) ramping is used to slowly make the cell available to
 * an increasing number of MS. This avoids overload at startup time in cases where
 * a lot of MS would discover the new cell and try to connect to it all at once.
 */

#define ACC_RAMP_STEP_SIZE_MIN 1 /* allow at most 1 new ACC per ramp step */
#define ACC_RAMP_STEP_SIZE_DEFAULT ACC_RAMP_STEP_SIZE_MIN
#define ACC_RAMP_STEP_SIZE_MAX 10 /* allow all ACC in one step (effectively disables ramping) */

#define ACC_RAMP_STEP_INTERVAL_MIN 5	/* 5 seconds */
#define ACC_RAMP_STEP_INTERVAL_MAX 600	/* 10 minutes */

#define ACC_RAMP_CHAN_LOAD_THRESHOLD_LOW 71
#define ACC_RAMP_CHAN_LOAD_THRESHOLD_UP 89

/*!
 * Data structure used to manage ACC ramping. Please avoid setting or reading fields
 * in this structure directly. Use the accessor functions below instead.
 */
struct acc_ramp {
	struct gsm_bts *bts; /*!< backpointer to BTS using this ACC ramp */

	bool acc_ramping_enabled; /*!< whether ACC ramping is enabled */

	/*!
	 * This controls the maximum number of ACCs to allow per ramping step (1 - 10).
	 * The compile-time default value is ACC_RAMP_STEP_SIZE_DEFAULT.
	 * This value can be changed by VTY configuration.
	 * A value of ACC_RAMP_STEP_SIZE_MAX effectively disables ramping.
	 */
	unsigned int step_size;

	/*!
	 * Ramping step interval in seconds.
	 * This value depends on the current BTS channel load average, unless
	 * it has been overridden by VTY configuration.
	 */
	unsigned int step_interval_sec;
	struct osmo_timer_list step_timer;

	/*!
	* Channel Load Upper/Lower Thresholds:
	* They control how ramping subset size of allowed ACCs changes in
	* relation to current channel load (%, 0-100): Under the lower
	* threshold, subset size may be increased; above the upper threshold,
	* subset size may be decreased.
	*/
	unsigned int chan_load_lower_threshold;
	unsigned int chan_load_upper_threshold;
};

/*!
 * Enable or disable ACC ramping.
 * When enabled, ramping begins once acc_ramp_start() is called.
 * When disabled, an ACC ramping process in progress will continue
 * unless acc_ramp_abort() is called as well.
 * \param[in] acc_ramp Pointer to acc_ramp structure.
 */
static inline void acc_ramp_set_enabled(struct acc_ramp *acc_ramp, bool enable)
{
	acc_ramp->acc_ramping_enabled = enable;
}

/*!
 * Return true if ACC ramping is currently enabled, else false.
 * \param[in] acc_ramp Pointer to acc_ramp structure.
 */
static inline bool acc_ramp_is_enabled(struct acc_ramp *acc_ramp)
{
	return acc_ramp->acc_ramping_enabled;
}

/*!
 * Return the current ACC ramp step size.
 * \param[in] acc_ramp Pointer to acc_ramp structure.
 */
static inline unsigned int acc_ramp_get_step_size(struct acc_ramp *acc_ramp)
{
	return acc_ramp->step_size;
}

/*!
 * Return the current ACC ramp step interval (in seconds)
 * \param[in] acc_ramp Pointer to acc_ramp structure.
 */
static inline unsigned int acc_ramp_get_step_interval(struct acc_ramp *acc_ramp)
{
	return acc_ramp->step_interval_sec;
}

/*!
 * Return the current ACC ramp step interval (in seconds)
 * \param[in] acc_ramp Pointer to acc_ramp structure.
 */
static inline unsigned int acc_ramp_is_running(struct acc_ramp *acc_ramp)
{
	return acc_ramp->step_interval_sec;
}

void acc_ramp_init(struct acc_ramp *acc_ramp, struct gsm_bts *bts);
int acc_ramp_set_step_size(struct acc_ramp *acc_ramp, unsigned int step_size);
int acc_ramp_set_step_interval(struct acc_ramp *acc_ramp, unsigned int step_interval);
int acc_ramp_set_chan_load_thresholds(struct acc_ramp *acc_ramp, unsigned int low_threshold, unsigned int up_threshold);
void acc_ramp_trigger(struct acc_ramp *acc_ramp);
void acc_ramp_abort(struct acc_ramp *acc_ramp);
