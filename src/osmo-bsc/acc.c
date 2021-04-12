/* (C) 2018-2020 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
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

#include <strings.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>
#include <stdbool.h>

#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/acc.h>
#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/chan_alloc.h>
#include <osmocom/bsc/signal.h>
#include <osmocom/bsc/abis_nm.h>
#include <osmocom/bsc/bts.h>

/*
 * Check if an ACC has been permanently barred for a BTS,
 * e.g. with the 'rach access-control-class' VTY command.
 */
static bool acc_is_permanently_barred(struct gsm_bts *bts, unsigned int acc)
{
	OSMO_ASSERT(acc <= 9);
	if (acc == 8 || acc == 9)
		return (bts->si_common.rach_control.t2 & (1 << (acc - 8)));
	return (bts->si_common.rach_control.t3 & (1 << (acc)));
}

/*!
 * Return bitmasks which correspond to access control classes that are currently
 * denied access. Ramping is only concerned with those bits which control access
 * for ACCs 0-9, and any of the other bits will always be set to zero in these masks, i.e.
 * it is safe to OR these bitmasks with the corresponding fields in struct gsm48_rach_control.
 * \param[in] acc_mgr Pointer to acc_mgr structure.
 */
static inline uint8_t acc_mgr_get_barred_t2(struct acc_mgr *acc_mgr)
{
	return ((~acc_mgr->allowed_subset_mask) >> 8) & 0x03;
};
static inline uint8_t acc_mgr_get_barred_t3(struct acc_mgr *acc_mgr)
{
	return (~acc_mgr->allowed_subset_mask) & 0xff;
}

static uint8_t acc_mgr_subset_len(struct acc_mgr *acc_mgr)
{
	return OSMO_MIN(acc_mgr->len_allowed_ramp, acc_mgr->len_allowed_adm);
}

static void acc_mgr_enable_rotation_cond(struct acc_mgr *acc_mgr)
{
	if (acc_mgr->allowed_permanent_count && acc_mgr->allowed_subset_mask_count &&
	    acc_mgr->allowed_permanent_count != acc_mgr->allowed_subset_mask_count) {
		if (!osmo_timer_pending(&acc_mgr->rotate_timer))
			osmo_timer_schedule(&acc_mgr->rotate_timer, acc_mgr->rotation_time_sec, 0);
	} else {
		/* No rotation needed, disable rotation timer */
		if (osmo_timer_pending(&acc_mgr->rotate_timer))
			osmo_timer_del(&acc_mgr->rotate_timer);
	}
}

static void acc_mgr_gen_subset(struct acc_mgr *acc_mgr, bool update_si)
{
	uint8_t acc;

	acc_mgr->allowed_subset_mask = 0; /* clean mask */
	acc_mgr->allowed_subset_mask_count = 0;
	acc_mgr->allowed_permanent_count = 0;

	for (acc = 0; acc < 10; acc++) {
		if (acc_is_permanently_barred(acc_mgr->bts, acc))
			continue;
		acc_mgr->allowed_permanent_count++;
		if (acc_mgr->allowed_subset_mask_count < acc_mgr_subset_len(acc_mgr)) {
			acc_mgr->allowed_subset_mask |= (1 << acc);
			acc_mgr->allowed_subset_mask_count++;
		}
	}

	acc_mgr_enable_rotation_cond(acc_mgr);

	LOG_BTS(acc_mgr->bts, DRSL, LOGL_INFO,
		"ACC: New ACC allowed subset 0x%03" PRIx16 " (active_len=%" PRIu8
		", ramp_len=%" PRIu8 ", adm_len=%" PRIu8 ", perm_len=%" PRIu8 ", rotation=%s)\n",
		acc_mgr->allowed_subset_mask, acc_mgr->allowed_subset_mask_count,
		acc_mgr->len_allowed_ramp, acc_mgr->len_allowed_adm,
		acc_mgr->allowed_permanent_count,
		osmo_timer_pending(&(acc_mgr)->rotate_timer) ? "on" : "off");

	/* Trigger SI data update, acc_mgr_apply_acc will bew called */
	if (update_si)
		gsm_bts_set_system_infos(acc_mgr->bts);
}

static uint8_t get_highest_allowed_acc(uint16_t mask)
{
	int i;

	for (i = 9; i >= 0; i--) {
		if (mask & (1 << i))
			return i;
	}
	OSMO_ASSERT(0);
	return 0;
}

static uint8_t get_lowest_allowed_acc(uint16_t mask)
{
	int i;

	for (i = 0; i < 10; i++) {
		if (mask & (1 << i))
			return i;
	}
	OSMO_ASSERT(0);
	return 0;
}

#define LOG_ACC_CHG(acc_mgr, level, old_mask, verb_str) \
	LOG_BTS((acc_mgr)->bts, DRSL, level, \
		"ACC: %s ACC allowed active subset 0x%03" PRIx16 " -> 0x%03" PRIx16 \
		" (active_len=%" PRIu8 ", ramp_len=%" PRIu8 ", adm_len=%" PRIu8 \
		", perm_len=%" PRIu8 ", rotation=%s)\n", \
		verb_str, old_mask, (acc_mgr)->allowed_subset_mask, \
		(acc_mgr)->allowed_subset_mask_count, \
		(acc_mgr)->len_allowed_ramp, (acc_mgr)->len_allowed_adm, \
		(acc_mgr)->allowed_permanent_count, \
		osmo_timer_pending(&(acc_mgr)->rotate_timer) ? "on" : "off")

/* Call when either adm_len or ramp_len changed (and values have been updated) */
static void acc_mgr_subset_length_changed(struct acc_mgr *acc_mgr)
{
	uint16_t old_mask = acc_mgr->allowed_subset_mask;
	uint8_t curr_len = acc_mgr->allowed_subset_mask_count;
	uint8_t new_len = acc_mgr_subset_len(acc_mgr);
	int8_t diff = new_len - curr_len;
	uint8_t i;

	if (curr_len == new_len)
		return;

	if (new_len == 0) {
		acc_mgr->allowed_subset_mask = 0;
		acc_mgr->allowed_subset_mask_count = 0;
		acc_mgr_enable_rotation_cond(acc_mgr);
		LOG_ACC_CHG(acc_mgr, LOGL_INFO, old_mask, "update");
		gsm_bts_set_system_infos(acc_mgr->bts);
		return;
	}

	if (curr_len == 0) {
		acc_mgr_gen_subset(acc_mgr, true);
		return;
	}

	/* Try to add new ACCs to the set starting from highest one (since we rotate rolling up) */
	if (diff > 0) { /* curr_len < new_len */
		uint8_t highest = get_highest_allowed_acc(acc_mgr->allowed_subset_mask);
		/* It's fine skipping highest in the loop since it's known to be already set: */
		for (i = (highest + 1) % 10; i != highest; i = (i + 1) % 10) {
			if (acc_is_permanently_barred(acc_mgr->bts, i))
				continue;
			if (acc_mgr->allowed_subset_mask & (1 << i))
				continue; /* already in set */
			acc_mgr->allowed_subset_mask |= (1 << i);
			acc_mgr->allowed_subset_mask_count++;
			diff--;
			if (diff == 0)
				break;
		}
	} else { /* curr_len > new_len, try removing from lowest one. */
		uint8_t lowest = get_lowest_allowed_acc(acc_mgr->allowed_subset_mask);
		i = lowest;
		do {
			if ((acc_mgr->allowed_subset_mask & (1 << i))) {
				acc_mgr->allowed_subset_mask &= ~(1 << i);
				acc_mgr->allowed_subset_mask_count--;
				diff++;
				if (diff == 0)
					break;
			}
			i = (i + 1) % 10;
		} while(i != lowest);
	}

	acc_mgr_enable_rotation_cond(acc_mgr);
	LOG_ACC_CHG(acc_mgr, LOGL_INFO, old_mask, "update");

	/* if we updated the set, notify about it */
	if (curr_len != acc_mgr->allowed_subset_mask_count)
		gsm_bts_set_system_infos(acc_mgr->bts);

}

/* Eg: (2,3,4) -> first=2; last=4. (3,7,8) -> first=3, last=8; (8,9,2) -> first=8, last=2 */
void get_subset_limits(struct acc_mgr *acc_mgr, uint8_t *first, uint8_t *last)
{
	uint8_t lowest = get_lowest_allowed_acc(acc_mgr->allowed_subset_mask);
	uint8_t highest = get_highest_allowed_acc(acc_mgr->allowed_subset_mask);
	/* check if there's unselected ACCs between lowest and highest, that
	 * means subset is wrapping around, eg: (8,9,1)
	 * Assumption: The permanent set is bigger than the current selected subset */
	bool is_wrapped = false;
	uint8_t i = (lowest + 1) % 10;
	if (lowest != highest) { /* len(allowed_subset_mask) > 1 */
		i = (lowest + 1) % 10;
		do {
			if (!acc_is_permanently_barred(acc_mgr->bts, i) &&
			    !(acc_mgr->allowed_subset_mask & (1 << i))) {
				is_wrapped = true;
				break;
			}
			i = (i + 1) % 10;
		} while (i != (highest + 1) % 10);
	}

	if (is_wrapped) {
		/* Assumption: "i" is pointing to the lowest dynamically barred ACC.
		   Example: 11 1000 00>0<1.  */
		*last = i - 1;
		while (acc_is_permanently_barred(acc_mgr->bts, *last))
			*last -= 1;
		*first = i + 1;
		while (acc_is_permanently_barred(acc_mgr->bts, *first) ||
		       !(acc_mgr->allowed_subset_mask & (1 << (*first))))
			*first += 1;
	} else {
		*first = lowest;
		*last = highest;
	}
}
static void do_acc_rotate_step(void *data)
{
	struct acc_mgr *acc_mgr = data;
	uint8_t i;
	uint8_t first, last;
	uint16_t old_mask = acc_mgr->allowed_subset_mask;

	/* Assumption: The size of the subset didn't change, that's handled by
	 * acc_mgr_subset_length_changed()
	 */

	/* Assumption: Rotation timer has been disabled if no ACC is allowed */
	OSMO_ASSERT(acc_mgr->allowed_subset_mask_count != 0);

	/* One ACC is rotated at a time: Drop first ACC and add next from last ACC */
	get_subset_limits(acc_mgr, &first, &last);

	acc_mgr->allowed_subset_mask &= ~(1 << first);
	i = (last + 1) % 10;
	do {
		if (!acc_is_permanently_barred(acc_mgr->bts, i) &&
		    !(acc_mgr->allowed_subset_mask & (1 << i))) {
			/* found first one which can be allowed, do it and be done */
			acc_mgr->allowed_subset_mask |= (1 << i);
			break;
		}
		i = (i + 1 ) % 10;
	} while (i != (last + 1) % 10);

	osmo_timer_schedule(&acc_mgr->rotate_timer, acc_mgr->rotation_time_sec, 0);

	if (old_mask != acc_mgr->allowed_subset_mask) {
		LOG_ACC_CHG(acc_mgr, LOGL_INFO, old_mask, "rotate");
		gsm_bts_set_system_infos(acc_mgr->bts);
	}
}

void acc_mgr_init(struct acc_mgr *acc_mgr, struct gsm_bts *bts)
{
	acc_mgr->bts = bts;
	acc_mgr->len_allowed_adm = 10; /* Allow all by default */
	acc_mgr->len_allowed_ramp = 10;
	acc_mgr->rotation_time_sec = ACC_MGR_QUANTUM_DEFAULT;
	osmo_timer_setup(&acc_mgr->rotate_timer, do_acc_rotate_step, acc_mgr);
	/* FIXME: Don't update SI yet, avoid crash due to bts->model being NULL */
	acc_mgr_gen_subset(acc_mgr, false);
}

uint8_t acc_mgr_get_len_allowed_adm(struct acc_mgr *acc_mgr)
{
	return acc_mgr->len_allowed_adm;
}

uint8_t acc_mgr_get_len_allowed_ramp(struct acc_mgr *acc_mgr)
{
	return acc_mgr->len_allowed_ramp;
}

void acc_mgr_set_len_allowed_adm(struct acc_mgr *acc_mgr, uint8_t len_allowed_adm)
{
	uint8_t old_len;

	OSMO_ASSERT(len_allowed_adm <= 10);

	if (acc_mgr->len_allowed_adm == len_allowed_adm)
		return;

	LOG_BTS(acc_mgr->bts, DRSL, LOGL_DEBUG,
		"ACC: administrative rotate subset size set to %" PRIu8 "\n", len_allowed_adm);

	old_len = acc_mgr_subset_len(acc_mgr);
	acc_mgr->len_allowed_adm = len_allowed_adm;
	if (old_len != acc_mgr_subset_len(acc_mgr))
		acc_mgr_subset_length_changed(acc_mgr);
}
void acc_mgr_set_len_allowed_ramp(struct acc_mgr *acc_mgr, uint8_t len_allowed_ramp)
{
	uint8_t old_len;

	OSMO_ASSERT(len_allowed_ramp <= 10);

	if (acc_mgr->len_allowed_ramp == len_allowed_ramp)
		return;

	LOG_BTS(acc_mgr->bts, DRSL, LOGL_DEBUG,
		"ACC: ramping rotate subset size set to %" PRIu8 "\n", len_allowed_ramp);

	old_len = acc_mgr_subset_len(acc_mgr);
	acc_mgr->len_allowed_ramp = len_allowed_ramp;
	if (old_len != acc_mgr_subset_len(acc_mgr))
		acc_mgr_subset_length_changed(acc_mgr);
}

void acc_mgr_set_rotation_time(struct acc_mgr *acc_mgr, uint32_t rotation_time_sec)
{
	LOG_BTS(acc_mgr->bts, DRSL, LOGL_DEBUG,
		"ACC: rotate subset time set to %" PRIu32 " seconds\n", rotation_time_sec);
	acc_mgr->rotation_time_sec = rotation_time_sec;
}

void acc_mgr_perm_subset_changed(struct acc_mgr *acc_mgr, struct gsm48_rach_control *rach_control)
{
	/* Even if amount is the same, the allowed/barred ones may have changed,
	 * so let's retrigger generation of an entire subset rather than
	 * rotating it */
	acc_mgr_gen_subset(acc_mgr, true);
}

/*!
 * Potentially mark certain Access Control Classes (ACCs) as barred in accordance to ACC policy.
 * \param[in] acc_mgr Pointer to acc_mgr structure.
 * \param[in] rach_control RACH control parameters in which barred ACCs will be configured.
 */
void acc_mgr_apply_acc(struct acc_mgr *acc_mgr, struct gsm48_rach_control *rach_control)
{
	rach_control->t2 |= acc_mgr_get_barred_t2(acc_mgr);
	rach_control->t3 |= acc_mgr_get_barred_t3(acc_mgr);
}


//////////////////////////
// acc_ramp
//////////////////////////
static void do_acc_ramping_step(void *data)
{
	struct acc_ramp *acc_ramp = data;
	struct gsm_bts *bts = acc_ramp->bts;
	struct acc_mgr *acc_mgr = &bts->acc_mgr;

	uint8_t old_len = acc_mgr_get_len_allowed_ramp(acc_mgr);
	uint8_t new_len = old_len;

	/* Remark dec: Never decrease back to 0, it is desirable to always allow at
	 * least 1 ACC at ramping lvl to allow subscribers to eventually use the
	 * network. If total barring is desired, it can be controlled by the
	 * adminsitrative subset length through VTY.
	 * Remark inc: Never try going over the admin subset size, since it
	 * wouldn't change final subset size anyway and it would create a fake
	 * sense of safe load handling capacity. If then load became high, being
	 * on upper size would mean the BTS requires more time to effectively
	 * drop down the final subset size, hence delaying recovery.
	 */
	if (bts->chan_load_avg > acc_ramp->chan_load_upper_threshold)
		new_len = (uint8_t)OSMO_MAX(1, (int)(old_len - acc_ramp->step_size));
	else if (bts->chan_load_avg < acc_ramp->chan_load_lower_threshold)
		new_len = OSMO_MIN(acc_mgr_get_len_allowed_adm(acc_mgr),
				   old_len + acc_ramp->step_size);
	else
		new_len = old_len;

	if (new_len != old_len) {
		LOG_BTS(bts, DRSL, LOGL_DEBUG,
			"ACC RAMP: changing ramping subset size %" PRIu8
			" -> %" PRIu8 ", chan_load_avg=%" PRIu8 "%%\n",
			old_len, new_len, bts->chan_load_avg);
		acc_mgr_set_len_allowed_ramp(acc_mgr, new_len);
	}

	osmo_timer_schedule(&acc_ramp->step_timer, acc_ramp->step_interval_sec, 0);
}

/* Implements osmo_signal_cbfn() -- trigger or abort ACC ramping upon changes RF lock state. */
static int acc_ramp_nm_sig_cb(unsigned int subsys, unsigned int signal, void *handler_data, void *signal_data)
{
	struct nm_statechg_signal_data *nsd = signal_data;
	struct acc_ramp *acc_ramp = handler_data;
	struct gsm_bts_trx *trx = NULL;
	bool trigger_ramping = false, abort_ramping = false;

	/* Handled signals map to an Administrative State Change ACK, or a State Changed Event Report. */
	if (signal != S_NM_STATECHG_ADM && signal != S_NM_STATECHG_OPER)
		return 0;

	if (nsd->obj_class != NM_OC_RADIO_CARRIER)
		return 0;

	trx = nsd->obj;

	LOG_TRX(trx, DRSL, LOGL_DEBUG, "ACC RAMP: administrative state %s -> %s\n",
	    get_value_string(abis_nm_adm_state_names, nsd->old_state->administrative),
	    get_value_string(abis_nm_adm_state_names, nsd->new_state->administrative));
	LOG_TRX(trx, DRSL, LOGL_DEBUG, "ACC RAMP: operational state %s -> %s\n",
	    abis_nm_opstate_name(nsd->old_state->operational),
	    abis_nm_opstate_name(nsd->new_state->operational));

	/* We only care about state changes of the first TRX. */
	if (trx->nr != 0)
		return 0;

	/* RSL must already be up. We cannot send RACH system information to the BTS otherwise. */
	if (trx->rsl_link_primary == NULL) {
		LOG_TRX(trx, DRSL, LOGL_DEBUG,
			"ACC RAMP: ignoring state change because RSL link is down\n");
		return 0;
	}

	/* Trigger or abort ACC ramping based on the new state of this TRX. */
	if (nsd->old_state->administrative != nsd->new_state->administrative) {
		switch (nsd->new_state->administrative) {
		case NM_STATE_UNLOCKED:
			if (nsd->old_state->operational != nsd->new_state->operational) {
				/*
				 * Administrative and operational state have both changed.
				 * Trigger ramping only if TRX 0 will be both enabled and unlocked.
				 */
				if (nsd->new_state->operational == NM_OPSTATE_ENABLED)
					trigger_ramping = true;
				else
					LOG_TRX(trx, DRSL, LOGL_DEBUG,
						"ACC RAMP: ignoring state change because TRX is "
						"transitioning into operational state '%s'\n",
						abis_nm_opstate_name(nsd->new_state->operational));
			} else {
				/*
				 * Operational state has not changed.
				 * Trigger ramping only if TRX 0 is already usable.
				 */
				if (trx_is_usable(trx))
					trigger_ramping = true;
				else
					LOG_TRX(trx, DRSL, LOGL_DEBUG, "ACC RAMP: ignoring state change "
						"because TRX is not usable\n");
			}
			break;
		case NM_STATE_LOCKED:
		case NM_STATE_SHUTDOWN:
			abort_ramping = true;
			break;
		case NM_STATE_NULL:
		default:
			LOG_TRX(trx, DRSL, LOGL_ERROR, "ACC RAMP: unrecognized administrative state '0x%x' "
				"reported for TRX 0\n", nsd->new_state->administrative);
			break;
		}
	}
	if (nsd->old_state->operational != nsd->new_state->operational) {
		switch (nsd->new_state->operational) {
		case NM_OPSTATE_ENABLED:
			if (nsd->old_state->administrative != nsd->new_state->administrative) {
				/*
				 * Administrative and operational state have both changed.
				 * Trigger ramping only if TRX 0 will be both enabled and unlocked.
				 */
				if (nsd->new_state->administrative == NM_STATE_UNLOCKED)
					trigger_ramping = true;
				else
					LOG_TRX(trx, DRSL, LOGL_DEBUG, "ACC RAMP: ignoring state change "
						"because TRX is transitioning into administrative state '%s'\n",
						get_value_string(abis_nm_adm_state_names, nsd->new_state->administrative));
			} else {
				/*
				 * Administrative state has not changed.
				 * Trigger ramping only if TRX 0 is already unlocked.
				 */
				if (trx->mo.nm_state.administrative == NM_STATE_UNLOCKED)
					trigger_ramping = true;
				else
					LOG_TRX(trx, DRSL, LOGL_DEBUG, "ACC RAMP: ignoring state change "
						"because TRX is in administrative state '%s'\n",
						get_value_string(abis_nm_adm_state_names, trx->mo.nm_state.administrative));
			}
			break;
		case NM_OPSTATE_DISABLED:
			abort_ramping = true;
			break;
		case NM_OPSTATE_NULL:
		default:
			LOG_TRX(trx, DRSL, LOGL_ERROR, "ACC RAMP: unrecognized operational state '0x%x' "
			     "reported for TRX 0\n", nsd->new_state->administrative);
			break;
		}
	}

	if (trigger_ramping)
		acc_ramp_trigger(acc_ramp);
	else if (abort_ramping)
		acc_ramp_abort(acc_ramp);

	return 0;
}

/*!
 * Initialize an acc_ramp data structure.
 * Storage for this structure must be provided by the caller.
 *
 * By default, ACC ramping is disabled and all ACCs are allowed.
 *
 * \param[in] acc_ramp Pointer to acc_ramp structure to be initialized.
 * \param[in] bts BTS which uses this ACC ramp data structure.
 */
void acc_ramp_init(struct acc_ramp *acc_ramp, struct gsm_bts *bts)
{
	acc_ramp->bts = bts;
	acc_ramp_set_enabled(acc_ramp, false);
	acc_ramp->step_size = ACC_RAMP_STEP_SIZE_DEFAULT;
	acc_ramp->step_interval_sec = ACC_RAMP_STEP_INTERVAL_MIN;
	acc_ramp->chan_load_lower_threshold = ACC_RAMP_CHAN_LOAD_THRESHOLD_LOW;
	acc_ramp->chan_load_upper_threshold = ACC_RAMP_CHAN_LOAD_THRESHOLD_UP;
	osmo_timer_setup(&acc_ramp->step_timer, do_acc_ramping_step, acc_ramp);
	osmo_signal_register_handler(SS_NM, acc_ramp_nm_sig_cb, acc_ramp);
}

/*!
 * Change the ramping step size which controls how many ACCs will be allowed per ramping step.
 * Returns negative on error (step_size out of range), else zero.
 * \param[in] acc_ramp Pointer to acc_ramp structure.
 * \param[in] step_size The new step size value.
 */
int acc_ramp_set_step_size(struct acc_ramp *acc_ramp, unsigned int step_size)
{
	if (step_size < ACC_RAMP_STEP_SIZE_MIN || step_size > ACC_RAMP_STEP_SIZE_MAX)
		return -ERANGE;

	acc_ramp->step_size = step_size;
	LOG_BTS(acc_ramp->bts, DRSL, LOGL_DEBUG, "ACC RAMP: ramping step size set to %u\n", step_size);
	return 0;
}

/*!
 * Change the ramping step interval to a fixed value. Unless this function is called,
 * the interval is automatically scaled to the BTS channel load average.
 * \param[in] acc_ramp Pointer to acc_ramp structure.
 * \param[in] step_interval The new fixed step interval in seconds.
 */
int acc_ramp_set_step_interval(struct acc_ramp *acc_ramp, unsigned int step_interval)
{
	if (step_interval < ACC_RAMP_STEP_INTERVAL_MIN || step_interval > ACC_RAMP_STEP_INTERVAL_MAX)
		return -ERANGE;

	acc_ramp->step_interval_sec = step_interval;
	LOG_BTS(acc_ramp->bts, DRSL, LOGL_DEBUG, "ACC RAMP: ramping step interval set to %u seconds\n",
		step_interval);
	return 0;
}

/*!
 * Change the ramping channel load thresholds. They control how ramping subset
 * size of allowed ACCs changes in relation to current channel load (%, 0-100):
 * Under the lower threshold, subset size may be increased; above the upper
 * threshold, subset size may be decreased.
 * \param[in] acc_ramp Pointer to acc_ramp structure.
 * \param[in] low_threshold The new minimum threshold: values under it allow for increasing the ramping subset size.
 * \param[in] up_threshold The new maximum threshold: values under it allow for increasing the ramping subset size.
 */
int acc_ramp_set_chan_load_thresholds(struct acc_ramp *acc_ramp, unsigned int low_threshold, unsigned int up_threshold)
{
	/* for instance, high=49 and lower=50 makes sense:
	   [50-100] -> decrease, [0-49] -> increase */
	if ((int)up_threshold - (int)low_threshold < -1)
		return -ERANGE;

	acc_ramp->chan_load_lower_threshold = low_threshold;
	acc_ramp->chan_load_upper_threshold = up_threshold;
	return 0;
}

/*!
 * Determine if ACC ramping should be started according to configuration, and
 * begin the ramping process if the necessary conditions are present.
 * Perform at least one ramping step to allow 'step_size' ACCs.
 * If 'step_size' is ACC_RAMP_STEP_SIZE_MAX, or if ACC ramping is disabled,
 * all ACCs will be allowed immediately.
 * \param[in] acc_ramp Pointer to acc_ramp structure.
 */
void acc_ramp_trigger(struct acc_ramp *acc_ramp)
{
	if (acc_ramp_is_enabled(acc_ramp)) {
		if (osmo_timer_pending(&acc_ramp->step_timer))
			return; /* Already started, nothing to do */

		/* Set all available ACCs to barred and start ramping up. */
		acc_mgr_set_len_allowed_ramp(&acc_ramp->bts->acc_mgr, 0);
		if (acc_ramp->chan_load_lower_threshold == 0 &&
		    acc_ramp->chan_load_upper_threshold == 100) {
			LOG_BTS(acc_ramp->bts, DRSL, LOGL_ERROR,
				"ACC RAMP: starting ramp up with 0 ACCs and "
				"no possibility to grow the allowed subset size! "
				"Check VTY cmd access-control-class-ramping-chan-load\n");
		}
		do_acc_ramping_step(acc_ramp);
	} else {
		/* Abort any previously running ramping process and allow all available ACCs. */
		acc_ramp_abort(acc_ramp);
	}
}

/*!
 * Abort the ramping process and allow all available ACCs immediately.
 * \param[in] acc_ramp Pointer to acc_ramp structure.
 */
void acc_ramp_abort(struct acc_ramp *acc_ramp)
{
	if (osmo_timer_pending(&acc_ramp->step_timer))
		osmo_timer_del(&acc_ramp->step_timer);

	acc_mgr_set_len_allowed_ramp(&acc_ramp->bts->acc_mgr, 10);
}
