/* (C) 2018 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 *
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

#include <talloc.h>
#include <time.h>
#include <stdint.h>

#include <osmocom/core/linuxlist.h>

#include <osmocom/bsc/penalty_timers.h>
#include <osmocom/bsc/gsm_data.h>

static unsigned int time_now(void)
{
	time_t now;
	time(&now);
	/* FIXME: use monotonic clock */
	return (unsigned int)now;
}

/* Add a penalty timer for a target cell ID.
 * \param ctx  talloc context to allocate new struct penalty_timer from.
 * \param penalty_timers  llist head to add penalty timer to.
 * \param for_target_cell  Which handover target to penalize.
 * \param timeout  Penalty time in seconds.
 */
void penalty_timers_add(void *ctx, struct llist_head *penalty_timers,
			const struct gsm0808_cell_id *for_target_cell, int timeout)
{
	struct penalty_timer *timer;
	unsigned int now;
	unsigned int then;
	now = time_now();

	if (timeout <= 0)
		return;

	then = now + timeout;

	/* timer already running for that target cell? */
	llist_for_each_entry(timer, penalty_timers, entry) {
		if (!gsm0808_cell_ids_match(&timer->for_target_cell, for_target_cell, true))
			continue;
		/* raise, if running timer will timeout earlier or has timed
		 * out already, otherwise keep later timeout */
		if (timer->timeout < then)
			timer->timeout = then;
		return;
	}

	/* add new timer */
	timer = talloc_zero(ctx, struct penalty_timer);
	if (!timer)
		return;

	timer->for_target_cell = *for_target_cell;
	timer->timeout = then;

	llist_add_tail(&timer->entry, penalty_timers);
}

/* Add a penalty timer for each target cell ID in the given list.
 * \param ctx  talloc context to allocate new struct penalty_timer from.
 * \param penalty_timers  llist head to add penalty timer to.
 * \param for_target_cells  Which handover targets to penalize.
 * \param timeout  Penalty time in seconds.
 */
void penalty_timers_add_list(void *ctx, struct llist_head *penalty_timers,
			     const struct gsm0808_cell_id_list2 *for_target_cells, int timeout)
{
	int i;
	for (i = 0; i < for_target_cells->id_list_len; i++) {
		struct gsm0808_cell_id add = {
			.id_discr = for_target_cells->id_discr,
			.id = for_target_cells->id_list[i],
		};
		penalty_timers_add(ctx, penalty_timers, &add, timeout);
	}
}

/* Return the amount of penalty time in seconds remaining for a target cell.
 * \param penalty_timers  llist head to look up penalty time in.
 * \param for_target_cell  Which handover target to query.
 * \returns seconds remaining until all penalty time has expired.
 */
unsigned int penalty_timers_remaining(struct llist_head *penalty_timers,
				      const struct gsm0808_cell_id *for_target_cell)
{
	struct penalty_timer *timer;
	unsigned int now = time_now();
	unsigned int max_remaining = 0;
	llist_for_each_entry(timer, penalty_timers, entry) {
		unsigned int remaining;
		if (!gsm0808_cell_ids_match(&timer->for_target_cell, for_target_cell, true))
			continue;
		if (now >= timer->timeout)
			continue;
		remaining = timer->timeout - now;
		if (remaining > max_remaining)
			max_remaining = remaining;
	}
	return max_remaining;
}

/* Return the largest amount of penalty time in seconds remaining for any one of the given target cells.
 * Call penalty_timers_remaining() for each entry of for_target_cells and return the largest value encountered.
 * \param penalty_timers  llist head to look up penalty time in.
 * \param for_target_cells  Which handover targets to query.
 * \returns seconds remaining until all penalty time has expired.
 */
unsigned int penalty_timers_remaining_list(struct llist_head *penalty_timers,
					   const struct gsm0808_cell_id_list2 *for_target_cells)
{
	int i;
	unsigned int max_remaining = 0;
	for (i = 0; i < for_target_cells->id_list_len; i++) {
		unsigned int remaining;
		struct gsm0808_cell_id query = {
			.id_discr = for_target_cells->id_discr,
			.id = for_target_cells->id_list[i],
		};
		remaining = penalty_timers_remaining(penalty_timers, &query);
		max_remaining = OSMO_MAX(max_remaining, remaining);
	}
	return max_remaining;
}

/* Clear penalty timers for one target cell, or completely clear the entire list.
 * \param penalty_timers  llist head to add penalty timer to.
 * \param for_target_cell  Which handover target to clear timers for, or NULL to clear all timers. */
void penalty_timers_clear(struct llist_head *penalty_timers, const struct gsm0808_cell_id *for_target_cell)
{
	struct penalty_timer *timer, *timer2;
	llist_for_each_entry_safe(timer, timer2, penalty_timers, entry) {
		if (for_target_cell && !gsm0808_cell_ids_match(&timer->for_target_cell, for_target_cell, true))
			continue;
		llist_del(&timer->entry);
		talloc_free(timer);
	}
}
