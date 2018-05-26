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

struct penalty_timers {
	struct llist_head timers;
};

struct penalty_timer {
	struct llist_head entry;
	void *for_object;
	unsigned int timeout;
};

static unsigned int time_now(void)
{
	time_t now;
	time(&now);
	/* FIXME: use monotonic clock */
	return (unsigned int)now;
}

struct penalty_timers *penalty_timers_init(void *ctx)
{
	struct penalty_timers *pt = talloc_zero(ctx, struct penalty_timers);
	if (!pt)
		return NULL;
	INIT_LLIST_HEAD(&pt->timers);
	return pt;
}

void penalty_timers_add(struct penalty_timers *pt, void *for_object, int timeout)
{
	struct penalty_timer *timer;
	unsigned int now;
	unsigned int then;
	now = time_now();

	if (timeout <= 0)
		return;

	then = now + timeout;

	/* timer already running for that BTS? */
	llist_for_each_entry(timer, &pt->timers, entry) {
		if (timer->for_object != for_object)
			continue;
		/* raise, if running timer will timeout earlier or has timed
		 * out already, otherwise keep later timeout */
		if (timer->timeout < then)
			timer->timeout = then;
		return;
	}

	/* add new timer */
	timer = talloc_zero(pt, struct penalty_timer);
	if (!timer)
		return;

	timer->for_object = for_object;
	timer->timeout = then;

	llist_add_tail(&timer->entry, &pt->timers);
}

unsigned int penalty_timers_remaining(struct penalty_timers *pt, void *for_object)
{
	struct penalty_timer *timer;
	unsigned int now = time_now();
	unsigned int max_remaining = 0;
	llist_for_each_entry(timer, &pt->timers, entry) {
		unsigned int remaining;
		if (timer->for_object != for_object)
			continue;
		if (now >= timer->timeout)
			continue;
		remaining = timer->timeout - now;
		if (remaining > max_remaining)
			max_remaining = remaining;
	}
	return max_remaining;
}

void penalty_timers_clear(struct penalty_timers *pt, void *for_object)
{
	struct penalty_timer *timer, *timer2;
	llist_for_each_entry_safe(timer, timer2, &pt->timers, entry) {
		if (for_object && timer->for_object != for_object)
			continue;
		llist_del(&timer->entry);
		talloc_free(timer);
	}
}

void penalty_timers_free(struct penalty_timers **pt_p)
{
	struct penalty_timers *pt = *pt_p;
	if (!pt)
		return;
	penalty_timers_clear(pt, NULL);
	talloc_free(pt);
	*pt_p = NULL;
}
