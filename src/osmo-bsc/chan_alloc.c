/* GSM Channel allocation routines
 *
 * (C) 2008 by Harald Welte <laforge@gnumonks.org>
 * (C) 2008, 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>

#include <osmocom/bsc/chan_alloc.h>
#include <osmocom/bsc/abis_nm.h>
#include <osmocom/bsc/abis_rsl.h>
#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/signal.h>
#include <osmocom/bsc/timeslot_fsm.h>
#include <osmocom/bsc/lchan_fsm.h>
#include <osmocom/bsc/gsm_04_08_rr.h>

#include <osmocom/core/talloc.h>

void bts_chan_load(struct pchan_load *cl, const struct gsm_bts *bts)
{
	struct gsm_bts_trx *trx;

	llist_for_each_entry(trx, &bts->trx_list, list) {
		int i;

		/* skip administratively deactivated tranxsceivers */
		if (!nm_is_running(&trx->mo.nm_state) ||
		    !nm_is_running(&trx->bb_transc.mo.nm_state))
			continue;

		for (i = 0; i < ARRAY_SIZE(trx->ts); i++) {
			struct gsm_bts_trx_ts *ts = &trx->ts[i];
			struct load_counter *pl = &cl->pchan[ts->pchan_on_init];
			struct gsm_lchan *lchan;

			/* skip administratively deactivated timeslots */
			if (!nm_is_running(&ts->mo.nm_state))
				continue;

			ts_for_each_lchan(lchan, ts) {
				pl->total++;

				switch (lchan->fi->state) {
				case LCHAN_ST_UNUSED:
					break;
				default:
					pl->used++;
					break;
				}
			}
		}
	}
}

void network_chan_load(struct pchan_load *pl, struct gsm_network *net)
{
	struct gsm_bts *bts;

	memset(pl, 0, sizeof(*pl));

	llist_for_each_entry(bts, &net->bts_list, list)
		bts_chan_load(pl, bts);
}

/* Update T3122 wait indicator based on samples of BTS channel load. */
void
bts_update_t3122_chan_load(struct gsm_bts *bts)
{
	struct pchan_load pl;
	uint64_t used = 0;
	uint32_t total = 0;
	uint64_t load;
	uint64_t wait_ind;
	static const uint8_t min_wait_ind = GSM_T3122_DEFAULT;
	static const uint8_t max_wait_ind = 128; /* max wait ~2 minutes */
	int i;

	/* Ignore BTS that are not in operation, in order to not flood the log with "bogus channel load"
	 * messages */
	if (!trx_is_usable(bts->c0))
		return;

	/* Sum up current load across all channels. */
	memset(&pl, 0, sizeof(pl));
	bts_chan_load(&pl, bts);
	for (i = 0; i < ARRAY_SIZE(pl.pchan); i++) {
		struct load_counter *lc = &pl.pchan[i];

		/* Ignore samples too large for fixed-point calculations (shouldn't happen). */
		if (lc->used > UINT16_MAX || lc->total > UINT16_MAX) {
			LOGP(DRLL, LOGL_NOTICE, "(bts=%d) numbers in channel load sample "
			     "too large (used=%u / total=%u)\n", bts->nr, lc->used, lc->total);
			continue;
		}

		used += lc->used;
		total += lc->total;
	}

	/* Check for invalid samples (shouldn't happen). */
	if (total == 0 || used > total) {
		LOGP(DRLL, LOGL_NOTICE, "(bts=%d) bogus channel load sample (used=%"PRIu64" / total=%"PRIu32")\n",
		     bts->nr, used, total);
		bts->T3122 = 0; /* disable override of network-wide default value */
		bts->chan_load_samples_idx = 0; /* invalidate other samples collected so far */
		return;
	}

	/* If we haven't got enough samples yet, store measurement for later use. */
	if (bts->chan_load_samples_idx < ARRAY_SIZE(bts->chan_load_samples)) {
		struct load_counter *sample = &bts->chan_load_samples[bts->chan_load_samples_idx++];
		sample->total = (unsigned int)total;
		sample->used = (unsigned int)used;
		return;
	}

	/* We have enough samples and will overwrite our current samples later. */
	bts->chan_load_samples_idx = 0;

	/* Add all previous samples to the current sample. */
	for (i = 0; i < ARRAY_SIZE(bts->chan_load_samples); i++) {
		struct load_counter *sample = &bts->chan_load_samples[i];
		total += sample->total;
		used += sample->used;
	}

	used <<= 8; /* convert to fixed-point */

	/* Log channel load average. */
	load = ((used / total) * 100);
	LOGP(DRLL, LOGL_DEBUG, "(bts=%d) channel load average is %"PRIu64".%.2"PRIu64"%%\n",
	     bts->nr, (load & 0xffffff00) >> 8, (load & 0xff) / 10);
	bts->chan_load_avg = ((load & 0xffffff00) >> 8);
	OSMO_ASSERT(bts->chan_load_avg <= 100);
	osmo_stat_item_set(bts->bts_statg->items[BTS_STAT_CHAN_LOAD_AVERAGE], bts->chan_load_avg);

	/* Calculate new T3122 wait indicator. */
	wait_ind = ((used / total) * max_wait_ind);
	wait_ind >>= 8; /* convert from fixed-point to integer */
	if (wait_ind < min_wait_ind)
		wait_ind = min_wait_ind;
	else if (wait_ind > max_wait_ind)
		wait_ind = max_wait_ind;

	LOGP(DRLL, LOGL_DEBUG, "(bts=%d) T3122 wait indicator set to %"PRIu64" seconds\n", bts->nr, wait_ind);
	bts->T3122 = (uint8_t)wait_ind;
	osmo_stat_item_set(bts->bts_statg->items[BTS_STAT_T3122], wait_ind);
}
