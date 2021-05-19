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
#include <osmocom/bsc/bts.h>

#include <osmocom/core/talloc.h>

/* Update channel load calculation for the given BTS */
void bts_chan_load(struct pchan_load *cl, const struct gsm_bts *bts)
{
	struct gsm_bts_trx *trx;

	llist_for_each_entry(trx, &bts->trx_list, list) {
		int i;

		/* skip administratively deactivated transceivers */
		if (!trx_is_usable(trx))
			continue;

		for (i = 0; i < ARRAY_SIZE(trx->ts); i++) {
			struct gsm_bts_trx_ts *ts = &trx->ts[i];
			struct load_counter *pl = &cl->pchan[ts->pchan_on_init];
			struct gsm_lchan *lchan;

			/* skip administratively deactivated timeslots */
			if (!nm_is_running(&ts->mo.nm_state))
				continue;

			/* A dynamic timeslot currently in PDCH mode are available as TCH, beause they can be switched
			 * to TCH mode at any moment. Count TCH/F_TCH/H_PDCH as one total timeslot, even though it may
			 * be switched to TCH/H and would then count as two -- hence opt for pessimistic load. */
			if ((ts->pchan_on_init == GSM_PCHAN_TCH_F_TCH_H_PDCH ||
			     ts->pchan_on_init == GSM_PCHAN_TCH_F_PDCH) &&
			    (ts->pchan_is == GSM_PCHAN_NONE ||
			     ts->pchan_is == GSM_PCHAN_PDCH)) {
				pl->total++;
				/* Below loop would not count this timeslot, since in PDCH mode it has no usable
				 * timeslots. But let's make it clear that the timeslot must not be counted again: */
				continue;
			}

			ts_for_n_lchans(lchan, ts, ts->max_primary_lchans) {
				/* don't even count CBCH slots in total */
				if (lchan->type == GSM_LCHAN_CBCH)
					continue;

				pl->total++;

				/* lchans under a BORKEN TS should be counted
				 * as used just as BORKEN lchans under a normal TS */
				if (ts->fi->state == TS_ST_BORKEN) {
					pl->used++;
					continue;
				}

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

/* Update channel load calculation for all BTS in the BSC */
void network_chan_load(struct pchan_load *pl, struct gsm_network *net)
{
	struct gsm_bts *bts;

	memset(pl, 0, sizeof(*pl));

	llist_for_each_entry(bts, &net->bts_list, list)
		bts_chan_load(pl, bts);
}

static void chan_load_stat_set(enum gsm_phys_chan_config pchan,
                               struct gsm_bts *bts,
                               struct load_counter *lc)
{
	switch (pchan) {
	case GSM_PCHAN_NONE:
	case GSM_PCHAN_CCCH:
	case GSM_PCHAN_PDCH:
	case GSM_PCHAN_UNKNOWN:
		break;
	case GSM_PCHAN_CCCH_SDCCH4:
		osmo_stat_item_set(osmo_stat_item_group_get_item(bts->bts_statg, BTS_STAT_CHAN_CCCH_SDCCH4_USED), lc->used);
		osmo_stat_item_set(osmo_stat_item_group_get_item(bts->bts_statg, BTS_STAT_CHAN_CCCH_SDCCH4_TOTAL), lc->total);
		break;
	case GSM_PCHAN_TCH_F:
		osmo_stat_item_set(osmo_stat_item_group_get_item(bts->bts_statg, BTS_STAT_CHAN_TCH_F_USED), lc->used);
		osmo_stat_item_set(osmo_stat_item_group_get_item(bts->bts_statg, BTS_STAT_CHAN_TCH_F_TOTAL), lc->total);
		break;
	case GSM_PCHAN_TCH_H:
		osmo_stat_item_set(osmo_stat_item_group_get_item(bts->bts_statg, BTS_STAT_CHAN_TCH_H_USED), lc->used);
		osmo_stat_item_set(osmo_stat_item_group_get_item(bts->bts_statg, BTS_STAT_CHAN_TCH_H_TOTAL), lc->total);
		break;
	case GSM_PCHAN_SDCCH8_SACCH8C:
		osmo_stat_item_set(osmo_stat_item_group_get_item(bts->bts_statg, BTS_STAT_CHAN_SDCCH8_USED), lc->used);
		osmo_stat_item_set(osmo_stat_item_group_get_item(bts->bts_statg, BTS_STAT_CHAN_SDCCH8_TOTAL), lc->total);
		break;
	case GSM_PCHAN_TCH_F_PDCH:
		osmo_stat_item_set(osmo_stat_item_group_get_item(bts->bts_statg, BTS_STAT_CHAN_TCH_F_PDCH_USED), lc->used);
		osmo_stat_item_set(osmo_stat_item_group_get_item(bts->bts_statg, BTS_STAT_CHAN_TCH_F_PDCH_TOTAL), lc->total);
		break;
	case GSM_PCHAN_CCCH_SDCCH4_CBCH:
		osmo_stat_item_set(osmo_stat_item_group_get_item(bts->bts_statg, BTS_STAT_CHAN_CCCH_SDCCH4_CBCH_USED), lc->used);
		osmo_stat_item_set(osmo_stat_item_group_get_item(bts->bts_statg, BTS_STAT_CHAN_CCCH_SDCCH4_CBCH_TOTAL), lc->total);
		break;
	case GSM_PCHAN_SDCCH8_SACCH8C_CBCH:
		osmo_stat_item_set(osmo_stat_item_group_get_item(bts->bts_statg, BTS_STAT_CHAN_SDCCH8_CBCH_USED), lc->used);
		osmo_stat_item_set(osmo_stat_item_group_get_item(bts->bts_statg, BTS_STAT_CHAN_SDCCH8_CBCH_TOTAL), lc->total);
		break;
	case GSM_PCHAN_TCH_F_TCH_H_PDCH:
		osmo_stat_item_set(osmo_stat_item_group_get_item(bts->bts_statg, BTS_STAT_CHAN_TCH_F_TCH_H_PDCH_USED), lc->used);
		osmo_stat_item_set(osmo_stat_item_group_get_item(bts->bts_statg, BTS_STAT_CHAN_TCH_F_TCH_H_PDCH_TOTAL), lc->total);
		break;
	default:
		LOG_BTS(bts, DRLL, LOGL_NOTICE, "Unknown channel type %d\n", pchan);
	}
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

		/* Export channel load to stats gauges */
		chan_load_stat_set(i, bts, lc);

		/* Ignore samples too large for fixed-point calculations (shouldn't happen). */
		if (lc->used > UINT16_MAX || lc->total > UINT16_MAX) {
			LOG_BTS(bts, DRLL, LOGL_NOTICE, "numbers in channel load sample "
				"too large (used=%u / total=%u)\n", lc->used, lc->total);
			continue;
		}

		used += lc->used;
		total += lc->total;
	}

	/* Check for invalid samples (shouldn't happen). */
	if (used > total) {
		LOG_BTS(bts, DRLL, LOGL_NOTICE, "bogus channel load sample (used=%"PRIu64" / total=%"PRIu32")\n",
			used, total);
	}
	if (total == 0 || used > total) {
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
	LOG_BTS(bts, DRLL, LOGL_DEBUG, "channel load average is %"PRIu64".%.2"PRIu64"%%\n",
		(load & 0xffffff00) >> 8, (load & 0xff) / 10);
	bts->chan_load_avg = ((load & 0xffffff00) >> 8);
	OSMO_ASSERT(bts->chan_load_avg <= 100);
	osmo_stat_item_set(osmo_stat_item_group_get_item(bts->bts_statg, BTS_STAT_CHAN_LOAD_AVERAGE), bts->chan_load_avg);

	/* Calculate new T3122 wait indicator. */
	wait_ind = ((used / total) * max_wait_ind);
	wait_ind >>= 8; /* convert from fixed-point to integer */
	if (wait_ind < min_wait_ind)
		wait_ind = min_wait_ind;
	else if (wait_ind > max_wait_ind)
		wait_ind = max_wait_ind;

	LOG_BTS(bts, DRLL, LOGL_DEBUG, "T3122 wait indicator set to %"PRIu64" seconds\n", wait_ind);
	bts->T3122 = (uint8_t)wait_ind;
	osmo_stat_item_set(osmo_stat_item_group_get_item(bts->bts_statg, BTS_STAT_T3122), wait_ind);
}
