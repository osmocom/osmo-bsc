/* count total, allocated and free channels of all types.
 *
 * (C) 2021 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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

#include <osmocom/gsm/gsm_utils.h>

#include <osmocom/bsc/bts.h>
#include <osmocom/bsc/bts_trx.h>
#include <osmocom/bsc/lchan_fsm.h>
#include <osmocom/bsc/chan_counts.h>

static const unsigned int lchans_per_pchan[_GSM_PCHAN_MAX][_GSM_LCHAN_MAX] = {
	[GSM_PCHAN_NONE] = {0},
	[GSM_PCHAN_CCCH] = { [GSM_LCHAN_CCCH] = 1, },
	[GSM_PCHAN_PDCH] = { [GSM_LCHAN_PDTCH] = 1, },
	[GSM_PCHAN_CCCH_SDCCH4] = {
		[GSM_LCHAN_CCCH] = 1,
		[GSM_LCHAN_SDCCH] = 3,
	},
	[GSM_PCHAN_TCH_F] = { [GSM_LCHAN_TCH_F] = 1, },
	[GSM_PCHAN_TCH_H] = { [GSM_LCHAN_TCH_H] = 2, },
	[GSM_PCHAN_SDCCH8_SACCH8C] = { [GSM_LCHAN_SDCCH] = 8, },
	[GSM_PCHAN_CCCH_SDCCH4_CBCH] = {
		[GSM_LCHAN_CCCH] = 1,
		[GSM_LCHAN_SDCCH] = 3,
		[GSM_LCHAN_CBCH] = 1,
	},
	[GSM_PCHAN_SDCCH8_SACCH8C_CBCH] = {
		[GSM_LCHAN_SDCCH] = 8,
		[GSM_LCHAN_CBCH] = 1,
	},
	[GSM_PCHAN_OSMO_DYN] = {
		[GSM_LCHAN_TCH_F] = 1,
		[GSM_LCHAN_TCH_H] = 2,
		[GSM_LCHAN_SDCCH] = 8,
		[GSM_LCHAN_PDTCH] = 1,
	},
	[GSM_PCHAN_TCH_F_PDCH] = {
		[GSM_LCHAN_TCH_F] = 1,
		[GSM_LCHAN_PDTCH] = 1,
	},
};

static inline void chan_counts_per_pchan_add(struct chan_counts *dst,
					     enum chan_counts_dim1 dim1, enum chan_counts_dim2 dim2,
					     enum gsm_phys_chan_config pchan)
{
	int i;
	for (i = 0; i < _GSM_LCHAN_MAX; i++)
		dst->val[dim1][dim2][i] += lchans_per_pchan[pchan][i];
}

void chan_counts_for_trx(struct chan_counts *trx_counts, const struct gsm_bts_trx *trx)
{
	const struct gsm_bts_trx_ts *ts;
	const struct gsm_lchan *lchan;
	int i;

	chan_counts_zero(trx_counts);

	if (!trx_is_usable(trx))
		return;

	for (i = 0; i < ARRAY_SIZE(trx->ts); i++) {
		bool ts_is_dynamic;
		struct chan_counts ts_count = {0};
		ts = &trx->ts[i];
		if (!ts_is_usable(ts))
			continue;

		/* Count the full potential nr of lchans for dynamic TS */
		chan_counts_per_pchan_add(&ts_count, CHAN_COUNTS1_ALL, CHAN_COUNTS2_MAX_TOTAL, ts->pchan_on_init);

		switch (ts->pchan_on_init) {
		case GSM_PCHAN_TCH_F_PDCH:
		case GSM_PCHAN_OSMO_DYN:
			ts_is_dynamic = true;
			break;
		default:
			ts_is_dynamic = false;
			break;
		}

		if (ts_is_dynamic && ts->pchan_is == GSM_PCHAN_PDCH) {
			/* Dynamic timeslots in PDCH mode can become TCH or SDCCH immediately,
			 * so set CURRENT_TOTAL = MAX_TOTAL. */
			chan_counts_dim3_add(&ts_count, CHAN_COUNTS1_ALL, CHAN_COUNTS2_CURRENT_TOTAL,
					     &ts_count, CHAN_COUNTS1_ALL, CHAN_COUNTS2_MAX_TOTAL);
		} else {
			/* Static TS, or dyn TS that are currently fixed on a specific pchan: count lchans for the
			 * current pchan mode. */
			chan_counts_per_pchan_add(&ts_count, CHAN_COUNTS1_ALL, CHAN_COUNTS2_CURRENT_TOTAL, ts->pchan_is);
		}

		/* Count currently allocated lchans */
		ts_for_n_lchans(lchan, ts, ts->max_primary_lchans) {
			if (!lchan_state_is(lchan, LCHAN_ST_UNUSED))
				ts_count.val[CHAN_COUNTS1_ALL][CHAN_COUNTS2_ALLOCATED][lchan->type]++;
		}

		chan_counts_dim3_add(&ts_count, CHAN_COUNTS1_ALL, CHAN_COUNTS2_FREE,
				     &ts_count, CHAN_COUNTS1_ALL, CHAN_COUNTS2_CURRENT_TOTAL);
		chan_counts_dim3_sub(&ts_count, CHAN_COUNTS1_ALL, CHAN_COUNTS2_FREE,
				     &ts_count, CHAN_COUNTS1_ALL, CHAN_COUNTS2_ALLOCATED);

		if (ts_is_dynamic)
			chan_counts_dim2_add(trx_counts, CHAN_COUNTS1_DYNAMIC, &ts_count, CHAN_COUNTS1_ALL);
		else
			chan_counts_dim2_add(trx_counts, CHAN_COUNTS1_STATIC, &ts_count, CHAN_COUNTS1_ALL);
		chan_counts_dim2_add(trx_counts, CHAN_COUNTS1_ALL, &ts_count, CHAN_COUNTS1_ALL);
	}
}

void chan_counts_for_bts(struct chan_counts *bts_counts, const struct gsm_bts *bts)
{
	struct gsm_bts_trx *trx;
	chan_counts_zero(bts_counts);

	llist_for_each_entry(trx, &bts->trx_list, list) {
		struct chan_counts trx_counts;
		chan_counts_for_trx(&trx_counts, trx);
		chan_counts_add(bts_counts, &trx_counts);
	}
}
