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
#include <osmocom/bsc/bsc_stats.h>
#include <osmocom/bsc/signal.h>

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

static const char *chan_counts_dim1_name[_CHAN_COUNTS1_NUM] = {
	[CHAN_COUNTS1_ALL] = "all",
	[CHAN_COUNTS1_STATIC] = "static",
	[CHAN_COUNTS1_DYNAMIC] = "dynamic",
};

static const char *chan_counts_dim2_name[_CHAN_COUNTS2_NUM] = {
	[CHAN_COUNTS2_MAX_TOTAL] = "max",
	[CHAN_COUNTS2_CURRENT_TOTAL] = "current",
	[CHAN_COUNTS2_ALLOCATED] = "alloc",
	[CHAN_COUNTS2_FREE] = "free",
};

int chan_counts_to_str_buf(char *buf, size_t buflen, const struct chan_counts *c)
{
	struct osmo_strbuf sb = { .buf = buf, .len = buflen };
	int i1, i2, i3;
	OSMO_STRBUF_PRINTF(sb, "{");
	for (i1 = 0; i1 < _CHAN_COUNTS1_NUM; i1++) {
		for (i2 = 0; i2 < _CHAN_COUNTS2_NUM; i2++) {
			bool p12 = false;

			for (i3 = 0; i3 < _GSM_LCHAN_MAX; i3++) {

				int v = c->val[i1][i2][i3];
				if (v) {
					if (!p12) {
						p12 = true;
						OSMO_STRBUF_PRINTF(sb, " %s.%s{", chan_counts_dim1_name[i1],
								   chan_counts_dim2_name[i2]);
					}
					OSMO_STRBUF_PRINTF(sb, " %s=%d", gsm_chan_t_name(i3), v);
				}
			}

			if (p12)
				OSMO_STRBUF_PRINTF(sb, " }");
		}
	}
	OSMO_STRBUF_PRINTF(sb, " }");
	return sb.chars_needed;
}

char *chan_counts_to_str_c(void *ctx, const struct chan_counts *c)
{
	OSMO_NAME_C_IMPL(ctx, 64, "ERROR", chan_counts_to_str_buf, c)
}

void chan_counts_for_ts(struct chan_counts *ts_counts, const struct gsm_bts_trx_ts *ts)
{
	const struct gsm_lchan *lchan;
	bool ts_is_dynamic;

	chan_counts_zero(ts_counts);

	if (!ts_is_usable(ts))
		return;

	/* Count the full potential nr of lchans for dynamic TS */
	chan_counts_per_pchan_add(ts_counts, CHAN_COUNTS1_ALL, CHAN_COUNTS2_MAX_TOTAL, ts->pchan_on_init);

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
		chan_counts_dim3_add(ts_counts, CHAN_COUNTS1_ALL, CHAN_COUNTS2_CURRENT_TOTAL,
				     ts_counts, CHAN_COUNTS1_ALL, CHAN_COUNTS2_MAX_TOTAL);
	} else {
		/* Static TS, or dyn TS that are currently fixed on a specific pchan: count lchans for the
		 * current pchan mode. */
		chan_counts_per_pchan_add(ts_counts, CHAN_COUNTS1_ALL, CHAN_COUNTS2_CURRENT_TOTAL, ts->pchan_is);
	}

	/* Count currently allocated lchans */
	ts_for_n_lchans(lchan, ts, ts->max_primary_lchans) {
		if (!lchan_state_is(lchan, LCHAN_ST_UNUSED))
			ts_counts->val[CHAN_COUNTS1_ALL][CHAN_COUNTS2_ALLOCATED][lchan->type]++;
	}

	chan_counts_dim3_add(ts_counts, CHAN_COUNTS1_ALL, CHAN_COUNTS2_FREE,
			     ts_counts, CHAN_COUNTS1_ALL, CHAN_COUNTS2_CURRENT_TOTAL);
	chan_counts_dim3_sub(ts_counts, CHAN_COUNTS1_ALL, CHAN_COUNTS2_FREE,
			     ts_counts, CHAN_COUNTS1_ALL, CHAN_COUNTS2_ALLOCATED);

	if (ts_is_dynamic)
		chan_counts_dim2_add(ts_counts, CHAN_COUNTS1_DYNAMIC, ts_counts, CHAN_COUNTS1_ALL);
	else
		chan_counts_dim2_add(ts_counts, CHAN_COUNTS1_STATIC, ts_counts, CHAN_COUNTS1_ALL);
}

static void chan_counts_diff(struct chan_counts *diff, const struct chan_counts *left, const struct chan_counts *right)
{
	chan_counts_zero(diff);
	chan_counts_add(diff, right);
	chan_counts_sub(diff, left);
}

static void _chan_counts_ts_update(struct gsm_bts_trx_ts *ts, const struct chan_counts *ts_new_counts)
{
	struct chan_counts diff;

	chan_counts_diff(&diff, &ts->chan_counts, ts_new_counts);
	if (chan_counts_is_zero(&diff))
		return;

	ts->chan_counts = *ts_new_counts;
	chan_counts_add(&ts->trx->chan_counts, &diff);
	chan_counts_add(&ts->trx->bts->chan_counts, &diff);
	chan_counts_add(&bsc_gsmnet->chan_counts, &diff);

	all_allocated_update_bts(ts->trx->bts);
	all_allocated_update_bsc();

	LOGP(DLGLOBAL, LOGL_DEBUG, "change in channel counts: ts %u-%u-%u: %s\n",
	     ts->trx->bts->nr, ts->trx->nr, ts->nr, chan_counts_to_str_c(OTC_SELECT, &diff));
	LOGP(DLGLOBAL, LOGL_DEBUG, "bsc channel counts: %s\n",
	     chan_counts_to_str_c(OTC_SELECT, &bsc_gsmnet->chan_counts));
}

/* Re-count this TS, and update ts->chan_counts. If the new ts->chan_counts differ, propagate the difference to
 * trx->chan_counts, bts->chan_counts and gsm_network->chan_counts. */
void chan_counts_ts_update(struct gsm_bts_trx_ts *ts)
{
	struct chan_counts ts_new_counts;
	chan_counts_for_ts(&ts_new_counts, ts);
	_chan_counts_ts_update(ts, &ts_new_counts);
}

void chan_counts_ts_clear(struct gsm_bts_trx_ts *ts)
{
	struct chan_counts ts_new_counts = {0};
	_chan_counts_ts_update(ts, &ts_new_counts);
}

void chan_counts_trx_update(struct gsm_bts_trx *trx)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(trx->ts); i++) {
		struct gsm_bts_trx_ts *ts = &trx->ts[i];
		chan_counts_ts_update(ts);
	}
}

static int chan_counts_sig_cb(unsigned int subsys, unsigned int signal, void *handler_data, void *signal_data)
{
	struct nm_running_chg_signal_data *nsd;
	struct gsm_bts_trx *trx;
	if (signal != S_NM_RUNNING_CHG)
		return 0;
	nsd = signal_data;
	switch (nsd->obj_class) {
	case NM_OC_RADIO_CARRIER:
		trx = (struct gsm_bts_trx *)nsd->obj;
		break;
	case NM_OC_BASEB_TRANSC:
		trx = gsm_bts_bb_trx_get_trx((struct gsm_bts_bb_trx *)nsd->obj);
		break;
	default:
		return 0;
	}
	chan_counts_trx_update(trx);
	return 0;
}

void chan_counts_sig_init(void)
{
	osmo_signal_register_handler(SS_NM, chan_counts_sig_cb, NULL);
}

void chan_counts_bsc_verify()
{
	struct gsm_bts *bts;
	struct chan_counts bsc_counts = {0};
	struct chan_counts diff;

	llist_for_each_entry(bts, &bsc_gsmnet->bts_list, list) {
		struct gsm_bts_trx *trx;
		struct chan_counts bts_counts = {0};

		llist_for_each_entry(trx, &bts->trx_list, list) {
			struct chan_counts trx_counts = {0};
			int i;

			for (i = 0; i < ARRAY_SIZE(trx->ts); i++) {
				struct chan_counts ts_counts;
				struct gsm_bts_trx_ts *ts = &trx->ts[i];
				chan_counts_for_ts(&ts_counts, ts);

				chan_counts_diff(&diff, &ts->chan_counts, &ts_counts);
				if (!chan_counts_is_zero(&diff)) {
					LOGP(DLGLOBAL, LOGL_ERROR,
					     "internal error in channel counts, on bts-trx-ts %u-%u-%u, fixing."
					     " diff: %s\n",
					     bts->nr, trx->nr, ts->nr,
					     chan_counts_to_str_c(OTC_SELECT, &diff));
					ts->chan_counts = ts_counts;
				}

				chan_counts_add(&trx_counts, &ts_counts);
			}

			chan_counts_diff(&diff, &trx->chan_counts, &trx_counts);
			if (!chan_counts_is_zero(&diff)) {
				LOGP(DLGLOBAL, LOGL_ERROR, "internal error in channel counts, on bts-trx %u-%u, fixing."
				     " diff: %s\n",
				     bts->nr, trx->nr, chan_counts_to_str_c(OTC_SELECT, &diff));
				trx->chan_counts = trx_counts;
			}

			chan_counts_add(&bts_counts, &trx_counts);
		}

		chan_counts_diff(&diff, &bts->chan_counts, &bts_counts);
		if (!chan_counts_is_zero(&diff)) {
			LOGP(DLGLOBAL, LOGL_ERROR, "internal error in channel counts, on bts %u, fixing. diff: %s\n",
			     bts->nr, chan_counts_to_str_c(OTC_SELECT, &diff));
			bts->chan_counts = bts_counts;
		}

		chan_counts_add(&bsc_counts, &bts_counts);
	}

	chan_counts_diff(&diff, &bsc_gsmnet->chan_counts, &bsc_counts);
	if (!chan_counts_is_zero(&diff)) {
		LOGP(DLGLOBAL, LOGL_ERROR, "internal error in overall channel counts, fixing. diff: %s\n",
		     chan_counts_to_str_c(OTC_SELECT, &diff));
		bsc_gsmnet->chan_counts = bsc_counts;
	}
}
