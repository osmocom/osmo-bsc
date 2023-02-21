/* Select a suitable lchan from a given cell.
 *
 * (C) 2008 by Harald Welte <laforge@gnumonks.org>
 * (C) 2008, 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2018-2022 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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

#include <stdlib.h>

#include <osmocom/bsc/debug.h>

#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/timeslot_fsm.h>
#include <osmocom/bsc/lchan_fsm.h>

#include <osmocom/bsc/lchan_select.h>
#include <osmocom/bsc/bts.h>

struct lchan_select_ts_list {
	struct gsm_bts_trx_ts **list;
	unsigned int num;
};

const struct value_string lchan_select_reason_names[] = {
	OSMO_VALUE_STRING(SELECT_FOR_MS_CHAN_REQ),
	OSMO_VALUE_STRING(SELECT_FOR_ASSIGNMENT),
	OSMO_VALUE_STRING(SELECT_FOR_HANDOVER),
	{0, NULL}
};

static struct gsm_lchan *pick_better_lchan(struct gsm_lchan *a, struct gsm_lchan *b)
{
	if (!a)
		return b;
	if (!b)
		return a;
	/* comparing negative dBm values: smaller value means less interference. */
	if (b->interf_dbm < a->interf_dbm)
		return b;
	return a;
}

static struct gsm_lchan *_lc_find(struct lchan_select_ts_list *ts_list,
				  enum gsm_phys_chan_config pchan,
				  enum gsm_phys_chan_config as_pchan,
				  bool allow_pchan_switch, bool log)
{
	struct gsm_lchan *lchan;
	struct gsm_lchan *found_lchan = NULL;

#define LOGPLCHANALLOC(fmt, args...) do { \
	if (log) \
		LOGP(DRLL, LOGL_DEBUG, "looking for lchan %s%s%s%s: " fmt, \
		     gsm_pchan_name(pchan), \
		     pchan == as_pchan ? "" : " as ", \
		     pchan == as_pchan ? "" : gsm_pchan_name(as_pchan), \
		     ((pchan != as_pchan) && !allow_pchan_switch) ? " without pchan switch" : "", \
		     ## args); \
	} while (0)

	for (unsigned int tn = 0; tn < ts_list->num; tn++) {
		struct gsm_bts_trx_ts *ts = ts_list->list[tn];
		int lchans_as_pchan;

		/* The caller first selects what kind of TS to search in, e.g. looking for exact
		 * GSM_PCHAN_TCH_F, or maybe among dynamic GSM_PCHAN_OSMO_DYN... */
		if (ts->pchan_on_init != pchan) {
			LOGPLCHANALLOC("%s is != %s\n", gsm_ts_and_pchan_name(ts),
				       gsm_pchan_name(pchan));
			continue;
		}
		/* Next, is this timeslot in or can it be switched to the pchan we want to use it for? */
		if (!ts_usable_as_pchan(ts, as_pchan, allow_pchan_switch)) {
			LOGPLCHANALLOC("%s is not usable as %s%s\n", gsm_ts_and_pchan_name(ts),
				       gsm_pchan_name(as_pchan),
				       allow_pchan_switch ? "" : " without pchan switch");
			continue;
		}

		/* TS is (going to be) in desired pchan mode. Go ahead and check for an available lchan. */
		lchans_as_pchan = pchan_subslots(as_pchan);
		ts_for_n_lchans(lchan, ts, lchans_as_pchan) {
			struct gsm_lchan *was = found_lchan;

			if (lchan->fi->state != LCHAN_ST_UNUSED) {
				LOGPLCHANALLOC("%s ss=%d in type=%s,state=%s not suitable\n",
					       gsm_ts_and_pchan_name(ts), lchan->nr,
					       gsm_chan_t_name(lchan->type),
					       osmo_fsm_inst_state_name(lchan->fi));
				continue;
			}

			found_lchan = pick_better_lchan(found_lchan, lchan);
			if (found_lchan != was)
				LOGPLCHANALLOC("%s ss=%d interf=%u=%ddBm is %s%s\n",
					       gsm_ts_and_pchan_name(ts), lchan->nr,
					       lchan->interf_band, lchan->interf_dbm,
					       was == NULL ? "available" : "better",
					       ts->pchan_is != as_pchan ? ", after dyn PCHAN change" : "");
			else
				LOGPLCHANALLOC("%s ss=%d interf=%u=%ddBm is also available but not better\n",
					       gsm_ts_and_pchan_name(ts), lchan->nr,
					       lchan->interf_band, lchan->interf_dbm);

			/* When picking an lchan with least interference, continue to loop across all lchans. When
			 * ignoring interference levels, return the first match. */
			if (found_lchan && !ts->trx->bts->chan_alloc_avoid_interf)
				return found_lchan;
		}
	}

	if (found_lchan)
		LOGPLCHANALLOC("%s ss=%d interf=%ddBm%s is the best pick\n",
			       gsm_ts_and_pchan_name(found_lchan->ts), found_lchan->nr,
			       found_lchan->interf_dbm,
			       found_lchan->ts->pchan_is != as_pchan ? ", after dyn PCHAN change," : "");
	else
		LOGPLCHANALLOC("Nothing found\n");
	return found_lchan;
#undef LOGPLCHANALLOC
}

static struct gsm_lchan *lc_dyn_find(struct lchan_select_ts_list *ts_list,
				     enum gsm_phys_chan_config pchan,
				     enum gsm_phys_chan_config dyn_as_pchan,
				     bool log)
{
	struct gsm_lchan *lchan;

	/* First find an lchan that needs no change in its timeslot pchan mode.
	 * In particular, this ensures that handover to a dynamic timeslot in TCH/H favors timeslots that are currently
	 * using only one of two TCH/H, so that we don't switch more dynamic timeslots to TCH/H than necessary.
	 * For non-dynamic timeslots, it is not necessary to do a second pass with allow_pchan_switch ==
	 * true, because they never switch anyway. */
	if ((lchan = _lc_find(ts_list, pchan, dyn_as_pchan, false, log)))
		return lchan;
	if ((lchan = _lc_find(ts_list, pchan, dyn_as_pchan, true, log)))
		return lchan;

	return NULL;
}

static struct gsm_lchan *lc_find(struct lchan_select_ts_list *ts_list,
				 enum gsm_phys_chan_config pchan,
				 bool log)
{
	return _lc_find(ts_list, pchan, pchan, false, log);
}

enum gsm_chan_t chan_mode_to_chan_type(enum gsm48_chan_mode chan_mode, enum channel_rate chan_rate)
{
	switch (gsm48_chan_mode_to_non_vamos(chan_mode)) {
	case GSM48_CMODE_SIGN:
		switch (chan_rate) {
		case CH_RATE_SDCCH:
			return GSM_LCHAN_SDCCH;
		case CH_RATE_HALF:
			return GSM_LCHAN_TCH_H;
		case CH_RATE_FULL:
			return GSM_LCHAN_TCH_F;
		default:
			return GSM_LCHAN_NONE;
		}
	case GSM48_CMODE_SPEECH_EFR:
		/* EFR works over FR channels only */
		if (chan_rate != CH_RATE_FULL)
			return GSM_LCHAN_NONE;
		/* fall through */
	case GSM48_CMODE_SPEECH_V1:
	case GSM48_CMODE_SPEECH_AMR:
	case GSM48_CMODE_DATA_14k5:
	case GSM48_CMODE_DATA_12k0:
	case GSM48_CMODE_DATA_6k0:
	case GSM48_CMODE_DATA_3k6:
		switch (chan_rate) {
		case CH_RATE_HALF:
			return GSM_LCHAN_TCH_H;
		case CH_RATE_FULL:
			return GSM_LCHAN_TCH_F;
		default:
			return GSM_LCHAN_NONE;
		}
	default:
		return GSM_LCHAN_NONE;
	}
}

static int qsort_func(const void *_a, const void *_b)
{
	const struct gsm_bts_trx *trx_a = *(const struct gsm_bts_trx **)_a;
	const struct gsm_bts_trx *trx_b = *(const struct gsm_bts_trx **)_b;

	int pwr_a = trx_a->nominal_power - trx_a->max_power_red;
	int pwr_b = trx_b->nominal_power - trx_b->max_power_red;

	/* Sort in descending order */
	return pwr_b - pwr_a;
}

static void populate_ts_list(struct lchan_select_ts_list *ts_list,
			     struct gsm_bts *bts,
			     bool chan_alloc_reverse,
			     bool sort_by_trx_power,
			     bool log)
{
	struct gsm_bts_trx **trx_list;
	struct gsm_bts_trx *trx;
	unsigned int num = 0;

	/* Allocate an array with pointers to all TRX instances of a BTS */
	trx_list = talloc_array_ptrtype(bts, trx_list, bts->num_trx);
	OSMO_ASSERT(trx_list != NULL);

	llist_for_each_entry(trx, &bts->trx_list, list)
		trx_list[trx->nr] = trx;

	/* Sort by TRX power in descending order (if needed) */
	if (sort_by_trx_power)
		qsort(&trx_list[0], bts->num_trx, sizeof(trx), &qsort_func);

	for (unsigned int trxn = 0; trxn < bts->num_trx; trxn++) {
		trx = trx_list[trxn];
		for (unsigned int tn = 0; tn < ARRAY_SIZE(trx->ts); tn++) {
			struct gsm_bts_trx_ts *ts = &trx->ts[tn];
			if (ts_is_usable(ts))
				ts_list->list[num++] = ts;
			else if (log)
				LOGP(DRLL, LOGL_DEBUG, "%s is not usable\n", gsm_ts_name(ts));
		}
	}

	talloc_free(trx_list);
	ts_list->num = num;

	/* Reverse the timeslot list if required */
	if (chan_alloc_reverse) {
		for (unsigned int tn = 0; tn < num / 2; tn++) {
			struct gsm_bts_trx_ts *temp = ts_list->list[tn];
			ts_list->list[tn] = ts_list->list[num - tn - 1];
			ts_list->list[num - tn - 1] = temp;
		}
	}
}

static bool chan_alloc_ass_dynamic_reverse(struct gsm_bts *bts,
					   void *ctx, bool log)
{
	const struct load_counter *ll = &bts->c0->lchan_load;
	const struct gsm_lchan *old_lchan = ctx;
	unsigned int lchan_load;
	int avg_ul_rxlev;

	OSMO_ASSERT(old_lchan != NULL);
	OSMO_ASSERT(old_lchan->ts->trx->bts == bts);

#define LOG_COND(fmt, args...) do { \
	if (log) \
		LOG_LCHAN(old_lchan, LOGL_DEBUG, fmt, ## args); \
	} while (0)

	/* Condition a) Channel load on the C0 (BCCH carrier) */
	lchan_load = ll->total ? ll->used * 100 / ll->total : 0;
	if (lchan_load < bts->chan_alloc_dyn_params.c0_chan_load_thresh) {
		LOG_COND("C0 Channel Load %u%% < thresh %u%% => using ascending order\n",
			 lchan_load, bts->chan_alloc_dyn_params.c0_chan_load_thresh);
		return false;
	}

	/* Condition b) average Uplink RxLev */
	avg_ul_rxlev = get_meas_rep_avg(old_lchan, TDMA_MEAS_FIELD_RXLEV,
					TDMA_MEAS_DIR_UL, TDMA_MEAS_SET_AUTO,
					bts->chan_alloc_dyn_params.ul_rxlev_avg_num);
	if (avg_ul_rxlev < 0) {
		LOG_COND("Unknown AVG UL RxLev => using ascending order\n");
		return false;
	}
	if (avg_ul_rxlev < bts->chan_alloc_dyn_params.ul_rxlev_thresh) {
		LOG_COND("AVG UL RxLev %u < thresh %u => using ascending order\n",
			 avg_ul_rxlev, bts->chan_alloc_dyn_params.ul_rxlev_thresh);
		return false;
	}

	LOG_COND("C0 Channel Load %u%% >= thresh %u%% and "
		 "AVG UL RxLev %u >= thresh %u => using descending order\n",
		 lchan_load, bts->chan_alloc_dyn_params.c0_chan_load_thresh,
		 avg_ul_rxlev, bts->chan_alloc_dyn_params.ul_rxlev_thresh);

#undef LOG_COND

	return true;
}

struct gsm_lchan *lchan_select_by_chan_mode(struct gsm_bts *bts,
					    enum gsm48_chan_mode chan_mode,
					    enum channel_rate chan_rate,
					    enum lchan_select_reason reason,
					    void *ctx)
{
	enum gsm_chan_t type = chan_mode_to_chan_type(chan_mode, chan_rate);
	if (type == GSM_LCHAN_NONE)
		return NULL;
	return lchan_select_by_type(bts, type, reason, ctx);
}

struct gsm_lchan *lchan_avail_by_type(struct gsm_bts *bts,
				      enum gsm_chan_t type,
				      enum lchan_select_reason reason,
				      void *ctx, bool log)
{
	struct gsm_lchan *lchan = NULL;
	enum gsm_phys_chan_config first, first_cbch, second, second_cbch;
	struct lchan_select_ts_list ts_list;
	bool sort_by_trx_power = false;
	bool chan_alloc_reverse = false;

	if (log) {
		LOG_BTS(bts, DRLL, LOGL_DEBUG, "lchan_avail_by_type(type=%s, reason=%s)\n",
			gsm_chan_t_name(type), lchan_select_reason_name(reason));
	}

	switch (reason) {
	case SELECT_FOR_MS_CHAN_REQ:
		chan_alloc_reverse = bts->chan_alloc_chan_req_reverse;
		break;
	case SELECT_FOR_ASSIGNMENT:
		if (bts->chan_alloc_assignment_dynamic) {
			chan_alloc_reverse = chan_alloc_ass_dynamic_reverse(bts, ctx, log);
			sort_by_trx_power = bts->chan_alloc_dyn_params.sort_by_trx_power;
		} else {
			chan_alloc_reverse = bts->chan_alloc_assignment_reverse;
		}
		break;
	case SELECT_FOR_HANDOVER:
		chan_alloc_reverse = bts->chan_alloc_handover_reverse;
		break;
	}

	/* Allocate an array with pointers to all timeslots of a BTS */
	ts_list.list = talloc_array_ptrtype(bts, ts_list.list, bts->num_trx * 8);
	if (OSMO_UNLIKELY(ts_list.list == NULL))
		return NULL;

	/* Populate this array with the actual pointers */
	populate_ts_list(&ts_list, bts, chan_alloc_reverse, sort_by_trx_power, log);

	switch (type) {
	case GSM_LCHAN_SDCCH:
		if (chan_alloc_reverse) {
			first = GSM_PCHAN_SDCCH8_SACCH8C;
			first_cbch = GSM_PCHAN_SDCCH8_SACCH8C_CBCH;
			second = GSM_PCHAN_CCCH_SDCCH4;
			second_cbch = GSM_PCHAN_CCCH_SDCCH4_CBCH;
		} else {
			first = GSM_PCHAN_CCCH_SDCCH4;
			first_cbch = GSM_PCHAN_CCCH_SDCCH4_CBCH;
			second = GSM_PCHAN_SDCCH8_SACCH8C;
			second_cbch = GSM_PCHAN_SDCCH8_SACCH8C_CBCH;
		}

		lchan = lc_find(&ts_list, first, log);
		if (lchan == NULL)
			lchan = lc_find(&ts_list, first_cbch, log);
		if (lchan == NULL)
			lchan = lc_find(&ts_list, second, log);
		if (lchan == NULL)
			lchan = lc_find(&ts_list, second_cbch, log);
		/* No dedicated SDCCH available -- try fully dynamic
		 * TCH/F_TCH/H_SDCCH8_PDCH if BTS supports it: */
		if (lchan == NULL && osmo_bts_has_feature(&bts->features, BTS_FEAT_DYN_TS_SDCCH8))
			lchan = lc_dyn_find(&ts_list, GSM_PCHAN_OSMO_DYN,
						      GSM_PCHAN_SDCCH8_SACCH8C, log);
		break;
	case GSM_LCHAN_TCH_F:
		lchan = lc_find(&ts_list, GSM_PCHAN_TCH_F, log);
		/* If we don't have TCH/F available, try dynamic TCH/F_PDCH */
		if (!lchan)
			lchan = lc_dyn_find(&ts_list, GSM_PCHAN_TCH_F_PDCH,
						      GSM_PCHAN_TCH_F, log);

		/* Try fully dynamic TCH/F_TCH/H_PDCH as TCH/F... */
		if (!lchan && bts->network->dyn_ts_allow_tch_f)
			lchan = lc_dyn_find(&ts_list, GSM_PCHAN_OSMO_DYN,
						      GSM_PCHAN_TCH_F, log);
		break;
	case GSM_LCHAN_TCH_H:
		lchan = lc_find(&ts_list, GSM_PCHAN_TCH_H, log);
		/* No dedicated TCH/x available -- try fully dynamic
		 * TCH/F_TCH/H_PDCH */
		if (!lchan)
			lchan = lc_dyn_find(&ts_list, GSM_PCHAN_OSMO_DYN,
						      GSM_PCHAN_TCH_H, log);
		break;
	default:
		LOG_BTS(bts, DRLL, LOGL_ERROR, "Unknown gsm_chan_t %u\n", type);
	}

	talloc_free(ts_list.list);

	return lchan;
}

/* Return a matching lchan from a specific BTS that is currently available. The next logical step is
 * lchan_activate() on it, which would possibly cause dynamic timeslot pchan switching, taken care of by
 * the lchan and timeslot FSMs. */
struct gsm_lchan *lchan_select_by_type(struct gsm_bts *bts,
				       enum gsm_chan_t type,
				       enum lchan_select_reason reason,
				       void *ctx)
{
	struct gsm_lchan *lchan = NULL;

	LOG_BTS(bts, DRLL, LOGL_DEBUG, "lchan_select_by_type(type=%s, reason=%s)\n",
		gsm_chan_t_name(type), lchan_select_reason_name(reason));

	lchan = lchan_avail_by_type(bts, type, reason, ctx, true);

	if (!lchan) {
		LOG_BTS(bts, DRLL, LOGL_NOTICE, "Failed to select %s channel (%s)\n",
			gsm_chan_t_name(type), lchan_select_reason_name(reason));
		return NULL;
	}

	lchan_select_set_type(lchan, type);
	return lchan;
}

/* Set available lchan to given type. Usually used on lchan obtained with
 * lchan_avail_by_type. The next logical step is lchan_activate() on it, which
 * would possibly cause dynamic timeslot pchan switching, taken care of by the
 * lchan and timeslot FSMs. */
void lchan_select_set_type(struct gsm_lchan *lchan, enum gsm_chan_t type)
{
	lchan->type = type;
	LOG_LCHAN(lchan, LOGL_INFO, "Selected\n");
}
