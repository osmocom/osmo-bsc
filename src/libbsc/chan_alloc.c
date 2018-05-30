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
#include <osmocom/bsc/gsm_04_08_utils.h>

#include <osmocom/core/talloc.h>

bool ts_is_usable(const struct gsm_bts_trx_ts *ts)
{
	if (!trx_is_usable(ts->trx)) {
		LOGP(DRLL, LOGL_DEBUG, "%s not usable\n", gsm_trx_name(ts->trx));
		return false;
	}

	/* If a TCH/F_PDCH TS is busy changing, it is already taken or not
	 * yet available. */
	if (ts->pchan == GSM_PCHAN_TCH_F_PDCH) {
		if (ts->flags & TS_F_PDCH_PENDING_MASK) {
			LOGP(DRLL, LOGL_DEBUG, "%s in switchover, not available\n",
			     gsm_ts_and_pchan_name(ts));
			return false;
		}
	}

	/* If a dynamic channel is busy changing, it is already taken or not
	 * yet available. */
	if (ts->pchan == GSM_PCHAN_TCH_F_TCH_H_PDCH) {
		if (ts->dyn.pchan_is != ts->dyn.pchan_want) {
			LOGP(DRLL, LOGL_DEBUG, "%s in switchover, not available\n",
			     gsm_ts_and_pchan_name(ts));
			return false;
		}
	}

	return true;
}

bool trx_is_usable(const struct gsm_bts_trx *trx)
{
	/* FIXME: How does this behave for BS-11 ? */
	if (is_ipaccess_bts(trx->bts)) {
		if (!nm_is_running(&trx->mo.nm_state) ||
		    !nm_is_running(&trx->bb_transc.mo.nm_state))
			return false;
	}

	return true;
}

static int trx_count_free_ts(struct gsm_bts_trx *trx, enum gsm_phys_chan_config pchan)
{
	struct gsm_bts_trx_ts *ts;
	int j, ss;
	int count = 0;

	if (!trx_is_usable(trx))
		return 0;

	for (j = 0; j < ARRAY_SIZE(trx->ts); j++) {
		enum gsm_phys_chan_config ts_pchan_is;
		ts = &trx->ts[j];
		if (!ts_is_usable(ts))
			continue;

		ts_pchan_is = ts_pchan(ts);

		if (ts_pchan_is == GSM_PCHAN_PDCH) {
			/* Dynamic timeslots in PDCH mode will become TCH if needed. */
			switch (ts->pchan) {
			case GSM_PCHAN_TCH_F_PDCH:
				if (pchan == GSM_PCHAN_TCH_F)
					count++;
				continue;

			case GSM_PCHAN_TCH_F_TCH_H_PDCH:
				if (pchan == GSM_PCHAN_TCH_F)
					count++;
				else if (pchan == GSM_PCHAN_TCH_H)
					count += 2;
				continue;

			default:
				/* Not dynamic, not applicable. */
				continue;
			}
		}

		if (ts_pchan_is != pchan)
			continue;
		/* check if all sub-slots are allocated yet */
		for (ss = 0; ss < ts_subslots(ts); ss++) {
			struct gsm_lchan *lc = &ts->lchan[ss];
			if (lc->type == GSM_LCHAN_NONE &&
			    lc->state == LCHAN_S_NONE)
				count++;
		}
	}

	return count;
}

/* Count number of free TS of given pchan type */
int bts_count_free_ts(struct gsm_bts *bts, enum gsm_phys_chan_config pchan)
{
	struct gsm_bts_trx *trx;
	int count = 0;

	llist_for_each_entry(trx, &bts->trx_list, list)
		count += trx_count_free_ts(trx, pchan);

	return count;
}

static bool ts_usable_as_pchan(struct gsm_bts_trx_ts *ts,
			       enum gsm_phys_chan_config as_pchan)
{
	switch (ts->pchan) {
	case GSM_PCHAN_TCH_F_PDCH:
		if (ts->flags & TS_F_PDCH_PENDING_MASK) {
			/* currently being switched over. Not usable. */
			return false;
		}
		switch (as_pchan) {
		case GSM_PCHAN_TCH_F:
		case GSM_PCHAN_PDCH:
			/* continue to check below. */
			break;
		default:
			return false;
		}
		break;

	case GSM_PCHAN_TCH_F_TCH_H_PDCH:
		if (ts->dyn.pchan_is != ts->dyn.pchan_want) {
			/* currently being switched over. Not usable. */
			return false;
		}
		switch (as_pchan) {
		case GSM_PCHAN_TCH_F:
		case GSM_PCHAN_TCH_H:
		case GSM_PCHAN_PDCH:
			/* continue to check below. */
			break;
		default:
			return false;
		}
		break;

	default:
		/* static timeslots never switch. */
		return ts->pchan == as_pchan;
	}

	/* Dynamic timeslots -- Checks depending on the current actual pchan mode: */
	switch (ts_pchan(ts)) {
	case GSM_PCHAN_NONE:
		/* Not initialized, possibly because GPRS was disabled. We may switch. */
		return true;

	case GSM_PCHAN_PDCH:
		/* This slot is in PDCH mode and available to switch pchan mode. But check for
		 * error states: */
		if (ts->lchan->state != LCHAN_S_NONE && ts->lchan->state != LCHAN_S_ACTIVE)
			return false;
		return true;

	case GSM_PCHAN_TCH_F:
	case GSM_PCHAN_TCH_H:
		/* No need to switch at all? */
		if (ts_pchan(ts) == as_pchan)
			return true;

		/* If any lchan is in use, we can't change the pchan kind */
		{
			int ss;
			int subslots = ts_subslots(ts);
			for (ss = 0; ss < subslots; ss++) {
				struct gsm_lchan *lc = &ts->lchan[ss];
				if (lc->type != GSM_LCHAN_NONE || lc->state != LCHAN_S_NONE)
					return false;
			}
		}
		return true;

	default:
		/* Not implemented. */
		return false;
	}
}

static struct gsm_lchan *
_lc_find_trx(struct gsm_bts_trx *trx, enum gsm_phys_chan_config pchan,
	     enum gsm_phys_chan_config as_pchan)
{
	struct gsm_bts_trx_ts *ts;
	int j, start, stop, dir, ss;
	int check_subslots;

#define LOGPLCHANALLOC(fmt, args...) \
		LOGP(DRLL, LOGL_DEBUG, "looking for lchan %s as %s: " fmt, \
		     gsm_pchan_name(pchan), gsm_pchan_name(as_pchan), ## args)

	if (!trx_is_usable(trx)) {
		LOGPLCHANALLOC("%s trx not usable\n", gsm_trx_name(trx));
		return NULL;
	}

	if (trx->bts->chan_alloc_reverse) {
		/* check TS 7..0 */
		start = 7;
		stop = -1;
		dir = -1;
	} else {
		/* check TS 0..7 */
		start = 0;
		stop = 8;
		dir = 1;
	}

	for (j = start; j != stop; j += dir) {
		ts = &trx->ts[j];
		if (!ts_is_usable(ts))
			continue;
		/* The caller first selects what kind of TS to search in, e.g. looking for exact
		 * GSM_PCHAN_TCH_F, or maybe among dynamic GSM_PCHAN_TCH_F_TCH_H_PDCH... */
		if (ts->pchan != pchan) {
			LOGPLCHANALLOC("%s is != %s\n", gsm_ts_and_pchan_name(ts),
				       gsm_pchan_name(pchan));
			continue;
		}
		/* Next, is this timeslot in or can it be switched to the pchan we want to use it for? */
		if (!ts_usable_as_pchan(ts, as_pchan)) {
			LOGPLCHANALLOC("%s is not usable as %s\n", gsm_ts_and_pchan_name(ts),
				       gsm_pchan_name(as_pchan));
			continue;
		}
		/* If we need to switch it, after above check we are also allowed to switch it, and we
		 * will always use the first lchan after the switch. Return that lchan and rely on the
		 * caller to perform the pchan switchover. */
		if (ts_pchan(ts) != as_pchan) {
			LOGPLCHANALLOC("%s is a match, will switch to %s\n", gsm_ts_and_pchan_name(ts),
				       gsm_pchan_name(as_pchan));
			return ts->lchan;
		}

		/* TS is in desired pchan mode. Go ahead and check for an available lchan. */
		check_subslots = ts_subslots(ts);
		for (ss = 0; ss < check_subslots; ss++) {
			struct gsm_lchan *lc = &ts->lchan[ss];
			if (lc->type == GSM_LCHAN_NONE &&
			    lc->state == LCHAN_S_NONE) {
				LOGPLCHANALLOC("%s ss=%d is available\n", gsm_ts_and_pchan_name(ts),
					       lc->nr);
				return lc;
			}
			LOGPLCHANALLOC("%s ss=%d in type=%s,state=%s not suitable\n",
				       gsm_ts_and_pchan_name(ts), lc->nr, gsm_lchant_name(lc->type),
				       gsm_lchans_name(lc->state));
		}
	}

	return NULL;
#undef LOGPLCHANALLOC
}

static struct gsm_lchan *
_lc_dyn_find_bts(struct gsm_bts *bts, enum gsm_phys_chan_config pchan,
		 enum gsm_phys_chan_config dyn_as_pchan)
{
	struct gsm_bts_trx *trx;
	struct gsm_lchan *lc;

	if (bts->chan_alloc_reverse) {
		llist_for_each_entry_reverse(trx, &bts->trx_list, list) {
			lc = _lc_find_trx(trx, pchan, dyn_as_pchan);
			if (lc)
				return lc;
		}
	} else {
		llist_for_each_entry(trx, &bts->trx_list, list) {
			lc = _lc_find_trx(trx, pchan, dyn_as_pchan);
			if (lc)
				return lc;
		}
	}

	return NULL;
}

static struct gsm_lchan *
_lc_find_bts(struct gsm_bts *bts, enum gsm_phys_chan_config pchan)
{
	return _lc_dyn_find_bts(bts, pchan, pchan);
}

/* Allocate a logical channel.
 *
 * Dynamic channel types: we always prefer a dedicated TS, and only pick +
 * switch a dynamic TS if no pure TS of the requested PCHAN is available.
 *
 * TCH_F/PDCH: if we pick a PDCH ACT style dynamic TS as TCH/F channel, PDCH
 * will be disabled in rsl_chan_activate_lchan(); there is no need to check
 * whether PDCH mode is currently active, here.
 */
struct gsm_lchan *lchan_alloc(struct gsm_bts *bts, enum gsm_chan_t type,
			      int allow_bigger)
{
	struct gsm_lchan *lchan = NULL;
	enum gsm_phys_chan_config first, first_cbch, second, second_cbch;

	LOGP(DRLL, LOGL_DEBUG, "(bts=%d) lchan_alloc(%s)\n", bts->nr, gsm_lchant_name(type));

	switch (type) {
	case GSM_LCHAN_SDCCH:
		if (bts->chan_alloc_reverse) {
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

		lchan = _lc_find_bts(bts, first);
		if (lchan == NULL)
			lchan = _lc_find_bts(bts, first_cbch);
		if (lchan == NULL)
			lchan = _lc_find_bts(bts, second);
		if (lchan == NULL)
			lchan = _lc_find_bts(bts, second_cbch);

		/* allow to assign bigger channels */
		if (allow_bigger) {
			if (lchan == NULL) {
				lchan = _lc_find_bts(bts, GSM_PCHAN_TCH_H);
				if (lchan)
					type = GSM_LCHAN_TCH_H;
			}

			if (lchan == NULL) {
				lchan = _lc_find_bts(bts, GSM_PCHAN_TCH_F);
				if (lchan)
					type = GSM_LCHAN_TCH_F;
			}

			/* try dynamic TCH/F_PDCH */
			if (lchan == NULL) {
				lchan = _lc_dyn_find_bts(bts, GSM_PCHAN_TCH_F_PDCH,
							 GSM_PCHAN_TCH_F);
				/* TCH/F_PDCH will be used as TCH/F */
				if (lchan)
					type = GSM_LCHAN_TCH_F;
			}

			/* try fully dynamic TCH/F_TCH/H_PDCH */
			if (lchan == NULL) {
				lchan = _lc_dyn_find_bts(bts, GSM_PCHAN_TCH_F_TCH_H_PDCH,
							 GSM_PCHAN_TCH_H);
				if (lchan)
					type = GSM_LCHAN_TCH_H;
			}
			/*
			 * No need to check fully dynamic channels for TCH/F:
			 * if no TCH/H was available, neither will be TCH/F.
			 */
		}
		break;
	case GSM_LCHAN_TCH_F:
		lchan = _lc_find_bts(bts, GSM_PCHAN_TCH_F);
		/* If we don't have TCH/F available, fall-back to TCH/H */
		if (!lchan) {
			lchan = _lc_find_bts(bts, GSM_PCHAN_TCH_H);
			if (lchan)
				type = GSM_LCHAN_TCH_H;
		}
		/* If we don't have TCH/H either, try dynamic TCH/F_PDCH */
		if (!lchan) {
			lchan = _lc_dyn_find_bts(bts, GSM_PCHAN_TCH_F_PDCH,
						 GSM_PCHAN_TCH_F);
			/* TCH/F_PDCH used as TCH/F -- here, type is already
			 * set to GSM_LCHAN_TCH_F, but for clarity's sake... */
			if (lchan)
				type = GSM_LCHAN_TCH_F;
		}

		/* Try fully dynamic TCH/F_TCH/H_PDCH as TCH/F... */
		if (!lchan && bts->network->dyn_ts_allow_tch_f) {
			lchan = _lc_dyn_find_bts(bts,
						 GSM_PCHAN_TCH_F_TCH_H_PDCH,
						 GSM_PCHAN_TCH_F);
			if (lchan)
				type = GSM_LCHAN_TCH_F;
		}
		/* ...and as TCH/H. */
		if (!lchan) {
			lchan = _lc_dyn_find_bts(bts,
						 GSM_PCHAN_TCH_F_TCH_H_PDCH,
						 GSM_PCHAN_TCH_H);
			if (lchan)
				type = GSM_LCHAN_TCH_H;
		}
		break;
	case GSM_LCHAN_TCH_H:
		lchan = _lc_find_bts(bts, GSM_PCHAN_TCH_H);
		/* If we don't have TCH/H available, fall-back to TCH/F */
		if (!lchan) {
			lchan = _lc_find_bts(bts, GSM_PCHAN_TCH_F);
			if (lchan)
				type = GSM_LCHAN_TCH_F;
		}
		/* No dedicated TCH/x available -- try fully dynamic
		 * TCH/F_TCH/H_PDCH */
		if (!lchan) {
			lchan = _lc_dyn_find_bts(bts,
						 GSM_PCHAN_TCH_F_TCH_H_PDCH,
						 GSM_PCHAN_TCH_H);
			if (lchan)
				type = GSM_LCHAN_TCH_H;
		}
		/*
		 * No need to check TCH/F_TCH/H_PDCH channels for TCH/F:
		 * if no TCH/H was available, neither will be TCH/F.
		 */
		/* If we don't have TCH/F either, try dynamic TCH/F_PDCH */
		if (!lchan) {
			lchan = _lc_dyn_find_bts(bts, GSM_PCHAN_TCH_F_PDCH,
						 GSM_PCHAN_TCH_F);
			if (lchan)
				type = GSM_LCHAN_TCH_F;
		}
		break;
	default:
		LOGP(DRLL, LOGL_ERROR, "Unknown gsm_chan_t %u\n", type);
	}

	if (lchan) {
		lchan->type = type;

		LOGP(DRLL, LOGL_INFO, "%s Allocating lchan=%u as %s\n",
		     gsm_ts_and_pchan_name(lchan->ts),
		     lchan->nr, gsm_lchant_name(lchan->type));

		/* reset measurement report counter and index */
	        lchan->meas_rep_count = 0;
	        lchan->meas_rep_idx = 0;
	        lchan->meas_rep_last_seen_nr = 255;

		/* clear sapis */
		memset(lchan->sapis, 0, ARRAY_SIZE(lchan->sapis));

		/* clear multi rate config */
		memset(&lchan->mr_ms_lv, 0, sizeof(lchan->mr_ms_lv));
		memset(&lchan->mr_bts_lv, 0, sizeof(lchan->mr_bts_lv));
		lchan->broken_reason = "";
	} else {
		struct challoc_signal_data sig;

		LOGP(DRLL, LOGL_ERROR, "(bts=%d) Failed to allocate %s channel\n",
		     bts->nr, gsm_lchant_name(type));

		sig.bts = bts;
		sig.type = type;
		osmo_signal_dispatch(SS_CHALLOC, S_CHALLOC_ALLOC_FAIL, &sig);
	}

	return lchan;
}

/* Free a logical channel */
void lchan_free(struct gsm_lchan *lchan)
{
	struct challoc_signal_data sig;
	int i;

	sig.type = lchan->type;
	lchan->type = GSM_LCHAN_NONE;


	if (lchan->conn
	    && !(lchan->ts->pchan == GSM_PCHAN_TCH_F_TCH_H_PDCH
		 && lchan->ts->dyn.pchan_is != lchan->ts->dyn.pchan_want)) {
		struct lchan_signal_data sig;

		/* We might kill an active channel... */
		sig.lchan = lchan;
		sig.mr = NULL;
		osmo_signal_dispatch(SS_LCHAN, S_LCHAN_UNEXPECTED_RELEASE, &sig);
	}

	/* stop the timer */
	osmo_timer_del(&lchan->T3101);

	/* clear cached measuement reports */
	lchan->meas_rep_idx = 0;
	for (i = 0; i < ARRAY_SIZE(lchan->meas_rep); i++) {
		lchan->meas_rep[i].flags = 0;
		lchan->meas_rep[i].nr = 0;
	}
	for (i = 0; i < ARRAY_SIZE(lchan->neigh_meas); i++)
		lchan->neigh_meas[i].arfcn = 0;

	if (lchan->rqd_ref) {
		talloc_free(lchan->rqd_ref);
		lchan->rqd_ref = NULL;
		lchan->rqd_ta = 0;
	}

	sig.lchan = lchan;
	sig.bts = lchan->ts->trx->bts;
	osmo_signal_dispatch(SS_CHALLOC, S_CHALLOC_FREED, &sig);

	if (lchan->conn
	    && !(lchan->ts->pchan == GSM_PCHAN_TCH_F_TCH_H_PDCH
		 && lchan->ts->dyn.pchan_is != lchan->ts->dyn.pchan_want)) {
		LOGP(DRLL, LOGL_ERROR, "the subscriber connection should be gone.\n");
		lchan->conn = NULL;
	}

	/* FIXME: ts_free() the timeslot, if we're the last logical
	 * channel using it */
}

/*
 * There was an error with the TRX and we need to forget
 * any state so that a lchan can be allocated again after
 * the trx is fully usable.
 *
 * This should be called after lchan_free to force a channel
 * be available for allocation again. This means that this
 * method will stop the "delay after error"-timer and set the
 * state to LCHAN_S_NONE.
 */
void lchan_reset(struct gsm_lchan *lchan)
{
	osmo_timer_del(&lchan->T3101);
	osmo_timer_del(&lchan->T3109);
	osmo_timer_del(&lchan->T3111);
	osmo_timer_del(&lchan->error_timer);

	lchan->type = GSM_LCHAN_NONE;
	rsl_lchan_set_state(lchan, LCHAN_S_NONE);
}

/* Drive the release process of the lchan */
static void _lchan_handle_release(struct gsm_lchan *lchan,
				  int sacch_deact, int mode)
{
	/* Release all SAPIs on the local end and continue */
	rsl_release_sapis_from(lchan, 1, RSL_REL_LOCAL_END);

	/*
	 * Shall we send a RR Release, start T3109 and wait for the
	 * release indication from the BTS or just take it down (e.g.
	 * on assignment requests)
	 */
	if (sacch_deact) {
		gsm48_send_rr_release(lchan);

		/* Deactivate the SACCH on the BTS side */
		rsl_deact_sacch(lchan);
		rsl_start_t3109(lchan);
	} else if (lchan->sapis[0] == LCHAN_SAPI_UNUSED) {
		rsl_direct_rf_release(lchan);
	} else {
		rsl_release_request(lchan, 0, mode);
	}
}

/* Consider releasing the channel now */
int lchan_release(struct gsm_lchan *lchan, int sacch_deact, enum rsl_rel_mode mode)
{
	DEBUGP(DRLL, "%s starting release sequence\n", gsm_lchan_name(lchan));
	rsl_lchan_set_state(lchan, LCHAN_S_REL_REQ);

	lchan->conn = NULL;
	_lchan_handle_release(lchan, sacch_deact, mode);
	return 1;
}

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
			struct load_counter *pl = &cl->pchan[ts->pchan];
			int j;
			int subslots;

			/* skip administratively deactivated timeslots */
			if (!nm_is_running(&ts->mo.nm_state))
				continue;

			subslots = ts_subslots(ts);
			for (j = 0; j < subslots; j++) {
				struct gsm_lchan *lchan = &ts->lchan[j];

				pl->total++;

				switch (lchan->state) {
				case LCHAN_S_NONE:
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
