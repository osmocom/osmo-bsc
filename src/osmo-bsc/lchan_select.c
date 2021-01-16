/* Select a suitable lchan from a given cell.
 *
 * (C) 2008 by Harald Welte <laforge@gnumonks.org>
 * (C) 2008, 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2018 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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

#include <osmocom/bsc/debug.h>

#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/timeslot_fsm.h>
#include <osmocom/bsc/lchan_fsm.h>

#include <osmocom/bsc/lchan_select.h>
#include <osmocom/bsc/bts.h>

static struct gsm_lchan *
_lc_find_trx(struct gsm_bts_trx *trx, enum gsm_phys_chan_config pchan,
	     enum gsm_phys_chan_config as_pchan, bool allow_pchan_switch, bool log)
{
	struct gsm_lchan *lchan;
	struct gsm_bts_trx_ts *ts;
	int j, start, stop, dir;

#define LOGPLCHANALLOC(fmt, args...) \
	if (log) \
		LOGP(DRLL, LOGL_DEBUG, "looking for lchan %s%s%s%s: " fmt, \
		     gsm_pchan_name(pchan), \
		     pchan == as_pchan ? "" : " as ", \
		     pchan == as_pchan ? "" : gsm_pchan_name(as_pchan), \
		     ((pchan != as_pchan) && !allow_pchan_switch) ? " without pchan switch" : "", \
		     ## args)

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
		ts_as_pchan_for_each_lchan(lchan, ts, as_pchan) {
			if (lchan->fi->state == LCHAN_ST_UNUSED) {
				LOGPLCHANALLOC("%s ss=%d is available%s\n",
					       gsm_ts_and_pchan_name(ts), lchan->nr,
					       ts->pchan_is != as_pchan ? " after dyn PCHAN change" : "");
				return lchan;
			}
			LOGPLCHANALLOC("%s ss=%d in type=%s,state=%s not suitable\n",
				       gsm_ts_and_pchan_name(ts), lchan->nr,
				       gsm_lchant_name(lchan->type),
				       osmo_fsm_inst_state_name(lchan->fi));
		}
	}

	return NULL;
#undef LOGPLCHANALLOC
}

static struct gsm_lchan *
_lc_dyn_find_bts(struct gsm_bts *bts, enum gsm_phys_chan_config pchan,
		 enum gsm_phys_chan_config dyn_as_pchan, bool log)
{
	struct gsm_bts_trx *trx;
	struct gsm_lchan *lc;
	int allow_pchan_switch;
	bool try_pchan_switch;

	/* First find an lchan that needs no change in its timeslot pchan mode.
	 * In particular, this ensures that handover to a dynamic timeslot in TCH/H favors timeslots that are currently
	 * using only one of two TCH/H, so that we don't switch more dynamic timeslots to TCH/H than necessary.
	 * For non-dynamic timeslots, it is not necessary to do a second pass with allow_pchan_switch ==
	 * true, because they never switch anyway. */
	try_pchan_switch = (pchan != dyn_as_pchan);
	for (allow_pchan_switch = 0; allow_pchan_switch <= (try_pchan_switch ? 1 : 0); allow_pchan_switch++) {
		if (bts->chan_alloc_reverse) {
			llist_for_each_entry_reverse(trx, &bts->trx_list, list) {
				lc = _lc_find_trx(trx, pchan, dyn_as_pchan, (bool)allow_pchan_switch, log);
				if (lc)
					return lc;
			}
		} else {
			llist_for_each_entry(trx, &bts->trx_list, list) {
				lc = _lc_find_trx(trx, pchan, dyn_as_pchan, (bool)allow_pchan_switch, log);
				if (lc)
					return lc;
			}
		}
	}

	return NULL;
}

static struct gsm_lchan *
_lc_find_bts(struct gsm_bts *bts, enum gsm_phys_chan_config pchan, bool log)
{
	return _lc_dyn_find_bts(bts, pchan, pchan, log);
}

struct gsm_lchan *lchan_select_by_chan_mode(struct gsm_bts *bts,
					    enum gsm48_chan_mode chan_mode, enum channel_rate chan_rate)
{
	enum gsm_chan_t type;

	switch (chan_mode) {
	case GSM48_CMODE_SIGN:
		switch (chan_rate) {
		case CH_RATE_SDCCH: type = GSM_LCHAN_SDCCH; break;
		case CH_RATE_HALF:  type = GSM_LCHAN_TCH_H; break;
		case CH_RATE_FULL:  type = GSM_LCHAN_TCH_F; break;
		default: return NULL;
		}
		break;
	case GSM48_CMODE_SPEECH_EFR:
		/* EFR works over FR channels only */
		if (chan_rate != CH_RATE_FULL)
			return NULL;
		/* fall through */
	case GSM48_CMODE_SPEECH_V1:
	case GSM48_CMODE_SPEECH_AMR:
		switch (chan_rate) {
		case CH_RATE_HALF:  type = GSM_LCHAN_TCH_H; break;
		case CH_RATE_FULL:  type = GSM_LCHAN_TCH_F; break;
		default: return NULL;
		}
		break;
	default:
		return NULL;
	}

	return lchan_select_by_type(bts, type);
}

struct gsm_lchan *lchan_avail_by_type(struct gsm_bts *bts, enum gsm_chan_t type, bool log)
{
	struct gsm_lchan *lchan = NULL;
	enum gsm_phys_chan_config first, first_cbch, second, second_cbch;

	if (log)
		LOG_BTS(bts, DRLL, LOGL_DEBUG, "lchan_avail_by_type(%s)\n", gsm_lchant_name(type));

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

		lchan = _lc_find_bts(bts, first, log);
		if (lchan == NULL)
			lchan = _lc_find_bts(bts, first_cbch, log);
		if (lchan == NULL)
			lchan = _lc_find_bts(bts, second, log);
		if (lchan == NULL)
			lchan = _lc_find_bts(bts, second_cbch, log);
		break;
	case GSM_LCHAN_TCH_F:
		lchan = _lc_find_bts(bts, GSM_PCHAN_TCH_F, log);
		/* If we don't have TCH/F available, try dynamic TCH/F_PDCH */
		if (!lchan) {
			lchan = _lc_dyn_find_bts(bts, GSM_PCHAN_TCH_F_PDCH,
						 GSM_PCHAN_TCH_F, log);
			/* TCH/F_PDCH used as TCH/F -- here, type is already
			 * set to GSM_LCHAN_TCH_F, but for clarity's sake... */
			if (lchan)
				type = GSM_LCHAN_TCH_F;
		}

		/* Try fully dynamic TCH/F_TCH/H_PDCH as TCH/F... */
		if (!lchan && bts->network->dyn_ts_allow_tch_f) {
			lchan = _lc_dyn_find_bts(bts,
						 GSM_PCHAN_TCH_F_TCH_H_PDCH,
						 GSM_PCHAN_TCH_F, log);
			if (lchan)
				type = GSM_LCHAN_TCH_F;
		}
		break;
	case GSM_LCHAN_TCH_H:
		lchan = _lc_find_bts(bts, GSM_PCHAN_TCH_H, log);
		/* No dedicated TCH/x available -- try fully dynamic
		 * TCH/F_TCH/H_PDCH */
		if (!lchan) {
			lchan = _lc_dyn_find_bts(bts,
						 GSM_PCHAN_TCH_F_TCH_H_PDCH,
						 GSM_PCHAN_TCH_H, log);
			if (lchan)
				type = GSM_LCHAN_TCH_H;
		}
		break;
	default:
		LOG_BTS(bts, DRLL, LOGL_ERROR, "Unknown gsm_chan_t %u\n", type);
	}

	return lchan;
}

/* Return a matching lchan from a specific BTS that is currently available. The next logical step is
 * lchan_activate() on it, which would possibly cause dynamic timeslot pchan switching, taken care of by
 * the lchan and timeslot FSMs. */
struct gsm_lchan *lchan_select_by_type(struct gsm_bts *bts, enum gsm_chan_t type)
{
	struct gsm_lchan *lchan = NULL;

	lchan = lchan_avail_by_type(bts, type, true);

	LOG_BTS(bts, DRLL, LOGL_DEBUG, "lchan_select_by_type(%s)\n", gsm_lchant_name(type));

	if (lchan) {
		lchan->type = type;
		LOG_LCHAN(lchan, LOGL_INFO, "Selected\n");
	} else
		LOG_BTS(bts, DRLL, LOGL_NOTICE, "Failed to select %s channel\n",
			gsm_lchant_name(type));

	return lchan;
}
