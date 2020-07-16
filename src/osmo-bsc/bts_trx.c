/* (C) 2008-2018 by Harald Welte <laforge@gnumonks.org>
 * (C) 2020 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
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

#include <osmocom/gsm/abis_nm.h>

#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/bts.h>
#include <osmocom/bsc/bts_trx.h>
#include <osmocom/bsc/timeslot_fsm.h>
#include <osmocom/bsc/abis_nm.h>
#include <osmocom/bsc/lchan_fsm.h>
#include <osmocom/bsc/debug.h>

struct gsm_bts_trx *gsm_bts_trx_alloc(struct gsm_bts *bts)
{
	struct gsm_bts_trx *trx = talloc_zero(bts, struct gsm_bts_trx);
	int k;

	if (!trx)
		return NULL;

	trx->bts = bts;
	trx->nr = bts->num_trx++;
	trx->mo.nm_state.administrative = NM_STATE_UNLOCKED;

	gsm_mo_init(&trx->mo, bts, NM_OC_RADIO_CARRIER,
		    bts->nr, trx->nr, 0xff);
	gsm_mo_init(&trx->bb_transc.mo, bts, NM_OC_BASEB_TRANSC,
		    bts->nr, trx->nr, 0xff);

	for (k = 0; k < TRX_NR_TS; k++) {
		struct gsm_bts_trx_ts *ts = &trx->ts[k];
		int l;


		ts->trx = trx;
		ts->nr = k;
		ts->pchan_from_config = ts->pchan_on_init = ts->pchan_is = GSM_PCHAN_NONE;
		ts->tsc = -1;

		ts_fsm_alloc(ts);

		gsm_mo_init(&ts->mo, bts, NM_OC_CHANNEL,
			    bts->nr, trx->nr, ts->nr);

		ts->hopping.arfcns.data_len = sizeof(ts->hopping.arfcns_data);
		ts->hopping.arfcns.data = ts->hopping.arfcns_data;
		ts->hopping.ma.data_len = sizeof(ts->hopping.ma_data);
		ts->hopping.ma.data = ts->hopping.ma_data;

		for (l = 0; l < TS_MAX_LCHAN; l++) {
			struct gsm_lchan *lchan;
			char *name;
			lchan = &ts->lchan[l];

			lchan->ts = ts;
			lchan->nr = l;
			lchan->type = GSM_LCHAN_NONE;

			name = gsm_lchan_name_compute(lchan);
			lchan->name = talloc_strdup(trx, name);
		}
	}

	if (trx->nr != 0)
		trx->nominal_power = bts->c0->nominal_power;

	llist_add_tail(&trx->list, &bts->trx_list);

	return trx;
}

static char ts2str[255];

char *gsm_trx_name(const struct gsm_bts_trx *trx)
{
	if (!trx)
		snprintf(ts2str, sizeof(ts2str), "(trx=NULL)");
	else
		snprintf(ts2str, sizeof(ts2str), "(bts=%d,trx=%d)",
			 trx->bts->nr, trx->nr);

	return ts2str;
}

/* determine logical channel based on TRX and channel number IE */
struct gsm_lchan *rsl_lchan_lookup(struct gsm_bts_trx *trx, uint8_t chan_nr,
				   int *rc)
{
	uint8_t ts_nr = chan_nr & 0x07;
	uint8_t cbits = chan_nr >> 3;
	uint8_t lch_idx;
	struct gsm_bts_trx_ts *ts = &trx->ts[ts_nr];
	bool ok;

	if (rc)
		*rc = -EINVAL;

	if (cbits == 0x01) {
		lch_idx = 0;	/* TCH/F */
		ok = ts_is_capable_of_pchan(ts, GSM_PCHAN_TCH_F)
			|| ts->pchan_on_init == GSM_PCHAN_PDCH; /* PDCH? really? */
	} else if ((cbits & 0x1e) == 0x02) {
		lch_idx = cbits & 0x1;	/* TCH/H */
		ok = ts_is_capable_of_pchan(ts, GSM_PCHAN_TCH_H);
	} else if ((cbits & 0x1c) == 0x04) {
		lch_idx = cbits & 0x3;	/* SDCCH/4 */
		ok = ts_is_capable_of_pchan(ts, GSM_PCHAN_CCCH_SDCCH4);
	} else if ((cbits & 0x18) == 0x08) {
		lch_idx = cbits & 0x7;	/* SDCCH/8 */
		ok = ts_is_capable_of_pchan(ts, GSM_PCHAN_SDCCH8_SACCH8C);
	} else if (cbits == 0x10 || cbits == 0x11 || cbits == 0x12) {
		lch_idx = 0; /* CCCH? */
		ok = ts_is_capable_of_pchan(ts, GSM_PCHAN_CCCH);
		/* FIXME: we should not return first sdcch4 !!! */
	} else if ((chan_nr & RSL_CHAN_NR_MASK) == RSL_CHAN_OSMO_PDCH) {
		lch_idx = 0;
		ok = (ts->pchan_on_init == GSM_PCHAN_TCH_F_TCH_H_PDCH);
	} else
		return NULL;

	if (rc && ok)
		*rc = 0;

	return &ts->lchan[lch_idx];
}

void gsm_trx_lock_rf(struct gsm_bts_trx *trx, bool locked, const char *reason)
{
	uint8_t new_state = locked ? NM_STATE_LOCKED : NM_STATE_UNLOCKED;


	if (!trx->bts || !trx->bts->oml_link) {
		/* Set initial state which will be sent when BTS connects. */
		trx->mo.nm_state.administrative = new_state;
		return;
	}

	LOG_TRX(trx, DNM, LOGL_NOTICE, "Requesting administrative state change %s -> %s [%s]\n",
	     get_value_string(abis_nm_adm_state_names, trx->mo.nm_state.administrative),
	     get_value_string(abis_nm_adm_state_names, new_state), reason);

	abis_nm_chg_adm_state(trx->bts, NM_OC_RADIO_CARRIER,
			      trx->bts->bts_nr, trx->nr, 0xff,
			      new_state);
}

bool trx_is_usable(const struct gsm_bts_trx *trx)
{
	/* FIXME: How does this behave for BS-11 ? */
	if (is_ipaccess_bts(trx->bts)) {
		if (!nm_is_running(&trx->mo.nm_state) ||
		    !nm_is_running(&trx->bb_transc.mo.nm_state))
			return false;
	} else if (is_ericsson_bts(trx->bts)) {
		/* The OM2000 -> 12.21 mapping we do doesn't have separate bb_transc MO */
		if (!nm_is_running(&trx->mo.nm_state))
			return false;
	}

	return true;
}


void gsm_trx_all_ts_dispatch(struct gsm_bts_trx *trx, uint32_t ts_ev, void *data)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(trx->ts); i++) {
		struct gsm_bts_trx_ts *ts = &trx->ts[i];
		osmo_fsm_inst_dispatch(ts->fi, ts_ev, data);
	}
}

int trx_count_free_ts(struct gsm_bts_trx *trx, enum gsm_phys_chan_config pchan)
{
	struct gsm_bts_trx_ts *ts;
	struct gsm_lchan *lchan;
	int j;
	int count = 0;

	if (!trx_is_usable(trx))
		return 0;

	for (j = 0; j < ARRAY_SIZE(trx->ts); j++) {
		ts = &trx->ts[j];
		if (!ts_is_usable(ts))
			continue;

		if (ts->pchan_is == GSM_PCHAN_PDCH) {
			/* Dynamic timeslots in PDCH mode will become TCH if needed. */
			switch (ts->pchan_on_init) {
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

		if (ts->pchan_is != pchan)
			continue;

		ts_for_each_lchan(lchan, ts) {
			if (lchan_state_is(lchan, LCHAN_ST_UNUSED))
				count++;
		}
	}

	return count;
}

bool trx_has_valid_pchan_config(const struct gsm_bts_trx *trx)
{
	bool combined = false;
	bool result = true;
	unsigned int i;

	/* Iterate over all timeslots */
	for (i = 0; i < 8; i++) {
		const struct gsm_bts_trx_ts *ts = &trx->ts[i];

		switch (ts->pchan_from_config) {
		case GSM_PCHAN_CCCH_SDCCH4_CBCH:
		case GSM_PCHAN_CCCH_SDCCH4:
			/* CCCH+SDCCH4 can only be configured on TS0 */
			if (i > 0) {
				LOGP(DNM, LOGL_ERROR, "Combined CCCH is not allowed "
						      "on TS%u > 0\n", i);
				result = false;
			}
			if (i == 0)
				combined = true;
			/* fall-through */
		case GSM_PCHAN_CCCH:
			/* 3GPP TS 45.002, Table 3, CCCH: TS (0, 2, 4, 6) */
			if (i % 2 != 0) {
				LOGP(DNM, LOGL_ERROR, "%s is not allowed on odd TS%u\n",
				     gsm_pchan_name(ts->pchan_from_config), i);
				result = false;
			}

			/* There can be no more CCCHs if TS0/C0 is combined */
			if (i > 0 && combined) {
				LOGP(DNM, LOGL_ERROR, "%s is not allowed on TS%u, "
				     "because TS0 is using combined channel configuration\n",
				     gsm_pchan_name(ts->pchan_from_config), i);
				result = false;
			}
			break;

		default:
			/* CCCH on TS0 is mandatory for C0 */
			if (trx->bts->c0 == trx && i == 0) {
				LOGP(DNM, LOGL_ERROR, "TS0 on C0 must be CCCH/BCCH\n");
				result = false;
			}
		}
	}

	return result;
}
