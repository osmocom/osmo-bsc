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
#include <osmocom/bsc/abis_rsl.h>
#include <osmocom/bsc/lchan_fsm.h>
#include <osmocom/bsc/system_information.h>
#include <osmocom/bsc/pcu_if.h>
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

static int rsl_si(struct gsm_bts_trx *trx, enum osmo_sysinfo_type i, int si_len)
{
	struct gsm_bts *bts = trx->bts;
	int rc, j;

	if (si_len) {
		DEBUGP(DRR, "SI%s: %s\n", get_value_string(osmo_sitype_strs, i),
			osmo_hexdump(GSM_BTS_SI(bts, i), GSM_MACBLOCK_LEN));
	} else
		DEBUGP(DRR, "SI%s: OFF\n", get_value_string(osmo_sitype_strs, i));

	switch (i) {
	case SYSINFO_TYPE_5:
	case SYSINFO_TYPE_5bis:
	case SYSINFO_TYPE_5ter:
	case SYSINFO_TYPE_6:
		rc = rsl_sacch_filling(trx, osmo_sitype2rsl(i),
				       si_len ? GSM_BTS_SI(bts, i) : NULL, si_len);
		break;
	case SYSINFO_TYPE_2quater:
		if (si_len == 0) {
			rc = rsl_bcch_info(trx, i, NULL, 0);
			break;
		}
		rc = 0;
		for (j = 0; j <= bts->si2q_count; j++)
			rc = rsl_bcch_info(trx, i, (const uint8_t *)GSM_BTS_SI2Q(bts, j), GSM_MACBLOCK_LEN);
		break;
	default:
		rc = rsl_bcch_info(trx, i, si_len ? GSM_BTS_SI(bts, i) : NULL, si_len);
		break;
	}

	return rc;
}

/* set all system information types for a TRX */
int gsm_bts_trx_set_system_infos(struct gsm_bts_trx *trx)
{
	int i, rc;
	struct gsm_bts *bts = trx->bts;
	uint8_t gen_si[_MAX_SYSINFO_TYPE], n_si = 0, n;
	int si_len[_MAX_SYSINFO_TYPE];

	bts->si_common.cell_sel_par.ms_txpwr_max_ccch =
			ms_pwr_ctl_lvl(bts->band, bts->ms_max_power);
	bts->si_common.cell_sel_par.neci = bts->network->neci;

	/* Zero/forget the state of the dynamically computed SIs, leeping the static ones */
	bts->si_valid = bts->si_mode_static;

	/* First, we determine which of the SI messages we actually need */

	if (trx == bts->c0) {
		/* 1...4 are always present on a C0 TRX */
		gen_si[n_si++] = SYSINFO_TYPE_1;
		gen_si[n_si++] = SYSINFO_TYPE_2;
		gen_si[n_si++] = SYSINFO_TYPE_2bis;
		gen_si[n_si++] = SYSINFO_TYPE_2ter;
		gen_si[n_si++] = SYSINFO_TYPE_2quater;
		gen_si[n_si++] = SYSINFO_TYPE_3;
		gen_si[n_si++] = SYSINFO_TYPE_4;

		/* 13 is always present on a C0 TRX of a GPRS BTS */
		if (bts->gprs.mode != BTS_GPRS_NONE)
			gen_si[n_si++] = SYSINFO_TYPE_13;
	}

	/* 5 and 6 are always present on every TRX */
	gen_si[n_si++] = SYSINFO_TYPE_5;
	gen_si[n_si++] = SYSINFO_TYPE_5bis;
	gen_si[n_si++] = SYSINFO_TYPE_5ter;
	gen_si[n_si++] = SYSINFO_TYPE_6;

	/* Second, we generate the selected SI via RSL */

	for (n = 0; n < n_si; n++) {
		i = gen_si[n];
		/* Only generate SI if this SI is not in "static" (user-defined) mode */
		if (!(bts->si_mode_static & (1 << i))) {
			/* Set SI as being valid. gsm_generate_si() might unset
			 * it, if SI is not required. */
			bts->si_valid |= (1 << i);
			rc = gsm_generate_si(bts, i);
			if (rc < 0)
				goto err_out;
			si_len[i] = rc;
		} else {
			if (i == SYSINFO_TYPE_5 || i == SYSINFO_TYPE_5bis
			 || i == SYSINFO_TYPE_5ter)
				si_len[i] = 18;
			else if (i == SYSINFO_TYPE_6)
				si_len[i] = 11;
			else
				si_len[i] = 23;
		}
	}

	/* Third, we send the selected SI via RSL */

	for (n = 0; n < n_si; n++) {
		i = gen_si[n];
		/* 3GPP TS 08.58 §8.5.1 BCCH INFORMATION. If we don't currently
		 * have this SI, we send a zero-length RSL BCCH FILLING /
		 * SACCH FILLING in order to deactivate the SI, in case it
		 * might have previously been active */
		if (!GSM_BTS_HAS_SI(bts, i)) {
			if (bts->si_unused_send_empty)
				rc = rsl_si(trx, i, 0);
			else
				rc = 0; /* some nanoBTS fw don't like receiving empty unsupported SI */
		} else
			rc = rsl_si(trx, i, si_len[i]);
		if (rc < 0)
			return rc;
	}

	/* Make sure the PCU is aware (in case anything GPRS related has
	 * changed in SI */
	pcu_info_update(bts);

	return 0;
err_out:
	LOGP(DRR, LOGL_ERROR, "Cannot generate SI%s for BTS %u: error <%s>, "
	     "most likely a problem with neighbor cell list generation\n",
	     get_value_string(osmo_sitype_strs, i), bts->nr, strerror(-rc));
	return rc;
}
