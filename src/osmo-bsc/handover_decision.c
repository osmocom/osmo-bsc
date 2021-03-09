/* Handover Decision making for Inter-BTS (Intra-BSC) Handover.  This
 * only implements the handover algorithm/decision, but not execution
 * of it */

/* (C) 2009 by Harald Welte <laforge@gnumonks.org>
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
#include <errno.h>

#include <osmocom/core/msgb.h>
#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/meas_rep.h>
#include <osmocom/bsc/signal.h>
#include <osmocom/core/talloc.h>
#include <osmocom/gsm/gsm_utils.h>

#include <osmocom/bsc/handover_fsm.h>
#include <osmocom/bsc/handover_cfg.h>
#include <osmocom/bsc/bts.h>

/* did we get a RXLEV for a given cell in the given report? */
static int rxlev_for_cell_in_rep(struct gsm_meas_rep *mr,
				 uint16_t arfcn, uint8_t bsic)
{
	int i;

	for (i = 0; i < mr->num_cell; i++) {
		struct gsm_meas_rep_cell *mrc = &mr->cell[i];

		/* search for matching report */
		if (!(mrc->arfcn == arfcn && mrc->bsic == bsic))
			continue;

		mrc->flags |= MRC_F_PROCESSED;
		return mrc->rxlev;
	}
	return -ENODEV;
}

/* obtain averaged rxlev for given neighbor */
static int neigh_meas_avg(struct neigh_meas_proc *nmp, int window)
{
	unsigned int i, idx;
	int avg = 0;

	/* reduce window to the actual number of existing measurements */
	if (window > nmp->rxlev_cnt)
		window = nmp->rxlev_cnt;
	/* this should never happen */
	if (window <= 0) {
		LOGP(DHODEC, LOGL_ERROR, "Requested Neighbor RxLev for invalid window size of %d\n", window);
		return 0;
	}

	idx = calc_initial_idx(ARRAY_SIZE(nmp->rxlev),
				nmp->rxlev_cnt % ARRAY_SIZE(nmp->rxlev),
				window);

	for (i = 0; i < window; i++) {
		int j = (idx+i) % ARRAY_SIZE(nmp->rxlev);

		avg += nmp->rxlev[j];
	}

	return avg / window;
}

/* find empty or evict bad neighbor */
static struct neigh_meas_proc *find_evict_neigh(struct gsm_lchan *lchan)
{
	int j, worst = 999999;
	struct neigh_meas_proc *nmp_worst = NULL;

	/* first try to find an empty/unused slot */
	for (j = 0; j < ARRAY_SIZE(lchan->neigh_meas); j++) {
		struct neigh_meas_proc *nmp = &lchan->neigh_meas[j];
		if (!nmp->arfcn)
			return nmp;
	}

	/* no empty slot found. evict worst neighbor from list */
	for (j = 0; j < ARRAY_SIZE(lchan->neigh_meas); j++) {
		struct neigh_meas_proc *nmp = &lchan->neigh_meas[j];
		int avg = neigh_meas_avg(nmp, MAX_WIN_NEIGH_AVG);
		if (!nmp_worst || avg < worst) {
			worst = avg;
			nmp_worst = nmp;
		}
	}

	return nmp_worst;
}

/* process neighbor cell measurement reports */
static void process_meas_neigh(struct gsm_meas_rep *mr)
{
	int i, j, idx;

	/* for each reported cell, try to update global state */
	for (j = 0; j < ARRAY_SIZE(mr->lchan->neigh_meas); j++) {
		struct neigh_meas_proc *nmp = &mr->lchan->neigh_meas[j];
		unsigned int idx;
		int rxlev;

		/* skip unused entries */
		if (!nmp->arfcn)
			continue;

		rxlev = rxlev_for_cell_in_rep(mr, nmp->arfcn, nmp->bsic);
		idx = nmp->rxlev_cnt % ARRAY_SIZE(nmp->rxlev);
		if (rxlev >= 0) {
			nmp->rxlev[idx] = rxlev;
			nmp->last_seen_nr = mr->nr;
		} else
			nmp->rxlev[idx] = 0;
		nmp->rxlev_cnt++;
	}

	/* iterate over list of reported cells, check if we did not
	 * process all of them */
	for (i = 0; i < mr->num_cell; i++) {
		struct gsm_meas_rep_cell *mrc = &mr->cell[i];
		struct neigh_meas_proc *nmp;

		if (mrc->flags & MRC_F_PROCESSED)
			continue;

		nmp = find_evict_neigh(mr->lchan);

		nmp->arfcn = mrc->arfcn;
		nmp->bsic = mrc->bsic;

		nmp->rxlev_cnt = 0;
		idx = nmp->rxlev_cnt % ARRAY_SIZE(nmp->rxlev);
		nmp->rxlev[idx] = mrc->rxlev;
		nmp->rxlev_cnt++;
		nmp->last_seen_nr = mr->nr;

		mrc->flags |= MRC_F_PROCESSED;
	}
}

/* attempt to do a handover */
static void attempt_handover(struct gsm_meas_rep *mr)
{
	struct handover_out_req req;
	struct gsm_bts *bts = mr->lchan->ts->trx->bts;
	struct neigh_meas_proc *best_cell = NULL;
	unsigned int best_better_db = 0;
	int i;

	if (!ho_get_ho_active(bts->ho))
		return;

	/* find the best cell in this report that is at least RXLEV_HYST
	 * better than the current serving cell */

	for (i = 0; i < ARRAY_SIZE(mr->lchan->neigh_meas); i++) {
		struct neigh_meas_proc *nmp = &mr->lchan->neigh_meas[i];
		int avg, better;

		/* skip empty slots */
		if (nmp->arfcn == 0)
			continue;

		/* calculate average rxlev for this cell over the window */
		avg = neigh_meas_avg(nmp, ho_get_hodec1_rxlev_neigh_avg_win(bts->ho));

		/* check if hysteresis is fulfilled */
		if (avg < mr->dl.full.rx_lev + ho_get_hodec1_pwr_hysteresis(bts->ho))
			continue;

		better = avg - mr->dl.full.rx_lev;
		if (better > best_better_db) {
			best_cell = nmp;
			best_better_db = better;
		}
	}

	if (!best_cell)
		return;

	req = (struct handover_out_req){
		.from_hodec_id = HODEC1,
		.old_lchan = mr->lchan,
		.target_cell_ab = {
			.arfcn = best_cell->arfcn,
			.bsic = best_cell->bsic,
		},
	};
	handover_request(&req);
}

/* process an already parsed measurement report and decide if we want to
 * attempt a handover */
static void on_measurement_report(struct gsm_meas_rep *mr)
{
	struct gsm_bts *bts = mr->lchan->ts->trx->bts;
	enum meas_rep_field dlev, dqual;
	int av_rxlev;
	unsigned int pwr_interval;

	/* If this cell does not use handover algorithm 1, then we're not responsible. */
	if (ho_get_algorithm(bts->ho) != 1)
		return;

	/* we currently only do handover for TCH channels */
	switch (mr->lchan->type) {
	case GSM_LCHAN_TCH_F:
	case GSM_LCHAN_TCH_H:
		break;
	default:
		return;
	}

	if (mr->flags & MEAS_REP_F_DL_DTX) {
		dlev = MEAS_REP_DL_RXLEV_SUB;
		dqual = MEAS_REP_DL_RXQUAL_SUB;
	} else {
		dlev = MEAS_REP_DL_RXLEV_FULL;
		dqual = MEAS_REP_DL_RXQUAL_FULL;
	}

	/* parse actual neighbor cell info */
	if (mr->num_cell > 0 && mr->num_cell < 7)
		process_meas_neigh(mr);

	av_rxlev = get_meas_rep_avg(mr->lchan, dlev,
				    ho_get_hodec1_rxlev_avg_win(bts->ho));

	/* Interference HO */
	if (rxlev2dbm(av_rxlev) > -85 &&
	    meas_rep_n_out_of_m_be(mr->lchan, dqual, 3, 4, 5)) {
		LOGPC(DHO, LOGL_INFO, "HO cause: Interference HO av_rxlev=%d dBm\n",
		      rxlev2dbm(av_rxlev));
		attempt_handover(mr);
		return;
	}

	/* Bad Quality */
	if (meas_rep_n_out_of_m_be(mr->lchan, dqual, 3, 4, 5)) {
		LOGPC(DHO, LOGL_INFO, "HO cause: Bad Quality av_rxlev=%d dBm\n", rxlev2dbm(av_rxlev));
		attempt_handover(mr);
		return;
	}

	/* Low Level */
	if (rxlev2dbm(av_rxlev) <= -110) {
		LOGPC(DHO, LOGL_INFO, "HO cause: Low Level av_rxlev=%d dBm\n", rxlev2dbm(av_rxlev));
		attempt_handover(mr);
		return;
	}

	/* Distance */
	if (mr->ms_l1.ta > ho_get_hodec1_max_distance(bts->ho)) {
		LOGPC(DHO, LOGL_INFO, "HO cause: Distance av_rxlev=%d dBm ta=%d \n",
					rxlev2dbm(av_rxlev), mr->ms_l1.ta);
		attempt_handover(mr);
		return;
	}

	/* Power Budget AKA Better Cell */
	pwr_interval = ho_get_hodec1_pwr_interval(bts->ho);
	/* handover_cfg.h defines pwr_interval as [1..99], but since we're using it in a modulo below,
	 * assert non-zero to clarify. */
	OSMO_ASSERT(pwr_interval);
	if ((mr->nr % pwr_interval) == pwr_interval - 1)
		attempt_handover(mr);
}

struct handover_decision_callbacks hodec1_callbacks = {
	.hodec_id = HODEC1,
	.on_measurement_report = on_measurement_report,
};

void handover_decision_1_init(void)
{
	handover_decision_callbacks_register(&hodec1_callbacks);
}
