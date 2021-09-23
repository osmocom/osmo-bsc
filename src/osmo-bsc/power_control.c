/* MS Power Control Loop L1 */

/* (C) 2014 by Holger Hans Peter Freyther
 * (C) 2020-2021 by sysmocom - s.m.f.c. GmbH <info@sysmocom.de>
 * Author: Vadim Yanitskiy <vyanitskiy@sysmocom.de>
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
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>

#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/bts.h>
#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/bsc_subscriber.h>
#include <osmocom/bsc/abis_rsl.h>
#include <osmocom/bsc/meas_rep.h>
#include <osmocom/bsc/power_control.h>

/* We don't want to deal with floating point, so we scale up */
#define EWMA_SCALE_FACTOR 100
/* EWMA_SCALE_FACTOR/2 = +50: Round to nearest value when downscaling, otherwise floor() is applied. */
#define EWMA_ROUND_FACTOR (EWMA_SCALE_FACTOR / 2)

/* Base Low-Pass Single-Pole IIR Filter (EWMA) formula:
 *
 *   Avg[n] = a * Val[n] + (1 - a) * Avg[n - 1]
 *
 * where parameter 'a' determines how much weight of the latest measurement value
 * 'Val[n]' carries vs the weight of the accumulated average 'Avg[n - 1]'.  The
 * value of 'a' is usually a float in range 0 .. 1, so:
 *
 *  - value 0.5 gives equal weight to both 'Val[n]' and 'Avg[n - 1]';
 *  - value 1.0 means no filtering at all (pass through);
 *  - value 0.0 makes no sense.
 *
 * Further optimization:
 *
 *   Avg[n] = a * Val[n] + Avg[n - 1] - a * Avg[n - 1]
 *   ^^^^^^                ^^^^^^^^^^
 *
 * a) this can be implemented in C using '+=' operator:
 *
 *   Avg += a * Val - a * Avg
 *   Avg += a * (Val - Avg)
 *
 * b) everything is scaled up by 100 to avoid floating point stuff:
 *
 *   Avg100 += A * (Val - Avg)
 *
 * where 'Avg100' is 'Avg * 100' and 'A' is 'a * 100'.
 *
 * For more details, see:
 *
 *   https://en.wikipedia.org/wiki/Moving_average
 *   https://en.wikipedia.org/wiki/Low-pass_filter#Simple_infinite_impulse_response_filter
 *   https://tomroelandts.com/articles/low-pass-single-pole-iir-filter
 */
static int do_pf_ewma(const struct gsm_power_ctrl_meas_params *mp,
		      struct gsm_power_ctrl_meas_proc_state *mps,
		      const int Val)
{
	const uint8_t A = mp->ewma.alpha;
	int *Avg100 = &mps->ewma.Avg100;

	/* We don't have 'Avg[n - 1]' if this is the first run */
	if (mps->meas_num++ == 0) {
		*Avg100 = Val * EWMA_SCALE_FACTOR;
		return Val;
	}

	*Avg100 += A * (Val - (*Avg100 + EWMA_ROUND_FACTOR) / EWMA_SCALE_FACTOR);
	return (*Avg100 + EWMA_ROUND_FACTOR) / EWMA_SCALE_FACTOR;
}

/* Calculate target RxLev value from lower/upper thresholds */
#define CALC_TARGET(mp) \
	((mp).lower_thresh + (mp).upper_thresh) / 2

static int do_avg_algo(const struct gsm_power_ctrl_meas_params *mp,
		       struct gsm_power_ctrl_meas_proc_state *mps,
		       const int val)
{
	int val_avg;
	switch (mp->algo) {
	case GSM_PWR_CTRL_MEAS_AVG_ALGO_OSMO_EWMA:
		val_avg = do_pf_ewma(mp, mps, val);
		break;
	/* TODO: implement other pre-processing methods */
	case GSM_PWR_CTRL_MEAS_AVG_ALGO_NONE:
	default:
		/* No filtering (pass through) */
		val_avg = val;
	}
	return val_avg;
}
/* Calculate a 'delta' value (for the given MS/BS power control parameters)
 * to be applied to the current Tx power level to approach the target level. */
static int calc_delta_rxlev(const struct gsm_power_ctrl_params *params, const uint8_t rxlev)
{
	int delta;

	/* Check if RxLev is within the threshold window */
	if (rxlev >= params->rxlev_meas.lower_thresh &&
	    rxlev <= params->rxlev_meas.upper_thresh)
		return 0;

	/* How many dBs measured power should be increased (+) or decreased (-)
	 * to reach expected power. */
	delta = CALC_TARGET(params->rxlev_meas) - rxlev;

	/* Don't ever change more than PWR_{LOWER,RAISE}_MAX_DBM during one loop
	 * iteration, i.e. reduce the speed at which the MS transmit power can
	 * change. A higher value means a lower level (and vice versa) */
	if (delta > params->inc_step_size_db)
		delta = params->inc_step_size_db;
	else if (delta < -params->red_step_size_db)
		delta = -params->red_step_size_db;

	return delta;
}

/* Shall we skip current block based on configured interval? */
static bool ctrl_interval_skip_block(const struct gsm_power_ctrl_params *params,
				     struct lchan_power_ctrl_state *state)
{
	/* Power control interval: how many blocks do we skip? */
	if (state->skip_block_num-- > 0)
		return true;

	/* Can we be sure if ONE Report is always going to correspond
	 * to ONE SACCH block at the BTS? - If not this is as approximation
	 * but it should not hurt. */

	/* Reset the number of SACCH blocks to be skipped:
	 *   ctrl_interval=0 => 0 blocks to skip,
	 *   ctrl_interval=1 => 1 blocks to skip,
	 *   ctrl_interval=2 => 3 blocks to skip,
	 *     so basically ctrl_interval * 2 - 1. */
	state->skip_block_num = params->ctrl_interval * 2 - 1;
	return false;
}

int lchan_ms_pwr_ctrl(struct gsm_lchan *lchan, const struct gsm_meas_rep *mr)
{
	struct lchan_power_ctrl_state *state = &lchan->ms_power_ctrl;
	struct gsm_bts_trx *trx = lchan->ts->trx;
	struct gsm_bts *bts = trx->bts;
	enum gsm_band band = bts->band;
	const struct gsm_power_ctrl_params *params = &bts->ms_power_ctrl;
	int8_t new_power_lvl; /* TS 05.05 power level */
	int8_t ms_dbm, new_dbm, current_dbm, bsc_max_dbm;
	uint8_t rxlev_avg;
	uint8_t ms_power_lvl = ms_pwr_ctl_lvl(band, mr->ms_l1.pwr);
	int8_t ul_rssi_dbm;
	bool ignore;

	if (params == NULL)
		return 0;
	/* Not doing the power loop here if we are not handling it */
	if (params->mode != GSM_PWR_CTRL_MODE_DYN_BSC)
		return 0;

	/* Shall we skip current block based on configured interval? */
	if (ctrl_interval_skip_block(params, state))
		return 0;

	/* If DTx is active on Uplink,
	 * use the '-SUB', otherwise '-FULL': */
	if (mr->flags & MEAS_REP_F_UL_DTX)
		ul_rssi_dbm = rxlev2dbm(mr->ul.sub.rx_lev);
	else
		ul_rssi_dbm = rxlev2dbm(mr->ul.full.rx_lev);

	ms_dbm = ms_pwr_dbm(band, ms_power_lvl);
	if (ms_dbm < 0) {
		LOGPLCHAN(lchan, DLOOP, LOGL_NOTICE,
			  "Failed to calculate dBm for power ctl level %" PRIu8 " on band %s\n",
			  ms_power_lvl, gsm_band_name(band));
		return 0;
	}

	bsc_max_dbm = bts->ms_max_power;
	rxlev_avg = do_avg_algo(&params->rxlev_meas, &state->rxlev_meas_proc, dbm2rxlev(ul_rssi_dbm));
	new_dbm = ms_dbm + calc_delta_rxlev(params, rxlev_avg);

	/* Make sure new_dbm is never negative. ms_pwr_ctl_lvl() can later on
	   cope with any unsigned dbm value, regardless of band minimal value. */
	if (new_dbm < 0)
		new_dbm = 0;
	/* Don't ask for smaller ms power level than the one set by ms max power for this BTS */
	if (new_dbm > bsc_max_dbm)
		new_dbm = bsc_max_dbm;

	new_power_lvl = ms_pwr_ctl_lvl(band, new_dbm);
	if (new_power_lvl < 0) {
		LOGPLCHAN(lchan, DLOOP, LOGL_NOTICE,
			  "Failed to retrieve power level for %" PRId8 " dBm on band %d\n",
			  new_dbm, band);
		return 0;
	}

	current_dbm = ms_pwr_dbm(band, lchan->ms_power);

	/* In this Power Control Loop, we infer a new good MS Power Level based
	 * on the previous MS Power Level announced by the MS (not the previous
	 * one we requested!) together with the related computed measurements.
	 * Hence, and since we allow for several good MS Power Levels falling into our
	 * thresholds, we could finally converge into an oscillation loop where
	 * the MS bounces between 2 different correct MS Power levels all the
	 * time, due to the fact that we "accept" and "request back" whatever
	 * good MS Power Level we received from the MS, but at that time the MS
	 * will be transmitting using the previous MS Power Level we
	 * requested, which we will later "accept" and "request back" on next loop
	 * iteration. As a result MS effectively bounces between those 2 MS
	 * Power Levels.
	 * In order to fix this permanent oscillation, if current MS_PWR used/announced
	 * by MS is good ("ms_dbm == new_dbm", hence within thresholds and no change
	 * required) but has higher Tx power than the one we last requested, we ignore
	 * it and keep requesting for one with lower Tx power. This way we converge to
	 * the lowest good Tx power avoiding oscillating over values within thresholds.
	 */
	ignore = (ms_dbm == new_dbm && ms_dbm > current_dbm);

	if (lchan->ms_power == new_power_lvl || ignore) {
		LOGPLCHAN(lchan, DLOOP, LOGL_INFO, "Keeping MS power at control level %d (%d dBm): "
			  "ms-pwr-lvl[curr %" PRIu8 ", max %" PRIu8 "], RSSI[curr %d, avg %d, thresh %d..%d] dBm\n",
			  new_power_lvl, ms_dbm, ms_power_lvl, bsc_max_dbm, ul_rssi_dbm, rxlev2dbm(rxlev_avg),
			  rxlev2dbm(params->rxlev_meas.lower_thresh), rxlev2dbm(params->rxlev_meas.upper_thresh));
		return 0;
	}

	LOGPLCHAN(lchan, DLOOP, LOGL_INFO, "%s MS power control level %d (%d dBm) => %d (%d dBm): "
		  "ms-pwr-lvl[curr %" PRIu8 ", max %" PRIu8 "], RSSI[curr %d, avg %d, thresh %d..%d] dBm\n",
		  (new_dbm > current_dbm) ? "Raising" : "Lowering",
		  lchan->ms_power, current_dbm, new_power_lvl, new_dbm, ms_power_lvl,
		  bsc_max_dbm, ul_rssi_dbm, rxlev2dbm(rxlev_avg),
		  rxlev2dbm(params->rxlev_meas.lower_thresh), rxlev2dbm(params->rxlev_meas.upper_thresh));

	lchan_update_ms_power_ctrl_level(lchan, new_dbm);

	return 1;

}
