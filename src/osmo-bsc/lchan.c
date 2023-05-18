/* (C) 2022 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * (C) 2008-2018 by Harald Welte <laforge@gnumonks.org>
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

#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>

#include <osmocom/gsm/gsm_utils.h>

#include <osmocom/bsc/lchan.h>
#include <osmocom/bsc/lchan_fsm.h>
#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/bts.h>
#include <osmocom/bsc/bts_trx.h>
#include <osmocom/bsc/abis_rsl.h>

void lchan_init(struct gsm_lchan *lchan, struct gsm_bts_trx_ts *ts, unsigned int nr)
{
	lchan->ts = ts;
	lchan->nr = nr;
	lchan->type = GSM_LCHAN_NONE;

	lchan_update_name(lchan);
}

void lchan_update_name(struct gsm_lchan *lchan)
{
	struct gsm_bts_trx_ts *ts = lchan->ts;
	if (lchan->name)
		talloc_free(lchan->name);
	lchan->name = talloc_asprintf(ts->trx, "(bts=%d,trx=%d,ts=%d,ss=%s%d)",
				      ts->trx->bts->nr, ts->trx->nr, ts->nr,
				      lchan->vamos.is_secondary ? "shadow" : "",
				      lchan->nr - (lchan->vamos.is_secondary ? ts->max_primary_lchans : 0));
}

/* If the lchan is currently active, return the duration since activation in milliseconds.
 * Otherwise return 0. */
uint64_t gsm_lchan_active_duration_ms(const struct gsm_lchan *lchan)
{
	struct timespec now, elapsed;

	if (lchan->active_start.tv_sec == 0 && lchan->active_start.tv_nsec == 0)
		return 0;

	osmo_clock_gettime(CLOCK_MONOTONIC, &now);
	timespecsub(&now, &lchan->active_start, &elapsed);

	return elapsed.tv_sec * 1000 + elapsed.tv_nsec / 1000000;
}

/* For a VAMOS secondary shadow lchan, return its primary lchan. If the lchan is not a secondary lchan, return NULL. */
struct gsm_lchan *gsm_lchan_vamos_to_primary(const struct gsm_lchan *lchan_vamos)
{
	struct gsm_lchan *lchan_primary;
	if (!lchan_vamos || !lchan_vamos->vamos.is_secondary)
		return NULL;
	/* OsmoBSC currently does not support mixed TCH/F + TCH/H VAMOS multiplexes. Hence the primary <-> secondary
	 * relation is a simple index shift in the lchan array. If mixed multiplexes were allowed, a TCH/F primary might
	 * have two TCH/H VAMOS secondary lchans, etc. Fortunately, we don't need to care about that. */
	lchan_primary = (struct gsm_lchan *)lchan_vamos - lchan_vamos->ts->max_primary_lchans;
	if (!lchan_primary->fi)
		return NULL;
	return lchan_primary;
}

/* For a primary lchan, return its VAMOS secondary shadow lchan. If the lchan is not a primary lchan, return NULL. */
struct gsm_lchan *gsm_lchan_primary_to_vamos(const struct gsm_lchan *lchan_primary)
{
	struct gsm_lchan *lchan_vamos;
	if (!lchan_primary || lchan_primary->vamos.is_secondary)
		return NULL;
	/* OsmoBSC currently does not support mixed TCH/F + TCH/H VAMOS multiplexes. Hence the primary <-> secondary
	 * relation is a simple index shift in the lchan array. If mixed multiplexes were allowed, a TCH/F primary might
	 * have two TCH/H VAMOS secondary lchans, etc. Fortunately, we don't need to care about that. */
	lchan_vamos = (struct gsm_lchan *)lchan_primary + lchan_primary->ts->max_primary_lchans;
	if (!lchan_vamos->fi)
		return NULL;
	return lchan_vamos;
}

void lchan_update_ms_power_ctrl_level(struct gsm_lchan *lchan, int ms_power_dbm)
{
	struct gsm_bts *bts = lchan->ts->trx->bts;
	struct gsm_subscriber_connection *conn = lchan->conn;
	int max_pwr_dbm_pwclass, new_pwr;
	bool send_pwr_ctrl_msg = false;

	LOG_LCHAN(lchan, LOGL_DEBUG,
		  "MS Power level update requested: %d dBm\n", ms_power_dbm);

	if (!conn)
		goto ms_power_default;

	if (conn->ms_power_class == 0)
		goto ms_power_default;

	if ((max_pwr_dbm_pwclass = (int)ms_class_gmsk_dbm(bts->band, conn->ms_power_class)) < 0) {
		LOG_LCHAN(lchan, LOGL_INFO,
			 "Failed getting max ms power for power class %" PRIu8
			 " on band %s, providing default max ms power\n",
			 conn->ms_power_class, gsm_band_name(bts->band));
		goto ms_power_default;
	}

	/* Current configured max pwr is above maximum one allowed on
	   current band + ms power class, so use that one. */
	if (ms_power_dbm > max_pwr_dbm_pwclass)
		ms_power_dbm = max_pwr_dbm_pwclass;

ms_power_default:
	if ((new_pwr = ms_pwr_ctl_lvl(bts->band, ms_power_dbm)) < 0) {
		LOG_LCHAN(lchan, LOGL_INFO,
			 "Failed getting max ms power level %d on band %s,"
			 " providing default max ms power\n",
			 ms_power_dbm, gsm_band_name(bts->band));
		return;
	}

	LOG_LCHAN(lchan, LOGL_DEBUG,
		  "MS Power level update (power class %" PRIu8 "): %" PRIu8 " -> %d\n",
		  conn ? conn->ms_power_class : 0, lchan->ms_power, new_pwr);

	/* If chan was already activated and max ms_power changes (due to power
	   classmark received), send an MS Power Control message */
	if (lchan->activate.activ_ack && new_pwr != lchan->ms_power)
		send_pwr_ctrl_msg = true;

	lchan->ms_power = new_pwr;

	if (send_pwr_ctrl_msg)
		rsl_chan_ms_power_ctrl(lchan);
}
