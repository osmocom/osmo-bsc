/* (C) 2017 by sysmocom s.f.m.c. GmbH
 * All Rights Reserved
 *
 * Author: Philipp Maier
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

#include <osmocom/core/signal.h>
#include <osmocom/bsc/signal.h>

#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/bsc_msc_data.h>
#include <osmocom/bsc/osmo_bsc_sigtran.h>
#include <osmocom/bsc/bssmap_reset.h>

static void a_reset_tx_reset(void *data)
{
	struct bsc_msc_data *msc = data;
	osmo_bsc_sigtran_tx_reset(msc);
}

static void a_reset_link_up(void *data)
{
	struct bsc_msc_data *msc = data;
	LOGP(DMSC, LOGL_NOTICE, "(msc%d) BSSMAP assocation is up\n", msc->nr);
	osmo_stat_item_inc(msc->msc_statg->items[MSC_STAT_MSC_LINKS_ACTIVE], 1);
	osmo_signal_dispatch(SS_MSC, S_MSC_CONNECTED, msc);
}

static void a_reset_link_lost(void *data)
{
	struct bsc_msc_data *msc = data;
	LOGP(DMSC, LOGL_NOTICE, "(msc%d) BSSMAP assocation is down\n", msc->nr);
	osmo_stat_item_dec(msc->msc_statg->items[MSC_STAT_MSC_LINKS_ACTIVE], 1);
	osmo_signal_dispatch(SS_MSC, S_MSC_LOST, msc);
	osmo_bsc_sigtran_reset(msc);
}

/* Create and start state machine which handles the reset/reset-ack procedure */
void a_reset_alloc(struct bsc_msc_data *msc, const char *name)
{
	struct bssmap_reset_cfg cfg = {
		.conn_cfm_failure_threshold = 3,
		.ops = {
			.tx_reset = a_reset_tx_reset,
			.link_up = a_reset_link_up,
			.link_lost = a_reset_link_lost,
		},
		.data = msc,
	};

	/* There must not be any double allocation! */
	if (msc->a.bssmap_reset) {
		LOGP(DMSC, LOGL_ERROR, "(msc%d) will not allocate a second reset FSM for this MSC\n", msc->nr);
		return;
	}

	msc->a.bssmap_reset = bssmap_reset_alloc(msc, name, &cfg);
}

/* Confirm that we successfully received a reset acknowledge message */
void a_reset_ack_confirm(struct bsc_msc_data *msc)
{
	if (!msc)
		return;

	if (!msc->a.bssmap_reset)
		return;

	osmo_fsm_inst_dispatch(msc->a.bssmap_reset->fi, BSSMAP_RESET_EV_RX_RESET_ACK, NULL);
}

/* Report a failed connection */
void a_reset_conn_fail(struct bsc_msc_data *msc)
{
	if (!msc)
		return;

	if (!msc->a.bssmap_reset)
		return;

	osmo_fsm_inst_dispatch(msc->a.bssmap_reset->fi, BSSMAP_RESET_EV_CONN_CFM_FAILURE, NULL);
}

/* Report a successful connection */
void a_reset_conn_success(struct bsc_msc_data *msc)
{
	if (!msc)
		return;

	if (!msc->a.bssmap_reset)
		return;

	osmo_fsm_inst_dispatch(msc->a.bssmap_reset->fi, BSSMAP_RESET_EV_CONN_CFM_SUCCESS, NULL);
}

/* Check if we have a connection to a specified msc */
bool a_reset_conn_ready(struct bsc_msc_data *msc)
{
	if (!msc)
		return false;

	if (!msc->a.bssmap_reset)
		return false;

	return bssmap_reset_is_conn_ready(msc->a.bssmap_reset);
}
