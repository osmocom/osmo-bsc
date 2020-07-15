/*
 * (C) 2010-2013 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010-2013 by On-Waves
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

#include <osmocom/bsc/osmo_bsc_grace.h>
#include <osmocom/bsc/osmo_bsc_rf.h>
#include <osmocom/bsc/bsc_msc_data.h>
#include <osmocom/bsc/bsc_subscriber.h>
#include <osmocom/bsc/paging.h>
#include <osmocom/bsc/signal.h>
#include <osmocom/bsc/lchan_fsm.h>
#include <osmocom/bsc/bts.h>

int bsc_grace_allow_new_connection(struct gsm_network *network, struct gsm_bts *bts)
{
	if (bts->excl_from_rf_lock)
		return 1;
	return network->rf_ctrl->policy == S_RF_ON;
}


/* Return value is like paging_request_bts():
 * returns 1 on success (one BTS was paged); 0 in case of error (e.g. TRX down) */
static int locked_paging_bts(struct gsm_bts *bts,
			     struct bsc_subscr *subscr,
			     int chan_needed,
			     struct bsc_msc_data *msc)
{
	/* Return error if the BTS is not excluded from the lock. */
	if (!bts->excl_from_rf_lock)
		return 0;

	/* in case of no lac patching is in place, check the BTS */
	if (msc->core_lac == -1 && subscr->lac != bts->location_area_code)
		return 0;

	return paging_request_bts(bts, subscr, chan_needed, msc);
}

/**
 * Page a subscriber in an MSC.
 * \param[in] rf_policy if not S_RF_ON, page only BTSs which are not excluded from the RF lock
 * \param[in] subscr subscriber we want to page
 * \param[in] chan_needed value of the GSM0808_IE_CHANNEL_NEEDED IE
 * \param[in] msc MSC which has issued this paging
 * \param[in] bts The BTS to issue the paging on
 * \returns 1 if paging was issued to the BTS, 0 if not
 */
int bsc_grace_paging_request(enum signal_rf rf_policy,
			     struct bsc_subscr *subscr,
			     int chan_needed,
			     struct bsc_msc_data *msc,
			     struct gsm_bts *bts)
{
	if (rf_policy == S_RF_ON)
		return paging_request_bts(bts, subscr, chan_needed, msc);
	return locked_paging_bts(bts, subscr, chan_needed, msc);
}
