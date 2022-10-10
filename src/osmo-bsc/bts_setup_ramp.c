/* (C) 2022 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 *
 * Author: Alexander Couzens <acouzens@sysmocom.de>
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

#include <stdbool.h>

#include <osmocom/core/fsm.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/utils.h>

#include <osmocom/bsc/bts.h>
#include <osmocom/bsc/bts_sm.h>
#include <osmocom/bsc/bts_setup_ramp.h>
#include <osmocom/bsc/nm_common_fsm.h>


static void _bts_setup_ramp_unblock_bts(struct gsm_bts *bts)
{
	llist_del_init(&bts->bts_setup_ramp.list);
	bts->bts_setup_ramp.state = BTS_SETUP_RAMP_READY;

	nm_fsm_dispatch_all_configuring(bts, NM_EV_SETUP_RAMP_READY, NULL);
}

/*!
 * Unblock a BTS from BTS setup ramping to continue setup and configure.
 *
 * \param bts pointer to the bts
 * \return 0 on success, -EINVAL when the BTS is not waiting.
 */
int bts_setup_ramp_unblock_bts(struct gsm_bts *bts)
{
	if (bts->bts_setup_ramp.state != BTS_SETUP_RAMP_WAIT)
		return -EINVAL;

	if (llist_empty(&bts->bts_setup_ramp.list))
		return -EINVAL;

	_bts_setup_ramp_unblock_bts(bts);
	return 0;
}

/*!
 * Timer callback and called by bts_setup_ramp_deactivate
 * \param _net pointer to struct gsm_network
 */
static void bts_setup_ramp_timer_cb(void *_net)
{
	struct gsm_network *net = (struct gsm_network *) _net;
	struct gsm_bts *bts, *n;
	net->bts_setup_ramp.count = 0;

	llist_for_each_entry_safe(bts, n, &net->bts_setup_ramp.head, bts_setup_ramp.list) {
		net->bts_setup_ramp.count++;
		_bts_setup_ramp_unblock_bts(bts);
		LOG_BTS(bts, DNM, LOGL_INFO, "Unblock BTS %d from BTS ramping.\n", bts->nr);
		if (bts_setup_ramp_active(net) && net->bts_setup_ramp.count >= net->bts_setup_ramp.step_size)
			break;
	}

	if (bts_setup_ramp_active(net))
		osmo_timer_schedule(&net->bts_setup_ramp.timer, net->bts_setup_ramp.step_interval, 0);
}

const struct value_string bts_setup_ramp_state_values[] = {
	{ BTS_SETUP_RAMP_INIT,	"Initial" },
	{ BTS_SETUP_RAMP_WAIT,	"Waiting" },
	{ BTS_SETUP_RAMP_READY,	"Ready" },
	{ 0,			NULL },
};

const char *bts_setup_ramp_get_state_str(struct gsm_bts *bts)
{
	return get_value_string_or_null(bts_setup_ramp_state_values, bts->bts_setup_ramp.state);
}

/* return true when state has been changed. */
static bool check_config(struct gsm_network *net)
{
	bool new_state = (net->bts_setup_ramp.enabled
			  && net->bts_setup_ramp.step_size > 0
			  && net->bts_setup_ramp.step_interval > 0);

	if (!new_state && bts_setup_ramp_active(net)) {
		net->bts_setup_ramp.active = false;
		osmo_timer_del(&net->bts_setup_ramp.timer);
		/* clear bts list */
		bts_setup_ramp_timer_cb(net);
		return true;
	} else if (new_state && !bts_setup_ramp_active(net)) {
		net->bts_setup_ramp.active = true;
		osmo_timer_schedule(&net->bts_setup_ramp.timer, net->bts_setup_ramp.step_interval, 0);
		return true;
	}

	return false;
}

/*!
 * Enable the bts setup ramping feature
 *
 * The BTS setup ramping prevents BSC overload when too many BTS tries to setup and
 * configure at the same time. E.g. this might happen if there is a major network outage
 * between all BTS and the BSC.
 *
 * \param[in] net a pointer to the gsm network
 */
void bts_setup_ramp_enable(struct gsm_network *net)
{
	net->bts_setup_ramp.enabled = true;
	check_config(net);
}

/*!
 * Disable the bts setup ramping feature
 *
 * \param[in] net a pointer to the gsm network
 */
void bts_setup_ramp_disable(struct gsm_network *net)
{
	net->bts_setup_ramp.enabled = false;
	check_config(net);
}

/*! Checks if the bts setup ramp correct configured and active
 *
 * \param[in] net a pointer to the gsm network
 * \return true if the bts setup ramp is active
 */
bool bts_setup_ramp_active(struct gsm_network *net)
{
	return net->bts_setup_ramp.active;
}

/*!
 * Check if the BTS should wait to setup.
 *
 * Can be called multiple times by the same BTS.
 *
 * \param bts pointer to the bts
 * \return true if the bts should wait
 */
bool bts_setup_ramp_wait(struct gsm_bts *bts)
{
	struct gsm_network *net = bts->network;

	if (!bts_setup_ramp_active(net)) {
		bts->bts_setup_ramp.state = BTS_SETUP_RAMP_READY;
		return false;
	}

	switch (bts->bts_setup_ramp.state) {
	case BTS_SETUP_RAMP_INIT:
		break;
	case BTS_SETUP_RAMP_WAIT:
		return true;
	case BTS_SETUP_RAMP_READY:
		return false;
	}

	if (net->bts_setup_ramp.count < net->bts_setup_ramp.step_size) {
		LOG_BTS(bts, DNM, LOGL_INFO,
			"BTS %d can configure without waiting for BTS ramping.\n", bts->nr);

		net->bts_setup_ramp.count++;
		bts->bts_setup_ramp.state = BTS_SETUP_RAMP_READY;
		return false;
	}

	bts->bts_setup_ramp.state = BTS_SETUP_RAMP_WAIT;
	llist_add_tail(&bts->bts_setup_ramp.list, &net->bts_setup_ramp.head);
	LOGP(DNM, LOGL_INFO, "BTS %d will wait for BTS ramping.\n", bts->nr);

	return true;
}

void bts_setup_ramp_init_network(struct gsm_network *net)
{
	INIT_LLIST_HEAD(&net->bts_setup_ramp.head);
	osmo_timer_setup(&net->bts_setup_ramp.timer, bts_setup_ramp_timer_cb, net);
}

void bts_setup_ramp_init_bts(struct gsm_bts *bts)
{
	/* Initialize bts_setup_ramp.list (llist_entry) to have llist_empty() available */
	INIT_LLIST_HEAD(&bts->bts_setup_ramp.list);
	bts->bts_setup_ramp.state = BTS_SETUP_RAMP_INIT;
}

/*!
 * Remove the bts from the bts setup ramp waiting list and resets the BTS setup ramping state.
 * Should be called when removing the BTS
 *
 * \param bts pointer to the bts
 */
void bts_setup_ramp_remove(struct gsm_bts *bts)
{
	if (!llist_empty(&bts->bts_setup_ramp.list))
		llist_del_init(&bts->bts_setup_ramp.list);
	bts->bts_setup_ramp.state = BTS_SETUP_RAMP_INIT;
}

/*!
 * Set the BTS setup ramping step interval.
 *
 * Within the time window of \param step_interval only a limited amount (see step_size)
 * of BTS will be configured.
 *
 * \param[in] net a pointer to the gsm network
 * \param step_interval in seconds
 */
void bts_setup_ramp_set_step_interval(struct gsm_network *net, unsigned int step_interval)
{
	net->bts_setup_ramp.step_interval = step_interval;
	check_config(net);
}

/*!
 * Set the BTS setup ramping step_size
 *
 * Within the time window of step_interval only a limited amount of BTS (\param step_size)
 * will be configured.
 *
 * \param[in] net a pointer to the gsm network
 * \param step_size the step size
 */
void bts_setup_ramp_set_step_size(struct gsm_network *net, unsigned int step_size)
{
	net->bts_setup_ramp.step_size = step_size;
	check_config(net);
}
