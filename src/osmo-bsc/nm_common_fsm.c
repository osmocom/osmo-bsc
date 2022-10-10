/* NM FSM, common bits */

/* (C) 2020 by sysmocom - s.m.f.c. GmbH <info@sysmocom.de>
 * Author: Pau Espin Pedrol <pespin@sysmocom.de>
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

#include <osmocom/core/linuxlist.h>
#include <osmocom/bsc/bts.h>
#include <osmocom/bsc/nm_common_fsm.h>
#include <osmocom/bsc/signal.h>

const struct value_string nm_fsm_event_names[] = {
	{ NM_EV_SW_ACT_REP, "SW_ACT_REP" },
	{ NM_EV_STATE_CHG_REP, "STATE_CHG_REP" },
	{ NM_EV_GET_ATTR_REP, "GET_ATTR_REP" },
	{ NM_EV_SET_ATTR_ACK, "SET_ATTR_ACK" },
	{ NM_EV_OPSTART_ACK, "OPSTART_ACK" },
	{ NM_EV_OPSTART_NACK, "OPSTART_NACK" },
	{ NM_EV_OML_DOWN, "OML_DOWN" },
	{ NM_EV_FORCE_LOCK, "FORCE_LOCK_CHG" },
	{ NM_EV_FEATURE_NEGOTIATED, "FEATURE_NEGOTIATED" },
	{ NM_EV_RSL_CONNECT_ACK, "RSL_CONNECT_ACK" },
	{ NM_EV_RSL_CONNECT_NACK, "RSL_CONNECT_NACK" },
	{ 0, NULL }
};

void nm_obj_fsm_becomes_enabled_disabled(struct gsm_bts *bts, void *obj,
					 enum abis_nm_obj_class obj_class, bool running)
{
	struct nm_running_chg_signal_data nsd;

	memset(&nsd, 0, sizeof(nsd));
	nsd.bts = bts;
	nsd.obj_class = obj_class;
	nsd.obj = obj;
	nsd.running = running;

	osmo_signal_dispatch(SS_NM, S_NM_RUNNING_CHG, &nsd);
}

/* nm_configuring_fsm_inst_dispatch(struct gsm_abis_mo *mo, uint32_t event, void *data) */
#define nm_configuring_fsm_inst_dispatch(mo, event, data) do { \
		if ((mo)->nm_state.operational != NM_OPSTATE_ENABLED) \
			_osmo_fsm_inst_dispatch((mo)->fi, event, data, __FILE__, __LINE__); \
	} while (0)

/*!
 * Dispatch an event to all configuring/non-enabled BTS NM fsms
 *
 * \param[in] bts a pointer to the BTS instance
 * \param[in] event the FSM event. See \fn osmo_fsm_inst_dispatch
 * \param[in] data the private data of the event.
 */
void nm_fsm_dispatch_all_configuring(struct gsm_bts *bts, uint32_t event, void *data)
{
	struct gsm_bts_trx *trx;

	nm_configuring_fsm_inst_dispatch(&bts->site_mgr->mo, event, data);
	nm_configuring_fsm_inst_dispatch(&bts->mo, event, data);
	llist_for_each_entry(trx, &bts->trx_list, list) {
		nm_configuring_fsm_inst_dispatch(&trx->mo, event, data);
		nm_configuring_fsm_inst_dispatch(&trx->bb_transc.mo, event, data);
		for (unsigned long i = 0; i < ARRAY_SIZE(trx->ts); i++) {
			struct gsm_bts_trx_ts *ts = &trx->ts[i];
			nm_configuring_fsm_inst_dispatch(&ts->mo, event, data);
		}
	}

	/* GPRS MOs */
	nm_configuring_fsm_inst_dispatch(&bts->site_mgr->gprs.nse.mo, event, data);
	for (unsigned long i = 0; i < ARRAY_SIZE(bts->site_mgr->gprs.nsvc); i++)
		nm_configuring_fsm_inst_dispatch(&bts->site_mgr->gprs.nsvc[i].mo, event, data);
	nm_configuring_fsm_inst_dispatch(&bts->gprs.cell.mo, event, data);
}
