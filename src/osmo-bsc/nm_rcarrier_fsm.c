/* NM Radio Carrier FSM */

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

#include <errno.h>
#include <unistd.h>
#include <inttypes.h>

#include <osmocom/core/fsm.h>
#include <osmocom/core/tdef.h>
#include <osmocom/gsm/protocol/gsm_12_21.h>

#include <osmocom/bsc/bts.h>
#include <osmocom/bsc/signal.h>
#include <osmocom/bsc/abis_nm.h>
#include <osmocom/bsc/bts_ipaccess_nanobts_omlattr.h>
#include <osmocom/bsc/nm_common_fsm.h>
#include <osmocom/bsc/debug.h>

#define X(s) (1 << (s))

#define nm_rcarrier_fsm_state_chg(fi, NEXT_STATE) \
	osmo_fsm_inst_state_chg(fi, NEXT_STATE, 0, 0)

//////////////////////////
// FSM STATE ACTIONS
//////////////////////////

static void st_op_disabled_notinstalled_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct gsm_bts_trx *trx = (struct gsm_bts_trx *)fi->priv;

	trx->mo.set_attr_sent = false;
	trx->mo.set_attr_ack_received = false;
	trx->mo.adm_unlock_sent = false;
	trx->mo.opstart_sent = false;
}

static void st_op_disabled_notinstalled(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct nm_statechg_signal_data *nsd;
	const struct gsm_nm_state *new_state;

	switch (event) {
	case NM_EV_SW_ACT_REP:
		break;
	case NM_EV_STATE_CHG_REP:
		nsd = (struct nm_statechg_signal_data *)data;
		new_state = nsd->new_state;
		if (new_state->operational == NM_OPSTATE_ENABLED) {
			/*should not happen... */
			nm_rcarrier_fsm_state_chg(fi, NM_RCARRIER_ST_OP_ENABLED);
			return;
		}
		switch (new_state->availability) { /* operational = DISABLED */
		case NM_AVSTATE_DEPENDENCY:
			nm_rcarrier_fsm_state_chg(fi, NM_RCARRIER_ST_OP_DISABLED_DEPENDENCY);
			return;
		case NM_AVSTATE_OFF_LINE:
		case NM_AVSTATE_OK:
			nm_rcarrier_fsm_state_chg(fi, NM_RCARRIER_ST_OP_DISABLED_OFFLINE);
			return;
		default:
			return;
		}
	default:
		OSMO_ASSERT(0);
	}
}

static void configure_loop(struct gsm_bts_trx *trx, const struct gsm_nm_state *state, bool allow_opstart)
{
	struct msgb *msgb;

	if (!trx->mo.set_attr_sent && !trx->mo.set_attr_ack_received) {
		trx->mo.set_attr_sent = true;
		msgb = nanobts_gen_set_radio_attr(trx->bts, trx);
		abis_nm_set_radio_attr(trx, msgb->data, msgb->len);
		msgb_free(msgb);
	}

	if (!trx->mo.force_rf_lock && state->administrative != NM_STATE_UNLOCKED &&
	    !trx->mo.adm_unlock_sent) {
		trx->mo.adm_unlock_sent = true;
		abis_nm_chg_adm_state(trx->bts, NM_OC_RADIO_CARRIER,
				      trx->bts->bts_nr, trx->nr, 0xff,
				      NM_STATE_UNLOCKED);
	}

	if (allow_opstart && state->administrative == NM_STATE_UNLOCKED &&
	    trx->mo.set_attr_ack_received && !trx->mo.opstart_sent) {
		trx->mo.opstart_sent = true;
		abis_nm_opstart(trx->bts, NM_OC_RADIO_CARRIER, trx->bts->bts_nr, trx->nr, 0xff);
	}
}

static void st_op_disabled_dependency_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct gsm_bts_trx *trx = (struct gsm_bts_trx *)fi->priv;

	/* In general nanoBTS is broken, doesn't follow TS 12.21. Opstart MUST
	 * be sent during Dependency, so we simply move to OFFLINE state here to
	 * avoid duplicating code. However, RadioCarrier seems to be implemented
	 * correctly and goes to Offline state during startup. If some HW
	 * version is found with the above estated bug, this code needs to be
	 * enabled, similar to what we do in nm_bb_transc_fsm:
	 */
	/*if (trx->bts->site_mgr.peer_has_no_avstate_offline) {
		nm_rcarrier_fsm_state_chg(fi, NM_RCARRIER_ST_OP_DISABLED_OFFLINE);
		return;
	}*/
	configure_loop(trx, &trx->mo.nm_state, false);
}

static void st_op_disabled_dependency(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_bts_trx *trx = (struct gsm_bts_trx *)fi->priv;
	struct nm_statechg_signal_data *nsd;
	const struct gsm_nm_state *new_state;

	switch (event) {
	case NM_EV_SET_ATTR_ACK:
		trx->mo.set_attr_ack_received = true;
		trx->mo.set_attr_sent = false;
		configure_loop(trx, &trx->mo.nm_state, false);
		return;
	case NM_EV_STATE_CHG_REP:
		nsd = (struct nm_statechg_signal_data *)data;
		new_state = nsd->new_state;
		if (new_state->operational == NM_OPSTATE_ENABLED) {
			/* should not happen... */
			nm_rcarrier_fsm_state_chg(fi, NM_RCARRIER_ST_OP_ENABLED);
			return;
		}
		switch (new_state->availability) { /* operational = DISABLED */
		case NM_AVSTATE_NOT_INSTALLED:
		case NM_AVSTATE_POWER_OFF:
			nm_rcarrier_fsm_state_chg(fi, NM_RCARRIER_ST_OP_DISABLED_NOTINSTALLED);
			return;
		case NM_AVSTATE_OFF_LINE:
		case NM_AVSTATE_OK:
			nm_rcarrier_fsm_state_chg(fi, NM_RCARRIER_ST_OP_DISABLED_OFFLINE);
			return;
		case NM_AVSTATE_DEPENDENCY:
			configure_loop(trx, new_state, false);
			return;
		default:
			return;
		}
	default:
		OSMO_ASSERT(0);
	}
}

static void st_op_disabled_offline_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct gsm_bts_trx *trx = (struct gsm_bts_trx *)fi->priv;

	/* Warning: In here we may be acessing an state older than new_state
	   from prev (syncrhonous) FSM state */
	configure_loop(trx, &trx->mo.nm_state, true);
}

static void st_op_disabled_offline(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_bts_trx *trx = (struct gsm_bts_trx *)fi->priv;
	struct nm_statechg_signal_data *nsd;
	const struct gsm_nm_state *new_state;

	switch (event) {
	case NM_EV_SET_ATTR_ACK:
		trx->mo.set_attr_ack_received = true;
		trx->mo.set_attr_sent = false;
		configure_loop(trx, &trx->mo.nm_state, true);
		return;
	case NM_EV_STATE_CHG_REP:
		nsd = (struct nm_statechg_signal_data *)data;
		new_state = nsd->new_state;
		if (new_state->operational == NM_OPSTATE_ENABLED) {
			nm_rcarrier_fsm_state_chg(fi, NM_RCARRIER_ST_OP_ENABLED);
			return;
		}
		switch (new_state->availability) { /* operational = DISABLED */
		case NM_AVSTATE_NOT_INSTALLED:
		case NM_AVSTATE_POWER_OFF:
			nm_rcarrier_fsm_state_chg(fi, NM_RCARRIER_ST_OP_DISABLED_NOTINSTALLED);
			return;
		case NM_AVSTATE_DEPENDENCY:
			nm_rcarrier_fsm_state_chg(fi, NM_RCARRIER_ST_OP_DISABLED_DEPENDENCY);
			return;
		case NM_AVSTATE_OFF_LINE:
		case NM_AVSTATE_OK:
			configure_loop(trx, new_state, true);
			return;
		default:
			return;
		}
	default:
		OSMO_ASSERT(0);
	}
}

static void st_op_enabled_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct gsm_bts_trx *trx = (struct gsm_bts_trx *)fi->priv;

	/* Reset state, we don't need it in this state and it will need to be
	  reused as soon as we move back to Disabled */
	trx->mo.opstart_sent = false;
	trx->mo.adm_unlock_sent = false;
	trx->mo.set_attr_ack_received = false;
	trx->mo.set_attr_sent = false;
}

static void st_op_enabled(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct nm_statechg_signal_data *nsd;
	const struct gsm_nm_state *new_state;

	switch (event) {
	case NM_EV_STATE_CHG_REP:
		nsd = (struct nm_statechg_signal_data *)data;
		new_state = nsd->new_state;
		if (new_state->operational == NM_OPSTATE_ENABLED)
			return;
		switch (new_state->availability) { /* operational = DISABLED */
		case NM_AVSTATE_NOT_INSTALLED:
		case NM_AVSTATE_POWER_OFF:
			nm_rcarrier_fsm_state_chg(fi, NM_RCARRIER_ST_OP_DISABLED_NOTINSTALLED);
			return;
		case NM_AVSTATE_DEPENDENCY:
			nm_rcarrier_fsm_state_chg(fi, NM_RCARRIER_ST_OP_DISABLED_DEPENDENCY);
			return;
		case NM_AVSTATE_OFF_LINE:
		case NM_AVSTATE_OK:
			nm_rcarrier_fsm_state_chg(fi, NM_RCARRIER_ST_OP_DISABLED_OFFLINE);
			return;
		default:
			return;
		}
	default:
		OSMO_ASSERT(0);
	}
}

static void st_op_allstate(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_bts_trx *trx = (struct gsm_bts_trx *)fi->priv;

	switch (event) {
	case NM_EV_OPSTART_ACK:
	case NM_EV_OPSTART_NACK:
		/* TODO: if on state OFFLINE and rx NACK, try again? */
		trx->mo.opstart_sent = false;
		break;
	case NM_EV_FORCE_LOCK:
		trx->mo.force_rf_lock = (bool)(intptr_t)data;
		abis_nm_chg_adm_state(trx->bts, NM_OC_RADIO_CARRIER,
				      trx->bts->bts_nr, trx->nr, 0xff,
				      trx->mo.force_rf_lock ? NM_STATE_LOCKED : NM_STATE_UNLOCKED);
		break;
	case NM_EV_OML_DOWN:
		if (fi->state != NM_RCARRIER_ST_OP_DISABLED_NOTINSTALLED)
			nm_rcarrier_fsm_state_chg(fi, NM_RCARRIER_ST_OP_DISABLED_NOTINSTALLED);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static struct osmo_fsm_state nm_rcarrier_fsm_states[] = {
	[NM_RCARRIER_ST_OP_DISABLED_NOTINSTALLED] = {
		.in_event_mask =
			X(NM_EV_SW_ACT_REP) |
			X(NM_EV_STATE_CHG_REP),
		.out_state_mask =
			X(NM_RCARRIER_ST_OP_DISABLED_DEPENDENCY) |
			X(NM_RCARRIER_ST_OP_DISABLED_OFFLINE) |
			X(NM_RCARRIER_ST_OP_ENABLED),
		.name = "DISABLED_NOTINSTALLED",
		.onenter = st_op_disabled_notinstalled_on_enter,
		.action = st_op_disabled_notinstalled,
	},
	[NM_RCARRIER_ST_OP_DISABLED_DEPENDENCY] = {
		.in_event_mask =
			X(NM_EV_STATE_CHG_REP) |
			X(NM_EV_SET_ATTR_ACK),
		.out_state_mask =
			X(NM_RCARRIER_ST_OP_DISABLED_NOTINSTALLED) |
			X(NM_RCARRIER_ST_OP_DISABLED_OFFLINE) |
			X(NM_RCARRIER_ST_OP_ENABLED),
		.name = "DISABLED_DEPENDENCY",
		.onenter = st_op_disabled_dependency_on_enter,
		.action = st_op_disabled_dependency,
	},
	[NM_RCARRIER_ST_OP_DISABLED_OFFLINE] = {
		.in_event_mask =
			X(NM_EV_STATE_CHG_REP) |
			X(NM_EV_SET_ATTR_ACK),
		.out_state_mask =
			X(NM_RCARRIER_ST_OP_DISABLED_NOTINSTALLED) |
			X(NM_RCARRIER_ST_OP_DISABLED_DEPENDENCY) |
			X(NM_RCARRIER_ST_OP_ENABLED),
		.name = "DISABLED_OFFLINE",
		.onenter = st_op_disabled_offline_on_enter,
		.action = st_op_disabled_offline,
	},
	[NM_RCARRIER_ST_OP_ENABLED] = {
	.in_event_mask =
		X(NM_EV_STATE_CHG_REP),
	.out_state_mask =
		X(NM_RCARRIER_ST_OP_DISABLED_NOTINSTALLED) |
		X(NM_RCARRIER_ST_OP_DISABLED_DEPENDENCY) |
		X(NM_RCARRIER_ST_OP_DISABLED_OFFLINE),
	.name = "ENABLED",
	.onenter = st_op_enabled_on_enter,
	.action = st_op_enabled,
	},
};

struct osmo_fsm nm_rcarrier_fsm = {
	.name = "NM_RCARRIER_OP",
	.states = nm_rcarrier_fsm_states,
	.num_states = ARRAY_SIZE(nm_rcarrier_fsm_states),
	.allstate_event_mask =
		X(NM_EV_OPSTART_ACK) |
		X(NM_EV_OPSTART_NACK) |
		X(NM_EV_FORCE_LOCK) |
		X(NM_EV_OML_DOWN),
	.allstate_action = st_op_allstate,
	.event_names = nm_fsm_event_names,
	.log_subsys = DNM,
};

static __attribute__((constructor)) void nm_rcarrier_fsm_init(void)
{
        OSMO_ASSERT(osmo_fsm_register(&nm_rcarrier_fsm) == 0);
}
