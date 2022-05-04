/* NM GPRS NSE FSM */

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

#include <osmocom/bsc/bts_sm.h>
#include <osmocom/bsc/bts.h>
#include <osmocom/bsc/signal.h>
#include <osmocom/bsc/abis_nm.h>
#include <osmocom/bsc/bts_ipaccess_nanobts_omlattr.h>
#include <osmocom/bsc/nm_common_fsm.h>
#include <osmocom/bsc/debug.h>

#define X(s) (1 << (s))

#define nm_gprs_nse_fsm_state_chg(fi, NEXT_STATE) \
	osmo_fsm_inst_state_chg(fi, NEXT_STATE, 0, 0)

//////////////////////////
// FSM STATE ACTIONS
//////////////////////////

static void st_op_disabled_notinstalled_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct gsm_gprs_nse *nse = (struct gsm_gprs_nse *)fi->priv;

	nse->mo.set_attr_sent = false;
	nse->mo.set_attr_ack_received = false;
	nse->mo.adm_unlock_sent = false;
	nse->mo.opstart_sent = false;
}

static void st_op_disabled_notinstalled(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct nm_statechg_signal_data *nsd;
	struct gsm_nm_state *new_state;

	switch (event) {
	case NM_EV_SW_ACT_REP:
		break;
	case NM_EV_STATE_CHG_REP:
		nsd = (struct nm_statechg_signal_data *)data;
		new_state = nsd->new_state;
		if (new_state->operational == NM_OPSTATE_ENABLED) {
			/* should not happen... */
			nm_gprs_nse_fsm_state_chg(fi, NM_GPRS_NSE_ST_OP_ENABLED);
			return;
		}
		switch (new_state->availability) { /* operational = DISABLED */
		case NM_AVSTATE_DEPENDENCY:
			nm_gprs_nse_fsm_state_chg(fi, NM_GPRS_NSE_ST_OP_DISABLED_DEPENDENCY);
			return;
		case NM_AVSTATE_OFF_LINE:
		case NM_AVSTATE_OK:
			nm_gprs_nse_fsm_state_chg(fi, NM_GPRS_NSE_ST_OP_DISABLED_OFFLINE);
			return;
		default:
			return;
		}
	default:
		OSMO_ASSERT(0);
	}
}

static void configure_loop(struct gsm_gprs_nse *nse, struct gsm_nm_state *state, bool allow_opstart)
{
	struct msgb *msgb;
	struct gsm_bts_sm *bts_sm = container_of(nse, struct gsm_bts_sm, gprs.nse);
	struct gsm_bts *bts = gsm_bts_sm_get_bts(bts_sm);

	if (!nse->mo.set_attr_sent && !nse->mo.set_attr_ack_received) {
		nse->mo.set_attr_sent = true;
		msgb = nanobts_gen_set_nse_attr(bts_sm);
		abis_nm_ipaccess_set_attr(bts, NM_OC_GPRS_NSE, bts->bts_nr,
					  0xff, 0xff, msgb->data,
					  msgb->len);
		msgb_free(msgb);
	}

	/* Attributes must be set before unlocking */
	if (state->administrative != NM_STATE_UNLOCKED && nse->mo.set_attr_ack_received &&
	    !nse->mo.adm_unlock_sent) {
		nse->mo.adm_unlock_sent = true;
		abis_nm_chg_adm_state(bts, NM_OC_GPRS_NSE,
				      bts->bts_nr, 0xff, 0xff,
				      NM_STATE_UNLOCKED);
	}

	if (allow_opstart && state->administrative == NM_STATE_UNLOCKED &&
	    nse->mo.set_attr_ack_received) {
		if (!nse->mo.opstart_sent) {
			nse->mo.opstart_sent = true;
			abis_nm_opstart(bts, NM_OC_GPRS_NSE, bts->bts_nr, 0xff, 0xff);
		}
	}
}

static void st_op_disabled_dependency_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct gsm_gprs_nse *nse = (struct gsm_gprs_nse *)fi->priv;
	struct gsm_bts_sm *bts_sm = container_of(nse, struct gsm_bts_sm, gprs.nse);

	/* nanoBTS is broken, doesn't follow TS 12.21. Opstart MUST be sent
	   during Dependency, so we simply move to OFFLINE state here to avoid
	   duplicating code */
	if (bts_sm->peer_has_no_avstate_offline) {
		nm_gprs_nse_fsm_state_chg(fi, NM_GPRS_NSE_ST_OP_DISABLED_OFFLINE);
		return;
	}
	configure_loop(nse, &nse->mo.nm_state, false);
}

static void st_op_disabled_dependency(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_gprs_nse *nse = (struct gsm_gprs_nse *)fi->priv;
	struct nm_statechg_signal_data *nsd;
	struct gsm_nm_state *new_state;

	switch (event) {
	case NM_EV_SET_ATTR_ACK:
		nse->mo.set_attr_ack_received = true;
		nse->mo.set_attr_sent = false;
		configure_loop(nse, &nse->mo.nm_state, false);
		return;
	case NM_EV_STATE_CHG_REP:
		nsd = (struct nm_statechg_signal_data *)data;
		new_state = nsd->new_state;
		if (new_state->operational == NM_OPSTATE_ENABLED) {
			/* should not happen... */
			nm_gprs_nse_fsm_state_chg(fi, NM_GPRS_NSE_ST_OP_ENABLED);
			return;
		}
		switch (new_state->availability) { /* operational = DISABLED */
		case NM_AVSTATE_NOT_INSTALLED:
		case NM_AVSTATE_POWER_OFF:
			nm_gprs_nse_fsm_state_chg(fi, NM_GPRS_NSE_ST_OP_DISABLED_NOTINSTALLED);
			return;
		case NM_AVSTATE_OFF_LINE:
		case NM_AVSTATE_OK:
			nm_gprs_nse_fsm_state_chg(fi, NM_GPRS_NSE_ST_OP_DISABLED_OFFLINE);
			return;
		case NM_AVSTATE_DEPENDENCY:
			configure_loop(nse, new_state, false);
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
	struct gsm_gprs_nse *nse = (struct gsm_gprs_nse *)fi->priv;

	/* Warning: In here we may be acessing an state older than new_state
	   from prev (syncrhonous) FSM state */
	configure_loop(nse, &nse->mo.nm_state, true);
}

static void st_op_disabled_offline(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_gprs_nse *nse = (struct gsm_gprs_nse *)fi->priv;
	struct gsm_bts_sm *bts_sm = container_of(nse, struct gsm_bts_sm, gprs.nse);
	struct nm_statechg_signal_data *nsd;
	struct gsm_nm_state *new_state;

	switch (event) {
	case NM_EV_SET_ATTR_ACK:
		nse->mo.set_attr_ack_received = true;
		nse->mo.set_attr_sent = false;
		configure_loop(nse, &nse->mo.nm_state, true);
		return;
	case NM_EV_STATE_CHG_REP:
		nsd = (struct nm_statechg_signal_data *)data;
		new_state = nsd->new_state;
		if (new_state->operational == NM_OPSTATE_ENABLED) {
			nm_gprs_nse_fsm_state_chg(fi, NM_GPRS_NSE_ST_OP_ENABLED);
			return;
		}
		switch (new_state->availability) { /* operational = DISABLED */
		case NM_AVSTATE_NOT_INSTALLED:
		case NM_AVSTATE_POWER_OFF:
			nm_gprs_nse_fsm_state_chg(fi, NM_GPRS_NSE_ST_OP_DISABLED_NOTINSTALLED);
			return;
		case NM_AVSTATE_DEPENDENCY:
			/* There's no point in moving back to Dependency, since it's broken
			   and it acts actually as if it was in Offline state */
			if (!bts_sm->peer_has_no_avstate_offline) {
				nm_gprs_nse_fsm_state_chg(fi, NM_GPRS_NSE_ST_OP_DISABLED_DEPENDENCY);
			} else {
				/* Moreover, in nanoBTS we need to check here for tx
				   Opstart since we may have gone Unlocked state
				   in this event, which means Opstart may be txed here. */
				configure_loop(nse, new_state, true);
			}
			return;
		case NM_AVSTATE_OFF_LINE:
		case NM_AVSTATE_OK:
			configure_loop(nse, new_state, true);
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
	struct gsm_gprs_nse *nse = (struct gsm_gprs_nse *)fi->priv;

	/* Reset state, we don't need it in this state and it will need to be
	  reused as soon as we move back to Disabled */
	nse->mo.opstart_sent = false;
	nse->mo.adm_unlock_sent = false;
	nse->mo.set_attr_ack_received = false;
	nse->mo.set_attr_sent = false;
}

static void st_op_enabled(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct nm_statechg_signal_data *nsd;
	struct gsm_nm_state *new_state;

	switch (event) {
	case NM_EV_STATE_CHG_REP:
		nsd = (struct nm_statechg_signal_data *)data;
		new_state = nsd->new_state;
		if (new_state->operational == NM_OPSTATE_ENABLED)
			return;
		switch (new_state->availability) { /* operational = DISABLED */
		case NM_AVSTATE_NOT_INSTALLED:
		case NM_AVSTATE_POWER_OFF:
			nm_gprs_nse_fsm_state_chg(fi, NM_GPRS_NSE_ST_OP_DISABLED_NOTINSTALLED);
			return;
		case NM_AVSTATE_DEPENDENCY:
			nm_gprs_nse_fsm_state_chg(fi, NM_GPRS_NSE_ST_OP_DISABLED_DEPENDENCY);
			return;
		case NM_AVSTATE_OFF_LINE:
		case NM_AVSTATE_OK:
			nm_gprs_nse_fsm_state_chg(fi, NM_GPRS_NSE_ST_OP_DISABLED_OFFLINE);
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
	struct gsm_gprs_nse *nse = (struct gsm_gprs_nse *)fi->priv;
	struct gsm_bts_sm *bts_sm = container_of(nse, struct gsm_bts_sm, gprs.nse);
	struct gsm_bts *bts = gsm_bts_sm_get_bts(bts_sm);

	switch (event) {
	case NM_EV_OPSTART_ACK:
	case NM_EV_OPSTART_NACK:
		/* TODO: if on state OFFLINE and rx NACK, try again? */
		nse->mo.opstart_sent = false;
		break;
	case NM_EV_FORCE_LOCK:
		nse->mo.force_rf_lock = (bool)(intptr_t)data;
		abis_nm_chg_adm_state(bts, NM_OC_GPRS_NSE,
				      bts->bts_nr, 0xff, 0xff,
				      nse->mo.force_rf_lock ? NM_STATE_LOCKED : NM_STATE_UNLOCKED);
		break;
	case NM_EV_OML_DOWN:
		if (fi->state != NM_GPRS_NSE_ST_OP_DISABLED_NOTINSTALLED)
			nm_gprs_nse_fsm_state_chg(fi, NM_GPRS_NSE_ST_OP_DISABLED_NOTINSTALLED);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static struct osmo_fsm_state nm_gprs_nse_fsm_states[] = {
	[NM_GPRS_NSE_ST_OP_DISABLED_NOTINSTALLED] = {
		.in_event_mask =
			X(NM_EV_SW_ACT_REP) |
			X(NM_EV_STATE_CHG_REP),
		.out_state_mask =
			X(NM_GPRS_NSE_ST_OP_DISABLED_DEPENDENCY) |
			X(NM_GPRS_NSE_ST_OP_DISABLED_OFFLINE) |
			X(NM_GPRS_NSE_ST_OP_ENABLED),
		.name = "DISABLED_NOTINSTALLED",
		.onenter = st_op_disabled_notinstalled_on_enter,
		.action = st_op_disabled_notinstalled,
	},
	[NM_GPRS_NSE_ST_OP_DISABLED_DEPENDENCY] = {
		.in_event_mask =
			X(NM_EV_STATE_CHG_REP) |
			X(NM_EV_SET_ATTR_ACK),
		.out_state_mask =
			X(NM_GPRS_NSE_ST_OP_DISABLED_NOTINSTALLED) |
			X(NM_GPRS_NSE_ST_OP_DISABLED_OFFLINE) |
			X(NM_GPRS_NSE_ST_OP_ENABLED),
		.name = "DISABLED_DEPENDENCY",
		.onenter = st_op_disabled_dependency_on_enter,
		.action = st_op_disabled_dependency,
	},
	[NM_GPRS_NSE_ST_OP_DISABLED_OFFLINE] = {
		.in_event_mask =
			X(NM_EV_STATE_CHG_REP) |
			X(NM_EV_SET_ATTR_ACK),
		.out_state_mask =
			X(NM_GPRS_NSE_ST_OP_DISABLED_NOTINSTALLED) |
			X(NM_GPRS_NSE_ST_OP_DISABLED_DEPENDENCY) |
			X(NM_GPRS_NSE_ST_OP_ENABLED),
		.name = "DISABLED_OFFLINE",
		.onenter = st_op_disabled_offline_on_enter,
		.action = st_op_disabled_offline,
	},
	[NM_GPRS_NSE_ST_OP_ENABLED] = {
	.in_event_mask =
		X(NM_EV_STATE_CHG_REP),
	.out_state_mask =
		X(NM_GPRS_NSE_ST_OP_DISABLED_NOTINSTALLED) |
		X(NM_GPRS_NSE_ST_OP_DISABLED_DEPENDENCY) |
		X(NM_GPRS_NSE_ST_OP_DISABLED_OFFLINE),
	.name = "ENABLED",
	.onenter = st_op_enabled_on_enter,
	.action = st_op_enabled,
	},
};

struct osmo_fsm nm_gprs_nse_fsm = {
	.name = "NM_GPRS_NSE_OP",
	.states = nm_gprs_nse_fsm_states,
	.num_states = ARRAY_SIZE(nm_gprs_nse_fsm_states),
	.allstate_event_mask =
		X(NM_EV_OPSTART_ACK) |
		X(NM_EV_OPSTART_NACK) |
		X(NM_EV_FORCE_LOCK) |
		X(NM_EV_OML_DOWN),
	.allstate_action = st_op_allstate,
	.event_names = nm_fsm_event_names,
	.log_subsys = DNM,
};

static __attribute__((constructor)) void nm_gprs_nse_fsm_init(void)
{
        OSMO_ASSERT(osmo_fsm_register(&nm_gprs_nse_fsm) == 0);
}
