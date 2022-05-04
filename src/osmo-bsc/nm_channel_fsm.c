/* NM Radio Channel FSM */

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
#include <osmocom/bsc/ipaccess.h>
#include <osmocom/bsc/nm_common_fsm.h>
#include <osmocom/bsc/debug.h>

#define X(s) (1 << (s))

#define nm_chan_fsm_state_chg(fi, NEXT_STATE) \
	osmo_fsm_inst_state_chg(fi, NEXT_STATE, 0, 0)

//////////////////////////
// FSM STATE ACTIONS
//////////////////////////

static void st_op_disabled_notinstalled_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct gsm_bts_trx_ts *ts = (struct gsm_bts_trx_ts *)fi->priv;

	ts->mo.set_attr_sent = false;
	ts->mo.set_attr_ack_received = false;
	ts->mo.adm_unlock_sent = false;
	ts->mo.opstart_sent = false;
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
		new_state = &nsd->new_state;
		if (new_state->operational == NM_OPSTATE_ENABLED) {
			/*should not happen... */
			nm_chan_fsm_state_chg(fi, NM_CHAN_ST_OP_ENABLED);
			return;
		}
		switch (new_state->availability) { /* operational = DISABLED */
		case NM_AVSTATE_DEPENDENCY:
			nm_chan_fsm_state_chg(fi, NM_CHAN_ST_OP_DISABLED_DEPENDENCY);
			return;
		case NM_AVSTATE_OFF_LINE:
		case NM_AVSTATE_OK:
			nm_chan_fsm_state_chg(fi, NM_CHAN_ST_OP_DISABLED_OFFLINE);
			return;
		default:
			return;
		}
	default:
		OSMO_ASSERT(0);
	}
}

static void configure_loop(struct gsm_bts_trx_ts *ts, const struct gsm_nm_state *state, bool allow_opstart)
{
	enum abis_nm_chan_comb ccomb;
	struct gsm_bts_trx *trx = ts->trx;

	if (!ts->mo.set_attr_sent && !ts->mo.set_attr_ack_received) {
		ts->mo.set_attr_sent = true;
		ccomb = abis_nm_chcomb4pchan(ts->pchan_from_config);
		if (abis_nm_set_channel_attr(ts, ccomb) == -EINVAL)
			ipaccess_drop_oml_deferred(trx->bts);
	}

	if (state->administrative != NM_STATE_UNLOCKED && !ts->mo.adm_unlock_sent) {
		ts->mo.adm_unlock_sent = true;
		abis_nm_chg_adm_state(trx->bts, NM_OC_CHANNEL,
				      trx->bts->bts_nr, trx->nr, ts->nr,
				      NM_STATE_UNLOCKED);
	}

	if (allow_opstart && state->administrative == NM_STATE_UNLOCKED &&
	    ts->mo.set_attr_ack_received && !ts->mo.opstart_sent) {
		ts->mo.opstart_sent = true;
		abis_nm_opstart(trx->bts, NM_OC_CHANNEL, trx->bts->bts_nr, trx->nr, ts->nr);
	}
}

static void st_op_disabled_dependency_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct gsm_bts_trx_ts *ts = (struct gsm_bts_trx_ts *)fi->priv;

	if (ts->trx->bts->site_mgr->peer_has_no_avstate_offline) {
		nm_chan_fsm_state_chg(fi, NM_CHAN_ST_OP_DISABLED_OFFLINE);
		return;
	}
	configure_loop(ts, &ts->mo.nm_state, false);
}

static void st_op_disabled_dependency(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_bts_trx_ts *ts = (struct gsm_bts_trx_ts *)fi->priv;
	struct nm_statechg_signal_data *nsd;
	const struct gsm_nm_state *new_state;

	switch (event) {
	case NM_EV_SET_ATTR_ACK:
		ts->mo.set_attr_ack_received = true;
		ts->mo.set_attr_sent = false;
		configure_loop(ts, &ts->mo.nm_state, false);
		return;
	case NM_EV_STATE_CHG_REP:
		nsd = (struct nm_statechg_signal_data *)data;
		new_state = &nsd->new_state;
		if (new_state->operational == NM_OPSTATE_ENABLED) {
			/* should not happen... */
			nm_chan_fsm_state_chg(fi, NM_CHAN_ST_OP_ENABLED);
			return;
		}
		switch (new_state->availability) { /* operational = DISABLED */
		case NM_AVSTATE_NOT_INSTALLED:
		case NM_AVSTATE_POWER_OFF:
			nm_chan_fsm_state_chg(fi, NM_CHAN_ST_OP_DISABLED_NOTINSTALLED);
			return;
		case NM_AVSTATE_OFF_LINE:
		case NM_AVSTATE_OK:
			nm_chan_fsm_state_chg(fi, NM_CHAN_ST_OP_DISABLED_OFFLINE);
			return;
		case NM_AVSTATE_DEPENDENCY:
			configure_loop(ts, new_state, false);
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
	struct gsm_bts_trx_ts *ts = (struct gsm_bts_trx_ts *)fi->priv;

	/* Warning: In here we may be acessing an state older than new_state
	   from prev (syncrhonous) FSM state */
	configure_loop(ts, &ts->mo.nm_state, true);
}

static void st_op_disabled_offline(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_bts_trx_ts *ts = (struct gsm_bts_trx_ts *)fi->priv;
	struct nm_statechg_signal_data *nsd;
	const struct gsm_nm_state *new_state;

	switch (event) {
	case NM_EV_SET_ATTR_ACK:
		ts->mo.set_attr_ack_received = true;
		ts->mo.set_attr_sent = false;
		configure_loop(ts, &ts->mo.nm_state, true);
		return;
	case NM_EV_STATE_CHG_REP:
		nsd = (struct nm_statechg_signal_data *)data;
		new_state = &nsd->new_state;
		if (new_state->operational == NM_OPSTATE_ENABLED) {
			nm_chan_fsm_state_chg(fi, NM_CHAN_ST_OP_ENABLED);
			return;
		}
		switch (new_state->availability) { /* operational = DISABLED */
		case NM_AVSTATE_NOT_INSTALLED:
		case NM_AVSTATE_POWER_OFF:
			nm_chan_fsm_state_chg(fi, NM_CHAN_ST_OP_DISABLED_NOTINSTALLED);
			return;
		case NM_AVSTATE_DEPENDENCY:
			/* There's no point in moving back to Dependency, since it's broken
			   and it acts actually as if it was in Offline state */
			if (!ts->trx->bts->site_mgr->peer_has_no_avstate_offline) {
				nm_chan_fsm_state_chg(fi, NM_CHAN_ST_OP_DISABLED_DEPENDENCY);
			} else {
				/* Moreover, in nanoBTS we need to check here for tx
				   Opstart since we may have gone Unlocked state
				   in this event, which means Opstart may be txed here. */
				configure_loop(ts, new_state, true);
			}
			return;
		case NM_AVSTATE_OFF_LINE:
		case NM_AVSTATE_OK:
			configure_loop(ts, new_state, true);
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
	struct gsm_bts_trx_ts *ts = (struct gsm_bts_trx_ts *)fi->priv;

	/* Reset state, we don't need it in this state and it will need to be
	  reused as soon as we move back to Disabled */
	ts->mo.opstart_sent = false;
	ts->mo.adm_unlock_sent = false;
	ts->mo.set_attr_ack_received = false;
	ts->mo.set_attr_sent = false;
}

static void st_op_enabled(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct nm_statechg_signal_data *nsd;
	const struct gsm_nm_state *new_state;

	switch (event) {
	case NM_EV_STATE_CHG_REP:
		nsd = (struct nm_statechg_signal_data *)data;
		new_state = &nsd->new_state;
		if (new_state->operational == NM_OPSTATE_ENABLED)
			return;
		switch (new_state->availability) { /* operational = DISABLED */
		case NM_AVSTATE_NOT_INSTALLED:
		case NM_AVSTATE_POWER_OFF:
			nm_chan_fsm_state_chg(fi, NM_CHAN_ST_OP_DISABLED_NOTINSTALLED);
			return;
		case NM_AVSTATE_DEPENDENCY:
			nm_chan_fsm_state_chg(fi, NM_CHAN_ST_OP_DISABLED_DEPENDENCY);
			return;
		case NM_AVSTATE_OFF_LINE:
		case NM_AVSTATE_OK:
			nm_chan_fsm_state_chg(fi, NM_CHAN_ST_OP_DISABLED_OFFLINE);
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
	struct gsm_bts_trx_ts *ts = (struct gsm_bts_trx_ts *)fi->priv;

	switch (event) {
	case NM_EV_OPSTART_ACK:
	case NM_EV_OPSTART_NACK:
		/* TODO: if on state OFFLINE and rx NACK, try again? */
		ts->mo.opstart_sent = false;
		break;
	case NM_EV_OML_DOWN:
		if (fi->state != NM_CHAN_ST_OP_DISABLED_NOTINSTALLED)
			nm_chan_fsm_state_chg(fi, NM_CHAN_ST_OP_DISABLED_NOTINSTALLED);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static struct osmo_fsm_state nm_chan_fsm_states[] = {
	[NM_CHAN_ST_OP_DISABLED_NOTINSTALLED] = {
		.in_event_mask =
			X(NM_EV_SW_ACT_REP) |
			X(NM_EV_STATE_CHG_REP),
		.out_state_mask =
			X(NM_CHAN_ST_OP_DISABLED_DEPENDENCY) |
			X(NM_CHAN_ST_OP_DISABLED_OFFLINE) |
			X(NM_CHAN_ST_OP_ENABLED),
		.name = "DISABLED_NOTINSTALLED",
		.onenter = st_op_disabled_notinstalled_on_enter,
		.action = st_op_disabled_notinstalled,
	},
	[NM_CHAN_ST_OP_DISABLED_DEPENDENCY] = {
		.in_event_mask =
			X(NM_EV_STATE_CHG_REP) |
                        X(NM_EV_SET_ATTR_ACK),
		.out_state_mask =
			X(NM_CHAN_ST_OP_DISABLED_NOTINSTALLED) |
			X(NM_CHAN_ST_OP_DISABLED_OFFLINE) |
			X(NM_CHAN_ST_OP_ENABLED),
		.name = "DISABLED_DEPENDENCY",
		.onenter = st_op_disabled_dependency_on_enter,
		.action = st_op_disabled_dependency,
	},
	[NM_CHAN_ST_OP_DISABLED_OFFLINE] = {
		.in_event_mask =
			X(NM_EV_STATE_CHG_REP) |
			X(NM_EV_SET_ATTR_ACK),
		.out_state_mask =
			X(NM_CHAN_ST_OP_DISABLED_NOTINSTALLED) |
			X(NM_CHAN_ST_OP_DISABLED_DEPENDENCY) |
			X(NM_CHAN_ST_OP_ENABLED),
		.name = "DISABLED_OFFLINE",
		.onenter = st_op_disabled_offline_on_enter,
		.action = st_op_disabled_offline,
	},
	[NM_CHAN_ST_OP_ENABLED] = {
		.in_event_mask =
			X(NM_EV_STATE_CHG_REP),
		.out_state_mask =
			X(NM_CHAN_ST_OP_DISABLED_NOTINSTALLED) |
			X(NM_CHAN_ST_OP_DISABLED_DEPENDENCY) |
			X(NM_CHAN_ST_OP_DISABLED_OFFLINE),
		.name = "ENABLED",
		.onenter = st_op_enabled_on_enter,
		.action = st_op_enabled,
	},
};

struct osmo_fsm nm_chan_fsm = {
	.name = "NM_CHAN_OP",
	.states = nm_chan_fsm_states,
	.num_states = ARRAY_SIZE(nm_chan_fsm_states),
	.allstate_event_mask =
		X(NM_EV_OPSTART_ACK) |
		X(NM_EV_OPSTART_NACK) |
		X(NM_EV_OML_DOWN),
	.allstate_action = st_op_allstate,
	.event_names = nm_fsm_event_names,
	.log_subsys = DNM,
};

static __attribute__((constructor)) void nm_chan_fsm_init(void)
{
	OSMO_ASSERT(osmo_fsm_register(&nm_chan_fsm) == 0);
}
