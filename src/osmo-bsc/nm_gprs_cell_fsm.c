/* NM GPRS Cell FSM */

/* (C) 2020 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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

#define nm_gprs_cell_fsm_state_chg(fi, NEXT_STATE) \
	osmo_fsm_inst_state_chg(fi, NEXT_STATE, 0, 0)

//////////////////////////
// FSM STATE ACTIONS
//////////////////////////

static void st_op_disabled_notinstalled_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct gsm_gprs_cell *cell = (struct gsm_gprs_cell *)fi->priv;

	cell->mo.get_attr_sent = false;
	cell->mo.get_attr_rep_received = false;
	cell->mo.set_attr_sent = false;
	cell->mo.set_attr_ack_received = false;
	cell->mo.adm_unlock_sent = false;
	cell->mo.opstart_sent = false;
}

static void st_op_disabled_notinstalled(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct nm_statechg_signal_data *nsd;
	const struct gsm_nm_state *new_state;

	switch (event) {
	case NM_EV_SW_ACT_REP:
	case NM_EV_SETUP_RAMP_READY:
		break;
	case NM_EV_STATE_CHG_REP:
		nsd = (struct nm_statechg_signal_data *)data;
		new_state = &nsd->new_state;
		if (new_state->operational == NM_OPSTATE_ENABLED) {
			/* should not happen... */
			nm_gprs_cell_fsm_state_chg(fi, NM_GPRS_CELL_ST_OP_ENABLED);
			return;
		}
		switch (new_state->availability) { /* operational = DISABLED */
		case NM_AVSTATE_DEPENDENCY:
			nm_gprs_cell_fsm_state_chg(fi, NM_GPRS_CELL_ST_OP_DISABLED_DEPENDENCY);
			return;
		case NM_AVSTATE_OFF_LINE:
		case NM_AVSTATE_OK:
			nm_gprs_cell_fsm_state_chg(fi, NM_GPRS_CELL_ST_OP_DISABLED_OFFLINE);
			return;
		default:
			return;
		}
	default:
		OSMO_ASSERT(0);
	}
}

static void configure_loop(struct gsm_gprs_cell *cell, const struct gsm_nm_state *state, bool allow_opstart)
{
	struct msgb *msgb;
	struct gsm_bts *bts = container_of(cell, struct gsm_bts, gprs.cell);

	if (bts->gprs.mode == BTS_GPRS_NONE)
		return;

	if (bts_setup_ramp_wait(bts))
		return;

	if (!cell->mo.get_attr_sent && !cell->mo.get_attr_rep_received) {
		uint8_t attr_buf[2]; /* enlarge if needed */
		uint8_t *ptr = &attr_buf[0];

		*(ptr++) = NM_ATT_SW_CONFIG;
		if (is_ipa_abisip_bts(bts))
			*(ptr++) = NM_ATT_IPACC_SUPP_FEATURES;

		OSMO_ASSERT((ptr - attr_buf) <= sizeof(attr_buf));
		abis_nm_get_attr(bts, NM_OC_GPRS_CELL,
				 bts->bts_nr, 0x00, 0xff,
				 &attr_buf[0], (ptr - attr_buf));
		cell->mo.get_attr_sent = true;
	}

	/* OS#6172: old osmo-bts versions do NACK Get Attributes for GPRS Cell,
	 * so we do not check if cell->mo.get_attr_rep_received is set here. */
	if (!cell->mo.set_attr_sent && !cell->mo.set_attr_ack_received) {
		cell->mo.set_attr_sent = true;
		msgb = nanobts_gen_set_cell_attr(bts);
		OSMO_ASSERT(msgb);
		abis_nm_ipaccess_set_attr(bts, NM_OC_GPRS_CELL, bts->bts_nr,
					  0, 0xff, msgb->data, msgb->len);
		msgb_free(msgb);
	}

	if (state->administrative != NM_STATE_UNLOCKED && !cell->mo.adm_unlock_sent) {
		cell->mo.adm_unlock_sent = true;
		abis_nm_chg_adm_state(bts, NM_OC_GPRS_CELL,
				      bts->bts_nr, 0, 0xff,
				      NM_STATE_UNLOCKED);
	}

	if (allow_opstart && state->administrative == NM_STATE_UNLOCKED &&
	    cell->mo.set_attr_ack_received) {
		if (!cell->mo.opstart_sent) {
			cell->mo.opstart_sent = true;
			abis_nm_opstart(bts, NM_OC_GPRS_CELL, bts->bts_nr, 0, 0xff);
		}
	}
}

static void st_op_disabled_dependency_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct gsm_gprs_cell *cell = (struct gsm_gprs_cell *)fi->priv;
	struct gsm_bts *bts = container_of(cell, struct gsm_bts, gprs.cell);

	/* nanoBTS is broken, doesn't follow TS 12.21. Opstart MUST be sent
	   during Dependency, so we simply move to OFFLINE state here to avoid
	   duplicating code */
	if (bts->site_mgr->peer_has_no_avstate_offline) {
		nm_gprs_cell_fsm_state_chg(fi, NM_GPRS_CELL_ST_OP_DISABLED_OFFLINE);
		return;
	}
	configure_loop(cell, &cell->mo.nm_state, false);
}

static void st_op_disabled_dependency(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_gprs_cell *cell = (struct gsm_gprs_cell *)fi->priv;
	struct nm_statechg_signal_data *nsd;
	const struct gsm_nm_state *new_state;

	switch (event) {
	case NM_EV_SW_ACT_REP:
		configure_loop(cell, &cell->mo.nm_state, false);
		break;
	case NM_EV_GET_ATTR_REP:
		cell->mo.get_attr_rep_received = true;
		cell->mo.get_attr_sent = false;
		configure_loop(cell, &cell->mo.nm_state, false);
		return;
	case NM_EV_SET_ATTR_ACK:
		cell->mo.set_attr_ack_received = true;
		cell->mo.set_attr_sent = false;
		configure_loop(cell, &cell->mo.nm_state, false);
		return;
	case NM_EV_STATE_CHG_REP:
		nsd = (struct nm_statechg_signal_data *)data;
		new_state = &nsd->new_state;
		if (new_state->operational == NM_OPSTATE_ENABLED) {
			/* should not happen... */
			nm_gprs_cell_fsm_state_chg(fi, NM_GPRS_CELL_ST_OP_ENABLED);
			return;
		}
		switch (new_state->availability) { /* operational = DISABLED */
		case NM_AVSTATE_NOT_INSTALLED:
		case NM_AVSTATE_POWER_OFF:
			nm_gprs_cell_fsm_state_chg(fi, NM_GPRS_CELL_ST_OP_DISABLED_NOTINSTALLED);
			return;
		case NM_AVSTATE_OFF_LINE:
		case NM_AVSTATE_OK:
			nm_gprs_cell_fsm_state_chg(fi, NM_GPRS_CELL_ST_OP_DISABLED_OFFLINE);
			return;
		case NM_AVSTATE_DEPENDENCY:
			configure_loop(cell, new_state, false);
			return;
		default:
			return;
		}
	case NM_EV_SETUP_RAMP_READY:
		configure_loop(cell, &cell->mo.nm_state, false);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_op_disabled_offline_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct gsm_gprs_cell *cell = (struct gsm_gprs_cell *)fi->priv;

	configure_loop(cell, &cell->mo.nm_state, true);
}

static void st_op_disabled_offline(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_gprs_cell *cell = (struct gsm_gprs_cell *)fi->priv;
	struct gsm_bts *bts = container_of(cell, struct gsm_bts, gprs.cell);
	struct nm_statechg_signal_data *nsd;
	const struct gsm_nm_state *new_state;

	switch (event) {
	case NM_EV_SW_ACT_REP:
		configure_loop(cell, &cell->mo.nm_state, true);
		break;
	case NM_EV_GET_ATTR_REP:
		cell->mo.get_attr_rep_received = true;
		cell->mo.get_attr_sent = false;
		configure_loop(cell, &cell->mo.nm_state, true);
		return;
	case NM_EV_SET_ATTR_ACK:
		cell->mo.set_attr_ack_received = true;
		cell->mo.set_attr_sent = false;
		configure_loop(cell, &cell->mo.nm_state, true);
		return;
	case NM_EV_STATE_CHG_REP:
		nsd = (struct nm_statechg_signal_data *)data;
		new_state = &nsd->new_state;
		if (new_state->operational == NM_OPSTATE_ENABLED) {
			nm_gprs_cell_fsm_state_chg(fi, NM_GPRS_CELL_ST_OP_ENABLED);
			return;
		}
		switch (new_state->availability) { /* operational = DISABLED */
		case NM_AVSTATE_NOT_INSTALLED:
		case NM_AVSTATE_POWER_OFF:
			nm_gprs_cell_fsm_state_chg(fi, NM_GPRS_CELL_ST_OP_DISABLED_NOTINSTALLED);
			return;
		case NM_AVSTATE_DEPENDENCY:
			/* There's no point in moving back to Dependency, since it's broken
			   and it acts actually as if it was in Offline state */
			if (!bts->site_mgr->peer_has_no_avstate_offline) {
				nm_gprs_cell_fsm_state_chg(fi, NM_GPRS_CELL_ST_OP_DISABLED_DEPENDENCY);
			} else {
				/* Moreover, in nanoBTS we need to check here for tx
				   Opstart since we may have gone Unlocked state
				   in this event, which means Opstart may be txed here. */
				configure_loop(cell, new_state, true);
			}
			return;
		case NM_AVSTATE_OFF_LINE:
		case NM_AVSTATE_OK:
			configure_loop(cell, new_state, true);
			return;
		default:
			return;
		}
	case NM_EV_SETUP_RAMP_READY:
		configure_loop(cell, &cell->mo.nm_state, true);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_op_enabled_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct gsm_gprs_cell *cell = (struct gsm_gprs_cell *)fi->priv;

	/* Reset state, we don't need it in this state and it will need to be
	  reused as soon as we move back to Disabled */
	cell->mo.opstart_sent = false;
	cell->mo.adm_unlock_sent = false;
	cell->mo.set_attr_ack_received = false;
	cell->mo.set_attr_sent = false;
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
			nm_gprs_cell_fsm_state_chg(fi, NM_GPRS_CELL_ST_OP_DISABLED_NOTINSTALLED);
			return;
		case NM_AVSTATE_DEPENDENCY:
			nm_gprs_cell_fsm_state_chg(fi, NM_GPRS_CELL_ST_OP_DISABLED_DEPENDENCY);
			return;
		case NM_AVSTATE_OFF_LINE:
		case NM_AVSTATE_OK:
			nm_gprs_cell_fsm_state_chg(fi, NM_GPRS_CELL_ST_OP_DISABLED_OFFLINE);
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
	struct gsm_gprs_cell *cell = (struct gsm_gprs_cell *)fi->priv;
	struct gsm_bts *bts = container_of(cell, struct gsm_bts, gprs.cell);

	switch (event) {
	case NM_EV_OPSTART_ACK:
	case NM_EV_OPSTART_NACK:
		/* TODO: if on state OFFLINE and rx NACK, try again? */
		cell->mo.opstart_sent = false;
		break;
	case NM_EV_FORCE_LOCK:
		cell->mo.force_rf_lock = (bool)(intptr_t)data;
		abis_nm_chg_adm_state(bts, NM_OC_GPRS_CELL,
				      bts->bts_nr, 0, 0xff,
				      cell->mo.force_rf_lock ? NM_STATE_LOCKED : NM_STATE_UNLOCKED);
		break;
	case NM_EV_OML_DOWN:
		if (fi->state != NM_GPRS_CELL_ST_OP_DISABLED_NOTINSTALLED)
			nm_gprs_cell_fsm_state_chg(fi, NM_GPRS_CELL_ST_OP_DISABLED_NOTINSTALLED);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static struct osmo_fsm_state nm_gprs_cell_fsm_states[] = {
	[NM_GPRS_CELL_ST_OP_DISABLED_NOTINSTALLED] = {
		.in_event_mask =
			X(NM_EV_SW_ACT_REP) |
			X(NM_EV_STATE_CHG_REP) |
			X(NM_EV_SETUP_RAMP_READY),
		.out_state_mask =
			X(NM_GPRS_CELL_ST_OP_DISABLED_DEPENDENCY) |
			X(NM_GPRS_CELL_ST_OP_DISABLED_OFFLINE) |
			X(NM_GPRS_CELL_ST_OP_ENABLED),
		.name = "DISABLED_NOTINSTALLED",
		.onenter = st_op_disabled_notinstalled_on_enter,
		.action = st_op_disabled_notinstalled,
	},
	[NM_GPRS_CELL_ST_OP_DISABLED_DEPENDENCY] = {
		.in_event_mask =
			X(NM_EV_SW_ACT_REP) |
			X(NM_EV_STATE_CHG_REP) |
			X(NM_EV_GET_ATTR_REP) |
			X(NM_EV_SET_ATTR_ACK) |
			X(NM_EV_SETUP_RAMP_READY),
		.out_state_mask =
			X(NM_GPRS_CELL_ST_OP_DISABLED_NOTINSTALLED) |
			X(NM_GPRS_CELL_ST_OP_DISABLED_OFFLINE) |
			X(NM_GPRS_CELL_ST_OP_ENABLED),
		.name = "DISABLED_DEPENDENCY",
		.onenter = st_op_disabled_dependency_on_enter,
		.action = st_op_disabled_dependency,
	},
	[NM_GPRS_CELL_ST_OP_DISABLED_OFFLINE] = {
		.in_event_mask =
			X(NM_EV_SW_ACT_REP) |
			X(NM_EV_STATE_CHG_REP) |
			X(NM_EV_GET_ATTR_REP) |
			X(NM_EV_SET_ATTR_ACK) |
			X(NM_EV_SETUP_RAMP_READY),
		.out_state_mask =
			X(NM_GPRS_CELL_ST_OP_DISABLED_NOTINSTALLED) |
			X(NM_GPRS_CELL_ST_OP_DISABLED_DEPENDENCY) |
			X(NM_GPRS_CELL_ST_OP_ENABLED),
		.name = "DISABLED_OFFLINE",
		.onenter = st_op_disabled_offline_on_enter,
		.action = st_op_disabled_offline,
	},
	[NM_GPRS_CELL_ST_OP_ENABLED] = {
	.in_event_mask =
		X(NM_EV_STATE_CHG_REP),
	.out_state_mask =
		X(NM_GPRS_CELL_ST_OP_DISABLED_NOTINSTALLED) |
		X(NM_GPRS_CELL_ST_OP_DISABLED_DEPENDENCY) |
		X(NM_GPRS_CELL_ST_OP_DISABLED_OFFLINE),
	.name = "ENABLED",
	.onenter = st_op_enabled_on_enter,
	.action = st_op_enabled,
	},
};

struct osmo_fsm nm_gprs_cell_fsm = {
	.name = "NM_GPRS_CELL_OP",
	.states = nm_gprs_cell_fsm_states,
	.num_states = ARRAY_SIZE(nm_gprs_cell_fsm_states),
	.allstate_event_mask =
		X(NM_EV_OPSTART_ACK) |
		X(NM_EV_OPSTART_NACK) |
		X(NM_EV_FORCE_LOCK) |
		X(NM_EV_OML_DOWN),
	.allstate_action = st_op_allstate,
	.event_names = nm_fsm_event_names,
	.log_subsys = DNM,
};

static __attribute__((constructor)) void nm_gprs_cell_fsm_init(void)
{
        OSMO_ASSERT(osmo_fsm_register(&nm_gprs_cell_fsm) == 0);
}
