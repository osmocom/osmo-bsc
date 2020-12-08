/* NM BTS Site Manager FSM */

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
#include <osmocom/bsc/nm_common_fsm.h>
#include <osmocom/bsc/debug.h>

#define X(s) (1 << (s))

#define nm_bts_sm_fsm_state_chg(fi, NEXT_STATE) \
	osmo_fsm_inst_state_chg(fi, NEXT_STATE, 0, 0)

//////////////////////////
// FSM STATE ACTIONS
//////////////////////////

static void st_op_disabled_notinstalled_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct gsm_bts_sm *site_mgr = (struct gsm_bts_sm *)fi->priv;
	struct gsm_bts *bts = gsm_bts_sm_get_bts(site_mgr);

	site_mgr->peer_has_no_avstate_offline = (bts->type == GSM_BTS_TYPE_NANOBTS);
	site_mgr->mo.opstart_sent = false;
}

static void st_op_disabled_notinstalled(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_bts_sm *site_mgr = (struct gsm_bts_sm *)fi->priv;
	struct gsm_bts *bts = gsm_bts_sm_get_bts(site_mgr);
	struct nm_statechg_signal_data *nsd;
	struct gsm_nm_state *new_state;

	switch (event) {
	case NM_EV_SW_ACT_REP:
		break;
	case NM_EV_STATE_CHG_REP:
		nsd = (struct nm_statechg_signal_data *)data;
		new_state = nsd->new_state;
		if (new_state->operational == NM_OPSTATE_ENABLED) {
			/* nanobts always go directly into Reported ENABLED state during
			   startup, but we still need to OPSTART it, otherwise it won't
			   connect on RSL later on */
			if (bts->type == GSM_BTS_TYPE_NANOBTS) {
				site_mgr->mo.opstart_sent = true;
				abis_nm_opstart(bts, NM_OC_SITE_MANAGER, 0xff, 0xff, 0xff);
			} else {
				LOGPFSML(fi, LOGL_NOTICE, "Received BTS Site Mgr State Report Enabled "
					 "without Opstart. You are probably using a nanoBTS but don't "
					 "have your .cfg with 'type nanobts'. Otherwise, you probably "
					 "are using an old osmo-bts; automatically adjusting OML "
					 "behavior to be backward-compatible.\n");
			}
			site_mgr->peer_has_no_avstate_offline = true;
			nm_bts_sm_fsm_state_chg(fi, NM_BTS_SM_ST_OP_ENABLED);
			return;
		}
		switch (new_state->availability) { /* operational = DISABLED */
		case NM_AVSTATE_DEPENDENCY:
			nm_bts_sm_fsm_state_chg(fi, NM_BTS_SM_ST_OP_DISABLED_DEPENDENCY);
			return;
		case NM_AVSTATE_OFF_LINE:
		case NM_AVSTATE_OK:
			nm_bts_sm_fsm_state_chg(fi, NM_BTS_SM_ST_OP_DISABLED_OFFLINE);
			return;
		default:
			return;
		}
	default:
		OSMO_ASSERT(0);
	}
}

static void st_op_disabled_dependency(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct nm_statechg_signal_data *nsd;
	struct gsm_nm_state *new_state;

	switch (event) {
	case NM_EV_STATE_CHG_REP:
		nsd = (struct nm_statechg_signal_data *)data;
		new_state = nsd->new_state;
		if (new_state->operational == NM_OPSTATE_ENABLED) {
			nm_bts_sm_fsm_state_chg(fi, NM_BTS_SM_ST_OP_ENABLED);
			return;
		}
		switch (new_state->availability) { /* operational = DISABLED */
		case NM_AVSTATE_NOT_INSTALLED:
		case NM_AVSTATE_POWER_OFF:
			nm_bts_sm_fsm_state_chg(fi, NM_BTS_SM_ST_OP_DISABLED_NOTINSTALLED);
			return;
		case NM_AVSTATE_OFF_LINE:
		case NM_AVSTATE_OK:
			nm_bts_sm_fsm_state_chg(fi, NM_BTS_SM_ST_OP_DISABLED_OFFLINE);
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
	struct gsm_bts_sm *site_mgr = (struct gsm_bts_sm *)fi->priv;
	struct gsm_bts *bts = gsm_bts_sm_get_bts(site_mgr);
	if (!site_mgr->mo.opstart_sent) {
		site_mgr->mo.opstart_sent = true;
		abis_nm_opstart(bts, NM_OC_SITE_MANAGER, 0xff, 0xff, 0xff);
	}
}

static void st_op_disabled_offline(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct nm_statechg_signal_data *nsd;
	struct gsm_nm_state *new_state;

	switch (event) {
	case NM_EV_STATE_CHG_REP:
		nsd = (struct nm_statechg_signal_data *)data;
		new_state = nsd->new_state;
		if (new_state->operational == NM_OPSTATE_ENABLED) {
			nm_bts_sm_fsm_state_chg(fi, NM_BTS_SM_ST_OP_ENABLED);
			return;
		}
		switch (new_state->availability) { /* operational = DISABLED */
		case NM_AVSTATE_NOT_INSTALLED:
		case NM_AVSTATE_POWER_OFF:
			nm_bts_sm_fsm_state_chg(fi, NM_BTS_SM_ST_OP_DISABLED_NOTINSTALLED);
			return;
		case NM_AVSTATE_DEPENDENCY:
			nm_bts_sm_fsm_state_chg(fi, NM_BTS_SM_ST_OP_DISABLED_DEPENDENCY);
			return;
		case NM_AVSTATE_OFF_LINE:
		case NM_AVSTATE_OK:
			return;
		default:
			return;
		}
	default:
		OSMO_ASSERT(0);
	}
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
			nm_bts_sm_fsm_state_chg(fi, NM_BTS_SM_ST_OP_DISABLED_NOTINSTALLED);
			return;
		case NM_AVSTATE_DEPENDENCY:
			nm_bts_sm_fsm_state_chg(fi, NM_BTS_SM_ST_OP_DISABLED_DEPENDENCY);
			return;
		case NM_AVSTATE_OFF_LINE:
		case NM_AVSTATE_OK:
			nm_bts_sm_fsm_state_chg(fi, NM_BTS_SM_ST_OP_DISABLED_OFFLINE);
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
	struct gsm_bts_sm *site_mgr = (struct gsm_bts_sm *)fi->priv;

	switch (event) {
	case NM_EV_OPSTART_ACK:
	case NM_EV_OPSTART_NACK:
		/* TODO: if on state OFFLINE and rx NACK, try again? */
		site_mgr->mo.opstart_sent = false;
		break;
	case NM_EV_OML_DOWN:
		if (fi->state != NM_BTS_SM_ST_OP_DISABLED_NOTINSTALLED)
			nm_bts_sm_fsm_state_chg(fi, NM_BTS_SM_ST_OP_DISABLED_NOTINSTALLED);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static struct osmo_fsm_state nm_bts_sm_fsm_states[] = {
	[NM_BTS_SM_ST_OP_DISABLED_NOTINSTALLED] = {
		.in_event_mask =
			X(NM_EV_SW_ACT_REP) |
			X(NM_EV_STATE_CHG_REP),
		.out_state_mask =
			X(NM_BTS_SM_ST_OP_DISABLED_DEPENDENCY) |
			X(NM_BTS_SM_ST_OP_DISABLED_OFFLINE) |
			X(NM_BTS_SM_ST_OP_ENABLED),
		.name = "DISABLED_NOTINSTALLED",
		.onenter = st_op_disabled_notinstalled_on_enter,
		.action = st_op_disabled_notinstalled,
	},
	[NM_BTS_SM_ST_OP_DISABLED_DEPENDENCY] = {
		.in_event_mask =
			X(NM_EV_STATE_CHG_REP),
		.out_state_mask =
			X(NM_BTS_SM_ST_OP_DISABLED_NOTINSTALLED) |
			X(NM_BTS_SM_ST_OP_DISABLED_OFFLINE) |
			X(NM_BTS_SM_ST_OP_ENABLED),
		.name = "DISABLED_DEPENDENCY",
		.action = st_op_disabled_dependency,
	},
	[NM_BTS_SM_ST_OP_DISABLED_OFFLINE] = {
		.in_event_mask =
			X(NM_EV_STATE_CHG_REP),
		.out_state_mask =
			X(NM_BTS_SM_ST_OP_DISABLED_NOTINSTALLED) |
			X(NM_BTS_SM_ST_OP_DISABLED_DEPENDENCY) |
			X(NM_BTS_SM_ST_OP_ENABLED),
		.name = "DISABLED_OFFLINE",
		.onenter = st_op_disabled_offline_on_enter,
		.action = st_op_disabled_offline,
	},
	[NM_BTS_SM_ST_OP_ENABLED] = {
		.in_event_mask =
			X(NM_EV_STATE_CHG_REP),
		.out_state_mask =
			X(NM_BTS_SM_ST_OP_DISABLED_NOTINSTALLED) |
			X(NM_BTS_SM_ST_OP_DISABLED_DEPENDENCY) |
			X(NM_BTS_SM_ST_OP_DISABLED_OFFLINE),
		.name = "ENABLED",
		.action = st_op_enabled,
	},
};

struct osmo_fsm nm_bts_sm_fsm = {
	.name = "NM_BTS_SM_OP",
	.states = nm_bts_sm_fsm_states,
	.num_states = ARRAY_SIZE(nm_bts_sm_fsm_states),
	.allstate_event_mask =
		X(NM_EV_OPSTART_ACK) |
		X(NM_EV_OPSTART_NACK) |
		X(NM_EV_OML_DOWN),
	.allstate_action = st_op_allstate,
	.event_names = nm_fsm_event_names,
	.log_subsys = DNM,
};

static __attribute__((constructor)) void nm_bts_sm_fsm_init(void)
{
	OSMO_ASSERT(osmo_fsm_register(&nm_bts_sm_fsm) == 0);
}
