/* NM BaseBand Transceiver FSM */

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
#include <osmocom/bsc/ipaccess.h>
#include <osmocom/bsc/nm_common_fsm.h>
#include <osmocom/bsc/debug.h>

#define X(s) (1 << (s))

#define nm_bb_transc_fsm_state_chg(fi, NEXT_STATE) \
	osmo_fsm_inst_state_chg(fi, NEXT_STATE, 0, 0)

static inline void nm_bb_transc_fsm_becomes_enabled(struct gsm_bts_bb_trx *bb_transc)
{
	struct gsm_bts_trx *trx = gsm_bts_bb_trx_get_trx(bb_transc);
	nm_obj_fsm_becomes_enabled_disabled(trx->bts, bb_transc, NM_OC_BASEB_TRANSC, true);
}

static inline void nm_bb_transc_fsm_becomes_disabled(struct gsm_bts_bb_trx *bb_transc)
{
	struct gsm_bts_trx *trx = gsm_bts_bb_trx_get_trx(bb_transc);
	nm_obj_fsm_becomes_enabled_disabled(trx->bts, bb_transc, NM_OC_BASEB_TRANSC, false);
}

//////////////////////////
// FSM STATE ACTIONS
//////////////////////////

static void st_op_disabled_notinstalled_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct gsm_bts_bb_trx *bb_transc = (struct gsm_bts_bb_trx *)fi->priv;

	bb_transc->mo.sw_act_rep_received = false;
	bb_transc->mo.get_attr_sent = false;
	bb_transc->mo.get_attr_rep_received = false;
	bb_transc->mo.adm_unlock_sent = false;
	bb_transc->mo.rsl_connect_sent = false;
	bb_transc->mo.rsl_connect_ack_received = false;
	bb_transc->mo.opstart_sent = false;
}

static void st_op_disabled_notinstalled(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_bts_bb_trx *bb_transc = (struct gsm_bts_bb_trx *)fi->priv;
	struct nm_statechg_signal_data *nsd;
	const struct gsm_nm_state *new_state;

	switch (event) {
	case NM_EV_SW_ACT_REP:
		bb_transc->mo.sw_act_rep_received = true;
		break;
	case NM_EV_SETUP_RAMP_READY:
		break;
	case NM_EV_STATE_CHG_REP:
		nsd = (struct nm_statechg_signal_data *)data;
		new_state = &nsd->new_state;
		if (new_state->operational == NM_OPSTATE_ENABLED) {
			/*should not happen... */
			nm_bb_transc_fsm_state_chg(fi, NM_BB_TRANSC_ST_OP_ENABLED);
			return;
		}
		switch (new_state->availability) { /* operational = DISABLED */
		case NM_AVSTATE_DEPENDENCY:
			nm_bb_transc_fsm_state_chg(fi, NM_BB_TRANSC_ST_OP_DISABLED_DEPENDENCY);
			return;
		case NM_AVSTATE_OFF_LINE:
		case NM_AVSTATE_OK:
			nm_bb_transc_fsm_state_chg(fi, NM_BB_TRANSC_ST_OP_DISABLED_OFFLINE);
			return;
		default:
			return;
		}
	default:
		OSMO_ASSERT(0);
	}
}

static void configure_loop(struct gsm_bts_bb_trx *bb_transc, const struct gsm_nm_state *state, bool allow_opstart)
{
	struct gsm_bts_trx *trx = gsm_bts_bb_trx_get_trx(bb_transc);

	if (bts_setup_ramp_wait(trx->bts))
		return;

	/* nanoBTS only: delay until SW Activated Report is received */
	if (is_nanobts(trx->bts) && !bb_transc->mo.sw_act_rep_received)
		return;

	/* Request TRX-level attributes */
	if (!bb_transc->mo.get_attr_sent && !bb_transc->mo.get_attr_rep_received) {
		uint8_t attr_buf[3]; /* enlarge if needed */
		uint8_t *ptr = &attr_buf[0];

		*(ptr++) = NM_ATT_MANUF_STATE;
		*(ptr++) = NM_ATT_SW_CONFIG;
		if (is_ipa_abisip_bts(trx->bts))
			*(ptr++) = NM_ATT_IPACC_SUPP_FEATURES;

		OSMO_ASSERT((ptr - attr_buf) <= sizeof(attr_buf));
		abis_nm_get_attr(trx->bts, NM_OC_BASEB_TRANSC, 0, trx->nr, 0xff,
				 &attr_buf[0], (ptr - attr_buf));
		bb_transc->mo.get_attr_sent = true;
	}

	if (bb_transc->mo.get_attr_rep_received &&
	    state->administrative != NM_STATE_UNLOCKED && !bb_transc->mo.adm_unlock_sent) {
		bb_transc->mo.adm_unlock_sent = true;
		/* Note: nanoBTS sometimes fails NACKing the BaseBand
		   Transceiver Unlock command while in Dependency, specially
		   during first attempt after boot. When NACK is received, the
		   OML link is dropped and the whole procedure is restarted. */
		abis_nm_chg_adm_state(trx->bts, NM_OC_BASEB_TRANSC,
				      trx->bts->bts_nr, trx->nr, 0xff,
				      NM_STATE_UNLOCKED);
	}

	/* Provision BTS with RSL IP addr & port to connect to: */
	if (allow_opstart && state->administrative == NM_STATE_UNLOCKED &&
	    !bb_transc->mo.rsl_connect_sent && !bb_transc->mo.rsl_connect_ack_received) {
		bb_transc->mo.rsl_connect_sent = true;
		abis_nm_ipaccess_rsl_connect(trx, trx->bts->ip_access.rsl_ip,
					     3003, trx->rsl_tei_primary);
	}

	/* OPSTART after receiving RSL CONNECT ACK. We cannot delay until the
	 * RSL/IPA socket is connected to us because nanoBTS only attempts
	 * connection after receiving an OPSTART: */
	if (allow_opstart && state->administrative == NM_STATE_UNLOCKED &&
	    bb_transc->mo.rsl_connect_ack_received && !bb_transc->mo.opstart_sent) {
		bb_transc->mo.opstart_sent = true;
		abis_nm_opstart(trx->bts, NM_OC_BASEB_TRANSC, trx->bts->bts_nr, trx->nr, 0xff);
	}
}

static void st_op_disabled_dependency_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct gsm_bts_bb_trx *bb_transc = (struct gsm_bts_bb_trx *)fi->priv;
	struct gsm_bts_trx *trx = gsm_bts_bb_trx_get_trx(bb_transc);

	if (trx->bts->site_mgr->peer_has_no_avstate_offline) {
		nm_bb_transc_fsm_state_chg(fi, NM_BB_TRANSC_ST_OP_DISABLED_OFFLINE);
		return;
	}
	configure_loop(bb_transc, &bb_transc->mo.nm_state, false);
}

static void st_op_disabled_dependency(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_bts_bb_trx *bb_transc = (struct gsm_bts_bb_trx *)fi->priv;
	struct gsm_bts_trx *trx = gsm_bts_bb_trx_get_trx(bb_transc);
	struct nm_statechg_signal_data *nsd;
	const struct gsm_nm_state *new_state;

	switch (event) {
	case NM_EV_SW_ACT_REP:
		bb_transc->mo.sw_act_rep_received = true;
		configure_loop(bb_transc, &bb_transc->mo.nm_state, false);
		break;
	case NM_EV_GET_ATTR_REP:
		bb_transc->mo.get_attr_rep_received = true;
		bb_transc->mo.get_attr_sent = false;
		configure_loop(bb_transc, &bb_transc->mo.nm_state, false);
		return;
	case NM_EV_RSL_CONNECT_ACK:
		bb_transc->mo.rsl_connect_ack_received = true;
		bb_transc->mo.rsl_connect_sent = false;
		configure_loop(bb_transc, &bb_transc->mo.nm_state, false);
		break;
	case NM_EV_RSL_CONNECT_NACK:
		ipaccess_drop_oml_deferred(trx->bts);
		break;
	case NM_EV_STATE_CHG_REP:
		nsd = (struct nm_statechg_signal_data *)data;
		new_state = &nsd->new_state;
		if (new_state->operational == NM_OPSTATE_ENABLED) {
			/* should not happen... */
			nm_bb_transc_fsm_state_chg(fi, NM_BB_TRANSC_ST_OP_ENABLED);
			return;
		}
		switch (new_state->availability) { /* operational = DISABLED */
		case NM_AVSTATE_NOT_INSTALLED:
		case NM_AVSTATE_POWER_OFF:
			nm_bb_transc_fsm_state_chg(fi, NM_BB_TRANSC_ST_OP_DISABLED_NOTINSTALLED);
			return;
		case NM_AVSTATE_OFF_LINE:
		case NM_AVSTATE_OK:
			nm_bb_transc_fsm_state_chg(fi, NM_BB_TRANSC_ST_OP_DISABLED_OFFLINE);
			return;
		case NM_AVSTATE_DEPENDENCY:
			configure_loop(bb_transc, new_state, false);
			return;
		default:
			return;
		}
	case NM_EV_SETUP_RAMP_READY:
		configure_loop(bb_transc, &bb_transc->mo.nm_state, false);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_op_disabled_offline_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct gsm_bts_bb_trx *bb_transc = (struct gsm_bts_bb_trx *)fi->priv;

	configure_loop(bb_transc, &bb_transc->mo.nm_state, true);
}

static void st_op_disabled_offline(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_bts_bb_trx *bb_transc = (struct gsm_bts_bb_trx *)fi->priv;
	struct gsm_bts_trx *trx = gsm_bts_bb_trx_get_trx(bb_transc);
	struct nm_statechg_signal_data *nsd;
	const struct gsm_nm_state *new_state;

	switch (event) {
	case NM_EV_SW_ACT_REP:
		bb_transc->mo.sw_act_rep_received = true;
		configure_loop(bb_transc, &bb_transc->mo.nm_state, true);
		break;
	case NM_EV_GET_ATTR_REP:
		bb_transc->mo.get_attr_rep_received = true;
		bb_transc->mo.get_attr_sent = false;
		configure_loop(bb_transc, &bb_transc->mo.nm_state, true);
		return;
	case NM_EV_RSL_CONNECT_ACK:
		bb_transc->mo.rsl_connect_ack_received = true;
		bb_transc->mo.rsl_connect_sent = false;
		configure_loop(bb_transc, &bb_transc->mo.nm_state, true);
		break;
	case NM_EV_RSL_CONNECT_NACK:
		ipaccess_drop_oml_deferred(trx->bts);
		break;
	case NM_EV_STATE_CHG_REP:
		nsd = (struct nm_statechg_signal_data *)data;
		new_state = &nsd->new_state;
		if (new_state->operational == NM_OPSTATE_ENABLED) {
			nm_bb_transc_fsm_state_chg(fi, NM_BB_TRANSC_ST_OP_ENABLED);
			return;
		}
		switch (new_state->availability) { /* operational = DISABLED */
		case NM_AVSTATE_NOT_INSTALLED:
		case NM_AVSTATE_POWER_OFF:
			nm_bb_transc_fsm_state_chg(fi, NM_BB_TRANSC_ST_OP_DISABLED_NOTINSTALLED);
			return;
		case NM_AVSTATE_DEPENDENCY:
			/* There's no point in moving back to Dependency, since it's broken
			   and it acts actually as if it was in Offline state */
			if (!trx->bts->site_mgr->peer_has_no_avstate_offline) {
				nm_bb_transc_fsm_state_chg(fi, NM_BB_TRANSC_ST_OP_DISABLED_DEPENDENCY);
			} else {
				/* Moreover, in nanoBTS we need to check here for tx
				   Opstart since we may have gone Unlocked state
				   in this event, which means Opstart may be txed here. */
				configure_loop(bb_transc, new_state, true);
			}
			return;
		case NM_AVSTATE_OFF_LINE:
		case NM_AVSTATE_OK:
			configure_loop(bb_transc, new_state, true);
			return;
		default:
			return;
		}
	case NM_EV_SETUP_RAMP_READY:
		configure_loop(bb_transc, &bb_transc->mo.nm_state, true);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_op_enabled_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct gsm_bts_bb_trx *bb_transc = (struct gsm_bts_bb_trx *)fi->priv;

	/* Reset state, we don't need it in this state and it will need to be
	  reused as soon as we move back to Disabled */
	bb_transc->mo.get_attr_sent = false;
	bb_transc->mo.get_attr_rep_received = false;
	bb_transc->mo.adm_unlock_sent = false;
	bb_transc->mo.rsl_connect_ack_received = false;
	bb_transc->mo.rsl_connect_sent = false;
	bb_transc->mo.opstart_sent = false;

	nm_bb_transc_fsm_becomes_enabled(bb_transc);
}

static void st_op_enabled(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_bts_bb_trx *bb_transc = (struct gsm_bts_bb_trx *)fi->priv;
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
			nm_bb_transc_fsm_becomes_disabled(bb_transc);
			nm_bb_transc_fsm_state_chg(fi, NM_BB_TRANSC_ST_OP_DISABLED_NOTINSTALLED);
			return;
		case NM_AVSTATE_DEPENDENCY:
			nm_bb_transc_fsm_becomes_disabled(bb_transc);
			nm_bb_transc_fsm_state_chg(fi, NM_BB_TRANSC_ST_OP_DISABLED_DEPENDENCY);
			return;
		case NM_AVSTATE_OFF_LINE:
		case NM_AVSTATE_OK:
			nm_bb_transc_fsm_becomes_disabled(bb_transc);
			nm_bb_transc_fsm_state_chg(fi, NM_BB_TRANSC_ST_OP_DISABLED_OFFLINE);
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
	struct gsm_bts_bb_trx *bb_transc = (struct gsm_bts_bb_trx *)fi->priv;

	switch (event) {
	case NM_EV_OPSTART_ACK:
	case NM_EV_OPSTART_NACK:
		/* TODO: if on state OFFLINE and rx NACK, try again? */
		bb_transc->mo.opstart_sent = false;
		break;
	case NM_EV_OML_DOWN:
		if (fi->state != NM_BB_TRANSC_ST_OP_DISABLED_NOTINSTALLED) {
			if (fi->state == NM_BB_TRANSC_ST_OP_ENABLED)
				nm_bb_transc_fsm_becomes_disabled(bb_transc);
			nm_bb_transc_fsm_state_chg(fi, NM_BB_TRANSC_ST_OP_DISABLED_NOTINSTALLED);
		}
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static struct osmo_fsm_state nm_bb_transc_fsm_states[] = {
	[NM_BB_TRANSC_ST_OP_DISABLED_NOTINSTALLED] = {
		.in_event_mask =
			X(NM_EV_SW_ACT_REP) |
			X(NM_EV_STATE_CHG_REP)  |
			X(NM_EV_SETUP_RAMP_READY),
		.out_state_mask =
			X(NM_BB_TRANSC_ST_OP_DISABLED_DEPENDENCY) |
			X(NM_BB_TRANSC_ST_OP_DISABLED_OFFLINE) |
			X(NM_BB_TRANSC_ST_OP_ENABLED),
		.name = "DISABLED_NOTINSTALLED",
		.onenter = st_op_disabled_notinstalled_on_enter,
		.action = st_op_disabled_notinstalled,
	},
	[NM_BB_TRANSC_ST_OP_DISABLED_DEPENDENCY] = {
		.in_event_mask =
			X(NM_EV_SW_ACT_REP) |
			X(NM_EV_STATE_CHG_REP) |
			X(NM_EV_GET_ATTR_REP) |
			X(NM_EV_RSL_CONNECT_ACK) |
			X(NM_EV_RSL_CONNECT_NACK) |
			X(NM_EV_SETUP_RAMP_READY),
		.out_state_mask =
			X(NM_BB_TRANSC_ST_OP_DISABLED_NOTINSTALLED) |
			X(NM_BB_TRANSC_ST_OP_DISABLED_OFFLINE) |
			X(NM_BB_TRANSC_ST_OP_ENABLED),
		.name = "DISABLED_DEPENDENCY",
		.onenter = st_op_disabled_dependency_on_enter,
		.action = st_op_disabled_dependency,
	},
	[NM_BB_TRANSC_ST_OP_DISABLED_OFFLINE] = {
		.in_event_mask =
			X(NM_EV_SW_ACT_REP) |
			X(NM_EV_STATE_CHG_REP) |
			X(NM_EV_GET_ATTR_REP) |
			X(NM_EV_RSL_CONNECT_ACK) |
			X(NM_EV_RSL_CONNECT_NACK) |
			X(NM_EV_SETUP_RAMP_READY),
		.out_state_mask =
			X(NM_BB_TRANSC_ST_OP_DISABLED_NOTINSTALLED) |
			X(NM_BB_TRANSC_ST_OP_DISABLED_DEPENDENCY) |
			X(NM_BB_TRANSC_ST_OP_ENABLED),
		.name = "DISABLED_OFFLINE",
		.onenter = st_op_disabled_offline_on_enter,
		.action = st_op_disabled_offline,
	},
	[NM_BB_TRANSC_ST_OP_ENABLED] = {
	.in_event_mask =
		X(NM_EV_STATE_CHG_REP),
	.out_state_mask =
		X(NM_BB_TRANSC_ST_OP_DISABLED_NOTINSTALLED) |
		X(NM_BB_TRANSC_ST_OP_DISABLED_DEPENDENCY) |
		X(NM_BB_TRANSC_ST_OP_DISABLED_OFFLINE),
	.name = "ENABLED",
	.onenter = st_op_enabled_on_enter,
	.action = st_op_enabled,
	},
};

struct osmo_fsm nm_bb_transc_fsm = {
	.name = "NM_BB_TRANSC_OP",
	.states = nm_bb_transc_fsm_states,
	.num_states = ARRAY_SIZE(nm_bb_transc_fsm_states),
	.allstate_event_mask =
		X(NM_EV_OPSTART_ACK) |
		X(NM_EV_OPSTART_NACK) |
		X(NM_EV_OML_DOWN),
	.allstate_action = st_op_allstate,
	.event_names = nm_fsm_event_names,
	.log_subsys = DNM,
};

static __attribute__((constructor)) void nm_bb_transc_fsm_init(void)
{
	OSMO_ASSERT(osmo_fsm_register(&nm_bb_transc_fsm) == 0);
}
