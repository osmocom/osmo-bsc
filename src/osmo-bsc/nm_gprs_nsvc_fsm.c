/* NM GPRS NSVC FSM */

/* (C) 2020 by sysmocom - s.m.f.c. GmbH <info@sysmocom.de>
 * Author: Alexander Couzens <lynxis@fe80.eu>
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

#define nm_gprs_nsvc_fsm_state_chg(fi, NEXT_STATE) \
	osmo_fsm_inst_state_chg(fi, NEXT_STATE, 0, 0)

//////////////////////////
// FSM STATE ACTIONS
//////////////////////////

static void st_op_disabled_notinstalled_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct gsm_gprs_nsvc *nsvc = (struct gsm_gprs_nsvc *)fi->priv;

	nsvc->mo.set_attr_sent = false;
	nsvc->mo.set_attr_sent = false;
	nsvc->mo.set_attr_ack_received = false;
	nsvc->mo.adm_unlock_sent = false;
	nsvc->mo.opstart_sent = false;
}

static void st_op_disabled_notinstalled(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct nm_statechg_signal_data *nsd;
	const struct gsm_nm_state *new_state;

	switch (event) {
	case NM_EV_FEATURE_NEGOTIATED:
		break;
	case NM_EV_SW_ACT_REP:
		break;
	case NM_EV_STATE_CHG_REP:
		nsd = (struct nm_statechg_signal_data *)data;
		new_state = nsd->new_state;
		if (new_state->operational == NM_OPSTATE_ENABLED) {
			/* should not happen... */
			nm_gprs_nsvc_fsm_state_chg(fi, NM_GPRS_NSVC_ST_OP_ENABLED);
			return;
		}
		switch (new_state->availability) { /* operational = DISABLED */
		case NM_AVSTATE_DEPENDENCY:
			nm_gprs_nsvc_fsm_state_chg(fi, NM_GPRS_NSVC_ST_OP_DISABLED_DEPENDENCY);
			return;
		case NM_AVSTATE_OFF_LINE:
		case NM_AVSTATE_OK:
			nm_gprs_nsvc_fsm_state_chg(fi, NM_GPRS_NSVC_ST_OP_DISABLED_OFFLINE);
			return;
		default:
			return;
		}
	default:
		OSMO_ASSERT(0);
	}
}

static void configure_loop(struct gsm_gprs_nsvc *nsvc, const struct gsm_nm_state *state, bool allow_opstart)
{
	struct msgb *msgb;

	if (nsvc->bts->gprs.mode == BTS_GPRS_NONE)
		return;

	/* We need to know BTS features in order to know if we can set IPv6 addresses */
	if (gsm_bts_features_negotiated(nsvc->bts) && !nsvc->mo.set_attr_sent &&
	    !nsvc->mo.set_attr_ack_received) {
		if (!osmo_bts_has_feature(&nsvc->bts->features, BTS_FEAT_IPV6_NSVC) &&
		    nsvc->remote.u.sa.sa_family == AF_INET6) {
			LOGPFSML(nsvc->mo.fi, LOGL_ERROR,
				 "BTS%d does not support IPv6 NSVC but an IPv6 address was configured!\n",
				 nsvc->bts->nr);
			return;
		}
		nsvc->mo.set_attr_sent = true;
		msgb = nanobts_gen_set_nsvc_attr(nsvc->bts);
		OSMO_ASSERT(msgb);
		abis_nm_ipaccess_set_attr(nsvc->bts, NM_OC_GPRS_NSVC, nsvc->bts->bts_nr,
					  nsvc->id, 0xff, msgb->data, msgb->len);
		msgb_free(msgb);
	}

	if (nsvc->mo.set_attr_ack_received && state->administrative != NM_STATE_UNLOCKED &&
	    !nsvc->mo.adm_unlock_sent) {
		nsvc->mo.adm_unlock_sent = true;
		abis_nm_chg_adm_state(nsvc->bts, NM_OC_GPRS_NSVC,
				      nsvc->bts->bts_nr, nsvc->id, 0xff,
				      NM_STATE_UNLOCKED);
	}

	if (allow_opstart && state->administrative == NM_STATE_UNLOCKED &&
	    nsvc->mo.set_attr_ack_received) {
		if (!nsvc->mo.opstart_sent) {
			nsvc->mo.opstart_sent = true;
			abis_nm_opstart(nsvc->bts, NM_OC_GPRS_NSVC,
					nsvc->bts->bts_nr, nsvc->id, 0xff);
		}
	}
}

static void st_op_disabled_dependency_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct gsm_gprs_nsvc *nsvc = (struct gsm_gprs_nsvc *)fi->priv;

	/* nanoBTS is broken, doesn't follow TS 12.21. Opstart MUST be sent
	   during Dependency, so we simply move to OFFLINE state here to avoid
	   duplicating code */
	if (nsvc->bts->site_mgr->peer_has_no_avstate_offline) {
		nm_gprs_nsvc_fsm_state_chg(fi, NM_GPRS_NSVC_ST_OP_DISABLED_OFFLINE);
		return;
	}
	configure_loop(nsvc, &nsvc->mo.nm_state, false);
}

static void st_op_disabled_dependency(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_gprs_nsvc *nsvc = (struct gsm_gprs_nsvc *)fi->priv;
	struct nm_statechg_signal_data *nsd;
	const struct gsm_nm_state *new_state;

	switch (event) {
	case NM_EV_FEATURE_NEGOTIATED:
		configure_loop(nsvc, &nsvc->mo.nm_state, false);
		return;
	case NM_EV_SET_ATTR_ACK:
		nsvc->mo.set_attr_ack_received = true;
		nsvc->mo.set_attr_sent = false;
		configure_loop(nsvc, &nsvc->mo.nm_state, false);
		return;
	case NM_EV_STATE_CHG_REP:
		nsd = (struct nm_statechg_signal_data *)data;
		new_state = nsd->new_state;
		if (new_state->operational == NM_OPSTATE_ENABLED) {
			/* should not happen... */
			nm_gprs_nsvc_fsm_state_chg(fi, NM_GPRS_NSVC_ST_OP_ENABLED);
			return;
		}
		switch (new_state->availability) { /* operational = DISABLED */
		case NM_AVSTATE_NOT_INSTALLED:
		case NM_AVSTATE_POWER_OFF:
			nm_gprs_nsvc_fsm_state_chg(fi, NM_GPRS_NSVC_ST_OP_DISABLED_NOTINSTALLED);
			return;
		case NM_AVSTATE_OFF_LINE:
		case NM_AVSTATE_OK:
			nm_gprs_nsvc_fsm_state_chg(fi, NM_GPRS_NSVC_ST_OP_DISABLED_OFFLINE);
			return;
		case NM_AVSTATE_DEPENDENCY:
			configure_loop(nsvc, new_state, false);
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
	struct gsm_gprs_nsvc *nsvc = (struct gsm_gprs_nsvc *)fi->priv;

	/* Warning: In here we may be acessing an state older than new_state
	   from prev (syncrhonous) FSM state */
	configure_loop(nsvc, &nsvc->mo.nm_state, true);
}

static void st_op_disabled_offline(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_gprs_nsvc *nsvc = (struct gsm_gprs_nsvc *)fi->priv;
	struct nm_statechg_signal_data *nsd;
	const struct gsm_nm_state *new_state;

	switch (event) {
	case NM_EV_FEATURE_NEGOTIATED:
		configure_loop(nsvc, &nsvc->mo.nm_state, true);
		return;
	case NM_EV_SET_ATTR_ACK:
		nsvc->mo.set_attr_ack_received = true;
		nsvc->mo.set_attr_sent = false;
		configure_loop(nsvc, &nsvc->mo.nm_state, true);
		return;
	case NM_EV_STATE_CHG_REP:
		nsd = (struct nm_statechg_signal_data *)data;
		new_state = nsd->new_state;
		if (new_state->operational == NM_OPSTATE_ENABLED) {
			nm_gprs_nsvc_fsm_state_chg(fi, NM_GPRS_NSVC_ST_OP_ENABLED);
			return;
		}
		switch (new_state->availability) { /* operational = DISABLED */
		case NM_AVSTATE_NOT_INSTALLED:
		case NM_AVSTATE_POWER_OFF:
			nm_gprs_nsvc_fsm_state_chg(fi, NM_GPRS_NSVC_ST_OP_DISABLED_NOTINSTALLED);
			return;
		case NM_AVSTATE_DEPENDENCY:
			/* There's no point in moving back to Dependency, since it's broken
			   and it acts actually as if it was in Offline state */
			if (!nsvc->bts->site_mgr->peer_has_no_avstate_offline) {
				nm_gprs_nsvc_fsm_state_chg(fi, NM_GPRS_NSVC_ST_OP_DISABLED_DEPENDENCY);
			} else {
				/* Moreover, in nanoBTS we need to check here for tx
				   Opstart since we may have gone Unlocked state
				   in this event, which means Opstart may be txed here. */
				configure_loop(nsvc, new_state, true);
			}
			return;
		case NM_AVSTATE_OFF_LINE:
		case NM_AVSTATE_OK:
			configure_loop(nsvc, new_state, true);
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
	struct gsm_gprs_nsvc *nsvc = (struct gsm_gprs_nsvc *)fi->priv;

	/* Reset state, we don't need it in this state and it will need to be
	  reused as soon as we move back to Disabled */
	nsvc->mo.opstart_sent = false;
	nsvc->mo.adm_unlock_sent = false;
	nsvc->mo.set_attr_sent = false;
	nsvc->mo.set_attr_ack_received = false;
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
			nm_gprs_nsvc_fsm_state_chg(fi, NM_GPRS_NSVC_ST_OP_DISABLED_NOTINSTALLED);
			return;
		case NM_AVSTATE_DEPENDENCY:
			nm_gprs_nsvc_fsm_state_chg(fi, NM_GPRS_NSVC_ST_OP_DISABLED_DEPENDENCY);
			return;
		case NM_AVSTATE_OFF_LINE:
		case NM_AVSTATE_OK:
			nm_gprs_nsvc_fsm_state_chg(fi, NM_GPRS_NSVC_ST_OP_DISABLED_OFFLINE);
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
	struct gsm_gprs_nsvc *nsvc = (struct gsm_gprs_nsvc *)fi->priv;

	switch (event) {
	case NM_EV_OPSTART_ACK:
	case NM_EV_OPSTART_NACK:
		/* TODO: if on state OFFLINE and rx NACK, try again? */
		nsvc->mo.opstart_sent = false;
		break;
	case NM_EV_OML_DOWN:
		if (fi->state != NM_GPRS_NSVC_ST_OP_DISABLED_NOTINSTALLED)
			nm_gprs_nsvc_fsm_state_chg(fi, NM_GPRS_NSVC_ST_OP_DISABLED_NOTINSTALLED);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static struct osmo_fsm_state nm_gprs_nsvc_fsm_states[] = {
	[NM_GPRS_NSVC_ST_OP_DISABLED_NOTINSTALLED] = {
		.in_event_mask =
			X(NM_EV_SW_ACT_REP) |
			X(NM_EV_FEATURE_NEGOTIATED) |
			X(NM_EV_STATE_CHG_REP),
		.out_state_mask =
			X(NM_GPRS_NSVC_ST_OP_DISABLED_DEPENDENCY) |
			X(NM_GPRS_NSVC_ST_OP_DISABLED_OFFLINE) |
			X(NM_GPRS_NSVC_ST_OP_ENABLED),
		.name = "DISABLED_NOTINSTALLED",
		.onenter = st_op_disabled_notinstalled_on_enter,
		.action = st_op_disabled_notinstalled,
	},
	[NM_GPRS_NSVC_ST_OP_DISABLED_DEPENDENCY] = {
		.in_event_mask =
			X(NM_EV_STATE_CHG_REP) |
			X(NM_EV_FEATURE_NEGOTIATED) |
			X(NM_EV_SET_ATTR_ACK),
		.out_state_mask =
			X(NM_GPRS_NSVC_ST_OP_DISABLED_NOTINSTALLED) |
			X(NM_GPRS_NSVC_ST_OP_DISABLED_OFFLINE) |
			X(NM_GPRS_NSVC_ST_OP_ENABLED),
		.name = "DISABLED_DEPENDENCY",
		.onenter = st_op_disabled_dependency_on_enter,
		.action = st_op_disabled_dependency,
	},
	[NM_GPRS_NSVC_ST_OP_DISABLED_OFFLINE] = {
		.in_event_mask =
			X(NM_EV_STATE_CHG_REP) |
			X(NM_EV_FEATURE_NEGOTIATED) |
			X(NM_EV_SET_ATTR_ACK),
		.out_state_mask =
			X(NM_GPRS_NSVC_ST_OP_DISABLED_NOTINSTALLED) |
			X(NM_GPRS_NSVC_ST_OP_DISABLED_DEPENDENCY) |
			X(NM_GPRS_NSVC_ST_OP_ENABLED),
		.name = "DISABLED_OFFLINE",
		.onenter = st_op_disabled_offline_on_enter,
		.action = st_op_disabled_offline,
	},
	[NM_GPRS_NSVC_ST_OP_ENABLED] = {
	.in_event_mask =
		X(NM_EV_STATE_CHG_REP),
	.out_state_mask =
		X(NM_GPRS_NSVC_ST_OP_DISABLED_NOTINSTALLED) |
		X(NM_GPRS_NSVC_ST_OP_DISABLED_DEPENDENCY) |
		X(NM_GPRS_NSVC_ST_OP_DISABLED_OFFLINE),
	.name = "ENABLED",
	.onenter = st_op_enabled_on_enter,
	.action = st_op_enabled,
	},
};

struct osmo_fsm nm_gprs_nsvc_fsm = {
	.name = "NM_GPRS_NSVC_OP",
	.states = nm_gprs_nsvc_fsm_states,
	.num_states = ARRAY_SIZE(nm_gprs_nsvc_fsm_states),
	.allstate_event_mask =
		X(NM_EV_OPSTART_ACK) |
		X(NM_EV_OPSTART_NACK) |
		X(NM_EV_OML_DOWN),
	.allstate_action = st_op_allstate,
	.event_names = nm_fsm_event_names,
	.log_subsys = DNM,
};

static __attribute__((constructor)) void nm_gprs_nsvc_fsm_init(void)
{
	OSMO_ASSERT(osmo_fsm_register(&nm_gprs_nsvc_fsm) == 0);
}
