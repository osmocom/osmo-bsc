/* (C) 2020 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Authors: Philipp Maier, Neels Hofmeyr
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

#include <osmocom/core/fsm.h>
#include <osmocom/core/tdef.h>
#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/bssmap_reset.h>
#include <osmocom/bsc/gsm_data.h>

static struct osmo_fsm bssmap_reset_fsm;

enum bssmap_reset_fsm_state {
	BSSMAP_RESET_ST_DISC,
	BSSMAP_RESET_ST_CONN,
};

static const struct value_string bssmap_reset_fsm_event_names[] = {
	OSMO_VALUE_STRING(BSSMAP_RESET_EV_RX_RESET),
	OSMO_VALUE_STRING(BSSMAP_RESET_EV_RX_RESET_ACK),
	OSMO_VALUE_STRING(BSSMAP_RESET_EV_CONN_CFM_FAILURE),
	OSMO_VALUE_STRING(BSSMAP_RESET_EV_CONN_CFM_SUCCESS),
	{}
};

static const struct osmo_tdef_state_timeout bssmap_reset_timeouts[32] = {
	[BSSMAP_RESET_ST_DISC] = { .T = 4 },
};

#define bssmap_reset_fsm_state_chg(FI, STATE) \
	osmo_tdef_fsm_inst_state_chg(FI, STATE, \
				     bssmap_reset_timeouts, \
				     (bsc_gsmnet)->T_defs, \
				     5)

struct bssmap_reset *bssmap_reset_alloc(void *ctx, const char *label, const struct bssmap_reset_cfg *cfg)
{
	struct bssmap_reset *bssmap_reset;
	struct osmo_fsm_inst *fi;

	fi = osmo_fsm_inst_alloc(&bssmap_reset_fsm, ctx, NULL, LOGL_DEBUG, label);
	OSMO_ASSERT(fi);

	bssmap_reset = talloc_zero(fi, struct bssmap_reset);
	OSMO_ASSERT(bssmap_reset);
	*bssmap_reset = (struct bssmap_reset){
		.fi = fi,
		.cfg = *cfg,
	};
	fi->priv = bssmap_reset;

	/* Immediately (1ms) kick off reset sending mechanism */
	osmo_fsm_inst_state_chg_ms(fi, BSSMAP_RESET_ST_DISC, 1, 0);
	return bssmap_reset;
}

void bssmap_reset_term_and_free(struct bssmap_reset *bssmap_reset)
{
	if (!bssmap_reset)
		return;
	osmo_fsm_inst_term(bssmap_reset->fi, OSMO_FSM_TERM_REQUEST, NULL);
	talloc_free(bssmap_reset);
}

static void link_up(struct bssmap_reset *bssmap_reset)
{
	LOGPFSML(bssmap_reset->fi, LOGL_NOTICE, "link up\n");
	bssmap_reset->conn_cfm_failures = 0;
	if (bssmap_reset->cfg.ops.link_up)
		bssmap_reset->cfg.ops.link_up(bssmap_reset->cfg.data);
}

static void link_lost(struct bssmap_reset *bssmap_reset)
{
	LOGPFSML(bssmap_reset->fi, LOGL_NOTICE, "link lost\n");
	if (bssmap_reset->cfg.ops.link_lost)
		bssmap_reset->cfg.ops.link_lost(bssmap_reset->cfg.data);
}

static void tx_reset(struct bssmap_reset *bssmap_reset)
{
	if (bssmap_reset->cfg.ops.tx_reset)
		bssmap_reset->cfg.ops.tx_reset(bssmap_reset->cfg.data);
}

static void tx_reset_ack(struct bssmap_reset *bssmap_reset)
{
	if (bssmap_reset->cfg.ops.tx_reset_ack)
		bssmap_reset->cfg.ops.tx_reset_ack(bssmap_reset->cfg.data);
}

static void bssmap_reset_disc_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct bssmap_reset *bssmap_reset = (struct bssmap_reset*)fi->priv;
	if (prev_state == BSSMAP_RESET_ST_CONN)
		link_lost(bssmap_reset);
}

static void bssmap_reset_disc_action(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct bssmap_reset *bssmap_reset = (struct bssmap_reset*)fi->priv;
	switch (event) {

	case BSSMAP_RESET_EV_RX_RESET:
		tx_reset_ack(bssmap_reset);
		bssmap_reset_fsm_state_chg(fi, BSSMAP_RESET_ST_CONN);
		break;

	case BSSMAP_RESET_EV_RX_RESET_ACK:
		bssmap_reset_fsm_state_chg(fi, BSSMAP_RESET_ST_CONN);
		break;

	case BSSMAP_RESET_EV_CONN_CFM_FAILURE:
		/* ignore */
		break;

	case BSSMAP_RESET_EV_CONN_CFM_SUCCESS:
		/* A connection succeeded before we managed to do a RESET handshake?
		 * Then the calling code is not taking care to check bssmap_reset_is_conn_ready().
		 */
		LOGPFSML(fi, LOGL_ERROR, "Connection success confirmed, but we have not seen a RESET-ACK; bug?\n");
		break;

	default:
		OSMO_ASSERT(false);
	}
}

static void bssmap_reset_conn_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct bssmap_reset *bssmap_reset = (struct bssmap_reset*)fi->priv;
	if (prev_state != BSSMAP_RESET_ST_CONN)
		link_up(bssmap_reset);
}

static void bssmap_reset_conn_action(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct bssmap_reset *bssmap_reset = (struct bssmap_reset*)fi->priv;

	switch (event) {

	case BSSMAP_RESET_EV_RX_RESET:
		/* We were connected, but the remote side has restarted. */
		link_lost(bssmap_reset);
		tx_reset_ack(bssmap_reset);
		link_up(bssmap_reset);
		break;

	case BSSMAP_RESET_EV_RX_RESET_ACK:
		LOGPFSML(fi, LOGL_INFO, "Link is already up, ignoring RESET ACK\n");
		break;

	case BSSMAP_RESET_EV_CONN_CFM_FAILURE:
		bssmap_reset->conn_cfm_failures++;
		if (bssmap_reset->conn_cfm_failures > bssmap_reset->cfg.conn_cfm_failure_threshold)
			bssmap_reset_fsm_state_chg(fi, BSSMAP_RESET_ST_DISC);
		break;

	case BSSMAP_RESET_EV_CONN_CFM_SUCCESS:
		bssmap_reset->conn_cfm_failures = 0;
		break;

	default:
		OSMO_ASSERT(false);
	}
}

static int bssmap_reset_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	struct bssmap_reset *bssmap_reset = (struct bssmap_reset*)fi->priv;

	tx_reset(bssmap_reset);

	/* (re-)enter disconnect state to resend RESET after timeout. */
	bssmap_reset_fsm_state_chg(fi, BSSMAP_RESET_ST_DISC);

	/* Return 0 to not terminate the fsm */
	return 0;
}

#define S(x) (1 << (x))

static struct osmo_fsm_state bssmap_reset_fsm_states[] = {
	[BSSMAP_RESET_ST_DISC] = {
		     .name = "DISC",
		     .in_event_mask = 0
			     | S(BSSMAP_RESET_EV_RX_RESET)
			     | S(BSSMAP_RESET_EV_RX_RESET_ACK)
			     | S(BSSMAP_RESET_EV_CONN_CFM_FAILURE)
			     | S(BSSMAP_RESET_EV_CONN_CFM_SUCCESS)
			     ,
		     .out_state_mask = 0
			     | S(BSSMAP_RESET_ST_DISC)
			     | S(BSSMAP_RESET_ST_CONN)
			     ,
		     .onenter = bssmap_reset_disc_onenter,
		     .action = bssmap_reset_disc_action,
		     },
	[BSSMAP_RESET_ST_CONN] = {
		     .name = "CONN",
		     .in_event_mask = 0
			     | S(BSSMAP_RESET_EV_RX_RESET)
			     | S(BSSMAP_RESET_EV_RX_RESET_ACK)
			     | S(BSSMAP_RESET_EV_CONN_CFM_FAILURE)
			     | S(BSSMAP_RESET_EV_CONN_CFM_SUCCESS)
			     ,
		     .out_state_mask = 0
			     | S(BSSMAP_RESET_ST_DISC)
			     | S(BSSMAP_RESET_ST_CONN)
			     ,
		     .onenter = bssmap_reset_conn_onenter,
		     .action = bssmap_reset_conn_action,
		     },
};

static struct osmo_fsm bssmap_reset_fsm = {
	.name = "bssmap_reset",
	.states = bssmap_reset_fsm_states,
	.num_states = ARRAY_SIZE(bssmap_reset_fsm_states),
	.log_subsys = DRESET,
	.timer_cb = bssmap_reset_fsm_timer_cb,
	.event_names = bssmap_reset_fsm_event_names,
};

bool bssmap_reset_is_conn_ready(const struct bssmap_reset *bssmap_reset)
{
	return bssmap_reset->fi->state == BSSMAP_RESET_ST_CONN;
}

static __attribute__((constructor)) void bssmap_reset_fsm_init()
{
	OSMO_ASSERT(osmo_fsm_register(&bssmap_reset_fsm) == 0);
}
