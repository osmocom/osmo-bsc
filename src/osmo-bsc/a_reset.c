/* (C) 2017 by sysmocom s.f.m.c. GmbH
 * All Rights Reserved
 *
 * Author: Philipp Maier
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

#include <osmocom/core/logging.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/fsm.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/bsc_msc_data.h>
#include <osmocom/bsc/osmo_bsc_sigtran.h>

#define RESET_RESEND_INTERVAL 2		/* sec */
#define RESET_RESEND_TIMER_NO 4		/* See also 3GPP TS 48.008 Chapter 3.1.4.1.3.1 */
#define BAD_CONNECTION_THRESOLD 3	/* connection failures */

/* Reset context data (callbacks, state machine etc...) */
struct reset_ctx {
	/* Connection failure counter. When this counter
	 * reaches a certain threshold, the reset procedure
	 * will be triggered */
	int conn_loss_counter;

	/* Callback function to be called when a connection
	 * failure is detected and a rest must occur */
	void (*cb)(void *priv);

	/* Privated data for the callback function */
	void *priv;
};

enum reset_fsm_states {
	ST_DISC,		/* Disconnected from remote end */
	ST_CONN,		/* We have a confirmed connection */
};

enum reset_fsm_evt {
	EV_RESET_ACK,		/* got reset acknowlegement from remote end */
	EV_N_DISCONNECT,	/* lost a connection */
	EV_N_CONNECT,		/* made a successful connection */
};

static const struct value_string fsm_event_names[] = {
	OSMO_VALUE_STRING(EV_RESET_ACK),
	OSMO_VALUE_STRING(EV_N_DISCONNECT),
	OSMO_VALUE_STRING(EV_N_CONNECT),
	{0, NULL}
};

/* Disconnected state event handler */
static void fsm_disc_cb(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct reset_ctx *reset_ctx = (struct reset_ctx *)fi->priv;
	OSMO_ASSERT(reset_ctx);

	reset_ctx->conn_loss_counter = 0;
	osmo_fsm_inst_state_chg(fi, ST_CONN, 0, 0);
}

/* Called when entering Disconnected state */
static void fsm_disc_onenter_cb(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct reset_ctx *reset_ctx = (struct reset_ctx *)fi->priv;
	struct bsc_msc_data *msc = reset_ctx->priv;

	LOGPFSML(fi, LOGL_NOTICE, "BSSMAP MSC assocation is down, reconnecting...\n");
	if (prev_state != ST_DISC)
		osmo_stat_item_dec(msc->msc_statg->items[MSC_STAT_MSC_LINKS_ACTIVE], 1);
}

/* Connected state event handler */
static void fsm_conn_cb(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct reset_ctx *reset_ctx = (struct reset_ctx *)fi->priv;
	OSMO_ASSERT(reset_ctx);

	switch (event) {
	case EV_N_DISCONNECT:
		if (reset_ctx->conn_loss_counter >= BAD_CONNECTION_THRESOLD)
			osmo_fsm_inst_state_chg(fi, ST_DISC, RESET_RESEND_INTERVAL, RESET_RESEND_TIMER_NO);
		else
			reset_ctx->conn_loss_counter++;
		break;
	case EV_N_CONNECT:
		reset_ctx->conn_loss_counter = 0;
		break;
	}
}

/* Called when entering Connected state */
static void fsm_conn_onenter_cb(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct reset_ctx *reset_ctx = (struct reset_ctx *)fi->priv;
	struct bsc_msc_data *msc = reset_ctx->priv;

	LOGPFSML(fi, LOGL_NOTICE, "BSSMAP MSC assocation is up.\n");
	if (prev_state != ST_CONN)
		osmo_stat_item_inc(msc->msc_statg->items[MSC_STAT_MSC_LINKS_ACTIVE], 1);
}

/* Timer callback to retransmit the reset signal */
static int fsm_reset_ack_timeout_cb(struct osmo_fsm_inst *fi)
{
	struct reset_ctx *reset_ctx = (struct reset_ctx *)fi->priv;
	OSMO_ASSERT(reset_ctx);

	LOGPFSML(fi, LOGL_NOTICE, "(re)sending BSSMAP RESET message...\n");

	reset_ctx->cb(reset_ctx->priv);

	osmo_fsm_inst_state_chg(fi, ST_DISC, RESET_RESEND_INTERVAL, RESET_RESEND_TIMER_NO);
	return 0;
}

static struct osmo_fsm_state reset_fsm_states[] = {
	[ST_DISC] = {
		     .in_event_mask = (1 << EV_RESET_ACK),
		     .out_state_mask = (1 << ST_DISC) | (1 << ST_CONN),
		     .name = "DISC",
		     .action = fsm_disc_cb,
		     .onenter = fsm_disc_onenter_cb,
		     },
	[ST_CONN] = {
		     .in_event_mask = (1 << EV_N_DISCONNECT) | (1 << EV_N_CONNECT),
		     .out_state_mask = (1 << ST_DISC) | (1 << ST_CONN),
		     .name = "CONN",
		     .action = fsm_conn_cb,
		     .onenter = fsm_conn_onenter_cb,
		     },
};

/* State machine definition */
static struct osmo_fsm fsm = {
	.name = "A-RESET",
	.states = reset_fsm_states,
	.num_states = ARRAY_SIZE(reset_fsm_states),
	.log_subsys = DMSC,
	.timer_cb = fsm_reset_ack_timeout_cb,
	.event_names = fsm_event_names,
};

/* Create and start state machine which handles the reset/reset-ack procedure */
void a_reset_alloc(struct bsc_msc_data *msc, const char *name, void *cb)
{
	struct reset_ctx *reset_ctx;
	struct osmo_fsm_inst *reset_fsm;

	OSMO_ASSERT(msc);
	OSMO_ASSERT(name);
	OSMO_ASSERT(cb);

	/* There must not be any double allocation! */
	OSMO_ASSERT(msc->a.reset_fsm == NULL);

	/* Allocate and configure a new fsm instance */
	reset_ctx = talloc_zero(msc, struct reset_ctx);
	OSMO_ASSERT(reset_ctx);
	reset_ctx->priv = msc;
	reset_ctx->cb = cb;
	reset_ctx->conn_loss_counter = 0;
	reset_fsm = osmo_fsm_inst_alloc(&fsm, msc, reset_ctx, LOGL_DEBUG, name);
	OSMO_ASSERT(reset_fsm);
	msc->a.reset_fsm = reset_fsm;

	/* Immediately (1ms) kick off reset sending mechanism */
	osmo_fsm_inst_state_chg_ms(reset_fsm, ST_DISC, 1, RESET_RESEND_TIMER_NO);

	/* Count the new MSC link */
	osmo_stat_item_inc(msc->msc_statg->items[MSC_STAT_MSC_LINKS_TOTAL], 1);
}

/* Confirm that we successfully received a reset acknowledge message */
void a_reset_ack_confirm(struct bsc_msc_data *msc)
{
	if (!msc)
		return;

	if (!msc->a.reset_fsm)
		return;

	osmo_fsm_inst_dispatch(msc->a.reset_fsm, EV_RESET_ACK, NULL);
}

/* Report a failed connection */
void a_reset_conn_fail(struct bsc_msc_data *msc)
{
	if (!msc)
		return;

	if (!msc->a.reset_fsm)
		return;

	osmo_fsm_inst_dispatch(msc->a.reset_fsm, EV_N_DISCONNECT, NULL);
}

/* Report a successful connection */
void a_reset_conn_success(struct bsc_msc_data *msc)
{
	if (!msc)
		return;

	if (!msc->a.reset_fsm)
		return;

	osmo_fsm_inst_dispatch(msc->a.reset_fsm, EV_N_CONNECT, NULL);
}

/* Check if we have a connection to a specified msc */
bool a_reset_conn_ready(struct bsc_msc_data *msc)
{
	if (!msc)
		return false;

	if (!msc->a.reset_fsm)
		return false;

	if (msc->a.reset_fsm->state == ST_CONN)
		return true;

	return false;
}

static __attribute__((constructor)) void a_reset_fsm_init()
{
	OSMO_ASSERT(osmo_fsm_register(&fsm) == 0);
}
