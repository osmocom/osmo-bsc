/* Handover Logic for Inter-BTS (Intra-BSC) Handover.  This does not
 * actually implement the handover algorithm/decision, but executes a
 * handover decision */

/* (C) 2009 by Harald Welte <laforge@gnumonks.org>
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
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <netinet/in.h>

#include <osmocom/core/msgb.h>
#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/gsm_data.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/bsc/abis_rsl.h>
#include <osmocom/bsc/chan_alloc.h>
#include <osmocom/bsc/signal.h>
#include <osmocom/core/talloc.h>
#include <osmocom/bsc/bsc_subscriber.h>
#include <osmocom/bsc/gsm_04_08_utils.h>
#include <osmocom/bsc/handover.h>
#include <osmocom/bsc/handover_cfg.h>
#include <osmocom/bsc/bsc_subscr_conn_fsm.h>

static LLIST_HEAD(bsc_handovers);
static LLIST_HEAD(handover_decision_callbacks);

static void handover_free(struct bsc_handover *ho)
{
	osmo_timer_del(&ho->T3103);
	llist_del(&ho->list);
	talloc_free(ho);
}

static struct bsc_handover *bsc_ho_by_new_lchan(struct gsm_lchan *new_lchan)
{
	struct bsc_handover *ho;

	llist_for_each_entry(ho, &bsc_handovers, list) {
		if (ho->new_lchan == new_lchan)
			return ho;
	}

	return NULL;
}

static struct bsc_handover *bsc_ho_by_old_lchan(struct gsm_lchan *old_lchan)
{
	struct bsc_handover *ho;

	llist_for_each_entry(ho, &bsc_handovers, list) {
		if (ho->old_lchan == old_lchan)
			return ho;
	}

	return NULL;
}

/*! Hand over the specified logical channel to the specified new BTS and possibly change the lchan type.
 * This is the main entry point for the actual handover algorithm, after the decision whether to initiate
 * HO to a specific BTS. To not change the lchan type, pass old_lchan->type. */
int bsc_handover_start(enum hodec_id from_hodec_id, struct gsm_lchan *old_lchan, struct gsm_bts *new_bts,
		       enum gsm_chan_t new_lchan_type)
{
	int rc;
	struct gsm_subscriber_connection *conn;
	struct bsc_handover *ho;
	static uint8_t ho_ref = 0;
	bool do_assignment;

	OSMO_ASSERT(old_lchan);

	/* don't attempt multiple handovers for the same lchan at
	 * the same time */
	if (bsc_ho_by_old_lchan(old_lchan))
		return -EBUSY;

	conn = old_lchan->conn;
	if (!conn) {
		LOGP(DHO, LOGL_ERROR, "Old lchan lacks connection data.\n");
		return -ENOSPC;
	}

	if (!new_bts)
		new_bts = old_lchan->ts->trx->bts;
	OSMO_ASSERT(new_bts);

	do_assignment = (new_bts == old_lchan->ts->trx->bts);

	ho = talloc_zero(conn, struct bsc_handover);
	if (!ho) {
		LOGP(DHO, LOGL_FATAL, "Out of Memory\n");
		return -ENOMEM;
	}
	ho->from_hodec_id = from_hodec_id;
	ho->old_lchan = old_lchan;
	ho->new_bts = new_bts;
	ho->new_lchan_type = new_lchan_type;
	ho->ho_ref = ho_ref++;
	ho->inter_cell = !do_assignment;
	ho->async = true;
	llist_add(&ho->list, &bsc_handovers);

	conn->ho = ho;

	DEBUGP(DHO, "(BTS %u trx %u ts %u lchan %u %s)->(BTS %u lchan %s) Initiating %s...\n",
	       old_lchan->ts->trx->bts->nr,
	       old_lchan->ts->trx->nr,
	       old_lchan->ts->nr,
	       old_lchan->nr,
	       gsm_pchan_name(old_lchan->ts->pchan),
	       new_bts->nr,
	       gsm_lchant_name(new_lchan_type),
	       do_assignment ? "Assignment" : "Handover");

	rc = osmo_fsm_inst_dispatch(conn->fi, GSCON_EV_HO_START, NULL);

	if (rc < 0) {
		LOGPHO(ho, LOGL_ERROR, "Failed to trigger handover, conn state does not allow it\n");
		conn->ho = NULL;
		talloc_free(ho);
	}
	return rc;
}

/*! Start actual handover. Call bsc_handover_start() instead; The only legal caller is the GSCON FSM in
 * bsc_subscr_conn_fsm.c. */
int bsc_handover_start_gscon(struct gsm_subscriber_connection *conn)
{
	int rc;
	struct gsm_network *network = conn->network;
	struct bsc_handover *ho = conn->ho;
	struct gsm_lchan *old_lchan;
	struct gsm_lchan *new_lchan;

	if (!ho) {
		LOGP(DHO, LOGL_ERROR, "%s: Requested to start handover, but conn->ho is NULL\n",
		     bsc_subscr_name(conn->bsub));
		return -EINVAL;
	}

	OSMO_ASSERT(ho->old_lchan && ho->new_bts);

	if (ho->old_lchan->conn != conn) {
		LOGP(DHO, LOGL_ERROR,
		     "%s: Requested to start handover, but the lchan does not belong to this conn\n",
		     bsc_subscr_name(conn->bsub));
		return -EINVAL;
	}

	rate_ctr_inc(&network->bsc_ctrs->ctr[BSC_CTR_HANDOVER_ATTEMPTED]);

	ho->new_lchan = lchan_alloc(ho->new_bts, ho->new_lchan_type, 0);
	if (!ho->new_lchan) {
		LOGP(DHO, LOGL_NOTICE, "No free channel for %s\n", gsm_lchant_name(ho->new_lchan_type));
		rate_ctr_inc(&network->bsc_ctrs->ctr[BSC_CTR_HANDOVER_NO_CHANNEL]);
		return -ENOSPC;
	}

	LOGPHO(ho, LOGL_INFO, "Triggering %s\n", ho->inter_cell? "Handover" : "Assignment");

	/* copy some parameters from old lchan */
	old_lchan = ho->old_lchan;
	new_lchan = ho->new_lchan;
	memcpy(&new_lchan->encr, &old_lchan->encr, sizeof(new_lchan->encr));
	if (!ho->inter_cell) {
		new_lchan->ms_power = old_lchan->ms_power;
		new_lchan->rqd_ta = old_lchan->rqd_ta;
	} else {
		new_lchan->ms_power =
			ms_pwr_ctl_lvl(ho->new_bts->band, ho->new_bts->ms_max_power);
		/* FIXME: do we have a better idea of the timing advance? */
		//new_lchan->rqd_ta = old_lchan->rqd_ta;
	}
	new_lchan->bs_power = old_lchan->bs_power;
	new_lchan->rsl_cmode = old_lchan->rsl_cmode;
	new_lchan->tch_mode = old_lchan->tch_mode;
	memcpy(&new_lchan->mr_ms_lv, &old_lchan->mr_ms_lv, sizeof(new_lchan->mr_ms_lv));
	memcpy(&new_lchan->mr_bts_lv, &old_lchan->mr_bts_lv, sizeof(new_lchan->mr_bts_lv));

	new_lchan->conn = conn;

	rc = rsl_chan_activate_lchan(new_lchan,
				     ho->async ? RSL_ACT_INTER_ASYNC : RSL_ACT_INTER_SYNC,
				     ho->ho_ref);
	if (rc < 0) {
		LOGPHO(ho, LOGL_INFO, "%s Failure: activate lchan rc = %d\n",
		       ho->inter_cell? "Handover" : "Assignment", rc);
		lchan_free(new_lchan);
		ho->new_lchan = NULL;
		bsc_clear_handover(conn, 0);
		return rc;
	}

	rsl_lchan_set_state(new_lchan, LCHAN_S_ACT_REQ);
	/* we continue in the SS_LCHAN handler / ho_chan_activ_ack */

	return 0;
}

/* clear any operation for this connection */
void bsc_clear_handover(struct gsm_subscriber_connection *conn, int free_lchan)
{
	struct bsc_handover *ho = conn->ho;

	if (!ho)
		return;

	if (ho->new_lchan) {
		ho->new_lchan->conn = NULL;
		if (free_lchan)
			lchan_release(ho->new_lchan, 0, RSL_REL_LOCAL_END);
		ho->new_lchan = NULL;
	}

	handover_free(ho);
	conn->ho = NULL;
}

/* T3103 expired: Handover has failed without HO COMPLETE or HO FAIL */
static void ho_T3103_cb(void *_ho)
{
	struct bsc_handover *ho = _ho;
	struct gsm_network *net = ho->new_lchan->ts->trx->bts->network;

	DEBUGP(DHO, "HO T3103 expired\n");
	rate_ctr_inc(&net->bsc_ctrs->ctr[BSC_CTR_HANDOVER_TIMEOUT]);

	/* Inform the GSCON FSM about the timed out handover */
	osmo_fsm_inst_dispatch(ho->old_lchan->conn->fi, GSCON_EV_HO_TIMEOUT, NULL);

	bsc_clear_handover(ho->old_lchan->conn, 1);
}

/* RSL has acknowledged activation of the new lchan */
static int ho_chan_activ_ack(struct gsm_lchan *new_lchan)
{
	struct bsc_handover *ho;

	/* we need to check if this channel activation is related to
	 * a handover at all (and if, which particular handover) */
	ho = bsc_ho_by_new_lchan(new_lchan);
	if (!ho)
		return -ENODEV;

	LOGPHO(ho, LOGL_INFO, "Channel Activate Ack, send %s COMMAND\n", ho->inter_cell? "HANDOVER" : "ASSIGNMENT");

	/* we can now send the 04.08 HANDOVER COMMAND to the MS
	 * using the old lchan */

	gsm48_send_ho_cmd(ho->old_lchan, new_lchan, new_lchan->ms_power, ho->ho_ref);

	/* start T3103.  We can continue either with T3103 expiration,
	 * 04.08 HANDOVER COMPLETE or 04.08 HANDOVER FAIL */
	osmo_timer_setup(&ho->T3103, ho_T3103_cb, ho);
	osmo_timer_schedule(&ho->T3103, 10, 0);

	/* create a RTP connection */
	if (is_ipaccess_bts(new_lchan->ts->trx->bts))
		rsl_ipacc_crcx(new_lchan);

	return 0;
}

/* RSL has not acknowledged activation of the new lchan */
static int ho_chan_activ_nack(struct gsm_lchan *new_lchan)
{
	struct bsc_handover *ho;
	struct handover_decision_callbacks *hdc;

	ho = bsc_ho_by_new_lchan(new_lchan);
	if (!ho) {
		/* This lchan is not involved in a handover. */
		return 0;
	}

	hdc = handover_decision_callbacks_get(ho->from_hodec_id);
	if (hdc && hdc->on_ho_chan_activ_nack)
		hdc->on_ho_chan_activ_nack(ho);

	bsc_clear_handover(new_lchan->conn, 0);
	return 0;
}

/* GSM 04.08 HANDOVER COMPLETE has been received on new channel */
static int ho_gsm48_ho_compl(struct gsm_lchan *new_lchan)
{
	struct gsm_network *net;
	struct bsc_handover *ho;

	ho = bsc_ho_by_new_lchan(new_lchan);
	if (!ho) {
		LOGP(DHO, LOGL_ERROR, "unable to find HO record\n");
		return -ENODEV;
	}

	net = new_lchan->ts->trx->bts->network;

	LOGPHO(ho, LOGL_INFO, "%s Complete\n", ho->inter_cell ? "Handover" : "Assignment");

	rate_ctr_inc(&net->bsc_ctrs->ctr[BSC_CTR_HANDOVER_COMPLETED]);

	osmo_timer_del(&ho->T3103);

	/* Replace the ho lchan with the primary one */
	if (ho->old_lchan != new_lchan->conn->lchan)
		LOGPHO(ho, LOGL_ERROR, "Primary lchan changed during handover.\n");

	if (new_lchan->conn->ho != ho)
		LOGPHO(ho, LOGL_ERROR, "Handover channel changed during this handover.\n");

	new_lchan->conn->lchan = new_lchan;
	ho->old_lchan->conn = NULL;

	lchan_release(ho->old_lchan, 0, RSL_REL_LOCAL_END);

	handover_free(ho);
	new_lchan->conn->ho = NULL;

	/* Inform the GSCON FSM that the handover is complete */
	osmo_fsm_inst_dispatch(new_lchan->conn->fi, GSCON_EV_HO_COMPL, NULL);
	return 0;
}

/* GSM 04.08 HANDOVER FAIL has been received */
static int ho_gsm48_ho_fail(struct gsm_lchan *old_lchan)
{
	struct gsm_network *net = old_lchan->ts->trx->bts->network;
	struct bsc_handover *ho;
	struct handover_decision_callbacks *hdc;

	ho = bsc_ho_by_old_lchan(old_lchan);
	if (!ho) {
		LOGP(DHO, LOGL_ERROR, "unable to find HO record\n");
		return -ENODEV;
	}

	hdc = handover_decision_callbacks_get(ho->from_hodec_id);
	if (hdc && hdc->on_ho_failure)
		hdc->on_ho_failure(ho);

	rate_ctr_inc(&net->bsc_ctrs->ctr[BSC_CTR_HANDOVER_FAILED]);

	bsc_clear_handover(ho->new_lchan->conn, 1);

	/* Inform the GSCON FSM that the handover failed */
	osmo_fsm_inst_dispatch(old_lchan->conn->fi, GSCON_EV_HO_FAIL, NULL);
	return 0;
}

/* GSM 08.58 HANDOVER DETECT has been received */
static int ho_rsl_detect(struct gsm_lchan *new_lchan)
{
	struct bsc_handover *ho;

	ho = bsc_ho_by_new_lchan(new_lchan);
	if (!ho) {
		LOGP(DHO, LOGL_ERROR, "unable to find HO record\n");
		return -ENODEV;
	}

	LOGPHO(ho, LOGL_DEBUG, "Handover RACH detected\n");

	/* This is just for logging on the DHO category. The actual MGCP switchover happens in
	 * osmo_bsc_mgcp.c by receiving the same S_LCHAN_HANDOVER_DETECT signal.
	 * (Calling mgcp_handover() directly currently breaks linking in utils/...) */

	return 0;
}

static int ho_meas_rep(struct gsm_meas_rep *mr)
{
	struct handover_decision_callbacks *hdc;
	enum hodec_id hodec_id = ho_get_algorithm(mr->lchan->ts->trx->bts->ho);

	hdc = handover_decision_callbacks_get(hodec_id);
	if (!hdc || !hdc->on_measurement_report)
		return 0;
	hdc->on_measurement_report(mr);
	return 0;
}

static int ho_logic_sig_cb(unsigned int subsys, unsigned int signal,
			   void *handler_data, void *signal_data)
{
	struct lchan_signal_data *lchan_data;
	struct gsm_lchan *lchan;

	lchan_data = signal_data;
	switch (subsys) {
	case SS_LCHAN:
		lchan = lchan_data->lchan;
		switch (signal) {
		case S_LCHAN_ACTIVATE_ACK:
			return ho_chan_activ_ack(lchan);
		case S_LCHAN_ACTIVATE_NACK:
			return ho_chan_activ_nack(lchan);
		case S_LCHAN_HANDOVER_DETECT:
			return ho_rsl_detect(lchan);
		case S_LCHAN_HANDOVER_COMPL:
			return ho_gsm48_ho_compl(lchan);
		case S_LCHAN_HANDOVER_FAIL:
			return ho_gsm48_ho_fail(lchan);
		case S_LCHAN_MEAS_REP:
			return ho_meas_rep(lchan_data->mr);
		}
		break;
	default:
		break;
	}

	return 0;
}

/* Return the old lchan or NULL. This is meant for audio handling */
struct gsm_lchan *bsc_handover_pending(struct gsm_lchan *new_lchan)
{
	struct bsc_handover *ho;
	ho = bsc_ho_by_new_lchan(new_lchan);
	if (!ho)
		return NULL;
	return ho->old_lchan;
}

static __attribute__((constructor)) void on_dso_load_ho_logic(void)
{
	osmo_signal_register_handler(SS_LCHAN, ho_logic_sig_cb, NULL);
}

/* Count number of currently ongoing handovers
 * inter_cell: if true, count only handovers between two cells. If false, count only handovers within one
 * cell. */
int bsc_ho_count(struct gsm_bts *bts, bool inter_cell)
{
	struct bsc_handover *ho;
	int count = 0;

	llist_for_each_entry(ho, &bsc_handovers, list) {
		if (ho->inter_cell != inter_cell)
			continue;
		if (ho->new_lchan->ts->trx->bts == bts)
			count++;
	}

	return count;
}

void handover_decision_callbacks_register(struct handover_decision_callbacks *hdc)
{
	llist_add_tail(&hdc->entry, &handover_decision_callbacks);
}

struct handover_decision_callbacks *handover_decision_callbacks_get(int hodec_id)
{
	struct handover_decision_callbacks *hdc;
	llist_for_each_entry(hdc, &handover_decision_callbacks, entry) {
		if (hdc->hodec_id == hodec_id)
			return hdc;
	}
	return NULL;
}
