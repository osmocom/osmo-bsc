/* Paging helper and manager.... */
/* (C) 2009,2013 by Holger Hans Peter Freyther <zecke@selfish.org>
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

/*
 * Relevant specs:
 *     12.21:
 *       - 9.4.12 for CCCH Local Threshold
 *
 *     05.58:
 *       - 8.5.2 CCCH Load indication
 *       - 9.3.15 Paging Load
 *
 * Approach:
 *       - Send paging command to subscriber
 *       - On Channel Request we will remember the reason
 *       - After the ACK we will request the identity
 *	 - Then we will send assign the gsm_subscriber and
 *	 - and call a callback
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/tdef.h>
#include <osmocom/gsm/gsm48.h>
#include <osmocom/gsm/gsm0502.h>

#include <osmocom/bsc/bsc_subscriber.h>
#include <osmocom/bsc/paging.h>
#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/signal.h>
#include <osmocom/bsc/abis_rsl.h>
#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/chan_alloc.h>
#include <osmocom/bsc/gsm_08_08.h>
#include <osmocom/bsc/gsm_04_08_rr.h>
#include <osmocom/bsc/bsc_subscr_conn_fsm.h>
#include <osmocom/bsc/bts.h>
#include <osmocom/bsc/bsc_stats.h>

void *tall_paging_ctx = NULL;

/* How many paging requests to Tx on RSL at max before going back to main loop */
#define MAX_PAGE_REQ_PER_ITER 10

/* How often to attempt sending new paging requests (initial, not retrans): 250ms */
static const struct timespec initial_period = {
	.tv_sec = 0,
	.tv_nsec = 250 * 1000 * 1000,
};

/* Minimum period between retransmits of paging req to a subscriber: 500ms */
static const struct timespec retrans_period = {
	.tv_sec = 0,
	.tv_nsec = 500 * 1000 * 1000,
};

/* If no CCCH Lod Ind is received before this time period, the BTS is considered
 * to have stopped sending CCCH Load Indication, probaby due to being under Load
 * Threshold: */
#define bts_no_ccch_load_ind_timeout_sec(bts) ((bts)->ccch_load_ind_period * 2)

/*
 * Kill one paging request update the internal list...
 */
static void paging_remove_request(struct gsm_paging_request *req)
{
	struct gsm_bts *bts = req->bts;
	struct gsm_bts_paging_state *bts_pag_st = &bts->paging;

	osmo_timer_del(&req->T3113);
	llist_del(&req->entry);
	if (req->attempts == 0)
		bts_pag_st->initial_req_list_len--;
	else
		bts_pag_st->retrans_req_list_len--;
	osmo_stat_item_dec(osmo_stat_item_group_get_item(bts->bts_statg, BTS_STAT_PAGING_REQ_QUEUE_LENGTH), 1);
	bsc_subscr_remove_active_paging_request(req->bsub, req);
	talloc_free(req);

	if (llist_empty(&bts_pag_st->initial_req_list) && llist_empty(&bts_pag_st->retrans_req_list))
		osmo_timer_del(&bts_pag_st->work_timer);
}

static void page_ms(struct gsm_paging_request *request)
{
	unsigned int page_group;
	struct gsm_bts *bts = request->bts;
	struct osmo_mobile_identity mi;

	log_set_context(LOG_CTX_BSC_SUBSCR, request->bsub);

	LOG_PAGING_BTS(request, bts, DPAG, LOGL_INFO,
		       "Going to send paging command for ch. type %d (attempt %d)\n",
		       request->chan_type, request->attempts);

	if (request->bsub->tmsi == GSM_RESERVED_TMSI) {
		mi = (struct osmo_mobile_identity){
			.type = GSM_MI_TYPE_IMSI,
		};
		OSMO_STRLCPY_ARRAY(mi.imsi, request->bsub->imsi);
	} else {
		mi = (struct osmo_mobile_identity){
			.type = GSM_MI_TYPE_TMSI,
			.tmsi = request->bsub->tmsi,
		};
	}

	page_group = gsm0502_calc_paging_group(&bts->si_common.chan_desc,
					       str_to_imsi(request->bsub->imsi));
	rsl_paging_cmd(bts, page_group, &mi, request->chan_type, false);
	log_set_context(LOG_CTX_BSC_SUBSCR, NULL);
}

static void paging_handle_pending_requests(struct gsm_bts_paging_state *paging_bts);

static void paging_schedule_if_needed(struct gsm_bts_paging_state *paging_bts)
{
	/* paging_handle_pending_requests() will schedule work_timer if work
	 * needs to be partitioned in several iterations. */
	if (!osmo_timer_pending(&paging_bts->work_timer))
		paging_handle_pending_requests(paging_bts);
}

/* Placeholder to set the value and update the related osmo_stat: */
static void paging_set_available_slots(struct gsm_bts *bts, uint16_t available_slots)
{
	bts->paging.available_slots = available_slots;
	osmo_stat_item_set(osmo_stat_item_group_get_item(bts->bts_statg, BTS_STAT_PAGING_AVAILABLE_SLOTS), available_slots);
}

static void paging_give_credit(void *data)
{
	struct gsm_bts_paging_state *paging_bts_st = data;
	struct gsm_bts *bts = paging_bts_st->bts;
	unsigned int load_ind_timeout = bts_no_ccch_load_ind_timeout_sec(bts);
	uint16_t estimated_slots = paging_estimate_available_slots(bts, load_ind_timeout);
	LOG_BTS(bts, DPAG, LOGL_INFO,
		"Timeout waiting for CCCH Load Indication, assuming BTS is below Load Threshold (available_slots %u -> %u)\n",
		paging_bts_st->available_slots, estimated_slots);
	paging_set_available_slots(bts, estimated_slots);
	paging_schedule_if_needed(paging_bts_st);
	osmo_timer_schedule(&bts->paging.credit_timer, load_ind_timeout, 0);
}

/*! count the number of free channels for given RSL channel type required
 * \param[in] BTS on which we shall count
 * \param[in] rsl_type the RSL channel needed type
 * \returns number of free channels matching \a rsl_type in \a bts */
static int can_send_pag_req(struct gsm_bts *bts, int rsl_type)
{
	struct pchan_load pl;
	int count;

	memset(&pl, 0, sizeof(pl));
	bts_chan_load(&pl, bts);

	switch (rsl_type) {
	case RSL_CHANNEED_TCH_F:
	case RSL_CHANNEED_TCH_ForH:
		goto count_tch;
		break;
	case RSL_CHANNEED_SDCCH:
		goto count_sdcch;
		break;
	case RSL_CHANNEED_ANY:
	default:
		if (bts->network->pag_any_tch)
			goto count_tch;
		else
			goto count_sdcch;
		break;
	}

	return 0;

	/* could available SDCCH */
count_sdcch:
	count = 0;
	count += pl.pchan[GSM_PCHAN_SDCCH8_SACCH8C].total
			- pl.pchan[GSM_PCHAN_SDCCH8_SACCH8C].used;
	count += pl.pchan[GSM_PCHAN_CCCH_SDCCH4].total
			- pl.pchan[GSM_PCHAN_CCCH_SDCCH4].used;
	return bts->paging.free_chans_need > count;

count_tch:
	count = 0;
	count += pl.pchan[GSM_PCHAN_TCH_F].total
			- pl.pchan[GSM_PCHAN_TCH_F].used;
	if (bts->network->neci)
		count += pl.pchan[GSM_PCHAN_TCH_H].total
				- pl.pchan[GSM_PCHAN_TCH_H].used;
	return bts->paging.free_chans_need > count;
}

static void paging_req_timeout_retrans(struct gsm_paging_request *request, const struct timespec *now)
{
	struct gsm_bts_paging_state *bts_pag_st = &request->bts->paging;
	page_ms(request);
	paging_set_available_slots(request->bts, bts_pag_st->available_slots - 1);

	if (request->attempts == 0) {
		/* req is removed from initial_req_list and inserted into retrans_req_list, update list lengths: */
		bts_pag_st->initial_req_list_len--;
		bts_pag_st->retrans_req_list_len++;
	}
	llist_del(&request->entry);
	llist_add_tail(&request->entry, &bts_pag_st->retrans_req_list);

	request->last_attempt_ts = *now;
	request->attempts++;
}

/* Returns number of paged initial requests (up to max_page_req_per_iter).
 * Returning work_done=false means the work timer has been scheduled internally and the caller should avoid processing
 * further requests right now.
 */
static unsigned int step_page_initial_reqs(struct gsm_bts_paging_state *bts_pag_st, unsigned int max_page_req_per_iter,
					   const struct timespec *now, bool *work_done)
{
	struct gsm_paging_request *request, *request2;
	unsigned int num_paged = 0;

	llist_for_each_entry_safe(request, request2, &bts_pag_st->initial_req_list, entry) {
		/* We run out of available slots. Wait until next CCCH Load Ind
		 * arrives or credit_timer triggers to keep processing requests.
		 */
		if (bts_pag_st->available_slots == 0) {
			LOG_PAGING_BTS(request, request->bts, DPAG, LOGL_INFO,
				       "Paging delayed: waiting for available slots at BTS\n");
			*work_done = false;
			return num_paged;
		}

		if (num_paged == max_page_req_per_iter) {
			goto sched_next_iter;
		}

		/* we need to determine the number of free channels */
		if (bts_pag_st->free_chans_need != -1 &&
		    can_send_pag_req(request->bts, request->chan_type) != 0) {
			LOG_PAGING_BTS(request, request->bts, DPAG, LOGL_INFO,
				"Paging delayed: not enough free channels (<%d)\n",
				 bts_pag_st->free_chans_need);
			goto sched_next_iter;
		}

		/* handle the paging request now */
		paging_req_timeout_retrans(request, now);
		num_paged++;
	}

	*work_done = true;
	return num_paged;

sched_next_iter:
	LOG_BTS(bts_pag_st->bts, DPAG, LOGL_DEBUG, "Scheduling next batch in %lld.%06lds (available_slots=%u)\n",
		(long long)initial_period.tv_sec, initial_period.tv_nsec / 1000,
		bts_pag_st->available_slots);
	osmo_timer_schedule(&bts_pag_st->work_timer, initial_period.tv_sec, initial_period.tv_nsec / 1000);
	*work_done = false;
	return num_paged;
}

static unsigned int step_page_retrans_reqs(struct gsm_bts_paging_state *bts_pag_st, unsigned int max_page_req_per_iter,
					   const struct timespec *now)
{
	struct gsm_paging_request *request, *initial_request;
	unsigned int num_paged = 0;
	struct timespec retrans_ts;

	/* do while loop: Try send at most first max_page_req_per_iter paging
	 * requests. Since transmitted requests are re-appended at the end of
	 * the list, we check until we find the first req again, in order to
	 * avoid retransmitting repeated requests until next time paging is
	 * scheduled. */
	initial_request = llist_first_entry_or_null(&bts_pag_st->retrans_req_list,
					    struct gsm_paging_request, entry);
	if (!initial_request)
		return num_paged;

	request = initial_request;
	do {
		/* We run out of available slots. Wait until next CCCH Load Ind
		 * arrives or credit_timer triggers to keep processing requests.
		 */
		if (bts_pag_st->available_slots == 0) {
			LOG_PAGING_BTS(request, request->bts, DPAG, LOGL_INFO,
				       "Paging delayed: waiting for available slots at BTS\n");
			return num_paged;
		}

		/* we need to determine the number of free channels */
		if (bts_pag_st->free_chans_need != -1 &&
		    can_send_pag_req(request->bts, request->chan_type) != 0) {
			LOG_PAGING_BTS(request, request->bts, DPAG, LOGL_INFO,
				"Paging delayed: not enough free channels (<%d)\n",
				 bts_pag_st->free_chans_need);
			goto sched_next_iter;
		}

		/* Check if time to retransmit has elapsed. Otherwise, wait until its time to retransmit. */
		timespecadd(&request->last_attempt_ts, &retrans_period, &retrans_ts);
		if (timespeccmp(now, &retrans_ts, <)) {
			struct timespec tdiff;
			timespecsub(&retrans_ts, now, &tdiff);
			LOG_PAGING_BTS(request, request->bts, DPAG, LOGL_DEBUG,
					"Paging delayed: retransmission happens in %lld.%06lds\n",
					(long long)tdiff.tv_sec, tdiff.tv_nsec / 1000);
			osmo_timer_schedule(&bts_pag_st->work_timer, tdiff.tv_sec, tdiff.tv_nsec / 1000);
			return num_paged;
		}

		if (num_paged >= max_page_req_per_iter)
			goto sched_next_iter;

		/* handle the paging request now */
		paging_req_timeout_retrans(request, now);
		num_paged++;

		request = llist_first_entry(&bts_pag_st->retrans_req_list,
					    struct gsm_paging_request, entry);
	} while (request != initial_request);

	/* Reaching this code paths means all retrans request have been scheduled (and intial_req_list is empty).
	 * Hence, reeschedule ourselves to now + retrans_period. */
	osmo_timer_schedule(&bts_pag_st->work_timer, retrans_period.tv_sec, retrans_period.tv_nsec / 1000);
	return num_paged;

sched_next_iter:
	LOG_BTS(bts_pag_st->bts, DPAG, LOGL_DEBUG, "Scheduling next batch in %lld.%06lds (available_slots=%u)\n",
		(long long)initial_period.tv_sec, initial_period.tv_nsec / 1000,
		bts_pag_st->available_slots);
	osmo_timer_schedule(&bts_pag_st->work_timer, initial_period.tv_sec, initial_period.tv_nsec / 1000);
	return num_paged;
}

/*
 * This is kicked by the periodic PAGING LOAD Indicator
 * coming from abis_rsl.c
 *
 * We attempt to iterate once over the list of items but
 * only upto available_slots.
 */
static void paging_handle_pending_requests(struct gsm_bts_paging_state *paging_bts)
{
	unsigned int num_paged_initial, num_paged_retrans = 0;
	unsigned int max_page_req_per_iter = MAX_PAGE_REQ_PER_ITER;
	struct timespec now;
	bool work_done = false;

	/*
	 * Determine if the pending_requests list is empty and
	 * return then.
	 */
	if (llist_empty(&paging_bts->initial_req_list) &&
	    llist_empty(&paging_bts->retrans_req_list)) {
		/* since the lists are empty, no need to reschedule the timer */
		return;
	}

	osmo_clock_gettime(CLOCK_MONOTONIC, &now);
	paging_bts->last_sched_ts = now;

	num_paged_initial = step_page_initial_reqs(paging_bts, max_page_req_per_iter, &now, &work_done);
	if (work_done) /* All work done for initial requests, work on retransmissions now: */
		num_paged_retrans = step_page_retrans_reqs(paging_bts, max_page_req_per_iter - num_paged_initial, &now);

	LOG_BTS(paging_bts->bts, DPAG, LOGL_DEBUG, "Paged %u subscribers (%u initial, %u retrans) during last iteration\n",
		num_paged_initial + num_paged_retrans, num_paged_initial, num_paged_retrans);
}

static void paging_worker(void *data)
{
	struct gsm_bts_paging_state *paging_bts = data;

	paging_handle_pending_requests(paging_bts);
}

/*! initialize the bts paging state, if it hasn't been initialized yet */
void paging_init(struct gsm_bts *bts)
{
	bts->paging.bts = bts;
	bts->paging.free_chans_need = -1;
	paging_set_available_slots(bts, 0);
	INIT_LLIST_HEAD(&bts->paging.initial_req_list);
	INIT_LLIST_HEAD(&bts->paging.retrans_req_list);
	osmo_timer_setup(&bts->paging.work_timer, paging_worker, &bts->paging);
	osmo_timer_setup(&bts->paging.credit_timer, paging_give_credit, &bts->paging);
}

/* Called upon the bts struct being freed */
void paging_destructor(struct gsm_bts *bts)
{
	paging_flush_bts(bts, NULL);
	osmo_timer_del(&bts->paging.credit_timer);
	osmo_timer_del(&bts->paging.work_timer);
}

/*! Call-back once T3113 (paging timeout) expires for given paging_request */
static void paging_T3113_expired(void *data)
{
	struct gsm_paging_request *req = (struct gsm_paging_request *)data;

	log_set_context(LOG_CTX_BSC_SUBSCR, req->bsub);

	 LOG_PAGING_BTS(req, req->bts, DPAG, LOGL_INFO, "T3113 expired\n");

	/* must be destroyed before calling cbfn, to prevent double free */
	rate_ctr_inc(rate_ctr_group_get_ctr(req->bts->bts_ctrs, BTS_CTR_PAGING_EXPIRED));

	/* If last BTS paging times out (active_paging_requests will be
	 * decremented in paging_remove_request below): */
	if (req->bsub->active_paging_requests_len == 1)
		rate_ctr_inc(rate_ctr_group_get_ctr(bsc_gsmnet->bsc_ctrs, BSC_CTR_PAGING_EXPIRED));

	/* destroy it now. Do not access req afterwards */
	paging_remove_request(req);

	log_set_context(LOG_CTX_BSC_SUBSCR, NULL);
}

#define GSM51_MFRAME_DURATION_us (51 * GSM_TDMA_FN_DURATION_uS) /* 235365 us */
static unsigned int paging_estimate_delay_us(struct gsm_bts *bts, unsigned int num_reqs,
					     unsigned int num_reqs_same_pgroup);

static unsigned int calculate_timer_3113(struct gsm_paging_request *req, unsigned int reqs_before,
					 unsigned int reqs_before_same_pgroup, unsigned int max_dynamic_value)
{
	unsigned int to_us, estimated_to, to;
	struct gsm_bts *bts = req->bts;
	struct osmo_tdef *d = osmo_tdef_get_entry(bts->network->T_defs, 3113);
	unsigned int rach_max_trans, rach_tx_integer, bs_pa_mfrms;

	/* Note: d should always contain a valid pointer since all timers,
	 * including 3113 are statically pre-defined in
	 * struct osmo_tdef gsm_network_T_defs. */
	OSMO_ASSERT(d);

	if (!bts->T3113_dynamic) {
		to = d->val;
		goto ret;
	}

	/* MFRMS defines repeat interval of paging messages for MSs that belong
	 * to same paging group across multiple 51 frame multiframes.
	 * MAXTRANS defines maximum number of RACH retransmissions, spread over
	 * TXINTEGER slots.
	 */
	rach_max_trans = rach_max_trans_raw2val(bts->si_common.rach_control.max_trans);
	rach_tx_integer = rach_tx_integer_raw2val(bts->si_common.rach_control.tx_integer);
	bs_pa_mfrms = (bts->si_common.chan_desc.bs_pa_mfrms + 2);
	to_us = GSM51_MFRAME_DURATION_us * bs_pa_mfrms +
		GSM_TDMA_FN_DURATION_uS * rach_tx_integer * rach_max_trans;

	/* Now add some extra time based on how many requests need to be transmitted before this one: */
	to_us += paging_estimate_delay_us(bts, reqs_before, reqs_before_same_pgroup);

	/* ceiling in seconds + extra time */
	estimated_to = (to_us + 999999) / 1000000 + d->val;

	/* upper bound: see X3113, PAGING_THRESHOLD_X3113_DEFAULT_SEC */
	if (estimated_to > max_dynamic_value)
		to = max_dynamic_value;
	else
		to = estimated_to;

	LOG_PAGING_BTS(req, bts, DPAG, LOGL_DEBUG,
		       "Paging request: T3113 expires in %u seconds (estimated %u)\n",
		       to, estimated_to);
ret:
	osmo_stat_item_set(osmo_stat_item_group_get_item(bts->bts_statg, BTS_STAT_PAGING_T3113), to);
	return to;
}

/*! Start paging + paging timer for given subscriber on given BTS
 * \param bts BTS on which to page
 * \param[in] bsub subscriber we want to page
 * \param[in] type type of radio channel we're requirign
 * \param[in] msc MSC which has issue this paging
 * \returns 0 on success, negative on error */
static int _paging_request(const struct bsc_paging_params *params, struct gsm_bts *bts)
{
	struct gsm_bts_paging_state *bts_entry = &bts->paging;
	struct gsm_paging_request *req;
	unsigned int t3113_timeout_s;
	unsigned int x3113_s = osmo_tdef_get(bts->network->T_defs, -3113, OSMO_TDEF_S, -1);
	unsigned int reqs_before = 0, reqs_before_same_pgroup = 0;
	uint8_t pgroup = gsm0502_calc_paging_group(&bts->si_common.chan_desc,
						   str_to_imsi(params->bsub->imsi));

	rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_PAGING_ATTEMPTED));

	/* Don't try to queue more requests than we can realistically handle within X3113 seconds,
	 * see PAGING_THRESHOLD_X3113_DEFAULT_SEC. */
	if (paging_pending_requests_nr(bts) > paging_estimate_available_slots(bts, x3113_s)) {
		rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_PAGING_OVERLOAD));
		return -ENOSPC;
	}

	/* Find if we already have one for the given subscriber on this BTS: */
	if (bsc_subscr_find_req_by_bts(params->bsub, bts)) {
		LOG_PAGING_BTS(params, bts, DPAG, LOGL_INFO, "Paging request already pending for this subscriber\n");
		rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_PAGING_ALREADY));
		return -EEXIST;
	}

	/* The incoming new req will be stored in initial_req_list giving higher prio
	 * to it over retransmissions. This avoids new subscribers being paged to
	 * be delayed if the paging queue is full due to a lot of retranmissions.
	 * Retranmissions usually mean MS are not reachable/available, so the
	 * rationale here is to prioritize new subs which may be available.
	 *
	 * Count initial reqs already stored in initial_req_list, since those
	 * will be scheduled for transmission before current incoming req and
	   need to be taken into account when calculating T3113 for it.
	 */
	llist_for_each_entry(req, &bts_entry->initial_req_list, entry) {
		reqs_before++;
		if (req->pgroup == pgroup)
			reqs_before_same_pgroup++;
	}

	LOG_PAGING_BTS(params, bts, DPAG, LOGL_DEBUG, "Start paging\n");
	req = talloc_zero(tall_paging_ctx, struct gsm_paging_request);
	OSMO_ASSERT(req);
	req->reason = params->reason;
	req->bsub = params->bsub;
	req->bts = bts;
	req->chan_type = params->chan_needed;
	req->pgroup = pgroup;
	req->msc = params->msc;
	osmo_timer_setup(&req->T3113, paging_T3113_expired, req);
	bsc_subscr_add_active_paging_request(req->bsub, req);

	bts_entry->initial_req_list_len++;
	osmo_stat_item_inc(osmo_stat_item_group_get_item(bts->bts_statg, BTS_STAT_PAGING_REQ_QUEUE_LENGTH), 1);
	llist_add_tail(&req->entry, &bts_entry->initial_req_list);

	t3113_timeout_s = calculate_timer_3113(req, reqs_before, reqs_before_same_pgroup, x3113_s);
	osmo_timer_schedule(&req->T3113, t3113_timeout_s, 0);

	/* Trigger scheduler if needed: */
	if (!osmo_timer_pending(&bts_entry->work_timer)) {
		paging_handle_pending_requests(bts_entry);
	} else if (bts_entry->initial_req_list_len == 1) {
		/* Worker timer is armed -> there was already one req before
		 * bts_entry->initial_req_list_len == 1 -> There were no initial requests
		 *       in the list, aka the timer is waiting for retransmition,
		 *       which is a longer period.
		 * Let's recaculate the time to adapt it to initial_period: */
		struct timespec now, elapsed, tdiff;
		osmo_clock_gettime(CLOCK_MONOTONIC, &now);
		timespecsub(&now, &bts_entry->last_sched_ts, &elapsed);
		if (timespeccmp(&elapsed, &initial_period, <)) {
			timespecsub(&initial_period, &elapsed, &tdiff);
		} else {
			tdiff = (struct timespec){.tv_sec = 0, .tv_nsec = 0 };
		}
		LOG_PAGING_BTS(req, req->bts, DPAG, LOGL_DEBUG,
			       "New req arrived: re-scheduling next batch in %lld.%06lds\n",
			       (long long)tdiff.tv_sec, tdiff.tv_nsec / 1000);
		/* Avoid scheduling timer for short periods, run cb directly: */
		if (tdiff.tv_sec == 0 && tdiff.tv_nsec < 5000)
			paging_worker(bts_entry);
		else
			osmo_timer_schedule(&bts_entry->work_timer, tdiff.tv_sec, tdiff.tv_nsec / 1000);
	} /* else: worker is already ongoing submitting initial requests, nothing do be done */

	return 0;
}

/*! Handle PAGING request from MSC for one (matching) BTS
 * \param bts BTS on which to page
 * \param[in] bsub subscriber we want to page
 * \param[in] type type of radio channel we're requirign
 * \param[in] msc MSC which has issue this paging
 * returns 1 on success; 0 in case of error (e.g. TRX down) */
int paging_request_bts(const struct bsc_paging_params *params, struct gsm_bts *bts)
{
	int rc;

	/* skip all currently inactive TRX */
	if (!trx_is_usable(bts->c0))
		return 0;

	/* Trigger paging, pass any error to the caller */
	rc = _paging_request(params, bts);
	if (rc < 0)
		return 0;
	return 1;
}

/*! Stop paging on all cells and return the MSC that paged (if any) and all pending paging reasons.
 * \param[out] returns the MSC that paged the subscriber, if there was a pending request.
 * \param[out] returns the ORed bitmask of all reasons of pending pagings.
 * \param[in] bts BTS which has received a paging response
 * \param[in] bsub subscriber
 */
void paging_request_stop(struct bsc_msc_data **msc_p, enum bsc_paging_reason *reasons_p,
			struct gsm_bts *bts, struct bsc_subscr *bsub)
{
	struct bsc_msc_data *paged_from_msc = NULL;
	enum bsc_paging_reason reasons = BSC_PAGING_NONE;
	OSMO_ASSERT(bts);
	struct gsm_paging_request *req = bsc_subscr_find_req_by_bts(bsub, bts);

	/* Avoid accessing bsub after reaching 0 active_paging_request_len,
	 * since it could be freed during put(): */
	unsigned remaining = bsub->active_paging_requests_len;

	if (req) {
		paged_from_msc = req->msc;
		reasons = req->reason;
		LOG_PAGING_BTS(req, bts, DPAG, LOGL_DEBUG, "Stop paging\n");
		rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_PAGING_RESPONDED));
		rate_ctr_inc(rate_ctr_group_get_ctr(bts->network->bsc_ctrs, BSC_CTR_PAGING_RESPONDED));
		paging_remove_request(req);
		remaining--;
	}

	while (remaining > 0) {
		struct gsm_paging_request *req;
		req = llist_first_entry(&bsub->active_paging_requests,
					 struct gsm_paging_request, bsub_entry);
		LOG_PAGING_BTS(req, req->bts, DPAG, LOGL_DEBUG, "Stop paging\n");
		reasons |= req->reason;
		if (!paged_from_msc) {
			/* If this happened, it would be a bit weird: it means there was no Paging Request
			 * pending on the BTS that sent the Paging Response, but there *is* a Paging Request
			 * pending on a different BTS. But why not return an MSC when we found one. */
			paged_from_msc = req->msc;
		}
		paging_remove_request(req);
		remaining--;
	}

	*msc_p = paged_from_msc;
	*reasons_p = reasons;
}

/* Remove all paging requests, for specific reasons only. */
void paging_request_cancel(struct bsc_subscr *bsub, enum bsc_paging_reason reasons)
{
	struct gsm_paging_request *req, *req2;
	OSMO_ASSERT(bsub);

	/* Avoid accessing bsub after reaching 0 active_paging_request_len,
	 * since it could be freed during put(): */
	unsigned remaining = bsub->active_paging_requests_len;

	llist_for_each_entry_safe(req, req2, &bsub->active_paging_requests, bsub_entry) {
		if (!(req->reason & reasons))
			continue;
		LOG_PAGING_BTS(req, req->bts, DPAG, LOGL_DEBUG, "Cancel paging reasons=0x%x\n",
			       reasons);
		if (req->reason & ~reasons) {
			/* Other reasons are active, simply drop the reasons from func arg: */
			req->reason &= ~reasons;
			continue;
		}
		/* No reason to keep the paging, remove it: */
		paging_remove_request(req);
		remaining--;
		if (remaining == 0)
			break;
	}
}

/*! Update the BTS paging buffer slots on given BTS */
void paging_update_buffer_space(struct gsm_bts *bts, uint16_t free_slots)
{
	LOG_BTS(bts, DPAG, LOGL_DEBUG, "Rx CCCH Load Indication from BTS (available_slots %u -> %u)\n",
		bts->paging.available_slots, free_slots);
	paging_set_available_slots(bts, free_slots);
	/* Re-arm credit_timer if needed */
	if (trx_is_usable(bts->c0)) {
		paging_schedule_if_needed(&bts->paging);
		osmo_timer_schedule(&bts->paging.credit_timer,
				    bts_no_ccch_load_ind_timeout_sec(bts), 0);
	}
}

/*! Count the number of pending paging requests on given BTS */
unsigned int paging_pending_requests_nr(const struct gsm_bts *bts)
{
	return bts->paging.initial_req_list_len + bts->paging.retrans_req_list_len;
}

/*! Flush all paging requests at a given BTS for a given MSC (or NULL if all MSC should be flushed). */
void paging_flush_bts(struct gsm_bts *bts, struct bsc_msc_data *msc)
{
	struct gsm_paging_request *req, *req2;
	int num_cancelled = 0;
	int i;

	struct llist_head *lists[] = { &bts->paging.initial_req_list, &bts->paging.retrans_req_list };

	for (i = 0; i < ARRAY_SIZE(lists); i++) {
		llist_for_each_entry_safe(req, req2, lists[i], entry) {
			if (msc && req->msc != msc)
				continue;
			/* now give up the data structure */
			LOG_PAGING_BTS(req, bts, DPAG, LOGL_DEBUG, "Stop paging (flush)\n");
			paging_remove_request(req);
			num_cancelled++;
		}
	}

	rate_ctr_add(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_PAGING_MSC_FLUSH), num_cancelled);
}

/*! Flush all paging requests issued by \a msc on any BTS in \a net */
void paging_flush_network(struct gsm_network *net, struct bsc_msc_data *msc)
{
	struct gsm_bts *bts;

	llist_for_each_entry(bts, &net->bts_list, list)
		paging_flush_bts(bts, msc);
}

/* Shim to avoid problems when compiling against libosmocore <= 1.7.0, since
 * gsm0502_get_n_pag_blocks() was not declared const despite being readonly. Once
 * osmo-bsc depends on libosmocore > 1.7.0, this shim can be dropped. */
static inline unsigned int _gsm0502_get_n_pag_blocks(const struct gsm48_control_channel_descr *chan_desc)
{
	return gsm0502_get_n_pag_blocks((struct gsm48_control_channel_descr *)chan_desc);
}

/*! Estimate available_slots credit over a time period, used when below CCCH Load Indication Threshold */
uint16_t paging_estimate_available_slots(const struct gsm_bts *bts, unsigned int time_span_s)
{
	unsigned int n_pag_blocks = _gsm0502_get_n_pag_blocks(&bts->si_common.chan_desc);
	uint16_t available_slots = n_pag_blocks * time_span_s * 1000000 / GSM51_MFRAME_DURATION_us;
	LOG_BTS(bts, DPAG, LOGL_DEBUG, "Estimated %u paging available_slots over %u seconds\n",
		available_slots, time_span_s);
	return available_slots;
}

/*! Conservative estimate of time needed by BTS to schedule a number of paging
 * requests (num_reqs), based on current load at the BSC queue (doesn't take into
 * account BTs own buffer) */
static unsigned int paging_estimate_delay_us(struct gsm_bts *bts, unsigned int num_reqs,
					     unsigned int num_reqs_same_pgroup)
{
	unsigned int n_pag_blocks, n_mframes, time_us = 0;

	n_pag_blocks = _gsm0502_get_n_pag_blocks(&bts->si_common.chan_desc);

	/* First of all, we need to extend the timeout in relation to the amount
	 * of paging requests in the BSC queue. In here we don't care about the
	 * paging group, because they are mixed in the same queue. If we don't
	 * take this into account, it could happen that if lots of requests are
	 * received at the BSC (from MSC) around the same time, they could time
	 * out in the BSC queue before arriving at the BTS. We already account of
	 * same-paging-group ones further below, so don't take them into account
	 * here: */
	unsigned int num_reqs_other_groups = num_reqs - num_reqs_same_pgroup;
	time_us += ((num_reqs_other_groups * GSM51_MFRAME_DURATION_us) + (n_pag_blocks - 1)) / n_pag_blocks;

	/* Now we extend the timeout based on the amount of requests of the same
	 * paging group before the present one: */
	n_mframes = (num_reqs_same_pgroup + (n_pag_blocks - 1)) / n_pag_blocks;
	time_us += n_mframes * GSM51_MFRAME_DURATION_us;
	/* the multiframes are not consecutive for a paging group, let's add the spacing between: */
	if (n_mframes > 1) {
		unsigned int bs_pa_mfrms = (bts->si_common.chan_desc.bs_pa_mfrms + 2);
		time_us += (n_mframes - 1) * bs_pa_mfrms * GSM51_MFRAME_DURATION_us;
	}
	return time_us;
}

/* Callback function to be called every time we receive a signal from NM */
static int nm_sig_cb(unsigned int subsys, unsigned int signal,
		     void *handler_data, void *signal_data)
{
	struct nm_running_chg_signal_data *nsd;
	struct gsm_bts *bts;
	struct gsm_bts_trx *trx;
	unsigned int load_ind_timeout;
	uint16_t estimated_slots;

	if (signal != S_NM_RUNNING_CHG)
		return 0;

	nsd = signal_data;
	bts = nsd->bts;

	switch (nsd->obj_class) {
	case NM_OC_RADIO_CARRIER:
		trx = (struct gsm_bts_trx *)nsd->obj;
		break;
	case NM_OC_BASEB_TRANSC:
		trx = gsm_bts_bb_trx_get_trx((struct gsm_bts_bb_trx *)nsd->obj);
		break;
	default:
		return 0;
	}

	/* We only care about state changes of C0. */
	if (trx != trx->bts->c0)
		return 0;

	if (nsd->running) {
		if (trx_is_usable(trx)) {
			LOG_BTS(bts, DPAG, LOGL_INFO, "C0 becomes available for paging\n");
			/* Fill in initial credit */
			load_ind_timeout = bts_no_ccch_load_ind_timeout_sec(bts);
			estimated_slots = paging_estimate_available_slots(bts, load_ind_timeout);
			paging_set_available_slots(bts, estimated_slots);
			/* Start scheduling credit_timer */
			osmo_timer_schedule(&bts->paging.credit_timer,
					    bts_no_ccch_load_ind_timeout_sec(bts), 0);
			/* work_timer will be started when new paging requests arrive. */
		}
	} else {
		/* If credit timer was not pending it means C0 was already unavailable before (rcarrier||bbtransc) */
		if (osmo_timer_pending(&bts->paging.credit_timer)) {
			LOG_BTS(bts, DPAG, LOGL_INFO, "C0 becomes unavailable for paging\n");
			/* Note: flushing will osmo_timer_del(&bts->paging.work_timer) when queue becomes empty */
			paging_flush_bts(bts, NULL);
			osmo_timer_del(&bts->paging.credit_timer);
		}
	}
	return 0;
}

/* To be called once at startup of the process: */
void paging_global_init(void)
{
	osmo_signal_register_handler(SS_NM, nm_sig_cb, NULL);
}
