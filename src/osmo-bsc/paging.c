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

/*
 * Kill one paging request update the internal list...
 */
static void paging_remove_request(struct gsm_bts_paging_state *paging_bts,
				  struct gsm_paging_request *to_be_deleted)
{
	to_be_deleted->bsub->active_paging_requests--;
	osmo_timer_del(&to_be_deleted->T3113);
	llist_del(&to_be_deleted->entry);
	bsc_subscr_put(to_be_deleted->bsub, BSUB_USE_PAGING_REQUEST);
	talloc_free(to_be_deleted);
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

static void paging_give_credit(void *data)
{
	struct gsm_bts_paging_state *paging_bts_st = data;
	struct gsm_bts *bts = paging_bts_st->bts;
	uint16_t estimated_slots = paging_estimate_available_slots(bts, bts->ccch_load_ind_period * 2);
	LOG_BTS(bts, DPAG, LOGL_INFO,
		"Timeout waiting for CCCH Load Indication, assuming BTS is below Load Threshold (available_slots %u -> %u)\n",
		paging_bts_st->available_slots, estimated_slots);
	paging_bts_st->available_slots = estimated_slots;
	paging_schedule_if_needed(paging_bts_st);
	osmo_timer_schedule(&bts->paging.credit_timer, bts->ccch_load_ind_period * 2, 0);
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

/*
 * This is kicked by the periodic PAGING LOAD Indicator
 * coming from abis_rsl.c
 *
 * We attempt to iterate once over the list of items but
 * only upto available_slots.
 */
static void paging_handle_pending_requests(struct gsm_bts_paging_state *paging_bts)
{
	struct gsm_paging_request *request, *initial_request;
	unsigned int num_paged = 0;
	struct gsm_bts *bts = paging_bts->bts;
	struct timespec now, retrans_ts;

	/*
	 * Determine if the pending_requests list is empty and
	 * return then.
	 */
	if (llist_empty(&paging_bts->pending_requests)) {
		/* since the list is empty, no need to reschedule the timer */
		return;
	}

	/* Skip paging if the bts is down. */
	if (!bts->c0->rsl_link_primary)
		goto sched_next_iter;

	osmo_clock_gettime(CLOCK_MONOTONIC, &now);

	/* do while loop: Try send at most first MAX_PAGE_REQ_PER_ITER paging
	 * requests (or before if there are no more available slots). Since
	 * transmitted requests are re-appended at the end of the list, we check
	 * until we find the first req again, in order to avoid retransmitting
	 * repeated requests until next time paging is scheduled. */
	initial_request = llist_first_entry(&paging_bts->pending_requests,
					    struct gsm_paging_request, entry);
	request = initial_request;
	do {
		/* We run out of available slots. Wait until next CCCH Load Ind
		 * arrives or credit_timer triggers to keep processing requests.
		 */
		if (paging_bts->available_slots == 0) {
			LOG_PAGING_BTS(request, request->bts, DPAG, LOGL_INFO,
				       "Paging delayed: waiting for available slots at BTS\n");
			return;
		}

		/* we need to determine the number of free channels */
		if (paging_bts->free_chans_need != -1 &&
		    can_send_pag_req(request->bts, request->chan_type) != 0) {
			LOG_PAGING_BTS(request, request->bts, DPAG, LOGL_INFO,
				"Paging delayed: not enough free channels (<%d)\n",
				 paging_bts->free_chans_need);
			goto sched_next_iter;
		}

		/* If we reach around back of the queue (retransmitions), check
		 * if time to retransmit has elapsed. Otherwise, wait until its
		 * time to retransmit. */
		if (request->attempts > 0) {
			timespecadd(&request->last_attempt_ts, &retrans_period, &retrans_ts);
			if (timespeccmp(&now, &retrans_ts, <)) {
				struct timespec tdiff;
				timespecsub(&retrans_ts, &now, &tdiff);
				LOG_PAGING_BTS(request, request->bts, DPAG, LOGL_DEBUG,
					"Paging delayed: retransmission happens later\n");
				osmo_timer_schedule(&paging_bts->work_timer, tdiff.tv_sec, tdiff.tv_nsec / 1000);
				return;
			}
		}

		/* handle the paging request now */
		page_ms(request);
		paging_bts->available_slots--;
		request->last_attempt_ts = now;
		request->attempts++;
		num_paged++;

		llist_del(&request->entry);
		llist_add_tail(&request->entry, &paging_bts->pending_requests);
		request = llist_first_entry(&paging_bts->pending_requests,
					    struct gsm_paging_request, entry);
	} while (request != initial_request && num_paged < MAX_PAGE_REQ_PER_ITER);

	/* Once done iterating, prepare next scheduling: */
sched_next_iter:
	LOG_BTS(bts, DPAG, LOGL_DEBUG, "Paged %u subscribers during last iteration. Scheduling next batch (available_slots=%u)\n",
		num_paged, paging_bts->available_slots);
	osmo_timer_schedule(&paging_bts->work_timer, initial_period.tv_sec, initial_period.tv_nsec / 1000);
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
	bts->paging.available_slots = paging_estimate_available_slots(bts, bts->ccch_load_ind_period * 2);
	INIT_LLIST_HEAD(&bts->paging.pending_requests);
	osmo_timer_setup(&bts->paging.work_timer, paging_worker, &bts->paging);
	osmo_timer_setup(&bts->paging.credit_timer, paging_give_credit, &bts->paging);
	osmo_timer_schedule(&bts->paging.credit_timer, bts->ccch_load_ind_period * 2, 0);
}

/* Called upon the bts struct being freed */
void paging_destructor(struct gsm_bts *bts)
{
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
	if (req->bsub->active_paging_requests == 1)
		rate_ctr_inc(rate_ctr_group_get_ctr(bsc_gsmnet->bsc_ctrs, BSC_CTR_PAGING_EXPIRED));

	/* destroy it now. Do not access req afterwards */
	paging_remove_request(&req->bts->paging, req);

	log_set_context(LOG_CTX_BSC_SUBSCR, NULL);
}

#define GSM51_MFRAME_DURATION_us (51 * GSM_TDMA_FN_DURATION_uS) /* 235365 us */
static unsigned int calculate_timer_3113(struct gsm_paging_request *req)
{
	unsigned int to_us, to;
	struct gsm_bts *bts = req->bts;
	struct osmo_tdef *d = osmo_tdef_get_entry(bts->network->T_defs, 3113);
	unsigned int rach_max_trans, rach_tx_integer, bs_pa_mfrms;

	/* Note: d should always contain a valid pointer since all timers,
	 * including 3113 are statically pre-defined in
	 * struct osmo_tdef gsm_network_T_defs. */
	OSMO_ASSERT(d);

	if (!bts->T3113_dynamic)
		return d->val;

	/* TODO: take into account load of paging group for req->bsub */

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

	/* ceiling in seconds + extra time */
	to = (to_us + 999999) / 1000000 + d->val;
	LOG_PAGING_BTS(req, bts, DPAG, LOGL_DEBUG, "Paging request: T3113 expires in %u seconds\n", to);
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
	struct gsm_paging_request *req, *last_initial_req = NULL;
	unsigned int t3113_timeout_s;

	rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_PAGING_ATTEMPTED));

	/* Iterate list of pending requests to find if we already have one for
	 * the given subscriber. While on it, find the last
	 * not-yet-ever-once-transmitted request; the new request will be added
	 * immediately after it, giving higher prio to initial transmissions
	 * (no retrans). This avoids new subscribers being paged to be delayed
	 * if the paging queue is full due to a lot of retranmissions.
	 * Retranmissions usually mean MS are not reachable/available, so the
	 * rationale here is to prioritize new subs which may be available. */
	llist_for_each_entry(req, &bts_entry->pending_requests, entry) {
		if (params->bsub == req->bsub) {
			LOG_PAGING_BTS(params, bts, DPAG, LOGL_INFO, "Paging request already pending for this subscriber\n");
			rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_PAGING_ALREADY));
			return -EEXIST;
		}
		if (req->attempts == 0)
			last_initial_req = req;
	}

	LOG_PAGING_BTS(params, bts, DPAG, LOGL_DEBUG, "Start paging\n");
	params->bsub->active_paging_requests++;
	req = talloc_zero(tall_paging_ctx, struct gsm_paging_request);
	OSMO_ASSERT(req);
	req->reason = params->reason;
	req->bsub = params->bsub;
	bsc_subscr_get(req->bsub, BSUB_USE_PAGING_REQUEST);
	req->bts = bts;
	req->chan_type = params->chan_needed;
	req->msc = params->msc;
	osmo_timer_setup(&req->T3113, paging_T3113_expired, req);

	/* there's no initial req (attempts==0), add to the start of the list */
	if (last_initial_req == NULL)
		llist_add(&req->entry, &bts_entry->pending_requests);
	else/* Add in the middle of the list after last_initial_req */
		__llist_add(&req->entry, &last_initial_req->entry, last_initial_req->entry.next);

	t3113_timeout_s = calculate_timer_3113(req);
	osmo_timer_schedule(&req->T3113, t3113_timeout_s, 0);
	paging_schedule_if_needed(bts_entry);

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

/*! Stop paging a given subscriber on a given BTS.
 * \param[out] returns the MSC that paged the subscriber, if any.
 * \param[out] returns the reason for a pending paging, if any.
 * \param[in] bts BTS which has received a paging response.
 * \param[in] bsub subscriber.
 * \returns number of pending pagings.
 */
static int paging_request_stop_bts(struct bsc_msc_data **msc_p, enum bsc_paging_reason *reason_p,
				   struct gsm_bts *bts, struct bsc_subscr *bsub)
{
	struct gsm_bts_paging_state *bts_entry = &bts->paging;
	struct gsm_paging_request *req, *req2;

	*msc_p = NULL;
	*reason_p = BSC_PAGING_NONE;

	llist_for_each_entry_safe(req, req2, &bts_entry->pending_requests,
				  entry) {
		if (req->bsub != bsub)
			continue;
		*msc_p = req->msc;
		*reason_p = req->reason;
		LOG_PAGING_BTS(req, bts, DPAG, LOGL_DEBUG, "Stop paging\n");
		paging_remove_request(&bts->paging, req);
		return 1;
	}

	return 0;
}

/*! Stop paging on all cells and return the MSC that paged (if any) and all pending paging reasons.
 * \param[out] returns the MSC that paged the subscriber, if there was a pending request.
 * \param[out] returns the ORed bitmask of all reasons of pending pagings.
 * \param[in] bts BTS which has received a paging response
 * \param[in] bsub subscriber
 * \returns number of pending pagings.
 */
int paging_request_stop(struct bsc_msc_data **msc_p, enum bsc_paging_reason *reasons_p,
			struct gsm_bts *bts, struct bsc_subscr *bsub)
{
	struct gsm_bts *bts_i;
	struct bsc_msc_data *paged_from_msc;
	int count;
	enum bsc_paging_reason reasons;
	OSMO_ASSERT(bts);

	count = paging_request_stop_bts(&paged_from_msc, &reasons, bts, bsub);
	if (paged_from_msc) {
		count++;
		rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_PAGING_RESPONDED));
		rate_ctr_inc(rate_ctr_group_get_ctr(bts->network->bsc_ctrs, BSC_CTR_PAGING_RESPONDED));
	}

	llist_for_each_entry(bts_i, &bsc_gsmnet->bts_list, list) {
		struct bsc_msc_data *paged_from_msc2;
		enum bsc_paging_reason reason2;
		count += paging_request_stop_bts(&paged_from_msc2, &reason2, bts_i, bsub);
		if (paged_from_msc2) {
			reasons |= reason2;
			if (!paged_from_msc) {
				/* If this happened, it would be a bit weird: it means there was no Paging Request
				 * pending on the BTS that sent the Paging Reponse, but there *is* a Paging Request
				 * pending on a different BTS. But why not return an MSC when we found one. */
				paged_from_msc = paged_from_msc2;
			}
		}
	}

	*msc_p = paged_from_msc;
	*reasons_p = reasons;

	return count;
}

/* Remove all paging requests, for specific reasons only. */
int paging_request_cancel(struct bsc_subscr *bsub, enum bsc_paging_reason reasons)
{
	struct gsm_bts *bts;
	int count = 0;

	llist_for_each_entry(bts, &bsc_gsmnet->bts_list, list) {
		struct gsm_paging_request *req, *req2;

		llist_for_each_entry_safe(req, req2, &bts->paging.pending_requests, entry) {
			if (req->bsub != bsub)
				continue;
			if (!(req->reason & reasons))
				continue;
			LOG_PAGING_BTS(req, bts, DPAG, LOGL_DEBUG, "Cancel paging\n");
			paging_remove_request(&bts->paging, req);
			count++;
		}
	}
	return count;
}

/*! Update the BTS paging buffer slots on given BTS */
void paging_update_buffer_space(struct gsm_bts *bts, uint16_t free_slots)
{
	LOG_BTS(bts, DPAG, LOGL_DEBUG, "Rx CCCH Load Indication from BTS (available_slots %u -> %u)\n",
		bts->paging.available_slots, free_slots);
	bts->paging.available_slots = free_slots;
	paging_schedule_if_needed(&bts->paging);
	/* Re-arm credit_timer */
	osmo_timer_schedule(&bts->paging.credit_timer, bts->ccch_load_ind_period * 2, 0);
}

/*! Count the number of pending paging requests on given BTS */
unsigned int paging_pending_requests_nr(struct gsm_bts *bts)
{
	unsigned int requests = 0;
	struct gsm_paging_request *req;

	llist_for_each_entry(req, &bts->paging.pending_requests, entry)
		++requests;

	return requests;
}

/*! Flush all paging requests at a given BTS for a given MSC (or NULL if all MSC should be flushed). */
void paging_flush_bts(struct gsm_bts *bts, struct bsc_msc_data *msc)
{
	struct gsm_paging_request *req, *req2;
	int num_cancelled = 0;

	llist_for_each_entry_safe(req, req2, &bts->paging.pending_requests, entry) {
		if (msc && req->msc != msc)
			continue;
		/* now give up the data structure */
		LOG_PAGING_BTS(req, bts, DPAG, LOGL_DEBUG, "Stop paging (flush)\n");
		paging_remove_request(&bts->paging, req);
		num_cancelled++;
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

/*! Estimate available_slots credit over a time period, used when below CCCH Load Indication Threshold */
uint16_t paging_estimate_available_slots(struct gsm_bts *bts, unsigned int time_span_s)
{
	/* TODO: use gsm48_number_of_paging_subchannels() instead? */
	unsigned int n_pag_blocks = gsm0502_get_n_pag_blocks(&bts->si_common.chan_desc);
	uint16_t available_slots = n_pag_blocks * time_span_s * 1000000 / GSM51_MFRAME_DURATION_us;
	LOG_BTS(bts, DPAG, LOGL_DEBUG, "Estimated %u paging available_slots over %u seconds\n",
		available_slots, time_span_s);
	return available_slots;
}
