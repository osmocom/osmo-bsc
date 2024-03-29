/* Paging helper and manager.... */
/* (C) 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
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

#ifndef PAGING_H
#define PAGING_H

#include <stdlib.h>
#include <string.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/timer.h>

#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/bsc_subscriber.h>
#include <osmocom/bsc/bsc_msc_data.h>

struct bsc_msc_data;

#define LOG_PAGING(PARAMS, SUBSYS, LEVEL, fmt, args...) \
	LOGP(SUBSYS, LEVEL, "(msc=%d) Paging%s: %s: " fmt, \
	     (PARAMS)->msc ? (PARAMS)->msc->nr : -1, \
	     (PARAMS)->reason == BSC_PAGING_FOR_LCS ? " for LCS" : "", \
	     bsc_subscr_name((PARAMS)->bsub), \
	     ##args)

#define LOG_PAGING_BTS(PARAMS, BTS, SUBSYS, LEVEL, fmt, args...) \
	LOG_PAGING(PARAMS, SUBSYS, LEVEL, "(bts=%u) " fmt, (BTS) ? (BTS)->nr : 255, ##args)

#define BSUB_USE_PAGING_START "paging-start"
#define BSUB_USE_PAGING_REQUEST "paging-req"

/* Bitmask of reasons for Paging. Each individual Paging via bsc_paging_start() typically has only one of these reasons
 * set, but when a subscriber responds, we need to aggregate all pending Paging reasons (by bitwise-OR). */
enum bsc_paging_reason {
	BSC_PAGING_NONE = 0,
	BSC_PAGING_FROM_CN = 0x1,
	BSC_PAGING_FOR_LCS = 0x2,
};

/* OS#5552, OS#5553: Maximum allowed scheduling transmit delay in paging
 * requests to be queued, in seconds. If calculated delay for requests to be
 * queued goes over this threshold, they are discarded instead of inserted to
 * the queue. This avoids keeping queueing requests which will be scheduled for
 * transmission too late.
 */
#define PAGING_THRESHOLD_X3113_DEFAULT_SEC 60

#define MAX_PAGING_BLOCKS_CCCH 9
#define MAX_BS_PA_MFRMS 9

struct bsc_paging_params {
	enum bsc_paging_reason reason;
	struct bsc_msc_data *msc;
	struct bsc_subscr *bsub;
	uint32_t tmsi;
	struct osmo_mobile_identity imsi;
	uint8_t chan_needed;
	struct gsm0808_cell_id_list2 cil;
};

/**
 * A pending paging request
 */
struct gsm_paging_request {
	/* list_head for list of all paging requests */
	struct llist_head entry;
	/* the subscriber which we're paging. This struct is included using
	 * bsub_entry field in list bsub->active_paging_requests */
	struct bsc_subscr *bsub;
	struct llist_head bsub_entry;
	/* back-pointer to the BTS on which we are paging */
	struct gsm_bts *bts;
	/* what kind of channel type do we ask the MS to establish */
	int chan_type;
	/* paging group of the subscriber: */
	uint8_t pgroup;

	/* Timer 3113: how long do we try to page? */
	struct osmo_timer_list T3113;

	/* How often did we ask the BTS to page? */
	int attempts;
	/* Timestamp of last time the subscriber was paged */
	struct timespec last_attempt_ts;

	/* MSC that has issued this paging */
	struct bsc_msc_data *msc;

	enum bsc_paging_reason reason;
};

/*
 * This keeps track of the paging status of one BTS. It
 * includes a number of pending requests, a back pointer
 * to the gsm_bts, a timer and some more state.
 */
struct gsm_bts_paging_state {
	/* pending requests (initial paging request, no retransmits) */
	struct llist_head initial_req_list;
	/* Number of requests in initial_req_list */
	unsigned int initial_req_list_len;
	/* pending requests (already transmitted at least once) */
	struct llist_head retrans_req_list;
	/* Number of requests in pending_requests_len */
	unsigned int retrans_req_list_len;

	/* Number of requests in initial_req_list, indexed by pgroup. */
	unsigned int initial_req_pgroup_counts[MAX_PAGING_BLOCKS_CCCH * MAX_BS_PA_MFRMS];

	struct gsm_bts *bts;

	struct osmo_timer_list work_timer;
	struct osmo_timer_list credit_timer;

	/* Last time paging worker was triggered */
	struct timespec last_sched_ts;

	/* free chans needed */
	int free_chans_need;

	/* load */
	uint16_t available_slots;
};

void paging_global_init(void);

void paging_init(struct gsm_bts *bts);
void paging_destructor(struct gsm_bts *bts);

/* schedule paging request */
int paging_request_bts(const struct bsc_paging_params *params, struct gsm_bts *bts);

void paging_request_stop(struct bsc_msc_data **msc_p, enum bsc_paging_reason *reasons_p,
			struct gsm_bts *bts, struct bsc_subscr *bsub);
void paging_request_cancel(struct bsc_subscr *bsub, enum bsc_paging_reason reasons);

/* pending paging requests */
unsigned int paging_pending_requests_nr(const struct gsm_bts *bts);

void paging_flush_bts(struct gsm_bts *bts, struct bsc_msc_data *msc);
void paging_flush_network(struct gsm_network *net, struct bsc_msc_data *msc);

uint16_t paging_estimate_available_slots(const struct gsm_bts *bts, unsigned int time_span_s);

int bsc_paging_start(struct bsc_paging_params *params);
#endif
