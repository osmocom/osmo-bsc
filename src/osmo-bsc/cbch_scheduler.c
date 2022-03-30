/* CBCH (Cell Broadcast Channel) Scheduler for OsmoBSC */
/*
 * (C) 2019 by Harald Welte <laforge@gnumonks.org>
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

#include <osmocom/core/stats.h>
#include <osmocom/core/select.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/talloc.h>

#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/smscb.h>
#include <osmocom/bsc/abis_rsl.h>
#include <osmocom/bsc/bts.h>

/* add all pages of given SMSCB so they appear as soon as possible *after* (included) base_idx. */
static int bts_smscb_sched_add_after(struct bts_smscb_page **sched_arr, int sched_arr_size,
				     int base_idx, struct bts_smscb_message *smscb)
{
	int arr_idx = base_idx;
	int i;

	OSMO_ASSERT(smscb->num_pages <= ARRAY_SIZE(smscb->page));
	for (i = 0; i < smscb->num_pages; i++) {
		while (sched_arr[arr_idx]) {
			arr_idx++;
			if (arr_idx >= sched_arr_size)
				return -ENOSPC;
		}
		sched_arr[arr_idx] = &smscb->page[i];
	}
	return arr_idx;
}

/* add all pages of given smscb so they appear *before* (included) last_idx. */
static int bts_smscb_sched_add_before(struct bts_smscb_page **sched_arr, int sched_arr_size,
				      int last_idx, struct bts_smscb_message *smscb)
{
	int arr_idx = last_idx;
	int last_used_idx = 0;
	int i;

	OSMO_ASSERT(smscb->num_pages <= ARRAY_SIZE(smscb->page));
	OSMO_ASSERT(smscb->num_pages >= 1);

	if (last_idx >= sched_arr_size)
		return -ERANGE;

	for (i = smscb->num_pages - 1; i >= 0; i--) {
		while (sched_arr[arr_idx]) {
			arr_idx--;
			if (arr_idx < 0)
				return -ENOSPC;
		}
		sched_arr[arr_idx] = &smscb->page[i];
		if (i == smscb->num_pages)
			last_used_idx = i;
	}
	return last_used_idx;
}

/* obtain the least frequently scheduled SMSCB for given SMSCB channel */
static struct bts_smscb_message *
bts_smscb_chan_get_least_frequent_smscb(struct bts_smscb_chan_state *cstate)
{
	if (llist_empty(&cstate->messages))
		return NULL;
	/* messages are expected to be ordered with increasing period, so we're
	 * able to return the last message in the list */
	return llist_entry(cstate->messages.prev, struct bts_smscb_message, list);
}

/*! Generate per-BTS SMSCB scheduling array
 *  \param[in] cstate BTS CBCH channel state
 *  \param[out] arr_out return argument for allocated + generated scheduling array
 *  \return size of returned scheduling array arr_out in number of entries; negative on error */
int bts_smscb_gen_sched_arr(struct bts_smscb_chan_state *cstate, struct bts_smscb_page ***arr_out)
{
	struct bts_smscb_message *smscb, *least_freq;
	struct bts_smscb_page **arr;
	int arr_size;
	int rc;

	/* start with one instance of the least frequent message at position 0, as we
	 * need to transmit it exactly once during the duration of the scheduling array */
	least_freq = bts_smscb_chan_get_least_frequent_smscb(cstate);
	if (!least_freq) {
		LOG_BTS(cstate->bts, DCBS, LOGL_DEBUG, "No SMSCB; cannot create schedule array\n");
		*arr_out = NULL;
		return 0;
	}
	arr_size = least_freq->input.rep_period;
	arr = talloc_zero_array(cstate->bts, struct bts_smscb_page *, arr_size);
	OSMO_ASSERT(arr);
	rc = bts_smscb_sched_add_after(arr, arr_size, 0, least_freq);
	if (rc < 0) {
		LOG_BTS(cstate->bts, DCBS, LOGL_ERROR, "Unable to schedule first instance of "
			"very first SMSCB %s ?!?\n", bts_smscb_msg2str(least_freq));
		talloc_free(arr);
		return rc;
	}

	/* continue filling with repetitions of the more frequent messages, starting from
	 * the most frequent message to the least frequent one, repeating them as needed
	 * throughout the duration of the array */
	llist_for_each_entry(smscb, &cstate->messages, list) {
		int last_page;
		if (smscb == least_freq)
			continue;
		/* messages are expected to be ordered with increasing period, so we're
		 * starting with the most frequent / shortest period first */
		rc = bts_smscb_sched_add_after(arr, arr_size, 0, smscb);
		if (rc < 0) {
			LOG_BTS(cstate->bts, DCBS, LOGL_ERROR, "Unable to schedule first instance of "
				"SMSCB %s\n", bts_smscb_msg2str(smscb));
			talloc_free(arr);
			return rc;
		}
		last_page = rc;

		while (last_page + smscb->input.rep_period < cstate->sched_arr_size) {
			/* store further instances in a way that the last block of the N+1th instance
			 * happens no later than "interval" after the last block of the Nth instance */
			rc = bts_smscb_sched_add_before(arr, arr_size,
							last_page + smscb->input.rep_period, smscb);
			if (rc < 0) {
				LOG_BTS(cstate->bts, DCBS, LOGL_ERROR, "Unable to schedule further "
					"SMSCB %s\n", bts_smscb_msg2str(smscb));
				talloc_free(arr);
				return rc;
			}
			last_page = rc;
		}
	}
	*arr_out = arr;
	return arr_size;
}

/*! Pull the next to-be-transmitted SMSCB page out of the scheduler for the given channel */
struct bts_smscb_page *bts_smscb_pull_page(struct bts_smscb_chan_state *cstate)
{
	struct bts_smscb_page *page;

	/* if there are no messages to schedule, there is no array */
	if (!cstate->sched_arr)
		return NULL;

	/* obtain the page from the scheduler array */
	page = cstate->sched_arr[cstate->next_idx];

	/* increment the index for the next call to this function */
	cstate->next_idx = (cstate->next_idx + 1) % cstate->sched_arr_size;

	/* the array can have gaps in between where there is nothing scheduled */
	if (!page)
		return NULL;

	return page;
}

/*! To be called after bts_smscb_pull_page() in order to update transmission count and
 *  check if SMSCB is complete.
 *  \param[in] cstate BTS CBC channel state
 *  \param[in] page SMSCB Page which had been returned by bts_smscb_pull_page() and which
 *  		    is no longer needed now */
void bts_smscb_page_done(struct bts_smscb_chan_state *cstate, struct bts_smscb_page *page)
{
	struct bts_smscb_message *smscb = page->msg;

	/* If this is the last page of a SMSCB, increment the SMSCB number-of-xmit counter */
	if (page->nr == smscb->num_pages) {
		smscb->bcast_count++;
		/* Check if the SMSCB transmission duration is now over */
		if (smscb->bcast_count >= smscb->input.num_bcast_req)
			bts_smscb_del(smscb, cstate, "COMPLETE");
	}
}


/***********************************************************************
 * BTS / RSL side
 ***********************************************************************/

static void bts_cbch_send_one(struct bts_smscb_chan_state *cstate)
{
	struct bts_smscb_page *page;
	struct gsm_bts *bts = cstate->bts;
	struct rsl_ie_cb_cmd_type cb_cmd;
	bool is_extended = false;

	if (cstate == &bts->cbch_extended)
		is_extended = true;

	if (cstate->overflow) {
		LOG_BTS(bts, DCBS, LOGL_DEBUG, "Skipping SMSCB due to overflow (%u)\n",
			cstate->overflow);
		cstate->overflow--;
		return;
	}

	page = bts_smscb_pull_page(cstate);
	if (!page) {
		LOG_BTS(bts, DCBS, LOGL_DEBUG, "Skipping SMSCB: No page available\n");
		return;
	}

	cb_cmd.spare = 0;
	cb_cmd.def_bcast = 0;
	cb_cmd.command = RSL_CB_CMD_TYPE_NORMAL;
	switch (page->num_blocks) {
	case 1:
		cb_cmd.last_block = RSL_CB_CMD_LASTBLOCK_1;
		break;
	case 2:
		cb_cmd.last_block = RSL_CB_CMD_LASTBLOCK_2;
		break;
	case 3:
		cb_cmd.last_block = RSL_CB_CMD_LASTBLOCK_3;
		break;
	case 4:
		cb_cmd.last_block = RSL_CB_CMD_LASTBLOCK_4;
		break;
	default:
		osmo_panic("SMSCB Page must have 1..4 blocks, not %d\n", page->num_blocks);
	}
	rsl_sms_cb_command(bts, RSL_CHAN_SDCCH4_ACCH, cb_cmd, is_extended,
			   page->data, sizeof(page->data));

	bts_smscb_page_done(cstate, page);
}

static void bts_cbch_timer_cb(void *data)
{
	struct gsm_bts *bts = (struct gsm_bts *)data;

	bts_cbch_send_one(&bts->cbch_basic);
	bts_cbch_send_one(&bts->cbch_extended);

	bts_cbch_timer_schedule(bts);
}

/* There is one SMSCB message (page) per eight 51-multiframes, i.e. 1.882 seconds */
void bts_cbch_timer_schedule(struct gsm_bts *bts)
{
	osmo_timer_setup(&bts->cbch_timer, &bts_cbch_timer_cb, bts);
	osmo_timer_schedule(&bts->cbch_timer, 1, 882920);
}

/*! Receive a (decoded) incoming CBCH LOAD IND from given bts. See TS 48.058 8.5.9
 *  \param[in] bts The BTS for which the load indication was received
 *  \param[in] cbch_extended Is this report for extended (true) or basic CBCH
 *  \param[in] is_overflow Is this report and overflow (true) or underflow report
 *  \param[in] slot_count amount of SMSCB messages needed / delay needed */
int bts_smscb_rx_cbch_load_ind(struct gsm_bts *bts, bool cbch_extended, bool is_overflow,
			       uint8_t slot_count)
{
	struct bts_smscb_chan_state *cstate = bts_get_smscb_chan(bts, cbch_extended);
	int i;

	if (!gsm_bts_get_cbch(bts))
		return -ENODEV;

	if (is_overflow) {
		/* halt/delay transmission of further CBCH messages */
		cstate->overflow = slot_count;
	} else {
		for (i = 0; i < slot_count; i++)
			bts_cbch_send_one(cstate);
		/* re-schedule the timer to count from now on */
		bts_cbch_timer_schedule(bts);
	}

	return 0;
}
