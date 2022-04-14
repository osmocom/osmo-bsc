/* SMSCB (SMS Cell Broadcast) Handling for OsmoBSC */
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

#include <limits.h>

#include <osmocom/core/stats.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/select.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/byteswap.h>

#include <osmocom/gsm/cbsp.h>
#include <osmocom/gsm/protocol/gsm_23_041.h>
#include <osmocom/gsm/protocol/gsm_48_049.h>
#include <osmocom/gsm/protocol/gsm_03_41.h>

#include <osmocom/netif/stream.h>

#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/smscb.h>
#include <osmocom/bsc/vty.h>
#include <osmocom/bsc/gsm_04_08_rr.h>
#include <osmocom/bsc/lchan_fsm.h>
#include <osmocom/bsc/abis_rsl.h>
#include <osmocom/bsc/bts.h>

/*********************************************************************************
 * Helper Functions
 *********************************************************************************/

/* replace the old head of an entire list with a new head; effectively moves the entire
 * list from old to new head */
static void llist_replace_head(struct llist_head *new, struct llist_head *old)
{
	if (llist_empty(old))
		INIT_LLIST_HEAD(new);
	else
		__llist_add(new, old->prev, old->next);
	INIT_LLIST_HEAD(old);
}

#define ETWS_PRIM_NOTIF_SIZE	56

/* Build a ETWS Primary Notification message as per TS 23.041 9.4.1.3 */
static int gen_etws_primary_notification(uint8_t *out, uint16_t serial_nr, uint16_t msg_id,
					 uint16_t warn_type, const uint8_t *sec_info)
{
	struct gsm341_etws_message *etws = (struct gsm341_etws_message *)out;

	memset(out, 0, ETWS_PRIM_NOTIF_SIZE);

	osmo_store16be(serial_nr, out);
	etws->msg_id = osmo_htons(msg_id);
	etws->warning_type = osmo_htons(warn_type);

	if (sec_info)
		memcpy(etws->data, sec_info, ETWS_PRIM_NOTIF_SIZE - sizeof(*etws));

	return ETWS_PRIM_NOTIF_SIZE;
}

/*! Obtain SMSCB Channel State for given BTS (basic or extended CBCH) */
struct bts_smscb_chan_state *bts_get_smscb_chan(struct gsm_bts *bts, bool extended)
{
	struct bts_smscb_chan_state *chan_state;

	if (extended)
		chan_state = &bts->cbch_extended;
	else
		chan_state = &bts->cbch_basic;

	return chan_state;
}

/* do an ordered list insertion. we keep the list with increasing period, i.e. the most
 * frequent message first */
static void __bts_smscb_add(struct bts_smscb_chan_state *cstate, struct bts_smscb_message *new)
{
	struct bts_smscb_message *tmp, *tmp2;

	if (llist_empty(&cstate->messages)) {
		llist_add(&new->list, &cstate->messages);
		return;
	}

	llist_for_each_entry_safe(tmp, tmp2, &cstate->messages, list) {
		if (tmp->input.rep_period > new->input.rep_period) {
			/* we found the first message with longer period than the new message,
			 * we must insert ourselves before that one */
			__llist_add(&new->list, tmp->list.prev, &tmp->list);
			return;
		}
	}
	/* we didn't find any messages with longer period than us, insert us at tail */
	llist_add_tail(&new->list, &cstate->messages);
}

/* stringify a SMSCB for logging */
const char *bts_smscb_msg2str(const struct bts_smscb_message *smscb)
{
	static char buf[128];
	snprintf(buf, sizeof(buf), "MsgId=0x%04x/SerialNr=0x%04x/Pages=%u/Period=%u/NumBcastReq=%u",
		 smscb->input.msg_id, smscb->input.serial_nr, smscb->num_pages,
		 smscb->input.rep_period, smscb->input.num_bcast_req);
	return buf;
}

const char *bts_smscb_chan_state_name(const struct bts_smscb_chan_state *cstate)
{
	if (cstate == &cstate->bts->cbch_basic)
		return "BASIC";
	else if (cstate == &cstate->bts->cbch_extended)
		return "EXTENDED";
	else
		return "UNKNOWN";
}

unsigned int bts_smscb_chan_load_percent(const struct bts_smscb_chan_state *cstate)
{
	unsigned int sched_arr_used = 0;
	unsigned int i;

	if (cstate->sched_arr_size == 0)
		return 0;

	/* count the number of used slots */
	for (i = 0; i < cstate->sched_arr_size; i++) {
		if (cstate->sched_arr[i])
			sched_arr_used++;
	}

	OSMO_ASSERT(sched_arr_used <= UINT_MAX/100);
	return (sched_arr_used * 100) / cstate->sched_arr_size;
}

unsigned int bts_smscb_chan_page_count(const struct bts_smscb_chan_state *cstate)
{
	struct bts_smscb_message *smscb;
	unsigned int page_count = 0;

	llist_for_each_entry(smscb, &cstate->messages, list)
		page_count += smscb->num_pages;

	return page_count;
}


/*! Obtain the Cell Global Identifier (CGI) of given BTS; returned in static buffer. */
static struct osmo_cell_global_id *bts_get_cgi(struct gsm_bts *bts)
{
	static struct osmo_cell_global_id cgi;
	cgi.lai.plmn = bts->network->plmn;
	cgi.lai.lac = bts->location_area_code;
	cgi.cell_identity = bts->cell_identity;
	return &cgi;
}

/* represents the various lists that the BSC can create as part of a response */
struct response_state {
	struct osmo_cbsp_cell_list success;	/* osmo_cbsp_cell_ent */
	struct llist_head fail;			/* osmo_cbsp_fail_ent */
	struct osmo_cbsp_num_compl_list num_completed;	/* osmo_cbsp_num_compl_ent */
	struct osmo_cbsp_loading_list loading;	/* osmo_cbsp_loading_ent */
};

/*! per-BTS callback function used by cbsp_per_bts().
 *  \param[in] bts BTS currently being processed
 *  \param[in] dec decoded CBSP message currently being processed
 *  \param r_state response state accumulating cell lists (success/failure/...)
 *  \param priv opaque private data provided by caller of cbsp_per_bts()
 *  \returns 0 on success; negative TS 48.049 cause value on error */
typedef int bts_cb_fn(struct gsm_bts *bts, const struct osmo_cbsp_decoded *dec,
		      struct response_state *r_state, void *priv);

/* append a success for given cell to response state */
static void append_success(struct response_state *r_state, struct gsm_bts *bts)
{
	struct osmo_cbsp_cell_ent *cent = talloc_zero(r_state, struct osmo_cbsp_cell_ent);
	struct osmo_cell_global_id *cgi = bts_get_cgi(bts);

	LOG_BTS(bts, DCBS, LOGL_INFO, "Success\n");

	OSMO_ASSERT(cent);

	cent->cell_id.global = *cgi;
	llist_add_tail(&cent->list, &r_state->success.list);
}

/* append a failure for given cell to response state */
static void append_fail(struct response_state *r_state, struct gsm_bts *bts, uint8_t cause)
{
	struct osmo_cbsp_fail_ent *fent = talloc_zero(r_state, struct osmo_cbsp_fail_ent);
	struct osmo_cell_global_id *cgi = bts_get_cgi(bts);

	LOG_BTS(bts, DCBS, LOGL_NOTICE, "Failure Cause 0x%02x\n", cause);

	OSMO_ASSERT(fent);

	fent->id_discr = CELL_IDENT_WHOLE_GLOBAL;
	fent->cell_id.global = *cgi;
	fent->cause = cause;
	llist_add_tail(&fent->list, &r_state->fail);
}

/* append a 'number of broadcasts completed' for given cell to response state */
static void append_bcast_compl(struct response_state *r_state, struct gsm_bts *bts,
				struct bts_smscb_message *smscb)
{
	struct osmo_cbsp_num_compl_ent *cent = talloc_zero(r_state, struct osmo_cbsp_num_compl_ent);
	struct osmo_cell_global_id *cgi = bts_get_cgi(bts);

	LOG_BTS(bts, DCBS, LOGL_DEBUG, "Number of Broadcasts Completed: %u\n", smscb->bcast_count);

	OSMO_ASSERT(cent);

	r_state->num_completed.id_discr = CELL_IDENT_WHOLE_GLOBAL;
	cent->cell_id.global = *cgi;
	if (smscb->bcast_count > INT16_MAX) {
		cent->num_compl = INT16_MAX;
		cent->num_bcast_info = 0x01; /* Overflow */
	} else {
		cent->num_compl = smscb->bcast_count;
		cent->num_bcast_info = 0x00;
	}
	llist_add_tail(&cent->list, &r_state->num_completed.list);
}

/*! Iterate over all BTSs, find matching ones, execute command on BTS, add result
 *  to succeeded/failed lists.
 *  \param[in] net GSM network in which we operate
 *  \param[in] caller-allocated Response state structure collecting results
 *  \param[in] cell_list Decoded CBSP cell list describing BTSs to operate on
 *  \param[in] cb_fn Call-back function to call for each matching BTS
 *  \param[in] priv Opqaue private data; passed to cb_fn
 *  */
static int cbsp_per_bts(struct gsm_network *net, struct response_state *r_state,
			const struct osmo_cbsp_cell_list *cell_list,
			bts_cb_fn *cb_fn, const struct osmo_cbsp_decoded *dec, void *priv)
{
	struct osmo_cbsp_cell_ent *ent;
	struct gsm_bts *bts;
	uint8_t bts_status[net->num_bts];
	int rc, ret = 0;

	memset(bts_status, 0, sizeof(bts_status));
	INIT_LLIST_HEAD(&r_state->success.list);
	INIT_LLIST_HEAD(&r_state->fail);
	INIT_LLIST_HEAD(&r_state->num_completed.list);
	INIT_LLIST_HEAD(&r_state->loading.list);

	/* special case as cell_list->list is empty in this case */
	if (cell_list->id_discr == CELL_IDENT_BSS) {
		llist_for_each_entry(bts, &net->bts_list, list) {
			bts_status[bts->nr] = 1;
			/* call function on this BTS */
			rc = cb_fn(bts, dec, r_state, priv);
			if (rc < 0) {
				append_fail(r_state, bts, -rc);
				ret = -1;
			} else
				append_success(r_state, bts);
		}
	} else {
		/* normal case: iterate over cell list */
		llist_for_each_entry(ent, &cell_list->list, list) {
			bool found_at_least_one = false;
			/* find all matching BTSs for this entry */
			llist_for_each_entry(bts, &net->bts_list, list) {
				struct gsm0808_cell_id cell_id = {
					.id_discr = cell_list->id_discr,
					.id = ent->cell_id
				};
				if (!gsm_bts_matches_cell_id(bts, &cell_id))
					continue;
				found_at_least_one = true;
				/* skip any BTSs which we've already processed */
				if (bts_status[bts->nr])
					continue;
				bts_status[bts->nr] = 1;
				/* call function on this BTS */
				rc = cb_fn(bts, dec, r_state, priv);
				if (rc < 0) {
					append_fail(r_state, bts, -rc);
					ret = -1;
				} else
					append_success(r_state, bts);
			}
			if (!found_at_least_one) {
				struct osmo_cbsp_fail_ent *fent;
				LOGP(DCBS, LOGL_NOTICE, "CBSP: Couldn't find a single matching BTS\n");
				fent = talloc_zero(r_state, struct osmo_cbsp_fail_ent);
				OSMO_ASSERT(fent);
				fent->id_discr = cell_list->id_discr;
				fent->cell_id = ent->cell_id;
				llist_add_tail(&fent->list, &r_state->fail);
				ret = -1;
			}
		}
	}
	return ret;
}

/*! Find an existing SMSCB message within given BTS.
 *  \param[in] chan_state BTS CBCH channel state
 *  \param[in] msg_id Message Id of to-be-found message
 *  \param[in] serial_nr Serial Number of to-be-found message
 *  \returns SMSCB message if found; NULL otherwise */
struct bts_smscb_message *bts_find_smscb(struct bts_smscb_chan_state *chan_state,
					 uint16_t msg_id, uint16_t serial_nr)
{
	struct bts_smscb_message *smscb;

	llist_for_each_entry(smscb, &chan_state->messages, list) {
		if (smscb->input.msg_id == msg_id && smscb->input.serial_nr == serial_nr)
			return smscb;
	}
	return NULL;
}

/*! create a new SMSCB message for specified BTS; don't link it yet.
 *  \param[in] bts BTS for which the SMSCB is to be allocated
 *  \param[in] wrepl CBSP write-replace message
 *  \returns callee-allocated SMSCB message filled with data from wrepl */
static struct bts_smscb_message *bts_smscb_msg_from_wrepl(struct gsm_bts *bts,
						const struct osmo_cbsp_write_replace *wrepl)
{
	struct bts_smscb_message *smscb = talloc_zero(bts, struct bts_smscb_message);
	struct osmo_cbsp_content *cont;
	int i;

	if (!smscb)
		return NULL;

	OSMO_ASSERT(wrepl->is_cbs);

	/* initialize all pages inside the message */
	for (i = 0; i < ARRAY_SIZE(smscb->page); i++) {
		struct bts_smscb_page *page = &smscb->page[i];
		page->nr = i+1; /* page numbers are 1-based */
		page->msg = smscb;
	}

	/* initialize "header" part */
	smscb->input.msg_id = wrepl->msg_id;
	smscb->input.serial_nr = wrepl->new_serial_nr;
	smscb->input.category = wrepl->u.cbs.category;
	smscb->input.rep_period = wrepl->u.cbs.rep_period;
	smscb->input.num_bcast_req = wrepl->u.cbs.num_bcast_req;
	smscb->input.dcs = wrepl->u.cbs.dcs;
	smscb->num_pages = llist_count(&wrepl->u.cbs.msg_content);
	if (smscb->num_pages > ARRAY_SIZE(smscb->page)) {
		LOG_BTS(bts, DCBS, LOGL_ERROR, "SMSCB with too many pages (%u > %zu)\n",
			smscb->num_pages, ARRAY_SIZE(smscb->page));
		talloc_free(smscb);
		return NULL;
	}

	i = 0;
	llist_for_each_entry(cont, &wrepl->u.cbs.msg_content, list) {
		struct gsm23041_msg_param_gsm *msg_param;
		struct bts_smscb_page *page;
		size_t bytes_used;

		/* we have just ensured a few lines above that this cannot overflow */
		page = &smscb->page[i++];
		msg_param = (struct gsm23041_msg_param_gsm *) &page->data[0];

		/* ensure we don't overflow in the memcpy below */
		osmo_static_assert(sizeof(*page) > sizeof(*msg_param) + sizeof(cont->data), smscb_space);

		/* build 6 byte header according to TS 23.041 9.4.1.2 */
		osmo_store16be(wrepl->new_serial_nr, &msg_param->serial_nr);
		osmo_store16be(wrepl->msg_id, &msg_param->message_id);
		msg_param->dcs = wrepl->u.cbs.dcs;
		msg_param->page_param.num_pages = smscb->num_pages;
		msg_param->page_param.page_nr = page->nr;

		OSMO_ASSERT(cont->user_len <= ARRAY_SIZE(cont->data));
		OSMO_ASSERT(cont->user_len <= ARRAY_SIZE(page->data) - sizeof(*msg_param));
		/* we must not use cont->user_len as length here, as it would truncate any
		 * possible 7-bit padding at the end. Always copy the whole page */
		memcpy(&msg_param->content, cont->data, sizeof(cont->data));
		bytes_used = sizeof(*msg_param) + cont->user_len;
		/* compute number of valid blocks in page */
		page->num_blocks = bytes_used / 22;
		if (bytes_used % 22)
			page->num_blocks += 1;
	}

	return smscb;
}

/*! remove a SMSCB message */
void bts_smscb_del(struct bts_smscb_message *smscb, struct bts_smscb_chan_state *cstate,
		   const char *reason)
{
	struct bts_smscb_page **arr;
	int rc;

	LOG_BTS(cstate->bts, DCBS, LOGL_INFO, "%s Deleting %s (Reason: %s)\n",
		bts_smscb_chan_state_name(cstate), bts_smscb_msg2str(smscb), reason);
	llist_del(&smscb->list);

	/* we must recompute the scheduler array here, as the old one will have pointers
	 * to the pages of the just-to-be-deleted message */
	rc = bts_smscb_gen_sched_arr(cstate, &arr);
	if (rc < 0) {
		LOG_BTS(cstate->bts, DCBS, LOGL_ERROR, "Cannot generate new CBCH scheduler array after "
			"removing message %s. WTF?\n", bts_smscb_msg2str(smscb));
		/* we cannot free the message now, to ensure the page pointers in the old
		 * array are still valid. let's re-add it to keep things sane */
		__bts_smscb_add(cstate, smscb);
	} else {
		/* success */
		talloc_free(smscb);

		/* replace array with new one */
		talloc_free(cstate->sched_arr);
		cstate->sched_arr = arr;
		cstate->sched_arr_size = rc;
		cstate->next_idx = 0;
	}
}


/*********************************************************************************
 * Transmit of CBSP to CBC
 *********************************************************************************/

/* transmit a CBSP RESTART message stating all message data was lost for entire BSS */
int cbsp_tx_restart(struct bsc_cbc_link *cbc, bool is_emerg)
{
	struct osmo_cbsp_decoded *cbsp = osmo_cbsp_decoded_alloc(cbc, CBSP_MSGT_RESTART);

	if (is_emerg)
		cbsp->u.restart.bcast_msg_type = 0x01;
	cbsp->u.restart.recovery_ind = 0x01; /* message data lost */
	cbsp->u.restart.cell_list.id_discr = CELL_IDENT_BSS;

	return cbsp_tx_decoded(cbc, cbsp);
}

/* transmit a CBSP KEEPALIVE COMPLETE to the CBC */
static int tx_cbsp_keepalive_compl(struct bsc_cbc_link *cbc)
{
	struct osmo_cbsp_decoded *cbsp = osmo_cbsp_decoded_alloc(cbc, CBSP_MSGT_KEEP_ALIVE_COMPL);
	return cbsp_tx_decoded(cbc, cbsp);
}

/*********************************************************************************
 * Per-BTS Processing of CBSP from CBC, called via cbsp_per_bts()
 *********************************************************************************/

/* timer call-back once ETWS warning period has expired */
static void etws_pn_cb(void *data)
{
	struct gsm_bts *bts = (struct gsm_bts *)data;
	LOG_BTS(bts, DCBS, LOGL_NOTICE, "ETWS PN Timeout; disabling broadcast via PCH\n");
	rsl_etws_pn_command(bts, RSL_CHAN_PCH_AGCH, NULL, 0);
}

static void etws_primary_to_bts(struct gsm_bts *bts, const struct osmo_cbsp_write_replace *wrepl)
{
	uint8_t etws_primary[ETWS_PRIM_NOTIF_SIZE];
	struct gsm_bts_trx *trx;
	unsigned int count = 0;
	int i, j;

	gen_etws_primary_notification(etws_primary, wrepl->new_serial_nr, wrepl->msg_id,
				      wrepl->u.emergency.warning_type,
				      wrepl->u.emergency.warning_sec_info);

	/* iterate over all lchan in each TS in each TRX of this BTS */
	llist_for_each_entry(trx, &bts->trx_list, list) {
		for (i = 0; i < ARRAY_SIZE(trx->ts); i++) {
			struct gsm_bts_trx_ts *ts = &trx->ts[i];
			for (j = 0; j < ARRAY_SIZE(ts->lchan); j++) {
				struct gsm_lchan *lchan = &ts->lchan[j];
				if (!lchan_may_receive_data(lchan))
					continue;
				gsm48_send_rr_app_info(lchan, 0x1, 0x0, etws_primary,
							sizeof(etws_primary));
				count++;
			}
		}
	}

	LOG_BTS(bts, DCBS, LOGL_NOTICE, "Sent ETWS Primary Notification via %u dedicated channels\n",
		count);

	/* Notify BTS of primary ETWS notification via vendor-specific Abis message */
	if (osmo_bts_has_feature(&bts->features, BTS_FEAT_ETWS_PN)) {
		rsl_etws_pn_command(bts, RSL_CHAN_PCH_AGCH, etws_primary, sizeof(etws_primary));
		LOG_BTS(bts, DCBS, LOGL_NOTICE, "Sent ETWS Primary Notification via common channel\n");
		if (wrepl->u.emergency.warning_period != 0xffffffff) {
			osmo_timer_setup(&bts->etws_timer, etws_pn_cb, bts);
			osmo_timer_schedule(&bts->etws_timer, wrepl->u.emergency.warning_period, 0);
		} else
			LOG_BTS(bts, DCBS, LOGL_NOTICE, "Unlimited ETWS PN broadcast, this breaks "
				"normal network operation due to PCH blockage\n");
	} else
		LOG_BTS(bts, DCBS, LOGL_ERROR, "BTS doesn't support RSL command for ETWS PN\n");
}

/*! Try to execute a write-replace operation; roll-back if it fails.
 *  \param[in] chan_state BTS CBCH channel state
 *  \param[in] extended_cbch Basic (false) or Extended (true) CBCH
 *  \param[in] new_msg New SMSCB message which should be added
 *  \param[in] exclude_msg Existing SMSCB message that shall be replaced (if possible). Can be NULL
 *  \return 0 on success; negative on error */
static int bts_try_write_replace(struct bts_smscb_chan_state *chan_state,
				 struct bts_smscb_message *new_msg,
				 struct bts_smscb_message *exclude_msg,
				 struct response_state *r_state)
{
	struct bts_smscb_page **arr;
	int rc;

	if (exclude_msg) {
		/* temporarily remove from list of SMSCB */
		llist_del(&exclude_msg->list);
	}
	/* temporarily add new_msg to list of SMSCB */
	__bts_smscb_add(chan_state, new_msg);

	/* attempt to create scheduling array */
	rc = bts_smscb_gen_sched_arr(chan_state, &arr);
	if (rc < 0) {
		/* it didn't work out; we couldn't schedule it */
		/* remove the new message again */
		llist_del(&new_msg->list);
		/* up to the caller to free() it */
		if (exclude_msg) {
			/* re-add the temporarily removed message */
			__bts_smscb_add(chan_state, new_msg);
		}
		return -1;
	}

	/* success! */
	if (exclude_msg) {
		LOG_BTS(chan_state->bts, DCBS, LOGL_INFO, "%s Replaced MsgId=0x%04x/Serial=0x%04x, "
			"pages(%u -> %u), period(%u -> %u), num_bcast(%u -> %u)\n",
			bts_smscb_chan_state_name(chan_state),
			new_msg->input.msg_id, new_msg->input.serial_nr,
			exclude_msg->num_pages, new_msg->num_pages,
			exclude_msg->input.rep_period, new_msg->input.rep_period,
			exclude_msg->input.num_bcast_req, new_msg->input.num_bcast_req);
		append_bcast_compl(r_state, chan_state->bts, exclude_msg);
		talloc_free(exclude_msg);
	} else
		LOG_BTS(chan_state->bts, DCBS, LOGL_INFO, "%s Added %s\n",
			bts_smscb_chan_state_name(chan_state), bts_smscb_msg2str(new_msg));

	/* replace array with new one */
	talloc_free(chan_state->sched_arr);
	chan_state->sched_arr = arr;
	chan_state->sched_arr_size = rc;
	chan_state->next_idx = 0;
	return 0;
}


static int bts_rx_write_replace(struct gsm_bts *bts, const struct osmo_cbsp_decoded *dec,
				struct response_state *r_state, void *priv)
{
	const struct osmo_cbsp_write_replace *wrepl = &dec->u.write_replace;
	bool extended_cbch = wrepl->u.cbs.channel_ind;
	struct bts_smscb_chan_state *chan_state = bts_get_smscb_chan(bts, extended_cbch);
	struct bts_smscb_message *smscb;
	int rc;

	if (!wrepl->is_cbs) {
		etws_primary_to_bts(bts, wrepl);
		return 0;
	}

	/* check if cell has a CBCH at all */
	if (!gsm_bts_get_cbch(bts))
		return -CBSP_CAUSE_CB_NOT_SUPPORTED;

	/* check for duplicate */
	if (bts_find_smscb(chan_state, wrepl->msg_id, wrepl->new_serial_nr))
		return -CBSP_CAUSE_MSG_REF_ALREADY_USED;

	if (!wrepl->old_serial_nr) { /* new message */
		/* create new message */
		smscb = bts_smscb_msg_from_wrepl(bts, wrepl);
		if (!smscb)
			return -CBSP_CAUSE_BSC_MEMORY_EXCEEDED;
		/* check if scheduling permits this additional message */
		rc = bts_try_write_replace(chan_state, smscb, NULL, r_state);
		if (rc < 0) {
			talloc_free(smscb);
			return -CBSP_CAUSE_BSC_CAPACITY_EXCEEDED;
		}
	} else { /* modify / replace existing message */
		struct bts_smscb_message *smscb_old;
		/* find existing message */
		smscb_old = bts_find_smscb(chan_state, wrepl->msg_id, *wrepl->old_serial_nr);
		if (!smscb_old)
			return -CBSP_CAUSE_MSG_REF_NOT_IDENTIFIED;
		/* create new message */
		smscb = bts_smscb_msg_from_wrepl(bts, wrepl);
		if (!smscb)
			return -CBSP_CAUSE_BSC_MEMORY_EXCEEDED;
		/* check if scheduling permits this modified message */
		rc = bts_try_write_replace(chan_state, smscb, smscb_old, r_state);
		if (rc < 0) {
			talloc_free(smscb);
			return -CBSP_CAUSE_BSC_CAPACITY_EXCEEDED;
		}
	}
	return 0;
}

static int bts_rx_kill(struct gsm_bts *bts, const struct osmo_cbsp_decoded *dec,
			struct response_state *r_state, void *priv)
{
	const struct osmo_cbsp_kill *kill = &dec->u.kill;
	struct bts_smscb_chan_state *chan_state;
	struct bts_smscb_message *smscb;
	bool extended = false;

	if (kill->channel_ind && *kill->channel_ind == 0x01)
		extended = true;
	chan_state = bts_get_smscb_chan(bts, extended);

	/* Find message by msg_id + old_serial_nr */
	smscb = bts_find_smscb(chan_state, kill->msg_id, kill->old_serial_nr);
	if (!smscb)
		return -CBSP_CAUSE_MSG_REF_NOT_IDENTIFIED;

	append_bcast_compl(r_state, chan_state->bts, smscb);

	/* Remove it */
	bts_smscb_del(smscb, chan_state, "KILL");
	return 0;
}

static int bts_rx_reset(struct gsm_bts *bts, const struct osmo_cbsp_decoded *dec,
			struct response_state *r_state, void *priv)
{
	struct bts_smscb_chan_state *chan_state;
	struct bts_smscb_message *smscb, *smscb2;

	LOG_BTS(bts, DCBS, LOGL_NOTICE, "Rx CBSP RESET: clearing all state; disabling broadcast\n");

	/* remove all SMSCB from CBCH BASIC this BTS */
	chan_state = bts_get_smscb_chan(bts, false);
	llist_for_each_entry_safe(smscb, smscb2, &chan_state->messages, list)
		bts_smscb_del(smscb, chan_state, "RESET");

	/* remove all SMSCB from CBCH EXTENDED this BTS */
	chan_state = bts_get_smscb_chan(bts, true);
	llist_for_each_entry_safe(smscb, smscb2, &chan_state->messages, list)
		bts_smscb_del(smscb, chan_state, "RESET");

	osmo_timer_del(&bts->etws_timer);

	/* Make sure that broadcast is disabled */
	rsl_etws_pn_command(bts, RSL_CHAN_PCH_AGCH, NULL, 0);
	return 0;
}

static int bts_rx_status_query(struct gsm_bts *bts, const struct osmo_cbsp_decoded *dec,
			       struct response_state *r_state, void *priv)
{
	const struct osmo_cbsp_msg_status_query *query = &dec->u.msg_status_query;
	struct bts_smscb_chan_state *chan_state;
	struct bts_smscb_message *smscb;
	bool extended = false;

	if (query->channel_ind == 0x01)
		extended = true;
	chan_state = bts_get_smscb_chan(bts, extended);

	/* Find message by msg_id + old_serial_nr */
	smscb = bts_find_smscb(chan_state, query->msg_id, query->old_serial_nr);
	if (!smscb)
		return -CBSP_CAUSE_MSG_REF_NOT_IDENTIFIED;

	append_bcast_compl(r_state, chan_state->bts, smscb);

	return 0;
}


/*********************************************************************************
 * Receive of CBSP from CBC
 *********************************************************************************/

static int cbsp_rx_write_replace(struct bsc_cbc_link *cbc, const struct osmo_cbsp_decoded *dec)
{
	const struct osmo_cbsp_write_replace *wrepl = &dec->u.write_replace;
	struct gsm_network *net = cbc->net;
	struct response_state *r_state = talloc_zero(cbc, struct response_state);
	struct osmo_cbsp_decoded *resp;
	enum cbsp_channel_ind channel_ind;
	int rc;

	LOGP(DCBS, LOGL_INFO, "CBSP Rx WRITE_REPLACE (%s)\n", wrepl->is_cbs ? "CBS" : "EMERGENCY");

	rc = cbsp_per_bts(net, r_state, &dec->u.write_replace.cell_list,
			  bts_rx_write_replace, dec, NULL);
	/* generate response */
	if (rc < 0) {
		resp = osmo_cbsp_decoded_alloc(cbc, CBSP_MSGT_WRITE_REPLACE_FAIL);
		struct osmo_cbsp_write_replace_failure *fail = &resp->u.write_replace_fail;
		fail->msg_id = wrepl->msg_id;
		fail->new_serial_nr = wrepl->new_serial_nr;
		fail->old_serial_nr = wrepl->old_serial_nr;
		llist_replace_head(&fail->fail_list, &r_state->fail);
		fail->cell_list.id_discr = r_state->success.id_discr;
		llist_replace_head(&fail->cell_list.list, &r_state->success.list);
		if (wrepl->is_cbs) {
			channel_ind = wrepl->u.cbs.channel_ind;
			fail->channel_ind = &channel_ind;
		}
		if (wrepl->old_serial_nr) {
			fail->num_compl_list.id_discr = r_state->num_completed.id_discr;
			llist_replace_head(&fail->num_compl_list.list, &r_state->num_completed.list);
		}
	} else {
		resp = osmo_cbsp_decoded_alloc(cbc, CBSP_MSGT_WRITE_REPLACE_COMPL);
		struct osmo_cbsp_write_replace_complete *compl = &resp->u.write_replace_compl;
		compl->msg_id = wrepl->msg_id;
		compl->new_serial_nr = wrepl->new_serial_nr;
		compl->old_serial_nr = wrepl->old_serial_nr;
		compl->cell_list.id_discr = r_state->success.id_discr;
		llist_replace_head(&compl->cell_list.list, &r_state->success.list);
		if (wrepl->is_cbs) {
			channel_ind = wrepl->u.cbs.channel_ind;
			compl->channel_ind = &channel_ind;
		}
		if (wrepl->old_serial_nr) {
			compl->num_compl_list.id_discr = r_state->num_completed.id_discr;
			llist_replace_head(&compl->num_compl_list.list, &r_state->num_completed.list);
		}
	}

	cbsp_tx_decoded(cbc, resp);
	talloc_free(r_state);
	return rc;
}

static int cbsp_rx_keep_alive(struct bsc_cbc_link *cbc, const struct osmo_cbsp_decoded *dec)
{
	LOGP(DCBS, LOGL_DEBUG, "CBSP Rx KEEP_ALIVE\n");

	/* FIXME: repetition period */
	return tx_cbsp_keepalive_compl(cbc);
}

static int cbsp_rx_kill(struct bsc_cbc_link *cbc, const struct osmo_cbsp_decoded *dec)
{
	const struct osmo_cbsp_kill *kill = &dec->u.kill;
	struct gsm_network *net = cbc->net;
	struct response_state *r_state = talloc_zero(cbc, struct response_state);
	struct osmo_cbsp_decoded *resp;
	int rc;

	LOGP(DCBS, LOGL_DEBUG, "CBSP Rx KILL\n");

	rc = cbsp_per_bts(net, r_state, &dec->u.kill.cell_list, bts_rx_kill, dec, NULL);
	if (rc < 0) {
		resp = osmo_cbsp_decoded_alloc(cbc, CBSP_MSGT_KILL_FAIL);
		struct osmo_cbsp_kill_failure *fail = &resp->u.kill_fail;
		fail->msg_id = kill->msg_id;
		fail->old_serial_nr = kill->old_serial_nr;
		fail->channel_ind = kill->channel_ind;
		llist_replace_head(&fail->fail_list, &r_state->fail);

		fail->cell_list.id_discr = r_state->success.id_discr;
		llist_replace_head(&fail->cell_list.list, &r_state->success.list);

		fail->num_compl_list.id_discr = r_state->num_completed.id_discr;
		llist_replace_head(&fail->num_compl_list.list, &r_state->num_completed.list);
	} else {
		resp = osmo_cbsp_decoded_alloc(cbc, CBSP_MSGT_KILL_COMPL);
		struct osmo_cbsp_kill_complete *compl = &resp->u.kill_compl;
		compl->msg_id = kill->msg_id;
		compl->old_serial_nr = kill->old_serial_nr;
		compl->channel_ind = kill->channel_ind;

		compl->cell_list.id_discr = r_state->success.id_discr;
		llist_replace_head(&compl->cell_list.list, &r_state->success.list);

		compl->num_compl_list.id_discr = r_state->num_completed.id_discr;
		llist_replace_head(&compl->num_compl_list.list, &r_state->num_completed.list);
	}

	cbsp_tx_decoded(cbc, resp);
	talloc_free(r_state);
	return rc;
}

static int cbsp_rx_reset(struct bsc_cbc_link *cbc, const struct osmo_cbsp_decoded *dec)
{
	struct gsm_network *net = cbc->net;
	struct response_state *r_state = talloc_zero(cbc, struct response_state);
	struct osmo_cbsp_decoded *resp;
	int rc;

	LOGP(DCBS, LOGL_DEBUG, "CBSP Rx RESET\n");

	rc = cbsp_per_bts(net, r_state, &dec->u.reset.cell_list, bts_rx_reset, dec, NULL);
	if (rc < 0) {
		resp = osmo_cbsp_decoded_alloc(cbc, CBSP_MSGT_RESET_FAIL);
		struct osmo_cbsp_reset_failure *fail = &resp->u.reset_fail;
		llist_replace_head(&fail->fail_list, &r_state->fail);

		fail->cell_list.id_discr = r_state->success.id_discr;
		llist_replace_head(&fail->cell_list.list, &r_state->success.list);
	} else {
		resp = osmo_cbsp_decoded_alloc(cbc, CBSP_MSGT_RESET_COMPL);
		struct osmo_cbsp_reset_complete *compl = &resp->u.reset_compl;
		if (dec->u.reset.cell_list.id_discr == CELL_IDENT_BSS) {
			/* replace the list of individual cell identities with CELL_IDENT_BSS */
			compl->cell_list.id_discr = CELL_IDENT_BSS;
			/* no need to free success_list entries, hierarchical talloc works */
		} else {
			compl->cell_list.id_discr = r_state->success.id_discr;
			llist_replace_head(&compl->cell_list.list, &r_state->success.list);
		}
	}
	cbsp_tx_decoded(cbc, resp);
	talloc_free(r_state);
	return rc;
}

static int cbsp_rx_status_query(struct bsc_cbc_link *cbc, const struct osmo_cbsp_decoded *dec)
{
	const struct osmo_cbsp_msg_status_query *query = &dec->u.msg_status_query;
	struct gsm_network *net = cbc->net;
	struct response_state *r_state = talloc_zero(cbc, struct response_state);
	struct osmo_cbsp_decoded *resp;
	int rc;

	LOGP(DCBS, LOGL_DEBUG, "CBSP Rx MESSAGE STATUS QUERY\n");

	rc = cbsp_per_bts(net, r_state, &dec->u.msg_status_query.cell_list, bts_rx_status_query, dec, NULL);
	if (rc < 0) {
		resp = osmo_cbsp_decoded_alloc(cbc, CBSP_MSGT_MSG_STATUS_QUERY_FAIL);
		struct osmo_cbsp_msg_status_query_failure *fail = &resp->u.msg_status_query_fail;
		fail->msg_id = query->msg_id;
		fail->old_serial_nr = query->old_serial_nr;
		fail->channel_ind = query->channel_ind;
		llist_replace_head(&fail->fail_list, &r_state->fail);

		fail->num_compl_list.id_discr = r_state->num_completed.id_discr;
		llist_replace_head(&fail->num_compl_list.list, &r_state->num_completed.list);
	} else {
		resp = osmo_cbsp_decoded_alloc(cbc, CBSP_MSGT_MSG_STATUS_QUERY_COMPL);
		struct osmo_cbsp_msg_status_query_complete *compl = &resp->u.msg_status_query_compl;
		compl->msg_id = query->msg_id;
		compl->old_serial_nr = query->old_serial_nr;
		compl->channel_ind = query->channel_ind;

		if (dec->u.msg_status_query.cell_list.id_discr == CELL_IDENT_BSS) {
			/* replace the list of individual cell identities with CELL_IDENT_BSS */
			compl->num_compl_list.id_discr = CELL_IDENT_BSS;
			/* no need to free num_completed_list entries, hierarchical talloc works */
		} else {
			compl->num_compl_list.id_discr = r_state->num_completed.id_discr;
			llist_replace_head(&compl->num_compl_list.list, &r_state->num_completed.list);
		}
	}
	cbsp_tx_decoded(cbc, resp);
	talloc_free(r_state);
	return rc;
}


/*! process an incoming, already decoded CBSP message from the CBC.
 *  \param[in] cbc link to the CBC
 *  \param[in] dec decoded CBSP message structure. Ownership not transferred.
 *  \returns 0 on success; negative on error. */
int cbsp_rx_decoded(struct bsc_cbc_link *cbc, const struct osmo_cbsp_decoded *dec)
{
	int rc = -1;

	switch (dec->msg_type) {
	case CBSP_MSGT_WRITE_REPLACE: 	/* create or modify message */
		rc = cbsp_rx_write_replace(cbc, dec);
		break;
	case CBSP_MSGT_KEEP_ALIVE:	/* solicit an acknowledgement */
		rc = cbsp_rx_keep_alive(cbc, dec);
		break;
	case CBSP_MSGT_KILL:		/* remove message */
		rc = cbsp_rx_kill(cbc, dec);
		break;
	case CBSP_MSGT_RESET:		/* stop broadcasting of all messages */
		rc = cbsp_rx_reset(cbc, dec);
		break;
	case CBSP_MSGT_MSG_STATUS_QUERY:
		rc = cbsp_rx_status_query(cbc, dec);
		break;
	case CBSP_MSGT_LOAD_QUERY:
	case CBSP_MSGT_SET_DRX:
		LOGP(DCBS, LOGL_ERROR, "Received Unimplemented CBSP Message Type %s",
			get_value_string(cbsp_msg_type_names, dec->msg_type));
		/* we should implement those eventually */
		break;
	default:
		LOGP(DCBS, LOGL_ERROR, "Received Unknown/Unexpected CBSP Message Type %s",
			get_value_string(cbsp_msg_type_names, dec->msg_type));
		break;
	}
	return rc;
}

/*********************************************************************************
 * VTY Interface (Introspection)
 *********************************************************************************/

static void vty_dump_smscb_chan_state(struct vty *vty, const struct bts_smscb_chan_state *cs)
{
	const struct bts_smscb_message *sm;

	vty_out(vty, "%s CBCH:%s", cs == &cs->bts->cbch_basic ? "BASIC" : "EXTENDED", VTY_NEWLINE);

	vty_out(vty, " MsgId | SerNo | Pg |      Category | Perd | #Tx  | #Req | DCS%s", VTY_NEWLINE);
	vty_out(vty, "-------|-------|----|---------------|------|------|------|----%s", VTY_NEWLINE);
	llist_for_each_entry(sm, &cs->messages, list) {
		vty_out(vty, "  %04x |  %04x | %2u | %13s | %4u | %4u | %4u | %02x%s",
			sm->input.msg_id, sm->input.serial_nr, sm->num_pages,
			get_value_string(cbsp_category_names, sm->input.category),
			sm->input.rep_period, sm->bcast_count, sm->input.num_bcast_req,
			sm->input.dcs, VTY_NEWLINE);
	}
	vty_out(vty, "%s", VTY_NEWLINE);
}

DEFUN(bts_show_cbs, bts_show_cbs_cmd,
	"show bts <0-255> smscb [(basic|extended)]",
	SHOW_STR "Display information about a BTS\n" "BTS number\n"
	"SMS Cell Broadcast State\n"
	"Show only information related to CBCH BASIC\n"
	"Show only information related to CBCH EXTENDED\n")
{
	struct gsm_network *net = gsmnet_from_vty(vty);
	int bts_nr = atoi(argv[0]);
	struct gsm_bts *bts;

	if (bts_nr >= net->num_bts) {
		vty_out(vty, "%% can't find BTS '%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}
	bts = gsm_bts_num(net, bts_nr);

	if (argc < 2 || !strcmp(argv[1], "basic"))
		vty_dump_smscb_chan_state(vty, &bts->cbch_basic);
	if (argc < 2 || !strcmp(argv[1], "extended"))
		vty_dump_smscb_chan_state(vty, &bts->cbch_extended);

	return CMD_SUCCESS;
}

void smscb_vty_init(void)
{
	install_element_ve(&bts_show_cbs_cmd);
}
