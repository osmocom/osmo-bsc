/* (C) 2009-2015 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009-2011 by On-Waves
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

#include <osmocom/bsc/bsc_subscr_conn_fsm.h>
#include <osmocom/bsc/osmo_bsc.h>
#include <osmocom/bsc/bsc_msc_data.h>
#include <osmocom/bsc/bsc_subscriber.h>
#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/paging.h>
#include <osmocom/bsc/gsm_08_08.h>
#include <osmocom/bsc/codec_pref.h>
#include <osmocom/bsc/lchan_fsm.h>

#include <osmocom/bsc/gsm_04_08_rr.h>
#include <osmocom/bsc/a_reset.h>

#include <osmocom/bsc/lcs_ta_req.h>
#include <osmocom/bsc/lcs_loc_req.h>

#include <osmocom/gsm/protocol/gsm_08_08.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gsm/gsm0808.h>
#include <osmocom/gsm/mncc.h>
#include <osmocom/gsm/gsm48.h>
#include <osmocom/gsm/gsm23236.h>

#include <osmocom/bsc/osmo_bsc_sigtran.h>
#include <osmocom/bsc/bts.h>

#define LOG_COMPL_L3(pdisc, mtype, loglevel, format, args...) \
	LOGP(DRSL, loglevel, "%s %s: " format, gsm48_pdisc_name(pdisc), gsm48_pdisc_msgtype_name(pdisc, mtype), ##args)

/* Check if we have a proper connection to the MSC */
static bool msc_connected(struct gsm_subscriber_connection *conn)
{
	/* No subscriber conn at all */
	if (!conn)
		return false;

	/* Connection to MSC not established */
	if (!conn->sccp.msc)
		return false;

	/* Reset procedure not (yet) executed */
	if (a_reset_conn_ready(conn->sccp.msc) == false)
		return false;

	return true;
}

/*! BTS->MSC: tell MSC a SAPI was not established. */
void bsc_sapi_n_reject(struct gsm_subscriber_connection *conn,
		       uint8_t dlci, enum gsm0808_cause cause)
{
	int rc;
	struct msgb *resp;

	if (!msc_connected(conn))
		return;

	LOGP(DMSC, LOGL_NOTICE, "Tx MSC SAPI N REJECT (dlci=0x%02x, cause='%s')\n",
	     dlci, gsm0808_cause_name(cause));
	resp = gsm0808_create_sapi_reject_cause(dlci, cause);
	rate_ctr_inc(&conn->sccp.msc->msc_ctrs->ctr[MSC_CTR_BSSMAP_TX_DT1_SAPI_N_REJECT]);
	rc = osmo_fsm_inst_dispatch(conn->fi, GSCON_EV_TX_SCCP, resp);
	if (rc != 0)
		msgb_free(resp);
}

/*! MS->MSC: Tell MSC that ciphering has been enabled. */
void bsc_cipher_mode_compl(struct gsm_subscriber_connection *conn, struct msgb *msg, uint8_t chosen_encr)
{
	int rc;
	struct msgb *resp;

	if (!msc_connected(conn))
		return;

	LOGP(DMSC, LOGL_DEBUG, "CIPHER MODE COMPLETE from MS, forwarding to MSC\n");
	resp = gsm0808_create_cipher_complete(msg, chosen_encr);
	rate_ctr_inc(&conn->sccp.msc->msc_ctrs->ctr[MSC_CTR_BSSMAP_TX_DT1_CIPHER_COMPLETE]);
	rc = osmo_fsm_inst_dispatch(conn->fi, GSCON_EV_TX_SCCP, resp);
	if (rc != 0)
		msgb_free(resp);
}

/* 9.2.5 CM service accept */
int gsm48_tx_mm_serv_ack(struct gsm_subscriber_connection *conn)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 SERV ACK");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	msg->lchan = conn->lchan;

	gh->proto_discr = GSM48_PDISC_MM;
	gh->msg_type = GSM48_MT_MM_CM_SERV_ACC;

	DEBUGP(DMM, "-> CM SERVICE ACK\n");

	gscon_submit_rsl_dtap(conn, msg, 0, 0);
	return 0;
}

static bool is_cm_service_for_emerg(struct msgb *msg)
{
	struct gsm48_service_request *cm;
	struct gsm48_hdr *gh = msgb_l3(msg);

	if (msgb_l3len(msg) < sizeof(*gh) + sizeof(*cm)) {
		LOGP(DMSC, LOGL_ERROR, "CM ServiceRequest does not fit.\n");
		return false;
	}

	cm = (struct gsm48_service_request *) &gh->data[0];
	return cm->cm_service_type == GSM48_CMSERV_EMERGENCY;
}

static bool is_lu_from_other_plmn(struct msgb *msg)
{
	const struct gsm48_hdr *gh;
	int8_t pdisc;
	uint8_t mtype;
	const struct gsm48_loc_upd_req *lu;
	struct osmo_location_area_id old_lai;

	if (msgb_l3len(msg) < sizeof(*gh))
		return false;

	gh = msgb_l3(msg);
	pdisc = gsm48_hdr_pdisc(gh);
	mtype = gsm48_hdr_msg_type(gh);

	switch (pdisc) {
	case GSM48_PDISC_MM:

		switch (mtype) {
		case GSM48_MT_MM_LOC_UPD_REQUEST:
			/* First make sure that lu-> can be dereferenced */
			if (msgb_l3len(msg) < sizeof(*gh) + sizeof(*lu))
				return false;

			lu = (struct gsm48_loc_upd_req*)gh->data;
			gsm48_decode_lai2(&lu->lai, &old_lai);

			if (osmo_plmn_cmp(&old_lai.plmn, &bsc_gsmnet->plmn) != 0)
				return true;
			break;

		default:
			break;
		}
		break;
	default:
		break;
	}

	return false;
}

static bool is_msc_usable(struct bsc_msc_data *msc, bool is_emerg)
{
	if (is_emerg && !msc->allow_emerg)
		return false;
	if (!a_reset_conn_ready(msc))
		return false;
	return true;
}

/* Decide which MSC to forward this Complete Layer 3 request to.
 * a) If the subscriber was previously paged from a particular MSC, that MSC shall receive the Paging Response.
 * b) If the message contains an NRI indicating a particular MSC and the MSC is connected, that MSC shall handle this
 *    conn.
 * c) All other cases distribute the messages across connected MSCs in a round-robin fashion.
 */
static struct bsc_msc_data *bsc_find_msc(struct gsm_subscriber_connection *conn, const struct osmo_mobile_identity *mi,
					 bool is_emerg, bool from_other_plmn)
{
	struct gsm_network *net = conn->network;
	struct bsc_msc_data *msc;
	struct bsc_msc_data *msc_target = NULL;
	struct bsc_msc_data *msc_round_robin_next = NULL;
	struct bsc_msc_data *msc_round_robin_first = NULL;
	uint8_t round_robin_next_nr;
	int16_t nri_v = -1;
	bool is_null_nri = false;

#define LOG_NRI(LOGLEVEL, FORMAT, ARGS...) \
	LOGP(DMSC, LOGLEVEL, "%s NRI(%d)=0x%x=%d: " FORMAT, osmo_mobile_identity_to_str_c(OTC_SELECT, mi), \
	     net->nri_bitlen, nri_v, nri_v, ##ARGS)

	/* Extract NRI bits from TMSI, possibly indicating which MSC is responsible */
	if (mi->type == GSM_MI_TYPE_TMSI) {
		if (osmo_tmsi_nri_v_get(&nri_v, mi->tmsi, net->nri_bitlen)) {
			LOGP(DMSC, LOGL_ERROR, "Unable to retrieve NRI from TMSI, nri_bitlen == %u\n", net->nri_bitlen);
			nri_v = -1;
		} else if (from_other_plmn) {
			/* If a subscriber was previously attached to a different PLMN, it might still send the other
			 * PLMN's TMSI identity in an IMSI Attach. The LU sends a LAI indicating the previous PLMN. If
			 * it mismatches our PLMN, ignore the NRI. */
			LOG_NRI(LOGL_DEBUG,
				"This LU Request indicates a switch from another PLMN. Ignoring the TMSI's NRI.\n");
			nri_v = -1;
		} else {
			is_null_nri = osmo_nri_v_matches_ranges(nri_v, net->null_nri_ranges);
			if (is_null_nri)
				LOG_NRI(LOGL_DEBUG, "this is a NULL-NRI\n");
		}
	}

	/* Iterate MSCs to find one that matches the extracted NRI, and the next round-robin target for the case no NRI
	 * match is found. */
	round_robin_next_nr = (is_emerg ? net->mscs_round_robin_next_emerg_nr : net->mscs_round_robin_next_nr);
	llist_for_each_entry(msc, &net->mscs, entry) {
		bool nri_matches_msc = (nri_v >= 0 && osmo_nri_v_matches_ranges(nri_v, msc->nri_ranges));

		if (!is_msc_usable(msc, is_emerg)) {
			if (nri_matches_msc) {
				LOG_NRI(LOGL_DEBUG, "matches msc %d, but this MSC is currently not connected\n",
					msc->nr);
				rate_ctr_inc(&msc->msc_ctrs->ctr[MSC_CTR_MSCPOOL_SUBSCR_ATTACH_LOST]);
			}
			continue;
		}

		/* Return MSC if it matches this NRI, with some debug logging. */
		if (nri_matches_msc) {
			if (is_null_nri) {
				LOG_NRI(LOGL_DEBUG, "matches msc %d, but this NRI is also configured as NULL-NRI\n",
					msc->nr);
			} else {
				LOG_NRI(LOGL_DEBUG, "matches msc %d\n", msc->nr);
				rate_ctr_inc(&msc->msc_ctrs->ctr[MSC_CTR_MSCPOOL_SUBSCR_KNOWN]);
				if (is_emerg) {
					rate_ctr_inc(&msc->msc_ctrs->ctr[MSC_CTR_MSCPOOL_EMERG_FORWARDED]);
					rate_ctr_inc(&bsc_gsmnet->bsc_ctrs->ctr[BSC_CTR_MSCPOOL_EMERG_FORWARDED]);
				}
				return msc;
			}
		}

		/* Figure out the next round-robin MSC. The MSCs may appear unsorted in net->mscs. Make sure to linearly
		 * round robin the MSCs by number: pick the lowest msc->nr >= round_robin_next_nr, and also remember the
		 * lowest available msc->nr to wrap back to that in case no next MSC is left.
		 *
		 * MSCs configured with `no allow-attach` do not accept new subscribers and hence must not be picked by
		 * round-robin. Such an MSC still provides service for already attached subscribers: those that
		 * successfully performed IMSI-Attach and have a TMSI with an NRI pointing at that MSC. We only avoid
		 * adding IMSI-Attach of new subscribers. The idea is that the MSC is in a mode of off-loading
		 * subscribers, and the MSC decides when each subscriber is off-loaded, by assigning the NULL-NRI in a
		 * new TMSI (at the next periodical LU). So until the MSC decides to offload, an attached subscriber
		 * remains attached to that MSC and is free to use its services.
		 */
		if (!msc->allow_attach)
			continue;
		if (!msc_round_robin_first || msc->nr < msc_round_robin_first->nr)
			msc_round_robin_first = msc;
		if (msc->nr >= round_robin_next_nr
		    && (!msc_round_robin_next || msc->nr < msc_round_robin_next->nr))
			msc_round_robin_next = msc;
	}

	if (nri_v >= 0 && !is_null_nri)
		LOG_NRI(LOGL_DEBUG, "No MSC found for this NRI, doing round-robin\n");

	/* No dedicated MSC found. Choose by round-robin.
	 * If msc_round_robin_next is NULL, there are either no more MSCs at/after mscs_round_robin_next_nr, or none of
	 * them are usable -- wrap to the start. */
	msc_target = msc_round_robin_next ? : msc_round_robin_first;
	if (!msc_target) {
		rate_ctr_inc(&bsc_gsmnet->bsc_ctrs->ctr[BSC_CTR_MSCPOOL_SUBSCR_NO_MSC]);
		if (is_emerg)
			rate_ctr_inc(&bsc_gsmnet->bsc_ctrs->ctr[BSC_CTR_MSCPOOL_EMERG_LOST]);
		return NULL;
	}

	LOGP(DMSC, LOGL_DEBUG, "New subscriber %s: MSC round-robin selects msc %d\n",
	     osmo_mobile_identity_to_str_c(OTC_SELECT, mi), msc_target->nr);

	if (is_null_nri)
		rate_ctr_inc(&msc_target->msc_ctrs->ctr[MSC_CTR_MSCPOOL_SUBSCR_REATTACH]);
	else
		rate_ctr_inc(&msc_target->msc_ctrs->ctr[MSC_CTR_MSCPOOL_SUBSCR_NEW]);

	if (is_emerg) {
		rate_ctr_inc(&msc_target->msc_ctrs->ctr[MSC_CTR_MSCPOOL_EMERG_FORWARDED]);
		rate_ctr_inc(&bsc_gsmnet->bsc_ctrs->ctr[BSC_CTR_MSCPOOL_EMERG_FORWARDED]);
	}

	/* An MSC was picked by round-robin, so update the next round-robin nr to pick */
	if (is_emerg)
		net->mscs_round_robin_next_emerg_nr = msc_target->nr + 1;
	else
		net->mscs_round_robin_next_nr = msc_target->nr + 1;
	return msc_target;
#undef LOG_NRI
}

static void parse_powercap(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	uint8_t pdisc = gsm48_hdr_pdisc(gh);
	uint8_t mtype = gsm48_hdr_msg_type(gh);
	struct gsm48_loc_upd_req *lu;
	struct gsm48_service_request *serv_req;
	uint8_t pwr_lev;
	struct gsm_bts *bts;
	int8_t rc8;

	switch (pdisc) {
	case GSM48_PDISC_MM:
		switch (mtype) {
		case GSM48_MT_MM_LOC_UPD_REQUEST:
			if (msgb_l3len(msg) < sizeof(*gh) + sizeof(*lu)) {
				LOGPFSML(conn->fi, LOGL_ERROR, "rx Location Updating message too short: %u\n", msgb_l3len(msg));
				return;
			}
			lu = (struct gsm48_loc_upd_req *) gh->data;
			pwr_lev = lu->classmark1.pwr_lev;
			break;

		case GSM48_MT_MM_CM_SERV_REQ:
			if (msgb_l3len(msg) < sizeof(*gh) + sizeof(*serv_req)) {
				LOGPFSML(conn->fi, LOGL_ERROR, "rx CM Service Request message too short: %u\n", msgb_l3len(msg));
				return;
			}
			serv_req = (struct gsm48_service_request *) gh->data;
			pwr_lev = serv_req->classmark2.pwr_lev;
			break;

		default:
			/* No power cap in other messages */
			return;
		}
		break;
	/* FIXME: pwr_lev in Paging Response? */
	default:
		/* No power cap in other messages */
		return;
	}

	bts = conn_get_bts(conn);
	OSMO_ASSERT(bts);
	rc8 = osmo_gsm48_rfpowercap2powerclass(bts->band, pwr_lev);
	if (rc8 < 0) {
		LOGPFSML(conn->fi, LOGL_NOTICE, "%s %s: Unable to decode RF power capability 0x%x\n",
			 gsm48_pdisc_name(pdisc), gsm48_pdisc_msgtype_name(pdisc, mtype), pwr_lev);
		rc8 = 0;
	}
	conn_update_ms_power_class(conn, rc8);
}

/*! MS->MSC: New MM context with L3 payload. */
int bsc_compl_l3(struct gsm_lchan *lchan, struct msgb *msg, uint16_t chosen_channel)
{
	struct gsm_subscriber_connection *conn = NULL;
	struct bsc_subscr *bsub = NULL;
	struct bsc_msc_data *paged_from_msc;
	enum bsc_paging_reason paging_reasons;
	struct bsc_msc_data *msc;
	struct msgb *create_l3;
	struct gsm0808_speech_codec_list scl;
	struct gsm0808_speech_codec_list *use_scl;
	int rc = -2;
	struct gsm_bts *bts;
	struct osmo_cell_global_id *cgi;
	struct osmo_mobile_identity mi;
	struct gsm48_hdr *gh;
	uint8_t pdisc, mtype;
	bool is_emerg;
	bool release_lchan = true;

	if (msgb_l3len(msg) < sizeof(*gh)) {
		LOGP(DRSL, LOGL_ERROR, "There is no GSM48 header here.\n");
		goto early_exit;
	}

	gh = msgb_l3(msg);
	pdisc = gsm48_hdr_pdisc(gh);
	mtype = gsm48_hdr_msg_type(gh);

	bts = lchan->ts->trx->bts;
	OSMO_ASSERT(bts);

	/* Normally, if an lchan has no conn yet, it is an all new Complete Layer 3, and we allocate a new conn on the
	 * A-interface. But there are cases where a conn on A already exists for this subscriber (e.g. Perform Location
	 * Request on IDLE MS). The Mobile Identity tells us whether that is the case. */
	if (osmo_mobile_identity_decode_from_l3(&mi, msg, false)) {
		LOG_COMPL_L3(pdisc, mtype, LOGL_ERROR, "Cannot extract Mobile Identity: %s\n",
			     msgb_hexdump_c(OTC_SELECT, msg));
		/* Likely this is an invalid Complete Layer 3 message that deserves to be rejected. However, the current
		 * state of our ttcn3 tests does send invalid Layer 3 Info in some tests and expects osmo-bsc to not
		 * care about that. So, changing the behavior to rejecting on missing MI causes test failure and, if at
		 * all, should happen in a separate patch.
		 * See e.g.  BSC_Tests.TC_chan_rel_rll_rel_ind: "dt := * f_est_dchan('23'O, 23, '00010203040506'O);"
		 */
	} else {
		bsub = bsc_subscr_find_or_create_by_mi(bsc_gsmnet->bsc_subscribers, &mi, __func__);
	}

	/* If this Mobile Identity already has an active bsc_subscr, look whether there also is an active A-interface
	 * conn for this subscriber. This may be the case during a Perform Location Request (LCS) from the MSC that
	 * started on an IDLE MS, and now the MS is becoming active. Associate with the existing conn. */
	if (bsub)
		conn = bsc_conn_by_bsub(bsub);

	if (!conn) {
		/* Typical Complete Layer 3 with a new conn being established. */
		conn = bsc_subscr_con_allocate(bsc_gsmnet);
		if (!conn) {
			LOG_COMPL_L3(pdisc, mtype, LOGL_ERROR, "Failed to allocate conn\n");
			goto early_exit;
		}
	}
	if (bsub) {
		/* We got the conn either from new allocation, or by searching for it by bsub. So: */
		OSMO_ASSERT((!conn->bsub) || (conn->bsub == bsub));
		if (!conn->bsub) {
			conn->bsub = bsub;
			bsc_subscr_get(conn->bsub, BSUB_USE_CONN);
		}
		bsc_subscr_put(bsub, __func__);
	}
	/* Associate lchan with the conn, and set the id string for logging */
	gscon_change_primary_lchan(conn, lchan);
	gscon_update_id(conn);

	log_set_context(LOG_CTX_BSC_SUBSCR, conn->bsub);

	is_emerg = (pdisc == GSM48_PDISC_MM && mtype == GSM48_MT_MM_CM_SERV_REQ) && is_cm_service_for_emerg(msg);

	/* When receiving a Paging Response, stop Paging for this subscriber on all cells, and figure out which MSC
	 * sent the Paging Request, if any. */
	paged_from_msc = NULL;
	paging_reasons = BSC_PAGING_NONE;
	if (pdisc == GSM48_PDISC_RR && mtype == GSM48_MT_RR_PAG_RESP) {
		paging_request_stop(&paged_from_msc, &paging_reasons, bts, conn->bsub);
		if (!paged_from_msc) {
			/* This looks like an unsolicited Paging Response. It is required to pick any MSC, because any
			 * MT-CSFB calls were Paged by the MSC via SGs, and hence are not listed in the BSC. */
			LOG_COMPL_L3(pdisc, mtype, LOGL_DEBUG,
				     "%s Unsolicited Paging Response, possibly an MT-CSFB call.\n",
				     osmo_mobile_identity_to_str_c(OTC_SELECT, &mi));

			rate_ctr_inc(&bts->bts_ctrs->ctr[BTS_CTR_PAGING_NO_ACTIVE_PAGING]);
			rate_ctr_inc(&bsc_gsmnet->bsc_ctrs->ctr[BSC_CTR_PAGING_NO_ACTIVE_PAGING]);
		} else if (is_msc_usable(paged_from_msc, is_emerg)) {
			LOG_COMPL_L3(pdisc, mtype, LOGL_DEBUG, "%s matches earlier Paging from msc %d\n",
				     osmo_mobile_identity_to_str_c(OTC_SELECT, &mi), paged_from_msc->nr);
			rate_ctr_inc(&paged_from_msc->msc_ctrs->ctr[MSC_CTR_MSCPOOL_SUBSCR_PAGED]);
		} else {
			LOG_COMPL_L3(pdisc, mtype, LOGL_DEBUG,
				     "%s matches earlier Paging from msc %d, but this MSC is not connected\n",
				     osmo_mobile_identity_to_str_c(OTC_SELECT, &mi), paged_from_msc->nr);
			paged_from_msc = NULL;
		}
	}

	if (!conn->sccp.msc) {
		/* The conn was just allocated, and no target MSC has been picked for it yet. */
		if (paged_from_msc)
			msc = paged_from_msc;
		else
			msc = bsc_find_msc(conn, &mi, is_emerg, is_lu_from_other_plmn(msg));
		if (!msc) {
			LOG_COMPL_L3(pdisc, mtype, LOGL_ERROR,
				     "%s%s: No suitable MSC for this Complete Layer 3 request found\n",
				     osmo_mobile_identity_to_str_c(OTC_SELECT, &mi),
				     is_emerg ? " FOR EMERGENCY CALL" : "");
			goto early_exit;
		}

		/* allocate resource for a new connection */
		if (osmo_bsc_sigtran_new_conn(conn, msc) != BSC_CON_SUCCESS)
			goto early_exit;
	} else if (paged_from_msc && conn->sccp.msc != paged_from_msc) {
		LOG_COMPL_L3(pdisc, mtype, LOGL_ERROR,
			     "%s%s: there is a conn to MSC %u, but there is a pending Paging request from MSC %u\n",
			     osmo_mobile_identity_to_str_c(OTC_SELECT, &mi),
			     is_emerg ? " FOR EMERGENCY CALL" : "",
			     conn->sccp.msc->nr, paged_from_msc->nr);
	}
	OSMO_ASSERT(conn->sccp.msc);

	parse_powercap(conn, msg);

	/* If a BSSLAP TA Request from the SMLC is waiting for a TA value, we have one now. */
	if (conn->lcs.loc_req && conn->lcs.loc_req->ta_req)
		osmo_fsm_inst_dispatch(conn->lcs.loc_req->ta_req->fi, LCS_TA_REQ_EV_GOT_TA, NULL);

	/* If the Paging was issued only by OsmoBSC for LCS, don't bother to establish Layer 3 to the MSC. */
	if (paged_from_msc && !(paging_reasons & BSC_PAGING_FROM_CN)) {
		LOG_COMPL_L3(pdisc, mtype, LOGL_DEBUG,
			     "%s%s: Paging was for Perform Location Request only, not establishing Layer 3\n",
			     osmo_mobile_identity_to_str_c(OTC_SELECT, &mi),
			     is_emerg ? " FOR EMERGENCY CALL" : "");
		rc = 0;
		goto early_exit;
	}

	/* Send the Create Layer 3. */
	use_scl = NULL;
	if (gscon_is_aoip(conn)) {
		gen_bss_supported_codec_list(&scl, conn->sccp.msc, bts);
		if (scl.len > 0)
			use_scl = &scl;
		/* For AoIP, we should always pass a Codec List (BSS Supported). But osmo-bsc may be configured to
		 * support no voice codecs -- then omit the Codec List. */
	}
	cgi = cgi_for_msc(conn->sccp.msc, bts);
	if (!cgi) {
		/* should never happen */
		LOG_COMPL_L3(pdisc, mtype, LOGL_ERROR, "%s: internal error: BTS without identity\n",
			     osmo_mobile_identity_to_str_c(OTC_SELECT, &mi));
		goto early_exit;
	}
	create_l3 = gsm0808_create_layer3_2(msg, cgi, use_scl);
	if (!create_l3) {
		LOG_COMPL_L3(pdisc, mtype, LOGL_ERROR, "%s: Failed to compose Create Layer 3 message\n",
			     osmo_mobile_identity_to_str_c(OTC_SELECT, &mi));
		goto early_exit;
	}
	rc = osmo_fsm_inst_dispatch(conn->fi, GSCON_EV_MO_COMPL_L3, create_l3);
	if (!rc)
		release_lchan = false;

early_exit:
	if (release_lchan)
		lchan_release(lchan, true, true, RSL_ERR_EQUIPMENT_FAIL);
	log_set_context(LOG_CTX_BSC_SUBSCR, NULL);
	return rc;
}

/* Data Link Connection Identifier (DLCI) is defined in 3GPP TS 48.006, section 9.3.2.
 * .... .SSS - SAPI value used on the radio link;
 * CC.. .... - control channel identification:
 *   00.. .... - indicates that the control channel is not further specified,
 *   10.. .... - represents the FACCH or the SDCCH,
 *   11.. .... - represents the SACCH,
 *   other values are reserved. */
#define RSL_LINK_ID2DLCI(link_id) \
	(link_id & 0x40 ? 0xc0 : 0x80) | (link_id & 0x07)

/*! MS->BSC/MSC: Um L3 message. */
void bsc_dtap(struct gsm_subscriber_connection *conn, uint8_t link_id, struct msgb *msg)
{
	log_set_context(LOG_CTX_BSC_SUBSCR, conn->bsub);

	if (!msc_connected(conn))
		goto done;

	LOGP(DMSC, LOGL_INFO, "Tx MSC DTAP LINK_ID=0x%02x\n", link_id);

	parse_powercap(conn, msg);

	/* convert RSL link ID to DLCI, store in msg->cb */
	OBSC_LINKID_CB(msg) = RSL_LINK_ID2DLCI(link_id);

	osmo_fsm_inst_dispatch(conn->fi, GSCON_EV_MO_DTAP, msg);
done:
	log_set_context(LOG_CTX_BSC_SUBSCR, NULL);
	return;
}

/*! BSC->MSC: Classmark Update. */
void bsc_cm_update(struct gsm_subscriber_connection *conn,
		   const uint8_t *cm2, uint8_t cm2_len,
		   const uint8_t *cm3, uint8_t cm3_len)
{
	struct gsm48_classmark2 *cm2_parsed = (struct gsm48_classmark2 *)cm2;
	int8_t rc8;
	int rc;
	struct msgb *resp;
	struct gsm_bts *bts = conn_get_bts(conn);

	if (!bts) {
		/* should never happen */
		LOGP(DMSC, LOGL_ERROR, "Classmark Update without lchan\n");
		return;
	}

	rc8 = osmo_gsm48_rfpowercap2powerclass(bts->band, cm2_parsed->pwr_lev);
	if (rc8 < 0) {
		LOGP(DMSC, LOGL_NOTICE,
		     "Unable to decode RF power capability %x from classmark1 during CM Update.\n",
		     cm2_parsed->pwr_lev);
		rc8 = 0;
	}
	conn_update_ms_power_class(conn, rc8);

        rc = gsm48_decode_classmark3(&conn->cm3, cm3, cm3_len);
	if (rc < 0) {
		LOGP(DMSC, LOGL_NOTICE, "Unable to decode classmark3 during CM Update.\n");
		memset(&conn->cm3, 0, sizeof(conn->cm3));
		conn->cm3_valid = false;
	} else
		conn->cm3_valid = true;

	if (!msc_connected(conn))
		return;

	rate_ctr_inc(&conn->sccp.msc->msc_ctrs->ctr[MSC_CTR_BSSMAP_TX_DT1_CLASSMARK_UPDATE]);
	resp = gsm0808_create_classmark_update(cm2, cm2_len, cm3, cm3_len);
	rc = osmo_fsm_inst_dispatch(conn->fi, GSCON_EV_TX_SCCP, resp);
	if (rc != 0)
		msgb_free(resp);
}
