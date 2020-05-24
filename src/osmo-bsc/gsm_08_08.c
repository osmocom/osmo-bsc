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

#include <osmocom/bsc/gsm_04_08_rr.h>
#include <osmocom/bsc/a_reset.h>

#include <osmocom/gsm/protocol/gsm_08_08.h>
#include <osmocom/gsm/gsm0808.h>
#include <osmocom/gsm/mncc.h>
#include <osmocom/gsm/gsm48.h>

#include <osmocom/bsc/osmo_bsc_sigtran.h>

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
void bsc_sapi_n_reject(struct gsm_subscriber_connection *conn, int dlci)
{
	int rc;
	struct msgb *resp;

	if (!msc_connected(conn))
		return;

	LOGP(DMSC, LOGL_NOTICE, "Tx MSC SAPI N REJECT DLCI=0x%02x\n", dlci);
	resp = gsm0808_create_sapi_reject(dlci);
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

static int is_cm_service_for_emerg(struct msgb *msg)
{
	struct gsm48_service_request *cm;
	struct gsm48_hdr *gh = msgb_l3(msg);

	if (msgb_l3len(msg) < sizeof(*gh) + sizeof(*cm)) {
		LOGP(DMSC, LOGL_ERROR, "CM ServiceRequest does not fit.\n");
		return 0;
	}

	cm = (struct gsm48_service_request *) &gh->data[0];
	return cm->cm_service_type == GSM48_CMSERV_EMERGENCY;
}

/* extract a subscriber from the paging response */
static struct bsc_subscr *extract_sub(struct gsm_subscriber_connection *conn,
				   struct msgb *msg)
{
	uint8_t mi_type;
	char mi_string[GSM48_MI_SIZE];
	struct gsm48_hdr *gh;
	struct gsm48_pag_resp *resp;
	struct bsc_subscr *subscr;

	if (msgb_l3len(msg) < sizeof(*gh) + sizeof(*resp)) {
		LOGP(DMSC, LOGL_ERROR, "PagingResponse too small: %u\n", msgb_l3len(msg));
		return NULL;
	}

	gh = msgb_l3(msg);
	resp = (struct gsm48_pag_resp *) &gh->data[0];

	gsm48_paging_extract_mi(resp, msgb_l3len(msg) - sizeof(*gh),
				mi_string, &mi_type);
	DEBUGP(DRR, "PAGING RESPONSE: MI(%s)=%s\n",
		gsm48_mi_type_name(mi_type), mi_string);

	switch (mi_type) {
	case GSM_MI_TYPE_TMSI:
		subscr = bsc_subscr_find_by_tmsi(conn->network->bsc_subscribers,
					      tmsi_from_string(mi_string));
		break;
	case GSM_MI_TYPE_IMSI:
		subscr = bsc_subscr_find_by_imsi(conn->network->bsc_subscribers,
					      mi_string);
		break;
	default:
		subscr = NULL;
		break;
	}

	return subscr;
}

static struct bsc_msc_data *bsc_find_msc(struct gsm_subscriber_connection *conn,
				   struct msgb *msg)
{
	struct gsm48_hdr *gh;
	int8_t pdisc;
	uint8_t mtype;
	struct osmo_bsc_data *bsc;
	struct bsc_msc_data *msc, *pag_msc;
	struct bsc_subscr *subscr;
	int is_emerg = 0;

	bsc = conn->network->bsc_data;

	if (msgb_l3len(msg) < sizeof(*gh)) {
		LOGP(DMSC, LOGL_ERROR, "There is no GSM48 header here.\n");
		return NULL;
	}

	gh = msgb_l3(msg);
	pdisc = gsm48_hdr_pdisc(gh);
	mtype = gsm48_hdr_msg_type(gh);

	/*
	 * We are asked to select a MSC here but they are not equal. We
	 * want to respond to a paging request on the MSC where we got the
	 * request from. This is where we need to decide where this connection
	 * will go.
	 */
	if (pdisc == GSM48_PDISC_RR && mtype == GSM48_MT_RR_PAG_RESP)
		goto paging;
	else if (pdisc == GSM48_PDISC_MM && mtype == GSM48_MT_MM_CM_SERV_REQ) {
		is_emerg = is_cm_service_for_emerg(msg);
		goto round_robin;
	} else
		goto round_robin;

round_robin:
	llist_for_each_entry(msc, &bsc->mscs, entry) {
		if (is_emerg && !msc->allow_emerg)
			continue;

		/* force round robin by moving it to the end */
		llist_move_tail(&msc->entry, &bsc->mscs);
		return msc;
	}

	return NULL;

paging:
	subscr = extract_sub(conn, msg);

	if (!subscr) {
		LOGP(DMSC, LOGL_INFO, "Got paging response but no subscriber found, will now (blindly) deliver the paging response to the first configured MSC!\n");
		goto blind;
	}

	pag_msc = paging_get_msc(conn_get_bts(conn), subscr);
	bsc_subscr_put(subscr);

	llist_for_each_entry(msc, &bsc->mscs, entry) {
		if (msc != pag_msc)
			continue;

		/*
		 * We don't check if the MSC is connected. In case it
		 * is not the connection will be dropped.
		 */

		/* force round robin by moving it to the end */
		llist_move_tail(&msc->entry, &bsc->mscs);
		return msc;
	}

	LOGP(DMSC, LOGL_INFO, "Got paging response but no request found, will now (blindly) deliver the paging response to the first configured MSC!\n");

blind:
	/* In the case of an MT CSFB call we will get a paging response from
	 * the BTS without a preceding paging request via A-Interface. In those
	 * cases the MSC will page the subscriber via SGs interface, so the BSC
	 * can not know about the paging in advance. In those cases we can not
	 * know the MSC which is in charge. The only meaningful option we have
	 * is to deliver the paging response to the first configured MSC
	 * blindly. */
	msc = llist_first_entry_or_null(&bsc->mscs, struct bsc_msc_data, entry);
	if (msc)
		return msc;
	LOGP(DMSC, LOGL_ERROR, "Unable to find any suitable MSC to deliver paging response!\n");
	return NULL;
}

static int handle_page_resp(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	struct bsc_subscr *subscr = extract_sub(conn, msg);

	if (!subscr) {
		LOGP(DMSC, LOGL_ERROR, "Non active subscriber got paged.\n");
		rate_ctr_inc(&conn->lchan->ts->trx->bts->bts_ctrs->ctr[BTS_CTR_PAGING_NO_ACTIVE_PAGING]);
		rate_ctr_inc(&conn->network->bsc_ctrs->ctr[BSC_CTR_PAGING_NO_ACTIVE_PAGING]);
		return -1;
	}

	paging_request_stop(&conn->network->bts_list, conn_get_bts(conn), subscr, conn,
			    msg);
	bsc_subscr_put(subscr);
	return 0;
}

/* TS 04.08 sec 9.2.15 "Location updating request" */
static void handle_lu_request(struct gsm_subscriber_connection *conn,
			      struct msgb *msg)
{
	struct gsm48_hdr *gh;
	struct gsm48_loc_upd_req *lu;
	int8_t rc8;
	struct gsm_bts *bts = conn_get_bts(conn);


	if (msgb_l3len(msg) < sizeof(*gh) + sizeof(*lu)) {
		LOGP(DMSC, LOGL_ERROR, "LU too small to look at: %u\n", msgb_l3len(msg));
		return;
	}

	gh = msgb_l3(msg);
	lu = (struct gsm48_loc_upd_req *) gh->data;

	rc8 = osmo_gsm48_rfpowercap2powerclass(bts->band, lu->classmark1.pwr_lev);
	if (rc8 < 0) {
		LOGP(DMSC, LOGL_NOTICE,
		     "Unable to decode RF power capability %x from classmark1 during LU.\n",
		     lu->classmark1.pwr_lev);
		rc8 = 0;
	}
	conn_update_ms_power_class(conn, rc8);
}


/* TS 04.08 sec 9.2.15 "Location updating request" */
static void handle_cm_serv_req(struct gsm_subscriber_connection *conn,
			      struct msgb *msg)
{
	struct gsm48_hdr *gh;
	struct gsm48_service_request *serv_req;
	struct gsm48_classmark2* cm2;
	int8_t rc8;
	struct gsm_bts *bts = conn_get_bts(conn);

	if (msgb_l3len(msg) < sizeof(*gh) + sizeof(*serv_req)) {
		LOGP(DMSC, LOGL_ERROR, "CM Serv Req too small to look at: %u\n", msgb_l3len(msg));
		return;
	}

	gh = msgb_l3(msg);
	serv_req = (struct gsm48_service_request *) gh->data;

	cm2 = (struct gsm48_classmark2*)(((uint8_t*)&serv_req->classmark)+1);
	/* FIXME: one classmark2 is available in libosmocore:
	cm2 = &serv_req->classmark2; */
	rc8 = osmo_gsm48_rfpowercap2powerclass(bts->band, cm2->pwr_lev);
	if (rc8 < 0) {
		LOGP(DMSC, LOGL_NOTICE,
		     "Unable to decode RF power capability %x from classmark2 during CM Service Req.\n",
		     cm2->pwr_lev);
		rc8 = 0;
	}
	conn_update_ms_power_class(conn, rc8);
}

int bsc_scan_bts_msg(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	uint8_t pdisc = gsm48_hdr_pdisc(gh);
	uint8_t mtype = gsm48_hdr_msg_type(gh);

	if (pdisc == GSM48_PDISC_MM) {
		if (mtype == GSM48_MT_MM_LOC_UPD_REQUEST)
			handle_lu_request(conn, msg);
		else if(mtype == GSM48_MT_MM_CM_SERV_REQ)
			handle_cm_serv_req(conn, msg);
	} else if (pdisc == GSM48_PDISC_RR) {
		if (mtype == GSM48_MT_RR_PAG_RESP)
			handle_page_resp(conn, msg);
	}

	return 0;
}

/*! MS->MSC: New MM context with L3 payload. */
int bsc_compl_l3(struct gsm_subscriber_connection *conn, struct msgb *msg, uint16_t chosen_channel)
{
	struct bsc_msc_data *msc;
	struct msgb *resp;
	struct gsm0808_speech_codec_list scl;
	int rc = -2;

	log_set_context(LOG_CTX_BSC_SUBSCR, conn->bsub);

	LOGP(DMSC, LOGL_INFO, "Tx MSC COMPL L3\n");

	/* find the MSC link we want to use */
	msc = bsc_find_msc(conn, msg);
	if (!msc) {
		LOGP(DMSC, LOGL_ERROR, "Failed to find a MSC for a connection.\n");
		rc = -1;
		goto early_fail;
	}

	/* allocate resource for a new connection */
	if (osmo_bsc_sigtran_new_conn(conn, msc) != BSC_CON_SUCCESS)
		goto early_fail;

	bsc_scan_bts_msg(conn, msg);

	if (gscon_is_aoip(conn)) {
		gen_bss_supported_codec_list(&scl, msc, conn_get_bts(conn));
		if (scl.len > 0)
			resp = gsm0808_create_layer3_2(msg, cgi_for_msc(conn->sccp.msc, conn_get_bts(conn)), &scl);
		else {
			/* Note: 3GPP TS 48.008 3.2.1.32, COMPLETE LAYER 3 INFORMATION clearly states that
			 * Codec List (BSS Supported) shall be included, if the radio access network
			 * supports an IP based user plane interface. It may be intentional that the
			 * current configuration does not support any voice codecs, in those cases the
			 * network does not support an IP based user plane interface, and therefore the
			 * Codec List (BSS Supported) IE can be left out in those situations. */
			resp = gsm0808_create_layer3_2(msg, cgi_for_msc(conn->sccp.msc, conn_get_bts(conn)), NULL);
		}
	} else
		resp = gsm0808_create_layer3_2(msg, cgi_for_msc(conn->sccp.msc, conn_get_bts(conn)), NULL);

	if (resp)
		rc = osmo_fsm_inst_dispatch(conn->fi, GSCON_EV_A_CONN_REQ, resp);
	else
		LOGP(DMSC, LOGL_DEBUG, "Failed to create layer3 message.\n");
early_fail:
	log_set_context(LOG_CTX_BSC_SUBSCR, NULL);
	return rc;
}

/*! MS->BSC/MSC: Um L3 message. */
void bsc_dtap(struct gsm_subscriber_connection *conn, uint8_t link_id, struct msgb *msg)
{
	log_set_context(LOG_CTX_BSC_SUBSCR, conn->bsub);

	if (!msc_connected(conn))
		goto done;

	LOGP(DMSC, LOGL_INFO, "Tx MSC DTAP LINK_ID=0x%02x\n", link_id);

	bsc_scan_bts_msg(conn, msg);

	/* Store link_id in msg->cb */
	OBSC_LINKID_CB(msg) = link_id;
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

	rc8 = osmo_gsm48_rfpowercap2powerclass(bts->band, cm2_parsed->pwr_lev);
	if (rc8 < 0) {
		LOGP(DMSC, LOGL_NOTICE,
		     "Unable to decode RF power capability %x from classmark1 during CM Update.\n",
		     cm2_parsed->pwr_lev);
		rc8 = 0;
	}
	conn_update_ms_power_class(conn, rc8);

	if (!msc_connected(conn))
		return;

	rate_ctr_inc(&conn->sccp.msc->msc_ctrs->ctr[MSC_CTR_BSSMAP_TX_DT1_CLASSMARK_UPDATE]);
	resp = gsm0808_create_classmark_update(cm2, cm2_len, cm3, cm3_len);
	rc = osmo_fsm_inst_dispatch(conn->fi, GSCON_EV_TX_SCCP, resp);
	if (rc != 0)
		msgb_free(resp);
}
