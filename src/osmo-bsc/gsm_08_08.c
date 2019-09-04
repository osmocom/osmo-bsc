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

#include <osmocom/bsc/gsm_04_80.h>
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

static bool complete_layer3(struct gsm_subscriber_connection *conn,
			    struct msgb *msg, struct bsc_msc_data *msc);

static void bsc_maybe_lu_reject(struct gsm_subscriber_connection *conn, int con_type, int cause)
{
	struct msgb *msg;

	/* ignore cm service request or such */
	if (con_type != FLT_CON_TYPE_LU)
		return;

	msg = gsm48_create_loc_upd_rej(cause);
	if (!msg) {
		LOGP(DMM, LOGL_ERROR, "Failed to create msg for LOCATION UPDATING REJECT.\n");
		return;
	}

	msg->lchan = conn->lchan;
	gscon_submit_rsl_dtap(conn, msg, 0, 0);
}

static int bsc_filter_initial(struct osmo_bsc_data *bsc,
				struct bsc_msc_data *msc,
				struct gsm_subscriber_connection *conn,
				struct msgb *msg, char **imsi, int *con_type,
				int *lu_cause)
{
	struct bsc_filter_request req;
	struct bsc_filter_reject_cause cause;
	struct gsm48_hdr *gh = msgb_l3(msg);
	int rc;

	req.ctx = conn;
	req.black_list = NULL;
	req.access_lists = bsc_access_lists();
	req.local_lst_name = msc->acc_lst_name;
	req.global_lst_name = conn_get_bts(conn)->network->bsc_data->acc_lst_name;
	req.bsc_nr = 0;

	rc = bsc_msg_filter_initial(gh, msgb_l3len(msg), &req,
				con_type, imsi, &cause);
	*lu_cause = cause.lu_reject_cause;
	return rc;
}

static int bsc_filter_data(struct gsm_subscriber_connection *conn,
				struct msgb *msg, int *lu_cause)
{
	struct bsc_filter_request req;
	struct gsm48_hdr *gh = msgb_l3(msg);
	struct bsc_filter_reject_cause cause;
	int rc;

	req.ctx = conn;
	req.black_list = NULL;
	req.access_lists = bsc_access_lists();
	req.local_lst_name = conn->sccp.msc->acc_lst_name;
	req.global_lst_name = conn_get_bts(conn)->network->bsc_data->acc_lst_name;
	req.bsc_nr = 0;

	rc = bsc_msg_filter_data(gh, msgb_l3len(msg), &req,
				&conn->filter_state,
				&cause);
	*lu_cause = cause.lu_reject_cause;
	return rc;
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

static void bsc_send_ussd_no_srv(struct gsm_subscriber_connection *conn,
				 struct msgb *msg, const char *text)
{
	struct gsm48_hdr *gh;
	int8_t pdisc;
	uint8_t mtype;
	int drop_message = 1;

	if (!text)
		return;

	if (!msg || msgb_l3len(msg) < sizeof(*gh))
		return;

	gh = msgb_l3(msg);
	pdisc = gsm48_hdr_pdisc(gh);
	mtype = gsm48_hdr_msg_type(gh);

	/* Is CM service request? */
	if (pdisc == GSM48_PDISC_MM && mtype == GSM48_MT_MM_CM_SERV_REQ) {
		struct gsm48_service_request *cm;

		cm = (struct gsm48_service_request *) &gh->data[0];

		/* Is type SMS or call? */
		if (cm->cm_service_type == GSM48_CMSERV_SMS)
			drop_message = 0;
		else if (cm->cm_service_type == GSM48_CMSERV_MO_CALL_PACKET)
			drop_message = 0;
	}

	if (drop_message) {
		LOGP(DMSC, LOGL_DEBUG, "Skipping (not sending) USSD message: '%s'\n", text);
		return;
	}

	LOGP(DMSC, LOGL_INFO, "Sending CM Service Accept\n");
	gsm48_tx_mm_serv_ack(conn);

	LOGP(DMSC, LOGL_INFO, "Sending USSD message: '%s'\n", text);
	bsc_send_ussd_notify(conn, 1, text);
	bsc_send_ussd_release_complete(conn);
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

struct bsc_msc_data *bsc_find_msc(struct gsm_subscriber_connection *conn,
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
		if (!is_emerg && msc->type != MSC_CON_TYPE_NORMAL)
			continue;
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

/*! MS->MSC: New MM context with L3 payload. */
int bsc_compl_l3(struct gsm_subscriber_connection *conn, struct msgb *msg, uint16_t chosen_channel)
{
	struct bsc_msc_data *msc;

	LOGP(DMSC, LOGL_INFO, "Tx MSC COMPL L3\n");

	/* find the MSC link we want to use */
	msc = bsc_find_msc(conn, msg);
	if (!msc) {
		LOGP(DMSC, LOGL_ERROR, "Failed to find a MSC for a connection.\n");
		bsc_send_ussd_no_srv(conn, msg,
				     conn_get_bts(conn)->network->bsc_data->ussd_no_msc_txt);
		return -1;
	}

	return complete_layer3(conn, msg, msc) ? 0 : -2;
}

static int handle_page_resp(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	struct bsc_subscr *subscr = extract_sub(conn, msg);

	if (!subscr) {
		LOGP(DMSC, LOGL_ERROR, "Non active subscriber got paged.\n");
		return -1;
	}

	paging_request_stop(&conn->network->bts_list, conn_get_bts(conn), subscr, conn,
			    msg);
	bsc_subscr_put(subscr);
	return 0;
}

static void handle_lu_request(struct gsm_subscriber_connection *conn,
			      struct msgb *msg)
{
	struct gsm48_hdr *gh;
	struct gsm48_loc_upd_req *lu;
	struct gsm48_loc_area_id lai;

	if (msgb_l3len(msg) < sizeof(*gh) + sizeof(*lu)) {
		LOGP(DMSC, LOGL_ERROR, "LU too small to look at: %u\n", msgb_l3len(msg));
		return;
	}

	gh = msgb_l3(msg);
	lu = (struct gsm48_loc_upd_req *) gh->data;

	gsm48_generate_lai2(&lai, bts_lai(conn_get_bts(conn)));

	if (memcmp(&lai, &lu->lai, sizeof(lai)) != 0) {
		LOGP(DMSC, LOGL_DEBUG, "Marking con for welcome USSD.\n");
		conn->new_subscriber = 1;
	}
}

int bsc_scan_bts_msg(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	uint8_t pdisc = gsm48_hdr_pdisc(gh);
	uint8_t mtype = gsm48_hdr_msg_type(gh);

	if (pdisc == GSM48_PDISC_MM) {
		if (mtype == GSM48_MT_MM_LOC_UPD_REQUEST)
			handle_lu_request(conn, msg);
	} else if (pdisc == GSM48_PDISC_RR) {
		if (mtype == GSM48_MT_RR_PAG_RESP)
			handle_page_resp(conn, msg);
	}

	return 0;
}

static bool complete_layer3(struct gsm_subscriber_connection *conn,
			    struct msgb *msg, struct bsc_msc_data *msc)
{
	int con_type, rc, lu_cause;
	char *imsi = NULL;
	struct msgb *resp;
	enum bsc_con ret;
	struct gsm0808_speech_codec_list scl;

	log_set_context(LOG_CTX_BSC_SUBSCR, conn->bsub);

	/* Check the filter */
	rc = bsc_filter_initial(msc->network->bsc_data, msc, conn, msg,
				&imsi, &con_type, &lu_cause);
	if (rc < 0) {
		bsc_maybe_lu_reject(conn, con_type, lu_cause);
		goto early_fail;
	}

	/* allocate resource for a new connection */
	ret = osmo_bsc_sigtran_new_conn(conn, msc);

	if (ret != BSC_CON_SUCCESS) {
		/* allocation has failed */
		if (ret == BSC_CON_REJECT_NO_LINK)
			bsc_send_ussd_no_srv(conn, msg, msc->ussd_msc_lost_txt);
		else if (ret == BSC_CON_REJECT_RF_GRACE)
			bsc_send_ussd_no_srv(conn, msg, msc->ussd_grace_txt);
		goto early_fail;
	}

	/* TODO: also extract TMSI. We get an IMSI only when an initial L3 Complete comes in that
	 * contains an IMSI. We filter by IMSI. A TMSI identity is never returned here, see e.g.
	 * _cr_check_loc_upd() and other similar functions called from bsc_msg_filter_initial(). */
	if (imsi) {
		conn->filter_state.imsi = talloc_steal(conn, imsi);
		if (conn->bsub) {
			log_set_context(LOG_CTX_BSC_SUBSCR, conn->bsub);
			/* Already a subscriber on L3 Complete? Should never happen... */
			if (conn->bsub->imsi[0]
			    && strcmp(conn->bsub->imsi, imsi))
				LOGP(DMSC, LOGL_ERROR, "Subscriber's IMSI changes from %s to %s\n",
				     conn->bsub->imsi, imsi);
			bsc_subscr_set_imsi(conn->bsub, imsi);
		} else {
			conn->bsub = bsc_subscr_find_or_create_by_imsi(msc->network->bsc_subscribers,
								       imsi);
			log_set_context(LOG_CTX_BSC_SUBSCR, conn->bsub);
		}
		gscon_update_id(conn);
	}
	conn->filter_state.con_type = con_type;

	/* check return value, if failed check msg for and send USSD */

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
		osmo_fsm_inst_dispatch(conn->fi, GSCON_EV_A_CONN_REQ, resp);
	else
		LOGP(DMSC, LOGL_DEBUG, "Failed to create layer3 message.\n");

	log_set_context(LOG_CTX_BSC_SUBSCR, NULL);
	return !!resp;
early_fail:
	log_set_context(LOG_CTX_BSC_SUBSCR, NULL);
	return false;
}

static int bsc_clear_request(struct gsm_subscriber_connection *conn, uint32_t cause);

/*
 * Plastic surgery... we want to give up the current connection
 */
static int move_to_msc(struct gsm_subscriber_connection *_conn,
		       struct msgb *msg, struct bsc_msc_data *msc)
{
	/*
	 * 1. Give up the old connection.
	 * This happens by sending a clear request to the MSC,
	 * it should end with the MSC releasing the connection.
	 */
	bsc_clear_request(_conn, 0);

	/*
	 * 2. Attempt to create a new connection to the local
	 * MSC. If it fails the caller will need to handle this
	 * properly.
	 */
	if (!complete_layer3(_conn, msg, msc)) {
		/* FIXME: I have not the slightest idea what move_to_msc() intends to do; during lchan
		 * FSM introduction, I changed this and hope it is the appropriate action. I actually
		 * assume this is unused legacy code for osmo-bsc_nat?? */
		gscon_release_lchans(_conn, false);
		return 1;
	}

	return 2;
}

static int handle_cc_setup(struct gsm_subscriber_connection *conn,
			   struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	uint8_t pdisc = gsm48_hdr_pdisc(gh);
	uint8_t mtype = gsm48_hdr_msg_type(gh);

	struct bsc_msc_data *msc;
	struct gsm_mncc_number called;
	struct tlv_parsed tp;
	unsigned payload_len;

	char _dest_nr[35];

	/*
	 * Do we have a setup message here? if not return fast.
	 */
	if (pdisc != GSM48_PDISC_CC || mtype != GSM48_MT_CC_SETUP)
		return 0;

	payload_len = msgb_l3len(msg) - sizeof(*gh);

	tlv_parse(&tp, &gsm48_att_tlvdef, gh->data, payload_len, 0, 0);
	if (!TLVP_PRESENT(&tp, GSM48_IE_CALLED_BCD)) {
		LOGP(DMSC, LOGL_ERROR, "Called BCD not present in setup.\n");
		return -1;
	}

	memset(&called, 0, sizeof(called));
	gsm48_decode_called(&called,
			    TLVP_VAL(&tp, GSM48_IE_CALLED_BCD) - 1);

	if (called.plan != 1 && called.plan != 0)
		return 0;

	if (called.plan == 1 && called.type == 1) {
		_dest_nr[0] = _dest_nr[1] = '0';
		memcpy(_dest_nr + 2, called.number, sizeof(called.number));
	} else
		memcpy(_dest_nr, called.number, sizeof(called.number));

	/*
	 * Check if the connection should be moved...
	 */
	llist_for_each_entry(msc, &conn_get_bts(conn)->network->bsc_data->mscs, entry) {
		if (msc->type != MSC_CON_TYPE_LOCAL)
			continue;
		if (!msc->local_pref)
			continue;
		if (regexec(&msc->local_pref_reg, _dest_nr, 0, NULL, 0) != 0)
			continue;

		return move_to_msc(conn, msg, msc);
	}

	return 0;
}


/*! MS->BSC/MSC: Um L3 message. */
void bsc_dtap(struct gsm_subscriber_connection *conn, uint8_t link_id, struct msgb *msg)
{
	int lu_cause;

	log_set_context(LOG_CTX_BSC_SUBSCR, conn->bsub);

	if (!msc_connected(conn))
		goto done;

	LOGP(DMSC, LOGL_INFO, "Tx MSC DTAP LINK_ID=0x%02x\n", link_id);

	/*
	 * We might want to move this connection to a new MSC. Ask someone
	 * to handle it. If it was handled we will return.
	 */
	if (handle_cc_setup(conn, msg) >= 1)
		goto done;

	/* Check the filter */
	if (bsc_filter_data(conn, msg, &lu_cause) < 0) {
		bsc_maybe_lu_reject(conn,
					conn->filter_state.con_type,
					lu_cause);
		bsc_clear_request(conn, 0);
		goto done;
	}

	bsc_scan_bts_msg(conn, msg);

	/* Store link_id in msg->cb */
	OBSC_LINKID_CB(msg) = link_id;
	osmo_fsm_inst_dispatch(conn->fi, GSCON_EV_MO_DTAP, msg);
done:
	log_set_context(LOG_CTX_BSC_SUBSCR, NULL);
	return;
}

/*! BSSMAP Clear Request for legacy code paths, instead see gscon_bssmap_clear(). */
static int bsc_clear_request(struct gsm_subscriber_connection *conn, uint32_t cause)
{
	int rc;
	struct msgb *resp;

	if (!msc_connected(conn))
		return 1;

	LOGP(DMSC, LOGL_INFO, "Tx MSC CLEAR REQUEST\n");

	resp = gsm0808_create_clear_rqst(GSM0808_CAUSE_RADIO_INTERFACE_FAILURE);
	if (!resp) {
		LOGP(DMSC, LOGL_ERROR, "Failed to allocate response.\n");
		return 1;
	}

	rc = osmo_fsm_inst_dispatch(conn->fi, GSCON_EV_TX_SCCP, resp);
	if (rc != 0)
		msgb_free(resp);

	return 1;
}

/*! BSC->MSC: Classmark Update. */
void bsc_cm_update(struct gsm_subscriber_connection *conn,
		   const uint8_t *cm2, uint8_t cm2_len,
		   const uint8_t *cm3, uint8_t cm3_len)
{
	int rc;
	struct msgb *resp;

	if (!msc_connected(conn))
		return;

	resp = gsm0808_create_classmark_update(cm2, cm2_len, cm3, cm3_len);
	rc = osmo_fsm_inst_dispatch(conn->fi, GSCON_EV_TX_SCCP, resp);
	if (rc != 0)
		msgb_free(resp);
}
