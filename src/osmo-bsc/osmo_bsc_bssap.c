/* GSM 08.08 BSSMAP handling						*/
/* (C) 2009-2012 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009-2012 by On-Waves
 * (C) 2017 by Harald Welte <laforge@gnumonks.org>
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

#include <osmocom/mgcp_client/mgcp_client_fsm.h>

#include <osmocom/bsc/osmo_bsc.h>
#include <osmocom/bsc/osmo_bsc_grace.h>
#include <osmocom/bsc/osmo_bsc_rf.h>
#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/bsc_subscriber.h>
#include <osmocom/bsc/paging.h>
#include <osmocom/bsc/gsm_04_08_rr.h>
#include <osmocom/bsc/gsm_04_80.h>
#include <osmocom/bsc/bsc_subscr_conn_fsm.h>
#include <osmocom/bsc/codec_pref.h>
#include <osmocom/bsc/abis_rsl.h>
#include <osmocom/bsc/handover_fsm.h>

#include <osmocom/gsm/protocol/gsm_08_08.h>
#include <osmocom/gsm/gsm0808.h>
#include <osmocom/bsc/osmo_bsc_sigtran.h>
#include <osmocom/bsc/osmo_bsc_lcls.h>
#include <osmocom/bsc/a_reset.h>
#include <osmocom/bsc/handover.h>
#include <osmocom/core/fsm.h>
#include <osmocom/core/socket.h>

#define IP_V4_ADDR_LEN 4

/*
 * helpers for the assignment command
 */


static int bssmap_handle_reset_ack(struct bsc_msc_data *msc,
				   struct msgb *msg, unsigned int length)
{
	LOGP(DMSC, LOGL_NOTICE, "RESET ACK from MSC: %s\n",
	     osmo_sccp_addr_name(osmo_ss7_instance_find(msc->a.cs7_instance),
				 &msc->a.msc_addr));

	/* Inform the FSM that controls the RESET/RESET-ACK procedure
	 * that we have successfully received the reset-ack message */
	a_reset_ack_confirm(msc->a.reset_fsm);

	return 0;
}

/* Handle MSC sided reset */
static int bssmap_handle_reset(struct bsc_msc_data *msc,
			       struct msgb *msg, unsigned int length)
{
	LOGP(DMSC, LOGL_NOTICE, "RESET from MSC: %s\n",
	     osmo_sccp_addr_name(osmo_ss7_instance_find(msc->a.cs7_instance),
				 &msc->a.msc_addr));

	/* Instruct the bsc to close all open sigtran connections and to
	 * close all active channels on the BTS side as well */
	osmo_bsc_sigtran_reset(msc);

	/* Drop all ongoing paging requests that this MSC has created on any BTS */
	paging_flush_network(msc->network, msc);

	/* Inform the MSC that we have received the reset request and
	 * that we acted accordingly */
	osmo_bsc_sigtran_tx_reset_ack(msc);

	return 0;
}

/* Page a subscriber based on TMSI and LAC via the specified BTS.
 * The msc parameter is the MSC which issued the corresponding paging request.
 * Log an error if paging failed. */
static void
page_subscriber(struct bsc_msc_data *msc, struct gsm_bts *bts,
    uint32_t tmsi, uint32_t lac, const char *mi_string, uint8_t chan_needed)
{
	struct bsc_subscr *subscr;
	int ret;

	LOGP(DMSC, LOGL_INFO, "Paging request from MSC BTS: %d IMSI: '%s' TMSI: '0x%x/%u' LAC: 0x%x\n",
	    bts->nr, mi_string, tmsi, tmsi, lac);

	subscr = bsc_subscr_find_or_create_by_imsi(msc->network->bsc_subscribers,
						   mi_string);
	if (!subscr) {
		LOGP(DMSC, LOGL_ERROR, "Paging request failed: Could not allocate subscriber for %s\n", mi_string);
		return;
	}

	subscr->lac = lac;
	subscr->tmsi = tmsi;

	ret = bsc_grace_paging_request(msc->network->bsc_data->rf_ctrl->policy, subscr, chan_needed, msc, bts);
	if (ret == 0)
		LOGP(DMSC, LOGL_ERROR, "Paging request failed: BTS: %d IMSI: '%s' TMSI: '0x%x/%u' LAC: 0x%x\n",
		     bts->nr, mi_string, tmsi, tmsi, lac);

	/* the paging code has grabbed its own references */
	bsc_subscr_put(subscr);
}

static void
page_all_bts(struct bsc_msc_data *msc, uint32_t tmsi, const char *mi_string, uint8_t chan_needed)
{
	struct gsm_bts *bts;
	llist_for_each_entry(bts, &msc->network->bts_list, list)
		page_subscriber(msc, bts, tmsi, GSM_LAC_RESERVED_ALL_BTS, mi_string, chan_needed);
}

static void
page_cgi(struct bsc_msc_data *msc, struct gsm0808_cell_id_list2 *cil,
	 uint32_t tmsi, const char *mi_string, uint8_t chan_needed)
{
	int i;
	for (i = 0; i < cil->id_list_len; i++) {
		struct osmo_cell_global_id *id = &cil->id_list[i].global;
		if (!osmo_plmn_cmp(&id->lai.plmn, &msc->network->plmn)) {
			int paged = 0;
			struct gsm_bts *bts;
			llist_for_each_entry(bts, &msc->network->bts_list, list) {
				if (bts->location_area_code != id->lai.lac)
					continue;
				if (bts->cell_identity != id->cell_identity)
					continue;
				page_subscriber(msc, bts, tmsi, id->lai.lac, mi_string, chan_needed);
				paged = 1;
			}
			if (!paged) {
				LOGP(DMSC, LOGL_NOTICE, "Paging IMSI %s: BTS with LAC %d and CI %d not found\n",
				     mi_string, id->lai.lac, id->cell_identity);
			}
		} else {
			LOGP(DMSC, LOGL_DEBUG, "Paging IMSI %s: MCC-MNC in Cell Identifier List "
			     "(%s) do not match our network (%s)\n",
			     mi_string, osmo_plmn_name(&id->lai.plmn),
			     osmo_plmn_name2(&msc->network->plmn));
		}
	}
}

static void
page_lac_and_ci(struct bsc_msc_data *msc, struct gsm0808_cell_id_list2 *cil,
	 uint32_t tmsi, const char *mi_string, uint8_t chan_needed)
{
	int i;

	for (i = 0; i < cil->id_list_len; i++) {
		struct osmo_lac_and_ci_id *id = &cil->id_list[i].lac_and_ci;
		int paged = 0;
		struct gsm_bts *bts;
		llist_for_each_entry(bts, &msc->network->bts_list, list) {
			if (bts->location_area_code != id->lac)
				continue;
			if (bts->cell_identity != id->ci)
				continue;
			page_subscriber(msc, bts, tmsi, id->lac, mi_string, chan_needed);
			paged = 1;
		}
		if (!paged) {
			LOGP(DMSC, LOGL_NOTICE, "Paging IMSI %s: BTS with LAC %d and CI %d not found\n",
			     mi_string, id->lac, id->ci);
		}
	}
}

static void
page_ci(struct bsc_msc_data *msc, struct gsm0808_cell_id_list2 *cil,
	 uint32_t tmsi, const char *mi_string, uint8_t chan_needed)
{
	int i;

	for (i = 0; i < cil->id_list_len; i++) {
		uint16_t ci = cil->id_list[i].ci;
		int paged = 0;
		struct gsm_bts *bts;
		llist_for_each_entry(bts, &msc->network->bts_list, list) {
			if (bts->cell_identity != ci)
				continue;
			page_subscriber(msc, bts, tmsi, GSM_LAC_RESERVED_ALL_BTS, mi_string, chan_needed);
			paged = 1;
		}
		if (!paged) {
			LOGP(DMSC, LOGL_NOTICE, "Paging IMSI %s: BTS with CI %d not found\n",
			     mi_string, ci);
		}
	}
}

static void
page_lai_and_lac(struct bsc_msc_data *msc, struct gsm0808_cell_id_list2 *cil,
	 uint32_t tmsi, const char *mi_string, uint8_t chan_needed)
{
	int i;

	for (i = 0; i < cil->id_list_len; i++) {
		struct osmo_location_area_id *id = &cil->id_list[i].lai_and_lac;
		if (!osmo_plmn_cmp(&id->plmn, &msc->network->plmn)) {
			int paged = 0;
			struct gsm_bts *bts;
			llist_for_each_entry(bts, &msc->network->bts_list, list) {
				if (bts->location_area_code != id->lac)
					continue;
				page_subscriber(msc, bts, tmsi, id->lac, mi_string, chan_needed);
				paged = 1;
			}
			if (!paged) {
				LOGP(DMSC, LOGL_NOTICE, "Paging IMSI %s: BTS with LAC %d not found\n",
				     mi_string, id->lac);
			}
		} else {
			LOGP(DMSC, LOGL_DEBUG, "Paging IMSI %s: MCC-MNC in Cell Identifier List "
			     "(%s) do not match our network (%s)\n",
			     mi_string, osmo_plmn_name(&id->plmn),
			     osmo_plmn_name2(&msc->network->plmn));
		}
	}
}

static void
page_lac(struct bsc_msc_data *msc, struct gsm0808_cell_id_list2 *cil,
	 uint32_t tmsi, const char *mi_string, uint8_t chan_needed)
{
	int i;

	for (i = 0; i < cil->id_list_len; i++) {
		uint16_t lac = cil->id_list[i].lac;
		int paged = 0;
		struct gsm_bts *bts;
		llist_for_each_entry(bts, &msc->network->bts_list, list) {
			if (bts->location_area_code != lac)
				continue;
			page_subscriber(msc, bts, tmsi, lac, mi_string, chan_needed);
			paged = 1;
		}
		if (!paged) {
			LOGP(DMSC, LOGL_NOTICE, "Paging IMSI %s: BTS with LAC %d not found\n",
			     mi_string, lac);
		}
	}
}

/* GSM 08.08 § 3.2.1.19 */
static int bssmap_handle_paging(struct bsc_msc_data *msc,
				struct msgb *msg, unsigned int payload_length)
{
	struct tlv_parsed tp;
	char mi_string[GSM48_MI_SIZE];
	uint32_t tmsi = GSM_RESERVED_TMSI;
	uint8_t data_length;
	int remain;
	const uint8_t *data;
	uint8_t chan_needed = RSL_CHANNEED_ANY;
	struct gsm0808_cell_id_list2 cil;

	tlv_parse(&tp, gsm0808_att_tlvdef(), msg->l4h + 1, payload_length - 1, 0, 0);
	remain = payload_length - 1;

	if (!TLVP_PRESENT(&tp, GSM0808_IE_IMSI)) {
		LOGP(DMSC, LOGL_ERROR, "Mandatory IMSI not present.\n");
		return -1;
	} else if ((TLVP_VAL(&tp, GSM0808_IE_IMSI)[0] & GSM_MI_TYPE_MASK) != GSM_MI_TYPE_IMSI) {
		LOGP(DMSC, LOGL_ERROR, "Wrong content in the IMSI\n");
		return -1;
	}
	remain -= TLVP_LEN(&tp, GSM0808_IE_IMSI);

	if (!TLVP_PRESENT(&tp, GSM0808_IE_CELL_IDENTIFIER_LIST)) {
		LOGP(DMSC, LOGL_ERROR, "Mandatory CELL IDENTIFIER LIST not present.\n");
		return -1;
	}

	if (TLVP_PRESENT(&tp, GSM0808_IE_TMSI) &&
	    TLVP_LEN(&tp, GSM0808_IE_TMSI) == 4) {
		tmsi = ntohl(tlvp_val32_unal(&tp, GSM0808_IE_TMSI));
		remain -= TLVP_LEN(&tp, GSM0808_IE_TMSI);
	}

	if (remain <= 0) {
		LOGP(DMSC, LOGL_ERROR, "Payload too short.\n");
		return -1;
	}

	/*
	 * parse the IMSI
	 */
	gsm48_mi_to_string(mi_string, sizeof(mi_string),
			   TLVP_VAL(&tp, GSM0808_IE_IMSI), TLVP_LEN(&tp, GSM0808_IE_IMSI));

	/*
	 * There are various cell identifier list types defined at 3GPP TS § 08.08, we don't support all
	 * of them yet. To not disrupt paging operation just because we're lacking some implementation,
	 * interpret any unknown cell identifier type as "page the entire BSS".
	 */
	data_length = TLVP_LEN(&tp, GSM0808_IE_CELL_IDENTIFIER_LIST);
	data = TLVP_VAL(&tp, GSM0808_IE_CELL_IDENTIFIER_LIST);
	if (gsm0808_dec_cell_id_list2(&cil, data, data_length) < 0) {
		LOGP(DMSC, LOGL_ERROR, "Paging IMSI %s: Could not parse Cell Identifier List\n",
		     mi_string);
		return -1;
	}
	remain = 0;

	if (TLVP_PRESENT(&tp, GSM0808_IE_CHANNEL_NEEDED) && TLVP_LEN(&tp, GSM0808_IE_CHANNEL_NEEDED) == 1)
		chan_needed = TLVP_VAL(&tp, GSM0808_IE_CHANNEL_NEEDED)[0] & 0x03;

	if (TLVP_PRESENT(&tp, GSM0808_IE_EMLPP_PRIORITY)) {
		LOGP(DMSC, LOGL_ERROR, "eMLPP is not handled\n");
	}

	rate_ctr_inc(&msc->network->bsc_ctrs->ctr[BSC_CTR_PAGING_ATTEMPTED]);

	switch (cil.id_discr) {
	case CELL_IDENT_NO_CELL:
		page_all_bts(msc, tmsi, mi_string, chan_needed);
		break;

	case CELL_IDENT_WHOLE_GLOBAL:
		page_cgi(msc, &cil, tmsi, mi_string, chan_needed);
		break;

	case CELL_IDENT_LAC_AND_CI:
		page_lac_and_ci(msc, &cil, tmsi, mi_string, chan_needed);
		break;

	case CELL_IDENT_CI:
		page_ci(msc, &cil, tmsi, mi_string, chan_needed);
		break;

	case CELL_IDENT_LAI_AND_LAC:
		page_lai_and_lac(msc, &cil, tmsi, mi_string, chan_needed);
		break;

	case CELL_IDENT_LAC:
		page_lac(msc, &cil, tmsi, mi_string, chan_needed);
		break;

	case CELL_IDENT_BSS:
		if (data_length != 1) {
			LOGP(DMSC, LOGL_ERROR, "Paging IMSI %s: Cell Identifier List for BSS (0x%x)"
			     " has invalid length: %u, paging entire BSS anyway (%s)\n",
			     mi_string, CELL_IDENT_BSS, data_length, osmo_hexdump(data, data_length));
		}
		page_all_bts(msc, tmsi, mi_string, chan_needed);
		break;

	default:
		LOGP(DMSC, LOGL_NOTICE, "Paging IMSI %s: unimplemented Cell Identifier List (0x%x),"
		     " paging entire BSS instead (%s)\n",
		     mi_string, cil.id_discr, osmo_hexdump(data, data_length));
		page_all_bts(msc, tmsi, mi_string, chan_needed);
		break;
	}

	return 0;
}

/* select the best cipher permitted by the intersection of both masks */
static int select_best_cipher(uint8_t msc_mask, uint8_t bsc_mask)
{
	uint8_t intersection = msc_mask & bsc_mask;
	int i;

	for (i = 7; i >= 0; i--) {
		if (intersection & (1 << i))
			return i;
	}
	return -1;
}

/*
 * GSM 08.08 § 3.4.7 cipher mode handling. We will have to pick
 * the cipher to be used for this. In case we are already using
 * a cipher we will have to send cipher mode reject to the MSC,
 * otherwise we will have to pick something that we and the MS
 * is supporting. Currently we are doing it in a rather static
 * way by picking one encryption or no encryption.
 */
static int bssmap_handle_cipher_mode(struct gsm_subscriber_connection *conn,
				     struct msgb *msg, unsigned int payload_length)
{
	uint16_t len;
	struct gsm_network *network = NULL;
	const uint8_t *data;
	struct tlv_parsed tp;
	struct msgb *resp;
	int reject_cause = -1;
	int include_imeisv = 1;
	const uint8_t *enc_key;
	uint16_t enc_key_len;
	uint8_t enc_bits_msc;
	int chosen_cipher;

	if (!conn) {
		LOGP(DMSC, LOGL_ERROR, "No lchan/msc_data in cipher mode command.\n");
		goto reject;
	}

	if (conn->ciphering_handled) {
		LOGP(DMSC, LOGL_ERROR, "Already seen ciphering command. Protocol Error.\n");
		goto reject;
	}

	conn->ciphering_handled = 1;

	tlv_parse(&tp, gsm0808_att_tlvdef(), msg->l4h + 1, payload_length - 1, 0, 0);
	if (!TLVP_PRESENT(&tp, GSM0808_IE_ENCRYPTION_INFORMATION)) {
		LOGP(DMSC, LOGL_ERROR, "IE Encryption Information missing.\n");
		goto reject;
	}

	/*
	 * check if our global setting is allowed
	 *  - Currently we check for A5/0 and A5/1
	 *  - Copy the key if that is necessary
	 *  - Otherwise reject
	 */
	len = TLVP_LEN(&tp, GSM0808_IE_ENCRYPTION_INFORMATION);
	if (len < 1) {
		LOGP(DMSC, LOGL_ERROR, "IE Encryption Information is too short.\n");
		goto reject;
	}

	network = conn_get_bts(conn)->network;
	data = TLVP_VAL(&tp, GSM0808_IE_ENCRYPTION_INFORMATION);
	enc_bits_msc = data[0];
	enc_key = &data[1];
	enc_key_len = len - 1;

	if (TLVP_PRESENT(&tp, GSM0808_IE_CIPHER_RESPONSE_MODE))
		include_imeisv = TLVP_VAL(&tp, GSM0808_IE_CIPHER_RESPONSE_MODE)[0] & 0x1;

	/* Identical to the GSM0808_IE_ENCRYPTION_INFORMATION above:
	 * a5_encryption == 0 --> 0x01
	 * a5_encryption == 1 --> 0x02
	 * a5_encryption == 2 --> 0x04 ... */
	enc_bits_msc = data[0];

	/* The bit-mask of permitted ciphers from the MSC (sent in ASSIGNMENT COMMAND) is intersected
	 * with the vty-configured mask a the BSC.  Finally, the best (highest) possible cipher is
	 * chosen. */
	chosen_cipher = select_best_cipher(enc_bits_msc, network->a5_encryption_mask);
	if (chosen_cipher < 0) {
		LOGP(DMSC, LOGL_ERROR, "Reject: no overlapping A5 ciphers between BSC (0x%02x) "
			"and MSC (0x%02x)\n", network->a5_encryption_mask, enc_bits_msc);
		reject_cause = GSM0808_CAUSE_CIPHERING_ALGORITHM_NOT_SUPPORTED;
		goto reject;
	}

	/* To complete the confusion, gsm0808_cipher_mode again expects the encryption as a number
	 * from 0 to 7. */
	if (gsm0808_cipher_mode(conn, chosen_cipher, enc_key, enc_key_len,
				include_imeisv)) {
		reject_cause = GSM0808_CAUSE_PROTOCOL_ERROR_BETWEEN_BSS_AND_MSC;
		goto reject;
	}
	return 0;

reject:
	resp = gsm0808_create_cipher_reject(reject_cause);
	if (!resp) {
		LOGP(DMSC, LOGL_ERROR, "Sending the cipher reject failed.\n");
		return -1;
	}

	osmo_fsm_inst_dispatch(conn->fi, GSCON_EV_TX_SCCP, resp);
	return -1;
}

/* handle LCLS specific IES in BSSMAP ASS REQ */
static void bssmap_handle_ass_req_lcls(struct gsm_subscriber_connection *conn,
					const struct tlv_parsed *tp)
{
	const struct tlv_p_entry *tlv;
	const uint8_t *config, *control;

	tlv = TLVP_GET(tp, GSM0808_IE_GLOBAL_CALL_REF);
	if (tlv) {
		if (tlv->len > sizeof(conn->lcls.global_call_ref))
			LOGPFSML(conn->fi, LOGL_ERROR, "Global Call Ref IE of %u bytes is too long\n",
				tlv->len);
		else {
			LOGPFSM(conn->fi, "Setting GCR to %s\n", osmo_hexdump_nospc(tlv->val, tlv->len));
			memcpy(&conn->lcls.global_call_ref, tlv->val, tlv->len);
			conn->lcls.global_call_ref_len = tlv->len;
		}
	}

	config = TLVP_VAL_MINLEN(tp, GSM0808_IE_LCLS_CONFIG, 1);
	control = TLVP_VAL_MINLEN(tp, GSM0808_IE_LCLS_CONN_STATUS_CTRL, 1);

	if (config || control) {
		LOGPFSM(conn->fi, "BSSMAP ASS REQ contains LCLS (%s / %s)\n",
			config ? gsm0808_lcls_config_name(*config) : "NULL",
			control ? gsm0808_lcls_control_name(*control) : "NULL");
	}

	/* Update the LCLS state with Config + CSC (if any) */
	lcls_update_config(conn, config, control);

	/* Do not attempt to perform correlation yet, as during processing of the ASS REQ
	 * we don't have the MGCP/MGW connections yet, and hence couldn't enable LS. */
}

/* TS 48.008 3.2.1.91 */
static int bssmap_handle_lcls_connect_ctrl(struct gsm_subscriber_connection *conn,
					   struct msgb *msg, unsigned int length)
{
	struct msgb *resp;
	struct tlv_parsed tp;
	const uint8_t *config, *control;
	int rc;

	OSMO_ASSERT(conn);

	rc = tlv_parse(&tp, gsm0808_att_tlvdef(), msg->l4h + 1, length - 1, 0, 0);
	if (rc < 0) {
		LOGPFSML(conn->fi, LOGL_ERROR, "Error parsing TLVs of LCLS CONNT CTRL: %s\n",
			 msgb_hexdump(msg));
		return rc;
	}
	config = TLVP_VAL_MINLEN(&tp, GSM0808_IE_LCLS_CONFIG, 1);
	control = TLVP_VAL_MINLEN(&tp, GSM0808_IE_LCLS_CONN_STATUS_CTRL, 1);

	LOGPFSM(conn->fi, "Rx LCLS CONNECT CTRL (%s / %s)\n",
		config ? gsm0808_lcls_config_name(*config) : "NULL",
		control ? gsm0808_lcls_control_name(*control) : "NULL");

	if (conn->lcls.global_call_ref_len == 0) {
		LOGPFSML(conn->fi, LOGL_ERROR, "Ignoring LCLS as no GCR was set before\n");
		return 0;
	}
	/* Update the LCLS state with Config + CSC (if any) */
	lcls_update_config(conn, TLVP_VAL_MINLEN(&tp, GSM0808_IE_LCLS_CONFIG, 1),
				TLVP_VAL_MINLEN(&tp, GSM0808_IE_LCLS_CONN_STATUS_CTRL, 1));
	lcls_apply_config(conn);

	LOGPFSM(conn->fi, "Tx LCLS CONNECT CTRL ACK (%s)\n",
		gsm0808_lcls_status_name(lcls_get_status(conn)));
	resp = gsm0808_create_lcls_conn_ctrl_ack(lcls_get_status(conn));
	osmo_fsm_inst_dispatch(conn->fi, GSCON_EV_TX_SCCP, resp);

	return 0;
}

/*
 * Handle the assignment request message.
 *
 * See §3.2.1.1 for the message type
 */
static int bssmap_handle_assignm_req(struct gsm_subscriber_connection *conn,
				     struct msgb *msg, unsigned int length)
{
	struct msgb *resp;
	struct bsc_msc_data *msc;
	struct tlv_parsed tp;
	uint16_t cic = 0;
	enum gsm48_chan_mode chan_mode = GSM48_CMODE_SIGN;
	bool full_rate = false;
	bool aoip = false;
	struct sockaddr_storage rtp_addr;
	struct gsm0808_channel_type ct;
	uint8_t cause;
	int rc;
	struct assignment_request req = {};

	if (!conn) {
		LOGP(DMSC, LOGL_ERROR,
		     "No lchan/msc_data in Assignment Request\n");
		return -1;
	}

	msc = conn->sccp.msc;
	aoip = gscon_is_aoip(conn);

	tlv_parse(&tp, gsm0808_att_tlvdef(), msg->l4h + 1, length - 1, 0, 0);

	/* Check for channel type element, if its missing, immediately reject */
	if (!TLVP_PRESENT(&tp, GSM0808_IE_CHANNEL_TYPE)) {
		LOGP(DMSC, LOGL_ERROR, "Mandatory channel type not present.\n");
		cause = GSM0808_CAUSE_INFORMATION_ELEMENT_OR_FIELD_MISSING;
		goto reject;
	}

	/* Decode Channel Type element */
	rc = gsm0808_dec_channel_type(&ct,  TLVP_VAL(&tp, GSM0808_IE_CHANNEL_TYPE),
				      TLVP_LEN(&tp, GSM0808_IE_CHANNEL_TYPE));
	if (rc < 0) {
		LOGP(DMSC, LOGL_ERROR, "unable to decode channel type.\n");
		cause = GSM0808_CAUSE_INCORRECT_VALUE;
		goto reject;
	}

	bssmap_handle_ass_req_lcls(conn, &tp);

	/* Currently we only support a limited subset of all
	 * possible channel types, such as multi-slot or CSD */
	switch (ct.ch_indctr) {
	case GSM0808_CHAN_DATA:
		LOGP(DMSC, LOGL_ERROR, "Unsupported channel type, currently only speech is supported!\n");
		cause = GSM0808_CAUSE_REQ_CODEC_TYPE_OR_CONFIG_NOT_SUPP;
		goto reject;
	case GSM0808_CHAN_SPEECH:
		if (TLVP_PRESENT(&tp, GSM0808_IE_CIRCUIT_IDENTITY_CODE)) {
			/* CIC is permitted in both AoIP and SCCPlite */
			cic = osmo_load16be(TLVP_VAL(&tp, GSM0808_IE_CIRCUIT_IDENTITY_CODE));
		} else {
			if (!aoip) {
				/* no CIC but SCCPlite: illegal */
				LOGP(DMSC, LOGL_ERROR, "SCCPlite MSC, but no CIC in ASSIGN REQ?\n");
				cause = GSM0808_CAUSE_INFORMATION_ELEMENT_OR_FIELD_MISSING;
				goto reject;
			}
		}
		if (TLVP_PRESENT(&tp, GSM0808_IE_AOIP_TRASP_ADDR)) {
			if (!aoip) {
				/* SCCPlite and AoIP transport address: illegal */
				LOGP(DMSC, LOGL_ERROR, "AoIP Transport address over IPA ?!?\n");
				cause = GSM0808_CAUSE_INCORRECT_VALUE;
				goto reject;
			}
			/* Decode AoIP transport address element */
			rc = gsm0808_dec_aoip_trasp_addr(&rtp_addr,
							 TLVP_VAL(&tp, GSM0808_IE_AOIP_TRASP_ADDR),
							 TLVP_LEN(&tp, GSM0808_IE_AOIP_TRASP_ADDR));
			if (rc < 0) {
				LOGP(DMSC, LOGL_ERROR, "Unable to decode AoIP transport address.\n");
				cause = GSM0808_CAUSE_INCORRECT_VALUE;
				goto reject;
			}
		} else if (aoip) {
			/* no AoIP transport level address but AoIP transport: illegal */
			LOGP(DMSC, LOGL_ERROR, "AoIP transport address missing in ASSIGN REQ, "
			     "audio would not work; rejecting\n");
			cause = GSM0808_CAUSE_INFORMATION_ELEMENT_OR_FIELD_MISSING;
			goto reject;
		}

		/* Decode speech codec list. First set len = 0. */
		conn->codec_list = (struct gsm0808_speech_codec_list){};
		/* Check for speech codec list element */
		if (TLVP_PRESENT(&tp, GSM0808_IE_SPEECH_CODEC_LIST)) {
			/* Decode Speech Codec list */
			rc = gsm0808_dec_speech_codec_list(&conn->codec_list,
							   TLVP_VAL(&tp, GSM0808_IE_SPEECH_CODEC_LIST),
							   TLVP_LEN(&tp, GSM0808_IE_SPEECH_CODEC_LIST));
			if (rc < 0) {
				LOGP(DMSC, LOGL_ERROR, "Unable to decode speech codec list\n");
				cause = GSM0808_CAUSE_INCORRECT_VALUE;
				goto reject;
			}
		}

		if (aoip && !conn->codec_list.len) {
			LOGP(DMSC, LOGL_ERROR, "%s: AoIP speech mode Assignment Request:"
			     " Missing or empty Speech Codec List IE\n", bsc_subscr_name(conn->bsub));
			cause = GSM0808_CAUSE_INFORMATION_ELEMENT_OR_FIELD_MISSING;
			goto reject;
		}

		/* Match codec information from the assignment command against the
		 * local preferences of the BSC and BTS */
		rc = match_codec_pref(&chan_mode, &full_rate, &ct, &conn->codec_list,
				      msc->audio_support, msc->audio_length,
				      &conn_get_bts(conn)->codec);
		if (rc < 0) {
			LOGP(DMSC, LOGL_ERROR, "No supported audio type found for channel_type ="
			     " { ch_indctr=0x%x, ch_rate_type=0x%x, perm_spch=[ %s] }\n",
			     ct.ch_indctr, ct.ch_rate_type, osmo_hexdump(ct.perm_spch, ct.perm_spch_len));
			/* TODO: actually output codec names, e.g. implement
			 * gsm0808_permitted_speech_names[] and iterate perm_spch. */
			cause = GSM0808_CAUSE_REQ_CODEC_TYPE_OR_CONFIG_UNAVAIL;
			goto reject;
		}

		DEBUGP(DMSC, "Found matching audio type: %s %s for channel_type ="
		       " { ch_indctr=0x%x, ch_rate_type=0x%x, perm_spch=[ %s] }\n",
		       full_rate? "full rate" : "half rate",
		       get_value_string(gsm48_chan_mode_names, chan_mode),
		       ct.ch_indctr, ct.ch_rate_type, osmo_hexdump(ct.perm_spch, ct.perm_spch_len));

		req = (struct assignment_request){
			.aoip = aoip,
			.msc_assigned_cic = cic,
			.chan_mode = chan_mode,
			.full_rate = full_rate,
		};
		if (aoip) {
			unsigned int rc = osmo_sockaddr_to_str_and_uint(req.msc_rtp_addr,
									sizeof(req.msc_rtp_addr),
									&req.msc_rtp_port,
									(const struct sockaddr*)&rtp_addr);
			if (!rc || rc >= sizeof(req.msc_rtp_addr)) {
				LOGP(DMSC, LOGL_ERROR, "Assignment request: RTP address is too long\n");
				cause = GSM0808_CAUSE_REQ_CODEC_TYPE_OR_CONFIG_UNAVAIL;
				goto reject;
			}
		}
		break;
	case GSM0808_CHAN_SIGN:
		req = (struct assignment_request){
			.aoip = aoip,
			.chan_mode = chan_mode,
		};
		break;
	default:
		cause = GSM0808_CAUSE_INVALID_MESSAGE_CONTENTS;
		goto reject;
	}

	return osmo_fsm_inst_dispatch(conn->fi, GSCON_EV_ASSIGNMENT_START, &req);

reject:
	resp = gsm0808_create_assignment_failure(cause, NULL);
	OSMO_ASSERT(resp);

	osmo_fsm_inst_dispatch(conn->fi, GSCON_EV_TX_SCCP, resp);
	return -1;
}

/* Handle Handover Command message, part of inter-BSC handover:
 * This BSS sent a Handover Required message.
 * The MSC contacts the remote BSS and receives from it an RR Handover Command; this BSSMAP Handover
 * Command passes the RR Handover Command over to us and it's our job to forward to the MS.
 *
 * See 3GPP TS 48.008 §3.2.1.11
 */
static int bssmap_handle_handover_cmd(struct gsm_subscriber_connection *conn,
				      struct msgb *msg, unsigned int length)
{
	struct tlv_parsed tp;

	if (!conn->ho.fi) {
		LOGPFSML(conn->fi, LOGL_ERROR,
			 "Received Handover Command, but no handover was requested\n");
		/* Should we actually allow the MSC to make us handover without us having requested it
		 * first? Doesn't make any practical sense AFAICT. */
		return -EINVAL;
	}

	tlv_parse(&tp, gsm0808_att_tlvdef(), msg->l4h + 1, length - 1, 0, 0);

	/* Check for channel type element, if its missing, immediately reject */
	if (!TLVP_PRESENT(&tp, GSM0808_IE_LAYER_3_INFORMATION)) {
		LOGPFSML(conn->fi, LOGL_ERROR,
			 "Received Handover Command,"
			 " but mandatory IE not present: Layer 3 Information\n");
		goto reject;
	}

	/* Due to constness, need to declare this after tlv_parse(). */
	struct ho_out_rx_bssmap_ho_command rx = {
		.l3_info = TLVP_VAL(&tp, GSM0808_IE_LAYER_3_INFORMATION),
		.l3_info_len = TLVP_LEN(&tp, GSM0808_IE_LAYER_3_INFORMATION),
	};

	osmo_fsm_inst_dispatch(conn->ho.fi, HO_OUT_EV_BSSMAP_HO_COMMAND, &rx);
	return 0;
reject:
	/* No "Handover Command Reject" message or similar is specified, so we cannot reply in case of
	 * failure. Or is there?? */
	handover_end(conn, HO_RESULT_ERROR);
	return -EINVAL;
}

static int bssmap_rcvmsg_udt(struct bsc_msc_data *msc,
			     struct msgb *msg, unsigned int length)
{
	int ret = 0;

	if (length < 1) {
		LOGP(DMSC, LOGL_ERROR, "Not enough room: %d\n", length);
		return -1;
	}

	LOGP(DMSC, LOGL_INFO, "Rx MSC UDT BSSMAP %s\n",
		gsm0808_bssmap_name(msg->l4h[0]));

	switch (msg->l4h[0]) {
	case BSS_MAP_MSG_RESET_ACKNOWLEDGE:
		ret = bssmap_handle_reset_ack(msc, msg, length);
		break;
	case BSS_MAP_MSG_RESET:
		ret = bssmap_handle_reset(msc, msg, length);
		break;
	case BSS_MAP_MSG_PAGING:
		ret = bssmap_handle_paging(msc, msg, length);
		break;
	default:
		LOGP(DMSC, LOGL_NOTICE, "Received unimplemented BSSMAP UDT %s\n",
			gsm0808_bssmap_name(msg->l4h[0]));
		break;
	}

	return ret;
}

static int bssmap_rcvmsg_dt1(struct gsm_subscriber_connection *conn,
			     struct msgb *msg, unsigned int length)
{
	int ret = 0;

	if (length < 1) {
		LOGP(DMSC, LOGL_ERROR, "Not enough room: %d\n", length);
		return -1;
	}

	LOGP(DMSC, LOGL_INFO, "Rx MSC DT1 BSSMAP %s\n",
		gsm0808_bssmap_name(msg->l4h[0]));

	switch (msg->l4h[0]) {
	case BSS_MAP_MSG_CLEAR_CMD:
		osmo_fsm_inst_dispatch(conn->fi, GSCON_EV_A_CLEAR_CMD, msg);
		break;
	case BSS_MAP_MSG_CIPHER_MODE_CMD:
		ret = bssmap_handle_cipher_mode(conn, msg, length);
		break;
	case BSS_MAP_MSG_ASSIGMENT_RQST:
		ret = bssmap_handle_assignm_req(conn, msg, length);
		break;
	case BSS_MAP_MSG_LCLS_CONNECT_CTRL:
		ret = bssmap_handle_lcls_connect_ctrl(conn, msg, length);
		break;
	case BSS_MAP_MSG_HANDOVER_CMD:
		ret = bssmap_handle_handover_cmd(conn, msg, length);
		break;
	default:
		LOGP(DMSC, LOGL_NOTICE, "Unimplemented msg type: %s\n",
			gsm0808_bssmap_name(msg->l4h[0]));
		break;
	}

	return ret;
}

int bsc_send_welcome_ussd(struct gsm_subscriber_connection *conn)
{
	bsc_send_ussd_notify(conn, 1, conn->sccp.msc->ussd_welcome_txt);
	bsc_send_ussd_release_complete(conn);

	return 0;
}

static int dtap_rcvmsg(struct gsm_subscriber_connection *conn,
		       struct msgb *msg, unsigned int length)
{
	struct dtap_header *header;
	struct msgb *gsm48;
	uint8_t *data;
	int rc, dtap_rc;

	LOGP(DMSC, LOGL_DEBUG, "Rx MSC DTAP: %s\n",
		osmo_hexdump(msg->l3h, length));

	if (!conn) {
		LOGP(DMSC, LOGL_ERROR, "No subscriber connection available\n");
		return -1;
	}

	header = (struct dtap_header *) msg->l3h;
	if (sizeof(*header) >= length) {
		LOGP(DMSC, LOGL_ERROR, "The DTAP header does not fit. Wanted: %zu got: %u\n", sizeof(*header), length);
                LOGP(DMSC, LOGL_ERROR, "hex: %s\n", osmo_hexdump(msg->l3h, length));
                return -1;
	}

	if (header->length > length - sizeof(*header)) {
		LOGP(DMSC, LOGL_ERROR, "The DTAP l4 information does not fit: header: %u length: %u\n", header->length, length);
                LOGP(DMSC, LOGL_ERROR, "hex: %s\n", osmo_hexdump(msg->l3h, length));
		return -1;
	}

	LOGP(DMSC, LOGL_INFO, "Rx MSC DTAP, SAPI: %u CHAN: %u\n", header->link_id & 0x07, header->link_id & 0xC0);

	/* forward the data */
	gsm48 = gsm48_msgb_alloc_name("GSM 04.08 DTAP RCV");
	if (!gsm48) {
		LOGP(DMSC, LOGL_ERROR, "Allocation of the message failed.\n");
		return -1;
	}

	gsm48->l3h = gsm48->data;
	data = msgb_put(gsm48, length - sizeof(*header));
	memcpy(data, msg->l3h + sizeof(*header), length - sizeof(*header));

	/* pass it to the filter for extra actions */
	rc = bsc_scan_msc_msg(conn, gsm48);
	/* Store link_id in msgb->cb */
	OBSC_LINKID_CB(msg) = header->link_id;
	dtap_rc = osmo_fsm_inst_dispatch(conn->fi, GSCON_EV_MT_DTAP, gsm48);
	if (rc == BSS_SEND_USSD)
		bsc_send_welcome_ussd(conn);
	return dtap_rc;
}

int bsc_handle_udt(struct bsc_msc_data *msc,
		   struct msgb *msgb, unsigned int length)
{
	struct bssmap_header *bs;

	LOGP(DMSC, LOGL_DEBUG, "Rx MSC UDT: %s\n",
		osmo_hexdump(msgb->l3h, length));

	if (length < sizeof(*bs)) {
		LOGP(DMSC, LOGL_ERROR, "The header is too short.\n");
		return -1;
	}

	bs = (struct bssmap_header *) msgb->l3h;
	if (bs->length < length - sizeof(*bs))
		return -1;

	switch (bs->type) {
	case BSSAP_MSG_BSS_MANAGEMENT:
		msgb->l4h = &msgb->l3h[sizeof(*bs)];
		bssmap_rcvmsg_udt(msc, msgb, length - sizeof(*bs));
		break;
	default:
		LOGP(DMSC, LOGL_NOTICE, "Unimplemented msg type: %s\n",
			gsm0808_bssmap_name(bs->type));
	}

	return 0;
}

int bsc_handle_dt(struct gsm_subscriber_connection *conn,
		  struct msgb *msg, unsigned int len)
{
	if (len < sizeof(struct bssmap_header)) {
		LOGP(DMSC, LOGL_ERROR, "The header is too short.\n");
	}

	switch (msg->l3h[0]) {
	case BSSAP_MSG_BSS_MANAGEMENT:
		msg->l4h = &msg->l3h[sizeof(struct bssmap_header)];
		bssmap_rcvmsg_dt1(conn, msg, len - sizeof(struct bssmap_header));
		break;
	case BSSAP_MSG_DTAP:
		dtap_rcvmsg(conn, msg, len);
		break;
	default:
		LOGP(DMSC, LOGL_NOTICE, "Unimplemented BSSAP msg type: %s\n",
			gsm0808_bssap_name(msg->l3h[0]));
	}

	return -1;
}

int bsc_tx_bssmap_ho_required(struct gsm_lchan *lchan, const struct gsm0808_cell_id_list2 *target_cells)
{
	int rc;
	struct msgb *msg;
	struct gsm0808_handover_required params = {
		.cause = GSM0808_CAUSE_BETTER_CELL,
		.cil = *target_cells,
		.current_channel_type_1_present = true,
		.current_channel_type_1 = gsm0808_current_channel_type_1(lchan->type),
	};

	switch (lchan->type) {
	case GSM_LCHAN_TCH_F:
	case GSM_LCHAN_TCH_H:
		params.speech_version_used_present = true;
		params.speech_version_used = gsm0808_permitted_speech(lchan->type,
								      lchan->tch_mode);
		if (!params.speech_version_used) {
			LOG_HO(lchan->conn, LOGL_ERROR, "Cannot encode Speech Version (Used)"
			       " for BSSMAP Handover Required message\n");
			return -EINVAL;
		}
		break;
	default:
		break;
	}

	msg = gsm0808_create_handover_required(&params);
	if (!msg) {
		LOG_HO(lchan->conn, LOGL_ERROR, "Cannot compose BSSMAP Handover Required message\n");
		return -EINVAL;
	}

	rc = gscon_sigtran_send(lchan->conn, msg);
	if (rc) {
		LOG_HO(lchan->conn, LOGL_ERROR, "Cannot send BSSMAP Handover Required message\n");
		return rc;
	}

	return 0;
}

/* Inter-BSC MT HO, new BSS has allocated a channel and sends the RR Handover Command via MSC to the old
 * BSS, encapsulated in a BSSMAP Handover Request Acknowledge. */
int bsc_tx_bssmap_ho_request_ack(struct gsm_subscriber_connection *conn, struct msgb *rr_ho_command)
{
	struct msgb *msg;
	struct gsm_lchan *new_lchan = conn->ho.new_lchan;

	msg = gsm0808_create_handover_request_ack(rr_ho_command->data, rr_ho_command->len,
						  gsm0808_chosen_channel(new_lchan->type,
									 new_lchan->tch_mode),
						  new_lchan->encr.alg_id,
						  gsm0808_permitted_speech(new_lchan->type,
									   new_lchan->tch_mode));
	msgb_free(rr_ho_command);
	if (!msg)
		return -ENOMEM;
	return osmo_bsc_sigtran_send(conn, msg);
}

int bsc_tx_bssmap_ho_detect(struct gsm_subscriber_connection *conn)
{
	struct msgb *msg;
	msg = gsm0808_create_handover_detect();
	if (!msg)
		return -ENOMEM;

	return osmo_bsc_sigtran_send(conn, msg);
}

enum handover_result bsc_tx_bssmap_ho_complete(struct gsm_subscriber_connection *conn,
					       struct gsm_lchan *lchan)
{
	int rc;
	struct msgb *msg;
	struct handover *ho = &conn->ho;
	enum gsm0808_lcls_status lcls_status = lcls_get_status(conn);

	struct gsm0808_handover_complete params = {
		.chosen_encr_alg_present = true,
		.chosen_encr_alg = lchan->encr.alg_id,

		.chosen_channel_present = true,
		.chosen_channel = gsm0808_chosen_channel(lchan->type, lchan->tch_mode),

		.lcls_bss_status_present = (lcls_status != 0xff),
		.lcls_bss_status = lcls_status,
	};

	/* speech_codec_chosen */
	if (ho->new_lchan->activate.requires_voice_stream && gscon_is_aoip(conn)) {
		int perm_spch = gsm0808_permitted_speech(lchan->type, lchan->tch_mode);
		params.speech_codec_chosen_present = true;
		rc = gsm0808_speech_codec_from_chan_type(&params.speech_codec_chosen, perm_spch);
		if (rc) {
			LOG_HO(conn, LOGL_ERROR, "Unable to compose Speech Codec (Chosen)\n");
			return HO_RESULT_ERROR;
		}
	}

	msg = gsm0808_create_handover_complete(&params);
	if (!msg) {
		LOG_HO(conn, LOGL_ERROR, "Unable to compose BSSMAP Handover Complete message\n");
		return HO_RESULT_ERROR;
	}

	rc = gscon_sigtran_send(conn, msg);
	if (rc) {
		LOG_HO(conn, LOGL_ERROR, "Cannot send BSSMAP Handover Complete message\n");
		return HO_RESULT_ERROR;
	}

	return HO_RESULT_OK;
}

void bsc_tx_bssmap_ho_failure(struct gsm_subscriber_connection *conn)
{
	int rc;
	struct msgb *msg;
	struct gsm0808_handover_failure params = {};

	msg = gsm0808_create_handover_failure(&params);
	if (!msg) {
		LOG_HO(conn, LOGL_ERROR, "Unable to compose BSSMAP Handover Failure message\n");
		return;
	}

	rc = gscon_sigtran_send(conn, msg);
	if (rc)
		LOG_HO(conn, LOGL_ERROR, "Cannot send BSSMAP Handover Failure message (rc=%d %s)\n",
		       rc, strerror(-rc));
}
