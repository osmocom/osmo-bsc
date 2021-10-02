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

#include <osmocom/core/sockaddr_str.h>
#include <osmocom/mgcp_client/mgcp_client_endpoint_fsm.h>

#include <osmocom/bsc/osmo_bsc.h>
#include <osmocom/bsc/osmo_bsc_grace.h>
#include <osmocom/bsc/osmo_bsc_rf.h>
#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/bsc_subscriber.h>
#include <osmocom/bsc/paging.h>
#include <osmocom/bsc/gsm_04_08_rr.h>
#include <osmocom/bsc/bsc_subscr_conn_fsm.h>
#include <osmocom/bsc/codec_pref.h>
#include <osmocom/bsc/abis_rsl.h>
#include <osmocom/bsc/handover_fsm.h>
#include <osmocom/bsc/bts.h>
#include <osmocom/bsc/bsc_stats.h>

#include <osmocom/gsm/protocol/gsm_08_08.h>
#include <osmocom/gsm/gsm0808.h>
#include <osmocom/bsc/osmo_bsc_sigtran.h>
#include <osmocom/bsc/osmo_bsc_lcls.h>
#include <osmocom/bsc/a_reset.h>
#include <osmocom/bsc/handover.h>
#include <osmocom/core/fsm.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/sockaddr_str.h>
#include <osmocom/bsc/lcs_loc_req.h>
#include <osmocom/bsc/bssmap_reset.h>

#define IP_V4_ADDR_LEN 4

/*
 * helpers for the assignment command
 */

/* We expect MSC to provide use with an Osmocom extension TLV in BSSMAP_RESET to
 * announce Osmux support */
static void update_msc_osmux_support(struct bsc_msc_data *msc,
				      struct msgb *msg, unsigned int length)
{
	struct tlv_parsed tp;
	int rc;
	bool old_value = msc->remote_supports_osmux;

	rc = tlv_parse(&tp, gsm0808_att_tlvdef(), msg->l4h + 1, length - 1, 0, 0);
	if (rc < 0)
		LOGP(DMSC, LOGL_NOTICE, "Failed parsing TLV looking for Osmux support\n");

	msc->remote_supports_osmux = !!TLVP_PRESENT(&tp, GSM0808_IE_OSMO_OSMUX_SUPPORT);

	if (old_value != msc->remote_supports_osmux)
		LOGP(DMSC, LOGL_INFO, "MSC detected AoIP Osmux support changed: %d->%d\n",
		     old_value,  msc->remote_supports_osmux);
}

static int bssmap_handle_reset_ack(struct bsc_msc_data *msc,
				   struct msgb *msg, unsigned int length)
{
	LOGP(DMSC, LOGL_NOTICE, "RESET ACK from MSC: %s\n",
	     osmo_sccp_addr_name(osmo_ss7_instance_find(msc->a.cs7_instance),
				 &msc->a.msc_addr));

	/* Inform the FSM that controls the RESET/RESET-ACK procedure
	 * that we have successfully received the reset-ack message */
	a_reset_ack_confirm(msc);

	update_msc_osmux_support(msc, msg, length);

	return 0;
}

/* Handle MSC sided reset */
static int bssmap_handle_reset(struct bsc_msc_data *msc,
			       struct msgb *msg, unsigned int length)
{
	LOGP(DMSC, LOGL_NOTICE, "RESET from MSC: %s\n",
	     osmo_sccp_addr_name(osmo_ss7_instance_find(msc->a.cs7_instance),
				 &msc->a.msc_addr));

	update_msc_osmux_support(msc, msg, length);

	if (!msc->a.bssmap_reset) {
		LOGP(DMSC, LOGL_ERROR, "(msc%d) missing RESET FSM\n", msc->nr);
		/* Make sure to shut down all open connections, if any */
		osmo_bsc_sigtran_reset(msc);
		return -1;
	}

	/* Normal case: let the reset FSM orchestrate link down / link up callbacks. */
	return osmo_fsm_inst_dispatch(msc->a.bssmap_reset->fi, BSSMAP_RESET_EV_RX_RESET, NULL);
}

/* Page a subscriber based on TMSI and LAC via the specified BTS.
 * The msc parameter is the MSC which issued the corresponding paging request.
 * Log an error if paging failed. */
static void
page_subscriber(const struct bsc_paging_params *params, struct gsm_bts *bts, uint32_t lac)
{
	int ret;

	if (!bsc_grace_allow_new_connection(bsc_gsmnet, bts)) {
		LOG_PAGING_BTS(params, bts, DMSC, LOGL_DEBUG, "RF-locked: not paging on this BTS\n");
		return;
	}

	LOG_PAGING_BTS(params, bts, DMSC, LOGL_INFO, "Paging on LAC %u\n", lac);

	ret = paging_request_bts(params, bts);
	if (ret == 0)
		LOG_PAGING_BTS(params, bts, DMSC, LOGL_INFO,
			       "Paging request failed, or repeated paging on LAC %u\n", lac);
}

static void
page_all_bts(const struct bsc_paging_params *params)
{
	struct gsm_bts *bts;
	llist_for_each_entry(bts, &bsc_gsmnet->bts_list, list)
		page_subscriber(params, bts, GSM_LAC_RESERVED_ALL_BTS);
}

static void
page_cgi(const struct bsc_paging_params *params)
{
	int i;
	for (i = 0; i < params->cil.id_list_len; i++) {
		const struct osmo_cell_global_id *id = &params->cil.id_list[i].global;
		if (!osmo_plmn_cmp(&id->lai.plmn, &bsc_gsmnet->plmn)) {
			int paged = 0;
			struct gsm_bts *bts;
			llist_for_each_entry(bts, &bsc_gsmnet->bts_list, list) {
				if (bts->location_area_code != id->lai.lac)
					continue;
				if (bts->cell_identity != id->cell_identity)
					continue;
				page_subscriber(params, bts, id->lai.lac);
				paged = 1;
			}
			if (!paged) {
				LOG_PAGING(params, DMSC, LOGL_NOTICE, "BTS with LAC %u and CI %u not found\n",
					   id->lai.lac, id->cell_identity);
			}
		} else {
			LOG_PAGING(params, DMSC, LOGL_DEBUG,
				   "MCC-MNC in Cell Identifier List (%s) do not match our network (%s)\n",
				   osmo_plmn_name_c(OTC_SELECT, &id->lai.plmn),
				   osmo_plmn_name_c(OTC_SELECT, &bsc_gsmnet->plmn));
		}
	}
}

static void
page_lac_and_ci(const struct bsc_paging_params *params)
{
	int i;

	for (i = 0; i < params->cil.id_list_len; i++) {
		const struct osmo_lac_and_ci_id *id = &params->cil.id_list[i].lac_and_ci;
		int paged = 0;
		struct gsm_bts *bts;
		llist_for_each_entry(bts, &bsc_gsmnet->bts_list, list) {
			if (bts->location_area_code != id->lac)
				continue;
			if (bts->cell_identity != id->ci)
				continue;
			page_subscriber(params, bts, id->lac);
			paged = 1;
		}
		if (!paged) {
			LOG_PAGING(params, DMSC, LOGL_NOTICE, "BTS with LAC %u and CI %u not found\n", id->lac, id->ci);
		}
	}
}

static void
page_ci(const struct bsc_paging_params *params)
{
	int i;

	for (i = 0; i < params->cil.id_list_len; i++) {
		uint16_t ci = params->cil.id_list[i].ci;
		int paged = 0;
		struct gsm_bts *bts;
		llist_for_each_entry(bts, &bsc_gsmnet->bts_list, list) {
			if (bts->cell_identity != ci)
				continue;
			page_subscriber(params, bts, GSM_LAC_RESERVED_ALL_BTS);
			paged = 1;
		}
		if (!paged) {
			LOG_PAGING(params, DMSC, LOGL_NOTICE, "BTS with CI %u not found\n", ci);
		}
	}
}

static void
page_lai_and_lac(const struct bsc_paging_params *params)
{
	int i;

	for (i = 0; i < params->cil.id_list_len; i++) {
		const struct osmo_location_area_id *id = &params->cil.id_list[i].lai_and_lac;
		if (!osmo_plmn_cmp(&id->plmn, &bsc_gsmnet->plmn)) {
			int paged = 0;
			struct gsm_bts *bts;
			llist_for_each_entry(bts, &bsc_gsmnet->bts_list, list) {
				if (bts->location_area_code != id->lac)
					continue;
				page_subscriber(params, bts, id->lac);
				paged = 1;
			}
			if (!paged) {
				LOG_PAGING(params, DMSC, LOGL_NOTICE, "BTS with LAC %u not found\n", id->lac);
			}
		} else {
			LOG_PAGING(params, DMSC, LOGL_DEBUG,
				   "MCC-MNC in Cell Identifier List (%s) do not match our network (%s)\n",
				   osmo_plmn_name_c(OTC_SELECT, &id->plmn),
				   osmo_plmn_name_c(OTC_SELECT, &bsc_gsmnet->plmn));
		}
	}
}

static void
page_lac(const struct bsc_paging_params *params)
{
	int i;

	for (i = 0; i < params->cil.id_list_len; i++) {
		uint16_t lac = params->cil.id_list[i].lac;
		int paged = 0;
		struct gsm_bts *bts;
		llist_for_each_entry(bts, &bsc_gsmnet->bts_list, list) {
			if (bts->location_area_code != lac)
				continue;
			page_subscriber(params, bts, lac);
			paged = 1;
		}
		if (!paged) {
			LOG_PAGING(params, DMSC, LOGL_NOTICE, "BTS with LAC %u not found\n", lac);
		}
	}
}

/* GSM 08.08 § 3.2.1.19 */
static int bssmap_handle_paging(struct bsc_msc_data *msc,
				struct msgb *msg, unsigned int payload_length)
{
	struct tlv_parsed tp;
	uint8_t data_length;
	int remain;
	const uint8_t *data;
	struct bsc_paging_params paging = {
		.reason = BSC_PAGING_FROM_CN,
		.msc = msc,
		.tmsi = GSM_RESERVED_TMSI,
	};

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
		paging.tmsi = ntohl(tlvp_val32_unal(&tp, GSM0808_IE_TMSI));
		remain -= TLVP_LEN(&tp, GSM0808_IE_TMSI);
	}

	if (remain <= 0) {
		LOGP(DMSC, LOGL_ERROR, "Payload too short.\n");
		return -1;
	}

	/*
	 * parse the IMSI
	 */
	if (osmo_mobile_identity_decode(&paging.imsi, TLVP_VAL(&tp, GSM0808_IE_IMSI), TLVP_LEN(&tp, GSM0808_IE_IMSI), false)
	    || paging.imsi.type != GSM_MI_TYPE_IMSI) {
		LOGP(DMSC, LOGL_ERROR, "Paging: could not parse IMSI\n");
		return -1;
	}

	/*
	 * There are various cell identifier list types defined at 3GPP TS § 08.08, we don't support all
	 * of them yet. To not disrupt paging operation just because we're lacking some implementation,
	 * interpret any unknown cell identifier type as "page the entire BSS".
	 */
	data_length = TLVP_LEN(&tp, GSM0808_IE_CELL_IDENTIFIER_LIST);
	data = TLVP_VAL(&tp, GSM0808_IE_CELL_IDENTIFIER_LIST);
	if (gsm0808_dec_cell_id_list2(&paging.cil, data, data_length) < 0) {
		LOG_PAGING(&paging, DMSC, LOGL_ERROR, "Could not parse Cell Identifier List\n");
		return -1;
	}
	if (paging.cil.id_discr == CELL_IDENT_BSS && data_length != 1) {
		LOG_PAGING(&paging, DMSC, LOGL_ERROR, "Cell Identifier List for BSS (0x%x)"
		     " has invalid length: %u, paging entire BSS anyway (%s)\n",
		     CELL_IDENT_BSS, data_length, osmo_hexdump(data, data_length));
	}
	remain = 0;

	if (TLVP_PRESENT(&tp, GSM0808_IE_CHANNEL_NEEDED) && TLVP_LEN(&tp, GSM0808_IE_CHANNEL_NEEDED) == 1)
		paging.chan_needed = TLVP_VAL(&tp, GSM0808_IE_CHANNEL_NEEDED)[0] & 0x03;

	if (TLVP_PRESENT(&tp, GSM0808_IE_EMLPP_PRIORITY)) {
		LOG_PAGING(&paging, DMSC, LOGL_ERROR, "eMLPP IE present, but eMLPP is not handled\n");
	}

	return bsc_paging_start(&paging);
}

int bsc_paging_start(struct bsc_paging_params *params)
{
	rate_ctr_inc(rate_ctr_group_get_ctr(bsc_gsmnet->bsc_ctrs, BSC_CTR_PAGING_ATTEMPTED));

	if (!params->bsub) {
		params->bsub = bsc_subscr_find_or_create_by_imsi(bsc_gsmnet->bsc_subscribers, params->imsi.imsi,
								 BSUB_USE_PAGING_START);
		if (!params->bsub) {
			LOG_PAGING(params, DMSC, LOGL_ERROR, "Paging request failed: Could not allocate subscriber\n");
			return -EINVAL;
		}
	}
	if (params->tmsi != GSM_RESERVED_TMSI)
		params->bsub->tmsi = params->tmsi;
	log_set_context(LOG_CTX_BSC_SUBSCR, params->bsub);

	switch (params->cil.id_discr) {
	case CELL_IDENT_NO_CELL:
		page_all_bts(params);
		break;

	case CELL_IDENT_WHOLE_GLOBAL:
		page_cgi(params);
		break;

	case CELL_IDENT_LAC_AND_CI:
		page_lac_and_ci(params);
		break;

	case CELL_IDENT_CI:
		page_ci(params);
		break;

	case CELL_IDENT_LAI_AND_LAC:
		page_lai_and_lac(params);
		break;

	case CELL_IDENT_LAC:
		page_lac(params);
		break;

	case CELL_IDENT_BSS:
		page_all_bts(params);
		break;

	default:
		LOG_PAGING(params, DMSC, LOGL_NOTICE,
			   "unimplemented Cell Identifier List type (0x%x), paging entire BSS instead\n",
			   params->cil.id_discr);
		page_all_bts(params);
		break;
	}

	bsc_subscr_put(params->bsub, BSUB_USE_PAGING_START);
	log_set_context(LOG_CTX_BSC_SUBSCR, NULL);
	return 0;
}

/* select the best cipher permitted by the intersection of both masks */
static int select_best_cipher(uint8_t msc_mask, uint8_t bsc_mask)
{
	/* A5/7 ... A5/3: We assume higher is better,
	 * but: A5/1 is better than A5/2, which is better than A5/0 */
	const uint8_t codec_strength[8] = { 7, 6, 5, 4, 3, 1, 2, 0 };
	uint8_t intersection = msc_mask & bsc_mask;
	int i;

	for (i = 0; i < ARRAY_SIZE(codec_strength); i++) {
		uint8_t codec = codec_strength[i];
		if (intersection & (1 << codec))
			return codec;
	}
	return -1;
}

static int bssmap_handle_clear_cmd(struct gsm_subscriber_connection *conn,
				   struct msgb *msg, unsigned int length)
{
	struct tlv_parsed tp;
	enum gsm0808_cause cause_0808;

	tlv_parse(&tp, gsm0808_att_tlvdef(), msg->l4h + 1, length - 1, 0, 0);

	cause_0808 = gsm0808_get_cause(&tp);
	if (cause_0808 < 0) {
		LOGPFSML(conn->fi, LOGL_ERROR, "Clear Command: Mandatory Cause IE not present.\n");
		/* Clear anyway, but without a proper cause. */
		cause_0808 = GSM0808_CAUSE_RADIO_INTERFACE_MESSAGE_FAILURE;
	}

	if (TLVP_PRESENT(&tp, GSM0808_IE_CSFB_INDICATION) &&
	    !conn->fast_return.last_eutran_plmn_valid) {
		LOGPFSML(conn->fi, LOGL_NOTICE,
			 "Clear Command: CSFB Indication present, "
			 "but subscriber has no Last Used E-UTRAN PLMN Id! "
			 "This probably means MSC doesn't support proper return "
			 "to the last used PLMN after CS fallback.\n");
	}

	osmo_fsm_inst_dispatch(conn->fi, GSCON_EV_A_CLEAR_CMD, &cause_0808);

	return 0;
}

/*
 * GSM 08.08 § 3.1.14 cipher mode handling. We will have to pick
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
	const uint8_t *data;
	struct tlv_parsed tp;
	struct msgb *resp;
	int reject_cause = -1;
	int include_imeisv = 1;
	const uint8_t *enc_key;
	uint16_t enc_key_len;
	uint8_t enc_bits_msc;
	int chosen_cipher;
	const struct tlv_p_entry *ie_kc128;

	if (!conn || !conn->lchan) {
		LOGP(DMSC, LOGL_ERROR, "No lchan/msc_data in cipher mode command.\n");
		return -1;
	}

	if (conn->ciphering_handled) {
		LOGP(DMSC, LOGL_ERROR, "Already seen ciphering command. Protocol Error.\n");
		reject_cause = GSM0808_CAUSE_PROTOCOL_ERROR_BETWEEN_BSS_AND_MSC;
		goto reject;
	}

	conn->ciphering_handled = 1;

	tlv_parse(&tp, gsm0808_att_tlvdef(), msg->l4h + 1, payload_length - 1, 0, 0);
	if (!TLVP_PRESENT(&tp, GSM0808_IE_ENCRYPTION_INFORMATION)) {
		LOGP(DMSC, LOGL_ERROR, "IE Encryption Information missing.\n");
		reject_cause = GSM0808_CAUSE_INFORMATION_ELEMENT_OR_FIELD_MISSING;
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
		reject_cause = GSM0808_CAUSE_INCORRECT_VALUE;
		goto reject;
	}

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
	chosen_cipher = select_best_cipher(enc_bits_msc, bsc_gsmnet->a5_encryption_mask);
	if (chosen_cipher < 0) {
		LOGP(DMSC, LOGL_ERROR, "Reject: no overlapping A5 ciphers between BSC (0x%02x) "
			"and MSC (0x%02x)\n", bsc_gsmnet->a5_encryption_mask, enc_bits_msc);
		reject_cause = GSM0808_CAUSE_CIPHERING_ALGORITHM_NOT_SUPPORTED;
		goto reject;
	}

	if (chosen_cipher > 0 && !enc_key_len) {
		LOGP(DRSL, LOGL_ERROR, "%s: Need to have an encryption key.\n",
		     bsc_subscr_name(conn->bsub));
		reject_cause = GSM0808_CAUSE_PROTOCOL_ERROR_BETWEEN_BSS_AND_MSC;
		goto reject;
	}

	if (enc_key_len > MAX_A5_KEY_LEN) {
		LOGP(DRSL, LOGL_ERROR, "%s: The key is too long: %d\n",
		     bsc_subscr_name(conn->bsub), len);
		reject_cause = GSM0808_CAUSE_PROTOCOL_ERROR_BETWEEN_BSS_AND_MSC;
		goto reject;
	}

	conn->lchan->encr.alg_id = RSL_ENC_ALG_A5(chosen_cipher);
	if (enc_key_len) {
		conn->lchan->encr.key_len = enc_key_len;
		memcpy(conn->lchan->encr.key, enc_key, enc_key_len);
	}
	if ((ie_kc128 = TLVP_GET(&tp, GSM0808_IE_KC_128))) {
		if (ie_kc128->len != sizeof(conn->lchan->encr.kc128)) {
			LOGPFSML(conn->fi, LOGL_ERROR, "Kc128 IE has wrong length: %u (expect %zu)\n",
				 ie_kc128->len, sizeof(conn->lchan->encr.kc128));
			reject_cause = GSM0808_CAUSE_INFORMATION_ELEMENT_OR_FIELD_MISSING;
			goto reject;
		}
		memcpy(conn->lchan->encr.kc128, ie_kc128->val, sizeof(conn->lchan->encr.kc128));
		conn->lchan->encr.kc128_present = true;
	}

	if (chosen_cipher == 4 && !conn->lchan->encr.kc128_present) {
		LOGPFSML(conn->fi, LOGL_ERROR, "A5/4 encryption selected, but no Kc128\n");
		reject_cause = GSM0808_CAUSE_INFORMATION_ELEMENT_OR_FIELD_MISSING;
		goto reject;
	}

	LOGP(DRSL, LOGL_DEBUG, "(subscr %s) Cipher Mode: cipher=%d key=%s kc128=%s include_imeisv=%d\n",
	     bsc_subscr_name(conn->bsub), chosen_cipher, osmo_hexdump_nospc(enc_key, enc_key_len),
	     ie_kc128? osmo_hexdump_nospc_c(OTC_SELECT, ie_kc128->val, ie_kc128->len) : "-",
	     include_imeisv);

	if (gsm48_send_rr_ciph_mode(conn->lchan, include_imeisv) < 0) {
		reject_cause = GSM0808_CAUSE_RADIO_INTERFACE_FAILURE;
		goto reject;
	}
	return 0;

reject:
	resp = gsm0808_create_cipher_reject(reject_cause);
	if (!resp) {
		LOGP(DMSC, LOGL_ERROR, "Sending the cipher reject failed.\n");
		return -1;
	}

	rate_ctr_inc(rate_ctr_group_get_ctr(conn->sccp.msc->msc_ctrs, MSC_CTR_BSSMAP_TX_DT1_CIPHER_REJECT));
	osmo_fsm_inst_dispatch(conn->fi, GSCON_EV_TX_SCCP, resp);
	return -1;
}

/* handle LCLS specific IES in BSSMAP ASS REQ */
static void bssmap_handle_ass_req_lcls(struct gsm_subscriber_connection *conn,
					const struct tlv_parsed *tp)
{
	const uint8_t *config, *control, *gcr;
	uint8_t gcr_len;

	/* TS 48.008 sec 3.2.2.115 Global Call Reference */
	if (TLVP_PRESENT(tp, GSM0808_IE_GLOBAL_CALL_REF)) {
		gcr = TLVP_VAL(tp, GSM0808_IE_GLOBAL_CALL_REF);
		gcr_len = TLVP_LEN(tp, GSM0808_IE_GLOBAL_CALL_REF);
		if (gcr_len > sizeof(conn->lcls.global_call_ref)) {
			LOGPFSML(conn->fi, LOGL_ERROR, "Global Call Ref IE of %u bytes is too long: %s\n",
				 gcr_len, osmo_hexdump_nospc(gcr, gcr_len));
		} else if (gcr_len < 13) { /* FIXME: document this magic value 13 */
			LOGPFSML(conn->fi, LOGL_ERROR, "Global Call Ref IE of %u bytes is too short: %s\n",
				 gcr_len, osmo_hexdump_nospc(gcr, gcr_len));
		} else {
			LOGPFSM(conn->fi, "Setting GCR to %s\n", osmo_hexdump_nospc(gcr, gcr_len));
			memcpy(&conn->lcls.global_call_ref, gcr, gcr_len);
			conn->lcls.global_call_ref_len = gcr_len;
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
	rate_ctr_inc(rate_ctr_group_get_ctr(conn->sccp.msc->msc_ctrs, MSC_CTR_BSSMAP_TX_DT1_LCLS_CONNECT_CTRL_ACK));
	osmo_fsm_inst_dispatch(conn->fi, GSCON_EV_TX_SCCP, resp);

	return 0;
}

/* Select a preferred and an alternative codec rate depending on the available
 * capabilities. This decision does not include the actual channel load yet,
 * this is also the reason why the result is a preferred and an alternate
 * setting. The final decision is made in assignment_fsm.c when the actual
 * lchan is requested. The preferred lchan will be requested first. If we
 * find an alternate setting here, this one will be tried secondly if our
 * primary choice fails. */
static int select_codecs(struct assignment_request *req, struct gsm0808_channel_type *ct,
			 struct gsm_subscriber_connection *conn)
{
	int rc, i, nc = 0;
	struct bsc_msc_data *msc;
	struct gsm_bts *bts = conn_get_bts(conn);

	if (!bts) {
		LOGP(DMSC, LOGL_ERROR, "No lchan, cannot select codecs\n");
		return -EINVAL;
	}

	msc = conn->sccp.msc;

	switch (ct->ch_rate_type) {
	case GSM0808_SPEECH_FULL_BM:
		rc = match_codec_pref(&req->ch_mode_rate_list[nc], ct, &conn->codec_list, msc, bts,
				      RATE_PREF_FR);
		nc += (rc == 0) ? 1 : 0;
		break;
	case GSM0808_SPEECH_HALF_LM:
		rc = match_codec_pref(&req->ch_mode_rate_list[nc], ct, &conn->codec_list, msc, bts,
				      RATE_PREF_HR);
		nc += (rc == 0) ? 1 : 0;
		break;
	case GSM0808_SPEECH_PERM:
	case GSM0808_SPEECH_PERM_NO_CHANGE:
	case GSM0808_SPEECH_FULL_PREF_NO_CHANGE:
	case GSM0808_SPEECH_FULL_PREF:
		rc = match_codec_pref(&req->ch_mode_rate_list[nc], ct, &conn->codec_list, msc, bts,
				      RATE_PREF_FR);
		nc += (rc == 0) ? 1 : 0;
		rc = match_codec_pref(&req->ch_mode_rate_list[nc], ct, &conn->codec_list, msc, bts,
				      RATE_PREF_HR);
		nc += (rc == 0) ? 1 : 0;
		break;
	case GSM0808_SPEECH_HALF_PREF_NO_CHANGE:
	case GSM0808_SPEECH_HALF_PREF:
		rc = match_codec_pref(&req->ch_mode_rate_list[nc], ct, &conn->codec_list, msc, bts,
				      RATE_PREF_HR);
		nc += (rc == 0) ? 1 : 0;
		rc = match_codec_pref(&req->ch_mode_rate_list[nc], ct, &conn->codec_list, msc, bts,
				      RATE_PREF_FR);
		nc += (rc == 0) ? 1 : 0;
		break;
	default:
		rc = -EINVAL;
		break;
	}

	if (!nc) {
		LOGP(DMSC, LOGL_ERROR, "No supported audio type found for channel_type ="
		     " { ch_indctr=0x%x, ch_rate_type=0x%x, perm_spch=[%s] }\n",
		     ct->ch_indctr, ct->ch_rate_type, osmo_hexdump(ct->perm_spch, ct->perm_spch_len));
		/* TODO: actually output codec names, e.g. implement
		 * gsm0808_permitted_speech_names[] and iterate perm_spch. */
		return -EINVAL;
	}

	for (i = 0; i < nc; i++ ) {
		DEBUGP(DMSC, "Found matching audio type (pref=%d): %s %s for channel_type ="
		       " { ch_indctr=0x%x, ch_rate_type=0x%x, perm_spch=[ %s] }\n",
		       i,
		       req->ch_mode_rate_list[i].chan_rate == CH_RATE_FULL ? "full rate" : "half rate",
		       get_value_string(gsm48_chan_mode_names, req->ch_mode_rate_list[i].chan_mode),
		       ct->ch_indctr, ct->ch_rate_type, osmo_hexdump(ct->perm_spch, ct->perm_spch_len));
	}

	req->n_ch_mode_rate = nc;

	return 0;
}

static int select_sign_chan(struct assignment_request *req, struct gsm0808_channel_type *ct)
{
	int i, nc = 0;

	switch (ct->ch_rate_type) {
	case GSM0808_SIGN_ANY:
		req->ch_mode_rate_list[nc++].chan_rate = CH_RATE_SDCCH;
		req->ch_mode_rate_list[nc++].chan_rate = CH_RATE_HALF;
		req->ch_mode_rate_list[nc++].chan_rate = CH_RATE_FULL;
		break;
	case GSM0808_SIGN_SDCCH:
		req->ch_mode_rate_list[nc++].chan_rate = CH_RATE_SDCCH;
		break;
	case GSM0808_SIGN_SDCCH_FULL_BM:
		req->ch_mode_rate_list[nc++].chan_rate = CH_RATE_SDCCH;
		req->ch_mode_rate_list[nc++].chan_rate = CH_RATE_FULL;
		break;
	case GSM0808_SIGN_SDCCH_HALF_LM:
		req->ch_mode_rate_list[nc++].chan_rate = CH_RATE_SDCCH;
		req->ch_mode_rate_list[nc++].chan_rate = CH_RATE_HALF;
		break;
	case GSM0808_SIGN_FULL_BM:
		req->ch_mode_rate_list[nc++].chan_rate = CH_RATE_FULL;
		break;
	case GSM0808_SIGN_HALF_LM:
		req->ch_mode_rate_list[nc++].chan_rate = CH_RATE_HALF;
		break;
	case GSM0808_SIGN_FULL_PREF:
	case GSM0808_SIGN_FULL_PREF_NO_CHANGE:
		req->ch_mode_rate_list[nc++].chan_rate = CH_RATE_FULL;
		req->ch_mode_rate_list[nc++].chan_rate = CH_RATE_HALF;
		break;
	case GSM0808_SIGN_HALF_PREF:
	case GSM0808_SIGN_HALF_PREF_NO_CHANGE:
		req->ch_mode_rate_list[nc++].chan_rate = CH_RATE_HALF;
		req->ch_mode_rate_list[nc++].chan_rate = CH_RATE_FULL;
		break;
	default:
		break;
	}

	for (i = 0; i < nc; i++)
		req->ch_mode_rate_list[i].chan_mode = GSM48_CMODE_SIGN;

	req->n_ch_mode_rate = nc;

	return nc > 0 ? 0 : -EINVAL;
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
	struct tlv_parsed tp;
	uint16_t cic = 0;
	bool aoip = false;
	bool use_osmux = false;
	uint8_t osmux_cid = 0;
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

		if (TLVP_PRESENT(&tp, GSM0808_IE_OSMO_OSMUX_CID)) {
			if (conn->sccp.msc->use_osmux == OSMUX_USAGE_OFF) {
				LOGP(DMSC, LOGL_ERROR, "MSC using Osmux but we have it disabled.\n");
				cause = GSM0808_CAUSE_INCORRECT_VALUE;
				goto reject;
			}
			use_osmux = true;
			rc = gsm0808_dec_osmux_cid(&osmux_cid,
						   TLVP_VAL(&tp, GSM0808_IE_OSMO_OSMUX_CID),
						   TLVP_LEN(&tp, GSM0808_IE_OSMO_OSMUX_CID));
			if (rc < 0) {
				LOGP(DMSC, LOGL_ERROR, "Unable to decode Osmux CID.\n");
				cause = GSM0808_CAUSE_INCORRECT_VALUE;
				goto reject;
			}
		} else {
			if (conn->sccp.msc->use_osmux == OSMUX_USAGE_ONLY) {
				LOGP(DMSC, LOGL_ERROR, "MSC not using Osmux but we are forced to use it.\n");
				cause = GSM0808_CAUSE_INCORRECT_VALUE;
				goto reject;
			} else if (conn->sccp.msc->use_osmux == OSMUX_USAGE_ON)
				LOGP(DMSC, LOGL_NOTICE, "MSC not using Osmux but we have Osmux enabled.\n");
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

		req = (struct assignment_request){
			.assign_for = ASSIGN_FOR_BSSMAP_REQ,
			.aoip = aoip,
			.msc_assigned_cic = cic,
			.use_osmux = use_osmux,
			.osmux_cid = osmux_cid,
		};

		/* Match codec information from the assignment command against the
		 * local preferences of the BSC and BTS */
		rc = select_codecs(&req, &ct, conn);
		if (rc < 0) {
			cause = GSM0808_CAUSE_REQ_CODEC_TYPE_OR_CONFIG_UNAVAIL;
			goto reject;
		}

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
			.assign_for = ASSIGN_FOR_BSSMAP_REQ,
			.aoip = aoip,
		};

		rc = select_sign_chan(&req, &ct);
		if (rc < 0) {
			cause = GSM0808_CAUSE_INCORRECT_VALUE;
			goto reject;
		}
		break;
	default:
		cause = GSM0808_CAUSE_INVALID_MESSAGE_CONTENTS;
		goto reject;
	}

	return osmo_fsm_inst_dispatch(conn->fi, GSCON_EV_ASSIGNMENT_START, &req);

reject:
	resp = gsm0808_create_assignment_failure(cause, NULL);
	OSMO_ASSERT(resp);

	rate_ctr_inc(rate_ctr_group_get_ctr(conn->sccp.msc->msc_ctrs, MSC_CTR_BSSMAP_TX_DT1_ASSIGMENT_FAILURE));
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

/* Handle Confusion message, MSC indicating an error to us:
 *
 * See 3GPP TS 48.008 §3.2.1.45
 */
static int bssmap_handle_confusion(struct gsm_subscriber_connection *conn,
				      struct msgb *msg, unsigned int length)
{
	struct tlv_parsed tp;
	int diag_len;
	enum gsm0808_cause cause;
	enum gsm0808_cause_class cause_class;
	struct gsm0808_diagnostics *diag;

	osmo_bssap_tlv_parse(&tp, msg->l4h + 1, length - 1);

	/* Check for the Cause and Diagnostic mandatory elements */
	if (!TLVP_PRESENT(&tp, GSM0808_IE_CAUSE) || !TLVP_PRESENT(&tp, GSM0808_IE_DIAGNOSTIC)) {
		LOGPFSML(conn->fi, LOGL_ERROR,
		         "Received BSSMAP Confusion message,"
		         " but either Cause or Diagnostic mandatory IE is not present: %s\n",
		         osmo_hexdump(msg->l4h, length));
		return -EINVAL;
	}

	diag_len = TLVP_LEN(&tp, GSM0808_IE_DIAGNOSTIC);
	if (diag_len < 5) {
		LOGPFSML(conn->fi, LOGL_ERROR,
		         "Received BSSMAP Confusion message with short Diagnostic length: %d (expected > 5)\n",
		         diag_len);
		return -EINVAL;
	}

	cause = gsm0808_get_cause(&tp);
	cause_class = gsm0808_cause_class(cause);
	diag = (struct gsm0808_diagnostics *)TLVP_VAL(&tp, GSM0808_IE_DIAGNOSTIC);

	LOGPFSML(conn->fi, LOGL_ERROR,
	         "Received BSSMAP Confusion: class 0x%x (%s), cause 0x%x (%s), "
	         "error octet %d (%s), error bit %d (%s), original message: %s\n",
	         cause_class, gsm0808_cause_class_name(cause_class),
	         cause, gsm0808_cause_name(cause),
	         diag->error_pointer_octet,
	         gsm0808_diagnostics_octet_location_str(diag->error_pointer_octet),
	         diag->error_pointer_bit,
	         gsm0808_diagnostics_bit_location_str(diag->error_pointer_bit),
	         osmo_hexdump(diag->msg, diag_len-2));

	return 0;
}

/* Common ID; 3GPP TS 48.008 3.2.1.68 */
static int bssmap_handle_common_id(struct gsm_subscriber_connection *conn,
				   struct msgb *msg, unsigned int length)
{
	struct tlv_parsed tp;

	osmo_bssap_tlv_parse(&tp, msg->l4h + 1, length - 1);

	/* Check for the mandatory elements */
	if (!TLVP_PRESENT(&tp, GSM0808_IE_IMSI)) {
		LOGPFSML(conn->fi, LOGL_ERROR,
		         "CommonID: missing mandatory IMSI IE: %s\n",
		         osmo_hexdump(msg->l4h, length));
		return -EINVAL;
	}

	osmo_fsm_inst_dispatch(conn->fi, GSCON_EV_A_COMMON_ID_IND, &tp);

	return 0;
}

static int bssmap_rcvmsg_udt(struct bsc_msc_data *msc,
			     struct msgb *msg, unsigned int length)
{
	int ret = 0;
	struct rate_ctr *ctrs = msc->msc_ctrs->ctr;

	if (length < 1) {
		LOGP(DMSC, LOGL_ERROR, "Not enough room: %d\n", length);
		return -1;
	}

	LOGP(DMSC, LOGL_INFO, "Rx MSC UDT BSSMAP %s\n",
		gsm0808_bssmap_name(msg->l4h[0]));

	switch (msg->l4h[0]) {
	case BSS_MAP_MSG_RESET_ACKNOWLEDGE:
		rate_ctr_inc(&ctrs[MSC_CTR_BSSMAP_RX_UDT_RESET_ACKNOWLEDGE]);
		ret = bssmap_handle_reset_ack(msc, msg, length);
		break;
	case BSS_MAP_MSG_RESET:
		rate_ctr_inc(&ctrs[MSC_CTR_BSSMAP_RX_UDT_RESET]);
		ret = bssmap_handle_reset(msc, msg, length);
		break;
	case BSS_MAP_MSG_PAGING:
		rate_ctr_inc(&ctrs[MSC_CTR_BSSMAP_RX_UDT_PAGING]);
		ret = bssmap_handle_paging(msc, msg, length);
		break;
	default:
		rate_ctr_inc(&ctrs[MSC_CTR_BSSMAP_RX_UDT_UNKNOWN]);
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
	struct rate_ctr *ctrs = conn->sccp.msc->msc_ctrs->ctr;

	if (length < 1) {
		LOGP(DMSC, LOGL_ERROR, "Not enough room: %d\n", length);
		return -1;
	}

	LOGP(DMSC, LOGL_INFO, "Rx MSC DT1 BSSMAP %s\n",
		gsm0808_bssmap_name(msg->l4h[0]));

	switch (msg->l4h[0]) {
	case BSS_MAP_MSG_CLEAR_CMD:
		rate_ctr_inc(&ctrs[MSC_CTR_BSSMAP_RX_DT1_CLEAR_CMD]);
		ret = bssmap_handle_clear_cmd(conn, msg, length);
		break;
	case BSS_MAP_MSG_CIPHER_MODE_CMD:
		rate_ctr_inc(&ctrs[MSC_CTR_BSSMAP_RX_DT1_CIPHER_MODE_CMD]);
		ret = bssmap_handle_cipher_mode(conn, msg, length);
		break;
	case BSS_MAP_MSG_ASSIGMENT_RQST:
		rate_ctr_inc(&ctrs[MSC_CTR_BSSMAP_RX_DT1_ASSIGMENT_RQST]);
		ret = bssmap_handle_assignm_req(conn, msg, length);
		break;
	case BSS_MAP_MSG_LCLS_CONNECT_CTRL:
		rate_ctr_inc(&ctrs[MSC_CTR_BSSMAP_RX_DT1_LCLS_CONNECT_CTRL]);
		ret = bssmap_handle_lcls_connect_ctrl(conn, msg, length);
		break;
	case BSS_MAP_MSG_HANDOVER_CMD:
		rate_ctr_inc(&ctrs[MSC_CTR_BSSMAP_RX_DT1_HANDOVER_CMD]);
		ret = bssmap_handle_handover_cmd(conn, msg, length);
		break;
	case BSS_MAP_MSG_CLASSMARK_RQST:
		rate_ctr_inc(&ctrs[MSC_CTR_BSSMAP_RX_DT1_CLASSMARK_RQST]);
		ret = gsm48_send_rr_classmark_enquiry(conn->lchan);
		break;
	case BSS_MAP_MSG_CONFUSION:
		rate_ctr_inc(&ctrs[MSC_CTR_BSSMAP_RX_DT1_CONFUSION]);
		ret = bssmap_handle_confusion(conn, msg, length);
		break;
	case BSS_MAP_MSG_COMMON_ID:
		rate_ctr_inc(&ctrs[MSC_CTR_BSSMAP_RX_DT1_COMMON_ID]);
		ret = bssmap_handle_common_id(conn, msg, length);
		break;
	case BSS_MAP_MSG_PERFORM_LOCATION_RQST:
		rate_ctr_inc(&ctrs[MSC_CTR_BSSMAP_RX_DT1_PERFORM_LOCATION_REQUEST]);
		lcs_loc_req_start(conn, msg);
		ret = 0;
		break;
	case BSS_MAP_MSG_PERFORM_LOCATION_ABORT:
		rate_ctr_inc(&ctrs[MSC_CTR_BSSMAP_RX_DT1_PERFORM_LOCATION_ABORT]);
		if (conn->lcs.loc_req) {
			ret = osmo_fsm_inst_dispatch(conn->lcs.loc_req->fi, LCS_LOC_REQ_EV_RX_A_PERFORM_LOCATION_ABORT,
						     msg);
		} else {
			LOGP(DMSC, LOGL_ERROR, "Rx BSSMAP Perform Location Abort without ongoing Location Request\n");
			ret = 0;
		}
		break;
	default:
		rate_ctr_inc(&ctrs[MSC_CTR_BSSMAP_RX_DT1_UNKNOWN]);
		LOGP(DMSC, LOGL_NOTICE, "Unimplemented msg type: %s\n",
			gsm0808_bssmap_name(msg->l4h[0]));
		break;
	}

	return ret;
}

/* RSL Link Identifier is defined in 3GPP TS 3GPP TS 48.058, section 9.3.2.
 * .... .SSS - SAPI value used on the radio link;
 * ...P P... - priority for SAPI0 messages;
 * CC.. .... - control channel identification:
 *   00.. .... - main signalling channel (FACCH or SDCCH),
 *   01.. .... - SACCH,
 *   other values are reserved. */
#define DLCI2RSL_LINK_ID(dlci) \
	((dlci & 0xc0) == 0xc0 ? 0x40 : 0x00) | (dlci & 0x07)

static int dtap_rcvmsg(struct gsm_subscriber_connection *conn,
		       struct msgb *msg, unsigned int length)
{
	struct dtap_header *header;
	struct msgb *gsm48;
	uint8_t *data;
	int dtap_rc;
	struct rate_ctr *ctrs;

	LOGP(DMSC, LOGL_DEBUG, "Rx MSC DTAP: %s\n",
		osmo_hexdump(msg->l3h, length));

	if (!conn) {
		LOGP(DMSC, LOGL_ERROR, "No subscriber connection available\n");
		return -1;
	}

	ctrs = conn->sccp.msc->msc_ctrs->ctr;
	header = (struct dtap_header *) msg->l3h;
	if (sizeof(*header) >= length) {
		rate_ctr_inc(&ctrs[MSC_CTR_BSSMAP_RX_DT1_DTAP_ERROR]);
		LOGP(DMSC, LOGL_ERROR, "The DTAP header does not fit. Wanted: %zu got: %u, hex: %s\n",
		     sizeof(*header), length, osmo_hexdump(msg->l3h, length));
		return -1;
	}

	if (header->length > length - sizeof(*header)) {
		rate_ctr_inc(&ctrs[MSC_CTR_BSSMAP_RX_DT1_DTAP_ERROR]);
		LOGP(DMSC, LOGL_ERROR, "The DTAP l4 information does not fit. Wanted: %u got: %zu, hex: %s\n",
		     header->length, length - sizeof(*header), osmo_hexdump(msg->l3h, length));
		return -1;
	}

	rate_ctr_inc(&ctrs[MSC_CTR_BSSMAP_RX_DT1_DTAP]);
	LOGP(DMSC, LOGL_INFO, "Rx MSC DTAP, SAPI: %s CHAN: %u\n", gsm0406_dlci_sapi_name(header->dlci_sapi), header->dlci_cc);

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
	bsc_scan_msc_msg(conn, gsm48);

	/* convert DLCI to RSL link ID, store in msg->cb */
	OBSC_LINKID_CB(gsm48) = DLCI2RSL_LINK_ID(header->link_id);

	dtap_rc = osmo_fsm_inst_dispatch(conn->fi, GSCON_EV_MT_DTAP, gsm48);
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

/* Extract and verify the length information from the BSSMAP header. */
static unsigned int bssmap_msg_len(struct msgb *msg, unsigned int length,
				   const struct gsm_subscriber_connection *conn)
{
	unsigned int expected_len;
	unsigned int calculated_len;
	struct bssmap_header *bssmap_header;

	bssmap_header = (struct bssmap_header *)msg->l3h;

	calculated_len = length - sizeof(struct bssmap_header);
	expected_len = bssmap_header->length;

	/* In case of contradictory length information, decide for the
	 * shorter length */
	if (calculated_len > expected_len) {
		LOGPFSML(conn->fi, LOGL_NOTICE,
			 "BSSMAP message contains extra data, expected %u bytes, got %u bytes, truncated\n",
			 expected_len, calculated_len);
		return expected_len;
	} else if (calculated_len < expected_len) {
		LOGPFSML(conn->fi, LOGL_NOTICE,
			 "Short BSSMAP message, expected %u bytes, got %u bytes\n",
			 expected_len, calculated_len);
		return calculated_len;
	}

	return expected_len;
}

int bsc_handle_dt(struct gsm_subscriber_connection *conn,
		  struct msgb *msg, unsigned int len)
{
	log_set_context(LOG_CTX_BSC_SUBSCR, conn->bsub);

	if (len < sizeof(struct bssmap_header)) {
		LOGP(DMSC, LOGL_ERROR, "The header is too short.\n");
	}

	switch (msg->l3h[0]) {
	case BSSAP_MSG_BSS_MANAGEMENT:
		msg->l4h = &msg->l3h[sizeof(struct bssmap_header)];
		bssmap_rcvmsg_dt1(conn, msg, bssmap_msg_len(msg, len, conn));
		break;
	case BSSAP_MSG_DTAP:
		dtap_rcvmsg(conn, msg, len);
		break;
	default:
		LOGP(DMSC, LOGL_NOTICE, "Unimplemented BSSAP msg type: %s\n",
			gsm0808_bssap_name(msg->l3h[0]));
	}

	log_set_context(LOG_CTX_BSC_SUBSCR, NULL);
	return -1;
}

int bsc_tx_bssmap_ho_required(struct gsm_lchan *lchan, const struct gsm0808_cell_id_list2 *target_cells)
{
	int rc;
	struct msgb *msg;
	struct gsm_subscriber_connection *conn = lchan->conn;
	struct gsm0808_handover_required params = {
		.cause = GSM0808_CAUSE_BETTER_CELL,
		.cil = *target_cells,
		.current_channel_type_1_present = true,
		.current_channel_type_1 = gsm0808_current_channel_type_1(lchan->type),
	};

	/* Even if fast_return is now allowed locally, we may still want to
	 * signal the Last EUTRAN PLMN Id to the new cell, since destination
	 * config may differ and allow fast return */
	if (conn->fast_return.last_eutran_plmn_valid) {
		params.old_bss_to_new_bss_info_present = true;
		params.old_bss_to_new_bss_info.last_eutran_plmn_id_present = true;
		params.old_bss_to_new_bss_info.last_eutran_plmn_id = conn->fast_return.last_eutran_plmn;
	}

	switch (lchan->type) {
	case GSM_LCHAN_TCH_F:
	case GSM_LCHAN_TCH_H:
		params.speech_version_used_present = true;
		params.speech_version_used = gsm0808_permitted_speech(lchan->type,
								      lchan->current_ch_mode_rate.chan_mode);
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
		LOG_HO(conn, LOGL_ERROR, "Cannot compose BSSMAP Handover Required message\n");
		return -EINVAL;
	}

	rate_ctr_inc(rate_ctr_group_get_ctr(conn->sccp.msc->msc_ctrs, MSC_CTR_BSSMAP_TX_DT1_HANDOVER_REQUIRED));
	rc = gscon_sigtran_send(conn, msg);
	if (rc) {
		LOG_HO(conn, LOGL_ERROR, "Cannot send BSSMAP Handover Required message\n");
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
	struct sockaddr_storage ss;
	struct gsm0808_handover_request_ack params = {
		.l3_info = rr_ho_command->data,
		.l3_info_len = rr_ho_command->len,
		.chosen_channel_present = true,
		.chosen_channel = gsm0808_chosen_channel(new_lchan->type, new_lchan->current_ch_mode_rate.chan_mode),
		.chosen_encr_alg = new_lchan->encr.alg_id,
		.chosen_speech_version = gsm0808_permitted_speech(new_lchan->type,
								  new_lchan->current_ch_mode_rate.chan_mode),
	};

	if (gscon_is_aoip(conn)) {
		struct osmo_sockaddr_str to_msc_rtp;
		const struct mgcp_conn_peer *rtp_info = osmo_mgcpc_ep_ci_get_rtp_info(conn->user_plane.mgw_endpoint_ci_msc);
		if (!rtp_info) {
			LOG_HO(conn, LOGL_ERROR,
			       "Handover Request Acknowledge: no RTP address known to send as"
			       " AoIP Transport Layer Address\n");
			return -EINVAL;
		}
		if (osmo_sockaddr_str_from_str(&to_msc_rtp, rtp_info->addr, rtp_info->port)) {
			LOG_HO(conn, LOGL_ERROR, "Handover Request Acknowledge: cannot encode AoIP Transport Layer\n");
			return -EINVAL;
		}
		if (osmo_sockaddr_str_to_sockaddr(&to_msc_rtp, &ss)) {
			LOG_HO(conn, LOGL_ERROR, "Handover Request Acknowledge: cannot encode AoIP Transport Layer\n");
			return -EINVAL;
		}
		params.aoip_transport_layer = &ss;
	}

	rate_ctr_inc(rate_ctr_group_get_ctr(conn->sccp.msc->msc_ctrs, MSC_CTR_BSSMAP_TX_DT1_HANDOVER_RQST_ACKNOWLEDGE));
	LOG_HO(conn, LOGL_DEBUG, "Sending BSSMAP Handover Request Acknowledge\n");
	msg = gsm0808_create_handover_request_ack2(&params);
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

	rate_ctr_inc(rate_ctr_group_get_ctr(conn->sccp.msc->msc_ctrs, MSC_CTR_BSSMAP_TX_DT1_HANDOVER_DETECT));
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
		.chosen_channel = gsm0808_chosen_channel(lchan->type, lchan->current_ch_mode_rate.chan_mode),

		.lcls_bss_status_present = (lcls_status != 0xff),
		.lcls_bss_status = lcls_status,
	};

	/* speech_codec_chosen */
	if (ho->new_lchan->activate.info.requires_voice_stream && gscon_is_aoip(conn)) {
		int perm_spch = gsm0808_permitted_speech(lchan->type, lchan->current_ch_mode_rate.chan_mode);
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

	rate_ctr_inc(rate_ctr_group_get_ctr(conn->sccp.msc->msc_ctrs, MSC_CTR_BSSMAP_TX_DT1_HANDOVER_COMPLETE));
	rc = osmo_bsc_sigtran_send(conn, msg);
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

	rate_ctr_inc(rate_ctr_group_get_ctr(conn->sccp.msc->msc_ctrs, MSC_CTR_BSSMAP_TX_DT1_HANDOVER_FAILURE));
	rc = osmo_bsc_sigtran_send(conn, msg);
	if (rc)
		LOG_HO(conn, LOGL_ERROR, "Cannot send BSSMAP Handover Failure message (rc=%d %s)\n",
		       rc, strerror(-rc));
}
