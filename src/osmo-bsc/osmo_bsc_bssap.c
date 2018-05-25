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

#include <osmocom/bsc/osmo_bsc.h>
#include <osmocom/bsc/osmo_bsc_grace.h>
#include <osmocom/bsc/osmo_bsc_rf.h>
#include <osmocom/bsc/bsc_msc_data.h>
#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/bsc_subscriber.h>
#include <osmocom/bsc/paging.h>
#include <osmocom/bsc/gsm_04_08_utils.h>
#include <osmocom/bsc/bsc_subscr_conn_fsm.h>

#include <osmocom/gsm/protocol/gsm_08_08.h>
#include <osmocom/gsm/gsm0808.h>
#include <osmocom/gsm/gsm0808_utils.h>
#include <osmocom/gsm/gsm48.h>
#include <osmocom/bsc/osmo_bsc_sigtran.h>
#include <osmocom/bsc/a_reset.h>
#include <osmocom/core/byteswap.h>

#define IP_V4_ADDR_LEN 4

/*
 * helpers for the assignment command
 */

/* Helper function for match_codec_pref(), looks up a matching permitted speech
 * value for a given msc audio codec pref */
enum gsm0808_permitted_speech audio_support_to_gsm88(struct gsm_audio_support *audio)
{
	if (audio->hr) {
		switch (audio->ver) {
		case 1:
			return GSM0808_PERM_HR1;
			break;
		case 2:
			return GSM0808_PERM_HR2;
			break;
		case 3:
			return GSM0808_PERM_HR3;
			break;
		default:
			LOGP(DMSC, LOGL_ERROR, "Wrong speech mode: hr%d, using hr1 instead\n",
			     audio->ver);
			return GSM0808_PERM_HR1;
		}
	} else {
		switch (audio->ver) {
		case 1:
			return GSM0808_PERM_FR1;
			break;
		case 2:
			return GSM0808_PERM_FR2;
			break;
		case 3:
			return GSM0808_PERM_FR3;
			break;
		default:
			LOGP(DMSC, LOGL_ERROR, "Wrong speech mode: fr%d, using fr1 instead\n",
			     audio->ver);
			return GSM0808_PERM_FR1;
		}
	}
}

/* Helper function for match_codec_pref(), looks up a matching chan mode for
 * a given permitted speech value */
enum gsm48_chan_mode gsm88_to_chan_mode(enum gsm0808_permitted_speech speech)
{
	switch (speech) {
	case GSM0808_PERM_HR1:
	case GSM0808_PERM_FR1:
		return GSM48_CMODE_SPEECH_V1;
		break;
	case GSM0808_PERM_HR2:
	case GSM0808_PERM_FR2:
		return GSM48_CMODE_SPEECH_EFR;
		break;
	case GSM0808_PERM_HR3:
	case GSM0808_PERM_FR3:
		return GSM48_CMODE_SPEECH_AMR;
		break;
	default:
		LOGP(DMSC, LOGL_FATAL,
		     "Unsupported permitted speech selected, assuming AMR as channel mode...\n");
		return GSM48_CMODE_SPEECH_AMR;
	}
}

/* Helper function for match_codec_pref(), tests if a given audio support
 * matches one of the permitted speech settings of the channel type element.
 * The matched permitted speech value is then also compared against the
 * speech codec list. (optional, only relevant for AoIP) */
static bool test_codec_pref(const struct gsm0808_channel_type *ct,
			    const struct gsm0808_speech_codec_list *scl,
			    uint8_t perm_spch)
{
	unsigned int i;
	bool match = false;
	struct gsm0808_speech_codec sc;
	int rc;

	/* Try to finde the given permitted speech value in the
	 * codec list of the channel type element */
	for (i = 0; i < ct->perm_spch_len; i++) {
		if (ct->perm_spch[i] == perm_spch) {
			match = true;
			break;
		}
	}

	/* If we do not have a speech codec list to test against,
	 * we just exit early (will be always the case in non-AoIP networks) */
	if (!scl)
		return match;

	/* If we failed to match until here, there is no
	 * point in testing further */
	if (match == false)
		return false;

	/* Extrapolate speech codec data */
	rc = gsm0808_speech_codec_from_chan_type(&sc, perm_spch);
	if (rc < 0)
		return false;

	/* Try to find extrapolated speech codec data in
	 * the speech codec list */
	for (i = 0; i < scl->len; i++) {
		if (sc.type == scl->codec[i].type)
			return true;
	}

	return false;
}

/*! Helper function for bssmap_handle_assignm_req(), matches the codec
 *  preferences from the MSC with the codec preferences
 *  \param[out] full_rate '1' if full-rate, '0' if half-rate, '-1' if no match
 *  \param[out] chan_mode GSM 04.08 channel mode
 *  \param[in] ct GSM 08.08 channel type
 *  \param[in] scl GSM 08.08 speech codec list
 *  \param[in] msc MSC data [for configuration]
 *  \returns 0 on success, -1 in case no match was found */
static int match_codec_pref(int *full_rate, enum gsm48_chan_mode *chan_mode,
			    const struct gsm0808_channel_type *ct,
			    const struct gsm0808_speech_codec_list *scl,
			    const struct bsc_msc_data *msc)
{
	unsigned int i;
	uint8_t perm_spch;
	bool match = false;

	for (i = 0; i < msc->audio_length; i++) {
		perm_spch = audio_support_to_gsm88(msc->audio_support[i]);
		if (test_codec_pref(ct, scl, perm_spch)) {
			match = true;
			break;
		}
	}

	/* Exit without result, in case no match can be deteched */
	if (!match) {
		*full_rate = -1;
		*chan_mode = GSM48_CMODE_SIGN;
		return -1;
	}

	/* Check if the result is a half or full rate codec */
	if (perm_spch == GSM0808_PERM_HR1 || perm_spch == GSM0808_PERM_HR2
	    || perm_spch == GSM0808_PERM_HR3 || perm_spch == GSM0808_PERM_HR4
	    || perm_spch == GSM0808_PERM_HR6)
		*full_rate = 0;
	else
		*full_rate = 1;

	/* Lookup a channel mode for the selected codec */
	*chan_mode = gsm88_to_chan_mode(perm_spch);

	return 0;
}

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
	uint8_t timeslot = 0;
	uint8_t multiplex = 0;
	enum gsm48_chan_mode chan_mode = GSM48_CMODE_SIGN;
	int full_rate = -1;
	bool aoip = false;
	struct sockaddr_storage rtp_addr;
	struct gsm0808_channel_type ct;
	struct gsm0808_speech_codec_list *scl_ptr = NULL;
	uint8_t cause;
	int rc;

	if (!conn) {
		LOGP(DMSC, LOGL_ERROR,
		     "No lchan/msc_data in cipher mode command.\n");
		return -1;
	}

	msc = conn->sccp.msc;

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

	/* Currently we only support a limited subset of all
	 * possible channel types, such as multi-slot or CSD */
	switch (ct.ch_indctr) {
	case GSM0808_CHAN_DATA:
		LOGP(DMSC, LOGL_ERROR, "Unsupported channel type, currently only speech is supported!\n");
		cause = GSM0808_CAUSE_REQ_CODEC_TYPE_OR_CONFIG_NOT_SUPP;
		goto reject;
	case GSM0808_CHAN_SPEECH:
		/* Detect if a CIC code is present, if so, we use the classic ip.access method to
		 * calculate the RTP port */
		if (TLVP_PRESENT(&tp, GSM0808_IE_CIRCUIT_IDENTITY_CODE)) {
			conn->user_plane.cic =
				osmo_load16be(TLVP_VAL(&tp, GSM0808_IE_CIRCUIT_IDENTITY_CODE));
			timeslot = conn->user_plane.cic & 0x1f;
			multiplex = (conn->user_plane.cic & ~0x1f) >> 5;
		} else if (TLVP_PRESENT(&tp, GSM0808_IE_AOIP_TRASP_ADDR)) {
			/* Decode AoIP transport address element */
			rc = gsm0808_dec_aoip_trasp_addr(&rtp_addr,
							 TLVP_VAL(&tp, GSM0808_IE_AOIP_TRASP_ADDR),
							 TLVP_LEN(&tp, GSM0808_IE_AOIP_TRASP_ADDR));
			if (rc < 0) {
				LOGP(DMSC, LOGL_ERROR, "Unable to decode AoIP transport address.\n");
				cause = GSM0808_CAUSE_INCORRECT_VALUE;
				goto reject;
			}
			aoip = true;
		} else {
			LOGP(DMSC, LOGL_ERROR, "AoIP transport address and CIC missing. "
			     "Audio would not work; rejecting\n");
			cause = GSM0808_CAUSE_INFORMATION_ELEMENT_OR_FIELD_MISSING;
			goto reject;
		}

		/* Decode speech codec list (AoIP) */
		conn->codec_list_present = false;
		if (aoip) {

			/* Check for speech codec list element */
			if (!TLVP_PRESENT(&tp, GSM0808_IE_SPEECH_CODEC_LIST)) {
				LOGP(DMSC, LOGL_ERROR, "Mandatory speech codec list not present.\n");
				cause = GSM0808_CAUSE_INFORMATION_ELEMENT_OR_FIELD_MISSING;
				goto reject;
			}

			/* Decode Speech Codec list */
			rc = gsm0808_dec_speech_codec_list(&conn->codec_list,
							   TLVP_VAL(&tp, GSM0808_IE_SPEECH_CODEC_LIST),
							   TLVP_LEN(&tp, GSM0808_IE_SPEECH_CODEC_LIST));
			if (rc < 0) {
				LOGP(DMSC, LOGL_ERROR, "Unable to decode speech codec list\n");
				cause = GSM0808_CAUSE_INCORRECT_VALUE;
				goto reject;
			}
			conn->codec_list_present = true;
			scl_ptr = &conn->codec_list;
		}

		/* Match codec information from the assignment command against the
		 * local preferences of the BSC */
		rc = match_codec_pref(&full_rate, &chan_mode, &ct, scl_ptr, msc);
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

		/* Forward the assignment request to lower layers */
		if (aoip) {
			/* Store network side RTP connection information, we will
			 * process this address later after we have established an RTP
			 * connection to the BTS. This is just for organizational
			 * reasons, functional wise it would not matter when exactly
			 * the network side RTP connection is made, as long it is made
			 * before we return with the assignment complete message. */
			memcpy(&conn->user_plane.aoip_rtp_addr_remote, &rtp_addr, sizeof(rtp_addr));
		} else {
			/* Note: In the sccp-lite case we to not perform any mgcp operation,
			 * (the MSC does that for us). We set conn->rtp_ip to 0 and check
			 * on this later. By this we know that we have to behave accordingly
			 * to sccp-lite. */
			conn->user_plane.rtp_port = mgcp_timeslot_to_port(multiplex, timeslot, msc->rtp_base);
			conn->user_plane.rtp_ip = 0;
		}
		conn->user_plane.chan_mode = chan_mode;
		conn->user_plane.full_rate = full_rate;
		osmo_fsm_inst_dispatch(conn->fi, GSCON_EV_A_ASSIGNMENT_CMD, NULL);
		break;
	case GSM0808_CHAN_SIGN:
		conn->user_plane.chan_mode = GSM48_CMODE_SIGN;
		osmo_fsm_inst_dispatch(conn->fi, GSCON_EV_A_ASSIGNMENT_CMD, NULL);
		break;
	default:
		cause = GSM0808_CAUSE_INVALID_MESSAGE_CONTENTS;
		goto reject;
	}

	return 0;
reject:
	resp = gsm0808_create_assignment_failure(cause, NULL);
	OSMO_ASSERT(resp);

	osmo_fsm_inst_dispatch(conn->fi, GSCON_EV_TX_SCCP, resp);
	return -1;
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
	default:
		LOGP(DMSC, LOGL_NOTICE, "Unimplemented msg type: %s\n",
			gsm0808_bssmap_name(msg->l4h[0]));
		break;
	}

	return ret;
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
