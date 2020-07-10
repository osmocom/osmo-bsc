/* GSM Mobile Radio Interface Layer 3 messages on the A-bis interface
 * 3GPP TS 04.08 version 7.21.0 Release 1998 / ETSI TS 100 940 V7.21.0
 * utility functions
 */

/* (C) 2008-2009 by Harald Welte <laforge@gnumonks.org>
 * (C) 2008, 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
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
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/in.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/bitvec.h>
#include <osmocom/gsm/gsm48.h>
#include <osmocom/gsm/sysinfo.h>

#include <osmocom/bsc/abis_rsl.h>
#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/paging.h>
#include <osmocom/bsc/signal.h>
#include <osmocom/bsc/bsc_subscr_conn_fsm.h>
#include <osmocom/bsc/gsm_04_08_rr.h>
#include <osmocom/bsc/lchan_fsm.h>
#include <osmocom/bsc/assignment_fsm.h>
#include <osmocom/bsc/handover_fsm.h>
#include <osmocom/bsc/gsm_08_08.h>
#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/system_information.h>


int gsm48_sendmsg(struct msgb *msg)
{
	if (msg->lchan)
		msg->dst = msg->lchan->ts->trx->rsl_link;

	msg->l3h = msg->data;
	return rsl_data_request(msg, 0);
}

/* Section 9.1.8 / Table 9.9 */
struct chreq {
	uint8_t val;
	uint8_t mask;
	enum chreq_type type;
};

/* If SYSTEM INFORMATION TYPE 4 NECI bit == 1 */
static const struct chreq chreq_type_neci1[] = {
	{ 0xa0, 0xe0, CHREQ_T_EMERG_CALL },
	{ 0xc0, 0xe0, CHREQ_T_CALL_REEST_TCH_F },
	{ 0x68, 0xfc, CHREQ_T_CALL_REEST_TCH_H },
	{ 0x6c, 0xfc, CHREQ_T_CALL_REEST_TCH_H_DBL },
	{ 0xe0, 0xe0, CHREQ_T_TCH_F },
	{ 0x40, 0xf0, CHREQ_T_VOICE_CALL_TCH_H },
	{ 0x50, 0xf0, CHREQ_T_DATA_CALL_TCH_H },
	{ 0x00, 0xf0, CHREQ_T_LOCATION_UPD },
	{ 0x10, 0xf0, CHREQ_T_SDCCH },
	{ 0x80, 0xe0, CHREQ_T_PAG_R_ANY_NECI1 },
	{ 0x20, 0xf0, CHREQ_T_PAG_R_TCH_F },
	{ 0x30, 0xf0, CHREQ_T_PAG_R_TCH_FH },
	{ 0x67, 0xff, CHREQ_T_LMU },
	{ 0x60, 0xf9, CHREQ_T_RESERVED_SDCCH },
	{ 0x61, 0xfb, CHREQ_T_RESERVED_SDCCH },
	{ 0x63, 0xff, CHREQ_T_RESERVED_SDCCH },
	{ 0x70, 0xf8, CHREQ_T_PDCH_TWO_PHASE },
	{ 0x78, 0xfc, CHREQ_T_PDCH_ONE_PHASE },
	{ 0x78, 0xfa, CHREQ_T_PDCH_ONE_PHASE },
	{ 0x78, 0xf9, CHREQ_T_PDCH_ONE_PHASE },
	{ 0x7f, 0xff, CHREQ_T_RESERVED_IGNORE },
};

/* If SYSTEM INFORMATION TYPE 4 NECI bit == 0 */
static const struct chreq chreq_type_neci0[] = {
	{ 0xa0, 0xe0, CHREQ_T_EMERG_CALL },
	{ 0xc0, 0xe0, CHREQ_T_CALL_REEST_TCH_H },
	{ 0xe0, 0xe0, CHREQ_T_TCH_F },
	{ 0x50, 0xf0, CHREQ_T_DATA_CALL_TCH_H },
	{ 0x00, 0xe0, CHREQ_T_LOCATION_UPD },
	{ 0x80, 0xe0, CHREQ_T_PAG_R_ANY_NECI0 },
	{ 0x20, 0xf0, CHREQ_T_PAG_R_TCH_F },
	{ 0x30, 0xf0, CHREQ_T_PAG_R_TCH_FH },
	{ 0x67, 0xff, CHREQ_T_LMU },
	{ 0x60, 0xf9, CHREQ_T_RESERVED_SDCCH },
	{ 0x61, 0xfb, CHREQ_T_RESERVED_SDCCH },
	{ 0x63, 0xff, CHREQ_T_RESERVED_SDCCH },
	{ 0x70, 0xf8, CHREQ_T_PDCH_TWO_PHASE },
	{ 0x78, 0xfc, CHREQ_T_PDCH_ONE_PHASE },
	{ 0x78, 0xfa, CHREQ_T_PDCH_ONE_PHASE },
	{ 0x78, 0xf9, CHREQ_T_PDCH_ONE_PHASE },
	{ 0x7f, 0xff, CHREQ_T_RESERVED_IGNORE },
};

static const enum gsm_chan_t ctype_by_chreq[] = {
	[CHREQ_T_EMERG_CALL]		= GSM_LCHAN_TCH_F,
	[CHREQ_T_CALL_REEST_TCH_F]	= GSM_LCHAN_TCH_F,
	[CHREQ_T_CALL_REEST_TCH_H]	= GSM_LCHAN_TCH_H,
	[CHREQ_T_CALL_REEST_TCH_H_DBL]	= GSM_LCHAN_TCH_H,
	[CHREQ_T_SDCCH]			= GSM_LCHAN_SDCCH,
	[CHREQ_T_TCH_F]			= GSM_LCHAN_TCH_F,
	[CHREQ_T_VOICE_CALL_TCH_H]	= GSM_LCHAN_TCH_H,
	[CHREQ_T_DATA_CALL_TCH_H]	= GSM_LCHAN_TCH_H,
	[CHREQ_T_LOCATION_UPD]		= GSM_LCHAN_SDCCH,
	[CHREQ_T_PAG_R_ANY_NECI1]	= GSM_LCHAN_SDCCH,
	[CHREQ_T_PAG_R_ANY_NECI0]	= GSM_LCHAN_SDCCH,
	[CHREQ_T_PAG_R_TCH_F]		= GSM_LCHAN_TCH_F,
	[CHREQ_T_PAG_R_TCH_FH]		= GSM_LCHAN_TCH_H,
	[CHREQ_T_LMU]			= GSM_LCHAN_SDCCH,
	[CHREQ_T_RESERVED_SDCCH]	= GSM_LCHAN_SDCCH,
	[CHREQ_T_PDCH_ONE_PHASE]	= GSM_LCHAN_PDTCH,
	[CHREQ_T_PDCH_TWO_PHASE]	= GSM_LCHAN_PDTCH,
	[CHREQ_T_RESERVED_IGNORE]	= GSM_LCHAN_UNKNOWN,
};

static const enum gsm_chreq_reason_t reason_by_chreq[] = {
	[CHREQ_T_EMERG_CALL]		= GSM_CHREQ_REASON_EMERG,
	[CHREQ_T_CALL_REEST_TCH_F]	= GSM_CHREQ_REASON_CALL,
	[CHREQ_T_CALL_REEST_TCH_H]	= GSM_CHREQ_REASON_CALL,
	[CHREQ_T_CALL_REEST_TCH_H_DBL]	= GSM_CHREQ_REASON_CALL,
	[CHREQ_T_SDCCH]			= GSM_CHREQ_REASON_OTHER,
	[CHREQ_T_TCH_F]			= GSM_CHREQ_REASON_OTHER,
	[CHREQ_T_VOICE_CALL_TCH_H]	= GSM_CHREQ_REASON_CALL,
	[CHREQ_T_DATA_CALL_TCH_H]	= GSM_CHREQ_REASON_OTHER,
	[CHREQ_T_LOCATION_UPD]		= GSM_CHREQ_REASON_LOCATION_UPD,
	[CHREQ_T_PAG_R_ANY_NECI1]	= GSM_CHREQ_REASON_PAG,
	[CHREQ_T_PAG_R_ANY_NECI0]	= GSM_CHREQ_REASON_PAG,
	[CHREQ_T_PAG_R_TCH_F]		= GSM_CHREQ_REASON_PAG,
	[CHREQ_T_PAG_R_TCH_FH]		= GSM_CHREQ_REASON_PAG,
	[CHREQ_T_LMU]			= GSM_CHREQ_REASON_OTHER,
	[CHREQ_T_PDCH_ONE_PHASE]	= GSM_CHREQ_REASON_PDCH,
	[CHREQ_T_PDCH_TWO_PHASE]	= GSM_CHREQ_REASON_PDCH,
	[CHREQ_T_RESERVED_SDCCH]	= GSM_CHREQ_REASON_OTHER,
	[CHREQ_T_RESERVED_IGNORE]	= GSM_CHREQ_REASON_OTHER,
};

/* verify that the two tables match */
osmo_static_assert(sizeof(ctype_by_chreq) ==
	      sizeof(((struct gsm_network *) NULL)->ctype_by_chreq), assert_size);

/*
 * Update channel types for request based on policy. E.g. in the
 * case of a TCH/H network/bsc use TCH/H for the emergency calls,
 * for early assignment assign a SDCCH and some other options.
 */
void gsm_net_update_ctype(struct gsm_network *network)
{
	/* copy over the data */
	memcpy(network->ctype_by_chreq, ctype_by_chreq, sizeof(ctype_by_chreq));

	/*
	 * Use TCH/H for emergency calls when this cell allows TCH/H. Maybe it
	 * is better to iterate over the BTS/TRX and check if no TCH/F is available
	 * and then set it to TCH/H.
	 */
	if (network->neci)
		network->ctype_by_chreq[CHREQ_T_EMERG_CALL] = GSM_LCHAN_TCH_H;

	if (network->pag_any_tch) {
		if (network->neci) {
			network->ctype_by_chreq[CHREQ_T_PAG_R_ANY_NECI0] = GSM_LCHAN_TCH_H;
			network->ctype_by_chreq[CHREQ_T_PAG_R_ANY_NECI1] = GSM_LCHAN_TCH_H;
		} else {
			network->ctype_by_chreq[CHREQ_T_PAG_R_ANY_NECI0] = GSM_LCHAN_TCH_F;
			network->ctype_by_chreq[CHREQ_T_PAG_R_ANY_NECI1] = GSM_LCHAN_TCH_F;
		}
	}
}

enum gsm_chan_t get_ctype_by_chreq(struct gsm_network *network, uint8_t ra)
{
	int i;
	int length;
	const struct chreq *chreq;

	if (network->neci) {
		chreq = chreq_type_neci1;
		length = ARRAY_SIZE(chreq_type_neci1);
	} else {
		chreq = chreq_type_neci0;
		length = ARRAY_SIZE(chreq_type_neci0);
	}


	for (i = 0; i < length; i++) {
		const struct chreq *chr = &chreq[i];
		if ((ra & chr->mask) == chr->val)
			return network->ctype_by_chreq[chr->type];
	}
	LOGP(DRR, LOGL_ERROR, "Unknown CHANNEL REQUEST RQD 0x%02x\n", ra);
	return GSM_LCHAN_SDCCH;
}

int get_reason_by_chreq(uint8_t ra, int neci)
{
	int i;
	int length;
	const struct chreq *chreq;

	if (neci) {
		chreq = chreq_type_neci1;
		length = ARRAY_SIZE(chreq_type_neci1);
	} else {
		chreq = chreq_type_neci0;
		length = ARRAY_SIZE(chreq_type_neci0);
	}

	for (i = 0; i < length; i++) {
		const struct chreq *chr = &chreq[i];
		if ((ra & chr->mask) == chr->val)
			return reason_by_chreq[chr->type];
	}
	LOGP(DRR, LOGL_ERROR, "Unknown CHANNEL REQUEST REASON 0x%02x\n", ra);
	return GSM_CHREQ_REASON_OTHER;
}

static void mr_config_for_ms(struct gsm_lchan *lchan, struct msgb *msg)
{
	if (lchan->tch_mode == GSM48_CMODE_SPEECH_AMR)
		msgb_tlv_put(msg, GSM48_IE_MUL_RATE_CFG, lchan->mr_ms_lv[0],
			lchan->mr_ms_lv + 1);
}


#define CELL_SEL_IND_AFTER_REL_MAX_BITS (3+MAX_EARFCN_LIST*20+1)
#define CELL_SEL_IND_AFTER_REL_MAX_BYTES OSMO_BYTES_FOR_BITS(CELL_SEL_IND_AFTER_REL_MAX_BITS)

/* Generate a CSN.1 encoded "Cell Selection Indicator after release of all TCH and SDCCH"
 * as per TF 44.018 version 15.3.0 Table 10.5.2.1e.1.  This only generates the "value"
 * part of the IE, not the tag+length wrapper */
static int generate_cell_sel_ind_after_rel(uint8_t *out, unsigned int out_len, const struct gsm_bts *bts)
{
	struct bitvec bv;
	unsigned int i, rc;

	bv.data = out;
	bv.data_len = out_len;
	bitvec_zero(&bv);

	/* E-UTRAN Description */
	bitvec_set_uint(&bv, 3, 3);

	for (i = 0; i < MAX_EARFCN_LIST; i++) {
		const struct osmo_earfcn_si2q *e = &bts->si_common.si2quater_neigh_list;
		if (e->arfcn[i] == OSMO_EARFCN_INVALID)
			continue;

		/* tailroom must fit one more EARFCN (20 bits), plus the final list term bit. */
		if (bitvec_tailroom_bits(&bv) < 21) {
			LOGP(DRR, LOGL_NOTICE, "%s: Not enough room to store EARFCN %u in the "
				"Cell Selection Indicator IE\n", gsm_bts_name(bts), e->arfcn[i]);
		} else {
			bitvec_set_bit(&bv, 1);
			bitvec_set_uint(&bv, e->arfcn[i], 16);
			/* No "Measurement Bandwidth" */
			bitvec_set_bit(&bv, 0);
			/* No "Not Allowed Cells" */
			bitvec_set_bit(&bv, 0);
			/* No "TARGET_PCID" */
			bitvec_set_bit(&bv, 0);
		}
	}

	/* list term */
	bitvec_set_bit(&bv, 0);

	rc = bitvec_used_bytes(&bv);

	if (rc == 1) {
		/* only the header was written to the bitvec, no actual EARFCNs were present */
		return 0;
	} else {
		/* return the number of bytes used */
		return rc;
	}
}

/* 7.1.7 and 9.1.7: RR CHANnel RELease */
int gsm48_send_rr_release(struct gsm_lchan *lchan)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 RR REL");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	uint8_t *cause;

	msg->lchan = lchan;
	gh->proto_discr = GSM48_PDISC_RR;
	gh->msg_type = GSM48_MT_RR_CHAN_REL;

	cause = msgb_put(msg, 1);
	cause[0] = GSM48_RR_CAUSE_NORMAL;

	if (lchan->release.is_csfb) {
		uint8_t buf[CELL_SEL_IND_AFTER_REL_MAX_BYTES];
		int len;

		len = generate_cell_sel_ind_after_rel(buf, sizeof(buf), lchan->ts->trx->bts);
		if (len == 0) {
			LOGPLCHAN(lchan, DRR, LOGL_NOTICE, "MSC indicated CSFB Fast Return, but "
				"BTS has no EARFCN configured!\n");
		} else
			msgb_tlv_put(msg, GSM48_IE_CELL_SEL_IND_AFTER_REL, len, buf);
	}

	DEBUGP(DRR, "Sending Channel Release: Chan: Number: %d Type: %d\n",
		lchan->nr, lchan->type);

	/* Send actual release request to MS */
	return gsm48_sendmsg(msg);
}

int send_siemens_mrpci(struct gsm_lchan *lchan,
		       uint8_t *classmark2_lv)
{
	struct rsl_mrpci mrpci;

	if (classmark2_lv[0] < 2)
		return -EINVAL;

	mrpci.power_class = classmark2_lv[1] & 0x7;
	mrpci.vgcs_capable = classmark2_lv[2] & (1 << 1);
	mrpci.vbs_capable = classmark2_lv[2] & (1 <<2);
	mrpci.gsm_phase = (classmark2_lv[1]) >> 5 & 0x3;

	return rsl_siemens_mrpci(lchan, &mrpci);
}

/* 3GPP 44.018 9.1.12 Classmark Enquiry */
int gsm48_send_rr_classmark_enquiry(struct gsm_lchan *lchan)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 44.018 Classmark Enquiry");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	msg->lchan = lchan;
	gh->proto_discr = GSM48_PDISC_RR;
	gh->msg_type = GSM48_MT_RR_CLSM_ENQ;

	DEBUGP(DRR, "%s TX CLASSMARK ENQUIRY %u\n", gsm_lchan_name(lchan), msgb_length(msg));

	return gsm48_sendmsg(msg);
}

/* Chapter 9.1.9: Ciphering Mode Command */
int gsm48_send_rr_ciph_mode(struct gsm_lchan *lchan, int want_imeisv)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 CIPH");
	struct gsm48_hdr *gh;
	uint8_t ciph_mod_set;

	msg->lchan = lchan;

	DEBUGP(DRR, "TX CIPHERING MODE CMD\n");

	if (lchan->encr.alg_id <= RSL_ENC_ALG_A5(0))
		ciph_mod_set = 0;
	else
		ciph_mod_set = (lchan->encr.alg_id-2)<<1 | 1;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 1);
	gh->proto_discr = GSM48_PDISC_RR;
	gh->msg_type = GSM48_MT_RR_CIPH_M_CMD;
	gh->data[0] = (want_imeisv & 0x1) << 4 | (ciph_mod_set & 0xf);

	return rsl_encryption_cmd(msg);
}

static void gsm48_cell_desc(struct gsm48_cell_desc *cd,
			    const struct gsm_bts *bts)
{
	cd->ncc = (bts->bsic >> 3 & 0x7);
	cd->bcc = (bts->bsic & 0x7);
	cd->arfcn_hi = bts->c0->arfcn >> 8;
	cd->arfcn_lo = bts->c0->arfcn & 0xff;
}

/*! \brief Encode a TS 04.08 multirate config LV according to 10.5.2.21aa.
 *  \param[out] lv caller-allocated buffer of 7 bytes. First octet is is length.
 *  \param[in] mr_conf multi-rate configuration to encode (selected modes).
 *  \param[in] modes array describing the AMR modes.
 *  \param[in] num_modes length of the modes array.
 *  \returns 0 on success, -EINVAL on failure. */
int gsm48_multirate_config(uint8_t *lv,
			   const struct gsm48_multi_rate_conf *mr_conf,
			   const struct amr_mode *modes, unsigned int num_modes)
{
	int num = 0;
	unsigned int i;
	unsigned int k;
	unsigned int m = 0;
	bool mode_valid;
	uint8_t *gsm48_ie = (uint8_t *) mr_conf;
	const struct amr_mode *modes_selected[4];

	/* Check if modes for consistency (order and duplicates) */
	for (i = 0; i < num_modes; i++) {
		if (i > 0 && modes[i - 1].mode > modes[i].mode) {
			LOGP(DRR, LOGL_ERROR,
			     "BUG: Multirate codec with inconsistent config (mode order).\n");
			return -EINVAL;
		}
		if (i > 0 && modes[i - 1].mode == modes[i].mode) {
			LOGP(DRR, LOGL_ERROR,
			     "BUG: Multirate codec with inconsistent config (duplicate modes).\n");
			return -EINVAL;
		}
	}

	/* Check if the active set that is defined in mr_conf has at least one
	 * mode but not more than 4 modes set */
	for (i = 0; i < 8; i++) {
		if (((gsm48_ie[1] >> i) & 1))
			num++;
	}
	if (num > 4) {
		LOGP(DRR, LOGL_ERROR,
		     "BUG: Multirate codec with too many modes in config.\n");
		return -EINVAL;
	}
	if (num < 1) {
		LOGP(DRR, LOGL_ERROR,
		     "BUG: Multirate codec with no mode in config.\n");
		return -EINVAL;
	}

	/* Do not accept excess hysteresis or threshold values */
	for (i = 0; i < num_modes; i++) {
		if (modes[i].threshold >= 64) {
			LOGP(DRR, LOGL_ERROR,
			     "BUG: Multirate codec with excessive threshold values.\n");
			return -EINVAL;
		}
		if (modes[i].hysteresis >= 16) {
			LOGP(DRR, LOGL_ERROR,
			     "BUG: Multirate codec with excessive hysteresis values.\n");
			return -EINVAL;
		}
	}

	/* Scan through the selected modes and find a matching threshold/
	 * hysteresis value for that mode. */
	for (i = 0; i < 8; i++) {
		if (((gsm48_ie[1] >> i) & 1)) {
			mode_valid = false;
			for (k = 0; k < num_modes; k++) {
				if (modes[k].mode == i) {
					mode_valid = true;
					modes_selected[m] = &modes[k];
					m++;
				}
			}
			if (!mode_valid) {
				LOGP(DRR, LOGL_ERROR,
				     "BUG: Multirate codec with inconsistent config (no mode defined).\n");
				return -EINVAL;
			}
		}
	}
	OSMO_ASSERT(m <= 4);

	/* When the caller is not interested in any result, skip the actual
	 * composition of the IE (dry run) */
	if (!lv)
		return 0;

	/* Compose output buffer */
	lv[0] = (num == 1) ? 2 : (num + 2);
	memcpy(lv + 1, gsm48_ie, 2);
	if (num == 1)
		return 0;

	lv[3] = modes_selected[0]->threshold & 0x3f;
	lv[4] = modes_selected[0]->hysteresis << 4;
	if (num == 2)
		return 0;
	lv[4] |= (modes_selected[1]->threshold & 0x3f) >> 2;
	lv[5] = modes_selected[1]->threshold << 6;
	lv[5] |= (modes_selected[1]->hysteresis & 0x0f) << 2;
	if (num == 3)
		return 0;
	lv[5] |= (modes_selected[2]->threshold & 0x3f) >> 4;
	lv[6] = modes_selected[2]->threshold << 4;
	lv[6] |= modes_selected[2]->hysteresis & 0x0f;

	return 0;
}

#define GSM48_HOCMD_CCHDESC_LEN	16

/* Chapter 9.1.15: Handover Command */
struct msgb *gsm48_make_ho_cmd(struct gsm_lchan *new_lchan, uint8_t power_command, uint8_t ho_ref)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 HO CMD");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	struct gsm48_ho_cmd *ho =
		(struct gsm48_ho_cmd *) msgb_put(msg, sizeof(*ho));

	gh->proto_discr = GSM48_PDISC_RR;
	gh->msg_type = GSM48_MT_RR_HANDO_CMD;

	/* mandatory bits */
	gsm48_cell_desc(&ho->cell_desc, new_lchan->ts->trx->bts);
	gsm48_lchan2chan_desc(&ho->chan_desc, new_lchan);
	ho->ho_ref = ho_ref;
	ho->power_command = power_command;

	if (new_lchan->ts->hopping.enabled) {
		struct gsm_bts *bts = new_lchan->ts->trx->bts;
		struct gsm48_system_information_type_1 *si1;
		uint8_t *cur;

		si1 = GSM_BTS_SI(bts, SYSINFO_TYPE_1);
		/* Copy the Cell Chan Desc (ARFCNS in this cell) */
		msgb_put_u8(msg, GSM48_IE_CELL_CH_DESC);
		cur = msgb_put(msg, GSM48_HOCMD_CCHDESC_LEN);
		memcpy(cur, si1->cell_channel_description,
			GSM48_HOCMD_CCHDESC_LEN);
		/* Copy the Mobile Allocation */
		msgb_tlv_put(msg, GSM48_IE_MA_BEFORE,
			     new_lchan->ts->hopping.ma_len,
			     new_lchan->ts->hopping.ma_data);
	}
	/* FIXME: optional bits for type of synchronization? */

	msgb_tv_put(msg, GSM48_IE_CHANMODE_1, new_lchan->tch_mode);

	/* in case of multi rate we need to attach a config */
	if (new_lchan->tch_mode == GSM48_CMODE_SPEECH_AMR)
		msgb_tlv_put(msg, GSM48_IE_MUL_RATE_CFG, new_lchan->mr_ms_lv[0],
			new_lchan->mr_ms_lv + 1);

	return msg;
}

int gsm48_send_ho_cmd(struct gsm_lchan *old_lchan, struct gsm_lchan *new_lchan,
		      uint8_t power_command, uint8_t ho_ref)
{
	struct msgb *msg = gsm48_make_ho_cmd(new_lchan, power_command, ho_ref);
	if (!msg)
		return -EINVAL;
	msg->lchan = old_lchan;
	return gsm48_sendmsg(msg);
}

/* Chapter 9.1.2: Assignment Command */
int gsm48_send_rr_ass_cmd(struct gsm_lchan *dest_lchan, struct gsm_lchan *lchan, uint8_t power_command)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 ASS CMD");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	struct gsm48_ass_cmd *ass =
		(struct gsm48_ass_cmd *) msgb_put(msg, sizeof(*ass));

	DEBUGP(DRR, "-> ASSIGNMENT COMMAND tch_mode=0x%02x\n", lchan->tch_mode);

	msg->lchan = dest_lchan;
	gh->proto_discr = GSM48_PDISC_RR;
	gh->msg_type = GSM48_MT_RR_ASS_CMD;

	/*
	 * fill the channel information element, this code
	 * should probably be shared with rsl_rx_chan_rqd(),
	 * gsm48_lchan_modify(). But beware that 10.5.2.5
	 * 10.5.2.5.a have slightly different semantic for
	 * the chan_desc. But as long as multi-slot configurations
	 * are not used we seem to be fine.
	 */
	gsm48_lchan2chan_desc(&ass->chan_desc, lchan);
	ass->power_command = power_command;

	/* Cell Channel Description (freq. hopping), TV (see 3GPP TS 44.018, 10.5.2.1b) */
	if (lchan->ts->hopping.enabled) {
		uint8_t *chan_desc = msgb_put(msg, 1 + 16); /* tag + fixed length */
		generate_cell_chan_list(chan_desc + 1, dest_lchan->ts->trx->bts);
		chan_desc[0] = GSM48_IE_CELL_CH_DESC;
	}

	msgb_tv_put(msg, GSM48_IE_CHANMODE_1, lchan->tch_mode);

	/* Mobile Allocation (freq. hopping), TLV (see 3GPP TS 44.018, 10.5.2.21) */
	if (lchan->ts->hopping.enabled) {
		msgb_tlv_put(msg, GSM48_IE_MA_AFTER, lchan->ts->hopping.ma_len,
			     lchan->ts->hopping.ma_data);
	}

	/* in case of multi rate we need to attach a config */
	mr_config_for_ms(lchan, msg);

	return gsm48_sendmsg(msg);
}

/* TS 44.018 section 9.1.53 */
int gsm48_send_rr_app_info(struct gsm_lchan *lchan, uint8_t apdu_id, uint8_t apdu_flags,
			   const uint8_t *apdu_data, ssize_t apdu_data_len)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 APP INFO");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	if ((apdu_id & 0xF0) || (apdu_flags & 0xF0)) {
		msgb_free(msg);
		return -EINVAL;
	}

	msg->lchan = lchan;
	gh->proto_discr = GSM48_PDISC_RR;
	gh->msg_type = GSM48_MT_RR_APP_INFO;

	msgb_put_u8(msg, (apdu_flags << 4) | apdu_id);
	msgb_lv_put(msg, apdu_data_len, apdu_data);

	return gsm48_sendmsg(msg);
}

/* 9.1.5 Channel mode modify: Modify the mode on the MS side */
int gsm48_lchan_modify(struct gsm_lchan *lchan, uint8_t mode)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 CHN MOD");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	struct gsm48_chan_mode_modify *cmm =
		(struct gsm48_chan_mode_modify *) msgb_put(msg, sizeof(*cmm));

	DEBUGP(DRR, "-> CHANNEL MODE MODIFY mode=0x%02x\n", mode);

	lchan->tch_mode = mode;
	msg->lchan = lchan;
	gh->proto_discr = GSM48_PDISC_RR;
	gh->msg_type = GSM48_MT_RR_CHAN_MODE_MODIF;

	/* fill the channel information element, this code
	 * should probably be shared with rsl_rx_chan_rqd() */
	gsm48_lchan2chan_desc(&cmm->chan_desc, lchan);
	cmm->mode = mode;

	/* in case of multi rate we need to attach a config */
	mr_config_for_ms(lchan, msg);

	return gsm48_sendmsg(msg);
}

int gsm48_rx_rr_modif_ack(struct msgb *msg)
{
	int rc;
	struct gsm48_hdr *gh = msgb_l3(msg);
	struct gsm48_chan_mode_modify *mod =
				(struct gsm48_chan_mode_modify *) gh->data;

	LOG_LCHAN(msg->lchan, LOGL_DEBUG, "CHANNEL MODE MODIFY ACK for %s\n",
		  gsm48_chan_mode_name(mod->mode));

	if (mod->mode != msg->lchan->tch_mode) {
		LOG_LCHAN(msg->lchan, LOGL_ERROR,
			  "CHANNEL MODE MODIFY ACK has wrong mode: Wanted: %s Got: %s\n",
			  gsm48_chan_mode_name(msg->lchan->tch_mode),
			  gsm48_chan_mode_name(mod->mode));
		return -1;
	}

	/* update the channel type */
	switch (mod->mode) {
	case GSM48_CMODE_SIGN:
		msg->lchan->rsl_cmode = RSL_CMOD_SPD_SIGN;
		break;
	case GSM48_CMODE_SPEECH_V1:
	case GSM48_CMODE_SPEECH_EFR:
	case GSM48_CMODE_SPEECH_AMR:
		msg->lchan->rsl_cmode = RSL_CMOD_SPD_SPEECH;
		break;
	case GSM48_CMODE_DATA_14k5:
	case GSM48_CMODE_DATA_12k0:
	case GSM48_CMODE_DATA_6k0:
	case GSM48_CMODE_DATA_3k6:
		msg->lchan->rsl_cmode = RSL_CMOD_SPD_DATA;
		break;
	}

	/* We've successfully modified the MS side of the channel,
	 * now go on to modify the BTS side of the channel */
	rc = rsl_chan_mode_modify_req(msg->lchan);

	/* FIXME: we not only need to do this after mode modify, but
	 * also after channel activation */
	if (is_ipaccess_bts(msg->lchan->ts->trx->bts) && mod->mode != GSM48_CMODE_SIGN)
		rsl_tx_ipacc_crcx(msg->lchan);
	return rc;
}

int gsm48_parse_meas_rep(struct gsm_meas_rep *rep, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	uint8_t *data = gh->data;
	struct gsm_bts *bts = msg->lchan->ts->trx->bts;
	struct bitvec *nbv = &bts->si_common.neigh_list;
	struct gsm_meas_rep_cell *mrc;

	if (gh->msg_type != GSM48_MT_RR_MEAS_REP)
		return -EINVAL;

	if (data[0] & 0x80)
		rep->flags |= MEAS_REP_F_BA1;
	if (data[0] & 0x40)
		rep->flags |= MEAS_REP_F_UL_DTX;
	if ((data[1] & 0x40) == 0x00)
		rep->flags |= MEAS_REP_F_DL_VALID;

	rep->dl.full.rx_lev = data[0] & 0x3f;
	rep->dl.sub.rx_lev = data[1] & 0x3f;
	rep->dl.full.rx_qual = (data[2] >> 4) & 0x7;
	rep->dl.sub.rx_qual = (data[2] >> 1) & 0x7;

	rep->num_cell = ((data[3] >> 6) & 0x3) | ((data[2] & 0x01) << 2);
	if (rep->num_cell < 1 || rep->num_cell > 6) {
		/* There are no neighbor cell reports present. */
		rep->num_cell = 0;
		return 0;
	}

	/* an encoding nightmare in perfection */
	mrc = &rep->cell[0];
	mrc->rxlev = data[3] & 0x3f;
	mrc->neigh_idx = data[4] >> 3;
	mrc->arfcn = bitvec_get_nth_set_bit(nbv, mrc->neigh_idx + 1);
	mrc->bsic = ((data[4] & 0x07) << 3) | (data[5] >> 5);
	if (rep->num_cell < 2)
		return 0;

	mrc = &rep->cell[1];
	mrc->rxlev = ((data[5] & 0x1f) << 1) | (data[6] >> 7);
	mrc->neigh_idx = (data[6] >> 2) & 0x1f;
	mrc->arfcn = bitvec_get_nth_set_bit(nbv, mrc->neigh_idx + 1);
	mrc->bsic = ((data[6] & 0x03) << 4) | (data[7] >> 4);
	if (rep->num_cell < 3)
		return 0;

	mrc = &rep->cell[2];
	mrc->rxlev = ((data[7] & 0x0f) << 2) | (data[8] >> 6);
	mrc->neigh_idx = (data[8] >> 1) & 0x1f;
	mrc->arfcn = bitvec_get_nth_set_bit(nbv, mrc->neigh_idx + 1);
	mrc->bsic = ((data[8] & 0x01) << 5) | (data[9] >> 3);
	if (rep->num_cell < 4)
		return 0;

	mrc = &rep->cell[3];
	mrc->rxlev = ((data[9] & 0x07) << 3) | (data[10] >> 5);
	mrc->neigh_idx = data[10] & 0x1f;
	mrc->arfcn = bitvec_get_nth_set_bit(nbv, mrc->neigh_idx + 1);
	mrc->bsic = data[11] >> 2;
	if (rep->num_cell < 5)
		return 0;

	mrc = &rep->cell[4];
	mrc->rxlev = ((data[11] & 0x03) << 4) | (data[12] >> 4);
	mrc->neigh_idx = ((data[12] & 0xf) << 1) | (data[13] >> 7);
	mrc->arfcn = bitvec_get_nth_set_bit(nbv, mrc->neigh_idx + 1);
	mrc->bsic = (data[13] >> 1) & 0x3f;
	if (rep->num_cell < 6)
		return 0;

	mrc = &rep->cell[5];
	mrc->rxlev = ((data[13] & 0x01) << 5) | (data[14] >> 3);
	mrc->neigh_idx = ((data[14] & 0x07) << 2) | (data[15] >> 6);
	mrc->arfcn = bitvec_get_nth_set_bit(nbv, mrc->neigh_idx + 1);
	mrc->bsic = data[15] & 0x3f;

	return 0;
}

/* 9.1.29 RR Status */
struct msgb *gsm48_create_rr_status(uint8_t cause)
{
	struct msgb *msg;
	struct gsm48_hdr *gh;

	msg = gsm48_msgb_alloc_name("GSM 04.08 RR STATUS");
	if (!msg)
		return NULL;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 1);
	gh->proto_discr = GSM48_PDISC_RR;
	gh->msg_type = GSM48_MT_RR_STATUS;
	gh->data[0] = cause;

	return msg;
}

/* 9.1.29 RR Status */
int gsm48_tx_rr_status(struct gsm_subscriber_connection *conn, uint8_t cause)
{
	struct msgb *msg = gsm48_create_rr_status(cause);
	if (!msg)
		return -1;
	gscon_submit_rsl_dtap(conn, msg, 0, 0);
	return 0;
}

struct msgb *gsm48_create_mm_serv_rej(enum gsm48_reject_value value)
{
	struct msgb *msg;
	struct gsm48_hdr *gh;

	msg = gsm48_msgb_alloc_name("GSM 04.08 SERV REJ");
	if (!msg)
		return NULL;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 1);
	gh->proto_discr = GSM48_PDISC_MM;
	gh->msg_type = GSM48_MT_MM_CM_SERV_REJ;
	gh->data[0] = value;

	return msg;
}

struct msgb *gsm48_create_loc_upd_rej(uint8_t cause)
{
	struct gsm48_hdr *gh;
	struct msgb *msg;

	msg = gsm48_msgb_alloc_name("GSM 04.08 LOC UPD REJ");
	if (!msg)
		return NULL;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 1);
	gh->proto_discr = GSM48_PDISC_MM;
	gh->msg_type = GSM48_MT_MM_LOC_UPD_REJECT;
	gh->data[0] = cause;
	return msg;
}

/* As per TS 03.03 Section 2.2, the IMSI has 'not more than 15 digits' */
uint64_t str_to_imsi(const char *imsi_str)
{
	uint64_t ret;

	ret = strtoull(imsi_str, NULL, 10);

	return ret;
}

static void handle_classmark_chg(struct gsm_subscriber_connection *conn,
				 struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
	uint8_t cm2_len, cm3_len = 0;
	uint8_t *cm2, *cm3 = NULL;


	/* classmark 2 */
	cm2_len = gh->data[0];
	cm2 = &gh->data[1];

	if (cm2_len > 3) {
		LOG_LCHAN(msg->lchan, LOGL_ERROR, "CLASSMARK CHANGE: CM2 too long: %u\n", cm2_len);
		return;
	}

	if (payload_len > cm2_len + 1) {
		/* we must have a classmark3 */
		if (gh->data[cm2_len+1] != 0x20) {
			LOG_LCHAN(msg->lchan, LOGL_ERROR, "CLASSMARK CHANGE: invalid CM3 TAG\n");
			return;
		}

		cm3_len = gh->data[cm2_len+2];
		cm3 = &gh->data[cm2_len+3];
		if (cm3_len > 14) {
			LOG_LCHAN(msg->lchan, LOGL_ERROR, "CLASSMARK CHANGE: CM3 too long: %u\n",
				  cm3_len);
			return;
		}
	}

	LOG_LCHAN(msg->lchan, LOGL_DEBUG, "CLASSMARK CHANGE CM2(len=%u) CM3(len=%u)\n",
		  cm2_len, cm3_len);
	bsc_cm_update(conn, cm2, cm2_len, cm3, cm3_len);
}

static void dispatch_dtap(struct gsm_subscriber_connection *conn,
			  uint8_t link_id, struct msgb *msg)
{
	struct gsm48_hdr *gh;
	uint8_t pdisc;
	uint8_t msg_type;
	int rc;

	if (msgb_l3len(msg) < sizeof(*gh)) {
		LOG_LCHAN(msg->lchan, LOGL_ERROR,
			  "Message too short for a GSM48 header (%u)\n", msgb_l3len(msg));
		return;
	}

	gh = msgb_l3(msg);
	pdisc = gsm48_hdr_pdisc(gh);
	msg_type = gsm48_hdr_msg_type(gh);

	/* the idea is to handle all RR messages here, and only hand
	 * MM/CC/SMS-CP/LCS up to the MSC.  Some messages like PAGING
	 * RESPONSE or CM SERVICE REQUEST will not be covered here, as
	 * they are only possible in the first L3 message of each L2
	 * channel, i.e. 'conn' will not exist and gsm0408_rcvmsg()
	 * will call api->compl_l3() for it */
	switch (pdisc) {
	case GSM48_PDISC_RR:
		LOG_LCHAN(msg->lchan, LOGL_DEBUG, "Rx %s\n", gsm48_rr_msg_name(msg_type));
		switch (msg_type) {
		case GSM48_MT_RR_GPRS_SUSP_REQ:
			/* do something? */
			break;
		case GSM48_MT_RR_STATUS:
			LOG_LCHAN(msg->lchan, LOGL_NOTICE, "RR Status: %s\n", rr_cause_name(gh->data[0]));
			/* do something? */
			break;
		case GSM48_MT_RR_MEAS_REP:
			/* This shouldn't actually end up here, as RSL treats
			* L3 Info of 08.58 MEASUREMENT REPORT different by calling
			* directly into gsm48_parse_meas_rep */
			LOG_LCHAN(msg->lchan, LOGL_ERROR, "DIRECT GSM48 MEASUREMENT REPORT ?!?\n");
			gsm48_tx_rr_status(conn, GSM48_RR_CAUSE_MSG_TYPE_N_COMPAT);
			break;
		case GSM48_MT_RR_HANDO_COMPL:
			/* Chapter 9.1.16 Handover complete */
			if (!conn->ho.fi)
				LOG_LCHAN(msg->lchan, LOGL_ERROR,
					  "Rx RR Handover Complete, but no handover is ongoing\n");
			else
				osmo_fsm_inst_dispatch(conn->ho.fi, HO_EV_RR_HO_COMPLETE, msg);
			break;
		case GSM48_MT_RR_HANDO_FAIL:
			/* Chapter 9.1.17 Handover Failure */
			if (!conn->ho.fi)
				LOG_LCHAN(msg->lchan, LOGL_ERROR,
					  "Rx RR Handover Fail, but no handover is ongoing\n");
			else
				osmo_fsm_inst_dispatch(conn->ho.fi, HO_EV_RR_HO_FAIL, msg);
			break;
		case GSM48_MT_RR_CIPH_M_COMPL:
			bsc_cipher_mode_compl(conn, msg, conn->lchan->encr.alg_id);
			break;
		case GSM48_MT_RR_ASS_COMPL:
			if (conn->assignment.fi)
				osmo_fsm_inst_dispatch(conn->assignment.fi,
						       ASSIGNMENT_EV_RR_ASSIGNMENT_COMPLETE, msg);
			else
				LOGPLCHAN(msg->lchan, DRR, LOGL_ERROR,
					  "Rx RR Assignment Complete, but no assignment is ongoing\n");
			break;
		case GSM48_MT_RR_ASS_FAIL:
			if (conn->assignment.fi)
				osmo_fsm_inst_dispatch(conn->assignment.fi,
						       ASSIGNMENT_EV_RR_ASSIGNMENT_FAIL, msg);
			else
				LOGPLCHAN(msg->lchan, DRR, LOGL_ERROR,
					  "Rx RR Assignment Failure, but no assignment is ongoing\n");
			break;
		case GSM48_MT_RR_CHAN_MODE_MODIF_ACK:
			rc = gsm48_rx_rr_modif_ack(msg);
			if (rc < 0)
				osmo_fsm_inst_dispatch(msg->lchan->fi, LCHAN_EV_CHAN_MODE_MODIF_ERROR, &rc);
			else
				osmo_fsm_inst_dispatch(msg->lchan->fi, LCHAN_EV_CHAN_MODE_MODIF_ACK, msg);
			break;
		case GSM48_MT_RR_CLSM_CHG:
			handle_classmark_chg(conn, msg);
			break;
		case GSM48_MT_RR_APP_INFO:
			/* Passing RR APP INFO to MSC, not quite
			 * according to spec */
			bsc_dtap(conn, link_id, msg);
			break;
		default:
			/* Drop unknown RR message */
			LOG_LCHAN(msg->lchan, LOGL_NOTICE, "Unknown RR message: %s\n",
				  gsm48_rr_msg_name(msg_type));
			gsm48_tx_rr_status(conn, GSM48_RR_CAUSE_MSG_TYPE_N);
			break;
		}
		break;
	default:
		bsc_dtap(conn, link_id, msg);
		break;
	}
}

/*! \brief RSL has received a DATA INDICATION with L3 from MS */
int gsm0408_rcvmsg(struct msgb *msg, uint8_t link_id)
{
	struct gsm_lchan *lchan;
	int rc;

	lchan = msg->lchan;
	if (!lchan_may_receive_data(lchan)) {
		LOG_LCHAN(msg->lchan, LOGL_INFO, "Got data in non active state, discarding.\n");
		return 0;
	}

	if (lchan->conn) {
		/* if we already have a connection, forward via DTAP to
		 * MSC */
		dispatch_dtap(lchan->conn, link_id, msg);
	} else {
		/* allocate a new connection */
		lchan->conn = bsc_subscr_con_allocate(msg->lchan->ts->trx->bts->network);
		if (!lchan->conn) {
			lchan_release(lchan, false, true, RSL_ERR_EQUIPMENT_FAIL);
			return -1;
		}
		lchan->conn->lchan = lchan;

		/* fwd via bsc_api to send COMPLETE L3 INFO to MSC */
		rc = bsc_compl_l3(lchan->conn, msg, 0);
		if (rc < 0) {
			osmo_fsm_inst_dispatch(lchan->conn->fi, GSCON_EV_A_DISC_IND, NULL);
			return rc;
		}
		/* conn shall release lchan on teardown, also if this Layer 3 Complete is rejected. */
	}

	return 0;
}
