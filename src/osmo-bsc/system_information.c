/* GSM 04.08 System Information (SI) encoding and decoding
 * 3GPP TS 04.08 version 7.21.0 Release 1998 / ETSI TS 100 940 V7.21.0 */

/* (C) 2008-2010 by Harald Welte <laforge@gnumonks.org>
 * (C) 2012 Holger Hans Peter Freyther
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

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <netinet/in.h>
#include <stdbool.h>

#include <osmocom/core/bitvec.h>
#include <osmocom/core/utils.h>
#include <osmocom/gsm/sysinfo.h>
#include <osmocom/gsm/gsm48_ie.h>
#include <osmocom/gsm/gsm48_rest_octets.h>
#include <osmocom/gsm/gsm48.h>
#include <osmocom/gsm/gsm48_arfcn_range_encode.h>

#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/abis_rsl.h>
#include <osmocom/bsc/gsm_04_08_rr.h>
#include <osmocom/bsc/acc.h>
#include <osmocom/bsc/neighbor_ident.h>
#include <osmocom/bsc/bts.h>

struct gsm0808_cell_id_list2;

/*
 * DCS1800 and PCS1900 have overlapping ARFCNs. We would need to set the
 * ARFCN_PCS flag on the 1900 ARFCNs but this would increase cell_alloc
 * and other arrays to make sure (ARFCN_PCS + 1024)/8 ARFCNs fit into the
 * array. DCS1800 and PCS1900 can not be used at the same time so conserve
 * memory and do the below.
 */
static int band_compatible(const struct gsm_bts *bts, int arfcn)
{
	enum gsm_band band;

	if (gsm_arfcn2band_rc(arfcn, &band) < 0) {
		LOGP(DRR, LOGL_ERROR, "Invalid arfcn %d detected!\n", arfcn);
		return 0;
	}

	/* normal case */
	if (band == bts->band)
		return 1;
	/* deal with ARFCN_PCS not set */
	if (band == GSM_BAND_1800 && bts->band == GSM_BAND_1900)
		return 1;

	return 0;
}

static int is_dcs_net(const struct gsm_bts *bts)
{
	if (bts->band == GSM_BAND_850)
		return 0;
	if (bts->band == GSM_BAND_1900)
		return 0;
	return 1;
}

/* Return p(n) for given NR_OF_TDD_CELLS - see Table 9.1.54.1a, 3GPP TS 44.018 */
unsigned range1024_p(unsigned n)
{
	switch (n) {
	case 0: return 0;
	case 1: return 10;
	case 2: return 19;
	case 3: return 28;
	case 4: return 36;
	case 5: return 44;
	case 6: return 52;
	case 7: return 60;
	case 8: return 67;
	case 9: return 74;
	case 10: return 81;
	case 11: return 88;
	case 12: return 95;
	case 13: return 102;
	case 14: return 109;
	case 15: return 116;
	case 16: return 122;
	default: return 0;
	}
}

/* Return q(m) for given NR_OF_TDD_CELLS - see Table 9.1.54.1b, 3GPP TS 44.018 */
unsigned range512_q(unsigned m)
{
	switch (m) {
	case 0: return 0;
	case 1: return 9;
	case 2: return 17;
	case 3: return 25;
	case 4: return 32;
	case 5: return 39;
	case 6: return 46;
	case 7: return 53;
	case 8: return 59;
	case 9: return 65;
	case 10: return 71;
	case 11: return 77;
	case 12: return 83;
	case 13: return 89;
	case 14: return 95;
	case 15: return 101;
	case 16: return 106;
	case 17: return 111;
	case 18: return 116;
	case 19: return 121;
	case 20: return 126;
	default: return 0;
	}
}

size_t si2q_earfcn_count(const struct osmo_earfcn_si2q *e)
{
	unsigned i, ret = 0;

	if (!e)
		return 0;

	for (i = 0; i < e->length; i++)
		if (e->arfcn[i] != OSMO_EARFCN_INVALID)
			ret++;

	return ret;
}

/* generate SI2quater messages, return rest octets length of last generated message or negative error code */
static int make_si2quaters(struct gsm_bts *bts, bool counting)
{
	int rc;
	bool memory_exceeded = true;
	struct gsm48_system_information_type_2quater *si2q;

	for (bts->si2q_index = 0; bts->si2q_index < SI2Q_MAX_NUM; bts->si2q_index++) {
		si2q = GSM_BTS_SI2Q(bts, bts->si2q_index);
		if (counting) { /* that's legitimate if we're called for counting purpose: */
			if (bts->si2q_count < bts->si2q_index)
				bts->si2q_count = bts->si2q_index;
		} else {
			memset(si2q, GSM_MACBLOCK_PADDING, GSM_MACBLOCK_LEN);

			si2q->header.l2_plen = GSM48_LEN2PLEN(22);
			si2q->header.rr_protocol_discriminator = GSM48_PDISC_RR;
			si2q->header.skip_indicator = 0;
			si2q->header.system_information = GSM48_MT_RR_SYSINFO_2quater;
		}

		rc = osmo_gsm48_rest_octets_si2quater_encode(si2q->rest_octets, bts->si2q_index,
							     bts->si2q_count, bts->si_common.data.uarfcn_list,
							     &bts->u_offset, bts->si_common.uarfcn_length,
							     bts->si_common.data.scramble_list,
							     &bts->si_common.si2quater_neigh_list,
							     &bts->e_offset);
		if (rc < 0)
			return rc;

		if (bts->u_offset >= bts->si_common.uarfcn_length &&
		    bts->e_offset >= si2q_earfcn_count(&bts->si_common.si2quater_neigh_list)) {
			memory_exceeded = false;
			break;
		}
	}

	if (memory_exceeded)
		return -ENOMEM;

	return rc;
}

/* we generate SI2q rest octets twice to get proper estimation but it's one time cost anyway */
uint8_t si2q_num(struct gsm_bts *bts)
{
	int rc = make_si2quaters(bts, true);
	uint8_t num = bts->si2q_index + 1; /* number of SI2quater messages */

	/* N. B: si2q_num() should NEVER be called during actual SI2q rest octets generation
	   we're not re-entrant because of the following code: */
	bts->u_offset = 0;
	bts->e_offset = 0;

	if (rc < 0)
		return 0xFF; /* return impossible index as an indicator of error in generating SI2quater */

	return num;
}

/* 3GPP TS 44.018, Table 9.1.54.1 - prepend diversity bit to scrambling code */
static inline uint16_t encode_fdd(uint16_t scramble, bool diversity)
{
	if (diversity)
		return scramble | (1 << 9);
	return scramble;
}

int bts_earfcn_add(struct gsm_bts *bts, uint16_t earfcn, uint8_t thresh_hi, uint8_t thresh_lo, uint8_t prio,
		   uint8_t qrx, uint8_t meas_bw)
{
	struct osmo_earfcn_si2q *e = &bts->si_common.si2quater_neigh_list;
	int r = osmo_earfcn_add(e, earfcn, (meas_bw < EARFCN_MEAS_BW_INVALID) ? meas_bw : OSMO_EARFCN_MEAS_INVALID);

	if (r < 0)
		return r;

	if (e->thresh_hi && thresh_hi != e->thresh_hi)
		r = 1;

	e->thresh_hi = thresh_hi;

	if (thresh_lo != EARFCN_THRESH_LOW_INVALID) {
		if (e->thresh_lo_valid && e->thresh_lo != thresh_lo)
			r = EARFCN_THRESH_LOW_INVALID;
		e->thresh_lo = thresh_lo;
		e->thresh_lo_valid = true;
	}

	if (qrx != EARFCN_QRXLV_INVALID) {
		if (e->qrxlm_valid && e->qrxlm != qrx)
			r = EARFCN_QRXLV_INVALID + 1;
		e->qrxlm = qrx;
		e->qrxlm_valid = true;
	}

	if (prio != EARFCN_PRIO_INVALID) {
		if (e->prio_valid && e->prio != prio)
			r = EARFCN_PRIO_INVALID;
		e->prio = prio;
		e->prio_valid = true;
	}

	return r;
}

/* Scrambling Code as defined in 3GPP TS 25.213 is 9 bit long so number below is unreachable upper bound */
#define SC_BOUND 600

/* Find position for a given UARFCN (take SC into consideration if it's available) in a sorted list
   N. B: we rely on the assumption that (uarfcn, scramble) tuple is unique in the lists */
static int uarfcn_sc_pos(const struct gsm_bts *bts, uint16_t uarfcn, uint16_t scramble)
{
	const uint16_t *sc = bts->si_common.data.scramble_list;
	uint16_t i, scramble0 = encode_fdd(scramble, false), scramble1 = encode_fdd(scramble, true);
	for (i = 0; i < bts->si_common.uarfcn_length; i++)
		if (uarfcn == bts->si_common.data.uarfcn_list[i]) {
			if (scramble < SC_BOUND) {
				if (scramble0 == sc[i] || scramble1 == sc[i])
					return i;
			} else
				return i;
		}

	return -1;
}

int bts_uarfcn_del(struct gsm_bts *bts, uint16_t arfcn, uint16_t scramble)
{
	uint16_t *ual = bts->si_common.data.uarfcn_list, *scl = bts->si_common.data.scramble_list;
	size_t len = bts->si_common.uarfcn_length;
	int pos = uarfcn_sc_pos(bts, arfcn, scramble);

	if (pos < 0)
		return -EINVAL;

	if (pos != len - 1) { /* move the tail if necessary */
		memmove(ual + pos, ual + pos + 1, 2 * (len - pos + 1));
		memmove(scl + pos, scl + pos + 1, 2 * (len - pos + 1));
	}

	bts->si_common.uarfcn_length--;
	return 0;
}

int bts_uarfcn_add(struct gsm_bts *bts, uint16_t arfcn, uint16_t scramble, bool diversity)
{
	size_t len = bts->si_common.uarfcn_length, i;
	uint8_t si2q;
	int pos = uarfcn_sc_pos(bts, arfcn, scramble);
	uint16_t scr = diversity ? encode_fdd(scramble, true) : encode_fdd(scramble, false),
		*ual = bts->si_common.data.uarfcn_list,
		*scl = bts->si_common.data.scramble_list;

	if (len == MAX_EARFCN_LIST)
		return -ENOMEM;

	if (pos >= 0)
		return -EADDRINUSE;

	/* find the suitable position for arfcn if any */
	pos = uarfcn_sc_pos(bts, arfcn, SC_BOUND);
	i = (pos < 0) ? len : pos;

	/* move the tail to make space for inserting if necessary */
	if (i < len) {
		memmove(ual + i + 1, ual + i, (len - i) * 2);
		memmove(scl + i + 1, scl + i, (len - i) * 2);
	}

	/* insert into appropriate position */
	ual[i] = arfcn;
	scl[i] = scr;
	bts->si_common.uarfcn_length++;
	/* try to generate SI2q */
	si2q = si2q_num(bts);

	if (si2q <= SI2Q_MAX_NUM) {
		bts->si2q_count = si2q - 1;
		return 0;
	}

	/* rollback after unsuccessful generation */
	bts_uarfcn_del(bts, arfcn, scramble);
	return -ENOSPC;
}

static inline int use_arfcn(const struct gsm_bts *bts, const bool bis, const bool ter,
			const bool pgsm, const int arfcn)
{
	if (bts->force_combined_si_set ? bts->force_combined_si : bts->model->force_combined_si)
		return !bis && !ter;
	if (!bis && !ter && band_compatible(bts, arfcn))
		return 1;
	/* Correct but somehow broken with either the nanoBTS or the iPhone5 */
	if (bis && pgsm && band_compatible(bts, arfcn) && (arfcn < 1 || arfcn > 124))
		return 1;
	if (ter && !band_compatible(bts, arfcn))
		return 1;
	return 0;
}

/* Frequency Lists as per TS 04.08 10.5.2.13 */

/* 10.5.2.13.2: Bit map 0 format */
static int freq_list_bm0_set_arfcn(uint8_t *chan_list, unsigned int arfcn)
{
	unsigned int byte, bit;

	if (arfcn > 124 || arfcn < 1) {
		LOGP(DRR, LOGL_ERROR, "Bitmap 0 only supports ARFCN 1...124\n");
		return -EINVAL;
	}

	/* the bitmask is from 1..124, not from 0..123 */
	arfcn--;

	byte = arfcn / 8;
	bit = arfcn % 8;

	chan_list[GSM48_CELL_CHAN_DESC_SIZE-1-byte] |= (1 << bit);

	return 0;
}

/* 10.5.2.13.7: Variable bit map format */
static int freq_list_bmrel_set_arfcn(uint8_t *chan_list, unsigned int arfcn)
{
	unsigned int byte, bit;
	unsigned int min_arfcn;
	unsigned int bitno;

	min_arfcn = (chan_list[0] & 1) << 9;
	min_arfcn |= chan_list[1] << 1;
	min_arfcn |= (chan_list[2] >> 7) & 1;

	/* The lower end of our bitmaks is always implicitly included */
	if (arfcn == min_arfcn)
		return 0;

	if (((arfcn - min_arfcn) & 1023) > 111) {
		LOGP(DRR, LOGL_ERROR, "arfcn(%u) > min(%u) + 111\n", arfcn, min_arfcn);
		return -EINVAL;
	}

	bitno = (arfcn - min_arfcn) & 1023;
	byte = bitno / 8;
	bit = bitno % 8;

	chan_list[2 + byte] |= 1 << (7 - bit);

	return 0;
}

/* generate a variable bitmap */
static inline int enc_freq_lst_var_bitmap(uint8_t *chan_list,
				const struct bitvec *bv, const struct gsm_bts *bts,
				bool bis, bool ter, int min, bool pgsm)
{
	int i;

	/* set it to 'Variable bitmap format' */
	chan_list[0] = 0x8e;

	chan_list[0] |= (min >> 9) & 1;
	chan_list[1] = (min >> 1);
	chan_list[2] = (min & 1) << 7;

	for (i = 0; i < bv->data_len*8; i++) {
		/* see notes in bitvec2freq_list */
		if (bitvec_get_bit_pos(bv, i)
		 && ((!bis && !ter && band_compatible(bts,i))
		  || (bis && pgsm && band_compatible(bts,i) && (i < 1 || i > 124))
		  || (ter && !band_compatible(bts, i)))) {
			int rc = freq_list_bmrel_set_arfcn(chan_list, i);
			if (rc < 0)
				return rc;
		}
	}

	return 0;
}

int range_encode(enum osmo_gsm48_range r, int *arfcns, int arfcns_used, int *w,
		 int f0, uint8_t *chan_list)
{
	/*
	 * Manipulate the ARFCN list according to the rules in J4 depending
	 * on the selected range.
	 */
	int rc, f0_included;

	osmo_gsm48_range_enc_filter_arfcns(arfcns, arfcns_used, f0, &f0_included);

	rc = osmo_gsm48_range_enc_arfcns(r, arfcns, arfcns_used, w, 0);
	if (rc < 0)
		return rc;

	/* Select the range and the amount of bits needed */
	switch (r) {
	case OSMO_GSM48_ARFCN_RANGE_128:
		return osmo_gsm48_range_enc_128(chan_list, f0, w);
	case OSMO_GSM48_ARFCN_RANGE_256:
		return osmo_gsm48_range_enc_256(chan_list, f0, w);
	case OSMO_GSM48_ARFCN_RANGE_512:
		return osmo_gsm48_range_enc_512(chan_list, f0, w);
	case OSMO_GSM48_ARFCN_RANGE_1024:
		return osmo_gsm48_range_enc_1024(chan_list, f0, f0_included, w);
	default:
		return -ERANGE;
	};

	return f0_included;
}

/* generate a frequency list with the range 512 format */
static inline int enc_freq_lst_range(uint8_t *chan_list,
				const struct bitvec *bv, const struct gsm_bts *bts,
				bool bis, bool ter, bool pgsm)
{
	int arfcns[OSMO_GSM48_RANGE_ENC_MAX_ARFCNS];
	int w[OSMO_GSM48_RANGE_ENC_MAX_ARFCNS];
	int arfcns_used = 0;
	int i, range, f0;

	/*
	 * Select ARFCNs according to the rules in bitvec2freq_list
	 */
	for (i = 0; i < bv->data_len * 8; ++i) {
		/* More ARFCNs than the maximum */
		if (arfcns_used > ARRAY_SIZE(arfcns))
			return -1;
		/* Check if we can select it? */
		if (bitvec_get_bit_pos(bv, i) && use_arfcn(bts, bis, ter, pgsm, i))
			arfcns[arfcns_used++] = i;
	}

	/*
	 * Check if the given list of ARFCNs can be encoded.
	 */
	range = osmo_gsm48_range_enc_determine_range(arfcns, arfcns_used, &f0);
	if (range == OSMO_GSM48_ARFCN_RANGE_INVALID)
		return -2;

	memset(w, 0, sizeof(w));
	return range_encode(range, arfcns, arfcns_used, w, f0, chan_list);
}

/* generate a cell channel list as per Section 10.5.2.1b of 04.08 */
static int bitvec2freq_list(uint8_t *chan_list, const struct bitvec *bv,
			    const struct gsm_bts *bts, bool bis, bool ter)
{
	int i, rc, min = -1, max = -1, arfcns = 0;
	bool pgsm = false;
	memset(chan_list, 0, 16);

	/* According to 3GPP TS 44.018, section 10.5.2.1b.2, only ARFCN values
	 * in range 1..124 can be encoded using the 'bit map 0' format. */
	if (bts->band == GSM_BAND_900)
		pgsm = true;
	/* Check presence of E-GSM ARFCN 0 */
	if (pgsm && bitvec_get_bit_pos(bv, 0) == ONE)
		pgsm = false;
	/* Check presence of E-GSM ARFCNs 975..1023 */
	for (i = 975; pgsm && i <= 1023; i++) {
		if (bitvec_get_bit_pos(bv, i) == ONE)
			pgsm = false;
	}

	/* P-GSM-only handsets only support 'bit map 0 format' */
	if (!bis && !ter && pgsm) {
		chan_list[0] = 0;

		for (i = 1; i <= 124; i++) {
			if (!bitvec_get_bit_pos(bv, i))
				continue;
			rc = freq_list_bm0_set_arfcn(chan_list, i);
			if (rc < 0)
				return rc;
		}
		return 0;
	}

	for (i = 0; i < bv->data_len*8; i++) {
		/* in case of SI2 or SI5 allow all neighbours in same band
		 * in case of SI*bis, allow neighbours in same band outside pgsm
		 * in case of SI*ter, allow neighbours in different bands
		 */
		if (!bitvec_get_bit_pos(bv, i))
			continue;
		if (!use_arfcn(bts, bis, ter, pgsm, i))
			continue;
		/* count the arfcns we want to carry */
		arfcns += 1;

		/* 955..1023 < 0..885 */
		if (min < 0)
			min = i;
		if (i >= 955 && min < 955)
			min = i;
		if (i >= 955 && min >= 955 && i < min)
			min = i;
		if (i < 955 && min < 955 && i < min)
			min = i;
		if (max < 0)
			max = i;
		if (i < 955 && max >= 955)
			max = i;
		if (i >= 955 && max >= 955 && i > max)
			max = i;
		if (i < 955 && max < 955 && i > max)
			max = i;
	}

	if (arfcns == 0) {
		/* Empty set, use 'bit map 0 format' */
		chan_list[0] = 0;
		return 0;
	}

	/* Now find the best encoding */
	if (((max - min) & 1023) <= 111)
		return enc_freq_lst_var_bitmap(chan_list, bv, bts, bis,
				ter, min, pgsm);

	/* Attempt to do the range encoding */
	rc = enc_freq_lst_range(chan_list, bv, bts, bis, ter, pgsm);
	if (rc >= 0)
		return 0;

	LOGP(DRR, LOGL_ERROR, "min_arfcn=%u, max_arfcn=%u, arfcns=%d "
		"can not generate ARFCN list\n", min, max, arfcns);
	return -EINVAL;
}

/* (Re)generate Cell Allocation (basically a bit-vector of all cell channels) */
int generate_cell_chan_alloc(struct gsm_bts *bts)
{
	const struct gsm_bts_trx *trx;
	unsigned int chan, chan_num;
	unsigned int tn;

	/* Temporary Cell Allocation bit-vector */
	uint8_t ca[1024 / 8] = { 0 };
	struct bitvec bv = {
		.data_len = sizeof(ca),
		.data = &ca[0],
	};

	/* Calculate a bit-mask of all assigned ARFCNs */
	llist_for_each_entry(trx, &bts->trx_list, list) {
		/* Always add the TRX's ARFCN */
		bitvec_set_bit_pos(&bv, trx->arfcn, 1);
		for (tn = 0; tn < ARRAY_SIZE(trx->ts); tn++) {
			const struct gsm_bts_trx_ts *ts = &trx->ts[tn];
			/* Add any ARFCNs present in hopping channels */
			for (chan = 0; chan < sizeof(ca) * 8; chan++) {
				if (bitvec_get_bit_pos(&ts->hopping.arfcns, chan) == ONE)
					bitvec_set_bit_pos(&bv, chan, ONE);
			}
		}
	}

	/* Calculate the overall number of assigned ARFCNs */
	for (chan_num = 0, chan = 0; chan < sizeof(ca) * 8; chan++) {
		if (bitvec_get_bit_pos(&bv, chan) == ONE)
			chan_num++;
	}

	/* The Mobile Allocation IE may contain up to 64 bits, so here we
	 * cannot allow more than 64 channels in Cell Allocation. */
	if (chan_num > 64) {
		LOGP(DRR, LOGL_ERROR, "Failed to (re)generate Cell Allocation: "
		     "number of channels (%u) exceeds the maximum number of "
		     "ARFCNs in Mobile Allocation (64)\n", chan_num);
		return -E2BIG;
	}

	/* Commit the new Channel Allocation */
	memcpy(&bts->si_common.data.cell_alloc[0], ca, sizeof(ca));
	bts->si_common.cell_chan_num = chan_num;

	return 0;
}

/* generate a cell channel list as per Section 10.5.2.1b of 04.08 */
int generate_cell_chan_list(uint8_t *chan_list, struct gsm_bts *bts)
{
	const struct bitvec *bv = &bts->si_common.cell_alloc;

	/* generate a Frequency List from the Cell Allocation */
	return bitvec2freq_list(chan_list, bv, bts, false, false);
}

/*! generate a cell channel list as per Section 10.5.2.22 of 04.08
 *  \param[out] chan_list caller-provided output buffer
 *  \param[in] bts BTS descriptor used for input data
 *  \param[in] si5 Are we generating SI5xxx (true) or SI2xxx (false)
 *  \param[in] bis Are we generating SIXbis (true) or not (false)
 *  \param[in] ter Are we generating SIXter (true) or not (false)
 */
static int generate_bcch_chan_list(uint8_t *chan_list, struct gsm_bts *bts,
	bool si5, bool bis, bool ter)
{
	struct gsm_bts *cur_bts;
	struct bitvec *bv;
	int rc;

	/* first we generate a bitvec of the BCCH ARFCN's in our BSC */
	if (si5 && bts->neigh_list_manual_mode == NL_MODE_MANUAL_SI5SEP)
		bv = &bts->si_common.si5_neigh_list;
	else
		bv = &bts->si_common.neigh_list;

	/* Generate list of neighbor cells if we are in automatic mode */
	if (bts->neigh_list_manual_mode == NL_MODE_AUTOMATIC) {
		/* Zero-initialize the bit-vector */
		memset(bv->data, 0, bv->data_len);

		if (llist_empty(&bts->neighbors)) {
			/* There are no explicit neighbors, assume all BTS are. */
			llist_for_each_entry(cur_bts, &bts->network->bts_list, list) {
				if (cur_bts == bts)
					continue;
				bitvec_set_bit_pos(bv, cur_bts->c0->arfcn, 1);
			}
		} else {
			/* Only add explicit neighbor cells */
			struct neighbor *n;
			llist_for_each_entry(n, &bts->neighbors, entry) {
				if (n->type == NEIGHBOR_TYPE_CELL_ID && n->cell_id.ab_present) {
					bitvec_set_bit_pos(bv, n->cell_id.ab.arfcn, 1);
				} else {
					struct gsm_bts *neigh_bts;
					if (resolve_local_neighbor(&neigh_bts, bts, n)) {
						LOGP(DHO, LOGL_ERROR,
						     "Neither local nor remote neighbor: BTS %u -> %s\n",
						     bts->nr, neighbor_to_str_c(OTC_SELECT, n));
						continue;
					}
					if (neigh_bts->c0)
						bitvec_set_bit_pos(bv, neigh_bts->c0->arfcn, 1);
				}
			}
		}
	}

	/* then we generate a GSM 04.08 frequency list from the bitvec */
	rc = bitvec2freq_list(chan_list, bv, bts, bis, ter);
	if (rc < 0)
		return rc;

	/* Set BA-IND depending on whether we're generating SI2 or SI5.
	 * The point here is to be able to correlate whether a given MS
	 * measurement report was using the neighbor cells advertised in
	 * SI2 or in SI5, as those two could very well be different */
	if (si5)
		chan_list[0] |= 0x10;
	else
		chan_list[0] &= ~0x10;

	return rc;
}

static int list_arfcn(uint8_t *chan_list, uint8_t mask, char *text)
{
	int n = 0, i;
	struct gsm_sysinfo_freq freq[1024];

	memset(freq, 0, sizeof(freq));
	gsm48_decode_freq_list(freq, chan_list, 16, mask, 1);
	for (i = 0; i < 1024; i++) {
		if (freq[i].mask) {
			if (!n)
				LOGP(DRR, LOGL_INFO, "%s", text);
			LOGPC(DRR, LOGL_INFO, " %d", i);
			n++;
		}
	}
	if (n)
		LOGPC(DRR, LOGL_INFO, "\n");

	return n;
}

static int generate_si1(enum osmo_sysinfo_type t, struct gsm_bts *bts)
{
	int rc;
	struct gsm48_system_information_type_1 *si1 = (struct gsm48_system_information_type_1 *) GSM_BTS_SI(bts, t);

	memset(si1, GSM_MACBLOCK_PADDING, GSM_MACBLOCK_LEN);

	si1->header.l2_plen = GSM48_LEN2PLEN(21);
	si1->header.rr_protocol_discriminator = GSM48_PDISC_RR;
	si1->header.skip_indicator = 0;
	si1->header.system_information = GSM48_MT_RR_SYSINFO_1;

	rc = generate_cell_chan_list(si1->cell_channel_description, bts);
	if (rc < 0)
		return rc;
	list_arfcn(si1->cell_channel_description, 0xce, "Serving cell:");

	si1->rach_control = bts->si_common.rach_control;
	acc_mgr_apply_acc(&bts->acc_mgr, &si1->rach_control);

	/*
	 * SI1 Rest Octets (10.5.2.32), contains NCH position and band
	 * indicator but that is not in the 04.08.
	 */
	rc = osmo_gsm48_rest_octets_si1_encode(si1->rest_octets, NULL, is_dcs_net(bts));

	return sizeof(*si1) + rc;
}

static int generate_si2(enum osmo_sysinfo_type t, struct gsm_bts *bts)
{
	int rc;
	struct gsm48_system_information_type_2 *si2 = (struct gsm48_system_information_type_2 *) GSM_BTS_SI(bts, t);

	memset(si2, GSM_MACBLOCK_PADDING, GSM_MACBLOCK_LEN);

	si2->header.l2_plen = GSM48_LEN2PLEN(22);
	si2->header.rr_protocol_discriminator = GSM48_PDISC_RR;
	si2->header.skip_indicator = 0;
	si2->header.system_information = GSM48_MT_RR_SYSINFO_2;

	rc = generate_bcch_chan_list(si2->bcch_frequency_list, bts, false, false, false);
	if (rc < 0)
		return rc;
	list_arfcn(si2->bcch_frequency_list, 0xce,
		"SI2 Neighbour cells in same band:");

	si2->ncc_permitted = bts->si_common.ncc_permitted;
	si2->rach_control = bts->si_common.rach_control;
	acc_mgr_apply_acc(&bts->acc_mgr, &si2->rach_control);

	return sizeof(*si2);
}

/* Generate SI2bis Rest Octests 3GPP TS 44.018 Table 10.5.2.33.1 */
static int rest_octets_si2bis(uint8_t *data)
{
	struct bitvec bv;

	memset(&bv, 0, sizeof(bv));
	bv.data = data;
	bv.data_len = 1;

	bitvec_spare_padding(&bv, (bv.data_len * 8) - 1);

	return bv.data_len;
}

static int generate_si2bis(enum osmo_sysinfo_type t, struct gsm_bts *bts)
{
	int rc;
	struct gsm48_system_information_type_2bis *si2b =
		(struct gsm48_system_information_type_2bis *) GSM_BTS_SI(bts, t);
	int n;

	memset(si2b, GSM_MACBLOCK_PADDING, GSM_MACBLOCK_LEN);

	si2b->header.l2_plen = GSM48_LEN2PLEN(21);
	si2b->header.rr_protocol_discriminator = GSM48_PDISC_RR;
	si2b->header.skip_indicator = 0;
	si2b->header.system_information = GSM48_MT_RR_SYSINFO_2bis;

	rc = generate_bcch_chan_list(si2b->bcch_frequency_list, bts, false, true, false);
	if (rc < 0)
		return rc;
	n = list_arfcn(si2b->bcch_frequency_list, 0xce,
		"SI2bis Neighbour cells in same band, but outside P-GSM:");
	if (n) {
		/* indicate in SI2 and SI2bis: there is an extension */
		struct gsm48_system_information_type_2 *si2 =
			(struct gsm48_system_information_type_2 *) GSM_BTS_SI(bts, SYSINFO_TYPE_2);
		si2->bcch_frequency_list[0] |= 0x20;
		si2b->bcch_frequency_list[0] |= 0x20;
	} else
		bts->si_valid &= ~(1 << SYSINFO_TYPE_2bis);

	si2b->rach_control = bts->si_common.rach_control;
	acc_mgr_apply_acc(&bts->acc_mgr, &si2b->rach_control);

	/* SI2bis Rest Octets as per 3GPP TS 44.018 §10.5.2.33 */
	rc = rest_octets_si2bis(si2b->rest_octets);

	return sizeof(*si2b) + rc;
}


/* Generate SI2ter Rest Octests 3GPP TS 44.018 Table 10.5.2.33a.1 */
static int rest_octets_si2ter(uint8_t *data)
{
	struct bitvec bv;

	memset(&bv, 0, sizeof(bv));
	bv.data = data;
	bv.data_len = 4;

	/* No SI2ter_MP_CHANGE_MARK */
	bitvec_set_bit(&bv, L);

	bitvec_spare_padding(&bv, (bv.data_len * 8) - 1);

	return bv.data_len;
}

static int generate_si2ter(enum osmo_sysinfo_type t, struct gsm_bts *bts)
{
	int rc;
	struct gsm48_system_information_type_2ter *si2t =
		(struct gsm48_system_information_type_2ter *) GSM_BTS_SI(bts, t);
	int n;

	memset(si2t, GSM_MACBLOCK_PADDING, GSM_MACBLOCK_LEN);

	si2t->header.l2_plen = GSM48_LEN2PLEN(18);
	si2t->header.rr_protocol_discriminator = GSM48_PDISC_RR;
	si2t->header.skip_indicator = 0;
	si2t->header.system_information = GSM48_MT_RR_SYSINFO_2ter;

	rc = generate_bcch_chan_list(si2t->ext_bcch_frequency_list, bts, false, false, true);
	if (rc < 0)
		return rc;
	n = list_arfcn(si2t->ext_bcch_frequency_list, 0x8e,
		"SI2ter Neighbour cells in different band:");
	if (!n)
		bts->si_valid &= ~(1 << SYSINFO_TYPE_2ter);

	/* SI2ter Rest Octets as per 3GPP TS 44.018 §10.5.2.33a */
	rc = rest_octets_si2ter(si2t->rest_octets);

	return sizeof(*si2t) + rc;
}

/* SI2quater messages are optional - we only generate them when neighbor UARFCNs or EARFCNs are configured */
static inline bool si2quater_not_needed(struct gsm_bts *bts)
{
	unsigned i = MAX_EARFCN_LIST;

	if (bts->si_common.si2quater_neigh_list.arfcn)
		for (i = 0; i < MAX_EARFCN_LIST; i++)
			if (bts->si_common.si2quater_neigh_list.arfcn[i] != OSMO_EARFCN_INVALID)
				break;

	if (!bts->si_common.uarfcn_length && i == MAX_EARFCN_LIST) {
		bts->si_valid &= ~(1 << SYSINFO_TYPE_2quater); /* mark SI2q as invalid if no (E|U)ARFCNs are present */
		return true;
	}

	return false;
}

static int generate_si2quater(enum osmo_sysinfo_type t, struct gsm_bts *bts)
{
	int rc;
	struct gsm48_system_information_type_2quater *si2q;

	if (si2quater_not_needed(bts)) /* generate rest_octets for SI2q only when necessary */
		return GSM_MACBLOCK_LEN;

	bts->u_offset = 0;
	bts->e_offset = 0;
	bts->si2q_index = 0;
	bts->si2q_count = si2q_num(bts) - 1;

	rc = make_si2quaters(bts, false);
	if (rc < 0)
		return rc;

	OSMO_ASSERT(bts->si2q_count == bts->si2q_index);
	OSMO_ASSERT(bts->si2q_count <= SI2Q_MAX_NUM);

	return sizeof(*si2q) + rc;
}

static struct osmo_gsm48_si_ro_info si_info = {
	.selection_params = {
		.present = 0,
	},
	.power_offset = {
		.present = 0,
	},
	.si2ter_indicator = false,
	.early_cm_ctrl = true,
	.scheduling = {
		.present = 0,
	},
	.gprs_ind = {
		.si13_position = 0,
		.ra_colour = 0,
		.present = 1,
	},
	.early_cm_restrict_3g = false,
	.si2quater_indicator = false,
	.lsa_params = {
		.present = 0,
	},
	.cell_id = 0,	/* FIXME: doesn't the bts have this? */
	.break_ind = 0,
};

static int generate_si3(enum osmo_sysinfo_type t, struct gsm_bts *bts)
{
	int rc;
	struct gsm48_system_information_type_3 *si3 = (struct gsm48_system_information_type_3 *) GSM_BTS_SI(bts, t);

	memset(si3, GSM_MACBLOCK_PADDING, GSM_MACBLOCK_LEN);

	si3->header.l2_plen = GSM48_LEN2PLEN(18);
	si3->header.rr_protocol_discriminator = GSM48_PDISC_RR;
	si3->header.skip_indicator = 0;
	si3->header.system_information = GSM48_MT_RR_SYSINFO_3;

	/* The value in bts->si_common.chan_desc may get out of sync with the actual value
	 * in net->T_defs (e.g. after changing it via the VTY), so we need to sync it here. */
	bts->si_common.chan_desc.t3212 = osmo_tdef_get(bts->network->T_defs, 3212, OSMO_TDEF_CUSTOM, 0);

	si3->cell_identity = htons(bts->cell_identity);
	gsm48_generate_lai2(&si3->lai, bts_lai(bts));
	si3->control_channel_desc = bts->si_common.chan_desc;
	si3->cell_options = bts->si_common.cell_options;
	si3->cell_sel_par = bts->si_common.cell_sel_par;
	si3->rach_control = bts->si_common.rach_control;
	acc_mgr_apply_acc(&bts->acc_mgr, &si3->rach_control);

	/* allow/disallow DTXu */
	gsm48_set_dtx(&si3->cell_options, bts->dtxu, bts->dtxu, true);

	if (GSM_BTS_HAS_SI(bts, SYSINFO_TYPE_2ter)) {
		LOGP(DRR, LOGL_INFO, "SI 2ter is included.\n");
		si_info.si2ter_indicator = true;
	} else {
		si_info.si2ter_indicator = false;
	}
	if (GSM_BTS_HAS_SI(bts, SYSINFO_TYPE_2quater)) {
		LOGP(DRR, LOGL_INFO, "SI 2quater is included, based on %zu EARFCNs and %zu UARFCNs.\n",
		     si2q_earfcn_count(&bts->si_common.si2quater_neigh_list), bts->si_common.uarfcn_length);
		si_info.si2quater_indicator = true;
	} else {
		si_info.si2quater_indicator = false;
	}
	si_info.early_cm_ctrl = bts->early_classmark_allowed;
	si_info.early_cm_restrict_3g = !bts->early_classmark_allowed_3g;

	/* SI3 Rest Octets (10.5.2.34), containing
		CBQ, CELL_RESELECT_OFFSET, TEMPORARY_OFFSET, PENALTY_TIME
		Power Offset, 2ter Indicator, Early Classmark Sending,
		Scheduling if and WHERE, GPRS Indicator, SI13 position */
	rc = osmo_gsm48_rest_octets_si3_encode(si3->rest_octets, &si_info);

	return sizeof(*si3) + rc;
}

static int generate_si4(enum osmo_sysinfo_type t, struct gsm_bts *bts)
{
	int rc;
	struct gsm48_system_information_type_4 *si4 = (struct gsm48_system_information_type_4 *) GSM_BTS_SI(bts, t);
	struct gsm_lchan *cbch_lchan;
	uint8_t *tail = si4->data;

	/* length of all IEs present except SI4 rest octets and l2_plen */
	int l2_plen = sizeof(*si4) - 1;

	memset(si4, GSM_MACBLOCK_PADDING, GSM_MACBLOCK_LEN);

	si4->header.rr_protocol_discriminator = GSM48_PDISC_RR;
	si4->header.skip_indicator = 0;
	si4->header.system_information = GSM48_MT_RR_SYSINFO_4;

	gsm48_generate_lai2(&si4->lai, bts_lai(bts));
	si4->cell_sel_par = bts->si_common.cell_sel_par;
	si4->rach_control = bts->si_common.rach_control;
	acc_mgr_apply_acc(&bts->acc_mgr, &si4->rach_control);

	/* Optional: CBCH Channel Description + CBCH Mobile Allocation */
	cbch_lchan = gsm_bts_get_cbch(bts);
	if (cbch_lchan) {
		const struct gsm_bts_trx_ts *ts = cbch_lchan->ts;
		struct gsm48_chan_desc cd;

		/* 10.5.2.5 (TV) CBCH Channel Description IE.
		 * CBCH is never in VAMOS mode, so just pass allow_osmo_cbits == false. */
		if (gsm48_lchan_and_pchan2chan_desc(&cd, cbch_lchan, cbch_lchan->ts->pchan_from_config,
						    gsm_ts_tsc(cbch_lchan->ts), false))
			return -EINVAL;
		tail = tv_fixed_put(tail, GSM48_IE_CBCH_CHAN_DESC,
				    sizeof(cd), (uint8_t *) &cd);
		l2_plen += 1 + sizeof(cd);

		/* 10.5.2.21 (TLV) CBCH Mobile Allocation IE */
		if (ts->hopping.enabled) {
			/* Prevent potential buffer overflow */
			if (ts->hopping.ma_len > 2)
				return -ENOMEM;
			tail = tlv_put(tail, GSM48_IE_CBCH_MOB_AL,
				       ts->hopping.ma_len,
				       ts->hopping.ma_data);
			l2_plen += 2 + ts->hopping.ma_len;
		}
	}

	si4->header.l2_plen = GSM48_LEN2PLEN(l2_plen);

	/* SI4 Rest Octets (10.5.2.35), containing
		Optional Power offset, GPRS Indicator,
		Cell Identity, LSA ID, Selection Parameter */
	rc = osmo_gsm48_rest_octets_si4_encode(tail, &si_info, (uint8_t *)GSM_BTS_SI(bts, t) + GSM_MACBLOCK_LEN - tail);

	return l2_plen + 1 + rc;
}

static int generate_si5(enum osmo_sysinfo_type t, struct gsm_bts *bts)
{
	struct gsm48_system_information_type_5 *si5;
	uint8_t *output = GSM_BTS_SI(bts, t);
	int rc, l2_plen = 18;

	memset(output, GSM_MACBLOCK_PADDING, GSM_MACBLOCK_LEN);

	/* ip.access nanoBTS needs l2_plen!! */
	if (is_ipaccess_bts(bts)) {
		*output++ = GSM48_LEN2PLEN(l2_plen);
		l2_plen++;
	}

	si5 = (struct gsm48_system_information_type_5 *) output;

	/* l2 pseudo length, not part of msg: 18 */
	si5->rr_protocol_discriminator = GSM48_PDISC_RR;
	si5->skip_indicator = 0;
	si5->system_information = GSM48_MT_RR_SYSINFO_5;
	rc = generate_bcch_chan_list(si5->bcch_frequency_list, bts, true, false, false);
	if (rc < 0)
		return rc;
	list_arfcn(si5->bcch_frequency_list, 0xce,
		"SI5 Neighbour cells in same band:");

	/* 04.08 9.1.37: L2 Pseudo Length of 18 */
	return l2_plen;
}

static int generate_si5bis(enum osmo_sysinfo_type t, struct gsm_bts *bts)
{
	struct gsm48_system_information_type_5bis *si5b;
	uint8_t *output = GSM_BTS_SI(bts, t);
	int rc, l2_plen = 18;
	int n;

	memset(output, GSM_MACBLOCK_PADDING, GSM_MACBLOCK_LEN);

	/* ip.access nanoBTS needs l2_plen!! */
	if (is_ipaccess_bts(bts)) {
		*output++ = GSM48_LEN2PLEN(l2_plen);
		l2_plen++;
	}

	si5b = (struct gsm48_system_information_type_5bis *) output;

	/* l2 pseudo length, not part of msg: 18 */
	si5b->rr_protocol_discriminator = GSM48_PDISC_RR;
	si5b->skip_indicator = 0;
	si5b->system_information = GSM48_MT_RR_SYSINFO_5bis;
	rc = generate_bcch_chan_list(si5b->bcch_frequency_list, bts, true, true, false);
	if (rc < 0)
		return rc;
	n = list_arfcn(si5b->bcch_frequency_list, 0xce,
		"SI5bis Neighbour cells in same band, but outside P-GSM:");
	if (n) {
		/* indicate in SI5 and SI5bis: there is an extension */
		struct gsm48_system_information_type_5 *si5 =
			(struct gsm48_system_information_type_5 *) GSM_BTS_SI(bts, SYSINFO_TYPE_5)+1;
		si5->bcch_frequency_list[0] |= 0x20;
		si5b->bcch_frequency_list[0] |= 0x20;
	} else
		bts->si_valid &= ~(1 << SYSINFO_TYPE_5bis);

	/* 04.08 9.1.37: L2 Pseudo Length of 18 */
	return l2_plen;
}

static int generate_si5ter(enum osmo_sysinfo_type t, struct gsm_bts *bts)
{
	struct gsm48_system_information_type_5ter *si5t;
	uint8_t *output = GSM_BTS_SI(bts, t);
	int rc, l2_plen = 18;
	int n;

	memset(output, GSM_MACBLOCK_PADDING, GSM_MACBLOCK_LEN);

	/* ip.access nanoBTS needs l2_plen!! */
	if (is_ipaccess_bts(bts)) {
		*output++ = GSM48_LEN2PLEN(l2_plen);
		l2_plen++;
	}

	si5t = (struct gsm48_system_information_type_5ter *) output;

	/* l2 pseudo length, not part of msg: 18 */
	si5t->rr_protocol_discriminator = GSM48_PDISC_RR;
	si5t->skip_indicator = 0;
	si5t->system_information = GSM48_MT_RR_SYSINFO_5ter;
	rc = generate_bcch_chan_list(si5t->bcch_frequency_list, bts, true, false, true);
	if (rc < 0)
		return rc;
	n = list_arfcn(si5t->bcch_frequency_list, 0x8e,
		"SI5ter Neighbour cells in different band:");
	if (!n)
		bts->si_valid &= ~(1 << SYSINFO_TYPE_5ter);

	/* 04.08 9.1.37: L2 Pseudo Length of 18 */
	return l2_plen;
}

static int generate_si6(enum osmo_sysinfo_type t, struct gsm_bts *bts)
{
	struct gsm48_system_information_type_6 *si6;
	struct osmo_gsm48_si6_ro_info si6_ro_info;
	uint8_t *output = GSM_BTS_SI(bts, t);
	int l2_plen = 11;
	int rc;

	memset(output, GSM_MACBLOCK_PADDING, GSM_MACBLOCK_LEN);
	memset(&si6_ro_info, 0, sizeof(si6_ro_info));

	/* ip.access nanoBTS needs l2_plen!! */
	if (is_ipaccess_bts(bts)) {
		*output++ = GSM48_LEN2PLEN(l2_plen);
		l2_plen++;
	}

	si6 = (struct gsm48_system_information_type_6 *) output;

	/* l2 pseudo length, not part of msg: 11 */
	si6->rr_protocol_discriminator = GSM48_PDISC_RR;
	si6->skip_indicator = 0;
	si6->system_information = GSM48_MT_RR_SYSINFO_6;
	si6->cell_identity = htons(bts->cell_identity);
	gsm48_generate_lai2(&si6->lai, bts_lai(bts));
	si6->cell_options = bts->si_common.cell_options;
	si6->ncc_permitted = bts->si_common.ncc_permitted;
	/* allow/disallow DTXu */
	gsm48_set_dtx(&si6->cell_options, bts->dtxu, bts->dtxu, false);

	/* SI6 Rest Octets: 10.5.2.35a: PCH / NCH info, VBS/VGCS options */
	si6_ro_info.band_indicator_1900 = !is_dcs_net(bts);
	rc = osmo_gsm48_rest_octets_si6_encode(si6->rest_octets, &si6_ro_info);

	return l2_plen + rc;
}

static struct osmo_gsm48_si13_info si13_default = {
	.cell_opts = {
		.nmo 		= GPRS_NMO_II,
		.t3168		= 2000,
		.t3192		= 1500,
		.drx_timer_max	= 3,
		.bs_cv_max	= 15,
		.ctrl_ack_type_use_block = true,
		.ext_info_present = true,
		.ext_info = {
			.egprs_supported = 0,		/* overridden in gsm_generate_si() */
			.use_egprs_p_ch_req = 0,	/* overridden in generate_si13() */
			.bep_period = 5,
			.pfc_supported = 0,
			.dtm_supported = 0,
			.bss_paging_coordination = 0,	/* overridden in generate_si13() */
			.ccn_active = false,		/* overridden in generate_si13() */
		},
	},
	.pwr_ctrl_pars = {
		.alpha		= 0,	/* a = 0.0 */
		.t_avg_w	= 16,
		.t_avg_t	= 16,
		.pc_meas_chan	= 0, 	/* downling measured on CCCH */
		.n_avg_i	= 8,
	},
	.bcch_change_mark	= 1,
	.si_change_field	= 0,
	.rac		= 0,	/* needs to be patched */
	.spgc_ccch_sup 	= 0,
	.net_ctrl_ord	= 0,
	.prio_acc_thr	= 6,
};

static int generate_si13(enum osmo_sysinfo_type t, struct gsm_bts *bts)
{
	struct gsm48_system_information_type_13 *si13 =
		(struct gsm48_system_information_type_13 *) GSM_BTS_SI(bts, t);
	int ret;

	memset(si13, GSM_MACBLOCK_PADDING, GSM_MACBLOCK_LEN);

	si13->header.rr_protocol_discriminator = GSM48_PDISC_RR;
	si13->header.skip_indicator = 0;
	si13->header.system_information = GSM48_MT_RR_SYSINFO_13;

	si13_default.rac = bts->gprs.rac;
	si13_default.net_ctrl_ord = bts->gprs.net_ctrl_ord;

	si13_default.cell_opts.ctrl_ack_type_use_block =
		bts->gprs.ctrl_ack_type_use_block;

	/* Information about the other SIs */
	si13_default.bcch_change_mark = bts->bcch_change_mark;

	switch (bts->gprs.mode) {
	case BTS_GPRS_EGPRS:
		si13_default.cell_opts.ext_info.egprs_supported = 1;
		/* Whether EGPRS capable MSs shall use EGPRS PACKET CHANNEL REQUEST */
		if (bts->gprs.egprs_pkt_chan_request)
			si13_default.cell_opts.ext_info.use_egprs_p_ch_req = 1;
		else
			si13_default.cell_opts.ext_info.use_egprs_p_ch_req = 0;
		break;
	case BTS_GPRS_GPRS:
	case BTS_GPRS_NONE:
		si13_default.cell_opts.ext_info.egprs_supported = 0;
		si13_default.cell_opts.ext_info.use_egprs_p_ch_req = 0;
		break;
	}

	if (osmo_bts_has_feature(&bts->features, BTS_FEAT_PAGING_COORDINATION))
		si13_default.cell_opts.ext_info.bss_paging_coordination = 1;
	else
		si13_default.cell_opts.ext_info.bss_paging_coordination = 0;

	si13_default.cell_opts.ext_info.ccn_active = bts->gprs.ccn.forced_vty ?
						     bts->gprs.ccn.active :
						     osmo_bts_has_feature(&bts->model->features,
									  BTS_FEAT_CCN);
	si13_default.pwr_ctrl_pars.alpha = bts->gprs.pwr_ctrl.alpha;

	ret = osmo_gsm48_rest_octets_si13_encode(si13->rest_octets, &si13_default);
	if (ret < 0)
		return ret;

	/* length is coded in bit 2 an up */
	si13->header.l2_plen = 0x01;

	return sizeof (*si13) + ret;
}

typedef int (*gen_si_fn_t)(enum osmo_sysinfo_type t, struct gsm_bts *bts);

static const gen_si_fn_t gen_si_fn[_MAX_SYSINFO_TYPE] = {
	[SYSINFO_TYPE_1] = &generate_si1,
	[SYSINFO_TYPE_2] = &generate_si2,
	[SYSINFO_TYPE_2bis] = &generate_si2bis,
	[SYSINFO_TYPE_2ter] = &generate_si2ter,
	[SYSINFO_TYPE_2quater] = &generate_si2quater,
	[SYSINFO_TYPE_3] = &generate_si3,
	[SYSINFO_TYPE_4] = &generate_si4,
	[SYSINFO_TYPE_5] = &generate_si5,
	[SYSINFO_TYPE_5bis] = &generate_si5bis,
	[SYSINFO_TYPE_5ter] = &generate_si5ter,
	[SYSINFO_TYPE_6] = &generate_si6,
	[SYSINFO_TYPE_13] = &generate_si13,
};

int gsm_generate_si(struct gsm_bts *bts, enum osmo_sysinfo_type si_type)
{
	int rc;
	gen_si_fn_t gen_si;

	switch (bts->gprs.mode) {
	case BTS_GPRS_EGPRS:
	case BTS_GPRS_GPRS:
		si_info.gprs_ind.present = 1;
		break;
	case BTS_GPRS_NONE:
		si_info.gprs_ind.present = 0;
		break;
	}

	memcpy(&si_info.selection_params,
	       &bts->si_common.cell_ro_sel_par,
	       sizeof(struct osmo_gsm48_si_selection_params));

	gen_si = gen_si_fn[si_type];
	if (!gen_si) {
		LOGP(DRR, LOGL_ERROR, "bts %u: no gen_si_fn() for SI%s\n",
		     bts->nr, get_value_string(osmo_sitype_strs, si_type));
		return -EINVAL;
	}

	rc = gen_si(si_type, bts);
	if (rc < 0)
		LOGP(DRR, LOGL_ERROR, "bts %u: Error while generating SI%s: %s (%d)\n",
		     bts->nr, get_value_string(osmo_sitype_strs, si_type), strerror(-rc), rc);
	return rc;
}
