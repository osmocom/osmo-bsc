/* (C) 2009-2011 by Holger Hans Peter Freyther <zecke@selfish.org>
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

#include <osmocom/gsm/gsm48.h>

#include <osmocom/bsc/osmo_bsc.h>
#include <osmocom/bsc/bsc_msc_data.h>
#include <osmocom/bsc/gsm_04_08_rr.h>
#include <osmocom/bsc/bsc_subscriber.h>
#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/paging.h>
#include <osmocom/bsc/gsm_04_08_rr.h>
#include <osmocom/bsc/bts.h>

#include <stdlib.h>

static int bsc_patch_mm_info(struct gsm_subscriber_connection *conn,
		uint8_t *data, unsigned int length)
{
	struct tlv_parsed tp;
	int parse_res;
	int tzunits;
	uint8_t tzbsd = 0;
	uint8_t dst = 0;

	/* Is TZ patching enabled? */
	struct gsm_tz *tz = &conn->network->tz;
	if (!tz->override)
		return 0;

	parse_res = tlv_parse(&tp, &gsm48_mm_att_tlvdef, data, length, 0, 0);
	if (parse_res <= 0 && parse_res != -3)
		/* FIXME: -3 means unknown IE error, so this accepts messages
		 * with unknown IEs. But parsing has aborted with the unknown
		 * IE and the message is broken or parsed incompletely. */
		return 0;

	/* Convert tz.hr and tz.mn to units */
	if (tz->hr < 0) {
		tzunits = -tz->hr*4;
		tzbsd |= 0x08;
	} else
		tzunits = tz->hr*4;

	tzunits = tzunits + (tz->mn/15);

	tzbsd |= (tzunits % 10)*0x10 + (tzunits / 10);

	/* Convert DST value */
	if (tz->dst >= 0 && tz->dst <= 2)
		dst = tz->dst;

	if (TLVP_PRESENT(&tp, GSM48_IE_UTC)) {
		LOGP(DMSC, LOGL_DEBUG,
			"Changing 'Local time zone' from 0x%02x to 0x%02x.\n",
			TLVP_VAL(&tp, GSM48_IE_UTC)[6], tzbsd);
		((uint8_t *)(TLVP_VAL(&tp, GSM48_IE_UTC)))[0] = tzbsd;
	}
	if (TLVP_PRESENT(&tp, GSM48_IE_NET_TIME_TZ)) {
		LOGP(DMSC, LOGL_DEBUG,
			"Changing 'Universal time and local time zone' TZ from "
			"0x%02x to 0x%02x.\n",
			TLVP_VAL(&tp, GSM48_IE_NET_TIME_TZ)[6], tzbsd);
		((uint8_t *)(TLVP_VAL(&tp, GSM48_IE_NET_TIME_TZ)))[6] = tzbsd;
	}
#ifdef GSM48_IE_NET_DST
	if (TLVP_PRESENT(&tp, GSM48_IE_NET_DST)) {
		LOGP(DMSC, LOGL_DEBUG,
			"Changing 'Network daylight saving time' from "
			"0x%02x to 0x%02x.\n",
			TLVP_VAL(&tp, GSM48_IE_NET_DST)[0], dst);
		((uint8_t *)(TLVP_VAL(&tp, GSM48_IE_NET_DST)))[0] = dst;
	}
#endif

	return 0;
}

/**
 * Messages coming back from the MSC.
 */
int bsc_scan_msc_msg(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	struct gsm48_hdr *gh;
	uint8_t pdisc;
	uint8_t mtype;
	int length = msgb_l3len(msg);

	if (length < sizeof(*gh)) {
		LOGP(DMSC, LOGL_ERROR, "GSM48 header does not fit.\n");
		return -1;
	}

	gh = (struct gsm48_hdr *) msgb_l3(msg);
	length -= (const char *)&gh->data[0] - (const char *)gh;

	pdisc = gsm48_hdr_pdisc(gh);
	if (pdisc != GSM48_PDISC_MM)
		return 0;

	mtype = gsm48_hdr_msg_type(gh);
	if (mtype == GSM48_MT_MM_INFO) {
		bsc_patch_mm_info(conn, &gh->data[0], length);
	}

	if (conn && conn->lchan) {
		struct rate_ctr_group *bts_ctrs = conn->lchan->ts->trx->bts->bts_ctrs;
		switch (mtype) {
		case GSM48_MT_MM_LOC_UPD_ACCEPT:
			rate_ctr_inc(rate_ctr_group_get_ctr(bts_ctrs, BTS_CTR_LOCATION_UPDATE_ACCEPT));
			break;
		case GSM48_MT_MM_LOC_UPD_REJECT:
			rate_ctr_inc(rate_ctr_group_get_ctr(bts_ctrs, BTS_CTR_LOCATION_UPDATE_REJECT));
			break;
		case GSM48_MT_MM_IMSI_DETACH_IND:
			rate_ctr_inc(rate_ctr_group_get_ctr(bts_ctrs, BTS_CTR_LOCATION_UPDATE_DETACH));
			break;
		default:
			rate_ctr_inc(rate_ctr_group_get_ctr(bts_ctrs, BTS_CTR_LOCATION_UPDATE_UNKNOWN));
			break;
		}
	}

	return 0;
}
