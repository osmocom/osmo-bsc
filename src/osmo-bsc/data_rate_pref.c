/*
 * (C) 2023 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Oliver Smith
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

#include <osmocom/gsm/protocol/gsm_08_08.h>
#include <osmocom/gsm/protocol/gsm_08_58.h>
#include <osmocom/bsc/data_rate_pref.h>
#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/lchan.h>

static int gsm0808_data_rate_transp_to_gsm0858(enum gsm0808_data_rate_transp rate)
{
	switch (rate) {
	case GSM0808_DATA_RATE_TRANSP_32000:
		return RSL_CMOD_CSD_T_32000;
	case GSM0808_DATA_RATE_TRANSP_28800:
		return RSL_CMOD_CSD_T_29000;
	case GSM0808_DATA_RATE_TRANSP_14400:
		return RSL_CMOD_CSD_T_14400;
	case GSM0808_DATA_RATE_TRANSP_09600:
		return RSL_CMOD_CSD_T_9600;
	case GSM0808_DATA_RATE_TRANSP_04800:
		return RSL_CMOD_CSD_T_4800;
	case GSM0808_DATA_RATE_TRANSP_02400:
		return RSL_CMOD_CSD_T_2400;
	case GSM0808_DATA_RATE_TRANSP_01200:
		return RSL_CMOD_CSD_T_1200;
	case GSM0808_DATA_RATE_TRANSP_00600:
		return RSL_CMOD_CSD_T_600;
	case GSM0808_DATA_RATE_TRANSP_01200_75:
		return RSL_CMOD_CSD_T_1200_75;
	default:
		LOGP(DMSC, LOGL_ERROR, "Unsupported transparent data rate 0x%x\n", rate);
		return -1;
	}
}

static int gsm0808_data_rate_transp_to_gsm0408(enum gsm0808_data_rate_transp rate)
{
	switch (rate) {
	case GSM0808_DATA_RATE_TRANSP_14400:
		return GSM48_CMODE_DATA_14k5;
	case GSM0808_DATA_RATE_TRANSP_09600:
		return GSM48_CMODE_DATA_12k0;
	case GSM0808_DATA_RATE_TRANSP_04800:
		return GSM48_CMODE_DATA_6k0;
	case GSM0808_DATA_RATE_TRANSP_02400:
	case GSM0808_DATA_RATE_TRANSP_01200:
	case GSM0808_DATA_RATE_TRANSP_00600:
	case GSM0808_DATA_RATE_TRANSP_01200_75:
		return GSM48_CMODE_DATA_3k6;
	default:
		LOGP(DMSC, LOGL_ERROR, "Unsupported transparent data rate 0x%x\n", rate);
		return -1;
	}
}

static int gsm0808_data_rate_non_transp_to_gsm0408(enum gsm0808_data_rate_non_transp rate)
{
	LOGP(DMSC, LOGL_ERROR, "%s is not implemented\n", __func__); /* FIXME */
	return -1;
}

static int gsm0808_data_rate_non_transp_to_gsm0858(enum gsm0808_data_rate_non_transp rate, bool full_rate)
{
	switch (rate) {
	case GSM0808_DATA_RATE_NON_TRANSP_12000_6000:
		if (full_rate)
			return RSL_CMOD_CSD_NT_12k0;
		return RSL_CMOD_CSD_NT_6k0;
	case GSM0808_DATA_RATE_NON_TRANSP_14500:
		return RSL_CMOD_CSD_NT_14k5;
	case GSM0808_DATA_RATE_NON_TRANSP_12000:
		return RSL_CMOD_CSD_NT_12k0;
	case GSM0808_DATA_RATE_NON_TRANSP_06000:
		return RSL_CMOD_CSD_NT_6k0;
	case GSM0808_DATA_RATE_NON_TRANSP_43500:
		return RSL_CMOD_CSD_NT_43k5;
	case GSM0808_DATA_RATE_NON_TRANSP_29000:
		return RSL_CMOD_CSD_NT_28k8;
	default:
		LOGP(DMSC, LOGL_ERROR, "Unsupported non-transparent data rate 0x%x\n", rate);
		return -1;
	}
}

static enum gsm48_chan_mode match_non_transp_data_rate(const struct gsm0808_channel_type *ct, bool full_rate)
{
	/* FIXME: Handle ct->data_rate_allowed too if it is set. Find the best
	 * match by comparing the preferred ct->data_rate + all allowed
	 * ct->data_rate_allowed against what's most suitable for the BTS. */

	return gsm0808_data_rate_non_transp_to_gsm0858(ct->data_rate, full_rate);
}

/*! Match the GSM 08.08 channel type received from the MSC to suitable data for
 * the BTS, the GSM 04.08 channel mode, channel rate (FR/HR) and GSM 08.58
 * data rate.
 *  \param[out] ch_mode_rate resulting channel rate, channel mode and data rate
 *  \param[in] ct GSM 08.08 channel type received from MSC.
 *  \param[in] full_rate true means FR is preferred, false means HR
 *  \returns 0 on success, -1 in case no match was found */
int match_data_rate_pref(struct channel_mode_and_rate *ch_mode_rate,
			 const struct gsm0808_channel_type *ct,
			 const bool full_rate)
{
	int rc;
	*ch_mode_rate = (struct channel_mode_and_rate){};
	ch_mode_rate->chan_rate = full_rate ? CH_RATE_FULL : CH_RATE_HALF;
	ch_mode_rate->data_transparent = ct->data_transparent;

	if (ct->data_transparent) {
		rc = gsm0808_data_rate_transp_to_gsm0858(ct->data_rate);
		if (rc == -1)
			return -1;
		ch_mode_rate->data_rate.t = rc;

		rc = gsm0808_data_rate_transp_to_gsm0408(ct->data_rate);
		if (rc == -1)
			return -1;
		ch_mode_rate->chan_mode = rc;
	} else {
		rc = match_non_transp_data_rate(ct, full_rate);
		if (rc == -1)
			return -1;
		ch_mode_rate->data_rate.nt = rc;

		rc = gsm0808_data_rate_non_transp_to_gsm0408(ct->data_rate);
		if (rc == -1)
			return -1;
		ch_mode_rate->chan_mode = rc;
	}

	return 0;
}
