/*
 * (C) 2017-2018 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Philipp Maier
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

#include <osmocom/core/msgb.h>
#include <osmocom/gsm/gsm0808_utils.h>
#include <osmocom/bsc/bsc_msc_data.h>
#include <osmocom/bsc/codec_pref.h>
#include <osmocom/bsc/gsm_data.h>

/* Helper function for match_codec_pref(), looks up a matching chan mode for
 * a given permitted speech value */
static enum gsm48_chan_mode gsm88_to_chan_mode(enum gsm0808_permitted_speech speech)
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
		LOGP(DMSC, LOGL_FATAL, "Unsupported permitted speech selected, assuming AMR as channel mode...\n");
		return GSM48_CMODE_SPEECH_AMR;
	}
}

/* Helper function for match_codec_pref(), looks up a matching permitted speech
 * value for a given msc audio codec pref */
static enum gsm0808_permitted_speech audio_support_to_gsm88(const struct gsm_audio_support *audio)
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
			LOGP(DMSC, LOGL_ERROR, "Wrong speech mode: hr%d, using hr1 instead\n", audio->ver);
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
			LOGP(DMSC, LOGL_ERROR, "Wrong speech mode: fr%d, using fr1 instead\n", audio->ver);
			return GSM0808_PERM_FR1;
		}
	}
}

/* Helper function for match_codec_pref(), tests if a given audio support
 * matches one of the permitted speech settings of the channel type element.
 * The matched permitted speech value is then also compared against the
 * speech codec list. (optional, only relevant for AoIP) */
static bool test_codec_pref(const struct gsm0808_channel_type *ct,
			    const struct gsm0808_speech_codec_list *scl, uint8_t perm_spch)
{
	unsigned int i;
	bool match = false;
	struct gsm0808_speech_codec sc;
	int rc;

	/* Try to find the given permitted speech value in the
	 * codec list of the channel type element */
	for (i = 0; i < ct->perm_spch_len; i++) {
		if (ct->perm_spch[i] == perm_spch) {
			match = true;
			break;
		}
	}

	/* If we do not have a speech codec list to test against,
	 * we just exit early (will be always the case in non-AoIP networks) */
	if (!scl || !scl->len)
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

/* Helper function to check if the given permitted speech value is supported
 * by the BTS. (vty option bts->codec-support). */
static bool test_codec_support_bts(const struct bts_codec_conf *bts_codec, uint8_t perm_spch)
{
	switch (perm_spch) {
	case GSM0808_PERM_FR1:
		/* GSM-FR is always supported by all BTSs. There is also no way to
		 * selectively disable GSM-RF per BTS via VTY. */
		return true;
	case GSM0808_PERM_FR2:
		if (bts_codec->efr)
			return true;
	case GSM0808_PERM_FR3:
		if (bts_codec->amr)
			return true;
	case GSM0808_PERM_HR1:
		if (bts_codec->hr)
			return true;
	case GSM0808_PERM_HR3:
		if (bts_codec->amr)
			return true;
	default:
		return false;
	}

	return false;
}

/*! Match the codec preferences from local config with a received codec preferences IEs received from the
 * MSC and the BTS' codec configuration.
 *  \param[out] chan_mode GSM 04.08 channel mode.
 *  \param[out] full_rate true iff full-rate.
 *  \param[in] ct GSM 08.08 channel type received from MSC.
 *  \param[in] scl GSM 08.08 speech codec list received from MSC (optional).
 *  \param[in] audio_support List of allowed codecs as from local config.
 *  \param[in] audio_length Number of items in audio_support.
 *  \param[in] bts_codec BTS codec configuration.
 *  \returns 0 on success, -1 in case no match was found */
int match_codec_pref(enum gsm48_chan_mode *chan_mode,
		     bool *full_rate,
		     const struct gsm0808_channel_type *ct,
		     const struct gsm0808_speech_codec_list *scl,
		     struct gsm_audio_support * const *audio_support,
		     int audio_length,
		     const struct bts_codec_conf *bts_codec)
{
	unsigned int i;
	uint8_t perm_spch;
	bool match = false;

	for (i = 0; i < audio_length; i++) {
		/* Pick a permitted speech value from the global codec configuration list */
		perm_spch = audio_support_to_gsm88(audio_support[i]);

		/* Check this permitted speech value against the BTS specific parameters.
		 * if the BTS does not support the codec, try the next one */
		if (!test_codec_support_bts(bts_codec, perm_spch))
			continue;

		/* Match the permitted speech value against the codec lists that were
		 * advertised by the MS and the MSC */
		if (test_codec_pref(ct, scl, perm_spch)) {
			match = true;
			break;
		}
	}

	/* Exit without result, in case no match can be deteched */
	if (!match) {
		*full_rate = false;
		*chan_mode = GSM48_CMODE_SIGN;
		return -1;
	}

	/* Check if the result is a half or full rate codec */
	switch (perm_spch) {
	case GSM0808_PERM_HR1:
	case GSM0808_PERM_HR2:
	case GSM0808_PERM_HR3:
	case GSM0808_PERM_HR4:
	case GSM0808_PERM_HR6:
		*full_rate = false;
		break;

	case GSM0808_PERM_FR1:
	case GSM0808_PERM_FR2:
	case GSM0808_PERM_FR3:
	case GSM0808_PERM_FR4:
	case GSM0808_PERM_FR5:
		*full_rate = true;
		break;

	default:
		LOGP(DMSC, LOGL_ERROR, "Invalid permitted-speech value: %u\n", perm_spch);
		return -EINVAL;
	}

	/* Lookup a channel mode for the selected codec */
	*chan_mode = gsm88_to_chan_mode(perm_spch);

	return 0;
}
