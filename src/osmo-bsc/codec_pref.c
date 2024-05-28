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
#include <osmocom/mgcp_client/mgcp_client_fsm.h>
#include <osmocom/netif/rtp.h>
#include <osmocom/gsm/protocol/gsm_08_08.h>
#include <osmocom/gsm/gsm0808_utils.h>
#include <osmocom/bsc/bsc_msc_data.h>
#include <osmocom/bsc/codec_pref.h>
#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/bts.h>

/* Determine whether a permitted speech value is specifies a half rate or full
 * rate codec */
static int full_rate_from_perm_spch(bool * full_rate,
				    enum gsm0808_permitted_speech perm_spch)
{
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
		LOGP(DMSC, LOGL_ERROR, "Invalid permitted-speech value: %u\n",
		     perm_spch);
		return -EINVAL;
	}

	return 0;
}

/* Look up a matching chan mode for a given permitted speech value */
static enum gsm48_chan_mode gsm88_to_chan_mode(enum gsm0808_permitted_speech speech)
{
	switch (speech) {
	case GSM0808_PERM_HR1:
	case GSM0808_PERM_FR1:
		return GSM48_CMODE_SPEECH_V1;
		break;
	case GSM0808_PERM_FR2:
		return GSM48_CMODE_SPEECH_EFR;
		break;
	case GSM0808_PERM_HR3:
	case GSM0808_PERM_FR3:
		return GSM48_CMODE_SPEECH_AMR;
		break;
	case GSM0808_PERM_HR2:
		LOGP(DMSC, LOGL_FATAL, "Speech HR2 was never specified!\n");
		/* fall through */
	default:
		LOGP(DMSC, LOGL_FATAL, "Unsupported permitted speech %s selected, "
		     "assuming AMR as channel mode...\n",
		     gsm0808_permitted_speech_name(speech));
		return GSM48_CMODE_SPEECH_AMR;
	}
}

/* Look up a matching permitted speech value for a given msc audio codec pref */
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

/* Test if a given audio support matches one of the permitted speech settings
 * of the channel type element. The matched permitted speech value is then also
 * compared against the speech codec list. (optional, only relevant for AoIP) */
static bool test_codec_pref(const struct gsm0808_speech_codec **sc_match,
			    const struct gsm0808_speech_codec_list *scl,
			    const struct gsm0808_channel_type *ct,
			    uint8_t perm_spch)
{
	unsigned int i;
	bool match = false;
	struct gsm0808_speech_codec sc;
	int rc;

	LOGP(DLGLOBAL, LOGL_NOTICE, "%s(perm_spch=0x%x)\n", __func__, perm_spch);

	*sc_match = NULL;

	/* Try to find the given permitted speech value in the
	 * codec list of the channel type element */
	for (i = 0; i < ct->perm_spch_len; i++) {
		LOGP(DLGLOBAL, LOGL_NOTICE, "  channel_type->perm_spch[%d] = 0x%x\n", i, ct->perm_spch[i]);

		if (ct->perm_spch[i] == perm_spch) {
			LOGP(DLGLOBAL, LOGL_NOTICE, "    MATCH\n");
			match = true;
			break;
		}
	}

	/* If we do not have a speech codec list to test against,
	 * we just exit early (will be always the case in non-AoIP networks) */
	if (!scl || !scl->len) {
		LOGP(DLGLOBAL, LOGL_NOTICE, "!scl\n");
		return match;
	}

	/* If we failed to match until here, there is no
	 * point in testing further */
	if (match == false) {
		LOGP(DLGLOBAL, LOGL_NOTICE, "!match\n");
		return false;
	}

	/* Extrapolate speech codec data */
	rc = gsm0808_speech_codec_from_chan_type(&sc, perm_spch);
	if (rc < 0) {
		LOGP(DLGLOBAL, LOGL_NOTICE, "gsm0808_speech_codec_from_chan_type(0x%x) rc = %d\n", perm_spch, rc);
		return false;
	}

	/* Try to find extrapolated speech codec data in
	 * the speech codec list */
	LOGP(DLGLOBAL, LOGL_NOTICE, "looking for %s in scl:\n",
	     gsm0808_speech_codec_type_name(sc.type));
	for (i = 0; i < scl->len; i++) {
		LOGP(DLGLOBAL, LOGL_NOTICE, "  scl->codec[%d] = %s cfg=0x%x\n", i,
		     gsm0808_speech_codec_type_name(scl->codec[i].type), scl->codec[i].cfg);
		if (sc.type == scl->codec[i].type) {
			*sc_match = &scl->codec[i];
			LOGP(DLGLOBAL, LOGL_NOTICE, "    MATCH\n");
			return true;
		}
	}

	return false;
}

static bool test_codec_support_bts_rate(const struct gsm_bts *bts, const bool full_rate)
{
	unsigned int i;
	struct gsm_bts_trx *trx;

	llist_for_each_entry(trx, &bts->trx_list, list) {
		for (i = 0; i < TRX_NR_TS; i++) {
			switch (trx->ts[i].pchan_from_config) {
			case GSM_PCHAN_OSMO_DYN:
				return true;
			case GSM_PCHAN_TCH_F:
			case GSM_PCHAN_TCH_F_PDCH:
				if (full_rate)
					return true;
				break;
			case GSM_PCHAN_TCH_H:
				if (!full_rate)
					return true;
				break;
			default:
				continue;
			}
		}
	}

	return false;
}

/* Check if the given permitted speech value is supported by the BTS
 * (vty option bts->codec-support). */
static bool test_codec_support_bts(const struct gsm_bts *bts, uint8_t perm_spch)
{
	const struct bts_codec_conf *bts_codec = &bts->codec;
	bool full_rate;
	int rc;
	LOGP(DLGLOBAL, LOGL_NOTICE, "   test_codec_support_bts(0x%x)\n", perm_spch);

	/* Check if the BTS provides a physical channel that matches the
	 * bandwidth of the desired codec. */
	rc = full_rate_from_perm_spch(&full_rate, perm_spch);
	if (rc < 0)
		return false;
	if (!test_codec_support_bts_rate(bts, full_rate)) {
		LOGP(DLGLOBAL, LOGL_ERROR, "   test_codec_support_bts_rate(full_rate=%d) failed\n", full_rate);
		return false;
	}

	/* Check codec support */
	switch (perm_spch) {
	case GSM0808_PERM_FR1:
		/* GSM-FR is always supported by all BTSs. There is also no way to
		 * selectively disable GSM-RF per BTS via VTY. */
		return true;
	case GSM0808_PERM_FR2:
		LOGP(DLGLOBAL, LOGL_NOTICE, "bts_codec->efr == %u\n", bts_codec->efr);
		return (bool)bts_codec->efr;
	case GSM0808_PERM_FR3:
	case GSM0808_PERM_HR3:
		LOGP(DLGLOBAL, LOGL_NOTICE, "bts_codec->amr == %u\n", bts_codec->amr);
		return (bool)bts_codec->amr;
	case GSM0808_PERM_HR1:
		LOGP(DLGLOBAL, LOGL_NOTICE, "bts_codec->hr == %u\n", bts_codec->hr);
		return (bool)bts_codec->hr;
	default:
		LOGP(DLGLOBAL, LOGL_NOTICE, "   unsupported Permitted Speech 0x%x\n", perm_spch);
		return false;
	}
}

static uint8_t multi_rate_conf_to_amr_modes(const struct gsm48_multi_rate_conf *cfg)
{
	return ((uint8_t *)cfg)[1];
}

/* Set all Sn bits that have *all* their rates allowed in the gsm48_multi_rate_conf. */
static uint16_t sc_cfg_from_gsm48_mr_cfg(const struct gsm48_multi_rate_conf *cfg, bool fr)
{
	uint16_t s15_s0 = 0;
	int s_bit;
	uint8_t cfg_modes = multi_rate_conf_to_amr_modes(cfg);
	for (s_bit = 0; s_bit < 16; s_bit++) {
		uint8_t s_bit_modes = gsm0808_amr_modes_from_cfg[fr ? 1 : 0][s_bit];
		if (s_bit_modes && (cfg_modes & s_bit_modes) == s_bit_modes)
			s15_s0 |= (1 << s_bit);
	}
	return s15_s0;
}

/* Generate the bss supported amr configuration bits (S0-S15) */
static uint16_t gen_bss_supported_amr_s15_s0(const struct bsc_msc_data *msc, const struct gsm_bts *bts, bool hr)
{
	const struct gsm48_multi_rate_conf *amr_cfg_bts;
	const struct gsm48_multi_rate_conf *amr_cfg_msc;
	uint16_t amr_s15_s0_bts;
	uint16_t amr_s15_s0_msc;
	LOGP(DLGLOBAL, LOGL_NOTICE, "%s(hr=%d)\n", __func__, hr);

	/* Lookup the BTS specific AMR rate configuration. This config is set
	 * via the VTY for each BTS individually. In cases where no configuration
	 * is set we will assume a safe default */
	if (hr)
		amr_cfg_bts = (struct gsm48_multi_rate_conf *)&bts->mr_half.gsm48_ie;
	else
		amr_cfg_bts = (struct gsm48_multi_rate_conf *)&bts->mr_full.gsm48_ie;
	amr_s15_s0_bts = sc_cfg_from_gsm48_mr_cfg(amr_cfg_bts, !hr);
	LOGP(DLGLOBAL, LOGL_NOTICE, "  amr_s15_s0_bts = %x\n", amr_s15_s0_bts);

	/* Lookup the AMR rate configuration that is set for the MSC */
	amr_cfg_msc = &msc->amr_conf;
	amr_s15_s0_msc = sc_cfg_from_gsm48_mr_cfg(amr_cfg_msc, !hr);
	LOGP(DLGLOBAL, LOGL_NOTICE, "  amr_s15_s0_msc = %x\n", amr_s15_s0_msc);

	/* Calculate the intersection of the two configurations and update S0-S15
	 * in the codec list. */
	LOGP(DLGLOBAL, LOGL_NOTICE, " return %x\n", amr_s15_s0_bts & amr_s15_s0_msc);
	return amr_s15_s0_bts & amr_s15_s0_msc;
}

/* Special handling for AMR rate configuration bits (S15-S0) */
static int match_amr_s15_s0(struct channel_mode_and_rate *ch_mode_rate, const struct bsc_msc_data *msc, const struct gsm_bts *bts, const struct gsm0808_speech_codec *sc_match, uint8_t perm_spch)
{
	uint16_t amr_s15_s0_supported;
	LOGP(DLGLOBAL, LOGL_NOTICE, "match_amr_s15_s0()\n");

	/* Normally the MSC should never try to advertise an AMR codec
	 * configuration that we did not previously advertised as supported.
	 * However, to ensure that no unsupported AMR codec configuration
	 * enters the further processing steps we again lookup what we support
	 * and generate an intersection. All further processing is then done
	 * with this intersection result. At the same time we will make sure
	 * that the intersection contains at least one rate setting. */

	amr_s15_s0_supported = gen_bss_supported_amr_s15_s0(msc, bts, (perm_spch == GSM0808_PERM_HR3));
	LOGP(DLGLOBAL, LOGL_NOTICE, "amr_s15_s0_supported = %x\n", amr_s15_s0_supported);

	/* NOTE: The sc_match pointer points to a speech codec from the speech
	 * codec list that has been communicated with the ASSIGNMENT COMMAND.
	 * However, only AoIP based networks will include a speech codec list
	 * into the ASSIGNMENT COMMAND. For non AoIP based networks, no speech
	 * codec (sc_match) will be available, so we will fully rely on the
	 * local configuration for those cases. */
	if (sc_match)
		ch_mode_rate->s15_s0 = sc_match->cfg & amr_s15_s0_supported;
	else
		ch_mode_rate->s15_s0 = amr_s15_s0_supported;
	LOGP(DLGLOBAL, LOGL_NOTICE, "ch_mode_rate->s15_s0 = %x\n", ch_mode_rate->s15_s0);

	/* Make sure at least one rate is set. */
	if (!ch_mode_rate->s15_s0) {
		LOGP(DLGLOBAL, LOGL_ERROR, "%s(): no rates\n", __func__);
		return -EINVAL;
	}

	return 0;
}

/*! Match the codec preferences from local config with codec preference IEs
 * received from the MSC and the BTS' codec configuration.
 *  \param[out] ch_mode_rate resulting codec and rate information
 *  \param[in] ct GSM 08.08 channel type received from MSC.
 *  \param[in] scl GSM 08.08 speech codec list received from MSC (optional).
 *  \param[in] msc associated msc (current codec settings).
 *  \param[in] bts associated bts (current codec settings).
 *  \param[in] pref selected rate preference (full, half or none).
 *  \returns 0 on success, -1 in case no match was found */
int match_codec_pref(struct channel_mode_and_rate *ch_mode_rate,
		     const struct gsm0808_channel_type *ct,
		     const struct gsm0808_speech_codec_list *scl,
		     const struct bsc_msc_data *msc,
		     const struct gsm_bts *bts, enum rate_pref rate_pref)
{
	unsigned int i;
	uint8_t perm_spch;
	bool full_rate;
	bool match = false;
	const struct gsm0808_speech_codec *sc_match = NULL;
	int rc;

	LOGP(DLGLOBAL, LOGL_NOTICE, "%s()\n", __func__);

	/* Note: Normally the MSC should never try to advertise a codec that
	 * we did not advertise as supported before. In order to ensure that
	 * no unsupported codec is accepted, we make sure that the codec is
	 * indeed available with the current BTS and MSC configuration */
	for (i = 0; i < msc->audio_length; i++) {
		/* Pick a permitted speech value from the global codec configuration list */
		perm_spch = audio_support_to_gsm88(&msc->audio_support[i]);
		LOGP(DLGLOBAL, LOGL_NOTICE, " [%d] perm_spch=0x%x\n", i, perm_spch);

		/* Determine if the result is a half or full rate codec */
		rc = full_rate_from_perm_spch(&full_rate, perm_spch);
		if (rc < 0)
			return -EINVAL;
		ch_mode_rate->chan_rate = full_rate ? CH_RATE_FULL : CH_RATE_HALF;

		/* If we have a preference for FR or HR in our request, we
		 * discard the potential match */
		LOGP(DLGLOBAL, LOGL_NOTICE, "   rate_pref=%d chan_rate=%d\n", rate_pref, ch_mode_rate->chan_rate);
		if (rate_pref == RATE_PREF_HR && ch_mode_rate->chan_rate == CH_RATE_FULL)
			continue;
		if (rate_pref == RATE_PREF_FR && ch_mode_rate->chan_rate == CH_RATE_HALF)
			continue;
		LOGP(DLGLOBAL, LOGL_NOTICE, "   rate_pref=%d chan_rate=%d ok\n", rate_pref, ch_mode_rate->chan_rate);

		/* Check this permitted speech value against the BTS specific parameters.
		 * if the BTS does not support the codec, try the next one */
		if (!test_codec_support_bts(bts, perm_spch))
			continue;
		LOGP(DLGLOBAL, LOGL_NOTICE, "   test_codec_support_bts() ok\n");

		/* Match the permitted speech value against the codec lists that were
		 * advertised by the MS and the MSC */
		if (!test_codec_pref(&sc_match, scl, ct, perm_spch))
			continue;
		LOGP(DLGLOBAL, LOGL_NOTICE, "   test_codec_pref() ok\n");

		/* Special handling for AMR */
		if (perm_spch == GSM0808_PERM_HR3 || perm_spch == GSM0808_PERM_FR3) {
			rc = match_amr_s15_s0(ch_mode_rate, msc, bts, sc_match, perm_spch);
			if (rc < 0) {
				ch_mode_rate->s15_s0 = 0;
				continue;
			}
		} else
			ch_mode_rate->s15_s0 = 0;

		LOGP(DLGLOBAL, LOGL_NOTICE, "   match_amr_s15_s0() ok\n");
		match = true;
		break;
	}

	/* Exit without result, in case no match can be detected */
	if (!match) {
		ch_mode_rate->chan_mode = GSM48_CMODE_SIGN;
		ch_mode_rate->chan_rate = CH_RATE_SDCCH;
		ch_mode_rate->s15_s0 = 0;
		return -1;
	}

	/* Lookup a channel mode for the selected codec */
	ch_mode_rate->chan_mode = gsm88_to_chan_mode(perm_spch);

	return 0;
}

/*! Determine the BSS supported speech codec list that is sent to the MSC with
 * the COMPLETE LAYER 3 INFORMATION message.
 *  \param[out] scl GSM 08.08 speech codec list with BSS supported codecs.
 *  \param[in] msc associated msc (current codec settings).
 *  \param[in] bts associated bts (current codec settings). */
void gen_bss_supported_codec_list(struct gsm0808_speech_codec_list *scl,
				  const struct bsc_msc_data *msc, const struct gsm_bts *bts)
{
	uint8_t perm_spch;
	unsigned int i;
	int rc;

	memset(scl, 0, sizeof(*scl));

	for (i = 0; i < msc->audio_length; i++) {

		/* Pick a permitted speech value from the global codec configuration list */
		perm_spch = audio_support_to_gsm88(&msc->audio_support[i]);

		/* Check this permitted speech value against the BTS specific parameters.
		 * if the BTS does not support the codec, try the next one */
		if (!test_codec_support_bts(bts, perm_spch))
			continue;

		/* Write item into codec list */
		rc = gsm0808_speech_codec_from_chan_type(&scl->codec[scl->len], perm_spch);
		if (rc != 0)
			continue;

		/* AMR (HR/FR version 3) is the only codec that requires a codec
		 * configuration (S0-S15). Determine the current configuration and update
		 * the cfg flag. */
		if (msc->audio_support[i].ver == 3)
			scl->codec[scl->len].cfg = gen_bss_supported_amr_s15_s0(msc, bts, msc->audio_support[i].hr);

		scl->len++;
	}
}

/*! Calculate the intersection of the rate configuration of two multirate configuration
 *  IE structures. The result c will be a copy of a, but the rate configuration bits
 *  will be the intersection of the rate configuration bits in a and b.
 *  \param[out] c user provided memory to store the result.
 *  \param[in] a multi rate configuration a.
 *  \param[in] b multi rate configuration b.
 *  \returns 0 on success, -1 when the result contains an empty set of modes. */
int calc_amr_rate_intersection(struct gsm48_multi_rate_conf *c,
			       const struct gsm48_multi_rate_conf *b,
			       const struct gsm48_multi_rate_conf *a)
{
	struct gsm48_multi_rate_conf res;
	uint8_t *_a = (uint8_t *) a;
	uint8_t *_b = (uint8_t *) b;
	uint8_t *_res = (uint8_t *) & res;

	memcpy(&res, a, sizeof(res));

	_res[1] = _a[1] & _b[1];

	if (_res[1] == 0x00)
		return -1;

	if (c)
		memcpy(c, &res, sizeof(*c));

	return 0;
}

/*! Visit the codec settings for the MSC and for each BTS in order to make sure
 *  that the configuration does not contain any combinations that lead into a
 *  mutually exclusive codec configuration (empty intersection).
 *  \param[in] mscs list head of the msc list.
 *  \returns 0 on success, -1 in case an invalid setting is found. */
int check_codec_pref(struct llist_head *mscs)
{
	struct bsc_msc_data *msc;
	struct gsm_bts *bts;
	struct gsm0808_speech_codec_list scl;
	int rc = 0;
	int rc_rate;
	const struct gsm48_multi_rate_conf *bts_gsm48_ie;

	llist_for_each_entry(msc, mscs, entry) {
		llist_for_each_entry(bts, &msc->network->bts_list, list) {
			gen_bss_supported_codec_list(&scl, msc, bts);
			if (scl.len <= 0) {
				LOGP(DMSC, LOGL_FATAL,
				     "codec-support/trx config of BTS %u does not intersect with codec-list of MSC %u\n",
				     bts->nr, msc->nr);
				rc = -1;
			}

			/* Full rate codec check, only if any full rate TS is configured. */
			if (test_codec_support_bts_rate(bts, true)) {
				bts_gsm48_ie = (struct gsm48_multi_rate_conf *)&bts->mr_full.gsm48_ie;
				rc_rate = calc_amr_rate_intersection(NULL, &msc->amr_conf, bts_gsm48_ie);
				if (rc_rate < 0) {
					LOGP(DMSC, LOGL_FATAL,
					     "network amr tch-f mode config of BTS %u does not intersect with amr-config of MSC %u\n",
					     bts->nr, msc->nr);
					rc = -1;
				}
			}

			/* Half rate codec check, only if any half rate TS is configured. */
			if (test_codec_support_bts_rate(bts, false)) {
				bts_gsm48_ie = (struct gsm48_multi_rate_conf *)&bts->mr_half.gsm48_ie;
				rc_rate = calc_amr_rate_intersection(NULL, &msc->amr_conf, bts_gsm48_ie);
				if (rc_rate < 0) {
					LOGP(DMSC, LOGL_FATAL,
					     "network amr tch-h mode config of BTS %u does not intersect with amr-config of MSC %u\n",
					     bts->nr, msc->nr);
					rc = -1;
				}
			}
		}
	}

	return rc;
}
