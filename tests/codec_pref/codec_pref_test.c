/*
 * (C) 2018 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
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

#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/osmo_bsc.h>
#include <osmocom/bsc/bsc_msc_data.h>
#include <osmocom/bsc/gsm_04_80.h>
#include <osmocom/core/application.h>
#include <osmocom/bsc/codec_pref.h>

#include <stdio.h>

void *ctx = NULL;

#define MSC_AUDIO_SUPPORT_MAX 5
#define N_CONFIG_VARIANTS 9

/* Make sure that there is some memory to put our test configuration. */
static void init_msc_config(struct bsc_msc_data *msc)
{
	unsigned int i;

	msc->audio_support = talloc_zero_array(ctx, struct gsm_audio_support *, MSC_AUDIO_SUPPORT_MAX);
	msc->audio_length = MSC_AUDIO_SUPPORT_MAX;
	for (i = 0; i < MSC_AUDIO_SUPPORT_MAX; i++) {
		msc->audio_support[i] = talloc_zero(msc->audio_support, struct gsm_audio_support);
	}
}

/* Free memory that we have used for the test configuration. */
static void free_msc_config(struct bsc_msc_data *msc)
{
	talloc_free(msc->audio_support);
}

/* The speech codec list is sent by the MS and lists the voice codec settings
 * that the MS is able to support. The BSC must select one of this codecs
 * depending on what the MSC is able to support. The following function
 * generates some realistically made up speech codec lists. */
static void make_scl_config(struct gsm0808_speech_codec_list *scl, uint8_t config_no)
{
	OSMO_ASSERT(config_no < N_CONFIG_VARIANTS);

	switch (config_no) {
	case 0:
		/* FR1 only */
		scl->codec[0].type = GSM0808_SCT_FR1;
		scl->len = 1;
		break;
	case 1:
		/* HR1 only */
		scl->codec[0].type = GSM0808_SCT_HR1;
		scl->len = 1;
		break;
	case 2:
		/* FR2 only */
		scl->codec[0].type = GSM0808_SCT_FR2;
		scl->len = 1;
		break;
	case 3:
		/* FR3 only */
		scl->codec[0].type = GSM0808_SCT_FR3;
		scl->codec[0].cfg = GSM0808_SC_CFG_DEFAULT_FR_AMR;
		scl->len = 1;
		break;
	case 4:
		/* HR3 only */
		scl->codec[0].type = GSM0808_SCT_HR3;
		scl->codec[0].cfg = GSM0808_SC_CFG_DEFAULT_HR_AMR;
		scl->len = 1;
		break;
	case 5:
		/* FR1 and HR1 */
		scl->codec[0].type = GSM0808_SCT_FR1;
		scl->codec[1].type = GSM0808_SCT_HR1;
		scl->len = 2;
		break;
	case 6:
		/* FR1, FR2 and HR1 */
		scl->codec[0].type = GSM0808_SCT_FR1;
		scl->codec[1].type = GSM0808_SCT_FR2;
		scl->codec[2].type = GSM0808_SCT_HR1;
		scl->len = 3;
		break;
	case 7:
		/* FR1, FR3 and HR3 */
		scl->codec[0].type = GSM0808_SCT_FR1;
		scl->codec[1].type = GSM0808_SCT_FR3;
		scl->codec[1].cfg = GSM0808_SC_CFG_DEFAULT_FR_AMR;
		scl->codec[2].type = GSM0808_SCT_HR3;
		scl->codec[2].cfg = GSM0808_SC_CFG_DEFAULT_HR_AMR;
		scl->len = 3;
		break;
	case 8:
		/* FR1, FR2, FR3, HR1 and HR3 */
		scl->codec[0].type = GSM0808_SCT_FR1;
		scl->codec[1].type = GSM0808_SCT_FR2;
		scl->codec[2].type = GSM0808_SCT_FR3;
		scl->codec[2].cfg = GSM0808_SC_CFG_DEFAULT_FR_AMR;
		scl->codec[3].type = GSM0808_SCT_HR1;
		scl->codec[4].type = GSM0808_SCT_HR3;
		scl->codec[4].cfg = GSM0808_SC_CFG_DEFAULT_HR_AMR;
		scl->len = 5;
		break;
	}
}

/* The channel type element which is sent to the BSC by the MSC lists all the
 * codecs that the MSC is able to support. The following function generates
 * a realistic permitted speech settings */
static void make_ct_config(struct gsm0808_channel_type *ct, uint8_t config_no)
{
	OSMO_ASSERT(config_no < N_CONFIG_VARIANTS);

	switch (config_no) {
	case 0:
		/* FR1 only */
		ct->perm_spch[0] = GSM0808_PERM_FR1;
		ct->perm_spch_len = 1;
		break;
	case 1:
		/* HR1 only */
		ct->perm_spch[0] = GSM0808_PERM_HR1;
		ct->perm_spch_len = 1;
		break;
	case 2:
		/* FR2 only */
		ct->perm_spch[0] = GSM0808_PERM_FR2;
		ct->perm_spch_len = 1;
		break;
	case 3:
		/* FR3 only */
		ct->perm_spch[0] = GSM0808_PERM_FR3;
		ct->perm_spch_len = 1;
		break;
	case 4:
		/* HR3 only */
		ct->perm_spch[0] = GSM0808_PERM_HR3;
		ct->perm_spch_len = 1;
		break;
	case 5:
		/* FR1 and HR1 */
		ct->perm_spch[0] = GSM0808_PERM_FR1;
		ct->perm_spch[1] = GSM0808_PERM_HR1;
		ct->perm_spch_len = 2;
		break;
	case 6:
		/* FR1, FR2 and HR1 */
		ct->perm_spch[0] = GSM0808_PERM_FR1;
		ct->perm_spch[1] = GSM0808_PERM_FR2;
		ct->perm_spch[2] = GSM0808_PERM_HR1;
		ct->perm_spch_len = 3;
		break;
	case 7:
		/* FR1, FR3 and HR3 */
		ct->perm_spch[0] = GSM0808_PERM_FR1;
		ct->perm_spch[1] = GSM0808_PERM_FR3;
		ct->perm_spch[2] = GSM0808_PERM_HR3;
		ct->perm_spch_len = 3;
		break;
	case 8:
		/* FR1, FR2, FR3, HR1 and HR3 */
		ct->perm_spch[0] = GSM0808_PERM_FR1;
		ct->perm_spch[1] = GSM0808_PERM_FR2;
		ct->perm_spch[2] = GSM0808_PERM_FR3;
		ct->perm_spch[3] = GSM0808_PERM_HR1;
		ct->perm_spch[4] = GSM0808_PERM_HR3;
		ct->perm_spch_len = 5;
		break;
	}
}

/* Generate some realistic MSC configuration which one also could find in the
 * real world. This configuration acts as a filter. While the MSC could in
 * theory advertise codecs more codecs as we are able to support we have to
 * make sure that only the codecs we have support for are considered. */
static void make_msc_config(struct bsc_msc_data *msc, uint8_t config_no)
{
	/* 1 = FR1/HR1
	 * 2 = FR2/HR2
	 * 3 = FR2/HR3
	 * Note: HR2 is deprecated */

	OSMO_ASSERT(config_no < N_CONFIG_VARIANTS);

	/* Setup an AMR configuration, this configuration is separate and does
	 * not influence other codecs than AMR */
	msc->amr_conf.m4_75 = 1;
	msc->amr_conf.m5_15 = 1;
	msc->amr_conf.m5_90 = 1;
	msc->amr_conf.m6_70 = 1;
	msc->amr_conf.m7_40 = 1;
	msc->amr_conf.m7_95 = 1;
	msc->amr_conf.m10_2 = 1;
	msc->amr_conf.m12_2 = 1;

	switch (config_no) {
	case 0:
		/* FR1 only */
		msc->audio_support[0]->ver = 1;
		msc->audio_support[0]->hr = 0;
		msc->audio_length = 1;
		break;
	case 1:
		/* HR1 only */
		msc->audio_support[0]->ver = 1;
		msc->audio_support[0]->hr = 1;
		msc->audio_length = 1;
		break;
	case 2:
		/* FR2 only */
		msc->audio_support[0]->ver = 2;
		msc->audio_support[0]->hr = 0;
		msc->audio_length = 1;
		break;
	case 3:
		/* FR3 only */
		msc->audio_support[0]->ver = 3;
		msc->audio_support[0]->hr = 0;
		msc->audio_length = 1;
		break;
	case 4:
		/* HR3 only */
		msc->audio_support[0]->ver = 3;
		msc->audio_support[0]->hr = 1;
		msc->audio_length = 1;
		break;
	case 5:
		/* FR1 and HR1 */
		msc->audio_support[0]->ver = 1;
		msc->audio_support[0]->hr = 0;
		msc->audio_support[1]->ver = 1;
		msc->audio_support[1]->hr = 1;
		msc->audio_length = 2;
		break;
	case 6:
		/* FR1, FR2 and HR1 */
		msc->audio_support[0]->ver = 1;
		msc->audio_support[0]->hr = 0;
		msc->audio_support[1]->ver = 2;
		msc->audio_support[1]->hr = 0;
		msc->audio_support[2]->ver = 1;
		msc->audio_support[2]->hr = 1;
		msc->audio_length = 3;
		break;
	case 7:
		/* FR1, FR3 and HR3 */
		msc->audio_support[0]->ver = 1;
		msc->audio_support[0]->hr = 0;
		msc->audio_support[1]->ver = 3;
		msc->audio_support[1]->hr = 0;
		msc->audio_support[2]->ver = 3;
		msc->audio_support[2]->hr = 1;
		msc->audio_length = 3;
		break;
	case 8:
		/* FR1, FR2, FR3, HR1 and HR3 */
		msc->audio_support[0]->ver = 1;
		msc->audio_support[0]->hr = 0;
		msc->audio_support[1]->ver = 2;
		msc->audio_support[1]->hr = 0;
		msc->audio_support[2]->ver = 3;
		msc->audio_support[2]->hr = 0;
		msc->audio_support[3]->ver = 1;
		msc->audio_support[3]->hr = 1;
		msc->audio_support[4]->ver = 3;
		msc->audio_support[4]->hr = 1;
		msc->audio_length = 5;
		break;
	}
}

/* Generate a realitically looking bts codec configuration */
static void make_bts_config(struct gsm_bts *bts, uint8_t config_no)
{
	/* Note: FR is supported by all BTSs, so there is no flag for it */

	struct gsm48_multi_rate_conf *cfg;
	static struct gsm_bts_trx trx;

	OSMO_ASSERT(config_no < N_CONFIG_VARIANTS);

	bts->codec.hr = 0;
	bts->codec.efr = 0;
	bts->codec.amr = 0;
	memset(&bts->mr_full.gsm48_ie, 0, sizeof(bts->mr_full.gsm48_ie));
	memset(&bts->mr_full.gsm48_ie, 0, sizeof(bts->mr_half.gsm48_ie));

	/* Setup an AMR configuration, this configuration is separate and does
	 * not influence other codecs than AMR */
	cfg = (struct gsm48_multi_rate_conf*) &bts->mr_full.gsm48_ie;
	cfg->m4_75 = 1;
	cfg->m5_15 = 1;
	cfg->m5_90 = 1;
	cfg->m6_70 = 1;
	cfg->m7_40 = 1;
	cfg->m7_95 = 1;
	cfg->m10_2 = 1;
	cfg->m12_2 = 1;
	cfg = (struct gsm48_multi_rate_conf*) &bts->mr_half.gsm48_ie;
	cfg->m4_75 = 1;
	cfg->m5_15 = 1;
	cfg->m5_90 = 1;
	cfg->m6_70 = 1;
	cfg->m7_40 = 1;
	cfg->m7_95 = 1;
	cfg->m10_2 = 0;
	cfg->m12_2 = 0;

	/* Initalize TRX with a TCH/F and a TCH/H channel */
	memset(&trx, 0, sizeof(trx));
	INIT_LLIST_HEAD(&bts->trx_list);
	llist_add(&trx.list, &bts->trx_list);
	trx.ts[0].pchan_from_config = GSM_PCHAN_TCH_F;
	trx.ts[1].pchan_from_config = GSM_PCHAN_TCH_H;

	switch (config_no) {
	case 0:
		/* FR1 (implicit) only */
		break;
	case 1:
		/* HR1 only (+FR implicit) */
		bts->codec.hr = 1;
		break;
	case 2:
		/* FR2 only (+FR implicit)  */
		bts->codec.efr = 1;
		break;
	case 3:
		/* FR3 only (+FR implicit) */
		bts->codec.amr = 1;
		break;
	case 4:
		/* HR3 only (+FR implicit) */
		bts->codec.amr = 1;
		break;
	case 5:
		/* FR1 (implicit) and HR1 */
		bts->codec.hr = 1;
		break;
	case 6:
		/* FR1 (implicit), FR2 and HR1 */
		bts->codec.efr = 1;
		bts->codec.hr = 1;
		break;
	case 7:
		/* FR1 (implicit), FR3 and HR3 */
		bts->codec.amr = 1;
		break;
	case 8:
		/* FR1 (implicit), FR2, FR3, HR1 and HR3 */
		bts->codec.hr = 1;
		bts->codec.efr = 1;
		bts->codec.amr = 1;
		break;
	}
}

/* Try execute match_codec_pref(), display input and output parameters */
static int test_match_codec_pref(const struct gsm0808_channel_type *ct, const struct gsm0808_speech_codec_list *scl,
				 const struct bsc_msc_data *msc, struct gsm_bts *bts)
{
	int rc;
	unsigned int i;
	struct channel_mode_and_rate ch_mode_rate = { };

	printf("Determining channel mode and rate:\n");

	printf(" * MS: speech codec list (%u items):\n", scl->len);
	for (i = 0; i < scl->len; i++)
		printf("   codec[%u]->type=%s\n", i, gsm0808_speech_codec_type_name(scl->codec[i].type));

	printf(" * MSC: channel type permitted speech (%u items):\n", ct->perm_spch_len);
	for (i = 0; i < ct->perm_spch_len; i++)
		printf("   perm_spch[%u]=%s\n", i, gsm0808_permitted_speech_name(ct->perm_spch[i]));

	printf(" * BSS: audio support settings (%u items):\n", msc->audio_length);
	for (i = 0; i < msc->audio_length; i++)
		if (msc->audio_support[i]->hr)
			printf("   audio_support[%u]=HR%u\n", i, msc->audio_support[i]->ver);
		else
			printf("   audio_support[%u]=FR%u\n", i, msc->audio_support[i]->ver);

	printf(" * BTS: audio support settings:\n");
	printf("   (GSM-FR implicitly supported)\n");
	printf("   codec->hr=%u\n", bts->codec.hr);
	printf("   codec->efr=%u\n", bts->codec.efr);
	printf("   codec->amr=%u\n", bts->codec.amr);

	rc = match_codec_pref(&ch_mode_rate, ct, scl, msc, bts, RATE_PREF_NONE);
	printf(" * result: rc=%i, full_rate=%i, s15_s0=%04x, chan_mode=%s\n",
	       rc, ch_mode_rate.chan_rate == CH_RATE_FULL, ch_mode_rate.s15_s0, gsm48_chan_mode_name(ch_mode_rate.chan_mode));

	printf("\n");

	return rc;
}

/* MS, MSC and local MSC settings are the same */
static void test_one_to_one(void)
{
	unsigned int i;
	struct gsm0808_channel_type ct_msc;
	struct gsm0808_speech_codec_list scl_ms;
	struct bsc_msc_data msc_local;
	struct gsm_bts bts_local;
	int rc;

	printf("============== test_one_to_one ==============\n\n");

	init_msc_config(&msc_local);

	for (i = 0; i < N_CONFIG_VARIANTS; i++) {
		make_msc_config(&msc_local, i);
		make_scl_config(&scl_ms, i);
		make_ct_config(&ct_msc, i);
		make_bts_config(&bts_local, i);
		rc = test_match_codec_pref(&ct_msc, &scl_ms, &msc_local, &bts_local);
		OSMO_ASSERT(rc == 0);
	}

	free_msc_config(&msc_local);
}

/* Network supports all combinations, MS varies */
static void test_ms(void)
{
	unsigned int i;
	struct gsm0808_channel_type ct_msc;
	struct gsm0808_speech_codec_list scl_ms;
	struct bsc_msc_data msc_local;
	struct gsm_bts bts_local;
	int rc;

	printf("============== test_ms ==============\n\n");

	init_msc_config(&msc_local);

	make_msc_config(&msc_local, 8);
	make_ct_config(&ct_msc, 8);
	make_bts_config(&bts_local, 8);
	for (i = 0; i < N_CONFIG_VARIANTS; i++) {
		make_scl_config(&scl_ms, i);
		rc = test_match_codec_pref(&ct_msc, &scl_ms, &msc_local, &bts_local);
		OSMO_ASSERT(rc == 0);
	}

	free_msc_config(&msc_local);
}

/* BSS and MS support all combinations, MSC varies */
static void test_ct(void)
{
	unsigned int i;
	struct gsm0808_channel_type ct_msc;
	struct gsm0808_speech_codec_list scl_ms;
	struct bsc_msc_data msc_local;
	struct gsm_bts bts_local;
	int rc;

	printf("============== test_ct ==============\n\n");

	init_msc_config(&msc_local);

	make_msc_config(&msc_local, 8);
	make_scl_config(&scl_ms, 8);
	make_bts_config(&bts_local, 8);
	for (i = 0; i < N_CONFIG_VARIANTS; i++) {
		make_ct_config(&ct_msc, i);
		rc = test_match_codec_pref(&ct_msc, &scl_ms, &msc_local, &bts_local);
		OSMO_ASSERT(rc == 0);
	}

	free_msc_config(&msc_local);
}

/* MSC and MS support all combinations, BSS varies */
static void test_msc(void)
{
	unsigned int i;
	struct gsm0808_channel_type ct_msc;
	struct gsm0808_speech_codec_list scl_ms;
	struct bsc_msc_data msc_local;
	struct gsm_bts bts_local;
	int rc;

	printf("============== test_msc ==============\n\n");

	init_msc_config(&msc_local);

	make_ct_config(&ct_msc, 8);
	make_scl_config(&scl_ms, 8);
	make_bts_config(&bts_local, 8);
	for (i = 0; i < N_CONFIG_VARIANTS; i++) {
		make_msc_config(&msc_local, 8);
		rc = test_match_codec_pref(&ct_msc, &scl_ms, &msc_local, &bts_local);
		OSMO_ASSERT(rc == 0);
	}

	free_msc_config(&msc_local);
}

/* Some mixed configurations that are supposed to work */
static void test_selected_working(void)
{
	struct gsm0808_channel_type ct_msc;
	struct gsm0808_speech_codec_list scl_ms;
	struct bsc_msc_data msc_local;
	struct gsm_bts bts_local;
	int rc;

	printf("============== test_selected_working ==============\n\n");

	init_msc_config(&msc_local);

	make_scl_config(&scl_ms, 6);
	make_ct_config(&ct_msc, 5);
	make_msc_config(&msc_local, 7);
	make_bts_config(&bts_local, 8);
	rc = test_match_codec_pref(&ct_msc, &scl_ms, &msc_local, &bts_local);
	OSMO_ASSERT(rc == 0);

	make_scl_config(&scl_ms, 0);
	make_ct_config(&ct_msc, 5);
	make_msc_config(&msc_local, 7);
	make_bts_config(&bts_local, 8);
	rc = test_match_codec_pref(&ct_msc, &scl_ms, &msc_local, &bts_local);
	OSMO_ASSERT(rc == 0);

	make_scl_config(&scl_ms, 1);
	make_ct_config(&ct_msc, 5);
	make_msc_config(&msc_local, 6);
	make_bts_config(&bts_local, 8);
	rc = test_match_codec_pref(&ct_msc, &scl_ms, &msc_local, &bts_local);
	OSMO_ASSERT(rc == 0);

	make_scl_config(&scl_ms, 6);
	make_ct_config(&ct_msc, 5);
	make_msc_config(&msc_local, 7);
	make_bts_config(&bts_local, 4);
	rc = test_match_codec_pref(&ct_msc, &scl_ms, &msc_local, &bts_local);
	OSMO_ASSERT(rc == 0);

	make_scl_config(&scl_ms, 0);
	make_ct_config(&ct_msc, 5);
	make_msc_config(&msc_local, 7);
	make_bts_config(&bts_local, 2);
	rc = test_match_codec_pref(&ct_msc, &scl_ms, &msc_local, &bts_local);
	OSMO_ASSERT(rc == 0);

	make_scl_config(&scl_ms, 1);
	make_ct_config(&ct_msc, 5);
	make_msc_config(&msc_local, 6);
	make_bts_config(&bts_local, 1);
	rc = test_match_codec_pref(&ct_msc, &scl_ms, &msc_local, &bts_local);
	OSMO_ASSERT(rc == 0);

	free_msc_config(&msc_local);
}

/* Some mixed configurations that can not work */
static void test_selected_non_working(void)
{
	struct gsm0808_channel_type ct_msc;
	struct gsm0808_speech_codec_list scl_ms;
	struct bsc_msc_data msc_local;
	struct gsm_bts bts_local;
	int rc;

	printf("============== test_selected_non_working ==============\n\n");

	init_msc_config(&msc_local);

	make_scl_config(&scl_ms, 1);
	make_ct_config(&ct_msc, 5);
	make_msc_config(&msc_local, 7);
	make_bts_config(&bts_local, 8);
	rc = test_match_codec_pref(&ct_msc, &scl_ms, &msc_local, &bts_local);
	OSMO_ASSERT(rc == -1);

	make_scl_config(&scl_ms, 1);
	make_ct_config(&ct_msc, 5);
	make_msc_config(&msc_local, 7);
	make_bts_config(&bts_local, 8);
	rc = test_match_codec_pref(&ct_msc, &scl_ms, &msc_local, &bts_local);
	OSMO_ASSERT(rc == -1);

	make_scl_config(&scl_ms, 1);
	make_ct_config(&ct_msc, 4);
	make_msc_config(&msc_local, 6);
	make_bts_config(&bts_local, 8);
	rc = test_match_codec_pref(&ct_msc, &scl_ms, &msc_local, &bts_local);
	OSMO_ASSERT(rc == -1);

	make_scl_config(&scl_ms, 1);
	make_ct_config(&ct_msc, 2);
	make_msc_config(&msc_local, 7);
	make_bts_config(&bts_local, 8);
	rc = test_match_codec_pref(&ct_msc, &scl_ms, &msc_local, &bts_local);
	OSMO_ASSERT(rc == -1);

	make_scl_config(&scl_ms, 1);
	make_ct_config(&ct_msc, 5);
	make_msc_config(&msc_local, 4);
	make_bts_config(&bts_local, 8);
	rc = test_match_codec_pref(&ct_msc, &scl_ms, &msc_local, &bts_local);
	OSMO_ASSERT(rc == -1);

	make_scl_config(&scl_ms, 8);
	make_ct_config(&ct_msc, 4);
	make_msc_config(&msc_local, 6);
	make_bts_config(&bts_local, 7);
	rc = test_match_codec_pref(&ct_msc, &scl_ms, &msc_local, &bts_local);
	OSMO_ASSERT(rc == -1);

	free_msc_config(&msc_local);
}

/* Try execute bss_supp_codec_list(), display input and output parameters */
static void test_gen_bss_supported_codec_list(const struct bsc_msc_data *msc, struct gsm_bts *bts)
{
	unsigned int i;
	struct gsm0808_speech_codec_list scl;

	printf("Determining Codec List (BSS Supported):\n");

	printf(" * BSS: audio support settings (%u items):\n", msc->audio_length);
	for (i = 0; i < msc->audio_length; i++)
		if (msc->audio_support[i]->hr)
			printf("   audio_support[%u]=HR%u\n", i, msc->audio_support[i]->ver);
		else
			printf("   audio_support[%u]=FR%u\n", i, msc->audio_support[i]->ver);

	printf(" * BTS: audio support settings:\n");
	printf("   (GSM-FR implicitly supported)\n");
	printf("   codec->hr=%u\n", bts->codec.hr);
	printf("   codec->efr=%u\n", bts->codec.efr);
	printf("   codec->amr=%u\n", bts->codec.amr);

	gen_bss_supported_codec_list(&scl, msc, bts);

	printf(" * result: speech codec list (%u items):\n", scl.len);
	for (i = 0; i < scl.len; i++) {
		printf("   codec[%u]->type=%s", i, gsm0808_speech_codec_type_name(scl.codec[i].type));
		if (msc->audio_support[i]->ver == 3)
			printf(" S15-S0=%04x", scl.codec[i].cfg);
		printf("\n");
	}
	printf("\n");
}

/* Test gen_bss_supported_codec_list() with some mixed configurations */
static void test_gen_bss_supported_codec_list_cfgs(void)
{
	struct bsc_msc_data msc_local;
	struct gsm_bts bts_local;
	uint8_t i;
	uint8_t k;

	printf("============== test_gen_bss_supp_codec_list_cfgs ==============\n\n");
	init_msc_config(&msc_local);

	for (i = 0; i < N_CONFIG_VARIANTS; i++) {
		for (k = 0; k < N_CONFIG_VARIANTS; k++) {
			make_msc_config(&msc_local, i);
			make_bts_config(&bts_local, k);
			printf("MSC config: %u, BTS config: %u\n", i, k);
			test_gen_bss_supported_codec_list(&msc_local, &bts_local);
		}
	}

	free_msc_config(&msc_local);
}

static const struct log_info_cat log_categories[] = {
	[DMSC] = {
		  .name = "DMSC",
		  .description = "Mobile Switching Center",
		  .enabled = 1,.loglevel = LOGL_NOTICE,
		  },
};

static const struct log_info log_info = {
	.cat = log_categories,
	.num_cat = ARRAY_SIZE(log_categories),
};

int main(int argc, char **argv)
{
	ctx = talloc_named_const(NULL, 0, "codec_pref_test");
	msgb_talloc_ctx_init(ctx, 0);
	osmo_init_logging2(ctx, &log_info);

	test_one_to_one();
	test_ms();
	test_ct();
	test_msc();
	test_selected_working();
	test_selected_non_working();
	test_gen_bss_supported_codec_list_cfgs();

	printf("Testing execution completed.\n");
	talloc_free(ctx);
	return 0;
}
