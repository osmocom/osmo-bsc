#pragma once

#include <stdbool.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>

struct gsm0808_channel_type;
struct gsm0808_speech_codec_list;
struct gsm_audio_support;
struct bts_codec_conf;
struct bsc_msc_data;
struct gsm_bts;
struct channel_mode_and_rate;

enum rate_pref {
	RATE_PREF_NONE,
	RATE_PREF_HR,
	RATE_PREF_FR,
};

int match_codec_pref(struct channel_mode_and_rate *ch_mode_rate,
		     const struct gsm0808_channel_type *ct,
		     const struct gsm0808_speech_codec_list *scl,
		     const struct bsc_msc_data *msc,
		     const struct gsm_bts *bts, enum rate_pref rate_pref);

void gen_bss_supported_codec_list(struct gsm0808_speech_codec_list *scl,
				  const struct bsc_msc_data *msc,
				  const struct gsm_bts *bts);

int calc_amr_rate_intersection(struct gsm48_multi_rate_conf *c,
			       const struct gsm48_multi_rate_conf *b,
			       const struct gsm48_multi_rate_conf *a);

int check_codec_pref(struct llist_head *mscs);
