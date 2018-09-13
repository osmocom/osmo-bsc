#pragma once

#include <stdbool.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>

struct gsm0808_channel_type;
struct gsm0808_speech_codec_list;
struct gsm_audio_support;
struct bts_codec_conf;
struct bsc_msc_data;
struct gsm_bts;

int match_codec_pref(enum gsm48_chan_mode *chan_mode,
		     bool *full_rate,
		     const struct gsm0808_channel_type *ct,
		     const struct gsm0808_speech_codec_list *scl,
		     struct gsm_audio_support * const *audio_support,
		     int audio_length,
		     const struct bts_codec_conf *bts_codec);

void gen_bss_supported_codec_list(struct gsm0808_speech_codec_list *scl,
				  const struct bsc_msc_data *msc,
				  const struct gsm_bts *bts);
