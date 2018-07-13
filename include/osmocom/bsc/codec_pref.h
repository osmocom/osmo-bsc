#pragma once

struct gsm_bts;

int match_codec_pref(int *full_rate, enum gsm48_chan_mode *chan_mode, const struct gsm0808_channel_type *ct,
		      const struct gsm0808_speech_codec_list *scl, const struct bsc_msc_data *msc, struct gsm_bts *bts);
