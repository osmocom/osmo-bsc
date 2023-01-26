#pragma once

#include <stdbool.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>

struct gsm0808_channel_type;
struct channel_mode_and_rate;

int match_data_rate_pref(struct channel_mode_and_rate *ch_mode_rate,
			 const struct gsm0808_channel_type *ct,
			 const bool full_rate);
