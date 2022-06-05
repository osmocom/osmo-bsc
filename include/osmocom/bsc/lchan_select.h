/* Select a suitable lchan from a given cell. */
#pragma once

enum lchan_select_reason {
	SELECT_FOR_MS_CHAN_REQ,
	SELECT_FOR_ASSIGNMENT,
	SELECT_FOR_HANDOVER,
};

extern const struct value_string lchan_select_reason_names[];
static inline const char *lchan_select_reason_name(enum lchan_select_reason reason)
{ return get_value_string(lchan_select_reason_names, reason); }

struct gsm_lchan *lchan_select_by_type(struct gsm_bts *bts,
				       enum gsm_chan_t type,
				       enum lchan_select_reason reason);
enum gsm_chan_t chan_mode_to_chan_type(enum gsm48_chan_mode chan_mode, enum channel_rate chan_rate);
struct gsm_lchan *lchan_select_by_chan_mode(struct gsm_bts *bts,
					    enum gsm48_chan_mode chan_mode,
					    enum channel_rate chan_rate,
					    enum lchan_select_reason reason);
struct gsm_lchan *lchan_avail_by_type(struct gsm_bts *bts, enum gsm_chan_t type,
				      enum lchan_select_reason reason, bool log);
void lchan_select_set_type(struct gsm_lchan *lchan, enum gsm_chan_t type);
