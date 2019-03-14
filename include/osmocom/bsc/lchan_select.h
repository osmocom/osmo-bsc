/* Select a suitable lchan from a given cell. */
#pragma once

struct gsm_lchan *lchan_select_by_type(struct gsm_bts *bts, enum gsm_chan_t type);
struct gsm_lchan *lchan_select_by_chan_mode(struct gsm_bts *bts,
					    enum gsm48_chan_mode chan_mode, bool full_rate);
