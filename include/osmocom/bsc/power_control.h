#pragma once

#include <stdint.h>
#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/meas_rep.h>

int lchan_ms_pwr_ctrl(struct gsm_lchan *lchan, const struct gsm_meas_rep *mr);
