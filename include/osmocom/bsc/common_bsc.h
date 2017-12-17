#pragma once

#include <stdint.h>
#include <osmocom/bsc/common_cs.h>

struct gsm_network *bsc_network_init(void *ctx,
				     uint16_t country_code,
				     uint16_t network_code);
