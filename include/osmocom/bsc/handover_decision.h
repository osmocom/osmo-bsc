#pragma once

struct gsm_bts *bts_by_arfcn_bsic(const struct gsm_network *net, uint16_t arfcn, uint8_t bsic);

void handover_decision_1_init(void);
