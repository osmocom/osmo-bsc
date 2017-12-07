/* Handover Decision Algorithm 2 for intra-BSC (inter-BTS) handover, public API for OsmoBSC */

#pragma once
struct gsm_bts;

void hodec2_init(struct gsm_network *net);

void hodec2_on_change_congestion_check_interval(struct gsm_network *net, unsigned int new_interval);
void hodec2_congestion_check(struct gsm_network *net);
