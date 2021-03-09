/* Manage a list of penalty timers per BTS;
 * initially used by handover algorithm 2 to keep per-BTS timers for each subscriber connection. */
#pragma once

#include <osmocom/gsm/gsm0808_utils.h>

struct penalty_timer {
	struct llist_head entry;

	struct gsm0808_cell_id for_target_cell;
	unsigned int timeout;
};

void penalty_timers_add(void *ctx, struct llist_head *penalty_timers,
			const struct gsm0808_cell_id *for_target_cell, int timeout);
void penalty_timers_add_list(void *ctx, struct llist_head *penalty_timers,
			     const struct gsm0808_cell_id_list2 *for_target_cells, int timeout);

unsigned int penalty_timers_remaining(struct llist_head *penalty_timers,
				      const struct gsm0808_cell_id *for_target_cell);
unsigned int penalty_timers_remaining_list(struct llist_head *penalty_timers,
					   const struct gsm0808_cell_id_list2 *for_target_cells);

void penalty_timers_clear(struct llist_head *penalty_timers, const struct gsm0808_cell_id *for_target_cell);
