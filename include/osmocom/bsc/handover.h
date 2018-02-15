#pragma once

#include <stdint.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/timer.h>

struct gsm_lchan;
struct gsm_bts;
struct gsm_subscriber_connection;

#define LOGPHOLCHANTOLCHAN(old_lchan, new_lchan, level, fmt, args...) \
	LOGP(DHODEC, level, "(BTS %u trx %u arfcn %u ts %u lchan %u %s)->(BTS %u trx %u arfcn %u ts %u lchan %u %s) (subscr %s) " fmt, \
	     old_lchan->ts->trx->bts->nr, \
	     old_lchan->ts->trx->nr, \
	     old_lchan->ts->trx->arfcn, \
	     old_lchan->ts->nr, \
	     old_lchan->nr, \
	     gsm_pchan_name(old_lchan->ts->pchan), \
	     new_lchan->ts->trx->bts->nr, \
	     new_lchan->ts->trx->nr, \
	     new_lchan->ts->trx->arfcn, \
	     new_lchan->ts->nr, \
	     new_lchan->nr, \
	     gsm_pchan_name(new_lchan->ts->pchan), \
	     bsc_subscr_name(old_lchan->conn? old_lchan->conn->bsub : NULL), \
	     ## args)

#define LOGPHO(struct_bsc_handover, level, fmt, args ...) \
	LOGPHOLCHANTOLCHAN(struct_bsc_handover->old_lchan, struct_bsc_handover->new_lchan, level, fmt, ## args)

enum hodec_id {
	HODEC_NONE,
	HODEC1 = 1,
	HODEC2 = 2,
};

struct bsc_handover {
	struct llist_head list;

	enum hodec_id from_hodec_id;

	struct gsm_lchan *old_lchan;
	struct gsm_lchan *new_lchan;

	struct osmo_timer_list T3103;

	uint8_t ho_ref;

	bool inter_cell;
	bool async;
};

int bsc_handover_start(enum hodec_id from_hodec_id, struct gsm_lchan *old_lchan, struct gsm_bts *new_bts,
		       enum gsm_chan_t new_lchan_type);
void bsc_clear_handover(struct gsm_subscriber_connection *conn, int free_lchan);
struct gsm_lchan *bsc_handover_pending(struct gsm_lchan *new_lchan);

int bsc_ho_count(struct gsm_bts *bts, bool inter_cell);

/* Handover decision algorithms' actions to take on incoming handover-relevant events.
 *
 * All events that are interesting for handover decision are actually communicated by S_LCHAN_* signals,
 * so theoretically, each handover algorithm could evaluate those.  However, handover_logic.c cleans up
 * handover operation state upon receiving some of these signals. To allow a handover decision algorithm
 * to take advantage of e.g. the struct bsc_handover before it is discarded, the handover decision event
 * handler needs to be invoked before handover_logic.c discards the state. For example, if the handover
 * decision wants to place a penalty timer upon a handover failure, it still needs to know which target
 * cell the handover failed for; handover_logic.c erases that knowledge on handover failure, since it
 * needs to clean up the lchan's handover state.
 *
 * The most explicit and safest way to ensure the correct order of event handling is to invoke the
 * handover decision algorithm's actions from handover_logic.c itself, before cleaning up. This struct
 * provides the callback functions for this purpose.
 *
 * For consistency, also handle signals in this way that aren't actually in danger of interference from
 * handover_logic.c (which also saves repeated lookup of handover state for lchans). Thus, handover
 * decision algorithms should not register any signal handler at all.
 */
struct handover_decision_callbacks {
	struct llist_head entry;

	int hodec_id;

	void (*on_measurement_report)(struct gsm_meas_rep *mr);
	void (*on_ho_chan_activ_nack)(struct bsc_handover *ho);
	void (*on_ho_failure)(struct bsc_handover *ho);
};

void handover_decision_callbacks_register(struct handover_decision_callbacks *hdc);
struct handover_decision_callbacks *handover_decision_callbacks_get(int hodec_id);
