#pragma once

#include <stdint.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/timer.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/gsm/gsm0808.h>

#include <osmocom/bsc/neighbor_ident.h>
#include <osmocom/bsc/gsm_data.h>

struct gsm_network;
struct gsm_lchan;
struct gsm_bts;
struct gsm_subscriber_connection;
struct gsm_meas_rep mr;

enum handover_result {
	HO_RESULT_OK,
	HO_RESULT_FAIL_NO_CHANNEL,
	HO_RESULT_FAIL_RR_HO_FAIL,
	HO_RESULT_FAIL_TIMEOUT,
	HO_RESULT_CONN_RELEASE,
	HO_RESULT_ERROR,
};

extern const struct value_string handover_result_names[];
inline static const char *handover_result_name(enum handover_result val)
{ return get_value_string(handover_result_names, val); }

int bts_handover_count(struct gsm_bts *bts, int ho_scopes);

/* Handover decision algorithms' actions to take on incoming handover-relevant events.
 *
 * All events that are interesting for handover decision are actually communicated by S_LCHAN_* signals,
 * so theoretically, each handover algorithm could evaluate those.  However, handover_logic.c cleans up
 * handover operation state upon receiving some of these signals. To allow a handover decision algorithm
 * to take advantage of e.g. the struct handover before it is discarded, the handover decision event
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
	void (*on_handover_end)(struct gsm_subscriber_connection *conn, enum handover_result result);
};

void handover_decision_callbacks_register(struct handover_decision_callbacks *hdc);
struct handover_decision_callbacks *handover_decision_callbacks_get(int hodec_id);

int bsc_tx_bssmap_ho_required(struct gsm_lchan *lchan, const struct gsm0808_cell_id_list2 *target_cells);
int bsc_tx_bssmap_ho_request_ack(struct gsm_subscriber_connection *conn,
				 struct msgb *rr_ho_command);
int bsc_tx_bssmap_ho_detect(struct gsm_subscriber_connection *conn);
enum handover_result bsc_tx_bssmap_ho_complete(struct gsm_subscriber_connection *conn,
					       struct gsm_lchan *lchan);
void bsc_tx_bssmap_ho_failure(struct gsm_subscriber_connection *conn);

struct gsm_bts *bts_by_neighbor_ident(const struct gsm_network *net,
				      const struct neighbor_ident_key *search_for);
struct neighbor_ident_key *bts_ident_key(const struct gsm_bts *bts);

void handover_parse_inter_bsc_mt(struct gsm_subscriber_connection *conn,
				 struct msgb *ho_request_msg);

void handover_mt_allocate_lchan(struct handover *ho);
int handover_mt_send_rr_ho_command(struct handover *ho);
