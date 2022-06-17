/* Handover FSM implementation for intra-BSC and inter-BSC Handover.
 *
 * (C) 2018 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr <neels@hofmeyr.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <osmocom/core/socket.h>

#include <osmocom/gsm/rsl.h>
#include <osmocom/gsm/gsm0808.h>

#include <osmocom/mgcp_client/mgcp_client_endpoint_fsm.h>

#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/bsc_subscriber.h>

#include <osmocom/bsc/handover_fsm.h>
#include <osmocom/bsc/handover_cfg.h>
#include <osmocom/bsc/bsc_subscr_conn_fsm.h>
#include <osmocom/bsc/lchan_select.h>
#include <osmocom/bsc/lchan_fsm.h>
#include <osmocom/bsc/lchan_rtp_fsm.h>
#include <osmocom/bsc/gsm_04_08_rr.h>
#include <osmocom/bsc/abis_rsl.h>
#include <osmocom/bsc/bsc_msc_data.h>
#include <osmocom/bsc/osmo_bsc.h>
#include <osmocom/bsc/osmo_bsc_lcls.h>
#include <osmocom/bsc/codec_pref.h>
#include <osmocom/bsc/gsm_08_08.h>
#include <osmocom/bsc/bts.h>
#include <osmocom/bsc/lcs_loc_req.h>
#include <osmocom/bsc/bsc_stats.h>

#define LOG_FMT_BTS "bts %u lac-ci %u-%u arfcn-bsic %d-%d"
#define LOG_ARGS_BTS(bts) \
		(bts) ? (bts)->nr : 0, \
		(bts) ? (bts)->location_area_code : 0, \
		(bts) ? (bts)->cell_identity : 0, \
		(bts) ? (bts)->c0->arfcn : 0, \
		(bts) ? (bts)->bsic : 0

#define LOG_FMT_FROM_LCHAN "%u-%u-%u-%s-%u-%s"
#define LOG_ARGS_FROM_LCHAN(lchan) \
		lchan ? lchan->ts->trx->bts->nr : 0, \
		lchan ? lchan->ts->trx->nr : 0, \
		lchan ? lchan->ts->nr : 0, \
		lchan ? gsm_lchant_name(lchan->type) : "?", \
		lchan ? lchan->nr : 0, \
		lchan ? gsm48_chan_mode_name(lchan->current_ch_mode_rate.chan_mode) : "?"

#define LOG_FMT_TO_LCHAN "%u-%u-%u-%s%s%s-%u"
#define LOG_ARGS_TO_LCHAN(lchan) \
		lchan ? lchan->ts->trx->bts->nr : 0, \
		lchan ? lchan->ts->trx->nr : 0, \
		lchan ? lchan->ts->nr : 0, \
		lchan ? gsm_pchan_name(lchan->ts->pchan_on_init) : "?", \
		(!lchan || lchan->ts->pchan_on_init == lchan->ts->pchan_is)? "" : ":", \
		(!lchan || lchan->ts->pchan_on_init == lchan->ts->pchan_is)? "" \
			: gsm_pchan_name(lchan->ts->pchan_is), \
		lchan ? lchan->nr : 0

#define LOG_FMT_HO_SCOPE "(subscr %s) %s"
#define LOG_ARGS_HO_SCOPE(conn) \
	     bsc_subscr_name(conn->bsub), \
	     handover_scope_name(conn->ho.scope)

/* Assume presence of local var 'conn' as struct gsm_subscriber_connection.
 * This is a macro to preserve the source file and line number in logging. */
#define ho_count_bsc(counter) do { \
		/* If a handover target could not be found, the counter index may be -1. */ \
		if (counter < 0) \
			break; \
		LOG_HO(conn, LOGL_DEBUG, "(BSC) incrementing rate counter: %s %s\n", \
		       bsc_ctr_description[counter].name, \
		       bsc_ctr_description[counter].description); \
		rate_ctr_inc(rate_ctr_group_get_ctr(conn->network->bsc_ctrs, counter)); \
	} while (0)

/* Assume presence of local var 'conn' as struct gsm_subscriber_connection.
 * Handles bts == NULL gracefully
 * This is a macro to preserve the source file and line number in logging. */
#define ho_count_bts(bts, counter) do { \
		/* If a handover target could not be found, the counter index may be -1. */ \
		if (counter < 0) \
			break; \
		LOG_HO(conn, LOGL_DEBUG, "(BTS) incrementing rate counter: %s %s\n", \
		       bts_ctr_description[counter].name, \
		       bts_ctr_description[counter].description); \
		if (bts) \
			rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, counter)); \
		else \
			rate_ctr_inc(rate_ctr_group_get_ctr(conn->network->bts_unknown_ctrs, counter)); \
	} while (0)

/* Count handover result on both bts and bsc level.
 * Call with 'counter' being the counter name without the "BSC_"/"BTS_" part,
 * e.g. ho_count(conn_get_bts(conn), CTR_HANDOVER_ATTEMPTED); */
#define ho_count(bts, counter) do { \
		ho_count_bsc(BSC_##counter); \
		ho_count_bts(bts, BTS_##counter); \
	} while (0)

static uint8_t g_next_ho_ref = 1;

const char *handover_status(struct gsm_subscriber_connection *conn)
{
	static char buf[256];
	struct handover *ho = &conn->ho;

	if (!conn)
		return "";

	if (ho->scope & (HO_INTRA_CELL | HO_INTRA_BSC)) {
		if (ho->new_lchan)
			snprintf(buf, sizeof(buf),
				 "("LOG_FMT_FROM_LCHAN") --HO-> (" LOG_FMT_TO_LCHAN ") " LOG_FMT_HO_SCOPE,
				 LOG_ARGS_FROM_LCHAN(conn->lchan),
				 LOG_ARGS_TO_LCHAN(ho->new_lchan),
				 LOG_ARGS_HO_SCOPE(conn));
		else if (ho->new_bts)
			snprintf(buf, sizeof(buf),
				 "("LOG_FMT_FROM_LCHAN") --HO-> ("LOG_FMT_BTS",%s) " LOG_FMT_HO_SCOPE,
				 LOG_ARGS_FROM_LCHAN(conn->lchan),
				 LOG_ARGS_BTS(ho->new_bts),
				 gsm_lchant_name(ho->new_lchan_type),
				 LOG_ARGS_HO_SCOPE(conn));
		else
			snprintf(buf, sizeof(buf),
				 "("LOG_FMT_FROM_LCHAN") --HO->(?) " LOG_FMT_HO_SCOPE,
				 LOG_ARGS_FROM_LCHAN(conn->lchan),
				 LOG_ARGS_HO_SCOPE(conn));

	} else if (ho->scope & HO_INTER_BSC_OUT)
		snprintf(buf, sizeof(buf),
			 "("LOG_FMT_FROM_LCHAN") --HO-> (%s) " LOG_FMT_HO_SCOPE,
			 LOG_ARGS_FROM_LCHAN(conn->lchan),
			 cell_ab_to_str_c(OTC_SELECT, &ho->target_cell_ab),
			 LOG_ARGS_HO_SCOPE(conn));

	else if (ho->scope & HO_INTER_BSC_IN) {
		if (ho->new_lchan)
			snprintf(buf, sizeof(buf),
				 "(remote:%s) --HO-> (local:%s|"LOG_FMT_TO_LCHAN") " LOG_FMT_HO_SCOPE,
				 ho->inter_bsc_in.cell_id_serving_name,
				 ho->inter_bsc_in.cell_id_target_name,
				 LOG_ARGS_TO_LCHAN(ho->new_lchan),
				 LOG_ARGS_HO_SCOPE(conn));
		else if (ho->new_bts)
			snprintf(buf, sizeof(buf),
				 "(remote:%s) --HO-> (local:%s|"LOG_FMT_BTS",%s) " LOG_FMT_HO_SCOPE,
				 ho->inter_bsc_in.cell_id_serving_name,
				 ho->inter_bsc_in.cell_id_target_name,
				 LOG_ARGS_BTS(ho->new_bts),
				 gsm_lchant_name(ho->new_lchan_type),
				 LOG_ARGS_HO_SCOPE(conn));
		else
			snprintf(buf, sizeof(buf),
				 "(remote:%s) --HO-> (local:%s,%s) " LOG_FMT_HO_SCOPE,
				 ho->inter_bsc_in.cell_id_serving_name,
				 ho->inter_bsc_in.cell_id_target_name,
				 gsm_lchant_name(ho->new_lchan_type),
				 LOG_ARGS_HO_SCOPE(conn));
	} else
		snprintf(buf, sizeof(buf), LOG_FMT_HO_SCOPE, LOG_ARGS_HO_SCOPE(conn));
	return buf;
}

static struct osmo_fsm ho_fsm;

struct gsm_subscriber_connection *ho_fi_conn(struct osmo_fsm_inst *fi)
{
	OSMO_ASSERT(fi);
	OSMO_ASSERT(fi->fsm == &ho_fsm);
	OSMO_ASSERT(fi->priv);
	return fi->priv;
}

static const struct osmo_tdef_state_timeout ho_fsm_timeouts[32] = {
	[HO_ST_WAIT_LCHAN_ACTIVE] = { .T = 23042 },
	[HO_ST_WAIT_MGW_ENDPOINT_TO_MSC] = { .T = 23042 },
	[HO_ST_WAIT_RR_HO_DETECT] = { .T = 23042 },
	[HO_ST_WAIT_RR_HO_COMPLETE] = { .T = 23042 },
	[HO_ST_WAIT_LCHAN_ESTABLISHED] = { .T = 23042 },
	[HO_OUT_ST_WAIT_HO_COMMAND] = { .T = 7 },
	[HO_OUT_ST_WAIT_CLEAR] = { .T = 8 },
};

/* Transition to a state, using the T timer defined in ho_fsm_timeouts.
 * The actual timeout value is in turn obtained from network->T_defs.
 * Assumes local variable fi exists. */
#define ho_fsm_state_chg(state) \
	osmo_tdef_fsm_inst_state_chg(fi, state, \
				     ho_fsm_timeouts, \
				     ((struct gsm_subscriber_connection*)(fi->priv))->network->T_defs, \
				     5)

/* Log failure and transition to HO_ST_FAILURE, which triggers the appropriate actions. */
#define ho_fail(result, fmt, args...) do { \
		LOG_HO(conn, LOGL_ERROR, "Handover failed in state %s, %s: " fmt "\n", \
		       osmo_fsm_inst_state_name(conn->fi), handover_result_name(result), ## args); \
		handover_end(conn, result); \
	} while (0)

#define ho_success() do { \
		LOG_HO(conn, LOGL_DEBUG, "Handover succeeded\n"); \
		handover_end(conn, HO_RESULT_OK); \
	} while (0)

/* issue handover to a cell identified by ARFCN and BSIC */
int handover_request(struct handover_out_req *req)
{
	struct gsm_subscriber_connection *conn;
	OSMO_ASSERT(req->old_lchan);

	conn = req->old_lchan->conn;
	OSMO_ASSERT(conn && conn->fi);

	/* To make sure we're allowed to start a handover, go through a gscon event dispatch. If that is accepted, the
	 * same req is passed to handover_start(). */
	return osmo_fsm_inst_dispatch(conn->fi, GSCON_EV_HANDOVER_START, req);
}

/* Check that ho has old_lchan and/or new_lchan and conn pointers match.
 * If old_lchan and/or new_lchan are NULL, omit those checks.
 * On error, return false, log an error and call handover_end() with HO_RESULT_ERROR. */
bool handover_is_sane(struct gsm_subscriber_connection *conn, struct gsm_lchan *old_lchan, struct gsm_lchan *new_lchan)
{
	if (!conn->ho.fi) {
		LOG_HO(conn, LOGL_ERROR, "No handover ongoing\n");
		return false;
	}

	if (old_lchan
	    && (conn != old_lchan->conn || conn->lchan != old_lchan))
		goto insane;
	if (new_lchan
	    && (conn != new_lchan->conn || conn->ho.new_lchan != new_lchan))
		goto insane;
	if (conn->lchan && conn->lchan == conn->ho.new_lchan)
		goto insane;

	return true;
insane:
	LOG_HO(conn, LOGL_ERROR, "Handover state is corrupted\n");
	handover_end(conn, HO_RESULT_ERROR);
	return false;
}

static void ho_fsm_update_id(struct osmo_fsm_inst *fi, const char *label)
{
	struct gsm_subscriber_connection *conn = ho_fi_conn(fi);
	if (conn->fi->id)
		osmo_fsm_inst_update_id_f(fi, "%s_%s", label, conn->fi->id);
	else
		osmo_fsm_inst_update_id_f(fi, "%s_conn%u", label, conn->sccp.conn_id);
}

static void handover_reset(struct gsm_subscriber_connection *conn)
{
	struct osmo_mgcpc_ep_ci *ci;
	if (conn->ho.new_lchan)
		/* New lchan was activated but never passed to a conn */
		lchan_release(conn->ho.new_lchan, false, true, RSL_ERR_EQUIPMENT_FAIL,
			      NULL);

	ci = conn->ho.created_ci_for_msc;
	if (ci) {
		gscon_forget_mgw_endpoint_ci(conn, ci);
		/* If this is the last endpoint released, the mgw_endpoint_fsm will terminate and tell
		 * the gscon about it. */
		osmo_mgcpc_ep_ci_dlcx(ci);
	}

	conn->ho = (struct handover){
		.fi = conn->ho.fi,
	};
}

void handover_fsm_init()
{
	OSMO_ASSERT(osmo_fsm_register(&ho_fsm) == 0);
}

void handover_fsm_alloc(struct gsm_subscriber_connection *conn)
{
	OSMO_ASSERT(conn->fi);
	OSMO_ASSERT(!conn->ho.fi);

	conn->ho.fi = osmo_fsm_inst_alloc_child(&ho_fsm, conn->fi, GSCON_EV_HANDOVER_END);
	OSMO_ASSERT(conn->ho.fi);
	conn->ho.fi->priv = conn;
}

static void handover_start_intra_bsc(struct gsm_subscriber_connection *conn);
static void handover_start_inter_bsc_out(struct gsm_subscriber_connection *conn,
					 const struct gsm0808_cell_id_list2 *target_cells);

/* Invoked by gscon if a handover was accepted to start now. */
void handover_start(struct handover_out_req *req)
{

	OSMO_ASSERT(req && req->old_lchan && req->old_lchan->conn);
	struct gsm_subscriber_connection *conn = req->old_lchan->conn;
	const struct cell_ab *search_for = &req->target_cell_ab;
	struct handover *ho = &conn->ho;
	struct gsm_bts *local_target_cell = NULL;
	struct gsm0808_cell_id_list2 remote_target_cells = {};

	if (conn->ho.fi) {
		LOG_HO(conn, LOGL_ERROR, "Handover requested while another handover is ongoing; Ignore\n");
		return;
	}
	handover_reset(conn);

	/* When handover_start() is invoked by the gscon, it expects a HANDOVER_END event. The best way to ensure this
	 * is to always create a handover_fsm instance, even if the target cell is not resolved yet. Any failure should
	 * then call handover_end(), which ensures that the conn snaps back to a valid state. */
	handover_fsm_alloc(conn);
	ho_count(conn_get_bts(conn), CTR_HANDOVER_ATTEMPTED);

	ho->from_hodec_id = req->from_hodec_id;
	ho->new_lchan_type = req->new_lchan_type == GSM_LCHAN_NONE ?
		req->old_lchan->type : req->new_lchan_type;
	ho->target_cell_ab = req->target_cell_ab;

	if (find_handover_target_cell(&local_target_cell, &remote_target_cells,
				      conn, search_for, true)) {
		handover_end(conn, HO_RESULT_ERROR);
		return;
	}

	if (local_target_cell) {
		ho->new_bts = local_target_cell;
		handover_start_intra_bsc(conn);
		return;
	}

	if (remote_target_cells.id_list_len) {
		handover_start_inter_bsc_out(conn, &remote_target_cells);
		return;
	}

	/* should never reach this, because find_handover_target_cell() would have returned error. */
	OSMO_ASSERT(false);
}

/*! Hand over the specified logical channel to the specified new BTS and possibly change the lchan type.
 * This is the main entry point for the actual handover algorithm, after the decision whether to initiate
 * HO to a specific BTS. To not change the lchan type, pass old_lchan->type. */
static void handover_start_intra_bsc(struct gsm_subscriber_connection *conn)
{
	struct handover *ho = &conn->ho;
	struct osmo_fsm_inst *fi = conn->ho.fi;
	struct lchan_activate_info info;
        struct gsm_bts *bts = conn_get_bts(conn);

	OSMO_ASSERT(ho->new_bts);
	OSMO_ASSERT(ho->new_lchan_type != GSM_LCHAN_NONE);
	OSMO_ASSERT(!ho->new_lchan);

	ho->scope = (ho->new_bts == bts) ? HO_INTRA_CELL : HO_INTRA_BSC;
	ho->ho_ref = g_next_ho_ref++;
	ho->async = true;
	gsm_bts_cell_id_list(&ho->target_cell_ids, ho->new_bts);

	ho->new_lchan = lchan_select_by_type(ho->new_bts,
					     ho->new_lchan_type,
					     SELECT_FOR_HANDOVER,
					     NULL);

	if (ho->scope & HO_INTRA_CELL) {
		ho_count(bts, CTR_INTRA_CELL_HO_ATTEMPTED);
		ho_fsm_update_id(fi, "intraCell");
	} else {
		ho_count(bts, CTR_INTRA_BSC_HO_ATTEMPTED);
		ho_fsm_update_id(fi, "intraBSC");
		ho_count_bts(ho->new_bts, BTS_CTR_INCOMING_INTRA_BSC_HO_ATTEMPTED);
	}

	if (!ho->new_lchan) {
		ho_fail(HO_RESULT_FAIL_NO_CHANNEL,
			"No %s lchan available on BTS %u",
			gsm_lchant_name(ho->new_lchan_type), ho->new_bts->nr);
		return;
	}
	LOG_HO(conn, LOGL_DEBUG, "Selected lchan %s\n", gsm_lchan_name(ho->new_lchan));

	ho_fsm_state_chg(HO_ST_WAIT_LCHAN_ACTIVE);

	info = (struct lchan_activate_info){
		.activ_for = ACTIVATE_FOR_HANDOVER,
		.for_conn = conn,
		.ch_mode_rate = conn->lchan->current_ch_mode_rate,
		.encr = conn->lchan->encr,
		.requires_voice_stream = conn->lchan->mgw_endpoint_ci_bts ? true : false,
		.msc_assigned_cic = conn->ho.inter_bsc_in.msc_assigned_cic,
		.re_use_mgw_endpoint_from_lchan = conn->lchan,
		.wait_before_switching_rtp = true,
	};
	info.ch_mode_rate.chan_rate = chan_t_to_chan_rate(ho->new_lchan->type);

	/* For intra-cell handover, we know the accurate Timing Advance from the previous lchan. For inter-cell
	 * handover, no Timing Advance for the new cell is known, so leave it unset. */
	if (ho->new_bts == bts) {
		info.ta = conn->lchan->last_ta;
		info.ta_known = true;
	}

	lchan_activate(ho->new_lchan, &info);
}

/* 3GPP TS 48.008 § 3.2.2.58  Old BSS to New BSS Information */
static void parse_old2new_bss_info(struct gsm_subscriber_connection *conn,
				   const uint8_t* data, uint16_t len,
				   struct handover_in_req *req)
{
	/* § 3.2.2.58: Information contained here shall take precedence over
	   duplicate information from Information Elements in the HANDOVER
	   REQUEST  as long as the coding is understood by the new BSS */
	/* § 3.2.2.58: <<Reception of an erroneous "Old BSS to New BSS
	   information" shall not cause a rejection of the HANDOVER REQUEST
	   message; the "Old BSS to New BSS information" information element
	   shall be discarded and the handover resource allocation procedure
	   shall continue>>. See also 3.1.19.7. */
	struct tlv_parsed tp;
	if (tlv_parse(&tp, &gsm0808_old_bss_to_new_bss_info_att_tlvdef, data, len, 0, 0) <= 0) {
		LOG_HO(conn, LOGL_NOTICE, "Failed to parse IE \"Old BSS to New BSS information\"\n");
		return;
	}

	if (TLVP_VAL(&tp, GSM0808_FE_IE_LAST_USED_EUTRAN_PLMN_ID)) {
		req->last_eutran_plmn_valid = true;
		osmo_plmn_from_bcd(TLVP_VAL(&tp, GSM0808_FE_IE_LAST_USED_EUTRAN_PLMN_ID),
				   &req->last_eutran_plmn);
	}
}

/* 3GPP TS 48.008 § 3.2.1.8 Handover Request */
static bool parse_ho_request(struct gsm_subscriber_connection *conn, const struct msgb *msg,
			     struct handover_in_req *req)
{
	struct tlv_parsed tp_arr[2];
	struct tlv_parsed *tp = &tp_arr[0];
	struct tlv_parsed *tp2 = &tp_arr[1];
	struct tlv_p_entry *e;
	int payload_length;
	bool aoip = gscon_is_aoip(conn);
	bool sccplite = gscon_is_sccplite(conn);
	bool has_a54 = false;

	if ((aoip && sccplite) || !(aoip || sccplite)) {
		LOG_HO(conn, LOGL_ERROR, "Received BSSMAP Handover Request, but conn is not"
		       " marked as exactly one of AoIP or SCCPlite\n");
		return false;
	}

	payload_length = msg->tail - msg->l4h;
	if (tlv_parse2(tp_arr, 2, gsm0808_att_tlvdef(), msg->l4h + 1, payload_length - 1, 0, 0) <= 0) {
		LOG_HO(conn, LOGL_ERROR, "Failed to parse IEs\n");
		return false;
	}

	if (!(e = TLVP_GET(tp, GSM0808_IE_CHANNEL_TYPE))) {
		LOG_HO(conn, LOGL_ERROR, "Missing Channel Type IE\n");
		return false;
	}
	if (gsm0808_dec_channel_type(&req->ct, e->val, e->len) <= 0) {
		LOG_HO(conn, LOGL_ERROR, "Failed to parse Channel Type IE\n");
		return false;
	}

	if (!(e = TLVP_GET(tp, GSM0808_IE_ENCRYPTION_INFORMATION))) {
		LOG_HO(conn, LOGL_ERROR, "Missing Encryption Information IE\n");
		return false;
	}
	if (gsm0808_dec_encrypt_info(&req->ei, e->val, e->len) <= 0) {
		LOG_HO(conn, LOGL_ERROR, "Failed to parse Encryption Information IE\n");
		return false;
	}
	req->ei_as_bitmask = *e->val;

	if ((e = TLVP_GET(tp, GSM0808_IE_KC_128))) {
		if (e->len != 16) {
			LOG_HO(conn, LOGL_ERROR, "Invalid length in Kc128 IE: %u bytes (expected 16)\n", e->len);
			return false;
		}
		memcpy(req->kc128, e->val, 16);
		req->kc128_present = true;
	}

	if ((e = TLVP_GET(tp, GSM0808_IE_CLASSMARK_INFORMATION_TYPE_1))) {
		if (e->len != sizeof(req->classmark.classmark1)) {
			LOG_HO(conn, LOGL_ERROR, "Classmark Information 1 has wrong size\n");
			return false;
		}
		req->classmark.classmark1 = *(struct gsm48_classmark1*)e->val;
		req->classmark.classmark1_set = true;
	} else if ((e = TLVP_GET(tp, GSM0808_IE_CLASSMARK_INFORMATION_T2))) {
		uint8_t len = OSMO_MIN(sizeof(req->classmark.classmark2),
				       e->len);
		if (!len) {
			LOG_HO(conn, LOGL_ERROR, "Classmark Information 2 has zero size\n");
			return false;
		}
		memcpy(&req->classmark.classmark2, e->val, len);
		req->classmark.classmark2_len = len;
	} else
		LOG_HO(conn, LOGL_INFO,
		       "Missing mandatory IE: 3GPP mandates either Classmark Information 1 or 2"
		       " in BSSMAP Handover Request, but neither are present. Will continue without.\n");

	if ((e = TLVP_GET(tp, GSM0808_IE_CHOSEN_ENCR_ALG))) {
		req->chosen_encr_alg = e->val[0];
		if (req->chosen_encr_alg < 1 || req->chosen_encr_alg > 8)
			LOG_HO(conn, LOGL_ERROR, "Chosen Encryption Algorithm (Serving) is invalid: %u\n",
			       req->chosen_encr_alg);
	}

	LOG_HO(conn, LOGL_DEBUG, "Handover Request encryption info: chosen=A5/%u key=%s kc128=%s\n",
	       (req->chosen_encr_alg ? : 1) - 1,
	       req->ei.key_len ? osmo_hexdump_nospc(req->ei.key, req->ei.key_len) : "none",
	       has_a54 ? osmo_hexdump_nospc(req->kc128, 16) : "none");

	if (TLVP_PRESENT(tp, GSM0808_IE_AOIP_TRASP_ADDR)) {
		int rc;
		unsigned int u;
		struct sockaddr_storage msc_rtp_sa;

		if (!aoip) {
			LOG_HO(conn, LOGL_ERROR,
			       "BSSMAP Handover Request contains AoIP Transport Address,"
			       " but this is not an AoIP connection\n");
			return false;
		}
		rc = gsm0808_dec_aoip_trasp_addr(&msc_rtp_sa,
						 TLVP_VAL(tp, GSM0808_IE_AOIP_TRASP_ADDR),
						 TLVP_LEN(tp, GSM0808_IE_AOIP_TRASP_ADDR));
		if (rc < 0) {
			LOG_HO(conn, LOGL_ERROR, "Unable to decode AoIP Transport Address.\n");
			return false;
		}

		u = osmo_sockaddr_to_str_and_uint(req->msc_assigned_rtp_addr,
						  sizeof(req->msc_assigned_rtp_addr),
						  &req->msc_assigned_rtp_port,
						  (const struct sockaddr*)&msc_rtp_sa);
		if (!u || u >= sizeof(req->msc_assigned_rtp_addr)) {
			LOG_HO(conn, LOGL_ERROR, "MSC's RTP address is too long\n");
			return false;
		}
	} else if (aoip) {
		LOG_HO(conn, LOGL_ERROR,
		       "BSSMAP Handover Request lacks AoIP Transport Address on an AoIP connection\n");
		return false;
	}

	/* The Cell Identifier (Serving) and Cell Identifier (Target) are both 3.2.2.17 and are
	 * identified by the same tag. So get one from tp and the other from tp2. */
	if (!(e = TLVP_GET(tp, GSM0808_IE_CELL_IDENTIFIER))) {
		LOG_HO(conn, LOGL_ERROR, "Missing IE: Cell Identifier (Serving)\n");
		return false;
	}
	if (gsm0808_dec_cell_id(&req->cell_id_serving, e->val, e->len) < 0) {
		LOG_HO(conn, LOGL_ERROR, "Invalid IE: Cell Identifier (Serving)\n");
		return false;
	}
	/* LOG_HO() also calls gsm0808_cell_id_name(), so to be able to use gsm0808_cell_id_name() in
	 * logging without getting mixed up with those static buffers, store the result. */
	OSMO_STRLCPY_ARRAY(req->cell_id_serving_name, gsm0808_cell_id_name(&req->cell_id_serving));

	if (!(e = TLVP_GET(tp2, GSM0808_IE_CELL_IDENTIFIER))) {
		LOG_HO(conn, LOGL_ERROR, "Missing IE: Cell Identifier (Target)\n");
		return false;
	}
	if (gsm0808_dec_cell_id(&req->cell_id_target, e->val, e->len) < 0) {
		LOG_HO(conn, LOGL_ERROR, "Invalid IE: Cell Identifier (Target)\n");
		return false;
	}
	OSMO_STRLCPY_ARRAY(req->cell_id_target_name, gsm0808_cell_id_name(&req->cell_id_target));

	if ((e = TLVP_GET(tp, GSM0808_IE_CIRCUIT_IDENTITY_CODE))) {
		/* CIC is permitted in both AoIP and SCCPlite */
		req->msc_assigned_cic = osmo_load16be(e->val);
	} else if (sccplite) {
		/* no CIC but SCCPlite: illegal */
		LOG_HO(conn, LOGL_ERROR, "SCCPlite MSC, but no CIC in incoming inter-BSC Handover\n");
		return false;
	}

	if ((e = TLVP_GET(tp, GSM0808_IE_OLD_BSS_TO_NEW_BSS_INFORMATION))) {
		parse_old2new_bss_info(conn, e->val, e->len, req);
	}

	/* Decode "Codec List (MSC Preferred)". First set len = 0 to empty the list. (For inter-BSC incoming handover,
	 * there can't possibly be a list here already, because the conn has just now been created; just do ensure
	 * sanity.) */
	conn->codec_list = (struct gsm0808_speech_codec_list){};
	if ((e = TLVP_GET(tp, GSM0808_IE_SPEECH_CODEC_LIST))) {
		if (gsm0808_dec_speech_codec_list(&conn->codec_list, e->val, e->len) < 0) {
			LOG_HO(conn, LOGL_ERROR, "incoming inter-BSC Handover: HO Request:"
			       " Unable to decode Codec List (MSC Preferred)\n");
			return false;
		}
	}
	if (aoip && !conn->codec_list.len) {
		LOG_HO(conn, LOGL_ERROR, "incoming inter-BSC Handover: HO Request:"
		       " Invalid or empty Codec List (MSC Preferred)\n");
		return false;
	}

	/* A lot of IEs remain ignored... */

	return true;
}

static bool chan_mode_is_tch(enum gsm48_chan_mode mode)
{
	switch (gsm48_chan_mode_to_non_vamos(mode)) {
	case GSM48_CMODE_SPEECH_V1:
	case GSM48_CMODE_SPEECH_EFR:
	case GSM48_CMODE_SPEECH_AMR:
		return true;
	default:
		return false;
	}
}

void handover_start_inter_bsc_in(struct gsm_subscriber_connection *conn,
				 struct msgb *ho_request_msg)
{
	struct lchan_activate_info info;
	struct handover *ho = &conn->ho;
	struct bsc_msc_data *msc = conn->sccp.msc;
	struct handover_in_req *req = &ho->inter_bsc_in;
	int match_idx;
	struct osmo_fsm_inst *fi;
	struct channel_mode_and_rate ch_mode_rate = {};
	int chosen_a5_n;

	handover_fsm_alloc(conn);

	*ho = (struct handover){
		.fi = ho->fi,
		.from_hodec_id = HODEC_REMOTE,
		.scope = HO_INTER_BSC_IN,
		.ho_ref = g_next_ho_ref++,
		.async = true,
	};

	fi = ho->fi;
	ho_fsm_update_id(fi, "interBSCin");

	if (!parse_ho_request(conn, ho_request_msg, req)) {
		ho_fail(HO_RESULT_ERROR, "Invalid Handover Request message from MSC");
		return;
	}

	/* Figure out which cell to handover to. */
	for (match_idx = 0; ; match_idx++) {
		struct gsm_bts *bts;
		struct gsm_lchan *lchan;

		bts = gsm_bts_by_cell_id(conn->network, &req->cell_id_target,
					 match_idx);

		/* Did we iterate all matches? */
		if (!bts)
			break;

		LOG_HO(conn, LOGL_DEBUG, "BTS %u matches cell id %s\n",
		       bts->nr, req->cell_id_target_name);

		/* Figure out channel type */
		if (match_codec_pref(&ch_mode_rate, &req->ct, &req->scl, msc, bts, RATE_PREF_NONE)) {
			LOG_HO(conn, LOGL_DEBUG,
			       "BTS %u has no matching channel codec (%s, speech codec list len = %u)\n",
			       bts->nr, gsm0808_channel_type_name(&req->ct), req->scl.len);
			continue;
		}

		LOG_HO(conn, LOGL_DEBUG, "BTS %u: Found matching audio type: %s %s (for %s)\n",
		       bts->nr, gsm48_chan_mode_name(ch_mode_rate.chan_mode),
		       ch_mode_rate.chan_rate == CH_RATE_FULL ?  "full-rate" : "half-rate",
		       gsm0808_channel_type_name(&req->ct));

		lchan = lchan_select_by_chan_mode(bts,
						  ch_mode_rate.chan_mode,
						  ch_mode_rate.chan_rate,
						  SELECT_FOR_HANDOVER, NULL);
		if (!lchan) {
			LOG_HO(conn, LOGL_DEBUG, "BTS %u has no matching free channels\n", bts->nr);
			continue;
		}

		/* Found a match. */
		ho->new_bts = bts;
		ho->new_lchan = lchan;
		break;
	}

	ho_count(ho->new_bts, CTR_HANDOVER_ATTEMPTED);
	ho_count(ho->new_bts, CTR_INTER_BSC_HO_IN_ATTEMPTED);

	if (!ho->new_bts) {
		ho_fail(HO_RESULT_ERROR, "No local cell matches the target %s",
			req->cell_id_target_name);
		return;
	}

	if (!ho->new_lchan) {
		ho_fail(HO_RESULT_ERROR, "No free/matching lchan found for %s %s (speech codec list len = %u)",
			req->cell_id_target_name, gsm0808_channel_type_name(&req->ct), req->scl.len);
		return;
	}

	/* Just for completeness' sake, maybe some logging uses it? */
	ho->new_lchan_type = ho->new_lchan->type;

	ho_fsm_state_chg(HO_ST_WAIT_LCHAN_ACTIVE);

	info = (struct lchan_activate_info){
		.activ_for = ACTIVATE_FOR_HANDOVER,
		.for_conn = conn,
		.ch_mode_rate = ch_mode_rate,
		.requires_voice_stream = chan_mode_is_tch(ch_mode_rate.chan_mode),
		.msc_assigned_cic = req->msc_assigned_cic,
	};

	/* Figure out the encryption algorithm */
	chosen_a5_n = select_best_cipher(req->ei_as_bitmask, bsc_gsmnet->a5_encryption_mask);
	if (chosen_a5_n < 0) {
		ho_fail(HO_RESULT_FAIL_RR_HO_FAIL,
			"There is no A5 encryption mode that both BSC and MSC permit: MSC 0x%x & BSC 0x%x = 0",
			req->ei_as_bitmask, bsc_gsmnet->a5_encryption_mask);
		return;
	}
	if (chosen_a5_n > 0 && !req->ei.key_len) {
		/* There is no key. Is A5/0 permitted? */
		if ((req->ei_as_bitmask & bsc_gsmnet->a5_encryption_mask & 0x1) == 0x1) {
			chosen_a5_n = 0;
		} else {
			ho_fail(HO_RESULT_ERROR,
				"Encryption is required, but there is no key (Encryption Information)");
			return;
		}
	}

	/* Put encryption info in the chan activation info */
	info.encr.alg_a5_n = chosen_a5_n;
	if (chosen_a5_n > 0) {
		if (req->ei.key_len > sizeof(info.encr.key)) {
			ho_fail(HO_RESULT_ERROR, "Encryption Information IE key length is too large: %u",
				req->ei.key_len);
			return;
		}
		memcpy(info.encr.key, req->ei.key, req->ei.key_len);
		info.encr.key_len = req->ei.key_len;
	}

	if (req->kc128_present) {
		memcpy(info.encr.kc128, req->kc128, 16);
		info.encr.kc128_present = true;
	}

	if (req->last_eutran_plmn_valid) {
		conn->fast_return.allowed = ho->new_bts->srvcc_fast_return_allowed;
		conn->fast_return.last_eutran_plmn_valid = true;
		memcpy(&conn->fast_return.last_eutran_plmn, &req->last_eutran_plmn,
		       sizeof(conn->fast_return.last_eutran_plmn));
		ho_count(ho->new_bts, CTR_SRVCC_ATTEMPTED);
	}

	lchan_activate(ho->new_lchan, &info);
}

/* Create functions result_counter_{BSC,BTS}_{HANDOVER,...}(), to evaluate the handover result and return
 * BSC_CTR_HANDOVER_ATTEMPTED,
 * BSC_CTR_HANDOVER_COMPLETED,
 * BSC_CTR_HANDOVER_STOPPED,
 * BSC_CTR_HANDOVER_NO_CHANNEL,
 * BSC_CTR_HANDOVER_TIMEOUT,
 * BSC_CTR_HANDOVER_FAILED,
 * BSC_CTR_HANDOVER_ERROR,
 * or
 * BTS_CTR_HANDOVER_ATTEMPTED,
 * BTS_CTR_HANDOVER_COMPLETED,
 * BTS_CTR_HANDOVER_STOPPED,
 * BTS_CTR_HANDOVER_NO_CHANNEL,
 * BTS_CTR_HANDOVER_TIMEOUT,
 * BTS_CTR_HANDOVER_FAILED,
 * BTS_CTR_HANDOVER_ERROR,
 */
#define FUNC_RESULT_COUNTER(obj, name) \
static int result_counter_##obj##_##name(enum handover_result result) \
{ \
	switch (result) { \
	case HO_RESULT_OK: \
		return obj##_CTR_##name##_COMPLETED; \
	case HO_RESULT_FAIL_NO_CHANNEL: \
		return obj##_CTR_##name##_NO_CHANNEL; \
	case HO_RESULT_FAIL_RR_HO_FAIL: \
		return obj##_CTR_##name##_FAILED; \
	case HO_RESULT_FAIL_TIMEOUT: \
		return obj##_CTR_##name##_TIMEOUT; \
	case HO_RESULT_CONN_RELEASE: \
		return obj##_CTR_##name##_STOPPED; \
	default: \
	case HO_RESULT_ERROR: \
		return obj##_CTR_##name##_ERROR; \
	} \
}

FUNC_RESULT_COUNTER(BSC, HANDOVER)
FUNC_RESULT_COUNTER(BSC, INTRA_CELL_HO)
FUNC_RESULT_COUNTER(BSC, INTRA_BSC_HO)
FUNC_RESULT_COUNTER(BSC, INTER_BSC_HO_IN)

/* INTRA_BSC_HO_OUT does not have a NO_CHANNEL result, so can't do this with FUNC_RESULT_COUNTER() macro. */
static int result_counter_BSC_INTER_BSC_HO_OUT(enum handover_result result) {
	switch (result) {
	case HO_RESULT_OK:
		return BSC_CTR_INTER_BSC_HO_OUT_COMPLETED;
	case HO_RESULT_FAIL_RR_HO_FAIL:
		return BSC_CTR_INTER_BSC_HO_OUT_FAILED;
	case HO_RESULT_FAIL_TIMEOUT:
		return BSC_CTR_INTER_BSC_HO_OUT_TIMEOUT;
	case HO_RESULT_CONN_RELEASE:
		return BSC_CTR_INTER_BSC_HO_OUT_STOPPED;
	default:
	case HO_RESULT_ERROR:
		return BSC_CTR_INTER_BSC_HO_OUT_ERROR;
	}
}

static int result_counter_bsc(enum handover_scope scope, enum handover_result result)
{
	switch (scope) {
	default:
		return -1;
	case HO_INTRA_CELL:
		return result_counter_BSC_INTRA_CELL_HO(result);
	case HO_INTRA_BSC:
		return result_counter_BSC_INTRA_BSC_HO(result);
	case HO_INTER_BSC_OUT:
		return result_counter_BSC_INTER_BSC_HO_OUT(result);
	case HO_INTER_BSC_IN:
		return result_counter_BSC_INTER_BSC_HO_IN(result);
	}
}

FUNC_RESULT_COUNTER(BTS, HANDOVER)
FUNC_RESULT_COUNTER(BTS, INTRA_CELL_HO)
FUNC_RESULT_COUNTER(BTS, INTRA_BSC_HO)
FUNC_RESULT_COUNTER(BTS, INCOMING_INTRA_BSC_HO)
FUNC_RESULT_COUNTER(BTS, INTER_BSC_HO_IN)

/* INTRA_BSC_HO_OUT does not have a NO_CHANNEL result, so can't do this with FUNC_RESULT_COUNTER() macro. */
static int result_counter_BTS_INTER_BSC_HO_OUT(enum handover_result result) {
	switch (result) {
	case HO_RESULT_OK:
		return BTS_CTR_INTER_BSC_HO_OUT_COMPLETED;
	case HO_RESULT_FAIL_RR_HO_FAIL:
		return BTS_CTR_INTER_BSC_HO_OUT_FAILED;
	case HO_RESULT_FAIL_TIMEOUT:
		return BTS_CTR_INTER_BSC_HO_OUT_TIMEOUT;
	case HO_RESULT_CONN_RELEASE:
		return BTS_CTR_INTER_BSC_HO_OUT_STOPPED;
	default:
	case HO_RESULT_ERROR:
		return BTS_CTR_INTER_BSC_HO_OUT_ERROR;
	}
}

static int result_counter_bts(enum handover_scope scope, enum handover_result result)
{
	switch (scope) {
	default:
		return -1;
	case HO_INTRA_CELL:
		return result_counter_BTS_INTRA_CELL_HO(result);
	case HO_INTRA_BSC:
		return result_counter_BTS_INTRA_BSC_HO(result);
	case HO_INTER_BSC_OUT:
		return result_counter_BTS_INTER_BSC_HO_OUT(result);
	case HO_INTER_BSC_IN:
		return result_counter_BTS_INTER_BSC_HO_IN(result);
	}
}

FUNC_RESULT_COUNTER(BSC, SRVCC)
FUNC_RESULT_COUNTER(BTS, SRVCC)

static void send_handover_performed(struct gsm_subscriber_connection *conn)
{
	struct gsm_lchan *lchan = conn->lchan;
	struct handover *ho = &conn->ho;
	struct osmo_cell_global_id *cell;
	struct gsm0808_handover_performed ho_perf_params = {};
	struct msgb *msg;
	struct gsm0808_speech_codec sc;
	int rc;

	/* Cause 3.2.2.5 */
	ho_perf_params.cause = GSM0808_CAUSE_HANDOVER_SUCCESSFUL;

	/* Cell Identifier 3.2.2.17 */
	cell = cgi_for_msc(conn->sccp.msc, conn_get_bts(conn));
	if (!cell) {
		LOG_HO(conn, LOGL_ERROR, "Failed to generate Cell Identifier IE, can't send HANDOVER PERFORMED!\n");
		return;
	}
	ho_perf_params.cell_id = (struct gsm0808_cell_id){
		.id_discr = CELL_IDENT_WHOLE_GLOBAL,
		.id.global = *cell
	};

	/* Chosen Channel 3.2.2.33 */
	ho_perf_params.chosen_channel = gsm0808_chosen_channel(lchan->type, lchan->current_ch_mode_rate.chan_mode);
	if (!ho_perf_params.chosen_channel) {
		LOG_HO(conn, LOGL_ERROR, "Failed to generate Chosen Channel IE, can't send HANDOVER PERFORMED!\n");
		return;
	}
	ho_perf_params.chosen_channel_present = true;

	/* Chosen Encryption Algorithm 3.2.2.44 */
	ho_perf_params.chosen_encr_alg = ALG_A5_NR_TO_BSSAP(lchan->encr.alg_a5_n);
	ho_perf_params.chosen_encr_alg_present = true;

	if (ho->new_lchan->activate.info.requires_voice_stream) {
		/* Speech Version (chosen) 3.2.2.51 */
		ho_perf_params.speech_version_chosen = gsm0808_permitted_speech(lchan->type,
										lchan->current_ch_mode_rate.chan_mode);
		ho_perf_params.speech_version_chosen_present = true;

		/* Speech Codec (chosen) 3.2.2.104 */
		if (gscon_is_aoip(conn)) {
			/* Extrapolate speech codec from speech mode */
			gsm0808_speech_codec_from_chan_type(&sc, ho_perf_params.speech_version_chosen);
			sc.cfg = conn->lchan->current_ch_mode_rate.s15_s0;
			memcpy(&ho_perf_params.speech_codec_chosen, &sc, sizeof(sc));
			ho_perf_params.speech_codec_chosen_present = true;
		}
	}

	msg = gsm0808_create_handover_performed(&ho_perf_params);
	if (!msg) {
		LOG_HO(conn, LOGL_ERROR, "Failed to generate message, can't send HANDOVER PERFORMED!\n");
		return;
	}

	rate_ctr_inc(rate_ctr_group_get_ctr(conn->sccp.msc->msc_ctrs, MSC_CTR_BSSMAP_TX_DT1_HANDOVER_PERFORMED));
	rc = gscon_sigtran_send(conn, msg);
	if (rc < 0) {
		LOG_HO(conn, LOGL_ERROR, "message sending failed, can't send HANDOVER PERFORMED!\n");
		return;
	}
}

/* Notify the handover decision algorithm of failure and clear out any handover state. */
void handover_end(struct gsm_subscriber_connection *conn, enum handover_result result)
{
	struct handover_decision_callbacks *hdc;
	struct handover *ho = &conn->ho;
	struct gsm_bts *bts = conn_get_bts(conn);

	/* Sanity -- an error result ensures beyond doubt that we don't use the new lchan below
	 * when the handover isn't actually allowed to change this conn. */
	if (result == HO_RESULT_OK && ho->new_lchan) {
		if (!(ho->scope & (HO_INTRA_CELL | HO_INTRA_BSC | HO_INTER_BSC_IN))) {
			LOG_HO(conn, LOGL_ERROR, "Got new lchan, but this is not an incoming inter-BSC HO\n");
			result = HO_RESULT_ERROR;
		}
		if (ho->new_lchan->conn != conn) {
			LOG_HO(conn, LOGL_ERROR, "Got new lchan, but it is for another conn\n");
			result = HO_RESULT_ERROR;
		}
	}

	if (ho->scope & HO_INTER_BSC_IN) {
		if (result == HO_RESULT_OK) {
			if (!ho->new_lchan) {
				LOG_HO(conn, LOGL_ERROR, "Inter-BSC HO IN ends in success,"
				       " but there is no lchan\n");
				result = HO_RESULT_ERROR;
			} else
				result = bsc_tx_bssmap_ho_complete(conn, ho->new_lchan);
		}
		/* Not 'else': above checks may still result in HO_RESULT_ERROR. */
		if (result != HO_RESULT_OK) {
			/* Return a BSSMAP Handover Failure, as described in 3GPP TS 48.008 3.1.5.2.2
			 * "Handover Resource Allocation Failure" */
			bsc_tx_bssmap_ho_failure(conn);
		}
	} else if (ho->scope & HO_INTER_BSC_OUT) {
		switch (result) {
		case HO_RESULT_OK:
			break;
		case HO_RESULT_FAIL_RR_HO_FAIL:
			/* Return a BSSMAP Handover Failure, as described in 3GPP TS 48.008 3.1.5.3.2
			 * "Handover Failure" */
			bsc_tx_bssmap_ho_failure(conn);
			break;
		default:
		case HO_RESULT_FAIL_TIMEOUT:
			switch (ho->fi->state) {
			case HO_OUT_ST_WAIT_HO_COMMAND:
				/* MSC never replied with a Handover Command. Fail and ignore the
				 * handover, continue to use the lchan. */
				break;
			default:
			case HO_OUT_ST_WAIT_CLEAR:
				/* 3GPP TS 48.008 3.1.5.3.3 "Abnormal Conditions": if neither MS reports
				 * HO Failure nor the MSC sends a Clear Command, we should release the
				 * dedicated radio resources and send a Clear Request to the MSC. */
				lchan_release(conn->lchan, true, true, GSM48_RR_CAUSE_ABNORMAL_TIMER,
					      gscon_last_eutran_plmn(conn));
				/* Once the channel release is through, the BSSMAP Clear will follow. */
				break;
			}
			break;
		}
	}

	/* Rembered this only for error handling: should handover fail, handover_reset() will release the
	 * MGW endpoint right away. If successful, the conn continues to use the endpoint. */
	if (result == HO_RESULT_OK)
		conn->ho.created_ci_for_msc = NULL;

	/* If the performed handover was an INTRA BSC HANDOVER, inform the MSC that a handover has happened */
	if (result == HO_RESULT_OK && ((ho->scope & HO_INTRA_CELL) || (ho->scope & HO_INTRA_BSC)))
		send_handover_performed(conn);

	hdc = handover_decision_callbacks_get(ho->from_hodec_id);
	if (hdc && hdc->on_handover_end)
		hdc->on_handover_end(conn, result);

	/* HO_INTER_BSC_IN has the source BTS on a remote BSS, so count all of those on the target BTS; also count
	 * errors onto the HO target BTS if no lchan was obtained. */
	if (ho->scope & HO_INTER_BSC_IN)
		bts = ho->new_bts;

	ho_count_bsc(result_counter_BSC_HANDOVER(result));
	ho_count_bsc(result_counter_bsc(ho->scope, result));
	ho_count_bts(bts, result_counter_BTS_HANDOVER(result));
	ho_count_bts(bts, result_counter_bts(ho->scope, result));
	/* For inter-cell HO, also increment the "INCOMING" counters on the target BTS. */
	if (ho->scope & HO_INTRA_BSC)
		ho_count_bts(ho->new_bts, result_counter_BTS_INCOMING_INTRA_BSC_HO(result));
	if (ho->scope & HO_INTER_BSC_IN && conn->fast_return.last_eutran_plmn_valid) {
		/* From outside local BSC and with Last EUTRAN PLMN Id => SRVCC */
		ho_count_bsc(result_counter_BSC_SRVCC(result));
		ho_count_bts(bts, result_counter_BTS_SRVCC(result));
	}

	LOG_HO(conn, LOGL_INFO, "Result: %s\n", handover_result_name(result));

	if (ho->new_lchan && result == HO_RESULT_OK) {
		struct gsm_bts *bts;

		gscon_change_primary_lchan(conn, conn->ho.new_lchan);
		ho->new_lchan = NULL;

		bts = conn_get_bts(conn);
		if (is_siemens_bts(bts) && ts_is_tch(conn->lchan->ts)) {
			/* HACK: store the actual Classmark 2 LV from the subscriber and use it here! */
			uint8_t cm2_lv[] = { 0x02, 0x00, 0x00 };
			send_siemens_mrpci(conn->lchan, cm2_lv);
		}

		/* If a Perform Location Request (LCS) is busy, inform the SMLC that there is a new lchan */
		if (conn->lcs.loc_req)
			osmo_fsm_inst_dispatch(conn->lcs.loc_req->fi, LCS_LOC_REQ_EV_HANDOVER_PERFORMED, NULL);
	}

	osmo_fsm_inst_dispatch(conn->fi, GSCON_EV_HANDOVER_END, &result);

	/* Detach the new_lchan last, so we can still see it in above logging */
	if (ho->new_lchan) {
		/* Release new lchan, it didn't work out */
		lchan_release(ho->new_lchan, false, true, RSL_ERR_EQUIPMENT_FAIL, NULL);
		ho->new_lchan = NULL;
	}

	if ((ho->scope & HO_INTER_BSC_IN) && result == HO_RESULT_OK) {
		conn->user_plane.msc_assigned_cic = conn->ho.inter_bsc_in.msc_assigned_cic;
		osmo_strlcpy(conn->user_plane.msc_assigned_rtp_addr,
			     conn->ho.inter_bsc_in.msc_assigned_rtp_addr,
			     sizeof(conn->user_plane.msc_assigned_rtp_addr));
		conn->user_plane.msc_assigned_rtp_port = conn->ho.inter_bsc_in.msc_assigned_rtp_port;
	}

	handover_reset(conn);

	/* We've dispatched the handover result above, let's disconnect to not fire the same event again.
	 * The parent term event is a safety measure for unplanned termination. */
	osmo_fsm_inst_unlink_parent(conn->ho.fi, conn);
	osmo_fsm_inst_term(conn->ho.fi, OSMO_FSM_TERM_REGULAR, 0);
}

static void ho_fsm_wait_lchan_active(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_subscriber_connection *conn = ho_fi_conn(fi);
	struct handover *ho = &conn->ho;
	switch (event) {

	case HO_EV_LCHAN_ACTIVE:
		/* - If the lchan is voiceless, no need to even think about the MGW.
		 * - If this is an intra-BSC Handover, we already have an RTP stream towards the MSC and aren't
		 *   touching it.
		 * - If we're on SCCPlite, the MSC manages the MGW endpoint, all we do is the BTS side CI, so we can
		 *   skip the part that would CRCX towards the MSC.
		 * So create an MSC side endpoint CI only if a voice lchan is established for an incoming inter-BSC
		 * handover on AoIP. Otherwise go on to send a Handover Command and wait for the Detect.
		 */
		if (ho->new_lchan->activate.info.requires_voice_stream
		    && (ho->scope & HO_INTER_BSC_IN)
		    && gscon_is_aoip(conn))
			ho_fsm_state_chg(HO_ST_WAIT_MGW_ENDPOINT_TO_MSC);
		else
			ho_fsm_state_chg(HO_ST_WAIT_RR_HO_DETECT);
		return;

	case HO_EV_LCHAN_ERROR:
		ho_fail(HO_RESULT_ERROR, "error while activating lchan %s",
			gsm_lchan_name(conn->ho.new_lchan));
		return;

	default:
		OSMO_ASSERT(false);
	}
}

/* Only for voice, only for inter-BSC Handover into this BSC, and only for AoIP:
 *
 * Establish the MGW endpoint CI that points towards the MSC. This needs to happen after the lchan (lchan_rtp_fsm) has
 * created an MGW endpoint with the first CRCX, so that an endpoint is available, and before sending the Handover
 * Request Acknowledge, so that the RTP address and port established towards the MSC can be included in the Handover
 * Request Acknowledge message.
 * (For SCCPlite, the MSC manages the CN side endpoint CI itself, and we don't need to send any RTP address in the
 * Handover Request Acknowledge.)
 *
 * Actually, it should be possible to kick this off even above in handover_start_inter_bsc_in(), to do the CRCX towards
 * the MSC at the same time as establishing the lchan. The gscon_ensure_mgw_endpoint() doesn't care which one of
 * lchan_rtp_fsm or handover_start_inter_bsc_in() calls it first. The benefit would be that we'd send out the Handover
 * Command ever so slightly sooner -- which isn't critical really, because a) how long does a CRCX take, milliseconds?
 * and b) the time critical part is *after* the Handover Command was kicked off to keep the transition between cells as
 * short as possible. The drawback of doing this earlier is code complexity: receiving the HO_EV_MSC_MGW_OK /
 * HO_EV_MSC_MGW_FAIL events would need to be juggled in between the HO_EV_LCHAN_ACTIVE / HO_EV_LCHAN_ERROR. So the
 * decision for now is to leave it here.
 */
static void ho_fsm_wait_mgw_endpoint_to_msc_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct gsm_subscriber_connection *conn = ho_fi_conn(fi);
	struct handover *ho = &conn->ho;

	if (!gscon_connect_mgw_to_msc(conn,
				      ho->new_lchan,
				      ho->inter_bsc_in.msc_assigned_rtp_addr,
				      ho->inter_bsc_in.msc_assigned_rtp_port,
				      fi,
				      HO_EV_MSC_MGW_OK,
				      HO_EV_MSC_MGW_FAIL,
				      NULL,
				      &ho->created_ci_for_msc)) {
		ho_fail(HO_RESULT_ERROR,
			"Unable to connect MGW endpoint to the MSC side");
	}
}

static void ho_fsm_wait_mgw_endpoint_to_msc(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_subscriber_connection *conn = ho_fi_conn(fi);
	const struct mgcp_conn_peer *mgw_info;

	switch (event) {

	case HO_EV_MSC_MGW_OK:
		/* Ensure the endpoint is really there, and log it. This state is only entered for AoIP connections, see
		 * ho_fsm_wait_lchan_active() above. */
		mgw_info = osmo_mgcpc_ep_ci_get_rtp_info(conn->user_plane.mgw_endpoint_ci_msc);
		if (!mgw_info) {
			ho_fail(HO_RESULT_ERROR,
				"Unable to retrieve RTP port info allocated by MGW for"
				" the MSC side.");
			return;
		}
		LOG_HO(conn, LOGL_DEBUG, "MGW's MSC side CI: %s:%u\n",
		       mgw_info->addr, mgw_info->port);
		ho_fsm_state_chg(HO_ST_WAIT_RR_HO_DETECT);
		return;

	case HO_EV_MSC_MGW_FAIL:
		ho_fail(HO_RESULT_ERROR,
			"Unable to connect MGW endpoint to the MSC side");
		return;

	default:
		OSMO_ASSERT(false);
	}
}

static void ho_fsm_wait_rr_ho_detect_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	int rc;
	struct gsm_subscriber_connection *conn = ho_fi_conn(fi);
	struct handover *ho = &conn->ho;

	struct msgb *rr_ho_cmd = gsm48_make_ho_cmd(ho->new_lchan,
						   ho->scope, ho->async,
						   ho->new_lchan->ms_power,
						   ho->ho_ref);
	if (!rr_ho_cmd) {
		ho_fail(HO_RESULT_ERROR, "Unable to compose RR Handover Command");
		return;
	}


	if (ho->scope & (HO_INTRA_CELL | HO_INTRA_BSC)) {
		/* conn->lchan is the old lchan being handovered from */
		rr_ho_cmd->lchan = conn->lchan;
		rc = gsm48_sendmsg(rr_ho_cmd);
		if (rc)
			ho_fail(HO_RESULT_ERROR, "Unable to Tx RR Handover Command (rc=%d %s)",
				rc, strerror(-rc));
		return;
	}

	if (ho->scope & HO_INTER_BSC_IN) {
		rc = bsc_tx_bssmap_ho_request_ack(conn, rr_ho_cmd);
		if (rc)
			ho_fail(HO_RESULT_ERROR, "Unable to Tx BSSMAP Handover Request Ack (rc=%d %s)",
				rc, strerror(-rc));
		return;
	}

	ho_fail(HO_RESULT_ERROR, "Invalid situation, no target for RR Handover Command");
}

static void ho_fsm_wait_rr_ho_detect(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_subscriber_connection *conn = ho_fi_conn(fi);
	struct handover *ho = &conn->ho;
	switch (event) {

	case HO_EV_RR_HO_DETECT:
		{
			struct handover_rr_detect_data *d = data;
			OSMO_ASSERT(d);
			if (d->access_delay) {
				LOG_HO(conn, LOGL_DEBUG, "RR Handover Detect (Access Delay=%u)\n",
				       *(d->access_delay));
			} else
				LOG_HO(conn, LOGL_DEBUG, "RR Handover Detect (no Access Delay IE)\n");
		}

		if (ho->scope & HO_INTER_BSC_IN) {
			int rc = bsc_tx_bssmap_ho_detect(conn);
			if (rc) {
				ho_fail(HO_RESULT_ERROR,
					"Unable to send BSSMAP Handover Detect");
				return;
			}
		}

		if (ho->new_lchan->fi_rtp)
			osmo_fsm_inst_dispatch(ho->new_lchan->fi_rtp,
					       LCHAN_RTP_EV_READY_TO_SWITCH_RTP, 0);
		ho_fsm_state_chg(HO_ST_WAIT_RR_HO_COMPLETE);
		/* The lchan FSM will already start to redirect the RTP stream */
		return;

	case HO_EV_RR_HO_COMPLETE:
		LOG_HO(conn, LOGL_ERROR,
			"Received RR Handover Complete, but haven't even seen a Handover Detect yet;"
			" Accepting handover anyway\n");
		if (ho->new_lchan->fi_rtp)
			osmo_fsm_inst_dispatch(ho->new_lchan->fi_rtp,
					       LCHAN_RTP_EV_READY_TO_SWITCH_RTP, 0);
		ho_fsm_state_chg(HO_ST_WAIT_LCHAN_ESTABLISHED);
		return;

	case HO_EV_RR_HO_FAIL:
		ho_fail(HO_RESULT_FAIL_RR_HO_FAIL, "Received RR Handover Fail message");
		return;

	default:
		OSMO_ASSERT(false);
	}
}

static void ho_fsm_wait_rr_ho_complete(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_subscriber_connection *conn = ho_fi_conn(fi);

	switch (event) {

	case HO_EV_RR_HO_DETECT:
		/* Numerous HO Detect RACH bursts may follow after the initial one, ignore. */
		return;

	case HO_EV_LCHAN_ESTABLISHED:
		LOG_HO(conn, LOGL_DEBUG, "lchan established, still waiting for RR Handover Complete\n");
		/* The lchan is already done with all of its RTP setup. We will notice the lchan state
		 * being LCHAN_ST_ESTABLISHED in ho_fsm_wait_lchan_established_onenter(). */
		return;

	case HO_EV_RR_HO_COMPLETE:
		ho_fsm_state_chg(HO_ST_WAIT_LCHAN_ESTABLISHED);
		return;

	case HO_EV_RR_HO_FAIL:
		ho_fail(HO_RESULT_FAIL_RR_HO_FAIL, "Received RR Handover Fail message");
		return;

	default:
		OSMO_ASSERT(false);
	}
}

static void ho_fsm_wait_lchan_established_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct gsm_subscriber_connection *conn = ho_fi_conn(fi);

	if (conn->ho.fi && lchan_state_is(conn->ho.new_lchan, LCHAN_ST_ESTABLISHED)) {
		LOG_HO(conn, LOGL_DEBUG, "lchan already established earlier\n");
		ho_success();
	}
}

static void ho_fsm_wait_lchan_established(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_subscriber_connection *conn = ho_fi_conn(fi);

	switch (event) {
	case HO_EV_LCHAN_ESTABLISHED:
		ho_success();
		break;

	default:
		OSMO_ASSERT(false);
	}
}

/* Inter-BSC OUT */

static void handover_start_inter_bsc_out(struct gsm_subscriber_connection *conn,
					 const struct gsm0808_cell_id_list2 *target_cells)
{
	int rc;
	struct handover *ho = &conn->ho;
	struct osmo_fsm_inst *fi = conn->ho.fi;
	struct gsm_bts *bts = conn_get_bts(conn);

	ho->scope = HO_INTER_BSC_OUT;
	ho_fsm_update_id(fi, "interBSCout");
	ho_count(bts, CTR_INTER_BSC_HO_OUT_ATTEMPTED);

	rc = bsc_tx_bssmap_ho_required(conn->lchan, target_cells);
	if (rc) {
		ho_fail(HO_RESULT_ERROR, "Unable to send BSSMAP Handover Required message");
		return;
	}

	ho_fsm_state_chg(HO_OUT_ST_WAIT_HO_COMMAND);
}

static void ho_out_fsm_wait_ho_command(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	int rc;
	struct ho_out_rx_bssmap_ho_command *rx;
	struct gsm_subscriber_connection *conn = ho_fi_conn(fi);
	switch (event) {

	case HO_OUT_EV_BSSMAP_HO_COMMAND:
		rx = data;
		if (!rx) {
			ho_fail(HO_RESULT_ERROR,
				"Rx BSSMAP Handover Command: no L3 info passed with event");
			return;
		}

		LOG_HO(conn, LOGL_DEBUG, "Rx BSSMAP Handover Command: forwarding Layer 3 Info: %s\n",
		       osmo_hexdump(rx->l3_info, rx->l3_info_len));

		rc = rsl_forward_layer3_info(conn->lchan, rx->l3_info, rx->l3_info_len);
		if (rc) {
			ho_fail(HO_RESULT_ERROR,
				"Rx BSSMAP Handover Command: Failed to forward Layer 3 Info (rc=%d %s)",
				rc, strerror(-rc));
			return;
		}

		ho_fsm_state_chg(HO_OUT_ST_WAIT_CLEAR);
		return;

	default:
		OSMO_ASSERT(false);
	}
}

static void ho_out_fsm_wait_clear(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_subscriber_connection *conn = ho_fi_conn(fi);
	switch (event) {
		/* See also ho_fsm_allstate_action() for ho_success() on HO_EV_CONN_RELEASING */

	case HO_EV_RR_HO_FAIL:
		ho_fail(HO_RESULT_FAIL_RR_HO_FAIL, "Received RR Handover Failure message");
		return;

	default:
		OSMO_ASSERT(false);
	}
}

#define S(x)	(1 << (x))

static const struct osmo_fsm_state ho_fsm_states[] = {
	[HO_ST_NOT_STARTED] = {
		.name = "NOT_STARTED",
		.out_state_mask = 0
			| S(HO_ST_WAIT_LCHAN_ACTIVE)
			| S(HO_OUT_ST_WAIT_HO_COMMAND)
			,
	},
	[HO_ST_WAIT_LCHAN_ACTIVE] = {
		.name = "WAIT_LCHAN_ACTIVE",
		.action = ho_fsm_wait_lchan_active,
		.in_event_mask = 0
			| S(HO_EV_LCHAN_ACTIVE)
			| S(HO_EV_LCHAN_ERROR)
			,
		.out_state_mask = 0
			| S(HO_ST_WAIT_LCHAN_ACTIVE)
			| S(HO_ST_WAIT_MGW_ENDPOINT_TO_MSC)
			| S(HO_ST_WAIT_RR_HO_DETECT)
			,
	},
	[HO_ST_WAIT_MGW_ENDPOINT_TO_MSC] = {
		.name = "WAIT_MGW_ENDPOINT_TO_MSC",
		.onenter = ho_fsm_wait_mgw_endpoint_to_msc_onenter,
		.action = ho_fsm_wait_mgw_endpoint_to_msc,
		.in_event_mask = 0
			| S(HO_EV_MSC_MGW_OK)
			| S(HO_EV_MSC_MGW_FAIL)
			,
		.out_state_mask = 0
			| S(HO_ST_WAIT_RR_HO_DETECT)
			,
	},
	[HO_ST_WAIT_RR_HO_DETECT] = {
		.name = "WAIT_RR_HO_DETECT",
		.onenter = ho_fsm_wait_rr_ho_detect_onenter,
		.action = ho_fsm_wait_rr_ho_detect,
		.in_event_mask = 0
			| S(HO_EV_RR_HO_DETECT)
			| S(HO_EV_RR_HO_COMPLETE) /* actually as error */
			| S(HO_EV_RR_HO_FAIL)
			,
		.out_state_mask = 0
			| S(HO_ST_WAIT_RR_HO_COMPLETE)
			| S(HO_ST_WAIT_LCHAN_ESTABLISHED)
			,
	},
	[HO_ST_WAIT_RR_HO_COMPLETE] = {
		.name = "WAIT_RR_HO_COMPLETE",
		.action = ho_fsm_wait_rr_ho_complete,
		.in_event_mask = 0
			| S(HO_EV_RR_HO_DETECT) /* ignore extra HO RACH */
			| S(HO_EV_LCHAN_ESTABLISHED)
			| S(HO_EV_RR_HO_COMPLETE)
			| S(HO_EV_RR_HO_FAIL)
			,
		.out_state_mask = 0
			| S(HO_ST_WAIT_LCHAN_ESTABLISHED)
			,
	},
	[HO_ST_WAIT_LCHAN_ESTABLISHED] = {
		.name = "WAIT_LCHAN_ESTABLISHED",
		.onenter = ho_fsm_wait_lchan_established_onenter,
		.action = ho_fsm_wait_lchan_established,
		.in_event_mask = 0
			| S(HO_EV_LCHAN_ESTABLISHED)
			,
	},
	[HO_OUT_ST_WAIT_HO_COMMAND] = {
		.name = "inter-BSC-OUT:WAIT_HO_COMMAND",
		.action = ho_out_fsm_wait_ho_command,
		.in_event_mask = 0
			| S(HO_OUT_EV_BSSMAP_HO_COMMAND)
			,
		.out_state_mask = 0
			| S(HO_OUT_ST_WAIT_CLEAR)
			,
	},
	[HO_OUT_ST_WAIT_CLEAR] = {
		.name = "inter-BSC-OUT:WAIT_CLEAR",
		.in_event_mask = 0
			| S(HO_EV_RR_HO_FAIL)
			,
		.action = ho_out_fsm_wait_clear,
	},
};

static const struct value_string ho_fsm_event_names[] = {
	OSMO_VALUE_STRING(HO_EV_LCHAN_ACTIVE),
	OSMO_VALUE_STRING(HO_EV_LCHAN_ESTABLISHED),
	OSMO_VALUE_STRING(HO_EV_LCHAN_ERROR),
	OSMO_VALUE_STRING(HO_EV_RR_HO_DETECT),
	OSMO_VALUE_STRING(HO_EV_RR_HO_COMPLETE),
	OSMO_VALUE_STRING(HO_EV_RR_HO_FAIL),
	OSMO_VALUE_STRING(HO_EV_MSC_MGW_OK),
	OSMO_VALUE_STRING(HO_EV_MSC_MGW_FAIL),
	OSMO_VALUE_STRING(HO_EV_CONN_RELEASING),
	OSMO_VALUE_STRING(HO_OUT_EV_BSSMAP_HO_COMMAND),
	{}
};

void ho_fsm_allstate_action(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_subscriber_connection *conn = ho_fi_conn(fi);
	switch (event) {

	case HO_EV_CONN_RELEASING:
		switch (fi->state) {
		case HO_OUT_ST_WAIT_CLEAR:
			ho_success();
			return;
		default:
			ho_fail(HO_RESULT_CONN_RELEASE,
				"Connection releasing in the middle of handover");
			return;
		}

	case HO_EV_LCHAN_ERROR:
		switch (fi->state) {
		case HO_OUT_ST_WAIT_HO_COMMAND:
		case HO_OUT_ST_WAIT_CLEAR:
			LOG_HO(conn, LOGL_ERROR, "Event not permitted: %s\n",
			       osmo_fsm_event_name(fi->fsm, event));
			return;

		default:
			ho_fail(HO_RESULT_ERROR, "Error while establishing lchan %s",
				gsm_lchan_name(data));
			return;
		}

	default:
		OSMO_ASSERT(false);
	}
}

int ho_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	struct gsm_subscriber_connection *conn = ho_fi_conn(fi);
	ho_fail(HO_RESULT_FAIL_TIMEOUT, "Timeout");
	return 0;
}

void ho_fsm_cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct gsm_subscriber_connection *conn = ho_fi_conn(fi);
	conn->ho.fi = NULL;
}

static struct osmo_fsm ho_fsm = {
	.name = "handover",
	.states = ho_fsm_states,
	.num_states = ARRAY_SIZE(ho_fsm_states),
	.log_subsys = DRSL,
	.event_names = ho_fsm_event_names,
	.allstate_action = ho_fsm_allstate_action,
	.allstate_event_mask = 0
		| S(HO_EV_CONN_RELEASING)
		| S(HO_EV_LCHAN_ERROR)
		,
	.timer_cb = ho_fsm_timer_cb,
	.cleanup = ho_fsm_cleanup,
};
