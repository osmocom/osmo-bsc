/* GSM 08.08 like API for OpenBSC. The bridge from MSC to BSC */

/* (C) 2010-2011 by Holger Hans Peter Freyther
 * (C) 2010-2011 by On-Waves
 * (C) 2009,2017 by Harald Welte <laforge@gnumonks.org>
 *
 * All Rights Reserved
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

#include <osmocom/bsc/bsc_api.h>
#include <osmocom/bsc/bsc_rll.h>
#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/signal.h>
#include <osmocom/bsc/abis_rsl.h>
#include <osmocom/bsc/chan_alloc.h>
#include <osmocom/bsc/handover.h>
#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/gsm_04_08_utils.h>
#include <osmocom/bsc/bsc_subscriber.h>
#include <osmocom/bsc/penalty_timers.h>
#include <osmocom/bsc/osmo_bsc_sigtran.h>

#include <osmocom/gsm/protocol/gsm_08_08.h>
#include <osmocom/gsm/gsm48.h>

#include <osmocom/core/talloc.h>

#define GSM0808_T10_VALUE    6, 0

#define HO_DTAP_CACHE_MSGB_CB_LINK_ID 0
#define HO_DTAP_CACHE_MSGB_CB_ALLOW_SACCH 1

static void rll_ind_cb(struct gsm_lchan *, uint8_t, void *, enum bsc_rllr_ind);
static void handle_release(struct gsm_subscriber_connection *conn, struct  gsm_lchan *lchan);
static void handle_chan_ack(struct gsm_subscriber_connection *conn, struct  gsm_lchan *lchan);
static void handle_chan_nack(struct gsm_subscriber_connection *conn, struct  gsm_lchan *lchan);

/*
 * Start a new assignment and make sure that it is completed within T10 either
 * positively, negatively or by the timeout.
 *
 *  1.) allocate a new lchan
 *  2.) copy the encryption key and other data from the
 *      old to the new channel.
 *  3.) RSL Channel Activate this channel and wait
 *
 * -> Signal handler for the LCHAN
 *  4.) Send GSM 04.08 assignment command to the MS
 *
 * -> Assignment Complete/Assignment Failure
 *  5.) Release the SDCCH, continue signalling on the new link
 */
static int handle_new_assignment(struct gsm_subscriber_connection *conn, int chan_mode, int full_rate)
{
	struct gsm_lchan *new_lchan;
	enum gsm_chan_t chan_type;

	chan_type = full_rate ? GSM_LCHAN_TCH_F : GSM_LCHAN_TCH_H;

	new_lchan = lchan_alloc(conn_get_bts(conn), chan_type, 0);

	if (!new_lchan) {
		LOGP(DMSC, LOGL_NOTICE, "%s No free channel for %s\n",
		     bsc_subscr_name(conn->bsub), gsm_lchant_name(chan_type));
		return -1;
	}

	/* check if we are on TCH/F and requested TCH/H, but got TCH/F */
	if (conn->lchan->type == new_lchan->type
	    && chan_type != new_lchan->type) {
		LOGPLCHAN(conn->lchan, DHO, LOGL_NOTICE,
			  "-> %s Will not re-assign to identical channel type, %s was requested\n",
			  gsm_lchan_name(new_lchan), gsm_lchant_name(chan_type));
		lchan_free(new_lchan);
		return -1;
	}

	/* copy old data to the new channel */
	memcpy(&new_lchan->encr, &conn->lchan->encr, sizeof(new_lchan->encr));
	new_lchan->ms_power = conn->lchan->ms_power;
	new_lchan->bs_power = conn->lchan->bs_power;
	new_lchan->rqd_ta = conn->lchan->rqd_ta;

	/* copy new data to it */
	new_lchan->tch_mode = chan_mode;
	new_lchan->rsl_cmode = (chan_mode == GSM48_CMODE_SIGN) ?
					RSL_CMOD_SPD_SIGN : RSL_CMOD_SPD_SPEECH;

	/* handle AMR correctly */
	if (chan_mode == GSM48_CMODE_SPEECH_AMR)
		bsc_mr_config(conn, new_lchan, full_rate);

	if (rsl_chan_activate_lchan(new_lchan, RSL_ACT_INTRA_NORM_ASS, 0) < 0) {
		LOGPLCHAN(new_lchan, DHO, LOGL_ERROR, "could not activate channel\n");
		lchan_free(new_lchan);
		return -1;
	}

	/* remember that we have the channel */
	conn->secondary_lchan = new_lchan;
	new_lchan->conn = conn;
	return 0;
}

static void ho_dtap_cache_add(struct gsm_subscriber_connection *conn, struct msgb *msg,
			      int link_id, bool allow_sacch)
{
	if (conn->ho_dtap_cache_len >= 23) {
		LOGP(DHO, LOGL_ERROR, "%s: Cannot cache more DTAP messages,"
		     " already reached sane maximum of %u cached messages\n",
		     bsc_subscr_name(conn->bsub), conn->ho_dtap_cache_len);
		msgb_free(msg);
		return;
	}
	conn->ho_dtap_cache_len ++;
	LOGP(DHO, LOGL_DEBUG, "%s: Caching DTAP message during ho/ass (%u)\n",
	     bsc_subscr_name(conn->bsub), conn->ho_dtap_cache_len);
	msg->cb[HO_DTAP_CACHE_MSGB_CB_LINK_ID] = (unsigned long)link_id;
	msg->cb[HO_DTAP_CACHE_MSGB_CB_ALLOW_SACCH] = allow_sacch ? 1 : 0;
	msgb_enqueue(&conn->ho_dtap_cache, msg);
}

void ho_dtap_cache_flush(struct gsm_subscriber_connection *conn, int send)
{
	struct msgb *msg;
	unsigned int flushed_count = 0;

	if (conn->secondary_lchan || conn->ho) {
		LOGP(DHO, LOGL_ERROR, "%s: Cannot send cached DTAP messages, handover/assignment is still ongoing\n",
		     bsc_subscr_name(conn->bsub));
		send = 0;
	}

	while ((msg = msgb_dequeue(&conn->ho_dtap_cache))) {
		conn->ho_dtap_cache_len --;
		flushed_count ++;
		if (send) {
			int link_id = (int)msg->cb[HO_DTAP_CACHE_MSGB_CB_LINK_ID];
			bool allow_sacch = !!msg->cb[HO_DTAP_CACHE_MSGB_CB_ALLOW_SACCH];
			LOGP(DHO, LOGL_DEBUG, "%s: Sending cached DTAP message after handover/assignment (%u/%u)\n",
			     bsc_subscr_name(conn->bsub), flushed_count, conn->ho_dtap_cache_len);
			gsm0808_submit_dtap(conn, msg, link_id, allow_sacch);
		} else
			msgb_free(msg);
	}
}

/*! \brief process incoming 08.08 DTAP from MSC (send via BTS to MS) */
int gsm0808_submit_dtap(struct gsm_subscriber_connection *conn,
			struct msgb *msg, int link_id, int allow_sacch)
{
	uint8_t sapi;


	if (!conn->lchan) {
		LOGP(DMSC, LOGL_ERROR,
		     "%s Called submit dtap without an lchan.\n",
		     bsc_subscr_name(conn->bsub));
		msgb_free(msg);
		return -1;
	}

	/* buffer message during assignment / handover */
	if (conn->secondary_lchan || conn->ho) {
		ho_dtap_cache_add(conn, msg, link_id, !! allow_sacch);
		return 0;
	}

	sapi = link_id & 0x7;
	msg->lchan = conn->lchan;
	msg->dst = msg->lchan->ts->trx->rsl_link;

	/* If we are on a TCH and need to submit a SMS (on SAPI=3) we need to use the SACH */
	if (allow_sacch && sapi != 0) {
		if (conn->lchan->type == GSM_LCHAN_TCH_F || conn->lchan->type == GSM_LCHAN_TCH_H)
			link_id |= 0x40;
	}

	msg->l3h = msg->data;
	/* is requested SAPI already up? */
	if (conn->lchan->sapis[sapi] == LCHAN_SAPI_UNUSED) {
		/* Establish L2 for additional SAPI */
		OBSC_LINKID_CB(msg) = link_id;
		if (rll_establish(msg->lchan, sapi, rll_ind_cb, msg) != 0) {
			msgb_free(msg);
			bsc_sapi_n_reject(conn, link_id);
			return -1;
		}
		return 0;
	} else {
		/* Directly forward via RLL/RSL to BTS */
		return rsl_data_request(msg, link_id);
	}
}

/*
 * \brief Check if the given channel is compatible with the mode/fullrate
 */
static int chan_compat_with_mode(struct gsm_lchan *lchan, int chan_mode, int full_rate)
{
	switch (chan_mode) {
	case GSM48_CMODE_SIGN:
		switch (lchan->type) {
		case GSM_LCHAN_TCH_F:
		case GSM_LCHAN_TCH_H:
		case GSM_LCHAN_SDCCH:
			return 1;
		default:
			return 0;
		}
	case GSM48_CMODE_SPEECH_V1:
	case GSM48_CMODE_SPEECH_AMR:
	case GSM48_CMODE_DATA_3k6:
	case GSM48_CMODE_DATA_6k0:
		/* these services can all run on TCH/H, but we may have
		 * an explicit override by the 'full_rate' argument */
		switch (lchan->type) {
		case GSM_LCHAN_TCH_F:
			return full_rate ? 1 : 0;
		case GSM_LCHAN_TCH_H:
			return full_rate ? 0 : 1;
		default:
			return 0;
		}
	case GSM48_CMODE_DATA_12k0:
	case GSM48_CMODE_DATA_14k5:
	case GSM48_CMODE_SPEECH_EFR:
		/* these services all explicitly require a TCH/F */
		return (lchan->type == GSM_LCHAN_TCH_F) ? 1 : 0;
	default:
		return 0;
	}
}

/*! Send a GSM08.08 Assignment Request. Right now this does not contain the
 *  audio codec type or the allowed rates for the config. In case the current
 *  channel does not allow the selected mode a new one will be allocated.
 *  \param[out] conn related subscriber connection
 *  \param[in] chan_mode mode of the channel (see enum gsm48_chan_mode)
 *  \param[in] full_rate select full rate or half rate channel
 *  \returns 0 on success, 1 when no operation is neccessary, -1 on failure */
int gsm0808_assign_req(struct gsm_subscriber_connection *conn, int chan_mode, int full_rate)
{
	/* TODO: Add multirate configuration, make it work for more than audio. */

	if (!chan_compat_with_mode(conn->lchan, chan_mode, full_rate)) {
		if (handle_new_assignment(conn, chan_mode, full_rate) != 0)
			goto error;
	} else {
		/* Check if the channel is already in the requested mode, if
		 * yes, we skip unnecessary channel mode modify operations. */
		if (conn->lchan->tch_mode == chan_mode)
			return 1;

		if (chan_mode == GSM48_CMODE_SPEECH_AMR)
			bsc_mr_config(conn, conn->lchan, full_rate);

		LOGPLCHAN(conn->lchan, DMSC, LOGL_NOTICE,
			  "Sending ChanModify for speech: %s\n",
			  get_value_string(gsm48_chan_mode_names, chan_mode));
		gsm48_lchan_modify(conn->lchan, chan_mode);
	}

	/* we expect the caller will manage T10 */
	return 0;

error:
	bsc_assign_fail(conn, 0, NULL);
	return -1;
}

int gsm0808_page(struct gsm_bts *bts, unsigned int page_group, unsigned int mi_len,
		 uint8_t *mi, int chan_type)
{
	return rsl_paging_cmd(bts, page_group, mi_len, mi, chan_type, false);
}

static void handle_ass_compl(struct gsm_subscriber_connection *conn,
			     struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	enum gsm48_rr_cause cause;

	/* Expecting gsm48_hdr + cause value */
	if (msgb_l3len(msg) != sizeof(*gh) + 1) {
		LOGPLCHAN(msg->lchan, DRR, LOGL_ERROR,
			  "RR Assignment Complete: length invalid: %u, expected %zu\n",
			  msgb_l3len(msg), sizeof(*gh) + 1);
		return;
	}

	cause = gh->data[0];

	LOGPLCHAN(msg->lchan, DRR, LOGL_DEBUG, "ASSIGNMENT COMPLETE cause = %s\n",
		  rr_cause_name(cause));

	if (conn->ho) {
		struct lchan_signal_data sig = {
			.lchan = msg->lchan,
		};
		osmo_signal_dispatch(SS_LCHAN, S_LCHAN_ASSIGNMENT_COMPL, &sig);
		/* FIXME: release old channel */

		/* send pending messages, if any */
		ho_dtap_cache_flush(conn, 1);

		return;
	}

	if (conn->secondary_lchan != msg->lchan) {
		LOGPLCHAN(msg->lchan, DRR, LOGL_ERROR,
			  "RR Assignment Complete does not match conn's secondary lchan.\n");
		return;
	}

	lchan_release(conn->lchan, 0, RSL_REL_LOCAL_END);
	conn->lchan = conn->secondary_lchan;
	conn->secondary_lchan = NULL;

	/* send pending messages, if any */
	ho_dtap_cache_flush(conn, 1);

	if (is_ipaccess_bts(conn_get_bts(conn)) && conn->lchan->tch_mode != GSM48_CMODE_SIGN)
		rsl_ipacc_crcx(conn->lchan);

	bsc_assign_compl(conn, cause);
}

static void handle_ass_fail(struct gsm_subscriber_connection *conn,
			    struct msgb *msg)
{
	uint8_t *rr_failure;
	struct gsm48_hdr *gh;

	if (conn->ho) {
		struct lchan_signal_data sig;
		struct gsm48_hdr *gh = msgb_l3(msg);

		LOGPLCHAN(msg->lchan, DRR, LOGL_DEBUG, "ASSIGNMENT FAILED cause = %s\n",
			  rr_cause_name(gh->data[0]));

		sig.lchan = msg->lchan;
		sig.mr = NULL;
		osmo_signal_dispatch(SS_LCHAN, S_LCHAN_ASSIGNMENT_FAIL, &sig);
		/* FIXME: release allocated new channel */

		/* send pending messages, if any */
		ho_dtap_cache_flush(conn, 1);

		return;
	}

	if (conn->lchan != msg->lchan) {
		LOGPLCHAN(msg->lchan, DMSC, LOGL_ERROR,
			  "Assignment failure should occur on primary lchan.\n");
		return;
	}

	/* stop the timer and release it */
	if (conn->secondary_lchan) {
		lchan_release(conn->secondary_lchan, 0, RSL_REL_LOCAL_END);
		conn->secondary_lchan = NULL;
	}

	/* send pending messages, if any */
	ho_dtap_cache_flush(conn, 1);

	gh = msgb_l3(msg);
	if (msgb_l3len(msg) - sizeof(*gh) != 1) {
		LOGPLCHAN(conn->lchan, DMSC, LOGL_ERROR, "assignment failure unhandled: %zu\n",
			  msgb_l3len(msg) - sizeof(*gh));
		rr_failure = NULL;
	} else {
		rr_failure = &gh->data[0];
	}

	bsc_assign_fail(conn, GSM0808_CAUSE_RADIO_INTERFACE_MESSAGE_FAILURE, rr_failure);
}

static void handle_classmark_chg(struct gsm_subscriber_connection *conn,
				 struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
	uint8_t cm2_len, cm3_len = 0;
	uint8_t *cm2, *cm3 = NULL;

	LOGPLCHAN(msg->lchan, DRR, LOGL_DEBUG, "CLASSMARK CHANGE ");

	/* classmark 2 */
	cm2_len = gh->data[0];
	cm2 = &gh->data[1];
	DEBUGPC(DRR, "CM2(len=%u) ", cm2_len);

	if (payload_len > cm2_len + 1) {
		/* we must have a classmark3 */
		if (gh->data[cm2_len+1] != 0x20) {
			DEBUGPC(DRR, "ERR CM3 TAG\n");
			return;
		}
		if (cm2_len > 3) {
			DEBUGPC(DRR, "CM2 too long!\n");
			return;
		}

		cm3_len = gh->data[cm2_len+2];
		cm3 = &gh->data[cm2_len+3];
		if (cm3_len > 14) {
			DEBUGPC(DRR, "CM3 len %u too long!\n", cm3_len);
			return;
		}
		DEBUGPC(DRR, "CM3(len=%u)\n", cm3_len);
	}
	bsc_cm_update(conn, cm2, cm2_len, cm3, cm3_len);
}

/* Chapter 9.1.16 Handover complete */
static void handle_rr_ho_compl(struct msgb *msg)
{
	struct lchan_signal_data sig;
	struct gsm48_hdr *gh = msgb_l3(msg);

	LOGPLCHAN(msg->lchan, DRR, LOGL_DEBUG,
		  "HANDOVER COMPLETE cause = %s\n", rr_cause_name(gh->data[0]));

	sig.lchan = msg->lchan;
	sig.mr = NULL;
	osmo_signal_dispatch(SS_LCHAN, S_LCHAN_HANDOVER_COMPL, &sig);
	/* FIXME: release old channel */

	/* send pending messages, if any */
	ho_dtap_cache_flush(msg->lchan->conn, 1);
}

/* Chapter 9.1.17 Handover Failure */
static void handle_rr_ho_fail(struct msgb *msg)
{
	struct lchan_signal_data sig;
	struct gsm48_hdr *gh = msgb_l3(msg);

	/* Log on both RR and HO categories: it is an RR message, but is still quite important when
	 * filtering on HO. */
	LOGPLCHAN(msg->lchan, DRR, LOGL_DEBUG,
		  "HANDOVER FAILED cause = %s\n", rr_cause_name(gh->data[0]));
	LOGPLCHAN(msg->lchan, DHO, LOGL_DEBUG,
		  "HANDOVER FAILED cause = %s\n", rr_cause_name(gh->data[0]));

	sig.lchan = msg->lchan;
	sig.mr = NULL;
	osmo_signal_dispatch(SS_LCHAN, S_LCHAN_HANDOVER_FAIL, &sig);
	/* FIXME: release allocated new channel */

	/* send pending messages, if any */
	ho_dtap_cache_flush(msg->lchan->conn, 1);
}


static void dispatch_dtap(struct gsm_subscriber_connection *conn,
			  uint8_t link_id, struct msgb *msg)
{
	struct gsm48_hdr *gh;
	uint8_t pdisc;
	uint8_t msg_type;
	int rc;

	if (msgb_l3len(msg) < sizeof(*gh)) {
		LOGP(DMSC, LOGL_ERROR, "(%s) Message too short for a GSM48 header.\n",
		     bsc_subscr_name(conn->bsub));
		return;
	}

	gh = msgb_l3(msg);
	pdisc = gsm48_hdr_pdisc(gh);
	msg_type = gsm48_hdr_msg_type(gh);

	/* the idea is to handle all RR messages here, and only hand
	 * MM/CC/SMS-CP/LCS up to the MSC.  Some messages like PAGING
	 * RESPONSE or CM SERVICE REQUEST will not be covered here, as
	 * they are only possible in the first L3 message of each L2
	 * channel, i.e. 'conn' will not exist and gsm0408_rcvmsg()
	 * will call api->compl_l3() for it */
	switch (pdisc) {
	case GSM48_PDISC_RR:
		switch (msg_type) {
		case GSM48_MT_RR_GPRS_SUSP_REQ:
			LOGPLCHAN(msg->lchan, DRR, LOGL_DEBUG,
				  "%s\n", gsm48_rr_msg_name(GSM48_MT_RR_GPRS_SUSP_REQ));
			break;
		case GSM48_MT_RR_STATUS:
			LOGPLCHAN(msg->lchan, DRR, LOGL_NOTICE,
				  "%s (cause: %s)\n", gsm48_rr_msg_name(GSM48_MT_RR_STATUS),
				  rr_cause_name(gh->data[0]));
			break;
		case GSM48_MT_RR_MEAS_REP:
			/* This shouldn't actually end up here, as RSL treats
			* L3 Info of 08.58 MEASUREMENT REPORT different by calling
			* directly into gsm48_parse_meas_rep */
			LOGPLCHAN(msg->lchan, DMEAS, LOGL_ERROR,
				  "DIRECT GSM48 MEASUREMENT REPORT ?!?\n");
			gsm48_tx_rr_status(conn, GSM48_RR_CAUSE_MSG_TYPE_N_COMPAT);
			break;
		case GSM48_MT_RR_HANDO_COMPL:
			handle_rr_ho_compl(msg);
			break;
		case GSM48_MT_RR_HANDO_FAIL:
			handle_rr_ho_fail(msg);
			break;
		case GSM48_MT_RR_CIPH_M_COMPL:
			bsc_cipher_mode_compl(conn, msg, conn->lchan->encr.alg_id);
			break;
		case GSM48_MT_RR_ASS_COMPL:
			handle_ass_compl(conn, msg);
			break;
		case GSM48_MT_RR_ASS_FAIL:
			handle_ass_fail(conn, msg);
			break;
		case GSM48_MT_RR_CHAN_MODE_MODIF_ACK:
			rc = gsm48_rx_rr_modif_ack(msg);
			if (rc < 0)
				bsc_assign_fail(conn, GSM0808_CAUSE_NO_RADIO_RESOURCE_AVAILABLE, NULL);
			else
				bsc_assign_compl(conn, 0);
			break;
		case GSM48_MT_RR_CLSM_CHG:
			handle_classmark_chg(conn, msg);
			break;
		case GSM48_MT_RR_APP_INFO:
			/* Passing RR APP INFO to MSC, not quite
			 * according to spec */
			bsc_dtap(conn, link_id, msg);
			break;
		default:
			/* Drop unknown RR message */
			LOGPLCHAN(msg->lchan, DRR, LOGL_NOTICE,
				  "Dropping %s 04.08 RR message\n", gsm48_rr_msg_name(msg_type));
			gsm48_tx_rr_status(conn, GSM48_RR_CAUSE_MSG_TYPE_N);
			break;
		}
		break;
	default:
		bsc_dtap(conn, link_id, msg);
		break;
	}
}

/*! \brief RSL has received a DATA INDICATION with L3 from MS */
int gsm0408_rcvmsg(struct msgb *msg, uint8_t link_id)
{
	int rc;
	struct gsm_lchan *lchan;

	lchan = msg->lchan;
	if (lchan->state != LCHAN_S_ACTIVE) {
		LOGPLCHAN(msg->lchan, DRSL, LOGL_INFO, "Got data in non active state, discarding.\n");
		return -1;
	}


	if (lchan->conn) {
		/* if we already have a connection, forward via DTAP to
		 * MSC */
		dispatch_dtap(lchan->conn, link_id, msg);
	} else {
		/* allocate a new connection */
		rc = BSC_API_CONN_POL_REJECT;
		lchan->conn = bsc_subscr_con_allocate(msg->lchan->ts->trx->bts->network);
		if (!lchan->conn) {
			lchan_release(lchan, 1, RSL_REL_NORMAL);
			return -1;
		}
		lchan->conn->lchan = lchan;

		/* fwd via bsc_api to send COMPLETE L3 INFO to MSC */
		rc = bsc_compl_l3(lchan->conn, msg, 0);

		if (rc != BSC_API_CONN_POL_ACCEPT) {
			//osmo_fsm_inst_dispatch(lchan->conn->fi, FIXME, NULL);
		}
	}

	return 0;
}

/*! \brief We received a GSM 08.08 CIPHER MODE from the MSC */
int gsm0808_cipher_mode(struct gsm_subscriber_connection *conn, int cipher,
			const uint8_t *key, int len, int include_imeisv)
{
	if (cipher > 0 && key == NULL) {
		LOGP(DRSL, LOGL_ERROR, "%s: Need to have an encryption key.\n",
		     bsc_subscr_name(conn->bsub));
		return -1;
	}

	if (len > MAX_A5_KEY_LEN) {
		LOGP(DRSL, LOGL_ERROR, "%s: The key is too long: %d\n",
		     bsc_subscr_name(conn->bsub), len);
		return -1;
	}

	LOGP(DRSL, LOGL_DEBUG, "(subscr %s) Cipher Mode: cipher=%d key=%s include_imeisv=%d\n",
	     bsc_subscr_name(conn->bsub), cipher, osmo_hexdump_nospc(key, len), include_imeisv);

	conn->lchan->encr.alg_id = RSL_ENC_ALG_A5(cipher);
	if (key) {
		conn->lchan->encr.key_len = len;
		memcpy(conn->lchan->encr.key, key, len);
	}

	return gsm48_send_rr_ciph_mode(conn->lchan, include_imeisv);
}

/*
 * Release all occupied RF Channels but stay around for more.
 */
int gsm0808_clear(struct gsm_subscriber_connection *conn)
{
	if (conn->ho)
		bsc_clear_handover(conn, 1);

	if (conn->secondary_lchan)
		lchan_release(conn->secondary_lchan, 0, RSL_REL_LOCAL_END);

	if (conn->lchan)
		lchan_release(conn->lchan, 1, RSL_REL_NORMAL);

	conn->lchan = NULL;
	conn->secondary_lchan = NULL;

	return 0;
}

static void rll_ind_cb(struct gsm_lchan *lchan, uint8_t link_id, void *_data, enum bsc_rllr_ind rllr_ind)
{
	struct msgb *msg = _data;

	/*
	 * There seems to be a small window that the RLL timer can
	 * fire after a lchan_release call and before the S_CHALLOC_FREED
	 * is called. Check if a conn is set before proceeding.
	 */
	if (!lchan->conn)
		return;

	switch (rllr_ind) {
	case BSC_RLLR_IND_EST_CONF:
		rsl_data_request(msg, OBSC_LINKID_CB(msg));
		break;
	case BSC_RLLR_IND_REL_IND:
	case BSC_RLLR_IND_ERR_IND:
	case BSC_RLLR_IND_TIMEOUT:
		bsc_sapi_n_reject(lchan->conn, OBSC_LINKID_CB(msg));
		msgb_free(msg);
		break;
	}
}

static int bsc_handle_lchan_signal(unsigned int subsys, unsigned int signal,
				   void *handler_data, void *signal_data)
{
	struct gsm_lchan *lchan;
	struct lchan_signal_data *lchan_data;

	if (subsys != SS_LCHAN)
		return 0;


	lchan_data = signal_data;
	if (!lchan_data->lchan || !lchan_data->lchan->conn)
		return 0;

	lchan = lchan_data->lchan;

	switch (signal) {
	case S_LCHAN_UNEXPECTED_RELEASE:
		LOGPLCHAN(lchan, DMSC, LOGL_NOTICE, "S_LCHAN_UNEXPECTED_RELEASE\n");
		handle_release(lchan->conn, lchan);
		break;
	case S_LCHAN_ACTIVATE_ACK:
		handle_chan_ack(lchan->conn, lchan);
		break;
	case S_LCHAN_ACTIVATE_NACK:
		handle_chan_nack(lchan->conn, lchan);
		break;
	}

	return 0;
}

static void handle_release(struct gsm_subscriber_connection *conn, struct gsm_lchan *lchan)
{
	if (conn->secondary_lchan == lchan) {
		LOGPLCHAN(lchan, DMSC, LOGL_NOTICE,
			  "lchan release on new lchan, Assignment failed\n");
		conn->secondary_lchan = NULL;

		bsc_assign_fail(conn, GSM0808_CAUSE_RADIO_INTERFACE_FAILURE, NULL);
	}

	/* clear the connection now */
	bsc_clear_request(conn, 0);

	/* now give up all channels */
	if (conn->lchan == lchan)
		conn->lchan = NULL;
	if (conn->ho && conn->ho->new_lchan == lchan)
		bsc_clear_handover(conn, 0);
	lchan->conn = NULL;
}

static void handle_chan_ack(struct gsm_subscriber_connection *conn, struct gsm_lchan *lchan)
{
	if (conn->secondary_lchan != lchan)
		return;

	LOGPLCHAN(lchan, DMSC, LOGL_NOTICE, "Sending RR Assignment\n");
	gsm48_send_rr_ass_cmd(conn->lchan, lchan, lchan->ms_power);
}

static void handle_chan_nack(struct gsm_subscriber_connection *conn, struct gsm_lchan *lchan)
{
	if (conn->secondary_lchan != lchan)
		return;

	LOGPLCHAN(lchan, DMSC, LOGL_ERROR, "Channel activation failed.\n");
	conn->secondary_lchan->conn = NULL;
	conn->secondary_lchan = NULL;
	bsc_assign_fail(conn, GSM0808_CAUSE_RADIO_INTERFACE_FAILURE, NULL);
}

static __attribute__((constructor)) void on_dso_load_bsc(void)
{
	osmo_signal_register_handler(SS_LCHAN, bsc_handle_lchan_signal, NULL);
}
