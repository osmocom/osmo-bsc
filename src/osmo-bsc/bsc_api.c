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
#include <osmocom/bsc/gsm_04_08_rr.h>
#include <osmocom/bsc/bsc_subscriber.h>
#include <osmocom/bsc/penalty_timers.h>
#include <osmocom/bsc/osmo_bsc_sigtran.h>
#include <osmocom/bsc/bsc_subscr_conn_fsm.h>

#include <osmocom/gsm/protocol/gsm_08_08.h>
#include <osmocom/gsm/gsm48.h>

#include <osmocom/core/talloc.h>

#define GSM0808_T10_VALUE    6, 0

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
