/* osmo-bsc API to switch the RTP stream for an lchan.
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

#include <osmocom/core/fsm.h>
#include <osmocom/gsm/rtp_extensions.h>
#include <osmocom/netif/rtp.h>
#include <osmocom/mgcp_client/mgcp_client_endpoint_fsm.h>

#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/lchan_fsm.h>
#include <osmocom/bsc/lchan_rtp_fsm.h>
#include <osmocom/bsc/bsc_subscr_conn_fsm.h>
#include <osmocom/bsc/abis_rsl.h>
#include <osmocom/bsc/bsc_msc_data.h>
#include <osmocom/bsc/bts.h>
#include <osmocom/bsc/lchan.h>

static struct osmo_fsm lchan_rtp_fsm;

struct gsm_lchan *lchan_rtp_fi_lchan(struct osmo_fsm_inst *fi)
{
	OSMO_ASSERT(fi);
	OSMO_ASSERT(fi->fsm == &lchan_rtp_fsm);
	OSMO_ASSERT(fi->priv);
	return fi->priv;
}

struct osmo_tdef_state_timeout lchan_rtp_fsm_timeouts[32] = {
	[LCHAN_RTP_ST_WAIT_MGW_ENDPOINT_AVAILABLE] = { .T = -9 },
	[LCHAN_RTP_ST_WAIT_IPACC_CRCX_ACK]	= { .T = -7 },
	[LCHAN_RTP_ST_WAIT_IPACC_MDCX_ACK]	= { .T = -8 },
	[LCHAN_RTP_ST_WAIT_MGW_ENDPOINT_CONFIGURED] = { .T = -10 },
};

/* Transition to a state, using the T timer defined in lchan_rtp_fsm_timeouts.
 * The actual timeout value is in turn obtained from network->T_defs.
 * Assumes local variable fi exists. */
#define lchan_rtp_fsm_state_chg(state) \
	osmo_tdef_fsm_inst_state_chg(fi, state, \
				     lchan_rtp_fsm_timeouts, \
				     ((struct gsm_lchan*)(fi->priv))->ts->trx->bts->network->T_defs, \
				     5)

/* Set a failure message, trigger the common actions to take on failure, transition to a state to
 * continue with (using state timeouts from lchan_rtp_fsm_timeouts[]). Assumes local variable fi exists. */
#define lchan_rtp_fail(fmt, args...) do { \
		struct gsm_lchan *_lchan = fi->priv; \
		uint32_t state_was = fi->state; \
		LCHAN_SET_LAST_ERROR(_lchan, "lchan-rtp failure in state %s: " fmt, \
				     osmo_fsm_state_name(fi->fsm, state_was), ## args); \
		osmo_fsm_inst_dispatch(_lchan->fi, LCHAN_EV_RTP_ERROR, 0); \
	} while (0)

/* Called from lchan_fsm_init(), does not need to be visible in lchan_rtp_fsm.h */
static __attribute__((constructor)) void lchan_rtp_fsm_init(void)
{
	OSMO_ASSERT(osmo_fsm_register(&lchan_rtp_fsm) == 0);
}

static void lchan_rtp_fsm_update_id(struct gsm_lchan *lchan)
{
	OSMO_ASSERT(lchan->fi);
	OSMO_ASSERT(lchan->fi_rtp);
	osmo_fsm_inst_update_id_f(lchan->fi_rtp, lchan->fi->id);
}

bool lchan_rtp_established(struct gsm_lchan *lchan)
{
	if (!lchan->fi_rtp)
		return false;
	switch (lchan->fi_rtp->state) {
	case LCHAN_RTP_ST_READY:
	case LCHAN_RTP_ST_ESTABLISHED:
	case LCHAN_RTP_ST_ROLLBACK:
		return true;
	default:
		return false;
	}
}

void lchan_rtp_fsm_start(struct gsm_lchan *lchan)
{
	struct osmo_fsm_inst *fi;

	OSMO_ASSERT(lchan->ts);
	OSMO_ASSERT(lchan->ts->fi);
	OSMO_ASSERT(lchan->fi);
	OSMO_ASSERT(!lchan->fi_rtp);

	fi = osmo_fsm_inst_alloc_child(&lchan_rtp_fsm, lchan->fi, LCHAN_EV_RTP_RELEASED);
	OSMO_ASSERT(fi);
	fi->priv = lchan;
	lchan->fi_rtp = fi;
	lchan_rtp_fsm_update_id(lchan);

	/* Use old lchan only if there is an MGW endpoint present. Otherwise, on ROLLBACK, we might put
	 * an endpoint "back" to an lchan that never had one to begin with. */
	if (lchan->activate.info.re_use_mgw_endpoint_from_lchan
	    && !lchan->activate.info.re_use_mgw_endpoint_from_lchan->mgw_endpoint_ci_bts)
		lchan->activate.info.re_use_mgw_endpoint_from_lchan = NULL;

	lchan_rtp_fsm_state_chg(LCHAN_RTP_ST_WAIT_MGW_ENDPOINT_AVAILABLE);
}

/* While activating an lchan, for example for Handover, we may want to re-use another lchan's MGW
 * endpoint CI. If Handover fails half way, the old lchan must keep its MGW endpoint CI, and we must not
 * clean it up. Hence keep another lchan's mgw_endpoint_ci_bts out of lchan until all is done. */
struct osmo_mgcpc_ep_ci *lchan_use_mgw_endpoint_ci_bts(struct gsm_lchan *lchan)
{
	if (lchan->mgw_endpoint_ci_bts)
		return lchan->mgw_endpoint_ci_bts;
	if (lchan_state_is(lchan, LCHAN_ST_ESTABLISHED))
		return NULL;
	if (lchan->activate.info.re_use_mgw_endpoint_from_lchan)
		return lchan->activate.info.re_use_mgw_endpoint_from_lchan->mgw_endpoint_ci_bts;
	return NULL;
}

static void lchan_rtp_fsm_wait_mgw_endpoint_available_onenter(struct osmo_fsm_inst *fi,
							      uint32_t prev_state)
{
	struct gsm_lchan *lchan = lchan_rtp_fi_lchan(fi);
	struct gsm_bts *bts = lchan->ts->trx->bts;
	struct osmo_mgcpc_ep *mgwep;
	struct osmo_mgcpc_ep_ci *use_mgwep_ci = lchan_use_mgw_endpoint_ci_bts(lchan);
	struct mgcp_conn_peer crcx_info;

	if (!is_ipa_abisip_bts(lchan->ts->trx->bts)) {
		LOG_LCHAN_RTP(lchan, LOGL_DEBUG, "Audio link to-BTS via E1, skipping IPACC\n");
		lchan_rtp_fsm_state_chg(LCHAN_RTP_ST_WAIT_LCHAN_READY);
		return;
	}

	if (use_mgwep_ci) {
		LOG_LCHAN_RTP(lchan, LOGL_DEBUG, "MGW endpoint already available: %s\n",
			      osmo_mgcpc_ep_ci_name(use_mgwep_ci));
		lchan_rtp_fsm_state_chg(LCHAN_RTP_ST_WAIT_LCHAN_READY);
		return;
	}

	mgwep = gscon_ensure_mgw_endpoint(lchan->conn, lchan->activate.info.msc_assigned_cic, lchan);
	if (!mgwep) {
		lchan_rtp_fail("Internal error: cannot obtain MGW endpoint handle for conn");
		return;
	}

	lchan->mgw_endpoint_ci_bts = osmo_mgcpc_ep_ci_add(mgwep, "to-BTS");

	crcx_info = (struct mgcp_conn_peer){
		.ptime = 20,
		.x_osmo_osmux_cid = -1, /* -1 is wildcard, .x_osmo_osmux_use set below */
	};
	if (lchan->conn) {
		crcx_info.call_id = lchan->conn->sccp.conn.conn_id;
		if (lchan->conn->sccp.msc)
			crcx_info.x_osmo_ign = lchan->conn->sccp.msc->x_osmo_ign;
	}
	mgcp_pick_codec(&crcx_info, lchan, true);

	/* Set up Osmux use in MGW according to configured policy */
	bool amr_picked = mgcp_codec_is_picked(&crcx_info, CODEC_AMR_8000_1);
	switch (bts->use_osmux) {
	case OSMUX_USAGE_OFF:
		crcx_info.x_osmo_osmux_use = false;
		break;
	case OSMUX_USAGE_ON:
		crcx_info.x_osmo_osmux_use = amr_picked;
		break;
	case OSMUX_USAGE_ONLY:
		if (!amr_picked) {
			lchan_rtp_fail("Only AMR codec can be used when configured with policy 'osmux only'."
				       " Check your configuration.");
			return;
		}
		crcx_info.x_osmo_osmux_use = true;
		break;
	}

	osmo_mgcpc_ep_ci_request(lchan->mgw_endpoint_ci_bts, MGCP_VERB_CRCX, &crcx_info,
				fi, LCHAN_RTP_EV_MGW_ENDPOINT_AVAILABLE, LCHAN_RTP_EV_MGW_ENDPOINT_ERROR,
				0);
}

static void lchan_rtp_fsm_wait_mgw_endpoint_available(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_lchan *lchan = lchan_rtp_fi_lchan(fi);
	struct gsm_bts *bts = lchan->ts->trx->bts;
	switch (event) {

	case LCHAN_RTP_EV_MGW_ENDPOINT_AVAILABLE:
		LOG_LCHAN_RTP(lchan, LOGL_DEBUG, "MGW endpoint: %s\n",
			      osmo_mgcpc_ep_ci_name(lchan_use_mgw_endpoint_ci_bts(lchan)));
		if (osmo_mgcpc_ep_ci_get_crcx_info_to_osmux_cid(lchan->mgw_endpoint_ci_bts,
								&lchan->abis_ip.osmux.local_cid)) {
			if (bts->use_osmux == OSMUX_USAGE_OFF) {
				lchan_rtp_fail("Got Osmux CID from MGW but we didn't ask for it");
				return;
			}
			lchan->abis_ip.osmux.use = true;
		} else {
			if (bts->use_osmux == OSMUX_USAGE_ONLY) {
				lchan_rtp_fail("Got no Osmux CID from MGW but Osmux is mandatory");
				return;
			}
			lchan->abis_ip.osmux.use = false;
		}
		lchan_rtp_fsm_state_chg(LCHAN_RTP_ST_WAIT_LCHAN_READY);
		return;

	case LCHAN_RTP_EV_LCHAN_READY:
		/* will notice lchan->activate.activ_ack == true in
		 * lchan_rtp_fsm_wait_lchan_ready_onenter() */
		return;

	case LCHAN_RTP_EV_MGW_ENDPOINT_ERROR:
		lchan_rtp_fail("Failure to create MGW endpoint");
		return;

	case LCHAN_RTP_EV_ROLLBACK:
	case LCHAN_RTP_EV_RELEASE:
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REQUEST, 0);
		return;

	default:
		OSMO_ASSERT(false);
	}
}

static void lchan_rtp_fsm_post_lchan_ready(struct osmo_fsm_inst *fi);

static void lchan_rtp_fsm_wait_lchan_ready_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct gsm_lchan *lchan = lchan_rtp_fi_lchan(fi);

	if (lchan->activate.activ_ack) {
		LOG_LCHAN_RTP(lchan, LOGL_DEBUG, "Activ Ack received earlier, no need to wait\n");
		lchan_rtp_fsm_post_lchan_ready(fi);
	}
}

static void lchan_rtp_fsm_wait_lchan_ready(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {

	case LCHAN_RTP_EV_LCHAN_READY:
		lchan_rtp_fsm_post_lchan_ready(fi);
		return;

	case LCHAN_RTP_EV_ROLLBACK:
	case LCHAN_RTP_EV_RELEASE:
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REQUEST, 0);
		return;

	default:
		OSMO_ASSERT(false);
	}
}

static void lchan_rtp_fsm_switch_rtp(struct osmo_fsm_inst *fi)
{
	struct gsm_lchan *lchan = lchan_rtp_fi_lchan(fi);

	if (lchan->activate.info.wait_before_switching_rtp) {
		LOG_LCHAN_RTP(lchan, LOGL_DEBUG,
			      "Waiting for an event by caller before switching RTP\n");
		lchan_rtp_fsm_state_chg(LCHAN_RTP_ST_WAIT_READY_TO_SWITCH_RTP);
	} else
		lchan_rtp_fsm_state_chg(LCHAN_RTP_ST_WAIT_MGW_ENDPOINT_CONFIGURED);
}

static void lchan_rtp_fsm_post_lchan_ready(struct osmo_fsm_inst *fi)
{
	struct gsm_lchan *lchan = lchan_rtp_fi_lchan(fi);

	if (is_ipa_abisip_bts(lchan->ts->trx->bts))
		lchan_rtp_fsm_state_chg(LCHAN_RTP_ST_WAIT_IPACC_CRCX_ACK);
	else
		lchan_rtp_fsm_state_chg(LCHAN_RTP_ST_WAIT_MGW_ENDPOINT_CONFIGURED);
}

static void lchan_rtp_fsm_wait_ipacc_crcx_ack_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	int rc;
	int val;
	struct gsm_lchan *lchan = lchan_rtp_fi_lchan(fi);

	if (lchan->release.requested) {
		lchan_rtp_fail("Release requested while activating");
		return;
	}

	if (lchan->current_ch_indctr == GSM0808_CHAN_DATA) {
		enum rsl_ipac_rtp_csd_format_d format_d = RSL_IPAC_RTP_CSD_TRAU_BTS;

		if (lchan->activate.ch_mode_rate.data_transparent) {
			val = ipacc_rtp_csd_fmt_transp(&lchan->activate.ch_mode_rate, format_d);
			if (val < 0) {
				lchan_rtp_fail("Cannot determine Abis/IP RTP CSD format for rsl_cmod_csd_t=%d",
					       lchan->activate.ch_mode_rate.data_rate.t);
				return;
			}
		} else {
			val = ipacc_rtp_csd_fmt_non_transp(&lchan->activate.ch_mode_rate, format_d);
			if (val < 0) {
				lchan_rtp_fail("Cannot determine Abis/IP RTP CSD format for rsl_cmod_csd_nt=%d",
					       lchan->activate.ch_mode_rate.data_rate.nt);
				return;
			}
		}
		lchan->abis_ip.rtp_csd_fmt = val;
	} else {
		val = ipacc_speech_mode(lchan->activate.ch_mode_rate.chan_mode, lchan->type);
		if (val < 0) {
			lchan_rtp_fail("Cannot determine Abis/IP speech mode for tch_mode=%s type=%s",
				   get_value_string(gsm48_chan_mode_names, lchan->activate.ch_mode_rate.chan_mode),
				   gsm_chan_t_name(lchan->type));
			return;
		}
		lchan->abis_ip.speech_mode = val;
	}

	val = ipacc_payload_type(lchan->activate.ch_mode_rate.chan_mode, lchan->type);
	if (val < 0) {
		lchan_rtp_fail("Cannot determine Abis/IP payload type for tch_mode=%s type=%s",
			   get_value_string(gsm48_chan_mode_names, lchan->activate.ch_mode_rate.chan_mode),
			   gsm_chan_t_name(lchan->type));
		return;
	}
	lchan->abis_ip.rtp_payload = val;

	/* recv-only */
	ipacc_speech_mode_set_direction(&lchan->abis_ip.speech_mode, false);

	rc = rsl_tx_ipacc_crcx(lchan);
	if (rc)
		lchan_rtp_fail("Failure to transmit IPACC CRCX to BTS (rc=%d, %s)",
			   rc, strerror(-rc));
}

static void lchan_rtp_fsm_wait_ipacc_crcx_ack(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_lchan *lchan = lchan_rtp_fi_lchan(fi);
	switch (event) {

	case LCHAN_RTP_EV_IPACC_CRCX_ACK:
		lchan_rtp_fsm_switch_rtp(fi);
		return;

	case LCHAN_RTP_EV_IPACC_CRCX_NACK:
		lchan_rtp_fail("Received NACK on IPACC CRCX");
		return;

	case LCHAN_RTP_EV_READY_TO_SWITCH_RTP:
		lchan->activate.info.wait_before_switching_rtp = false;
		return;

	case LCHAN_RTP_EV_RELEASE:
	case LCHAN_RTP_EV_ROLLBACK:
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REQUEST, 0);
		return;

	default:
		OSMO_ASSERT(false);
	}
}

static void lchan_rtp_fsm_wait_ipacc_mdcx_ack_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	int rc;
	struct gsm_lchan *lchan = lchan_rtp_fi_lchan(fi);
	const struct mgcp_conn_peer *mgw_rtp;
	struct in_addr sin;

	if (lchan->release.requested) {
		lchan_rtp_fail("Release requested while activating");
		return;
	}

	mgw_rtp = osmo_mgcpc_ep_ci_get_rtp_info(lchan_use_mgw_endpoint_ci_bts(lchan));

	if (!mgw_rtp) {
		lchan_rtp_fail("Cannot send IPACC MDCX to BTS:"
			   " there is no RTP IP+port set that the BTS should send RTP to.");
		return;
	}

	/* Other RTP settings were already set up in lchan_rtp_fsm_wait_ipacc_crcx_ack_onenter() */
	if (inet_pton(AF_INET, mgw_rtp->addr, &sin) != 1) {
		/* Only IPv4 addresses are supported in IPACC */
		lchan_rtp_fail("Invalid remote IPv4 address %s", mgw_rtp->addr);
		return;
	}
	lchan->abis_ip.connect_ip = ntohl(sin.s_addr);
	lchan->abis_ip.connect_port = mgw_rtp->port;

	/* send-recv */
	ipacc_speech_mode_set_direction(&lchan->abis_ip.speech_mode, true);

	rc = rsl_tx_ipacc_mdcx(lchan);
	if (rc)
		lchan_rtp_fail("Failure to transmit IPACC MDCX to BTS (rc=%d, %s)",
			   rc, strerror(-rc));

}

static void lchan_rtp_fsm_wait_ipacc_mdcx_ack(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {

	case LCHAN_RTP_EV_IPACC_MDCX_ACK:
		lchan_rtp_fsm_state_chg(LCHAN_RTP_ST_READY);
		return;

	case LCHAN_RTP_EV_IPACC_MDCX_NACK:
		lchan_rtp_fail("Received NACK on IPACC MDCX");
		return;

	case LCHAN_RTP_EV_RELEASE:
	case LCHAN_RTP_EV_ROLLBACK:
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REQUEST, 0);
		return;

	default:
		OSMO_ASSERT(false);
	}
}

static void lchan_rtp_fsm_wait_ready_to_switch_rtp(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {

	case LCHAN_RTP_EV_READY_TO_SWITCH_RTP:
		lchan_rtp_fsm_state_chg(LCHAN_RTP_ST_WAIT_MGW_ENDPOINT_CONFIGURED);
		return;

	case LCHAN_RTP_EV_RELEASE:
	case LCHAN_RTP_EV_ROLLBACK:
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REQUEST, 0);
		return;

	default:
		OSMO_ASSERT(false);
	}
}

static void connect_mgw_endpoint_to_lchan(struct osmo_fsm_inst *fi,
					  struct osmo_mgcpc_ep_ci *ci,
					  struct gsm_lchan *to_lchan)
{
	int rc;
	struct gsm_lchan *lchan = lchan_rtp_fi_lchan(fi);
	struct mgcp_conn_peer mdcx_info;
	struct in_addr addr;
	const char *addr_str;

	if (lchan->abis_ip.osmux.use && !lchan->abis_ip.osmux.remote_cid_present) {
		lchan_rtp_fail("BTS didn't provide any remote Osmux CID for the call");
		return;
	}

	mdcx_info = (struct mgcp_conn_peer){
		.port = to_lchan->abis_ip.bound_port,
		.ptime = 20,
		.x_osmo_osmux_use = lchan->abis_ip.osmux.use,
		.x_osmo_osmux_cid = lchan->abis_ip.osmux.remote_cid,
	};
	mgcp_pick_codec(&mdcx_info, to_lchan, true);

	addr.s_addr = ntohl(to_lchan->abis_ip.bound_ip);
	addr_str = inet_ntoa(addr);
	rc = osmo_strlcpy(mdcx_info.addr, addr_str, sizeof(mdcx_info.addr));
	if (rc <= 0 || rc >= sizeof(mdcx_info.addr)) {
		lchan_rtp_fail("Cannot compose BTS side RTP IP address to send to MGW: '%s'",
			   addr_str);
		return;
	}

	if (!ci) {
		lchan_rtp_fail("No MGW endpoint ci configured");
		return;
	}

	LOG_LCHAN_RTP(lchan, LOGL_DEBUG, "Sending BTS side RTP port info %s:%u to MGW %s\n",
		      mdcx_info.addr, mdcx_info.port, osmo_mgcpc_ep_ci_name(ci));
	osmo_mgcpc_ep_ci_request(ci, MGCP_VERB_MDCX, &mdcx_info,
				fi, LCHAN_RTP_EV_MGW_ENDPOINT_CONFIGURED,
				LCHAN_RTP_EV_MGW_ENDPOINT_ERROR, 0);
}

static void lchan_rtp_fsm_wait_mgw_endpoint_configured_onenter(struct osmo_fsm_inst *fi,
							       uint32_t prev_state)
{
	struct gsm_lchan *lchan = lchan_rtp_fi_lchan(fi);
	struct gsm_lchan *old_lchan = lchan->activate.info.re_use_mgw_endpoint_from_lchan;

	if (lchan->release.requested) {
		lchan_rtp_fail("Release requested while activating");
		return;
	}

	if (!is_ipa_abisip_bts(lchan->ts->trx->bts)) {
		LOG_LCHAN_RTP(lchan, LOGL_DEBUG, "Audio link to-BTS via E1, skipping IPACC\n");
		lchan_rtp_fsm_state_chg(LCHAN_RTP_ST_READY);
		return;
	}

	/* At this point, we are taking over an old lchan's MGW endpoint (if any). */
	if (!lchan->mgw_endpoint_ci_bts && old_lchan) {
		/* The old lchan shall forget the endpoint now. We might put it back upon ROLLBACK */
		lchan->mgw_endpoint_ci_bts = old_lchan->mgw_endpoint_ci_bts;
		old_lchan->mgw_endpoint_ci_bts = NULL;
	}

	if (!lchan->mgw_endpoint_ci_bts) {
		lchan_rtp_fail("No MGW endpoint ci configured");
		return;
	}

	connect_mgw_endpoint_to_lchan(fi, lchan->mgw_endpoint_ci_bts, lchan);
}

static void lchan_rtp_fsm_wait_mgw_endpoint_configured(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_lchan *lchan = lchan_rtp_fi_lchan(fi);

	switch (event) {
	case LCHAN_RTP_EV_MGW_ENDPOINT_CONFIGURED:
		if (is_ipa_abisip_bts(lchan->ts->trx->bts))
			lchan_rtp_fsm_state_chg(LCHAN_RTP_ST_WAIT_IPACC_MDCX_ACK);
		else {
			lchan_rtp_fsm_state_chg(LCHAN_RTP_ST_READY);
		}
		return;

	case LCHAN_RTP_EV_MGW_ENDPOINT_ERROR:
		lchan_rtp_fail("Error while redirecting the MGW to the lchan's RTP port");
		return;

	case LCHAN_RTP_EV_ROLLBACK:
		lchan_rtp_fsm_state_chg(LCHAN_RTP_ST_ROLLBACK);
		return;

	case LCHAN_RTP_EV_RELEASE:
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, 0);
		return;

	default:
		OSMO_ASSERT(false);
	}
}

static void lchan_rtp_fsm_ready_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct gsm_lchan *lchan = lchan_rtp_fi_lchan(fi);
	osmo_fsm_inst_dispatch(lchan->fi, LCHAN_EV_RTP_READY, 0);
}

static void lchan_rtp_fsm_ready(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {

	case LCHAN_RTP_EV_ESTABLISHED:
		lchan_rtp_fsm_state_chg(LCHAN_RTP_ST_ESTABLISHED);
		return;

	case LCHAN_RTP_EV_RELEASE:
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REQUEST, 0);
		return;

	case LCHAN_RTP_EV_ROLLBACK:
		lchan_rtp_fsm_state_chg(LCHAN_RTP_ST_ROLLBACK);
		return;

	case LCHAN_RTP_EV_READY_TO_SWITCH_RTP:
		/* Ignore / silence an "event not permitted" error. In case of an inter-BSC incoming handover, there is
		 * no previous lchan to be switched over, and we are already in this state when the usual handover code
		 * path emits this event. */
		return;

	default:
		OSMO_ASSERT(false);
	}
}

static void lchan_rtp_fsm_rollback_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct gsm_lchan *lchan = lchan_rtp_fi_lchan(fi);
	struct gsm_lchan *old_lchan = lchan->activate.info.re_use_mgw_endpoint_from_lchan;

	if (!lchan->mgw_endpoint_ci_bts || !old_lchan) {
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REQUEST, 0);
		return;
	}

	if (is_ipa_abisip_bts(lchan->ts->trx->bts))
		connect_mgw_endpoint_to_lchan(fi, lchan->mgw_endpoint_ci_bts, old_lchan);
	else
		osmo_fsm_inst_dispatch(fi, LCHAN_RTP_EV_MGW_ENDPOINT_CONFIGURED, 0);
}

static void lchan_rtp_fsm_rollback(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_lchan *lchan = lchan_rtp_fi_lchan(fi);
	struct gsm_lchan *old_lchan = lchan->activate.info.re_use_mgw_endpoint_from_lchan;

	switch (event) {

	case LCHAN_RTP_EV_MGW_ENDPOINT_CONFIGURED:
		old_lchan->mgw_endpoint_ci_bts = lchan->mgw_endpoint_ci_bts;
		lchan->mgw_endpoint_ci_bts = NULL;
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, 0);
		return;

	case LCHAN_RTP_EV_MGW_ENDPOINT_ERROR:
		LOG_LCHAN_RTP(lchan, LOGL_ERROR,
			      "Error while connecting the MGW back to the old lchan's RTP port:"
			      " %s %s\n",
			      osmo_mgcpc_ep_ci_name(lchan->mgw_endpoint_ci_bts),
			      gsm_lchan_name(old_lchan));
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_ERROR, 0);
		return;

	case LCHAN_RTP_EV_RELEASE:
	case LCHAN_RTP_EV_ROLLBACK:
		/* Already rolling back, ignore. */
		return;

	default:
		OSMO_ASSERT(false);
	}
}

static void lchan_rtp_fsm_established_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct gsm_lchan *lchan = lchan_rtp_fi_lchan(fi);

	/* Make sure that we will not hand back the MGW endpoint to any old lchan from here on. */
	lchan->activate.info.re_use_mgw_endpoint_from_lchan = NULL;
}

static void lchan_rtp_fsm_established(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_lchan *lchan = lchan_rtp_fi_lchan(fi);

	switch (event) {

	case LCHAN_RTP_EV_RELEASE:
	case LCHAN_RTP_EV_ROLLBACK:
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, 0);
		return;
	case LCHAN_RTP_EV_IPACC_MDCX_ACK:
		LOG_LCHAN_RTP(lchan, LOGL_NOTICE,
			      "Received MDCX ACK on established lchan's RTP port: %s\n",
			      osmo_mgcpc_ep_ci_name(lchan->mgw_endpoint_ci_bts));
		return;
	default:
		OSMO_ASSERT(false);
	}
}

#define S(x)	(1 << (x))

static const struct osmo_fsm_state lchan_rtp_fsm_states[] = {
	[LCHAN_RTP_ST_WAIT_MGW_ENDPOINT_AVAILABLE] = {
		.name = "WAIT_MGW_ENDPOINT_AVAILABLE",
		.onenter = lchan_rtp_fsm_wait_mgw_endpoint_available_onenter,
		.action = lchan_rtp_fsm_wait_mgw_endpoint_available,
		.in_event_mask = 0
			| S(LCHAN_RTP_EV_MGW_ENDPOINT_AVAILABLE)
			| S(LCHAN_RTP_EV_MGW_ENDPOINT_ERROR)
			| S(LCHAN_RTP_EV_LCHAN_READY)
			| S(LCHAN_RTP_EV_RELEASE)
			| S(LCHAN_RTP_EV_ROLLBACK)
			,
		.out_state_mask = 0
			| S(LCHAN_RTP_ST_WAIT_MGW_ENDPOINT_AVAILABLE) /* for init */
			| S(LCHAN_RTP_ST_WAIT_LCHAN_READY)
			,
	},
	[LCHAN_RTP_ST_WAIT_LCHAN_READY] = {
		.name = "WAIT_LCHAN_READY",
		.onenter = lchan_rtp_fsm_wait_lchan_ready_onenter,
		.action = lchan_rtp_fsm_wait_lchan_ready,
		.in_event_mask = 0
			| S(LCHAN_RTP_EV_LCHAN_READY)
			| S(LCHAN_RTP_EV_RELEASE)
			| S(LCHAN_RTP_EV_ROLLBACK)
			,
		.out_state_mask = 0
			| S(LCHAN_RTP_ST_WAIT_IPACC_CRCX_ACK)
			| S(LCHAN_RTP_ST_WAIT_READY_TO_SWITCH_RTP)
			| S(LCHAN_RTP_ST_WAIT_MGW_ENDPOINT_CONFIGURED)
			,
	},
	[LCHAN_RTP_ST_WAIT_IPACC_CRCX_ACK] = {
		.name = "WAIT_IPACC_CRCX_ACK",
		.onenter = lchan_rtp_fsm_wait_ipacc_crcx_ack_onenter,
		.action = lchan_rtp_fsm_wait_ipacc_crcx_ack,
		.in_event_mask = 0
			| S(LCHAN_RTP_EV_READY_TO_SWITCH_RTP)
			| S(LCHAN_RTP_EV_IPACC_CRCX_ACK)
			| S(LCHAN_RTP_EV_IPACC_CRCX_NACK)
			| S(LCHAN_RTP_EV_RELEASE)
			| S(LCHAN_RTP_EV_ROLLBACK)
			,
		.out_state_mask = 0
			| S(LCHAN_RTP_ST_WAIT_READY_TO_SWITCH_RTP)
			| S(LCHAN_RTP_ST_WAIT_MGW_ENDPOINT_CONFIGURED) /*old: LCHAN_RTP_ST_WAIT_IPACC_MDCX_ACK*/
			,
	},
	[LCHAN_RTP_ST_WAIT_READY_TO_SWITCH_RTP] = {
		.name = "WAIT_READY_TO_SWITCH_RTP",
		.action = lchan_rtp_fsm_wait_ready_to_switch_rtp,
		.in_event_mask = 0
			| S(LCHAN_RTP_EV_READY_TO_SWITCH_RTP)
			| S(LCHAN_RTP_EV_RELEASE)
			| S(LCHAN_RTP_EV_ROLLBACK)
			,
		.out_state_mask = 0
			| S(LCHAN_RTP_ST_WAIT_MGW_ENDPOINT_CONFIGURED)
			,
	},
	[LCHAN_RTP_ST_WAIT_MGW_ENDPOINT_CONFIGURED] = {
		.name = "WAIT_MGW_ENDPOINT_CONFIGURED",
		.onenter = lchan_rtp_fsm_wait_mgw_endpoint_configured_onenter,
		.action = lchan_rtp_fsm_wait_mgw_endpoint_configured,
		.in_event_mask = 0
			| S(LCHAN_RTP_EV_MGW_ENDPOINT_CONFIGURED)
			| S(LCHAN_RTP_EV_MGW_ENDPOINT_ERROR)
			| S(LCHAN_RTP_EV_RELEASE)
			| S(LCHAN_RTP_EV_ROLLBACK)
			,
		.out_state_mask = 0
			| S(LCHAN_RTP_ST_WAIT_IPACC_MDCX_ACK)
			| S(LCHAN_RTP_ST_READY)
			| S(LCHAN_RTP_ST_ROLLBACK)
			,
	},
	[LCHAN_RTP_ST_WAIT_IPACC_MDCX_ACK] = {
		.name = "WAIT_IPACC_MDCX_ACK",
		.onenter = lchan_rtp_fsm_wait_ipacc_mdcx_ack_onenter,
		.action = lchan_rtp_fsm_wait_ipacc_mdcx_ack,
		.in_event_mask = 0
			| S(LCHAN_RTP_EV_IPACC_MDCX_ACK)
			| S(LCHAN_RTP_EV_IPACC_MDCX_NACK)
			| S(LCHAN_RTP_EV_RELEASE)
			| S(LCHAN_RTP_EV_ROLLBACK)
			,
		.out_state_mask = 0
			| S(LCHAN_RTP_ST_READY)
			| S(LCHAN_RTP_ST_ROLLBACK)
			,
	},
	[LCHAN_RTP_ST_READY] = {
		.name = "READY",
		.onenter = lchan_rtp_fsm_ready_onenter,
		.action = lchan_rtp_fsm_ready,
		.in_event_mask = 0
			| S(LCHAN_RTP_EV_ESTABLISHED)
			| S(LCHAN_RTP_EV_RELEASE)
			| S(LCHAN_RTP_EV_ROLLBACK)
			| S(LCHAN_RTP_EV_READY_TO_SWITCH_RTP)
			,
		.out_state_mask = 0
			| S(LCHAN_RTP_ST_ESTABLISHED)
			| S(LCHAN_RTP_ST_ROLLBACK)
			,
	},
	[LCHAN_RTP_ST_ESTABLISHED] = {
		.name = "ESTABLISHED",
		.onenter = lchan_rtp_fsm_established_onenter,
		.action = lchan_rtp_fsm_established,
		.in_event_mask = 0
			| S(LCHAN_RTP_EV_RELEASE)
			| S(LCHAN_RTP_EV_ROLLBACK)
			| S(LCHAN_RTP_EV_IPACC_MDCX_ACK)
			,
	},
	[LCHAN_RTP_ST_ROLLBACK] = {
		.name = "ROLLBACK",
		.onenter = lchan_rtp_fsm_rollback_onenter,
		.action = lchan_rtp_fsm_rollback,
		.in_event_mask = 0
			| S(LCHAN_RTP_EV_MGW_ENDPOINT_CONFIGURED)
			| S(LCHAN_RTP_EV_MGW_ENDPOINT_ERROR)
			| S(LCHAN_RTP_EV_RELEASE)
			| S(LCHAN_RTP_EV_ROLLBACK)
			,
	},
};

static const struct value_string lchan_rtp_fsm_event_names[] = {
	OSMO_VALUE_STRING(LCHAN_RTP_EV_LCHAN_READY),
	OSMO_VALUE_STRING(LCHAN_RTP_EV_READY_TO_SWITCH_RTP),
	OSMO_VALUE_STRING(LCHAN_RTP_EV_MGW_ENDPOINT_AVAILABLE),
	OSMO_VALUE_STRING(LCHAN_RTP_EV_MGW_ENDPOINT_ERROR),
	OSMO_VALUE_STRING(LCHAN_RTP_EV_IPACC_CRCX_ACK),
	OSMO_VALUE_STRING(LCHAN_RTP_EV_IPACC_CRCX_NACK),
	OSMO_VALUE_STRING(LCHAN_RTP_EV_IPACC_MDCX_ACK),
	OSMO_VALUE_STRING(LCHAN_RTP_EV_IPACC_MDCX_NACK),
	OSMO_VALUE_STRING(LCHAN_RTP_EV_READY_TO_SWITCH),
	OSMO_VALUE_STRING(LCHAN_RTP_EV_MGW_ENDPOINT_CONFIGURED),
	OSMO_VALUE_STRING(LCHAN_RTP_EV_ROLLBACK),
	OSMO_VALUE_STRING(LCHAN_RTP_EV_ESTABLISHED),
	OSMO_VALUE_STRING(LCHAN_RTP_EV_RELEASE),
	{}
};

static int lchan_rtp_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	struct gsm_lchan *lchan = lchan_rtp_fi_lchan(fi);
	lchan->release.in_error = true;
	lchan->release.rsl_error_cause = RSL_ERR_EQUIPMENT_FAIL;
	lchan_rtp_fail("Timeout");
	return 0;
}

static void lchan_rtp_fsm_cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct gsm_lchan *lchan = lchan_rtp_fi_lchan(fi);
	if (lchan->mgw_endpoint_ci_bts) {
		osmo_mgcpc_ep_ci_dlcx(lchan->mgw_endpoint_ci_bts);
		lchan->mgw_endpoint_ci_bts = NULL;
	}
	lchan->fi_rtp = NULL;

	/* In all other cause, FSM already takes care of sending the event we
	 * configured at osmo_fsm_inst_alloc_child() time immediately after
	 * returning here. */
	if (lchan->fi && cause == OSMO_FSM_TERM_PARENT)
		osmo_fsm_inst_dispatch(lchan->fi, LCHAN_EV_RTP_RELEASED, 0);
}

/* The mgw_endpoint was invalidated, just and simply forget the pointer without cleanup. */
void lchan_forget_mgw_endpoint(struct gsm_lchan *lchan)
{
	if (!lchan)
		return;
	lchan->mgw_endpoint_ci_bts = NULL;
}

static struct osmo_fsm lchan_rtp_fsm = {
	.name = "lchan_rtp",
	.states = lchan_rtp_fsm_states,
	.num_states = ARRAY_SIZE(lchan_rtp_fsm_states),
	.log_subsys = DCHAN,
	.event_names = lchan_rtp_fsm_event_names,
	.timer_cb = lchan_rtp_fsm_timer_cb,
	.cleanup = lchan_rtp_fsm_cleanup,
};

/* Depending on the channel mode and rate, return the codec type that is signalled towards the MGW. */
static enum mgcp_codecs chan_mode_to_mgcp_codec(enum gsm48_chan_mode chan_mode, bool full_rate)
{
	switch (gsm48_chan_mode_to_non_vamos(chan_mode)) {
	case GSM48_CMODE_DATA_14k5:
	case GSM48_CMODE_DATA_12k0:
	case GSM48_CMODE_DATA_6k0:
	case GSM48_CMODE_DATA_3k6:
		return CODEC_CLEARMODE;

	case GSM48_CMODE_SPEECH_V1:
		if (full_rate)
			return CODEC_GSM_8000_1;
		return CODEC_GSMHR_8000_1;

	case GSM48_CMODE_SPEECH_EFR:
		return CODEC_GSMEFR_8000_1;

	case GSM48_CMODE_SPEECH_AMR:
		return CODEC_AMR_8000_1;

	default:
		return -1;
	}
}

static int chan_mode_to_mgcp_bss_pt(enum mgcp_codecs codec)
{
	switch (codec) {
	case CODEC_GSMHR_8000_1:
		return RTP_PT_GSM_HALF;

	case CODEC_GSMEFR_8000_1:
		return RTP_PT_GSM_EFR;

	case CODEC_AMR_8000_1:
		return RTP_PT_AMR;

	default:
		/* Not an error, we just leave it to libosmo-mgcp-client to
		 * decide over the PT. */
		return -1;
	}
}

void mgcp_pick_codec(struct mgcp_conn_peer *verb_info, const struct gsm_lchan *lchan, bool bss_side)
{
	enum mgcp_codecs codec = chan_mode_to_mgcp_codec(lchan->activate.ch_mode_rate.chan_mode,
							 lchan->type == GSM_LCHAN_TCH_H? false : true);
	int custom_pt;

	if (codec < 0) {
		LOG_LCHAN(lchan, LOGL_ERROR,
			  "Unable to determine MGCP codec type for %s in chan-mode %s\n",
			  gsm_chan_t_name(lchan->type), gsm48_chan_mode_name(lchan->activate.ch_mode_rate.chan_mode));
		verb_info->codecs_len = 0;
		return;
	}

	verb_info->codecs[0] = codec;
	verb_info->codecs_len = 1;

	/* Setup custom payload types (only for BSS side and when required) */
	custom_pt = chan_mode_to_mgcp_bss_pt(codec);
	if (bss_side && custom_pt > 0) {
		verb_info->ptmap[0].codec = codec;
		verb_info->ptmap[0].pt = custom_pt;
		verb_info->ptmap_len = 1;
	}

	/* AMR requires additional parameters to be set up (framing mode) */
	if (verb_info->codecs[0] == CODEC_AMR_8000_1) {
		verb_info->param_present = true;
		verb_info->param.amr_octet_aligned_present = true;
	}

	if (bss_side && verb_info->codecs[0] == CODEC_AMR_8000_1) {
		/* FIXME: At the moment all BTSs we support are using the
		 * octet-aligned payload format. However, in the future
		 * we may support BTSs that are using bandwidth-efficient
		 * format. In this case we will have to add functionality
		 * that distinguishes by the BTS model which mode to use. */
		verb_info->param.amr_octet_aligned = true;
	}
	else if (!bss_side && verb_info->codecs[0] == CODEC_AMR_8000_1) {
		verb_info->param.amr_octet_aligned = lchan->conn->sccp.msc->amr_octet_aligned;
	}

	/* If the CN has requested RTP payload format extensions (change from
	 * RFC 3551 to TW-TS-001 for FR/EFR, or from RFC 5993 to TW-TS-002
	 * for HRv1) via BSSMAP IE of TW-TS-003, we need to pass this request
	 * to the MGW.  With E1 BTS our MGW is the origin of the RTP stream
	 * and thus the party responsible for payload format choices; with
	 * IP BTS our MGW is merely a forwarder and thus can get by without
	 * this detailed knowledge, but it doesn't hurt to inform the MGW
	 * in all cases.
	 *
	 * Note that the following code does not perform conditional checks
	 * of whether the selected codec is FR/EFR for TW-TS-001 or HRv1
	 * for TW-TS-002, but instead checks only the extension mode bits.
	 * This simplification is allowed by libosmo-mgcp-client API:
	 * struct mgcp_codec_param has dedicated fields for fr_efr_twts001
	 * and hr_twts002 parameters, and the code in libosmo-mgcp-client
	 * then emits the corresponding a=fmtp lines only when the SDP
	 * includes those codecs to which these attributes apply.
	 */
	if (lchan->conn->user_plane.rtp_extensions & OSMO_RTP_EXT_TWTS001) {
		verb_info->param_present = true;
		verb_info->param.fr_efr_twts001_present = true;
		verb_info->param.fr_efr_twts001 = true;
	}
	if (lchan->conn->user_plane.rtp_extensions & OSMO_RTP_EXT_TWTS002) {
		verb_info->param_present = true;
		verb_info->param.hr_twts002_present = true;
		verb_info->param.hr_twts002 = true;
	}
}

bool mgcp_codec_is_picked(const struct mgcp_conn_peer *verb_info, enum mgcp_codecs codec)
{
	return verb_info->codecs[0] == codec;
}
