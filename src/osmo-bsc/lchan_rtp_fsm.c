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

#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/lchan_fsm.h>
#include <osmocom/bsc/lchan_rtp_fsm.h>
#include <osmocom/bsc/mgw_endpoint_fsm.h>
#include <osmocom/bsc/bsc_subscr_conn_fsm.h>
#include <osmocom/bsc/abis_rsl.h>
#include <osmocom/bsc/bsc_msc_data.h>

static struct osmo_fsm lchan_rtp_fsm;

struct gsm_lchan *lchan_rtp_fi_lchan(struct osmo_fsm_inst *fi)
{
	OSMO_ASSERT(fi);
	OSMO_ASSERT(fi->fsm == &lchan_rtp_fsm);
	OSMO_ASSERT(fi->priv);
	return fi->priv;
}

struct osmo_tdef_state_timeout lchan_rtp_fsm_timeouts[32] = {
	[LCHAN_RTP_ST_WAIT_MGW_ENDPOINT_AVAILABLE] = { .T=23004 },
	[LCHAN_RTP_ST_WAIT_IPACC_CRCX_ACK]	= { .T=23005 },
	[LCHAN_RTP_ST_WAIT_IPACC_MDCX_ACK]	= { .T=23006 },
	[LCHAN_RTP_ST_WAIT_MGW_ENDPOINT_CONFIGURED] = { .T=23004 },
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
		lchan_set_last_error(_lchan, "lchan-rtp failure in state %s: " fmt, \
				     osmo_fsm_state_name(fi->fsm, state_was), ## args); \
		osmo_fsm_inst_dispatch(_lchan->fi, LCHAN_EV_RTP_ERROR, 0); \
	} while(0)

/* Called from lchan_fsm_init(), does not need to be visible in lchan_rtp_fsm.h */
void lchan_rtp_fsm_init()
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
struct mgwep_ci *lchan_use_mgw_endpoint_ci_bts(struct gsm_lchan *lchan)
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
	struct mgw_endpoint *mgwep;
	struct mgwep_ci *use_mgwep_ci = lchan_use_mgw_endpoint_ci_bts(lchan);
	struct mgcp_conn_peer crcx_info = {};

	if (use_mgwep_ci) {
		LOG_LCHAN_RTP(lchan, LOGL_DEBUG, "MGW endpoint already available: %s\n",
			      mgwep_ci_name(use_mgwep_ci));
		lchan_rtp_fsm_state_chg(LCHAN_RTP_ST_WAIT_LCHAN_READY);
		return;
	}

	mgwep = gscon_ensure_mgw_endpoint(lchan->conn, lchan->activate.info.msc_assigned_cic);
	if (!mgwep) {
		lchan_rtp_fail("Internal error: cannot obtain MGW endpoint handle for conn");
		return;
	}

	lchan->mgw_endpoint_ci_bts = mgw_endpoint_ci_add(mgwep, "to-BTS");

	if (lchan->conn) {
		crcx_info.call_id = lchan->conn->sccp.conn_id;
		if (lchan->conn->sccp.msc)
			crcx_info.x_osmo_ign = lchan->conn->sccp.msc->x_osmo_ign;
	}
	crcx_info.ptime = 20;
	mgcp_pick_codec(&crcx_info, lchan, true);

	mgw_endpoint_ci_request(lchan->mgw_endpoint_ci_bts, MGCP_VERB_CRCX, &crcx_info,
				fi, LCHAN_RTP_EV_MGW_ENDPOINT_AVAILABLE, LCHAN_RTP_EV_MGW_ENDPOINT_ERROR,
				0);
}

static void lchan_rtp_fsm_wait_mgw_endpoint_available(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_lchan *lchan = lchan_rtp_fi_lchan(fi);
	switch (event) {

	case LCHAN_RTP_EV_MGW_ENDPOINT_AVAILABLE:
		LOG_LCHAN_RTP(lchan, LOGL_DEBUG, "MGW endpoint: %s\n",
			      mgwep_ci_name(lchan_use_mgw_endpoint_ci_bts(lchan)));
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

	if (is_ipaccess_bts(lchan->ts->trx->bts))
		lchan_rtp_fsm_state_chg(LCHAN_RTP_ST_WAIT_IPACC_CRCX_ACK);
	else
		lchan_rtp_fsm_switch_rtp(fi);
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

	val = ipacc_speech_mode(lchan->tch_mode, lchan->type);
	if (val < 0) {
		lchan_rtp_fail("Cannot determine Abis/IP speech mode for tch_mode=%s type=%s\n",
			   get_value_string(gsm48_chan_mode_names, lchan->tch_mode),
			   gsm_lchant_name(lchan->type));
		return;
	}
	lchan->abis_ip.speech_mode = val;

	val = ipacc_payload_type(lchan->tch_mode, lchan->type);
	if (val < 0) {
		lchan_rtp_fail("Cannot determine Abis/IP payload type for tch_mode=%s type=%s\n",
			   get_value_string(gsm48_chan_mode_names, lchan->tch_mode),
			   gsm_lchant_name(lchan->type));
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
		/* the CRCX ACK parsing has already noted the RTP port information at
		 * lchan->abis_ip.bound_*, see ipac_parse_rtp(). We'll use that in
		 * lchan_rtp_fsm_wait_mgw_endpoint_configured_onenter(). */
		lchan_rtp_fsm_state_chg(LCHAN_RTP_ST_WAIT_IPACC_MDCX_ACK);
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

	if (lchan->release.requested) {
		lchan_rtp_fail("Release requested while activating");
		return;
	}

	mgw_rtp = mgwep_ci_get_rtp_info(lchan_use_mgw_endpoint_ci_bts(lchan));

	if (!mgw_rtp) {
		lchan_rtp_fail("Cannot send IPACC MDCX to BTS:"
			   " there is no RTP IP+port set that the BTS should send RTP to.");
		return;
	}

	/* Other RTP settings were already setup in lchan_rtp_fsm_wait_ipacc_crcx_ack_onenter() */
	lchan->abis_ip.connect_ip = ntohl(inet_addr(mgw_rtp->addr));
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
	struct gsm_lchan *lchan = lchan_rtp_fi_lchan(fi);
	switch (event) {

	case LCHAN_RTP_EV_IPACC_MDCX_ACK:
		lchan_rtp_fsm_switch_rtp(fi);
		return;

	case LCHAN_RTP_EV_IPACC_MDCX_NACK:
		lchan_rtp_fail("Received NACK on IPACC MDCX");
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
					  struct mgwep_ci *ci,
					  struct gsm_lchan *to_lchan)
{
	int rc;
	struct gsm_lchan *lchan = lchan_rtp_fi_lchan(fi);
	struct mgcp_conn_peer mdcx_info;
	struct in_addr addr;
	const char *addr_str;

	mdcx_info = (struct mgcp_conn_peer){
		.port = to_lchan->abis_ip.bound_port,
		.ptime = 20,
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
		      mdcx_info.addr, mdcx_info.port, mgwep_ci_name(ci));
	mgw_endpoint_ci_request(ci, MGCP_VERB_MDCX, &mdcx_info,
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

	/* At this point, we are taking over an old lchan's MGW endpoint (if any). */
	if (!lchan->mgw_endpoint_ci_bts && old_lchan) {
		/* The old lchan shall forget the enpoint now. We might put it back upon ROLLBACK */
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
	switch (event) {

	case LCHAN_RTP_EV_MGW_ENDPOINT_CONFIGURED:
		lchan_rtp_fsm_state_chg(LCHAN_RTP_ST_READY);
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
	connect_mgw_endpoint_to_lchan(fi, lchan->mgw_endpoint_ci_bts, old_lchan);
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
			      mgwep_ci_name(lchan->mgw_endpoint_ci_bts),
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
			      mgwep_ci_name(lchan->mgw_endpoint_ci_bts));
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
			| S(LCHAN_RTP_ST_WAIT_IPACC_MDCX_ACK)
			,
	},
	[LCHAN_RTP_ST_WAIT_IPACC_MDCX_ACK] = {
		.name = "WAIT_IPACC_MDCX_ACK",
		.onenter = lchan_rtp_fsm_wait_ipacc_mdcx_ack_onenter,
		.action = lchan_rtp_fsm_wait_ipacc_mdcx_ack,
		.in_event_mask = 0
			| S(LCHAN_RTP_EV_READY_TO_SWITCH_RTP)
			| S(LCHAN_RTP_EV_IPACC_MDCX_ACK)
			| S(LCHAN_RTP_EV_IPACC_MDCX_NACK)
			| S(LCHAN_RTP_EV_RELEASE)
			| S(LCHAN_RTP_EV_ROLLBACK)
			,
		.out_state_mask = 0
			| S(LCHAN_RTP_ST_WAIT_READY_TO_SWITCH_RTP)
			| S(LCHAN_RTP_ST_WAIT_MGW_ENDPOINT_CONFIGURED)
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
			| S(LCHAN_RTP_ST_READY)
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

int lchan_rtp_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	struct gsm_lchan *lchan = lchan_rtp_fi_lchan(fi);
	lchan->release.in_error = true;
	lchan->release.rsl_error_cause = RSL_ERR_EQUIPMENT_FAIL;
	lchan_rtp_fail("Timeout");
	return 0;
}

void lchan_rtp_fsm_cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct gsm_lchan *lchan = lchan_rtp_fi_lchan(fi);
	if (lchan->mgw_endpoint_ci_bts) {
		mgw_endpoint_ci_dlcx(lchan->mgw_endpoint_ci_bts);
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
