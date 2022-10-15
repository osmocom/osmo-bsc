/* (C) 2018 by Harald Welte <laforge@gnumonks.org>
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

#include <osmocom/core/utils.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/fsm.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/gsm/gsm0808.h>
#include <osmocom/core/msgb.h>
#include <osmocom/bsc/abis_rsl.h>
#include <osmocom/bsc/bsc_msc_data.h>
#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/osmo_bsc.h>
#include <osmocom/bsc/bsc_subscr_conn_fsm.h>
#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/osmo_bsc_lcls.h>
#include <osmocom/bsc/lchan_rtp_fsm.h>
#include <osmocom/bsc/lchan.h>
#include <osmocom/mgcp_client/mgcp_client_endpoint_fsm.h>

struct value_string lcls_event_names[] = {
	{ LCLS_EV_UPDATE_CFG_CSC,	"UPDATE_CFG_CSC" },
	{ LCLS_EV_APPLY_CFG_CSC,	"APPLY_CFG_CSC" },
	{ LCLS_EV_CORRELATED,		"CORRELATED" },
	{ LCLS_EV_OTHER_ENABLED,	"OTHER_ENABLED" },
	{ LCLS_EV_OTHER_BREAK,		"OTHER_BREAK" },
	{ LCLS_EV_OTHER_DEAD,		"OTHER_DEAD" },
	{ 0, NULL }
};

const struct value_string bsc_lcls_mode_names[] = {
	{ BSC_LCLS_MODE_DISABLED,	"disabled" },
	{ BSC_LCLS_MODE_MGW_LOOP,	"mgw-loop" },
	{ BSC_LCLS_MODE_BTS_LOOP,	"bts-loop" },
	{ 0, NULL }
};

/***********************************************************************
 * Utility functions
 ***********************************************************************/

enum gsm0808_lcls_status lcls_get_status(const struct gsm_subscriber_connection *conn)
{
	if (!conn->lcls.fi)
		return GSM0808_LCLS_STS_NA;

	switch (conn->lcls.fi->state) {
	case ST_NO_LCLS:
		return GSM0808_LCLS_STS_NA;
	case ST_NOT_YET_LS:
		return GSM0808_LCLS_STS_NOT_YET_LS;
	case ST_NOT_POSSIBLE_LS:
		return GSM0808_LCLS_STS_NOT_POSSIBLE_LS;
	case ST_NO_LONGER_LS:
		return GSM0808_LCLS_STS_NO_LONGER_LS;
	case ST_REQ_LCLS_NOT_SUPP:
		return GSM0808_LCLS_STS_REQ_LCLS_NOT_SUPP;
	case ST_LOCALLY_SWITCHED:
	case ST_LOCALLY_SWITCHED_WAIT_BREAK:
	case ST_LOCALLY_SWITCHED_WAIT_OTHER_BREAK:
		return GSM0808_LCLS_STS_LOCALLY_SWITCHED;
	}
	OSMO_ASSERT(0);
}

static void lcls_send_notify(struct gsm_subscriber_connection *conn)
{
	enum gsm0808_lcls_status status = lcls_get_status(conn);
	struct msgb *msg;

	if (status == GSM0808_LCLS_STS_NA)
		return;

	LOGPFSM(conn->lcls.fi, "Sending BSSMAP LCLS NOTIFICATION (%s)\n",
		gsm0808_lcls_status_name(status));
	msg = gsm0808_create_lcls_notification(status, false);
	osmo_fsm_inst_dispatch(conn->fi, GSCON_EV_TX_SCCP, msg);
}

static struct gsm_subscriber_connection *
find_conn_with_same_gcr(const struct gsm_subscriber_connection *conn_local)
{
	struct gsm_network *net = conn_local->network;
	struct gsm_subscriber_connection *conn_other;

	llist_for_each_entry(conn_other, &net->subscr_conns, entry) {
		/* don't report back the same connection */
		if (conn_other == conn_local)
			continue;
		/* don't consider any conn where GCR length is not the same as before */
		if (conn_other->lcls.global_call_ref_len != conn_local->lcls.global_call_ref_len)
			continue;
		if (!memcmp(conn_other->lcls.global_call_ref, conn_local->lcls.global_call_ref,
			    conn_local->lcls.global_call_ref_len))
			return conn_other;
	}
	return NULL;
}

static bool lcls_is_supported_config(enum gsm0808_lcls_config cfg)
{
	/* this is the only configuration that we support for now */
	if (cfg == GSM0808_LCLS_CFG_BOTH_WAY)
		return true;
	else
		return false;
}

/* LCLS Call Leg Correlation as per 23.284 4.3 / 48.008 3.1.33.2.1 */
static int lcls_perform_correlation(struct gsm_subscriber_connection *conn_local)
{
	struct gsm_subscriber_connection *conn_other;

	/* We can only correlate if a GCR is present */
	OSMO_ASSERT(conn_local->lcls.global_call_ref_len);
	/* We can only correlate if we're not in active LS */
	OSMO_ASSERT(conn_local->lcls.fi->state != ST_LOCALLY_SWITCHED &&
		    conn_local->lcls.fi->state != ST_LOCALLY_SWITCHED_WAIT_BREAK &&
		    conn_local->lcls.fi->state != ST_LOCALLY_SWITCHED_WAIT_OTHER_BREAK);

	conn_other = conn_local->lcls.other;
	if (conn_other) {
		LOGPFSM(conn_local->lcls.fi, "Breaking previous correlation with %s\n",
			osmo_fsm_inst_name(conn_other->lcls.fi));
		OSMO_ASSERT(conn_other->lcls.fi->state != ST_LOCALLY_SWITCHED &&
			    conn_other->lcls.fi->state != ST_LOCALLY_SWITCHED_WAIT_BREAK &&
			    conn_other->lcls.fi->state != ST_LOCALLY_SWITCHED_WAIT_OTHER_BREAK);
		conn_local->lcls.other->lcls.other = NULL;
		conn_local->lcls.other = NULL;
	}

	conn_other = find_conn_with_same_gcr(conn_local);
	if (!conn_other) {
		/* we found no other call with same GCR: not possible */
		LOGPFSM(conn_local->lcls.fi, "Unsuccessful correlation\n");
		return -ENODEV;
	}

	/* store pointer to "other" in "local" */
	conn_local->lcls.other = conn_other;

	LOGPFSM(conn_local->lcls.fi, "Successfully correlated with %s\n",
		osmo_fsm_inst_name(conn_other->lcls.fi));

	/* notify other conn about our correlation */
	osmo_fsm_inst_dispatch(conn_other->lcls.fi, LCLS_EV_CORRELATED, conn_local);

	return 0;
}

/* Update the connections LCLS configuration and return old/previous configuration.
 * \returns (staticallly allocated) old configuration; NULL if new config not supported */
static struct osmo_lcls *update_lcls_cfg_csc(struct gsm_subscriber_connection *conn,
					     const struct osmo_lcls *new_cfg_csc)
{
	static struct osmo_lcls old_cfg_csc = { 0 };
	old_cfg_csc.config = conn->lcls.config;
	old_cfg_csc.control = conn->lcls.control;

	if (new_cfg_csc->config != GSM0808_LCLS_CFG_NA) {
		if (!lcls_is_supported_config(new_cfg_csc->config))
			return NULL;
		if (conn->lcls.config != new_cfg_csc->config) {
			LOGPFSM(conn->lcls.fi, "LCLS update Config %s -> %s\n",
				gsm0808_lcls_config_name(conn->lcls.config),
				gsm0808_lcls_config_name(new_cfg_csc->config));
			conn->lcls.config = new_cfg_csc->config;
		}
	}
	if (new_cfg_csc->control != GSM0808_LCLS_CSC_NA) {
		if (conn->lcls.control != new_cfg_csc->control) {
			LOGPFSM(conn->lcls.fi, "LCLS update Control %s -> %s\n",
				gsm0808_lcls_control_name(conn->lcls.control),
				gsm0808_lcls_control_name(new_cfg_csc->control));
			conn->lcls.control = new_cfg_csc->control;
		}
	}

	return &old_cfg_csc;
}

/* Attempt to update conn->lcls with the new config/csc provided. If new config is
 * unsupported, change into LCLS NOT SUPPORTED state and return -EINVAL. */
static int lcls_handle_cfg_update(struct gsm_subscriber_connection *conn, void *data)
{
	struct osmo_lcls *new_cfg_csc, *old_cfg_csc;

	new_cfg_csc = (struct osmo_lcls *) data;
	old_cfg_csc = update_lcls_cfg_csc(conn, new_cfg_csc);
	if (!old_cfg_csc) {
		osmo_fsm_inst_state_chg(conn->lcls.fi, ST_REQ_LCLS_NOT_SUPP, 0, 0);
		return -EINVAL;
	}
	return 0;
}

/* notify the LCLS FSM about new LCLS Config and/or CSC */
void lcls_update_config(struct gsm_subscriber_connection *conn,
			const uint8_t *config, const uint8_t *control)
{
	struct osmo_lcls new_cfg = {
		.config = GSM0808_LCLS_CFG_NA,
		.control = GSM0808_LCLS_CSC_NA,
	};
	/* nothing to update, skip it */
	if (!config && !control)
		return;
	if (config)
		new_cfg.config = *config;
	if (control)
		new_cfg.control = *control;
	osmo_fsm_inst_dispatch(conn->lcls.fi, LCLS_EV_UPDATE_CFG_CSC, &new_cfg);
}

/* apply the configuration, may be changed before by lcls_update_config */
void lcls_apply_config(struct gsm_subscriber_connection *conn)
{
	osmo_fsm_inst_dispatch(conn->lcls.fi, LCLS_EV_APPLY_CFG_CSC, NULL);
}

/* Redirect BTS's RTP traffic via RSL MDCX command:
 * when enable == true, redirect to remote BTS's IP:port
 * when enable == false, redirect back to the MGW's IP:port
 */
static inline void lcls_rsl(const struct gsm_subscriber_connection *conn, bool enable)
{
       const struct gsm_lchan *lchan = conn->lchan;
       /* RSL_IE_IPAC_REMOTE_IP */
       uint32_t ip = enable ? conn->lcls.other->lchan->abis_ip.bound_ip : lchan->abis_ip.connect_ip;
       /* RSL_IE_IPAC_REMOTE_PORT */
       uint16_t port = enable ? conn->lcls.other->lchan->abis_ip.bound_port : lchan->abis_ip.connect_port;
       struct msgb *msg;

       if (!conn->lcls.other) {
	       LOGPFSM(conn->lcls.fi, "%s LCLS: other conn is not available!\n", enable ? "enable" : "disable");
               return;
       }

       msg = rsl_make_ipacc_mdcx(lchan, ip, port);
       if (!msg) {
	       LOGPFSML(conn->lcls.fi, LOGL_ERROR, "Error encoding IPACC MDCX\n");
	       return;
       }
       abis_rsl_sendmsg(msg);
}

static inline bool lcls_check_toggle_allowed(const struct gsm_subscriber_connection *conn, bool enable)
{
	if (conn->lcls.other &&
	    conn->sccp.msc->lcls_mode != conn->lcls.other->sccp.msc->lcls_mode) {
		LOGPFSM(conn->lcls.fi, "FIXME: LCLS connection mode mismatch: %s != %s\n",
			get_value_string(bsc_lcls_mode_names, conn->sccp.msc->lcls_mode),
			get_value_string(bsc_lcls_mode_names, conn->lcls.other->sccp.msc->lcls_mode));
		return false;
	}

	if (conn->sccp.msc->lcls_mode == BSC_LCLS_MODE_MGW_LOOP && !conn->user_plane.mgw_endpoint_ci_msc) {
		/* the MGCP FSM has died, e.g. due to some MGCP/SDP parsing error */
		LOGPFSML(conn->lcls.fi, LOGL_NOTICE, "Cannot %s LCLS without MSC-side MGCP FSM\n",
			 enable ? "enable" : "disable");
		return false;
	}

	return true;
}

/* Close the loop for LCLS using MGCP */
static inline void lcls_mdcx(const struct gsm_subscriber_connection *conn, struct mgcp_conn_peer *mdcx_info)
{
	mgcp_pick_codec(mdcx_info, conn->lchan, false);

	osmo_mgcpc_ep_ci_request(conn->user_plane.mgw_endpoint_ci_msc, MGCP_VERB_MDCX, mdcx_info,
				NULL, 0, 0, NULL);
}

static void lcls_break_local_switching(struct gsm_subscriber_connection *conn)
{
	struct mgcp_conn_peer mdcx_info = {};

	LOGPFSM(conn->lcls.fi, "=== HERE IS WHERE WE DISABLE LCLS(%s)\n",
		bsc_lcls_mode_name(conn->sccp.msc->lcls_mode));

	if (!lcls_check_toggle_allowed(conn, false))
		return;

	switch(conn->sccp.msc->lcls_mode) {
	case BSC_LCLS_MODE_MGW_LOOP:
		mdcx_info.port = conn->user_plane.msc_assigned_rtp_port;
		osmo_strlcpy(mdcx_info.addr, conn->user_plane.msc_assigned_rtp_addr, sizeof(mdcx_info.addr));
		lcls_mdcx(conn, &mdcx_info);
		break;
	case BSC_LCLS_MODE_BTS_LOOP:
		lcls_rsl(conn, false);
		break;
	case BSC_LCLS_MODE_DISABLED:
		LOGPFSM(conn->lcls.fi, "FIXME: attempt to break LCLS loop while LCLS is disabled?!\n");
		break;
	default:
		LOGPFSM(conn->lcls.fi, "FIXME: unknown LCLS mode %s\n",
			bsc_lcls_mode_name(conn->sccp.msc->lcls_mode));
	}
}

static bool lcls_enable_possible(const struct gsm_subscriber_connection *conn)
{
	struct gsm_subscriber_connection *other_conn = conn->lcls.other;
	OSMO_ASSERT(other_conn);

	if (!lcls_is_supported_config(conn->lcls.config)) {
		LOGPFSM(conn->lcls.fi, "Not enabling LS due to unsupported local config\n");
		return false;
	}

	if (!lcls_is_supported_config(other_conn->lcls.config)) {
		LOGPFSM(conn->lcls.fi, "Not enabling LS due to unsupported other config\n");
		return false;
	}

	if (conn->lcls.control != GSM0808_LCLS_CSC_CONNECT) {
		LOGPFSM(conn->lcls.fi, "Not enabling LS due to insufficient local control\n");
		return false;
	}

	if (other_conn->lcls.control != GSM0808_LCLS_CSC_CONNECT) {
		LOGPFSM(conn->lcls.fi, "Not enabling LS due to insufficient other control\n");
		return false;
	}

	if (conn->lchan->type != conn->lcls.other->lchan->type
	    && conn->sccp.msc->lcls_codec_mismatch_allow == false) {
		LOGPFSM(conn->lcls.fi,
			"Not enabling LS due to channel type mismatch: %s:%s != %s:%s\n",
			gsm_lchan_name(conn->lchan),
			gsm_chan_t_name(conn->lchan->type),
			gsm_lchan_name(conn->lcls.other->lchan),
			gsm_chan_t_name(conn->lcls.other->lchan->type));
		return false;
	}

	if (conn->lchan->current_ch_mode_rate.chan_mode != conn->lcls.other->lchan->current_ch_mode_rate.chan_mode
	    && conn->sccp.msc->lcls_codec_mismatch_allow == false) {
		LOGPFSM(conn->lcls.fi,
			"Not enabling LS due to TCH-mode mismatch: %s:%s != %s:%s\n",
			gsm_lchan_name(conn->lchan),
			gsm48_chan_mode_name(conn->lchan->current_ch_mode_rate.chan_mode),
			gsm_lchan_name(conn->lcls.other->lchan),
			gsm48_chan_mode_name(conn->lcls.other->lchan->current_ch_mode_rate.chan_mode));
		return false;
	}

	return true;
}

/***********************************************************************
 * State callback functions
 ***********************************************************************/

static void lcls_no_lcls_fn(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_subscriber_connection *conn = fi->priv;

	/* we're just starting and cannot yet have a correlated call */
	OSMO_ASSERT(conn->lcls.other == NULL);

	if (conn->sccp.msc->lcls_mode == BSC_LCLS_MODE_DISABLED) {
		LOGPFSML(fi, LOGL_DEBUG, "LCLS disabled for this MSC, ignoring %s\n",
			 osmo_fsm_event_name(fi->fsm, event));
		return;
	}

	/* If there's no GCR set, we can never leave this state */
	if (conn->lcls.global_call_ref_len == 0) {
		LOGPFSML(fi, LOGL_NOTICE, "No GCR set, ignoring %s\n",
			 osmo_fsm_event_name(fi->fsm, event));
		return;
	}

	switch (event) {
	case LCLS_EV_UPDATE_CFG_CSC:
		if (lcls_handle_cfg_update(conn, data) != 0)
			return;
		break;
	case LCLS_EV_APPLY_CFG_CSC:
		if (conn->lcls.config == GSM0808_LCLS_CFG_NA)
			return;
		if (lcls_perform_correlation(conn) != 0) {
			/* Correlation leads to no result: Not Possible to LS */
			osmo_fsm_inst_state_chg(fi, ST_NOT_POSSIBLE_LS, 0, 0);
			return;
		}
		/* we now have two correlated calls */
		OSMO_ASSERT(conn->lcls.other);
		if (lcls_enable_possible(conn)) {
			/* Local Switching now active */
			osmo_fsm_inst_state_chg(fi, ST_LOCALLY_SWITCHED, 0, 0);
			osmo_fsm_inst_dispatch(conn->lcls.other->lcls.fi, LCLS_EV_OTHER_ENABLED, conn);
		} else {
			/* Couldn't be enabled: Not yet LS */
			osmo_fsm_inst_state_chg(fi, ST_NOT_YET_LS, 0, 0);
		}
		break;
	default:
		OSMO_ASSERT(0);
		break;
	}
}

static void lcls_not_yet_ls_fn(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_subscriber_connection *conn = fi->priv;

	/* not yet locally switched means that we have correlation but no instruction
	 * to actually connect them yet */
	OSMO_ASSERT(conn->lcls.other);

	switch (event) {
	case LCLS_EV_UPDATE_CFG_CSC:
		if (lcls_handle_cfg_update(conn, data) != 0)
			return;
		break;
	case LCLS_EV_APPLY_CFG_CSC:
		if (lcls_enable_possible(conn)) {
			osmo_fsm_inst_state_chg(fi, ST_LOCALLY_SWITCHED, 0, 0);
			osmo_fsm_inst_dispatch(conn->lcls.other->lcls.fi, LCLS_EV_OTHER_ENABLED, conn);
		}
		break;
	case LCLS_EV_OTHER_ENABLED:
		OSMO_ASSERT(conn->lcls.other == data);
		if (lcls_enable_possible(conn)) {
			osmo_fsm_inst_state_chg(fi, ST_LOCALLY_SWITCHED, 0, 0);
			/* Send LCLS-NOTIFY to inform MSC */
			lcls_send_notify(conn);
		} else {
			/* we couldn't enable our side, so ask other side to break */
			osmo_fsm_inst_dispatch(conn->lcls.other->lcls.fi, LCLS_EV_OTHER_BREAK, conn);
		}
		break;
	case LCLS_EV_CORRELATED:
		/* other call informs us that he correlated with us */
		conn->lcls.other = data;
		break;
	case LCLS_EV_OTHER_DEAD:
		OSMO_ASSERT(conn->lcls.other == data);
		conn->lcls.other = NULL;
		osmo_fsm_inst_state_chg(fi, ST_NOT_POSSIBLE_LS, 0, 0);
		/* Send LCLS-NOTIFY to inform MSC */
		lcls_send_notify(conn);
		break;
	default:
		OSMO_ASSERT(0);
		break;
	}
}

static void lcls_not_possible_ls_fn(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_subscriber_connection *conn = fi->priv;

	OSMO_ASSERT(conn->lcls.other == NULL);

	switch (event) {
	case LCLS_EV_UPDATE_CFG_CSC:
		if (lcls_handle_cfg_update(conn, data) != 0)
			return;
		break;
	case LCLS_EV_APPLY_CFG_CSC:
		if (lcls_perform_correlation(conn) != 0) {
			/* no correlation result: Remain in NOT_POSSIBLE_LS */
			return;
		}
		/* we now have two correlated calls */
		OSMO_ASSERT(conn->lcls.other);
		if (lcls_enable_possible(conn)) {
			osmo_fsm_inst_state_chg(fi, ST_LOCALLY_SWITCHED, 0, 0);
			osmo_fsm_inst_dispatch(conn->lcls.other->lcls.fi, LCLS_EV_OTHER_ENABLED, conn);
		} else {
			osmo_fsm_inst_state_chg(fi, ST_NOT_YET_LS, 0, 0);
		}
		break;
	case LCLS_EV_CORRELATED:
		/* other call informs us that he correlated with us */
		conn->lcls.other = data;
		osmo_fsm_inst_state_chg(fi, ST_NOT_YET_LS, 0, 0);
		/* Send NOTIFY about the fact that correlation happened */
		lcls_send_notify(conn);
		break;
	case LCLS_EV_OTHER_DEAD:
		OSMO_ASSERT(conn->lcls.other == data);
		conn->lcls.other = NULL;
		break;
	default:
		OSMO_ASSERT(0);
		break;
	}
}

static void lcls_no_longer_ls_fn(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_subscriber_connection *conn = fi->priv;

	OSMO_ASSERT(conn->lcls.other);

	switch (event) {
	case LCLS_EV_UPDATE_CFG_CSC:
		if (lcls_handle_cfg_update(conn, data) != 0)
			return;
		if (lcls_enable_possible(conn)) {
			osmo_fsm_inst_state_chg(fi, ST_LOCALLY_SWITCHED, 0, 0);
			osmo_fsm_inst_dispatch(conn->lcls.other->lcls.fi, LCLS_EV_OTHER_ENABLED, conn);
		} else {
			osmo_fsm_inst_state_chg(fi, ST_NOT_YET_LS, 0, 0);
		}
		break;
	case LCLS_EV_OTHER_ENABLED:
		OSMO_ASSERT(conn->lcls.other == data);
		if (lcls_enable_possible(conn)) {
			osmo_fsm_inst_state_chg(fi, ST_LOCALLY_SWITCHED, 0, 0);
			/* Send LCLS-NOTIFY to inform MSC */
			lcls_send_notify(conn);
		} else {
			/* we couldn't enable our side, so ask other side to break */
			osmo_fsm_inst_dispatch(conn->lcls.other->lcls.fi, LCLS_EV_OTHER_BREAK, conn);
		}
		break;
	case LCLS_EV_CORRELATED:
		/* other call informs us that he correlated with us */
		conn->lcls.other = data;
		break;
	case LCLS_EV_OTHER_DEAD:
		OSMO_ASSERT(conn->lcls.other == data);
		conn->lcls.other = NULL;
		osmo_fsm_inst_state_chg(fi, ST_NOT_POSSIBLE_LS, 0, 0);
		/* Send LCLS-NOTIFY to inform MSC */
		lcls_send_notify(conn);
		break;
	case LCLS_EV_APPLY_CFG_CSC:
		break;
	default:
		OSMO_ASSERT(0);
		break;
	}
}

static void lcls_req_lcls_not_supp_fn(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_subscriber_connection *conn = fi->priv;

	/* we could have a correlated other call or not */

	switch (event) {
	case LCLS_EV_UPDATE_CFG_CSC:
		if (lcls_handle_cfg_update(conn, data) != 0)
			return;
		//FIXME osmo_fsm_inst_state_chg(fi,
		return;
	case LCLS_EV_APPLY_CFG_CSC:
		if (lcls_perform_correlation(conn) != 0) {
			osmo_fsm_inst_state_chg(fi, ST_NOT_POSSIBLE_LS, 0, 0);
			return;
		}
		/* we now have two correlated calls */
		OSMO_ASSERT(conn->lcls.other);
		if (!lcls_is_supported_config(conn->lcls.config))
			return;
		if (lcls_enable_possible(conn))
			osmo_fsm_inst_state_chg(fi, ST_LOCALLY_SWITCHED, 0, 0);
		else
			osmo_fsm_inst_state_chg(fi, ST_NOT_YET_LS, 0, 0);
		break;
	case LCLS_EV_CORRELATED:
		/* other call informs us that he correlated with us */
		conn->lcls.other = data;
		break;
	case LCLS_EV_OTHER_DEAD:
		OSMO_ASSERT(conn->lcls.other == data);
		conn->lcls.other = NULL;
		break;
	default:
		OSMO_ASSERT(0);
		break;
	}

}

static void lcls_locally_switched_fn(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_subscriber_connection *conn = fi->priv;

	OSMO_ASSERT(conn->lcls.other);

	switch (event) {
	case LCLS_EV_UPDATE_CFG_CSC:
		if (lcls_handle_cfg_update(conn, data) != 0) {
			lcls_break_local_switching(conn);
			return;
		}
		break;
	case LCLS_EV_APPLY_CFG_CSC:
		if (conn->lcls.control == GSM0808_LCLS_CSC_RELEASE_LCLS) {
			osmo_fsm_inst_state_chg(fi, ST_LOCALLY_SWITCHED_WAIT_OTHER_BREAK, 0, 0);
			osmo_fsm_inst_dispatch(conn->lcls.other->lcls.fi, LCLS_EV_OTHER_BREAK, conn);
			/* FIXME: what if there's a new config included? */
			return;
		}
		/* TODO: Handle any changes of "config" once we support bi-casting etc. */
		break;
	case LCLS_EV_OTHER_BREAK:
		OSMO_ASSERT(conn->lcls.other == data);
		osmo_fsm_inst_state_chg(fi, ST_LOCALLY_SWITCHED_WAIT_BREAK, 0, 0);
		break;
	case LCLS_EV_OTHER_DEAD:
		OSMO_ASSERT(conn->lcls.other == data);
		conn->lcls.other = NULL;
		osmo_fsm_inst_state_chg(fi, ST_NOT_POSSIBLE_LS, 0, 0);
		/* Send LCLS-NOTIFY to inform MSC */
		lcls_send_notify(conn);
		break;
	default:
		OSMO_ASSERT(0);
		break;
	}
}


static void lcls_locally_switched_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct gsm_subscriber_connection *conn = fi->priv;
	struct gsm_subscriber_connection *conn_other = conn->lcls.other;
	const struct mgcp_conn_peer *other_mgw_info;
	struct mgcp_conn_peer mdcx_info;

	OSMO_ASSERT(conn_other);

	if (!lcls_check_toggle_allowed(conn, true))
		return;

	LOGPFSM(fi, "=== HERE IS WHERE WE ENABLE LCLS(%s)\n",
		bsc_lcls_mode_name(conn->sccp.msc->lcls_mode));

	if (!conn_other->user_plane.mgw_endpoint_ci_msc) {
		LOGPFSML(fi, LOGL_ERROR, "Cannot enable LCLS without MSC-side MGCP FSM. FIXME\n");
		return;
	}

	other_mgw_info = osmo_mgcpc_ep_ci_get_rtp_info(conn_other->user_plane.mgw_endpoint_ci_msc);
	if (!other_mgw_info) {
		LOGPFSML(fi, LOGL_ERROR, "Cannot enable LCLS without RTP port info of MSC-side"
			 " -- missing CRCX?\n");
		return;
	}

	switch(conn->sccp.msc->lcls_mode) {
	case BSC_LCLS_MODE_MGW_LOOP:
		mdcx_info = *other_mgw_info;
		/* Make sure the request doesn't want to use the other side's endpoint string. */
		mdcx_info.endpoint[0] = 0;
		lcls_mdcx(conn, &mdcx_info);
		break;
	case BSC_LCLS_MODE_BTS_LOOP:
		lcls_rsl(conn, true);
		break;
	case BSC_LCLS_MODE_DISABLED:
		LOGPFSM(conn->lcls.fi, "FIXME: attempt to close LCLS loop while LCLS is disabled?!\n");
		break;
	default:
		LOGPFSM(conn->lcls.fi, "FIXME: unknown LCLS mode %s\n",
			bsc_lcls_mode_name(conn->sccp.msc->lcls_mode));
	}
}

static void lcls_locally_switched_wait_break_fn(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_subscriber_connection *conn = fi->priv;

	OSMO_ASSERT(conn->lcls.other);

	switch (event) {
	case LCLS_EV_UPDATE_CFG_CSC:
		if (lcls_handle_cfg_update(conn, data) != 0) {
			lcls_break_local_switching(conn);
			return;
		}
		break;
	case LCLS_EV_APPLY_CFG_CSC:
		if (conn->lcls.control == GSM0808_LCLS_CSC_RELEASE_LCLS) {
			lcls_break_local_switching(conn);
			osmo_fsm_inst_state_chg(fi, ST_NO_LONGER_LS, 0, 0);
			osmo_fsm_inst_dispatch(conn->lcls.other->lcls.fi, LCLS_EV_OTHER_BREAK, conn);
			/* no NOTIFY here, as the caller will be returning status in LCLS-CTRL-ACK */
			/* FIXME: what if there's a new config included? */
			return;
		}
		/* TODO: Handle any changes of "config" once we support bi-casting etc. */
		break;
	case LCLS_EV_OTHER_BREAK:
		/* we simply ignore it, must be a re-transmission */
		break;
	case LCLS_EV_OTHER_DEAD:
		OSMO_ASSERT(conn->lcls.other == data);
		conn->lcls.other = NULL;
		break;
	default:
		lcls_locally_switched_fn(fi, event, data);
		break;
	}
}

static void lcls_locally_switched_wait_other_break_fn(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_subscriber_connection *conn = fi->priv;

	OSMO_ASSERT(conn->lcls.other);

	switch (event) {
	case LCLS_EV_UPDATE_CFG_CSC:
		if (lcls_handle_cfg_update(conn, data) != 0) {
			lcls_break_local_switching(conn);
			return;
		}
		/* TODO: Handle any changes of "config" once we support bi-casting etc. */
		break;
	case LCLS_EV_OTHER_BREAK:
	case LCLS_EV_OTHER_DEAD:
		OSMO_ASSERT(conn->lcls.other == data);
		lcls_break_local_switching(conn);
		osmo_fsm_inst_state_chg(fi, ST_NO_LONGER_LS, 0, 0);
		/* Send LCLS-NOTIFY to inform MSC */
		lcls_send_notify(conn);
		break;
	default:
		lcls_locally_switched_fn(fi, event, data);
		break;
	}
}

static void lcls_fsm_cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct gsm_subscriber_connection *conn = fi->priv;

	if (conn->lcls.other) {
		/* inform the "other" side that we're dead, so it can disable LS and send NOTIFY */
		if (conn->lcls.other->fi)
			osmo_fsm_inst_dispatch(conn->lcls.other->lcls.fi, LCLS_EV_OTHER_DEAD, conn);
		conn->lcls.other = NULL;
	}
}


/***********************************************************************
 * FSM Definition
 ***********************************************************************/

#define S(x) (1 << (x))

static const struct osmo_fsm_state lcls_fsm_states[] = {
	[ST_NO_LCLS] = {
		.in_event_mask = S(LCLS_EV_UPDATE_CFG_CSC) |
				 S(LCLS_EV_APPLY_CFG_CSC),
		.out_state_mask = S(ST_NO_LCLS) |
				  S(ST_NOT_YET_LS) |
				  S(ST_NOT_POSSIBLE_LS) |
				  S(ST_REQ_LCLS_NOT_SUPP) |
				  S(ST_LOCALLY_SWITCHED),
		.name = "NO_LCLS",
		.action = lcls_no_lcls_fn,
	},
	[ST_NOT_YET_LS] = {
		.in_event_mask = S(LCLS_EV_UPDATE_CFG_CSC) |
				 S(LCLS_EV_APPLY_CFG_CSC) |
				 S(LCLS_EV_CORRELATED) |
				 S(LCLS_EV_OTHER_ENABLED) |
				 S(LCLS_EV_OTHER_DEAD),
		.out_state_mask = S(ST_NOT_YET_LS) |
				  S(ST_REQ_LCLS_NOT_SUPP) |
				  S(ST_LOCALLY_SWITCHED),
		.name = "NOT_YET_LS",
		.action = lcls_not_yet_ls_fn,
	},
	[ST_NOT_POSSIBLE_LS] = {
		.in_event_mask = S(LCLS_EV_UPDATE_CFG_CSC) |
				 S(LCLS_EV_APPLY_CFG_CSC) |
				 S(LCLS_EV_CORRELATED),
		.out_state_mask = S(ST_NOT_YET_LS) |
				  S(ST_NOT_POSSIBLE_LS) |
				  S(ST_REQ_LCLS_NOT_SUPP) |
				  S(ST_LOCALLY_SWITCHED),
		.name = "NOT_POSSIBLE_LS",
		.action = lcls_not_possible_ls_fn,
	},
	[ST_NO_LONGER_LS] = {
		.in_event_mask = S(LCLS_EV_UPDATE_CFG_CSC) |
				 S(LCLS_EV_APPLY_CFG_CSC) |
				 S(LCLS_EV_CORRELATED) |
				 S(LCLS_EV_OTHER_ENABLED) |
				 S(LCLS_EV_OTHER_DEAD),
		.out_state_mask = S(ST_NO_LONGER_LS) |
				  S(ST_REQ_LCLS_NOT_SUPP) |
				  S(ST_LOCALLY_SWITCHED),
		.name = "NO_LONGER_LS",
		.action = lcls_no_longer_ls_fn,
	},
	[ST_REQ_LCLS_NOT_SUPP] = {
		.in_event_mask = S(LCLS_EV_UPDATE_CFG_CSC) |
				 S(LCLS_EV_APPLY_CFG_CSC) |
				 S(LCLS_EV_CORRELATED) |
				 S(LCLS_EV_OTHER_DEAD),
		.out_state_mask = S(ST_NOT_YET_LS) |
				  S(ST_REQ_LCLS_NOT_SUPP) |
				  S(ST_LOCALLY_SWITCHED),
		.name = "REQ_LCLS_NOT_SUPP",
		.action = lcls_req_lcls_not_supp_fn,
	},
	[ST_LOCALLY_SWITCHED] = {
		.in_event_mask = S(LCLS_EV_UPDATE_CFG_CSC) |
				 S(LCLS_EV_APPLY_CFG_CSC) |
				 S(LCLS_EV_OTHER_BREAK) |
				 S(LCLS_EV_OTHER_DEAD),
		.out_state_mask = S(ST_NO_LONGER_LS) |
				  S(ST_NOT_POSSIBLE_LS) |
				  S(ST_REQ_LCLS_NOT_SUPP) |
				  S(ST_LOCALLY_SWITCHED_WAIT_BREAK) |
				  S(ST_LOCALLY_SWITCHED_WAIT_OTHER_BREAK) |
				  S(ST_LOCALLY_SWITCHED),
		.name = "LOCALLY_SWITCHED",
		.action = lcls_locally_switched_fn,
		.onenter = lcls_locally_switched_onenter,
	},
	/* received an "other" break, waiting for the local break */
	[ST_LOCALLY_SWITCHED_WAIT_BREAK] = {
		.in_event_mask = S(LCLS_EV_UPDATE_CFG_CSC) |
				 S(LCLS_EV_APPLY_CFG_CSC) |
				 S(LCLS_EV_OTHER_BREAK) |
				 S(LCLS_EV_OTHER_DEAD),
		.out_state_mask = S(ST_NO_LONGER_LS) |
				  S(ST_REQ_LCLS_NOT_SUPP) |
				  S(ST_LOCALLY_SWITCHED) |
				  S(ST_LOCALLY_SWITCHED_WAIT_BREAK),
		.name = "LOCALLY_SWITCHED_WAIT_BREAK",
		.action = lcls_locally_switched_wait_break_fn,
	},
	/* received a local break, waiting for the "other" break */
	[ST_LOCALLY_SWITCHED_WAIT_OTHER_BREAK] = {
		.in_event_mask = S(LCLS_EV_UPDATE_CFG_CSC) |
				 S(LCLS_EV_OTHER_BREAK) |
				 S(LCLS_EV_OTHER_DEAD),
		.out_state_mask = S(ST_NO_LONGER_LS) |
				  S(ST_REQ_LCLS_NOT_SUPP) |
				  S(ST_LOCALLY_SWITCHED) |
				  S(ST_LOCALLY_SWITCHED_WAIT_OTHER_BREAK),
		.name = "LOCALLY_SWITCHED_WAIT_OTHER_BREAK",
		.action = lcls_locally_switched_wait_other_break_fn,
	},


};

struct osmo_fsm lcls_fsm = {
	.name = "LCLS",
	.states = lcls_fsm_states,
	.num_states = ARRAY_SIZE(lcls_fsm_states),
	.allstate_event_mask = 0,
	.allstate_action = NULL,
	.cleanup = lcls_fsm_cleanup,
	.timer_cb = NULL,
	.log_subsys = DLCLS,
	.event_names = lcls_event_names,
};
