/* osmo-bsc API to manage all sides of an MGW endpoint
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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <osmocom/core/fsm.h>
#include <osmocom/core/byteswap.h>
#include <osmocom/netif/rtp.h>

#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/gsm_timers.h>

#include <osmocom/bsc/mgw_endpoint_fsm.h>
#include <osmocom/bsc/lchan_fsm.h>
#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/bsc_msc_data.h>

#define LOG_CI(ci, level, fmt, args...) do { \
	if (!ci || !ci->mgwep) \
		LOGP(DLGLOBAL, level, "(unknown MGW endpoint) " fmt, ## args); \
	else \
		LOG_MGWEP(ci->mgwep, level, "CI[%d] %s%s%s: " fmt, \
			(int)(ci - ci->mgwep->ci), \
			ci->label ? : "-", \
			ci->mgcp_ci_str[0] ? " CI=" : "", \
			ci->mgcp_ci_str[0] ? ci->mgcp_ci_str : "", \
			## args); \
	} while(0)

#define LOG_CI_VERB(ci, level, fmt, args...) do { \
	if (ci->verb_info.addr) \
		LOG_CI(ci, level, "%s %s:%u: " fmt, \
			mgcp_verb_name(ci->verb), ci->verb_info.addr, ci->verb_info.port, \
			## args); \
	else \
		LOG_CI(ci, level, "%s: " fmt, \
			mgcp_verb_name(ci->verb), \
			## args); \
	} while(0)

#define FIRST_CI_EVENT (_MGWEP_EV_LAST + (_MGWEP_EV_LAST & 1)) /* rounded up to even nr */
#define USABLE_CI ((32 - FIRST_CI_EVENT)/2)
#define EV_TO_CI_IDX(event) ((event - FIRST_CI_EVENT) / 2)

#define CI_EV_SUCCESS(ci) (FIRST_CI_EVENT + (((ci) - ci->mgwep->ci) * 2))
#define CI_EV_FAILURE(ci) (CI_EV_SUCCESS(ci) + 1)

static struct osmo_fsm mgwep_fsm;

struct mgwep_ci {
	struct mgw_endpoint *mgwep;

	bool occupied;
	char label[64];
	struct osmo_fsm_inst *mgcp_client_fi;

	bool pending;
	bool sent;
	enum mgcp_verb verb;
	struct mgcp_conn_peer verb_info;
	struct osmo_fsm_inst *notify;
	uint32_t notify_success;
	uint32_t notify_failure;
	void *notify_data;

	bool got_port_info;
	struct mgcp_conn_peer rtp_info;
	char mgcp_ci_str[MGCP_CONN_ID_LENGTH];
};

struct mgw_endpoint {
	struct mgcp_client *mgcp_client;
	struct osmo_fsm_inst *fi;
	char endpoint[MGCP_ENDPOINT_MAXLEN];

	struct mgwep_ci ci[USABLE_CI];
};

static const struct value_string mgcp_verb_names[] = {
	{ MGCP_VERB_CRCX, "CRCX" },
	{ MGCP_VERB_MDCX, "MDCX" },
	{ MGCP_VERB_DLCX, "DLCX" },
	{ MGCP_VERB_AUEP, "AUEP" },
	{ MGCP_VERB_RSIP, "RSIP" },
	{}
};

static inline const char *mgcp_verb_name(enum mgcp_verb val)
{ return get_value_string(mgcp_verb_names, val); }

static struct mgwep_ci *mgwep_check_ci(struct mgwep_ci *ci)
{
	if (!ci)
		return NULL;
	if (!ci->mgwep)
		return NULL;
	if (ci < ci->mgwep->ci || ci >= &ci->mgwep->ci[USABLE_CI])
		return NULL;
	return ci;
}

static struct mgwep_ci *mgwep_ci_for_event(struct mgw_endpoint *mgwep, uint32_t event)
{
	int idx;
	if (event < FIRST_CI_EVENT)
		return NULL;
	idx = EV_TO_CI_IDX(event);
	if (idx >= sizeof(mgwep->ci))
		return NULL;
	return mgwep_check_ci(&mgwep->ci[idx]);
}

const char *mgw_endpoint_name(const struct mgw_endpoint *mgwep)
{
	if (!mgwep)
		return "NULL";
	if (mgwep->endpoint[0])
		return mgwep->endpoint;
	return osmo_fsm_inst_name(mgwep->fi);
}

const char *mgcp_conn_peer_name(const struct mgcp_conn_peer *info)
{
	/* I'd be fine with a smaller buffer and accept truncation, but gcc possibly refuses to build if
	 * this buffer is too small. */
	static char buf[1024];

	if (!info)
		return "NULL";

	if (info->endpoint[0]
	    && info->addr[0])
		snprintf(buf, sizeof(buf), "%s:%s:%u",
			 info->endpoint, info->addr, info->port);
	else if (info->endpoint[0])
		snprintf(buf, sizeof(buf), "%s", info->endpoint);
	else if (info->addr[0])
		snprintf(buf, sizeof(buf), "%s:%u", info->addr, info->port);
	else
		return "empty";
	return buf;
}

const char *mgwep_ci_name(const struct mgwep_ci *ci)
{
	const struct mgcp_conn_peer *rtp_info;

	if (!ci)
		return "NULL";

	rtp_info = mgwep_ci_get_rtp_info(ci);

	if (rtp_info)
		return mgcp_conn_peer_name(rtp_info);
	return mgw_endpoint_name(ci->mgwep);
}

static struct value_string mgwep_fsm_event_names[33] = {};

static char mgwep_fsm_event_name_bufs[32][32] = {};

static void fill_event_names()
{
	int i;
	for (i = 0; i < (ARRAY_SIZE(mgwep_fsm_event_names) - 1); i++) {
		if (i < _MGWEP_EV_LAST)
			continue;
		if (i < FIRST_CI_EVENT || EV_TO_CI_IDX(i) > USABLE_CI) {
			mgwep_fsm_event_names[i] = (struct value_string){i, "Unused"};
			continue;
		}
		snprintf(mgwep_fsm_event_name_bufs[i], sizeof(mgwep_fsm_event_name_bufs[i]),
			 "MGW Response for CI #%d", EV_TO_CI_IDX(i));
		mgwep_fsm_event_names[i] = (struct value_string){i, mgwep_fsm_event_name_bufs[i]};
	}
}

static struct T_def *g_T_defs = NULL;

void mgw_endpoint_fsm_init(struct T_def *T_defs)
{
	g_T_defs = T_defs;
	OSMO_ASSERT(osmo_fsm_register(&mgwep_fsm) == 0);
	fill_event_names();
}

struct mgw_endpoint *mgwep_fi_mgwep(struct osmo_fsm_inst *fi)
{
	OSMO_ASSERT(fi);
	OSMO_ASSERT(fi->fsm == &mgwep_fsm);
	OSMO_ASSERT(fi->priv);
	return fi->priv;
}

struct mgw_endpoint *mgw_endpoint_alloc(struct osmo_fsm_inst *parent, uint32_t parent_term_event,
					struct mgcp_client *mgcp_client,
					const char *fsm_id,
					const char *endpoint_str_fmt, ...)
{
	va_list ap;
	struct osmo_fsm_inst *fi;
	struct mgw_endpoint *mgwep;
	int rc;

	if (!mgcp_client)
		return NULL;

	/* use mgcp_client as talloc ctx, so that the conn, lchan, ts can deallocate while MGCP DLCX are
	 * still going on. */
	fi = osmo_fsm_inst_alloc_child(&mgwep_fsm, parent, parent_term_event);
	OSMO_ASSERT(fi);

	osmo_fsm_inst_update_id(fi, fsm_id);

	mgwep = talloc_zero(fi, struct mgw_endpoint);
	OSMO_ASSERT(mgwep);

	mgwep->mgcp_client = mgcp_client;
	mgwep->fi = fi;
	mgwep->fi->priv = mgwep;

	va_start(ap, endpoint_str_fmt);
	rc = vsnprintf(mgwep->endpoint, sizeof(mgwep->endpoint), endpoint_str_fmt, ap);
	va_end(ap);

	if (rc <= 0 || rc >= sizeof(mgwep->endpoint)) {
		LOG_MGWEP(mgwep, LOGL_ERROR, "Endpoint name too long or too short: %s\n",
			  mgwep->endpoint);
		osmo_fsm_inst_term(mgwep->fi, OSMO_FSM_TERM_ERROR, 0);
		return NULL;
	}

	return mgwep;
}

struct mgwep_ci *mgw_endpoint_ci_add(struct mgw_endpoint *mgwep,
				     const char *label_fmt, ...)
{
	va_list ap;
	int i;
	struct mgwep_ci *ci;

	for (i = 0; i < USABLE_CI; i++) {
		ci = &mgwep->ci[i];

		if (ci->occupied || ci->mgcp_client_fi)
			continue;

		*ci = (struct mgwep_ci){
			.mgwep = mgwep,
			.occupied = true,
		};
		if (label_fmt) {
			va_start(ap, label_fmt);
			vsnprintf(ci->label, sizeof(ci->label), label_fmt, ap);
			va_end(ap);
		}
		return ci;
	}

	LOG_MGWEP(mgwep, LOGL_ERROR,
		  "Cannot allocate another endpoint, all "
		  OSMO_STRINGIFY_VAL(USABLE_CI) " are in use\n");

	return NULL;
}

static void mgwep_fsm_check_state_chg_after_response(struct osmo_fsm_inst *fi);

static void on_failure(struct mgwep_ci *ci)
{
	if (!ci->occupied)
		return;

	if (ci->notify)
		osmo_fsm_inst_dispatch(ci->notify, ci->notify_failure, ci->notify_data);

	*ci = (struct mgwep_ci){
		.mgwep = ci->mgwep,
	};


	mgwep_fsm_check_state_chg_after_response(ci->mgwep->fi);
}

static void on_success(struct mgwep_ci *ci, void *data)
{
	struct mgcp_conn_peer *rtp_info;

	if (!ci->occupied)
		return;

	ci->pending = false;

	switch (ci->verb) {
	case MGCP_VERB_CRCX:
		/* If we sent a wildcarded endpoint name on CRCX, we need to store the resulting endpoint
		 * name here. Also, we receive the MGW's RTP port information. */
		rtp_info = data;
		OSMO_ASSERT(rtp_info);
		ci->got_port_info = true;
		ci->rtp_info = *rtp_info;
		osmo_strlcpy(ci->mgcp_ci_str, mgcp_conn_get_ci(ci->mgcp_client_fi),
			sizeof(ci->mgcp_ci_str));
		if (rtp_info->endpoint[0]) {
			int rc;
			rc = osmo_strlcpy(ci->mgwep->endpoint, rtp_info->endpoint,
					  sizeof(ci->mgwep->endpoint));
			if (rc <= 0 || rc >= sizeof(ci->mgwep->endpoint)) {
				LOG_CI(ci, LOGL_ERROR, "Unable to copy endpoint name '%s'\n",
				       rtp_info->endpoint);
				mgw_endpoint_ci_dlcx(ci);
				on_failure(ci);
				return;
			}
		}
		break;

	default:
		break;
	}

	LOG_CI(ci, LOGL_DEBUG, "received successful response to %s RTP=%s%s\n",
	       mgcp_verb_name(ci->verb),
	       mgcp_conn_peer_name(ci->got_port_info? &ci->rtp_info : NULL),
	       ci->notify ? "" : " (not sending a notification)");

	if (ci->notify)
		osmo_fsm_inst_dispatch(ci->notify, ci->notify_success, ci->notify_data);

	mgwep_fsm_check_state_chg_after_response(ci->mgwep->fi);
}

const struct mgcp_conn_peer *mgwep_ci_get_rtp_info(const struct mgwep_ci *ci)
{
	ci = mgwep_check_ci((struct mgwep_ci*)ci);
	if (!ci)
		return NULL;
	if (!ci->got_port_info)
		return NULL;
	return &ci->rtp_info;
}

bool mgwep_ci_get_crcx_info_to_sockaddr(const struct mgwep_ci *ci, struct sockaddr_storage *dest)
{
	const struct mgcp_conn_peer *rtp_info;
	struct sockaddr_in *sin;

	rtp_info = mgwep_ci_get_rtp_info(ci);
	if (!rtp_info)
		return false;

        sin = (struct sockaddr_in *)dest;

        sin->sin_family = AF_INET;
        sin->sin_addr.s_addr = inet_addr(rtp_info->addr);
        sin->sin_port = osmo_ntohs(rtp_info->port);
	return true;
}


static const struct state_timeout mgwep_fsm_timeouts[32] = {
	[MGWEP_ST_WAIT_MGW_RESPONSE] = { .T=23042 },
};

/* Transition to a state, using the T timer defined in assignment_fsm_timeouts.
 * The actual timeout value is in turn obtained from g_T_defs.
 * Assumes local variable fi exists. */
#define mgwep_fsm_state_chg(state) \
	fsm_inst_state_chg_T(fi, state, mgwep_fsm_timeouts, g_T_defs, 5)

void mgw_endpoint_ci_request(struct mgwep_ci *ci,
			     enum mgcp_verb verb, const struct mgcp_conn_peer *verb_info,
			     struct osmo_fsm_inst *notify,
			     uint32_t event_success, uint32_t event_failure,
			     void *notify_data)
{
	struct mgw_endpoint *mgwep;
	struct osmo_fsm_inst *fi;
	struct mgwep_ci cleared_ci;
	ci = mgwep_check_ci(ci);

	if (!ci) {
		LOGP(DLGLOBAL, LOGL_ERROR, "Invalid MGW endpoint request: no ci\n");
		goto dispatch_error;
	}
	if (!verb_info && verb != MGCP_VERB_DLCX) {
		LOG_CI(ci, LOGL_ERROR, "Invalid MGW endpoint request: missing verb details for %s\n",
		       mgcp_verb_name(verb));
		goto dispatch_error;
	}
	if ((verb < 0) || (verb > MGCP_VERB_RSIP)) {
		LOG_CI(ci, LOGL_ERROR, "Invalid MGW endpoint request: unknown verb: %s\n",
		       mgcp_verb_name(verb));
		goto dispatch_error;
	}

	mgwep = ci->mgwep;
	fi = mgwep->fi;

	/* Clear volatile state by explicitly keeping those that should remain. Because we can't assign
	 * the char[] directly, dance through cleared_ci and copy back. */
	cleared_ci = (struct mgwep_ci){
		.mgwep = mgwep,
		.mgcp_client_fi = ci->mgcp_client_fi,
		.got_port_info = ci->got_port_info,
		.rtp_info = ci->rtp_info,

		.occupied = true,
		/* .pending = true follows below */
		.verb = verb,
		.notify = notify,
		.notify_success = event_success,
		.notify_failure = event_failure,
		.notify_data = notify_data,
	};
	osmo_strlcpy(cleared_ci.label, ci->label, sizeof(cleared_ci.label));
	osmo_strlcpy(cleared_ci.mgcp_ci_str, ci->mgcp_ci_str, sizeof(cleared_ci.mgcp_ci_str));
	*ci = cleared_ci;

	LOG_CI_VERB(ci, LOGL_DEBUG, "notify=%s\n", osmo_fsm_inst_name(ci->notify));

	if (verb_info)
		ci->verb_info = *verb_info;

	if (mgwep->endpoint[0]) {
		if (ci->verb_info.endpoint[0] && strcmp(ci->verb_info.endpoint, mgwep->endpoint))
			LOG_CI(ci, LOGL_ERROR,
			       "Warning: Requested %s on endpoint %s, but this CI is on endpoint %s."
			       " Using the proper endpoint instead.\n",
			       mgcp_verb_name(verb), ci->verb_info.endpoint, mgwep->endpoint);
		osmo_strlcpy(ci->verb_info.endpoint, mgwep->endpoint, sizeof(ci->verb_info.endpoint));
	}

	switch (ci->verb) {
	case MGCP_VERB_CRCX:
		if (ci->mgcp_client_fi) {
			LOG_CI(ci, LOGL_ERROR, "CRCX can be called only once per MGW endpoint CI\n");
			on_failure(ci);
			return;
		}
		break;

	case MGCP_VERB_MDCX:
	case MGCP_VERB_DLCX:
		if (!ci->mgcp_client_fi) {
			LOG_CI_VERB(ci, LOGL_ERROR, "The first verb on an unused MGW endpoint CI must be CRCX, not %s\n",
				    mgcp_verb_name(ci->verb));
			on_failure(ci);
			return;
		}
		break;

	default:
		LOG_CI(ci, LOGL_ERROR, "This verb is not supported: %s\n", mgcp_verb_name(ci->verb));
		on_failure(ci);
		return;
	}

	ci->pending = true;

	LOG_CI_VERB(ci, LOGL_DEBUG, "Scheduling\n");

	if (mgwep->fi->state != MGWEP_ST_WAIT_MGW_RESPONSE)
		mgwep_fsm_state_chg(MGWEP_ST_WAIT_MGW_RESPONSE);

	return;
dispatch_error:
	if (notify)
		osmo_fsm_inst_dispatch(notify, event_failure, notify_data);
}

static int send_verb(struct mgwep_ci *ci)
{
	int rc;
	struct mgw_endpoint *mgwep = ci->mgwep;

	if (!ci->occupied || !ci->pending || ci->sent)
		return 0;

	switch (ci->verb) {

	case MGCP_VERB_CRCX:
		OSMO_ASSERT(!ci->mgcp_client_fi);
		LOG_CI_VERB(ci, LOGL_DEBUG, "Sending\n");
		ci->mgcp_client_fi = mgcp_conn_create(mgwep->mgcp_client, mgwep->fi,
						      CI_EV_FAILURE(ci), CI_EV_SUCCESS(ci),
						      &ci->verb_info);
		ci->sent = true;
		if (!ci->mgcp_client_fi){
			LOG_CI_VERB(ci, LOGL_ERROR, "Cannot send\n");
			on_failure(ci);
		}
		osmo_fsm_inst_update_id(ci->mgcp_client_fi, ci->label);
		break;

	case MGCP_VERB_MDCX:
		OSMO_ASSERT(ci->mgcp_client_fi);
		LOG_CI_VERB(ci, LOGL_DEBUG, "Sending\n");
		rc = mgcp_conn_modify(ci->mgcp_client_fi, CI_EV_SUCCESS(ci), &ci->verb_info);
		ci->sent = true;
		if (rc) {
			LOG_CI_VERB(ci, LOGL_ERROR, "Cannot send (rc=%d %s)\n", rc, strerror(-rc));
			on_failure(ci);
		}
		break;

	case MGCP_VERB_DLCX:
		LOG_CI(ci, LOGL_DEBUG, "Sending MGCP: %s %s\n",
		       mgcp_verb_name(ci->verb), ci->mgcp_ci_str);
		/* The way this is designed, we actually need to forget all about the ci right away. */
		mgcp_conn_delete(ci->mgcp_client_fi);
		if (ci->notify)
			osmo_fsm_inst_dispatch(ci->notify, ci->notify_success, ci->notify_data);
		*ci = (struct mgwep_ci){
			.mgwep = mgwep,
		};
		break;

	default:
		OSMO_ASSERT(false);
	}

	return 1;
}

void mgw_endpoint_clear(struct mgw_endpoint *mgwep)
{
	if (!mgwep)
		return;
	osmo_fsm_inst_term(mgwep->fi, OSMO_FSM_TERM_REGULAR, 0);
}

static void mgwep_count(struct mgw_endpoint *mgwep, int *occupied, int *pending_not_sent,
			int *waiting_for_response)
{
	int i;

	if (occupied)
		*occupied = 0;

	if (pending_not_sent)
		*pending_not_sent = 0;

	if (waiting_for_response)
		*waiting_for_response = 0;

	for (i = 0; i < ARRAY_SIZE(mgwep->ci); i++) {
		struct mgwep_ci *ci = &mgwep->ci[i];
		if (ci->occupied) {
			if (occupied)
				(*occupied)++;
		} else
			continue;

		if (ci->pending)
			LOG_CI_VERB(ci, LOGL_DEBUG, "%s\n",
				    ci->sent ? "waiting for response" : "waiting to be sent");
		else
			LOG_CI_VERB(ci, LOGL_DEBUG, "%s\n", mgcp_conn_peer_name(mgwep_ci_get_rtp_info(ci)));

		if (ci->pending && ci->sent)
			if (waiting_for_response)
				(*waiting_for_response)++;
		if (ci->pending && !ci->sent)
			if (pending_not_sent)
				(*pending_not_sent)++;
	}
}

static void mgwep_fsm_check_state_chg_after_response(struct osmo_fsm_inst *fi)
{
	int waiting_for_response;
	int occupied;
	struct mgw_endpoint *mgwep = mgwep_fi_mgwep(fi);

	mgwep_count(mgwep, &occupied, NULL, &waiting_for_response);
	LOG_MGWEP(mgwep, LOGL_DEBUG, "CI in use: %d, waiting for response: %d\n", occupied, waiting_for_response);

	if (!occupied)  {
		/* All CI have been released. The endpoint no longer exists. Notify the parent FSM, by
		 * terminating. */
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, 0);
		return;
	}

	if (!waiting_for_response) {
		if (fi->state != MGWEP_ST_IN_USE)
			mgwep_fsm_state_chg(MGWEP_ST_IN_USE);
		return;
	}

}

static void mgwep_fsm_wait_mgw_response_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	int count = 0;
	int i;
	struct mgw_endpoint *mgwep = mgwep_fi_mgwep(fi);

	for (i = 0; i < ARRAY_SIZE(mgwep->ci); i++) {
		count += send_verb(&mgwep->ci[i]);
	}

	LOG_MGWEP(mgwep, LOGL_DEBUG, "Sent messages: %d\n", count);
	mgwep_fsm_check_state_chg_after_response(fi);

}

static void mgwep_fsm_handle_ci_events(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct mgwep_ci *ci;
	struct mgw_endpoint *mgwep = mgwep_fi_mgwep(fi);
	ci = mgwep_ci_for_event(mgwep, event);
	if (ci) {
		if (event == CI_EV_SUCCESS(ci))
			on_success(ci, data);
		else
			on_failure(ci);
	}
}

static void mgwep_fsm_in_use_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	int pending_not_sent;
	struct mgw_endpoint *mgwep = mgwep_fi_mgwep(fi);

	mgwep_count(mgwep, NULL, &pending_not_sent, NULL);
	if (pending_not_sent)
		mgwep_fsm_state_chg(MGWEP_ST_WAIT_MGW_RESPONSE);
}

#define S(x)	(1 << (x))

static const struct osmo_fsm_state mgwep_fsm_states[] = {
	[MGWEP_ST_UNUSED] = {
		.name = "UNUSED",
		.in_event_mask = 0,
		.out_state_mask = 0
			| S(MGWEP_ST_WAIT_MGW_RESPONSE)
			,
	},
	[MGWEP_ST_WAIT_MGW_RESPONSE] = {
		.name = "WAIT_MGW_RESPONSE",
		.onenter = mgwep_fsm_wait_mgw_response_onenter,
		.action = mgwep_fsm_handle_ci_events,
		.in_event_mask = 0xffffffff,
		.out_state_mask = 0
			| S(MGWEP_ST_IN_USE)
			,
	},
	[MGWEP_ST_IN_USE] = {
		.name = "IN_USE",
		.onenter = mgwep_fsm_in_use_onenter,
		.action = mgwep_fsm_handle_ci_events,
		.in_event_mask = 0xffffffff, /* mgcp_client_fsm may send parent term anytime */
		.out_state_mask = 0
			| S(MGWEP_ST_WAIT_MGW_RESPONSE)
			,
	},
};

static int mgwep_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	int i;
	struct mgw_endpoint *mgwep = mgwep_fi_mgwep(fi);

	switch (fi->T) {
	default:
		for (i = 0; i < ARRAY_SIZE(mgwep->ci); i++) {
			struct mgwep_ci *ci = &mgwep->ci[i];
			if (!ci->occupied)
				continue;
			if (!(ci->pending && ci->sent))
				continue;
			on_failure(ci);
		}
		return 0;
	}

	return 0;
}

static struct osmo_fsm mgwep_fsm = {
	.name = "mgw-endpoint",
	.states = mgwep_fsm_states,
	.num_states = ARRAY_SIZE(mgwep_fsm_states),
	.log_subsys = DRSL,
	.event_names = mgwep_fsm_event_names,
	.timer_cb = mgwep_fsm_timer_cb,
	/* The FSM termination will automatically trigger any mgcp_client_fsm instances to DLCX. */
};

/* Depending on the channel mode and rate, return the codec type that is signalled towards the MGW. */
enum mgcp_codecs chan_mode_to_mgcp_codec(enum gsm48_chan_mode chan_mode, bool full_rate)
{
	switch (chan_mode) {
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

int chan_mode_to_mgcp_bss_pt(enum mgcp_codecs codec)
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
	enum mgcp_codecs codec = chan_mode_to_mgcp_codec(lchan->tch_mode,
							 lchan->type == GSM_LCHAN_TCH_H? false : true);
	int custom_pt;

	if (codec < 0) {
		LOG_LCHAN(lchan, LOGL_ERROR,
			  "Unable to determine MGCP codec type for %s in chan-mode %s\n",
			  gsm_lchant_name(lchan->type), gsm48_chan_mode_name(lchan->tch_mode));
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
		 * we may support BTSs that are using bandwith-efficient
		 * format. In this case we will have to add functionality
		 * that distinguishes by the BTS model which mode to use. */
		verb_info->param.amr_octet_aligned = true;
	}
	else if (!bss_side && verb_info->codecs[0] == CODEC_AMR_8000_1) {
		verb_info->param.amr_octet_aligned = lchan->conn->sccp.msc->amr_octet_aligned;
	}
}
