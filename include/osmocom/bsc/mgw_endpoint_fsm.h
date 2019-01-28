/* osmo-bsc API to manage all sides of an MGW endpoint */
#pragma once

#include <osmocom/mgcp_client/mgcp_client_fsm.h>

#include <osmocom/bsc/debug.h>

/* This macro automatically includes a final \n, if omitted. */
#define LOG_MGWEP(mgwep, level, fmt, args...) do { \
	LOGPFSML(mgwep->fi, level, "(%s) " fmt, \
		 mgw_endpoint_name(mgwep), ## args); \
	} while(0)

enum mgwep_fsm_state {
	MGWEP_ST_UNUSED,
	MGWEP_ST_WAIT_MGW_RESPONSE,
	MGWEP_ST_IN_USE,
};

enum mgwep_fsm_event {
	_MGWEP_EV_LAST,
	/* and MGW response events are allocated dynamically */
};

struct mgw_endpoint;
struct mgwep_ci;
struct osmo_tdef;

void mgw_endpoint_fsm_init(struct osmo_tdef *T_defs);

struct mgw_endpoint *mgw_endpoint_alloc(struct osmo_fsm_inst *parent, uint32_t parent_term_event,
					struct mgcp_client *mgcp_client,
					const char *fsm_id,
					const char *endpoint_str_fmt, ...);

struct mgwep_ci *mgw_endpoint_ci_add(struct mgw_endpoint *mgwep,
				     const char *label_fmt, ...);
const struct mgcp_conn_peer *mgwep_ci_get_rtp_info(const struct mgwep_ci *ci);
bool mgwep_ci_get_crcx_info_to_sockaddr(const struct mgwep_ci *ci, struct sockaddr_storage *dest);

void mgw_endpoint_ci_request(struct mgwep_ci *ci,
			     enum mgcp_verb verb, const struct mgcp_conn_peer *verb_info,
			     struct osmo_fsm_inst *notify,
			     uint32_t event_success, uint32_t event_failure,
			     void *notify_data);

static inline void mgw_endpoint_ci_dlcx(struct mgwep_ci *ci)
{
	mgw_endpoint_ci_request(ci, MGCP_VERB_DLCX, NULL, NULL, 0, 0, NULL);
}

void mgw_endpoint_clear(struct mgw_endpoint *mgwep);

const char *mgw_endpoint_name(const struct mgw_endpoint *mgwep);
const char *mgwep_ci_name(const struct mgwep_ci *ci);
const char *mgcp_conn_peer_name(const struct mgcp_conn_peer *info);

enum mgcp_codecs chan_mode_to_mgcp_codec(enum gsm48_chan_mode chan_mode, bool full_rate);
void mgcp_pick_codec(struct mgcp_conn_peer *verb_info, const struct gsm_lchan *lchan, bool bss_side);
