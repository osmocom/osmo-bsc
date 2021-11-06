/* osmo-bsc API to manage lchans, logical channels in GSM cells. */
#pragma once

#define LOG_LCHAN_RTP(lchan, level, fmt, args...) do { \
	if (lchan->fi_rtp) \
		LOGPFSML(lchan->fi_rtp, level, fmt, ## args); \
	else \
		LOGP(DLMGCP, level, "%s (not initialized) " fmt, gsm_lchan_name(lchan), \
		     ## args); \
	} while (0)

struct gsm_lchan;
struct mgcp_conn_peer;

enum lchan_rtp_fsm_state {
	LCHAN_RTP_ST_WAIT_MGW_ENDPOINT_AVAILABLE,
	LCHAN_RTP_ST_WAIT_LCHAN_READY,
	LCHAN_RTP_ST_WAIT_IPACC_CRCX_ACK,
	LCHAN_RTP_ST_WAIT_IPACC_MDCX_ACK,
	LCHAN_RTP_ST_WAIT_READY_TO_SWITCH_RTP,
	LCHAN_RTP_ST_WAIT_MGW_ENDPOINT_CONFIGURED,
	LCHAN_RTP_ST_READY,
	LCHAN_RTP_ST_ROLLBACK,
	LCHAN_RTP_ST_ESTABLISHED,
};

enum lchan_rtp_fsm_event {
	LCHAN_RTP_EV_LCHAN_READY,
	LCHAN_RTP_EV_READY_TO_SWITCH_RTP,
	LCHAN_RTP_EV_MGW_ENDPOINT_AVAILABLE,
	LCHAN_RTP_EV_MGW_ENDPOINT_ERROR,
	LCHAN_RTP_EV_IPACC_CRCX_ACK,
	LCHAN_RTP_EV_IPACC_CRCX_NACK,
	LCHAN_RTP_EV_IPACC_MDCX_ACK,
	LCHAN_RTP_EV_IPACC_MDCX_NACK,
	LCHAN_RTP_EV_READY_TO_SWITCH,
	LCHAN_RTP_EV_MGW_ENDPOINT_CONFIGURED,
	LCHAN_RTP_EV_ROLLBACK, /*< Give the RTP back to the old lchan, if any */
	LCHAN_RTP_EV_ESTABLISHED, /*< All done, forget about the old lchan, if any */
	LCHAN_RTP_EV_RELEASE,
};

void lchan_rtp_fsm_start(struct gsm_lchan *lchan);
struct osmo_mgcpc_ep_ci *lchan_use_mgw_endpoint_ci_bts(struct gsm_lchan *lchan);
bool lchan_rtp_established(struct gsm_lchan *lchan);
void lchan_forget_mgw_endpoint(struct gsm_lchan *lchan);

void mgcp_pick_codec(struct mgcp_conn_peer *verb_info, const struct gsm_lchan *lchan, bool bss_side);
