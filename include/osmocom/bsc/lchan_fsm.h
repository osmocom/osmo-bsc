/* osmo-bsc API to manage lchans, logical channels in GSM cells. */
#pragma once

#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/debug.h>

/* This macro automatically includes a final \n, if omitted. */
#define LOG_LCHAN(lchan, level, fmt, args...) do { \
	if (lchan->fi) \
		LOGPFSML(lchan->fi, level, "(type=%s) " fmt, gsm_lchant_name(lchan->type), ## args); \
	else \
		LOGP(DRSL, level, "%s (not initialized) " fmt, gsm_lchan_name(lchan), ## args); \
	} while(0)

enum lchan_fsm_state {
	LCHAN_ST_UNUSED,
	LCHAN_ST_CBCH, /*< Blocked by CBCH channel combination, not usable as SDCCH. */
	LCHAN_ST_WAIT_TS_READY,
	LCHAN_ST_WAIT_ACTIV_ACK, /*< After RSL Chan Act Ack, lchan is active but RTP not configured. */
	LCHAN_ST_WAIT_RLL_RTP_ESTABLISH,
	LCHAN_ST_ESTABLISHED, /*< Active and RTP is fully configured. */
	LCHAN_ST_WAIT_RLL_RTP_RELEASED,
	LCHAN_ST_WAIT_BEFORE_RF_RELEASE,
	LCHAN_ST_WAIT_RF_RELEASE_ACK,
	LCHAN_ST_WAIT_AFTER_ERROR,
	LCHAN_ST_BORKEN,
};

enum lchan_fsm_event {
	LCHAN_EV_ACTIVATE,
	LCHAN_EV_TS_READY,
	LCHAN_EV_TS_ERROR,
	LCHAN_EV_RSL_CHAN_ACTIV_ACK,
	LCHAN_EV_RSL_CHAN_ACTIV_NACK,
	LCHAN_EV_RLL_ESTABLISH_IND,
	LCHAN_EV_RTP_READY,
	LCHAN_EV_RTP_ERROR,
	LCHAN_EV_RTP_RELEASED,
	LCHAN_EV_RLL_REL_IND,
	LCHAN_EV_RLL_REL_CONF,
	LCHAN_EV_RSL_RF_CHAN_REL_ACK,
	LCHAN_EV_RLL_ERR_IND,

	/* FIXME: not yet implemented: Chan Mode Modify, see assignment_fsm_start(). */
	LCHAN_EV_CHAN_MODE_MODIF_ACK,
	LCHAN_EV_CHAN_MODE_MODIF_ERROR,
};

void lchan_fsm_init();

void lchan_fsm_alloc(struct gsm_lchan *lchan);
void lchan_release(struct gsm_lchan *lchan, bool do_rr_release,
		   bool err, enum gsm48_rr_cause cause_rr);

void lchan_activate(struct gsm_lchan *lchan, struct lchan_activate_info *info);
void lchan_ready_to_switch_rtp(struct gsm_lchan *lchan);

static inline const char *lchan_state_name(struct gsm_lchan *lchan)
{
	return lchan->fi ? osmo_fsm_inst_state_name(lchan->fi) : "NULL";
}

static inline bool lchan_state_is(struct gsm_lchan *lchan, uint32_t state)
{
	return (!lchan->fi && state == LCHAN_ST_UNUSED)
		|| (lchan->fi && lchan->fi->state == state);
}

bool lchan_may_receive_data(struct gsm_lchan *lchan);

void lchan_forget_conn(struct gsm_lchan *lchan);

void lchan_set_last_error(struct gsm_lchan *lchan, const char *fmt, ...);
