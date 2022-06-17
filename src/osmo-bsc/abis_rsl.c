/* GSM Radio Signalling Link messages on the A-bis interface
 * 3GPP TS 08.58 version 8.6.0 Release 1999 / ETSI TS 100 596 V8.6.0 */

/* (C) 2008-2019 by Harald Welte <laforge@gnumonks.org>
 * (C) 2012 by Holger Hans Peter Freyther
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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/gsm_04_08_rr.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/bsc/abis_rsl.h>
#include <osmocom/bsc/bsc_rll.h>
#include <osmocom/bsc/debug.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gsm/protocol/gsm_08_58.h>
#include <osmocom/bsc/paging.h>
#include <osmocom/bsc/signal.h>
#include <osmocom/bsc/meas_rep.h>
#include <osmocom/abis/e1_input.h>
#include <osmocom/gsm/rsl.h>
#include <osmocom/core/talloc.h>
#include <osmocom/bsc/pcu_if.h>
#include <osmocom/bsc/gsm_08_08.h>
#include <osmocom/netif/rtp.h>
#include <osmocom/core/tdef.h>
#include <osmocom/bsc/bsc_subscr_conn_fsm.h>
#include <osmocom/bsc/timeslot_fsm.h>
#include <osmocom/bsc/lchan_select.h>
#include <osmocom/bsc/lchan_fsm.h>
#include <osmocom/bsc/lchan_rtp_fsm.h>
#include <osmocom/bsc/handover_fsm.h>
#include <osmocom/bsc/smscb.h>
#include <osmocom/bsc/bts.h>
#include <osmocom/bsc/power_control.h>
#include <osmocom/bsc/chan_counts.h>

static void send_lchan_signal(int sig_no, struct gsm_lchan *lchan,
			      struct gsm_meas_rep *resp)
{
	struct lchan_signal_data sig;
	sig.lchan = lchan;
	sig.mr = resp;
	osmo_signal_dispatch(SS_LCHAN, sig_no, &sig);
}

static void count_codecs(struct gsm_bts *bts, struct gsm_lchan *lchan)
{
	OSMO_ASSERT(bts);

	if (lchan->type == GSM_LCHAN_TCH_H) {
		switch (gsm48_chan_mode_to_non_vamos(lchan->current_ch_mode_rate.chan_mode)) {
		case GSM48_CMODE_SPEECH_AMR:
			rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_CODEC_AMR_H));
			break;
		case GSM48_CMODE_SPEECH_V1:
			rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_CODEC_V1_HR));
			break;
		default:
			break;
		}
	} else if (lchan->type == GSM_LCHAN_TCH_F) {
		switch (gsm48_chan_mode_to_non_vamos(lchan->current_ch_mode_rate.chan_mode)) {
		case GSM48_CMODE_SPEECH_AMR:
			rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_CODEC_AMR_F));
			break;
		case GSM48_CMODE_SPEECH_V1:
			rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_CODEC_V1_FR));
			break;
		case GSM48_CMODE_SPEECH_EFR:
			rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_CODEC_EFR));
			break;
		default:
			break;
		}
	}
}

static uint8_t mdisc_by_msgtype(uint8_t msg_type)
{
	/* mask off the transparent bit ? */
	msg_type &= 0xfe;

	if ((msg_type & 0xf0) == 0x00)
		return ABIS_RSL_MDISC_RLL;
	if ((msg_type & 0xf0) == 0x10) {
		if (msg_type >= 0x19 && msg_type <= 0x22)
			return ABIS_RSL_MDISC_TRX;
		else
			return ABIS_RSL_MDISC_COM_CHAN;
	}
	if ((msg_type & 0xe0) == 0x20)
		return ABIS_RSL_MDISC_DED_CHAN;

	return ABIS_RSL_MDISC_LOC;
}

static inline void init_dchan_hdr(struct abis_rsl_dchan_hdr *dh,
				  uint8_t msg_type)
{
	dh->c.msg_discr = mdisc_by_msgtype(msg_type);
	dh->c.msg_type = msg_type;
	dh->ie_chan = RSL_IE_CHAN_NR;
}

/* call rsl_lchan_lookup and set the log context */
static struct gsm_lchan *lchan_lookup(struct gsm_bts_trx *trx, uint8_t chan_nr,
				      const char *log_name)
{
	int rc;
	struct gsm_lchan *lchan = rsl_lchan_lookup(trx, chan_nr, &rc);

	if (!lchan) {
		LOGP(DRSL, LOGL_ERROR, "%sunknown chan_nr=0x%02x\n",
		     log_name, chan_nr);
		return NULL;
	}

	if (rc < 0)
		LOGP(DRSL, LOGL_ERROR, "%s %smismatching chan_nr=0x%02x\n",
		     gsm_ts_and_pchan_name(lchan->ts), log_name, chan_nr);

	return lchan;
}

static void pad_macblock(uint8_t *out, const uint8_t *in, int len)
{
	memcpy(out, in, len);

	if (len < GSM_MACBLOCK_LEN)
		memset(out+len, 0x2b, GSM_MACBLOCK_LEN - len);
}

/* Chapter 9.3.7: Encryption Information
 * Return negative on error, number of bytes written to 'out' on success.
 * 'out' must provide room for 17 bytes. */
static int build_encr_info(uint8_t *out, struct gsm_lchan *lchan)
{
	out[0] = ALG_A5_NR_TO_RSL(lchan->encr.alg_a5_n);
	switch (out[0]) {
	case GSM0808_ALG_ID_A5_1:
	case GSM0808_ALG_ID_A5_2:
	case GSM0808_ALG_ID_A5_3:
		if (!lchan->encr.key_len) {
			LOG_LCHAN(lchan, LOGL_ERROR, "A5/%d encryption chosen, but missing Kc\n", lchan->encr.alg_a5_n);
			return -EINVAL;
		}
		/* fall through */
	case GSM0808_ALG_ID_A5_0:
		/* When A5/0 is chosen, no encryption is active, so technically, no key is needed. However, 3GPP TS
		 * 48.058 9.3.7 Encryption Information stays quite silent about presence or absence of a key for A5/0.
		 * The only thing specified is how to indicate the length of the key; the possibility that the key may
		 * be zero length is not explicitly mentioned. So it seems that we should always send the key along,
		 * even for A5/0. Currently our ttcn3 test suite does expect the key to be present also for A5/0, see
		 * f_cipher_mode() in bsc/MSC_ConnectionHandler.ttcn. */
		if (lchan->encr.key_len)
			memcpy(&out[1], lchan->encr.key, lchan->encr.key_len);
		return 1 + lchan->encr.key_len;

	case GSM0808_ALG_ID_A5_4:
		if (!lchan->encr.kc128_present) {
			LOG_LCHAN(lchan, LOGL_ERROR, "A5/4 encryption chosen, but missing Kc128\n");
			return -EINVAL;
		}
		memcpy(&out[1], lchan->encr.kc128, sizeof(lchan->encr.kc128));
		return 1 + sizeof(lchan->encr.kc128);

	default:
		LOG_LCHAN(lchan, LOGL_ERROR, "A5/%d encryption not supported\n", lchan->encr.alg_a5_n);
		return -EINVAL;
	}
}

/* If the TLV contain an RSL Cause IE, return pointer to the cause value. If there is no Cause IE, return
 * NULL. Implementation choice: presence of a Cause IE cannot be indicated by a zero cause, because that
 * would mean RSL_ERR_RADIO_IF_FAIL; a pointer can return NULL or point to a cause value. */
static const uint8_t *rsl_cause(struct tlv_parsed *tp)
{
	if (TLVP_PRESENT(tp, RSL_IE_CAUSE))
		return (const uint8_t *)TLVP_VAL(tp, RSL_IE_CAUSE);
	return NULL;
}

/* If the TLV contain an RSL Cause IE, return the RSL cause name; otherwise return "". */
static const char *rsl_cause_name(struct tlv_parsed *tp)
{
	static char buf[128];
	if (TLVP_PRESENT(tp, RSL_IE_CAUSE)) {
		const uint8_t *cause = TLVP_VAL(tp, RSL_IE_CAUSE);
		snprintf(buf, sizeof(buf), " (cause=%s [ %s])",
			 rsl_err_name(*cause),
			 osmo_hexdump(cause, TLVP_LEN(tp, RSL_IE_CAUSE)));
		return buf;
	} else
		return "";
}

static void add_power_control_params(struct msgb *msg, enum abis_rsl_ie iei,
				     const struct gsm_lchan *lchan)
{
	const struct gsm_bts *bts = lchan->ts->trx->bts;
	const struct gsm_power_ctrl_params *cp;

	/* Since {MS,BS}_POWER_PARAM IE content is operator dependent, it's not
	 * known how different BTS models will interpret an empty IE, so let's
	 * better skip sending it unless we know for sure what each expects. */
	if (bts->model->power_ctrl_enc_rsl_params == NULL)
		return;

	if (iei == RSL_IE_MS_POWER_PARAM)
		cp = &bts->ms_power_ctrl;
	else
		cp = &bts->bs_power_ctrl;

	/* These parameters are only valid for dynamic mode */
	if (cp->mode != GSM_PWR_CTRL_MODE_DYN_BTS)
		return;

	/* No dynamic BS power control if the maximum is 0 dB */
	if (cp->dir == GSM_PWR_CTRL_DIR_DL) {
		if (lchan->bs_power_db == 0)
			return;
	}

	/* Put tag first, length will be updated later */
	uint8_t *ie_len = msgb_tl_put(msg, iei);
	uint8_t msg_len = msgb_length(msg);

	if (bts->model->power_ctrl_enc_rsl_params(msg, cp) != 0) {
		LOGP(DRSL, LOGL_ERROR, "Failed to encode MS/BS Power Control "
		     "parameters, omitting this IE (tag 0x%02x)\n", iei);
		msgb_get(msg, msg_len - 2);
		return;
	}

	/* Update length part of the containing IE */
	*ie_len = msgb_length(msg) - msg_len;
}

/* Send a BCCH_INFO message as per Chapter 8.5.1 */
/* Allow test to overwrite it */
__attribute__((weak)) int rsl_bcch_info(const struct gsm_bts_trx *trx, enum osmo_sysinfo_type si_type,
					const uint8_t *data, int len)
{
	struct abis_rsl_dchan_hdr *dh;
	const struct gsm_bts *bts = trx->bts;
	struct msgb *msg = rsl_msgb_alloc();
	uint8_t type = osmo_sitype2rsl(si_type);

	if (bts->c0 != trx)
		LOGP(DRR, LOGL_ERROR, "Attempting to set BCCH SI%s on wrong BTS%u/TRX%u\n",
		     get_value_string(osmo_sitype_strs, si_type), bts->nr, trx->nr);

	dh = (struct abis_rsl_dchan_hdr *) msgb_put(msg, sizeof*dh);
	init_dchan_hdr(dh, RSL_MT_BCCH_INFO);
	dh->chan_nr = RSL_CHAN_BCCH;

	if (trx->bts->type == GSM_BTS_TYPE_RBS2000
	    && type == RSL_SYSTEM_INFO_13) {
		/* Ericsson proprietary encoding of SI13 */
		msgb_tv_put(msg, RSL_IE_SYSINFO_TYPE, RSL_ERIC_SYSTEM_INFO_13);
		if (data)
			msgb_tlv_put(msg, RSL_IE_FULL_BCCH_INFO, len, data);
		msgb_tv_put(msg, RSL_IE_ERIC_BCCH_MAPPING, 0x00);
	} else {
		/* Normal encoding */
		msgb_tv_put(msg, RSL_IE_SYSINFO_TYPE, type);
		if (data)
			msgb_tlv_put(msg, RSL_IE_FULL_BCCH_INFO, len, data);
	}

	msg->dst = trx->rsl_link_primary;

	return abis_rsl_sendmsg(msg);
}

/* Allow test to overwrite it */
__attribute__((weak)) int rsl_sacch_filling(struct gsm_bts_trx *trx, uint8_t type,
		      const uint8_t *data, int len)
{
	struct abis_rsl_common_hdr *ch;
	struct msgb *msg = rsl_msgb_alloc();

	ch = (struct abis_rsl_common_hdr *) msgb_put(msg, sizeof(*ch));
	ch->msg_discr = ABIS_RSL_MDISC_TRX;
	ch->msg_type = RSL_MT_SACCH_FILL;

	msgb_tv_put(msg, RSL_IE_SYSINFO_TYPE, type);
	if (data)
		msgb_tl16v_put(msg, RSL_IE_L3_INFO, len, data);

	msg->dst = trx->rsl_link_primary;

	return abis_rsl_sendmsg(msg);
}

int rsl_sacch_info_modify(struct gsm_lchan *lchan, uint8_t type,
			  const uint8_t *data, int len)
{
	struct abis_rsl_dchan_hdr *dh;
	struct msgb *msg;
	int chan_nr = gsm_lchan2chan_nr(lchan, true);
	if (chan_nr < 0)
		return chan_nr;

	msg = rsl_msgb_alloc();

	dh = (struct abis_rsl_dchan_hdr *) msgb_put(msg, sizeof(*dh));
	init_dchan_hdr(dh, RSL_MT_SACCH_INFO_MODIFY);
	dh->chan_nr = chan_nr;

	msgb_tv_put(msg, RSL_IE_SYSINFO_TYPE, type);
	if (data)
		msgb_tl16v_put(msg, RSL_IE_L3_INFO, len, data);

	msg->dst = rsl_chan_link(lchan);

	return abis_rsl_sendmsg(msg);
}

int rsl_chan_bs_power_ctrl(struct gsm_lchan *lchan, unsigned int fpc, int db)
{
	struct abis_rsl_dchan_hdr *dh;
	struct msgb *msg;
	uint8_t bs_power_enc;
	int chan_nr = gsm_lchan2chan_nr(lchan, true);
	if (chan_nr < 0)
		return chan_nr;

	db = abs(db);
	if (db > 30)
		return -EINVAL;

	msg = rsl_msgb_alloc();

	bs_power_enc = db / 2;
	if (fpc)
		bs_power_enc |= 0x10;

	dh = (struct abis_rsl_dchan_hdr *) msgb_put(msg, sizeof(*dh));
	init_dchan_hdr(dh, RSL_MT_BS_POWER_CONTROL);
	dh->chan_nr = chan_nr;

	msgb_tv_put(msg, RSL_IE_BS_POWER, bs_power_enc);

	/* BS Power Control Parameters (if supported by BTS model) */
	add_power_control_params(msg, RSL_IE_BS_POWER_PARAM, lchan);

	msg->dst = rsl_chan_link(lchan);

	return abis_rsl_sendmsg(msg);
}

int rsl_chan_ms_power_ctrl(struct gsm_lchan *lchan)
{
	struct abis_rsl_dchan_hdr *dh;
	struct msgb *msg;
	int chan_nr = gsm_lchan2chan_nr(lchan, true);
	if (chan_nr < 0)
		return chan_nr;

	LOG_LCHAN(lchan, LOGL_DEBUG, "Tx MS POWER CONTROL (ms_power_lvl=%" PRIu8 ")\n",
		  lchan->ms_power);

	msg = rsl_msgb_alloc();

	dh = (struct abis_rsl_dchan_hdr *) msgb_put(msg, sizeof(*dh));
	init_dchan_hdr(dh, RSL_MT_MS_POWER_CONTROL);
	dh->chan_nr = chan_nr;

	msgb_tv_put(msg, RSL_IE_MS_POWER, lchan->ms_power);

	/* MS Power Control Parameters (if supported by BTS model) */
	add_power_control_params(msg, RSL_IE_MS_POWER_PARAM, lchan);

	msg->dst = rsl_chan_link(lchan);

	return abis_rsl_sendmsg(msg);
}

static int channel_mode_from_lchan(struct rsl_ie_chan_mode *cm,
				   struct gsm_lchan *lchan,
				   const struct channel_mode_and_rate *ch_mode_rate,
				   bool vamos)
{
	int rc;
	memset(cm, 0, sizeof(*cm));

	/* FIXME: what to do with data calls ? */
	cm->dtx_dtu = 0;
	if (lchan->ts->trx->bts->dtxu != GSM48_DTX_SHALL_NOT_BE_USED)
		cm->dtx_dtu |= RSL_CMOD_DTXu;
	if (lchan->ts->trx->bts->dtxd)
		cm->dtx_dtu |= RSL_CMOD_DTXd;

	/* set TCH Speech/Data */
	rc = chan_mode_to_rsl_cmod_spd(ch_mode_rate->chan_mode);
	if (rc < 0) {
		LOGP(DRSL, LOGL_ERROR, "unsupported: chan_mode = 0x%02x\n", ch_mode_rate->chan_mode);
		return rc;
	}
	cm->spd_ind = rc;

	switch (lchan->type) {
	case GSM_LCHAN_SDCCH:
		cm->chan_rt = RSL_CMOD_CRT_SDCCH;
		break;
	case GSM_LCHAN_TCH_F:
		cm->chan_rt = vamos ? RSL_CMOD_CRT_OSMO_TCH_VAMOS_Bm : RSL_CMOD_CRT_TCH_Bm;
		break;
	case GSM_LCHAN_TCH_H:
		cm->chan_rt = vamos ? RSL_CMOD_CRT_OSMO_TCH_VAMOS_Lm : RSL_CMOD_CRT_TCH_Lm;
		break;
	case GSM_LCHAN_NONE:
	case GSM_LCHAN_UNKNOWN:
	default:
		LOGP(DRSL, LOGL_ERROR,
		     "unsupported activation lchan->type %u %s\n",
		     lchan->type, gsm_lchant_name(lchan->type));
		return -EINVAL;
	}

	switch (gsm48_chan_mode_to_non_vamos(ch_mode_rate->chan_mode)) {
	case GSM48_CMODE_SIGN:
		cm->chan_rate = 0;
		break;
	case GSM48_CMODE_SPEECH_V1:
		cm->chan_rate = RSL_CMOD_SP_GSM1;
		break;
	case GSM48_CMODE_SPEECH_EFR:
		cm->chan_rate = RSL_CMOD_SP_GSM2;
		break;
	case GSM48_CMODE_SPEECH_AMR:
		cm->chan_rate = RSL_CMOD_SP_GSM3;
		break;
	case GSM48_CMODE_DATA_14k5:
	case GSM48_CMODE_DATA_12k0:
	case GSM48_CMODE_DATA_6k0:
		switch (ch_mode_rate->csd_mode) {
		case LCHAN_CSD_M_NT:
			/* non-transparent CSD with RLP */
			switch (ch_mode_rate->chan_mode) {
			case GSM48_CMODE_DATA_14k5:
				cm->chan_rate = RSL_CMOD_SP_NT_14k5;
				break;
			case GSM48_CMODE_DATA_12k0:
				cm->chan_rate = RSL_CMOD_SP_NT_12k0;
				break;
			case GSM48_CMODE_DATA_6k0:
				cm->chan_rate = RSL_CMOD_SP_NT_6k0;
				break;
			default:
				LOGP(DRSL, LOGL_ERROR,
				     "unsupported lchan->tch_mode %u\n",
				     ch_mode_rate->chan_mode);
				return -EINVAL;
			}
			break;
			/* transparent data services below */
		case LCHAN_CSD_M_T_1200_75:
			cm->chan_rate = RSL_CMOD_CSD_T_1200_75;
			break;
		case LCHAN_CSD_M_T_600:
			cm->chan_rate = RSL_CMOD_CSD_T_600;
			break;
		case LCHAN_CSD_M_T_1200:
			cm->chan_rate = RSL_CMOD_CSD_T_1200;
			break;
		case LCHAN_CSD_M_T_2400:
			cm->chan_rate = RSL_CMOD_CSD_T_2400;
			break;
		case LCHAN_CSD_M_T_9600:
			cm->chan_rate = RSL_CMOD_CSD_T_9600;
			break;
		case LCHAN_CSD_M_T_14400:
			cm->chan_rate = RSL_CMOD_CSD_T_14400;
			break;
		case LCHAN_CSD_M_T_29000:
			cm->chan_rate = RSL_CMOD_CSD_T_29000;
			break;
		case LCHAN_CSD_M_T_32000:
			cm->chan_rate = RSL_CMOD_CSD_T_32000;
			break;
		default:
			LOGP(DRSL, LOGL_ERROR, "unsupported csd_mode %u\n", ch_mode_rate->csd_mode);
			return -EINVAL;
		}
		break;
	default:
		LOGP(DRSL, LOGL_ERROR, "unsupported channel mode %u\n", ch_mode_rate->chan_mode);
		return -EINVAL;
	}

	return 0;
}

static int put_mr_config_for_bts(struct msgb *msg, const struct gsm48_multi_rate_conf *mr_conf_filtered,
				 const struct amr_multirate_conf *mr_modes)
{
	msgb_put_u8(msg, RSL_IE_MR_CONFIG);
	return gsm48_multirate_config(msg, mr_conf_filtered, mr_modes->bts_mode, mr_modes->num_modes);
}

/* indicate FACCH/SACCH Repetition to be performed by BTS,
 * see also: 3GPP TS 44.006, section 10 and 11 */
static void put_rep_acch_cap_ie(const struct gsm_lchan *lchan,
				struct msgb *msg)
{
	struct abis_rsl_osmo_rep_acch_cap *cap;
	const struct gsm_bts *bts = lchan->ts->trx->bts;

	/* The RSL_IE_OSMO_REP_ACCH_CAP IE is a proprietary IE, that can only
	 * be used with osmo-bts type BTSs */
	if (!(bts->model->type == GSM_BTS_TYPE_OSMOBTS
	      && osmo_bts_has_feature(&bts->features, BTS_FEAT_ACCH_REP)))
		return;

	cap = (struct abis_rsl_osmo_rep_acch_cap*) msg->tail;
	msgb_tlv_put(msg, RSL_IE_OSMO_REP_ACCH_CAP, sizeof(*cap),
		     (uint8_t *)&bts->rep_acch_cap);

	if (!(lchan->conn && lchan->conn->cm3_valid
	      && lchan->conn->cm3.repeated_acch_capability)) {
		/* MS supports only FACCH repetition for command frames, so
		 * we mask out all other features, even when they are enabled
		 * on this BTS. */
		cap->dl_facch_all = 0;
		cap->dl_sacch = 0;
		cap->ul_sacch = 0;
	}
}

/* indicate Temporary overpower of SACCH and FACCH channels */
static void put_top_acch_cap_ie(const struct gsm_lchan *lchan,
				const struct rsl_ie_chan_mode *cm,
				struct msgb *msg)
{
	const struct gsm_bts *bts = lchan->ts->trx->bts;

	/* The BTS_FEAT_ACCH_TEMP_OVP IE is a proprietary IE, that can only be used with osmo-bts type BTSs */
	if (!(bts->model->type == GSM_BTS_TYPE_OSMOBTS && osmo_bts_has_feature(&bts->features, BTS_FEAT_ACCH_TEMP_OVP)))
		return;

	/* Check if TOP is permitted for the given Channel Mode */
	switch (bts->top_acch_chan_mode) {
	case TOP_ACCH_CHAN_MODE_SPEECH_V3:
		if (cm->spd_ind != RSL_CMOD_SPD_SPEECH)
			return;
		if (cm->chan_rate != RSL_CMOD_SP_GSM3)
			return;
		break;
	case TOP_ACCH_CHAN_MODE_ANY:
		break;
	}

	msgb_tlv_put(msg, RSL_IE_OSMO_TEMP_OVP_ACCH_CAP,
		     sizeof(bts->top_acch_cap),
		     (void *)&bts->top_acch_cap);
}

/* Write RSL_IE_OSMO_TRAINING_SEQUENCE to msgb. The tsc_set argument's range is 1-4, tsc argument range is 0-7. */
static void put_osmo_training_sequence_ie(struct msgb *msg, uint8_t tsc_set, uint8_t tsc)
{
	uint8_t *len = msgb_tl_put(msg, RSL_IE_OSMO_TRAINING_SEQUENCE);
	*len = 2;
	/* Convert from spec conforming "human readable" TSC Set 1-4 to 0-3 on the wire */
	msgb_put_u8(msg, tsc_set - 1);
	/* TSC is 0-7 both on the wire and in spec descriptions */
	msgb_put_u8(msg, tsc);
}

/* Chapter 8.4.1 */
int rsl_tx_chan_activ(struct gsm_lchan *lchan, uint8_t act_type, uint8_t ho_ref)
{
	struct gsm_bts_trx *trx = lchan->ts->trx;
	struct gsm_bts *bts = trx->bts;
	struct abis_rsl_dchan_hdr *dh;
	struct msgb *msg;
	int rc;
	uint8_t *len;

	struct rsl_ie_chan_mode cm;
	struct gsm48_chan_desc cd;
	int chan_nr = gsm_lchan2chan_nr(lchan, true);
	if (chan_nr < 0)
		return chan_nr;

	DEBUGP(DRSL, "%s Tx RSL Channel Activate with act_type=%s\n",
	       gsm_ts_and_pchan_name(lchan->ts),
	       rsl_act_type_name(act_type));

	/* PDCH activation is a job for rsl_tx_dyn_ts_pdch_act_deact(); */
	OSMO_ASSERT(act_type != RSL_ACT_OSMO_PDCH);

	rc = channel_mode_from_lchan(&cm, lchan, &lchan->activate.ch_mode_rate, lchan->activate.info.vamos);
	if (rc < 0) {
		LOGP(DRSL, LOGL_ERROR,
		     "%s Cannot find channel mode from lchan type\n",
		     gsm_ts_and_pchan_name(lchan->ts));
		return rc;
	}

	memset(&cd, 0, sizeof(cd));
	rc = gsm48_lchan2chan_desc(&cd, lchan, lchan->activate.tsc, true);
	if (rc) {
		LOG_LCHAN(lchan, LOGL_ERROR, "Error encoding Channel Number\n");
		return rc;
	}

	msg = rsl_msgb_alloc();
	dh = (struct abis_rsl_dchan_hdr *) msgb_put(msg, sizeof(*dh));
	init_dchan_hdr(dh, RSL_MT_CHAN_ACTIV);

	dh->chan_nr = chan_nr;

	msgb_tv_put(msg, RSL_IE_ACT_TYPE, act_type);
	msgb_tlv_put(msg, RSL_IE_CHAN_MODE, sizeof(cm),
		     (uint8_t *) &cm);

	/*
	 * The Channel Identification is needed for Phase1 phones
	 * and it contains the GSM48 Channel Description and the
	 * Mobile Allocation. The GSM 08.58 asks for the Mobile
	 * Allocation to have a length of zero. We are using the
	 * msgb_l3len to calculate the length of both messages.
	 */
	msgb_v_put(msg, RSL_IE_CHAN_IDENT);
	len = msgb_put(msg, 1);
	msgb_tv_fixed_put(msg, GSM48_IE_CHANDESC_2, sizeof(cd), (const uint8_t *) &cd);

	/* See 3GPP TS 48.058 (version 15.0.0), section 9.3.5 "Channel Identification".
	 * The 3GPP TS 24.008 "Mobile Allocation" shall for compatibility reasons
	 * be included but empty, i.e. the length shall be zero. */
	msgb_tlv_put(msg, GSM48_IE_MA_AFTER, 0, NULL);

	/* update the calculated size */
	msg->l3h = len + 1;
	*len = msgb_l3len(msg);

	if (lchan->encr.alg_a5_n > 0) {
		uint8_t encr_info[MAX_A5_KEY_LEN+2];
		rc = build_encr_info(encr_info, lchan);
		if (rc > 0)
			msgb_tlv_put(msg, RSL_IE_ENCR_INFO, rc, encr_info);
		if (rc < 0) {
			msgb_free(msg);
			return rc;
		}
	}

	switch (act_type) {
	case RSL_ACT_INTER_ASYNC:
	case RSL_ACT_INTER_SYNC:
		msgb_tv_put(msg, RSL_IE_HANDO_REF, ho_ref);
		break;
	default:
		break;
	}

	if (bts->bs_power_ctrl.mode != GSM_PWR_CTRL_MODE_NONE)
		msgb_tv_put(msg, RSL_IE_BS_POWER, lchan->bs_power_db / 2);
	if (bts->ms_power_ctrl.mode != GSM_PWR_CTRL_MODE_NONE)
		msgb_tv_put(msg, RSL_IE_MS_POWER, lchan->ms_power);

	if (lchan->activate.info.ta_known) {
		uint8_t ta = lchan->activate.info.ta;
		/* BS11 requires TA shifted by 2 bits */
		if (bts->type == GSM_BTS_TYPE_BS11)
			ta <<= 2;
		msgb_tv_put(msg, RSL_IE_TIMING_ADVANCE, ta);
	} else if ((act_type & 0x06) == 0x00) {
		/* Note '4)' in section 8.4.1: The Timing Advance element must be
		 * included if activation type is intra cell channel change. */
		LOG_LCHAN(lchan, LOGL_NOTICE, "Timing Advance IE shall be present, "
			  "but the actual value is not known => assuming 0\n");
		msgb_tv_put(msg, RSL_IE_TIMING_ADVANCE, 0);
	}

	/* BS/MS Power Control Parameters (if supported by BTS model) */
	add_power_control_params(msg, RSL_IE_BS_POWER_PARAM, lchan);
	add_power_control_params(msg, RSL_IE_MS_POWER_PARAM, lchan);

	if (cm.chan_rate == RSL_CMOD_SP_GSM3) {
		rc = put_mr_config_for_bts(msg, &lchan->activate.mr_conf_filtered,
					   (lchan->type == GSM_LCHAN_TCH_F) ? &bts->mr_full : &bts->mr_half);
		if (rc) {
			LOG_LCHAN(lchan, LOGL_ERROR, "Cannot encode MultiRate Configuration IE\n");
			msgb_free(msg);
			return rc;
		}
	}

	put_rep_acch_cap_ie(lchan, msg);
	put_top_acch_cap_ie(lchan, &cm, msg);

	/* Selecting a specific TSC Set is only applicable to VAMOS mode */
	if (lchan->activate.info.vamos && lchan->activate.tsc_set >= 1)
		put_osmo_training_sequence_ie(msg, lchan->activate.tsc_set, lchan->activate.tsc);

	msg->dst = rsl_chan_link(lchan);

	rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_CHAN_ACT_TOTAL));
	switch (lchan->type) {
	case GSM_LCHAN_SDCCH:
		rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_CHAN_ACT_SDCCH));
		break;
	case GSM_LCHAN_TCH_H:
	case GSM_LCHAN_TCH_F:
		rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_CHAN_ACT_TCH));
		break;
	default:
		break;
	}

	return abis_rsl_sendmsg(msg);
}

/* Chapter 8.4.9: Modify channel mode on BTS side */
int rsl_chan_mode_modify_req(struct gsm_lchan *lchan)
{
	struct abis_rsl_dchan_hdr *dh;
	struct msgb *msg;
	int rc;

	struct rsl_ie_chan_mode cm;
	struct gsm_bts *bts = lchan->ts->trx->bts;

	int chan_nr = gsm_lchan2chan_nr(lchan, true);
	if (chan_nr < 0)
		return chan_nr;

	rc = channel_mode_from_lchan(&cm, lchan, &lchan->modify.ch_mode_rate, lchan->modify.info.vamos);
	if (rc < 0)
		return rc;

	msg = rsl_msgb_alloc();
	dh = (struct abis_rsl_dchan_hdr *) msgb_put(msg, sizeof(*dh));
	init_dchan_hdr(dh, RSL_MT_MODE_MODIFY_REQ);
	dh->chan_nr = chan_nr;

	msgb_tlv_put(msg, RSL_IE_CHAN_MODE, sizeof(cm),
		     (uint8_t *) &cm);

	if (lchan->encr.alg_a5_n > 0) {
		uint8_t encr_info[MAX_A5_KEY_LEN+2];
		rc = build_encr_info(encr_info, lchan);
		if (rc > 0)
			msgb_tlv_put(msg, RSL_IE_ENCR_INFO, rc, encr_info);
		if (rc < 0) {
			msgb_free(msg);
			return rc;
		}
	}

	if (cm.chan_rate == RSL_CMOD_SP_GSM3) {
		rc = put_mr_config_for_bts(msg, &lchan->modify.mr_conf_filtered,
					   (lchan->type == GSM_LCHAN_TCH_F) ? &bts->mr_full : &bts->mr_half);
		if (rc) {
			LOG_LCHAN(lchan, LOGL_ERROR, "Cannot encode MultiRate Configuration IE\n");
			msgb_free(msg);
			return rc;
		}
	}

	put_rep_acch_cap_ie(lchan, msg);
	put_top_acch_cap_ie(lchan, &cm, msg);

	/* Selecting a specific TSC Set is only applicable to VAMOS mode. Send this Osmocom specific IE only to OsmoBTS
	 * types. */
	if (lchan->modify.info.vamos && lchan->modify.tsc_set >= 1 && bts->model->type == GSM_BTS_TYPE_OSMOBTS)
		put_osmo_training_sequence_ie(msg, lchan->modify.tsc_set, lchan->modify.tsc);

	msg->dst = rsl_chan_link(lchan);

	return abis_rsl_sendmsg(msg);
}

/* Chapter 8.4.6: Send the encryption command with given L3 info */
int rsl_encryption_cmd(struct msgb *msg)
{
	struct abis_rsl_dchan_hdr *dh;
	struct gsm_lchan *lchan = msg->lchan;
	uint8_t encr_info[MAX_A5_KEY_LEN+2];
	uint8_t l3_len = msg->len;
	int rc;

	int chan_nr = gsm_lchan2chan_nr(lchan, true);
	if (chan_nr < 0)
		return chan_nr;

	/* First push the L3 IE tag and length */
	msgb_tv16_push(msg, RSL_IE_L3_INFO, l3_len);

	/* then the link identifier (SAPI0, main sign link) */
	msgb_tv_push(msg, RSL_IE_LINK_IDENT, 0);

	/* then encryption information */
	rc = build_encr_info(encr_info, lchan);
	if (rc <= 0)
		return rc;
	msgb_tlv_push(msg, RSL_IE_ENCR_INFO, rc, encr_info);

	/* and finally the DCHAN header */
	dh = (struct abis_rsl_dchan_hdr *) msgb_push(msg, sizeof(*dh));
	init_dchan_hdr(dh, RSL_MT_ENCR_CMD);
	dh->chan_nr = chan_nr;

	msg->dst = rsl_chan_link(lchan);

	return abis_rsl_sendmsg(msg);
}

/* Chapter 8.4.5 / 4.6: Deactivate the SACCH after 04.08 RR CHAN RELEASE */
int rsl_deact_sacch(struct gsm_lchan *lchan)
{
	struct abis_rsl_dchan_hdr *dh;
	struct msgb *msg = rsl_msgb_alloc();

	int chan_nr = gsm_lchan2chan_nr(lchan, true);
	if (chan_nr < 0)
		return chan_nr;

	dh = (struct abis_rsl_dchan_hdr *) msgb_put(msg, sizeof(*dh));
	init_dchan_hdr(dh, RSL_MT_DEACTIVATE_SACCH);
	dh->chan_nr = chan_nr;

	msg->lchan = lchan;
	msg->dst = rsl_chan_link(lchan);

	DEBUGP(DRSL, "%s DEACTivate SACCH CMD\n", gsm_lchan_name(lchan));

	return abis_rsl_sendmsg(msg);
}

/* Chapter 8.4.14 / 4.7: Tell BTS to release the radio channel */
int rsl_tx_rf_chan_release(struct gsm_lchan *lchan)
{
	struct abis_rsl_dchan_hdr *dh;
	struct msgb *msg;

	int chan_nr = gsm_lchan2chan_nr(lchan, true);
	if (chan_nr < 0)
		return chan_nr;

	msg = rsl_msgb_alloc();
	dh = (struct abis_rsl_dchan_hdr *) msgb_put(msg, sizeof(*dh));
	init_dchan_hdr(dh, RSL_MT_RF_CHAN_REL);
	dh->chan_nr = chan_nr;

	msg->lchan = lchan;
	msg->dst = rsl_chan_link(lchan);

	return abis_rsl_sendmsg(msg);
}

int rsl_paging_cmd(struct gsm_bts *bts, uint8_t paging_group,
		   const struct osmo_mobile_identity *mi,
		   uint8_t chan_needed, bool is_gprs)
{
	struct abis_rsl_cchan_hdr *cch;
	struct msgb *msg = rsl_msgb_alloc();
	uint8_t *l;
	int rc;

	cch = (struct abis_rsl_cchan_hdr *) msgb_put(msg, sizeof(*cch));
	rsl_init_cchan_hdr(cch, RSL_MT_PAGING_CMD);
	cch->chan_nr = RSL_CHAN_PCH_AGCH;

	msgb_tv_put(msg, RSL_IE_PAGING_GROUP, paging_group);

	l = msgb_tl_put(msg, RSL_IE_MS_IDENTITY);
	rc = osmo_mobile_identity_encode_msgb(msg, mi, false);
	if (rc < 0) {
		msgb_free(msg);
		return -EINVAL;
	}
	*l = rc;

	msgb_tv_put(msg, RSL_IE_CHAN_NEEDED, chan_needed);

	/* Ericsson wants to have this IE in case a paging message
	 * relates to packet paging */
	if (bts->type == GSM_BTS_TYPE_RBS2000 && is_gprs)
		msgb_tv_put(msg, RSL_IE_ERIC_PACKET_PAG_IND, 0);

	msg->dst = bts->c0->rsl_link_primary;

	return abis_rsl_sendmsg(msg);
}

int rsl_forward_layer3_info(struct gsm_lchan *lchan, const uint8_t *l3_info, uint8_t l3_info_len)
{
	struct msgb *msg;

	if (!l3_info || !l3_info_len)
		return -EINVAL;

	msg = rsl_msgb_alloc();
	msg->l3h = msgb_put(msg, l3_info_len);
	memcpy(msg->l3h, l3_info, l3_info_len);

	msg->lchan = lchan;
	return rsl_data_request(msg, 0);
}

/* Chapter 8.5.6 */
struct msgb *rsl_imm_assign_cmd_common(struct gsm_bts *bts, uint8_t len, uint8_t *val)
{
	struct msgb *msg = rsl_msgb_alloc();
	struct abis_rsl_dchan_hdr *dh;
	uint8_t buf[GSM_MACBLOCK_LEN];

	dh = (struct abis_rsl_dchan_hdr *) msgb_put(msg, sizeof(*dh));
	init_dchan_hdr(dh, RSL_MT_IMMEDIATE_ASSIGN_CMD);
	dh->chan_nr = RSL_CHAN_PCH_AGCH;

	switch (bts->type) {
	case GSM_BTS_TYPE_BS11:
		msgb_tlv_put(msg, RSL_IE_IMM_ASS_INFO, len, val);
		break;
	default:
		/* If phase 2, construct a FULL_IMM_ASS_INFO */
		pad_macblock(buf, val, len);
		msgb_tlv_put(msg, RSL_IE_FULL_IMM_ASS_INFO, GSM_MACBLOCK_LEN,
			     buf);
		break;
	}

	msg->dst = bts->c0->rsl_link_primary;
	return msg;
}

/* Chapter 8.5.6 */
int rsl_imm_assign_cmd(struct gsm_bts *bts, uint8_t len, uint8_t *val)
{
	struct msgb *msg = rsl_imm_assign_cmd_common(bts, len, val);
	if (!msg)
		return 1;
	return abis_rsl_sendmsg(msg);
}

/* Chapter 8.5.6 */
int rsl_ericsson_imm_assign_cmd(struct gsm_bts *bts, uint32_t tlli, uint8_t len, uint8_t *val)
{
	struct msgb *msg = rsl_imm_assign_cmd_common(bts, len, val);
	if (!msg)
		return 1;

	/* ericsson can handle a reference at the end of the message which is used in
	 * the confirm message. The confirm message is only sent if the trailer is present */
	msgb_put_u8(msg, RSL_IE_ERIC_MOBILE_ID);
	msgb_put_u32(msg, tlli);

	return abis_rsl_sendmsg(msg);
}

/* Send Siemens specific MS RF Power Capability Indication */
int rsl_siemens_mrpci(struct gsm_lchan *lchan, struct rsl_mrpci *mrpci)
{
	struct msgb *msg;
	struct abis_rsl_dchan_hdr *dh;

	int chan_nr = gsm_lchan2chan_nr(lchan, true);
	if (chan_nr < 0)
		return chan_nr;

	msg = rsl_msgb_alloc();

	dh = (struct abis_rsl_dchan_hdr *) msgb_put(msg, sizeof(*dh));
	init_dchan_hdr(dh, RSL_MT_SIEMENS_MRPCI);
	dh->c.msg_discr = ABIS_RSL_MDISC_DED_CHAN;
	dh->chan_nr = chan_nr;
	msgb_tv_put(msg, RSL_IE_SIEMENS_MRPCI, *(uint8_t *)mrpci);

	DEBUGP(DRSL, "%s TX Siemens MRPCI 0x%02x\n",
		gsm_lchan_name(lchan), *(uint8_t *)mrpci);

	msg->dst = rsl_chan_link(lchan);

	return abis_rsl_sendmsg(msg);
}


/* For 3GPP TS 52.402 unsuccReqsForService, we need to decode the DTAP and count CM Service Reject messages. */
static void count_unsucc_reqs_for_service(const struct msgb *msg)
{
	struct gsm_bts *bts = msg->lchan->ts->trx->bts;
	const struct gsm48_hdr *gh;
	uint8_t pdisc, mtype;
	uint8_t cause;

	if (msgb_l3len(msg) < sizeof(*gh))
		return;

	gh = msgb_l3(msg);
	pdisc = gsm48_hdr_pdisc(gh);
	mtype = gsm48_hdr_msg_type(gh);

	if (pdisc != GSM48_PDISC_MM || mtype != GSM48_MT_MM_CM_SERV_REJ)
		return;

	rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_CM_SERV_REJ));

	cause = gh->data[0];
	switch (cause) {
	case GSM48_REJECT_IMSI_UNKNOWN_IN_HLR:
		rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_CM_SERV_REJ_IMSI_UNKNOWN_IN_HLR));
		break;
	case GSM48_REJECT_ILLEGAL_MS:
		rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_CM_SERV_REJ_ILLEGAL_MS));
		break;
	case GSM48_REJECT_IMSI_UNKNOWN_IN_VLR:
		rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_CM_SERV_REJ_IMSI_UNKNOWN_IN_VLR));
		break;
	case GSM48_REJECT_IMEI_NOT_ACCEPTED:
		rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_CM_SERV_REJ_IMEI_NOT_ACCEPTED));
		break;
	case GSM48_REJECT_ILLEGAL_ME:
		rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_CM_SERV_REJ_ILLEGAL_ME));
		break;
	case GSM48_REJECT_PLMN_NOT_ALLOWED:
		rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_CM_SERV_REJ_PLMN_NOT_ALLOWED));
		break;
	case GSM48_REJECT_LOC_NOT_ALLOWED:
		rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_CM_SERV_REJ_LOC_NOT_ALLOWED));
		break;
	case GSM48_REJECT_ROAMING_NOT_ALLOWED:
		rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_CM_SERV_REJ_ROAMING_NOT_ALLOWED));
		break;
	case GSM48_REJECT_NETWORK_FAILURE:
		rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_CM_SERV_REJ_NETWORK_FAILURE));
		break;
	case GSM48_REJECT_SYNCH_FAILURE:
		rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_CM_SERV_REJ_SYNCH_FAILURE));
		break;
	case GSM48_REJECT_CONGESTION:
		rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_CM_SERV_REJ_CONGESTION));
		break;
	case GSM48_REJECT_SRV_OPT_NOT_SUPPORTED:
		rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_CM_SERV_REJ_SRV_OPT_NOT_SUPPORTED));
		break;
	case GSM48_REJECT_RQD_SRV_OPT_NOT_SUPPORTED:
		rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_CM_SERV_REJ_RQD_SRV_OPT_NOT_SUPPORTED));
		break;
	case GSM48_REJECT_SRV_OPT_TMP_OUT_OF_ORDER:
		rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_CM_SERV_REJ_SRV_OPT_TMP_OUT_OF_ORDER));
		break;
	case GSM48_REJECT_CALL_CAN_NOT_BE_IDENTIFIED:
		rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_CM_SERV_REJ_CALL_CAN_NOT_BE_IDENTIFIED));
		break;
	case GSM48_REJECT_INCORRECT_MESSAGE:
		rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_CM_SERV_REJ_INCORRECT_MESSAGE));
		break;
	case GSM48_REJECT_INVALID_MANDANTORY_INF:
		rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_CM_SERV_REJ_INVALID_MANDANTORY_INF));
		break;
	case GSM48_REJECT_MSG_TYPE_NOT_IMPLEMENTED:
		rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_CM_SERV_REJ_MSG_TYPE_NOT_IMPLEMENTED));
		break;
	case GSM48_REJECT_MSG_TYPE_NOT_COMPATIBLE:
		rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_CM_SERV_REJ_MSG_TYPE_NOT_COMPATIBLE));
		break;
	case GSM48_REJECT_INF_ELEME_NOT_IMPLEMENTED:
		rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_CM_SERV_REJ_INF_ELEME_NOT_IMPLEMENTED));
		break;
	case GSM48_REJECT_CONDTIONAL_IE_ERROR:
		rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_CM_SERV_REJ_CONDTIONAL_IE_ERROR));
		break;
	case GSM48_REJECT_MSG_NOT_COMPATIBLE:
		rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_CM_SERV_REJ_MSG_NOT_COMPATIBLE));
		break;
	default:
		if (cause >= 48 && cause <= 63) {
			rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_CM_SERV_REJ_RETRY_IN_NEW_CELL));
			break;
		}
		/* else fall thru */
	case GSM48_REJECT_PROTOCOL_ERROR:
		rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_CM_SERV_REJ_PROTOCOL_ERROR));
		break;
	}
}

/* Send "DATA REQUEST" message with given L3 Info payload */
/* Chapter 8.3.1 */
int rsl_data_request(struct msgb *msg, uint8_t link_id)
{
	int chan_nr;

	if (msg->lchan == NULL) {
		LOGP(DRSL, LOGL_ERROR, "cannot send DATA REQUEST to unknown lchan\n");
		msgb_free(msg);
		return -EINVAL;
	}

	count_unsucc_reqs_for_service(msg);

	chan_nr = gsm_lchan2chan_nr(msg->lchan, true);
	if (chan_nr < 0) {
		msgb_free(msg);
		return chan_nr;
	}

	rsl_rll_push_l3(msg, RSL_MT_DATA_REQ, chan_nr, link_id, 1);

	msg->dst = rsl_chan_link(msg->lchan);

	return abis_rsl_sendmsg(msg);
}

/* Send "ESTABLISH REQUEST" message with given L3 Info payload */
/* Chapter 8.3.1 */
int rsl_establish_request(struct gsm_lchan *lchan, uint8_t link_id)
{
	struct msgb *msg;
	int chan_nr = gsm_lchan2chan_nr(lchan, true);
	if (chan_nr < 0)
		return chan_nr;

	msg = rsl_rll_simple(RSL_MT_EST_REQ, chan_nr, link_id, 0);
	msg->dst = rsl_chan_link(lchan);

	DEBUGP(DRLL, "%s RSL RLL ESTABLISH REQ (link_id=0x%02x)\n",
		gsm_lchan_name(lchan), link_id);

	return abis_rsl_sendmsg(msg);
}

/* Chapter 8.3.7 Request the release of multiframe mode of RLL connection.
   This is what higher layers should call.  The BTS then responds with
   RELEASE CONFIRM, which we in turn use to trigger RSL CHANNEL RELEASE,
   which in turn is acknowledged by RSL CHANNEL RELEASE ACK, which calls
   lchan_free() */
int rsl_release_request(struct gsm_lchan *lchan, uint8_t link_id,
			enum rsl_rel_mode release_mode)
{

	struct msgb *msg;
	int chan_nr = gsm_lchan2chan_nr(lchan, true);
	if (chan_nr < 0)
		return chan_nr;

	msg = rsl_rll_simple(RSL_MT_REL_REQ, chan_nr, link_id, 0);
	/* 0 is normal release, 1 is local end */
	msgb_tv_put(msg, RSL_IE_RELEASE_MODE, release_mode);

	msg->dst = rsl_chan_link(lchan);

	DEBUGP(DRLL, "%s RSL RLL RELEASE REQ (link_id=0x%02x, reason=%u)\n",
		gsm_lchan_name(lchan), link_id, release_mode);

	abis_rsl_sendmsg(msg);

	return 0;
}

static bool msg_for_osmocom_dyn_ts(struct msgb *msg)
{
	struct abis_rsl_dchan_hdr *rslh = msgb_l2(msg);
	if (msg->lchan->ts->pchan_on_init != GSM_PCHAN_OSMO_DYN)
		return false;
	/* dyn TS messages always come in on the first lchan of a timeslot */
	if (msg->lchan->nr != 0)
		return false;
	return (rslh->chan_nr & RSL_CHAN_OSMO_PDCH) == RSL_CHAN_OSMO_PDCH;
}

/* Chapter 8.4.3: Channel Activate NACK */
static int rsl_rx_chan_act_nack(struct msgb *msg)
{
	struct abis_rsl_dchan_hdr *dh = msgb_l2(msg);
	struct tlv_parsed tp;
	struct gsm_lchan *lchan = msg->lchan;
	const uint8_t *cause_p;

	rate_ctr_inc(rate_ctr_group_get_ctr(msg->lchan->ts->trx->bts->bts_ctrs, BTS_CTR_CHAN_ACT_NACK));

	if (dh->ie_chan != RSL_IE_CHAN_NR) {
		LOG_LCHAN(msg->lchan, LOGL_ERROR, "Invalid IE: expected CHAN_NR IE (0x%x), got 0x%x\n",
			  RSL_IE_CHAN_NR, dh->ie_chan);
		return -EINVAL;
	}

	if (rsl_tlv_parse(&tp, dh->data, msgb_l2len(msg) - sizeof(*dh)) < 0) {
		LOG_LCHAN(msg->lchan, LOGL_ERROR, "Failed to parse RSL %s\n",
			  rsl_or_ipac_msg_name(dh->c.msg_type));
		return -EINVAL;
	}

	cause_p = rsl_cause(&tp);
	LOG_LCHAN(lchan, LOGL_ERROR, "CHANNEL ACTIVATE NACK%s\n", rsl_cause_name(&tp));

	if (msg_for_osmocom_dyn_ts(msg))
		osmo_fsm_inst_dispatch(lchan->ts->fi, TS_EV_PDCH_ACT_NACK, (void*)cause_p);
	else
		osmo_fsm_inst_dispatch(lchan->fi, LCHAN_EV_RSL_CHAN_ACTIV_NACK, (void*)cause_p);
	return 0;
}

/* Chapter 8.4.4: Connection Failure Indication */
static int rsl_rx_conn_fail(struct msgb *msg)
{
	struct abis_rsl_dchan_hdr *dh = msgb_l2(msg);
	struct gsm_lchan *lchan = msg->lchan;
	struct rate_ctr_group *bts_ctrs = lchan->ts->trx->bts->bts_ctrs;
	struct tlv_parsed tp;
	const uint8_t *cause_p;

	if (rsl_tlv_parse(&tp, dh->data, msgb_l2len(msg) - sizeof(*dh)) < 0) {
		LOG_LCHAN(msg->lchan, LOGL_ERROR, "Failed to parse RSL %s\n",
			  rsl_or_ipac_msg_name(dh->c.msg_type));
		return -EINVAL;
	}

	cause_p = rsl_cause(&tp);

	LOG_LCHAN(lchan, LOGL_ERROR, "CONNECTION FAIL%s\n", rsl_cause_name(&tp));

	rate_ctr_inc(rate_ctr_group_get_ctr(bts_ctrs, BTS_CTR_CHAN_RF_FAIL));
	switch (lchan->type) {
	case GSM_LCHAN_SDCCH:
		rate_ctr_inc(rate_ctr_group_get_ctr(bts_ctrs, BTS_CTR_CHAN_RF_FAIL_SDCCH));
		break;
	case GSM_LCHAN_TCH_H:
	case GSM_LCHAN_TCH_F:
		rate_ctr_inc(rate_ctr_group_get_ctr(bts_ctrs, BTS_CTR_CHAN_RF_FAIL_TCH));
		break;
	default:
		break;
	}

	/* If the lchan is associated with a conn, we shall notify the MSC of the RSL Conn Failure, and
	 * the connection will presumably be torn down and lead to an lchan release. During initial
	 * Channel Request from the MS, an lchan has no conn yet, so in that case release now. */
	if (!lchan->conn)
		lchan_release(lchan, false, true, *cause_p, NULL);
	else
		osmo_fsm_inst_dispatch(lchan->conn->fi, GSCON_EV_RSL_CONN_FAIL, (void*)cause_p);

	return 0;
}

static void print_meas_rep_uni(struct osmo_strbuf *sb,
			       const struct gsm_meas_rep_unidir *mru,
			       const char *prefix)
{
	OSMO_STRBUF_PRINTF(*sb, "RXL-FULL-%s=%3ddBm RXL-SUB-%s=%3ddBm ",
			   prefix, rxlev2dbm(mru->full.rx_lev),
			   prefix, rxlev2dbm(mru->sub.rx_lev));
	OSMO_STRBUF_PRINTF(*sb, "RXQ-FULL-%s=%d RXQ-SUB-%s=%d ",
			   prefix, mru->full.rx_qual, prefix, mru->sub.rx_qual);
}

static int print_meas_rep_buf(char *buf, size_t len, const struct gsm_meas_rep *mr)
{
	struct osmo_strbuf sb = { .buf = buf, .len = len };

	OSMO_STRBUF_PRINTF(sb, "MEASUREMENT RESULT NR=%d ", mr->nr);

	if (mr->flags & MEAS_REP_F_DL_DTX)
		OSMO_STRBUF_PRINTF(sb, "DTXd ");

	print_meas_rep_uni(&sb, &mr->ul, "ul");
	OSMO_STRBUF_PRINTF(sb, "BS_POWER=%ddB ", mr->bs_power_db);

	if (mr->flags & MEAS_REP_F_MS_TO)
		OSMO_STRBUF_PRINTF(sb, "MS_TO=%d ", mr->ms_timing_offset);

	if (mr->flags & MEAS_REP_F_MS_L1) {
		OSMO_STRBUF_PRINTF(sb, "L1_MS_PWR=%3ddBm ", mr->ms_l1.pwr);
		OSMO_STRBUF_PRINTF(sb, "L1_FPC=%u ", mr->flags & MEAS_REP_F_FPC ? 1 : 0);
		OSMO_STRBUF_PRINTF(sb, "L1_TA=%u ", mr->ms_l1.ta);
	}

	if (mr->flags & MEAS_REP_F_UL_DTX)
		OSMO_STRBUF_PRINTF(sb, "DTXu ");
	if (mr->flags & MEAS_REP_F_BA1)
		OSMO_STRBUF_PRINTF(sb, "BA1 ");
	if (!(mr->flags & MEAS_REP_F_DL_VALID))
		OSMO_STRBUF_PRINTF(sb, "NOT VALID ");
	else
		print_meas_rep_uni(&sb, &mr->dl, "dl");

	OSMO_STRBUF_PRINTF(sb, "NUM_NEIGH=%u", mr->num_cell);

	return sb.chars_needed;
}

static char *print_meas_rep_c(void *ctx, const struct gsm_meas_rep *mr)
{
	/* A naive count of required characters gets me to ~200, so 256 should be safe to get a large enough buffer on
	 * the first time. */
	OSMO_NAME_C_IMPL(ctx, 256, "ERROR", print_meas_rep_buf, mr)
}

static void print_meas_rep(struct gsm_lchan *lchan, const struct gsm_meas_rep *mr)
{
	int i;
	const char *name = "";
	struct bsc_subscr *bsub = NULL;

	if (lchan && lchan->conn) {
		bsub = lchan->conn->bsub;
		if (bsub) {
			log_set_context(LOG_CTX_BSC_SUBSCR, bsub);
			name = bsc_subscr_name(bsub);
		} else {
			name = lchan->name;
		}
	}

	DEBUGP(DMEAS, "[%s] %s\n", name, print_meas_rep_c(OTC_SELECT, mr));

	if (mr->num_cell != 7
	    && log_check_level(DMEAS, LOGL_DEBUG)) {
		for (i = 0; i < mr->num_cell; i++) {
			const struct gsm_meas_rep_cell *mrc = &mr->cell[i];
			DEBUGP(DMEAS, "IDX=%u ARFCN=%u BSIC=%u RXLEV=%ddBm\n",
			       mrc->neigh_idx, mrc->arfcn, mrc->bsic, rxlev2dbm(mrc->rxlev));
		}
	}

	if (bsub)
		log_set_context(LOG_CTX_BSC_SUBSCR, NULL);
}

static struct gsm_meas_rep *lchan_next_meas_rep(struct gsm_lchan *lchan)
{
	struct gsm_meas_rep *meas_rep;

	meas_rep = &lchan->meas_rep[lchan->meas_rep_idx];
	memset(meas_rep, 0, sizeof(*meas_rep));
	meas_rep->lchan = lchan;
	lchan->meas_rep_idx = (lchan->meas_rep_idx + 1)
					% ARRAY_SIZE(lchan->meas_rep);

	return meas_rep;
}

static int rsl_rx_meas_res(struct msgb *msg)
{
	struct abis_rsl_dchan_hdr *dh = msgb_l2(msg);
	struct tlv_parsed tp;
	struct gsm_meas_rep *mr = lchan_next_meas_rep(msg->lchan);
	uint8_t len;
	const uint8_t *val;
	int rc;
	uint8_t bs_power_enc;

	if (!lchan_may_receive_data(msg->lchan)) {
		LOG_LCHAN(msg->lchan, LOGL_DEBUG, "MEAS RES for inactive channel\n");
		return 0;
	}

	memset(mr, 0, sizeof(*mr));
	mr->lchan = msg->lchan;

	if (rsl_tlv_parse(&tp, dh->data, msgb_l2len(msg) - sizeof(*dh)) < 0) {
		LOG_LCHAN(msg->lchan, LOGL_ERROR, "Failed to parse RSL %s\n",
			  rsl_or_ipac_msg_name(dh->c.msg_type));
		return -EINVAL;
	}

	if (!TLVP_PRESENT(&tp, RSL_IE_MEAS_RES_NR) ||
	    !TLVP_PRESENT(&tp, RSL_IE_UPLINK_MEAS) ||
	    !TLVP_PRESENT(&tp, RSL_IE_BS_POWER)) {
		LOGP(DRSL, LOGL_ERROR, "%s Measurement Report lacks mandatory IEs\n",
		     gsm_lchan_name(mr->lchan));
		return -EIO;
	}

	/* Mandatory Parts */
	mr->nr = *TLVP_VAL(&tp, RSL_IE_MEAS_RES_NR);

	len = TLVP_LEN(&tp, RSL_IE_UPLINK_MEAS);
	val = TLVP_VAL(&tp, RSL_IE_UPLINK_MEAS);
	if (len >= 3) {
		if (val[0] & 0x40)
			mr->flags |= MEAS_REP_F_DL_DTX;
		mr->ul.full.rx_lev = val[0] & 0x3f;
		mr->ul.sub.rx_lev = val[1] & 0x3f;
		mr->ul.full.rx_qual = val[2]>>3 & 0x7;
		mr->ul.sub.rx_qual = val[2] & 0x7;
	}

	bs_power_enc = *TLVP_VAL(&tp, RSL_IE_BS_POWER);
	mr->bs_power_db = (bs_power_enc & 0x0f) * 2;

	/* Optional Parts */
	if (TLVP_PRESENT(&tp, RSL_IE_MS_TIMING_OFFSET)) {
		/* According to 3GPP TS 48.058 § MS Timing Offset = Timing Offset field - 63 */
		mr->ms_timing_offset = *TLVP_VAL(&tp, RSL_IE_MS_TIMING_OFFSET) - 63;
		mr->flags |= MEAS_REP_F_MS_TO;
	}

	if (TLVP_PRESENT(&tp, RSL_IE_L1_INFO)) {
		struct e1inp_sign_link *sign_link = msg->dst;

		val = TLVP_VAL(&tp, RSL_IE_L1_INFO);
		mr->flags |= MEAS_REP_F_MS_L1;
		mr->ms_l1.pwr = ms_pwr_dbm(sign_link->trx->bts->band, val[0] >> 3);
		if (val[0] & 0x04)
			mr->flags |= MEAS_REP_F_FPC;
		mr->ms_l1.ta = val[1];
		/* BS11, Nokia and RBS report TA shifted by 2 bits */
		if (msg->lchan->ts->trx->bts->type == GSM_BTS_TYPE_BS11
		 || msg->lchan->ts->trx->bts->type == GSM_BTS_TYPE_NOKIA_SITE
		 || msg->lchan->ts->trx->bts->type == GSM_BTS_TYPE_RBS2000)
			mr->ms_l1.ta >>= 2;
		/* store TA for handover decision, and for intra-cell re-assignment */
		mr->lchan->last_ta = mr->ms_l1.ta;
	}
	if (TLVP_PRESENT(&tp, RSL_IE_L3_INFO)) {
		msg->l3h = (uint8_t *) TLVP_VAL(&tp, RSL_IE_L3_INFO);
		rc = gsm48_parse_meas_rep(mr, msg);
		if (rc < 0)
			return rc;
	}

	mr->lchan->meas_rep_count++;
	mr->lchan->meas_rep_last_seen_nr = mr->nr;
	LOGP(DRSL, LOGL_DEBUG, "%s: meas_rep_count++=%d meas_rep_last_seen_nr=%u\n",
	     gsm_lchan_name(mr->lchan), mr->lchan->meas_rep_count, mr->lchan->meas_rep_last_seen_nr);

	print_meas_rep(msg->lchan, mr);

	lchan_ms_pwr_ctrl(msg->lchan, mr);

	send_lchan_signal(S_LCHAN_MEAS_REP, msg->lchan, mr);

	return 0;
}

/* Chapter 8.4.7 */
static int rsl_rx_hando_det(struct msgb *msg)
{
	struct abis_rsl_dchan_hdr *dh = msgb_l2(msg);
	struct tlv_parsed tp;
	struct handover_rr_detect_data d = {
		.msg = msg,
	};

	if (rsl_tlv_parse(&tp, dh->data, msgb_l2len(msg) - sizeof(*dh)) < 0) {
		LOG_LCHAN(msg->lchan, LOGL_ERROR, "Failed to parse RSL %s\n",
			  rsl_or_ipac_msg_name(dh->c.msg_type));
		return -EINVAL;
	}

	if (TLVP_PRESENT(&tp, RSL_IE_ACCESS_DELAY))
		d.access_delay = TLVP_VAL(&tp, RSL_IE_ACCESS_DELAY);

	if (!msg->lchan->conn || !msg->lchan->conn->ho.fi) {
		LOGP(DRSL, LOGL_ERROR, "%s HANDOVER DETECT but no handover is ongoing\n",
		     gsm_lchan_name(msg->lchan));
		return 0;
	}

	osmo_fsm_inst_dispatch(msg->lchan->conn->ho.fi, HO_EV_RR_HO_DETECT, &d);

	return 0;
}

static int rsl_rx_ipacc_pdch(struct msgb *msg, char *name, uint32_t ts_ev)
{
	struct gsm_bts_trx_ts *ts = msg->lchan->ts;

	if (ts->pchan_on_init != GSM_PCHAN_TCH_F_PDCH) {
		LOG_TS(ts, LOGL_ERROR, "Rx RSL ip.access PDCH %s acceptable only for %s\n",
		       name, gsm_pchan_name(GSM_PCHAN_TCH_F_PDCH));
		return -EINVAL;
	}

	osmo_fsm_inst_dispatch(ts->fi, ts_ev, NULL);
	return 0;
}

static int abis_rsl_rx_dchan(struct msgb *msg)
{
	struct abis_rsl_dchan_hdr *rslh = msgb_l2(msg);
	int rc = 0;
	struct e1inp_sign_link *sign_link = msg->dst;

	if (msgb_l2len(msg) < sizeof(*rslh))
		return -EINVAL;

	if (rslh->ie_chan != RSL_IE_CHAN_NR) {
		LOGP(DRSL, LOGL_ERROR,
		     "Rx RSL DCHAN: invalid RSL header, expecting Channel Number IE tag, got 0x%x\n",
		     rslh->ie_chan);
		return -EINVAL;
	}

	msg->lchan = lchan_lookup(sign_link->trx, rslh->chan_nr,
				  "Abis RSL rx DCHAN: ");
	if (!msg->lchan) {
		LOGP(DRSL, LOGL_ERROR,
		     "Rx RSL DCHAN: unable to match RSL message to an lchan: chan_nr=0x%x\n",
		     rslh->chan_nr);
		return -EINVAL;
	}

	LOG_LCHAN(msg->lchan, LOGL_DEBUG, "Rx %s\n", rsl_or_ipac_msg_name(rslh->c.msg_type));

	if (!msg->lchan->fi) {
		LOG_LCHAN(msg->lchan, LOGL_ERROR, "Rx RSL DCHAN: RSL message for unconfigured lchan\n");
		return -EINVAL;
	}

	switch (rslh->c.msg_type) {
	case RSL_MT_CHAN_ACTIV_ACK:
		if (msg_for_osmocom_dyn_ts(msg))
			osmo_fsm_inst_dispatch(msg->lchan->ts->fi, TS_EV_PDCH_ACT_ACK, NULL);
		else {
			osmo_fsm_inst_dispatch(msg->lchan->fi, LCHAN_EV_RSL_CHAN_ACTIV_ACK, NULL);
			count_codecs(sign_link->trx->bts, msg->lchan);
		}
		break;
	case RSL_MT_CHAN_ACTIV_NACK:
		rc = rsl_rx_chan_act_nack(msg);
		break;
	case RSL_MT_CONN_FAIL:
		rc = rsl_rx_conn_fail(msg);
		break;
	case RSL_MT_MEAS_RES:
		rc = rsl_rx_meas_res(msg);
		break;
	case RSL_MT_HANDO_DET:
		rc = rsl_rx_hando_det(msg);
		break;
	case RSL_MT_RF_CHAN_REL_ACK:
		if (msg_for_osmocom_dyn_ts(msg))
			osmo_fsm_inst_dispatch(msg->lchan->ts->fi, TS_EV_PDCH_DEACT_ACK, NULL);
		else
			osmo_fsm_inst_dispatch(msg->lchan->fi, LCHAN_EV_RSL_RF_CHAN_REL_ACK, NULL);
		break;
	case RSL_MT_MODE_MODIFY_ACK:
		LOG_LCHAN(msg->lchan, LOGL_DEBUG, "CHANNEL MODE MODIFY ACK\n");
		count_codecs(sign_link->trx->bts, msg->lchan);
		osmo_fsm_inst_dispatch(msg->lchan->fi, LCHAN_EV_RSL_CHAN_MODE_MODIFY_ACK, NULL);
		break;
	case RSL_MT_MODE_MODIFY_NACK:
		LOG_LCHAN(msg->lchan, LOGL_DEBUG, "CHANNEL MODE MODIFY NACK\n");
		rate_ctr_inc(rate_ctr_group_get_ctr(sign_link->trx->bts->bts_ctrs, BTS_CTR_MODE_MODIFY_NACK));
		osmo_fsm_inst_dispatch(msg->lchan->fi, LCHAN_EV_RSL_CHAN_MODE_MODIFY_NACK, NULL);
		break;
	case RSL_MT_IPAC_PDCH_ACT_ACK:
		rc = rsl_rx_ipacc_pdch(msg, "ACT ACK", TS_EV_PDCH_ACT_ACK);
		break;
	case RSL_MT_IPAC_PDCH_ACT_NACK:
		rc = rsl_rx_ipacc_pdch(msg, "ACT NACK", TS_EV_PDCH_ACT_NACK);
		break;
	case RSL_MT_IPAC_PDCH_DEACT_ACK:
		rc = rsl_rx_ipacc_pdch(msg, "DEACT ACK", TS_EV_PDCH_DEACT_ACK);
		break;
	case RSL_MT_IPAC_PDCH_DEACT_NACK:
		rc = rsl_rx_ipacc_pdch(msg, "DEACT NACK", TS_EV_PDCH_DEACT_NACK);
		break;
	case RSL_MT_PHY_CONTEXT_CONF:
	case RSL_MT_PREPROC_MEAS_RES:
	case RSL_MT_TALKER_DET:
	case RSL_MT_LISTENER_DET:
	case RSL_MT_REMOTE_CODEC_CONF_REP:
	case RSL_MT_MR_CODEC_MOD_ACK:
	case RSL_MT_MR_CODEC_MOD_NACK:
	case RSL_MT_MR_CODEC_MOD_PER:
		LOG_LCHAN(msg->lchan, LOGL_NOTICE, "Unimplemented Abis RSL DChan msg 0x%02x\n",
			  rslh->c.msg_type);
		rate_ctr_inc(rate_ctr_group_get_ctr(sign_link->trx->bts->bts_ctrs, BTS_CTR_RSL_UNKNOWN));
		break;
	default:
		LOG_LCHAN(msg->lchan, LOGL_NOTICE, "Unknown Abis RSL DChan msg 0x%02x\n",
			  rslh->c.msg_type);
		rate_ctr_inc(rate_ctr_group_get_ctr(sign_link->trx->bts->bts_ctrs, BTS_CTR_RSL_UNKNOWN));
		return -EINVAL;
	}

	return rc;
}

static int rsl_rx_error_rep(struct msgb *msg)
{
	struct abis_rsl_common_hdr *rslh = msgb_l2(msg);
	struct tlv_parsed tp;
	struct e1inp_sign_link *sign_link = msg->dst;

	if (msgb_l2len(msg) < sizeof(*rslh))
		return -EINVAL;

	if (rsl_tlv_parse(&tp, rslh->data, msgb_l2len(msg) - sizeof(*rslh)) < 0) {
		LOGP(DRSL, LOGL_ERROR, "%s Failed to parse RSL %s\n",
		     gsm_trx_name(sign_link->trx), rsl_or_ipac_msg_name(rslh->msg_type));
		return -EINVAL;
	}

	LOGP(DRSL, LOGL_ERROR, "%s ERROR REPORT%s\n",
	     gsm_trx_name(sign_link->trx), rsl_cause_name(&tp));

	return 0;
}

static int rsl_rx_resource_indication(struct msgb *msg)
{
	struct abis_rsl_common_hdr *rslh = msgb_l2(msg);
	struct tlv_parsed tp;
	struct e1inp_sign_link *sign_link = msg->dst;
	struct tlv_p_entry *res_info_ie;
	struct gsm_bts_trx *trx = sign_link->trx;
	struct gsm_lchan *lchan;
	int ts_nr;
	int i;

	LOGP(DRSL, LOGL_DEBUG, "%s Rx Resource Indication\n", gsm_trx_name(trx));

	/* First clear out all ratings, because only the last resource indication counts. If we can't parse the message,
	 * then there are no ratings. */
	for (ts_nr = 0; ts_nr < TRX_NR_TS; ts_nr++) {
		struct gsm_bts_trx_ts *ts = &trx->ts[ts_nr];
		ts_for_n_lchans(lchan, ts, ts->max_lchans_possible) {
			lchan->interf_dbm = INTERF_DBM_UNKNOWN;
			lchan->interf_band = INTERF_BAND_UNKNOWN;
		}
	}

	if (rsl_tlv_parse(&tp, rslh->data, msgb_l2len(msg) - sizeof(*rslh)) < 0) {
		LOGP(DRSL, LOGL_ERROR, "%s Failed to parse RSL %s\n",
		     gsm_trx_name(trx), rsl_or_ipac_msg_name(rslh->msg_type));
		return -EINVAL;
	}

	res_info_ie = TLVP_GET(&tp, RSL_IE_RESOURCE_INFO);
	if (!res_info_ie) {
		LOGP(DRSL, LOGL_ERROR, "Rx Resource Indication: missing Resource Info IE\n");
		return -EINVAL;
	}

	/* The IE value is defined in 3GPP TS 48.058 9.3.21 Resource Information:
	 * one octet channel nr, one octet interference level, channel nr, interference level, ...
	 * Where channel nr is cbits + tn (as usual),
	 * and interference level is a 3bit value in the most significant bits of the octet.
	 * Evaluate each pair and update interference ratings for all lchans in this trx. */

	/* There must be an even amount of octets in the value */
	if (res_info_ie->len & 1) {
		LOGP(DRSL, LOGL_ERROR, "Rx Resource Indication: Resource Info IE has odd length\n");
		return -EINVAL;
	}

	/* Now iterate the reported levels and update corresponding lchans.
	 * Note that an empty res_info_ie can also make sense, if no lchans are idle and no interference ratings are
	 * present. The practical effect of the message then is to invalidate previous interference ratings. */
	for (i = 0; i < res_info_ie->len; i += 2) {
		struct gsm_bts *bts = trx->bts;
		uint8_t chan_nr = res_info_ie->val[i];
		uint8_t interf_band = res_info_ie->val[i + 1] >> 5;

		lchan = lchan_lookup(trx, chan_nr, "Abis RSL Rx Resource Indication: ");
		if (!lchan)
			continue;

		/* Store the actual received index */
		lchan->interf_band = interf_band;
		/* Clamp the index to 5 before accessing array of interference band bounds */
		interf_band = OSMO_MIN(interf_band, ARRAY_SIZE(bts->interf_meas_params_used.bounds_dbm)-1);
		/* FIXME: when testing with ip.access nanoBTS, we observe a value range of 1..6. According to spec, it
		 * seems like values 0..5 are intended: 3GPP TS 48.058 9.3.21 Resource Information says:
		 * "The Interf Band field (bits 6-8) indicates in binary the interference level expressed as one of five
		 * possible interference level bands as defined by O&M."
		 * and 3GPP TS 52.021 9.4.25 "Interference level Boundaries" (OML) defines values 0, X1, X2, X3, X4, X5.
		 * If nanoBTS sends 6, the above code clamps it to 5, so that we lose one band in accuracy. */
		lchan->interf_dbm = -((int16_t)bts->interf_meas_params_used.bounds_dbm[interf_band]);
	}

	return 0;
}

static int abis_rsl_rx_trx(struct msgb *msg)
{
	struct abis_rsl_common_hdr *rslh = msgb_l2(msg);
	struct e1inp_sign_link *sign_link = msg->dst;
	int rc = 0;

	switch (rslh->msg_type) {
	case RSL_MT_ERROR_REPORT:
		rc = rsl_rx_error_rep(msg);
		break;
	case RSL_MT_RF_RES_IND:
		/* interference on idle channels of TRX */
		rc = rsl_rx_resource_indication(msg);
		break;
	case RSL_MT_OVERLOAD:
		/* indicate CCCH / ACCH / processor overload */
		LOGP(DRSL, LOGL_ERROR, "%s CCCH/ACCH/CPU Overload\n",
		     gsm_trx_name(sign_link->trx));
		break;
	case 0x42: /* Nokia specific: SI End ACK */
		LOGP(DRSL, LOGL_INFO, "Nokia SI End ACK\n");
		break;
	case 0x43: /* Nokia specific: SI End NACK */
		LOGP(DRSL, LOGL_INFO, "Nokia SI End NACK\n");
		break;
	default:
		LOGP(DRSL, LOGL_NOTICE, "%s Unknown Abis RSL TRX message "
			"type 0x%02x\n", gsm_trx_name(sign_link->trx), rslh->msg_type);
		rate_ctr_inc(rate_ctr_group_get_ctr(sign_link->trx->bts->bts_ctrs, BTS_CTR_RSL_UNKNOWN));
		return -EINVAL;
	}
	return rc;
}

/* Format an IMM ASS REJ according to 04.08 Chapter 9.1.20 */
static int rsl_send_imm_ass_rej(struct gsm_bts *bts,
				struct gsm48_req_ref *rqd_ref,
				uint8_t wait_ind)
{
	uint8_t buf[GSM_MACBLOCK_LEN];
	struct gsm48_imm_ass_rej *iar = (struct gsm48_imm_ass_rej *)buf;

	/* create IMMEDIATE ASSIGN REJECT 04.08 message */
	memset(iar, 0, sizeof(*iar));
	iar->proto_discr = GSM48_PDISC_RR;
	iar->msg_type = GSM48_MT_RR_IMM_ASS_REJ;
	iar->page_mode = GSM48_PM_SAME;

	/*
	 * Set all request references and wait indications to the same value.
	 * 3GPP TS 44.018 v4.5.0 release 4 (section 9.1.20.2) requires that
	 * we duplicate reference and wait indication to fill the message.
	 * The BTS will aggregate up to 4 of our ASS REJ messages if possible.
	 */
	memcpy(&iar->req_ref1, rqd_ref, sizeof(iar->req_ref1));
	iar->wait_ind1 = wait_ind;
	memcpy(&iar->req_ref2, rqd_ref, sizeof(iar->req_ref2));
	iar->wait_ind2 = wait_ind;
	memcpy(&iar->req_ref3, rqd_ref, sizeof(iar->req_ref3));
	iar->wait_ind3 = wait_ind;
	memcpy(&iar->req_ref4, rqd_ref, sizeof(iar->req_ref4));
	iar->wait_ind4 = wait_ind;

	/* we need to subtract 1 byte from sizeof(*iar) since ia includes the l2_plen field */
	iar->l2_plen = GSM48_LEN2PLEN((sizeof(*iar)-1));

	/* IAR Rest Octets:
	 *   0... .... = Extended RA: Not Present
	 *   .0.. .... = Extended RA: Not Present
	 *   ..0. .... = Extended RA: Not Present
	 *   ...0 .... = Extended RA: Not Present
	 *   .... L... = Additions in Rel-13: Not Present */
	iar->rest[0] = GSM_MACBLOCK_PADDING & 0x0f;

	return rsl_imm_assign_cmd(bts, sizeof(*iar) + 1, buf);
}

int rsl_tx_imm_ass_rej(struct gsm_bts *bts, struct gsm48_req_ref *rqd_ref)
{
	uint8_t wait_ind;
	wait_ind = bts->T3122;
	if (!wait_ind)
		wait_ind = osmo_tdef_get(bts->network->T_defs, 3122, OSMO_TDEF_S, -1);
	if (!wait_ind)
		wait_ind = GSM_T3122_DEFAULT;
	/* The BTS will gather multiple CHAN RQD and reject up to 4 MS at the same time. */
	return rsl_send_imm_ass_rej(bts, rqd_ref, wait_ind);
}

struct chan_rqd {
	struct llist_head entry;
	struct gsm_bts *bts;
	struct gsm48_req_ref ref;
	enum gsm_chreq_reason_t reason;
	uint8_t ta;
	/* set to true to mark that the release of the release_lchan is in progress */
	struct gsm_lchan *release_lchan;
	time_t timestamp;
};

/* Handle packet channel rach requests */
static int rsl_rx_pchan_rqd(struct chan_rqd *rqd)
{
	uint8_t t1, t2, t3;
	uint32_t fn;
	uint8_t rqd_ta;
	uint8_t is_11bit;

	/* Process rach request and forward contained information to PCU */
	if (rqd->ref.ra == 0x7F) {
		is_11bit = 1;

		/* FIXME: Also handle 11 bit rach requests */
		LOGP(DRSL, LOGL_ERROR, "BTS %d eleven bit access burst not supported yet!\n",rqd->bts->nr);
		return -EINVAL;
	} else {
		is_11bit = 0;
		t1 = rqd->ref.t1;
		t2 = rqd->ref.t2;
		t3 = rqd->ref.t3_low | (rqd->ref.t3_high << 3);
		fn = (51 * ((t3-t2) % 26) + t3 + 51 * 26 * t1);
		rqd_ta = rqd->ta;
	}

	return pcu_tx_rach_ind(rqd->bts, rqd_ta, rqd->ref.ra, fn, is_11bit,
			       GSM_L1_BURST_TYPE_ACCESS_0);
}

/* Protect against RACH DoS attack: If an excessive amount of RACH requests queues up it is likely that the current BTS
 * is under RACH DoS attack. To prevent excessive memory usage, remove all expired or at least one of the oldest channel
 * requests from the queue to prevent the queue from growing indefinetly. */
static void reduce_rach_dos(struct gsm_bts *bts)
{
	int rlt = gsm_bts_get_radio_link_timeout(bts);
	time_t timestamp_current = time(NULL);
	struct chan_rqd *rqd;
	struct chan_rqd *rqd_tmp;
	unsigned int rqd_count = 0;

	/* Drop all expired channel requests in the list */
	llist_for_each_entry_safe(rqd, rqd_tmp, &bts->chan_rqd_queue, entry) {
		/* If the channel request is older than the radio link timeout we drop it. This also means that the
		 * queue is under its overflow limit again. */
		if (timestamp_current - rqd->timestamp > rlt) {
			LOG_BTS(bts, DRSL, LOGL_INFO, "CHAN RQD: tossing expired channel request"
				"(ra=0x%02x, neci=0x%02x, chreq_reason=0x%02x)\n",
				rqd->ref.ra, bts->network->neci, rqd->reason);
			llist_del(&rqd->entry);
			talloc_free(rqd);
		} else {
			rqd_count++;
		}
	}

	/* If we find more than 255 (256) unexpired channel requests in the queue it is very likely that there is a
	 * problem with RACH dos on this BTS. We drop the first entry in the list to clip the growth of the list. */
	if (rqd_count > 255) {
		LOG_BTS(bts, DRSL, LOGL_INFO, "CHAN RQD: more than 255 queued RACH requests -- RACH DoS attack?\n");
		rqd = llist_first_entry(&bts->chan_rqd_queue, struct chan_rqd, entry);
		llist_del(&rqd->entry);
		talloc_free(rqd);
	}
}

/* Flush all channel requests pending on this BTS */
void abis_rsl_chan_rqd_queue_flush(struct gsm_bts *bts)
{
	struct chan_rqd *rqd;
	struct chan_rqd *rqd_tmp;

	llist_for_each_entry_safe(rqd, rqd_tmp, &bts->chan_rqd_queue, entry) {
		llist_del(&rqd->entry);
		talloc_free(rqd);
	}
}

/* MS has requested a channel on the RACH */
static int rsl_rx_chan_rqd(struct msgb *msg)
{
	struct e1inp_sign_link *sign_link = msg->dst;
	struct gsm_bts *bts = sign_link->trx->bts;
	struct abis_rsl_dchan_hdr *rqd_hdr = msgb_l2(msg);
	struct chan_rqd *rqd;

	reduce_rach_dos(bts);

	rqd = talloc_zero(bts, struct chan_rqd);
	OSMO_ASSERT(rqd);

	rqd->bts = bts;
	rqd->timestamp = time(NULL);

	/* parse request reference to be used in immediate assign */
	if (rqd_hdr->data[0] != RSL_IE_REQ_REFERENCE) {
		talloc_free(rqd);
		return -EINVAL;
	}
	memcpy(&rqd->ref, &rqd_hdr->data[1], sizeof(rqd->ref));

	/* parse access delay and use as TA */
	if (rqd_hdr->data[sizeof(struct gsm48_req_ref)+1] != RSL_IE_ACCESS_DELAY) {
		talloc_free(rqd);
		return -EINVAL;
	}
	rqd->ta = rqd_hdr->data[sizeof(struct gsm48_req_ref)+2];
	if (rqd->ta > bts->rach_max_delay) {
		LOG_BTS(bts, DRSL, LOGL_INFO, "Ignoring CHAN RQD: Access Delay(%d) greater than %u\n",
			rqd->ta, bts->rach_max_delay);
		rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_CHREQ_MAX_DELAY_EXCEEDED));
		talloc_free(rqd);
		return -EINVAL;
	}

	/* Determine channel request cause code */
	rqd->reason = get_reason_by_chreq(rqd->ref.ra, bts->network->neci);
	LOG_BTS(bts, DRSL, LOGL_INFO, "CHAN RQD: reason: %s (ra=0x%02x, neci=0x%02x, chreq_reason=0x%02x)\n",
		get_value_string(gsm_chreq_descs, rqd->reason), rqd->ref.ra, bts->network->neci, rqd->reason);

	rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_CHREQ_TOTAL));
	switch (rqd->reason) {
	case GSM_CHREQ_REASON_EMERG:
		rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_CHREQ_ATTEMPTED_EMERG));
		break;
	case GSM_CHREQ_REASON_CALL:
		rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_CHREQ_ATTEMPTED_CALL));
		break;
	case GSM_CHREQ_REASON_LOCATION_UPD:
		rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_CHREQ_ATTEMPTED_LOCATION_UPD));
		break;
	case GSM_CHREQ_REASON_PAG:
		rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_CHREQ_ATTEMPTED_PAG));
		break;
	case GSM_CHREQ_REASON_PDCH:
		rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_CHREQ_ATTEMPTED_PDCH));
		break;
	case GSM_CHREQ_REASON_OTHER:
		rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_CHREQ_ATTEMPTED_OTHER));
		break;
	default:
		rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_CHREQ_ATTEMPTED_UNKNOWN));
		break;
	}

	/* Block emergency calls if we explicitly disable them via sysinfo. */
	if (rqd->reason == GSM_CHREQ_REASON_EMERG) {
		if (bts->si_common.rach_control.t2 & 0x4) {
			LOG_BTS(bts, DRSL, LOGL_NOTICE, "CHAN RQD: MS attempts EMERGENCY CALL although EMERGENCY CALLS "
				"are not allowed in sysinfo (cfg: network / bts / rach emergency call allowed 0)\n");
			rsl_tx_imm_ass_rej(bts, &rqd->ref);
			talloc_free(rqd);
			return 0;
		}
	}

	/* Enqueue request */
	llist_add_tail(&rqd->entry, &bts->chan_rqd_queue);

	/* Forward the request directly. Most request will be finished with one attempt so no queuing will be
	 * necessary. */
	abis_rsl_chan_rqd_queue_poll(bts);

	return 0;
}

/* Find any busy TCH/H or TCH/F lchan */
static struct gsm_lchan *get_any_lchan(struct gsm_bts *bts)
{
	int trx_nr;
	int ts_nr;
	struct gsm_bts_trx *trx;
	struct gsm_bts_trx_ts *ts;
	struct gsm_lchan *lchan_est = NULL;
	struct gsm_lchan *lchan_any = NULL;
	struct gsm_lchan *lchan;

	for (trx_nr = 0; trx_nr < bts->num_trx; trx_nr++) {
		trx = gsm_bts_trx_num(bts, trx_nr);
		for (ts_nr = 0; ts_nr < TRX_NR_TS; ts_nr++) {
			ts = &trx->ts[ts_nr];
			ts_for_n_lchans(lchan, ts, ts->max_primary_lchans) {
				if (lchan->type == GSM_LCHAN_TCH_F || lchan->type == GSM_LCHAN_TCH_H) {
					if (lchan->fi->state == LCHAN_ST_ESTABLISHED) {
						if (!lchan_est || bts->chan_alloc_chan_req_reverse)
							lchan_est = lchan;
					} else {
						if (!lchan_any || bts->chan_alloc_chan_req_reverse)
							lchan_any = lchan;
					}
				}
			}
		}
	}

	if (lchan_est)
		return lchan_est;
	else if (lchan_any)
		return lchan_any;
	return NULL;
}

/* Ensure that an incoming emergency call gets priority, if all voice channels are busy, terminate one regular call.
 * Return true if freeing of a busy lchan is in progress, but not done yet, return false when done (either successfully
 * or unsuccessfully). */
static bool force_free_lchan_for_emergency(struct chan_rqd *rqd)
{
	/* If the request is not about an emergency call, we may exit early, without doing anything. */
	if (rqd->reason != GSM_CHREQ_REASON_EMERG)
              return false;

	/* First check the situation on the BTS, if we have TCH/H or TCH/F resources available for another (EMERGENCY)
	 * call. If yes, then no (further) action has to be carried out. */
	if (lchan_avail_by_type(rqd->bts, GSM_LCHAN_TCH_F, SELECT_FOR_MS_CHAN_REQ, NULL, true)) {
		LOG_BTS(rqd->bts, DRSL, LOGL_NOTICE,
			"CHAN RQD/EMERGENCY-PRIORITY: at least one TCH/F is (now) available!\n");
		return false;
	}
	if (lchan_avail_by_type(rqd->bts, GSM_LCHAN_TCH_H, SELECT_FOR_MS_CHAN_REQ, NULL, true)) {
		LOG_BTS(rqd->bts, DRSL, LOGL_NOTICE,
			"CHAN RQD/EMERGENCY-PRIORITY: at least one TCH/H is (now) available!\n");
		return false;
	}

	/* No free TCH/F or TCH/H was found, we now select one of the busy lchans and initate a release on that lchan.
	 * This will take a short amount of time. We need to come back and check regulary to see if we managed to
	 * free up another lchan. */
	if (!rqd->release_lchan) {
		struct gsm_lchan *release_lchan;
		/* Pick any busy TCH/F or TCH/H lchan and inititate a channel
		 * release to make room for the incoming emergency call */
		rqd->release_lchan = release_lchan = get_any_lchan(rqd->bts);
		if (!release_lchan) {
			/* It can not happen that we first find out that there
			 * is no TCH/H or TCH/F available and at the same time
			 * we ware unable to find any busy TCH/H or TCH/F. In
			 * this case, the BTS probably does not have any
			 * voice channels configured? */
			LOG_BTS(rqd->bts, DRSL, LOGL_NOTICE,
				"CHAN RQD/EMERGENCY-PRIORITY: no TCH/H or TCH/F available - check VTY config!\n");
			return false;
		}

		LOG_BTS(rqd->bts, DRSL, LOGL_NOTICE,
			"CHAN RQD/EMERGENCY-PRIORITY: inducing termination of lchan %s (state:%s) in favor of incoming EMERGENCY CALL!\n",
			gsm_lchan_name(release_lchan), osmo_fsm_inst_state_name(release_lchan->fi));

		/* Make sure the Clear Request to the MSC has the proper cause */
		if (release_lchan->conn)
			gscon_bssmap_clear(release_lchan->conn, GSM0808_CAUSE_PREEMPTION);
		/* The gscon FSM would only release the lchan after the MSC responds with a Clear Command.
		 * But we need it released right now. Also with the right RR cause. */
		lchan_release(release_lchan, !!(release_lchan->conn), true, GSM48_RR_CAUSE_PREMPTIVE_REL,
			      gscon_last_eutran_plmn(release_lchan->conn));

		/* Also release any overlapping VAMOS multiplexes on this lchan */
		release_lchan = gsm_lchan_primary_to_vamos(release_lchan);
		if (release_lchan)
			lchan_release(release_lchan, !!(release_lchan->conn), true, GSM48_RR_CAUSE_PREMPTIVE_REL,
				      gscon_last_eutran_plmn(release_lchan->conn));
	} else {
		/* if BTS has shut down, give up... */
		if (rqd->release_lchan->ts->fi->state == TS_ST_NOT_INITIALIZED)
			return false;

		OSMO_ASSERT(rqd->release_lchan->fi);

		LOG_BTS(rqd->bts, DRSL, LOGL_NOTICE,
			"CHAN RQD/EMERGENCY-PRIORITY: still terminating lchan %s (state:%s) in favor of incoming EMERGENCY CALL!\n",
			gsm_lchan_name(rqd->release_lchan), osmo_fsm_inst_state_name(rqd->release_lchan->fi));

		/* If the channel was released in error (not established), the
		 * lchan FSM automatically blocks the LCHAN for a short time.
		 * This is not acceptable in an emergency situation, so we skip
		 * this waiting period. */
		if (rqd->release_lchan->fi->state == LCHAN_ST_WAIT_AFTER_ERROR)
			lchan_fsm_skip_error(rqd->release_lchan);
	}

	/* We are still in the process of releasing a busy lchan in favvor of the incoming emergency call. */
	return true;
}

struct gsm_lchan *_select_sdcch_for_call(struct gsm_bts *bts, const struct chan_rqd *rqd, enum gsm_chan_t lctype)
{
	struct gsm_lchan *lchan = NULL;
	int free_tchf, free_tchh;
	bool needs_dyn_switch;

	lchan = lchan_avail_by_type(bts, GSM_LCHAN_SDCCH, SELECT_FOR_MS_CHAN_REQ, NULL, false);
	if (!lchan)
		return NULL;

	needs_dyn_switch = lchan->ts->pchan_on_init == GSM_PCHAN_OSMO_DYN &&
					lchan->ts->pchan_is != GSM_PCHAN_SDCCH8_SACCH8C;

	free_tchf = bts->chan_counts.val[CHAN_COUNTS1_ALL][CHAN_COUNTS2_FREE][GSM_LCHAN_TCH_F];
	free_tchh = bts->chan_counts.val[CHAN_COUNTS1_ALL][CHAN_COUNTS2_FREE][GSM_LCHAN_TCH_H];
	if (free_tchf == 0 && free_tchh == 0) {
		LOG_BTS(bts, DRSL, LOGL_INFO,
			"CHAN RQD: 0x%x Requesting %s reason=call but no TCH available\n",
			rqd->ref.ra, gsm_lchant_name(lctype));
		return NULL;
	}

	/* There's a TCH available and we'll not switch any dyn ts, so we are
	 * fine (we can switch one of them to SDCCH8 and still have one left) */
	if (!needs_dyn_switch)
		goto select_lchan;

	/* We need to switch, but there's at least 2 TCH TS available so we are fine: */
	if (free_tchf > 1 || free_tchh > 2)
		goto select_lchan;

	/* At this point (needs_dyn_switch==true), following cases are possible:
	 * [A] H=0, F=1
	 * [B] H=1, F=0
	 * [B] H=1, F=1
	 * [C] H=2, F=1
	 * If condition [C] is met, it means there's 1 dynamic TS (because a dyn
	 * TS is counted both as 1 free TCH/F and 2 free TCH/H at the same time)
	 * and it's the same as the dynamic TS available for SDCCH requiring
	 * switch, so selecting it would basically leave us without free TCH, so
	 * avoid selecting it. Regarding the other conditions, it basically
	 * results in them being different TS than the one we want to switch, so
	 * we are fine selecting the TS for SDCCH */
	if (free_tchf == 1 && free_tchh == 2) {
		LOG_BTS(bts, DRSL, LOGL_INFO,
			"CHAN RQD: 0x%x Requesting %s reason=call but dyn TS switch to "
			"SDCCH would starve the single available TCH timeslot\n",
			rqd->ref.ra, gsm_lchant_name(lctype));
		return NULL;
	}

select_lchan:
	lchan_select_set_type(lchan, GSM_LCHAN_SDCCH);
	return lchan;
}

void abis_rsl_chan_rqd_queue_poll(struct gsm_bts *bts)
{
	struct lchan_activate_info info;
	enum gsm_chan_t lctype;
	struct gsm_lchan *lchan = NULL;
	struct chan_rqd *rqd;

	rqd = llist_first_entry_or_null(&bts->chan_rqd_queue, struct chan_rqd, entry);
	if (!rqd)
		return;

	/* Handle PDCH related rach requests (in case of BSC-co-located-PCU) */
	if (rqd->reason == GSM_CHREQ_REASON_PDCH) {
		rsl_rx_pchan_rqd(rqd);
		return;
	}

	/* Ensure that emergency calls will get priority over regular calls, however releasing
	 * lchan in favor of an emergency call may take some time, so we exit here. The lchan_fsm
	 * will poll again when an lchan becomes available. */
	if (force_free_lchan_for_emergency(rqd))
		return;

	/* determine channel type (SDCCH/TCH_F/TCH_H) based on
	 * request reference RA */
	lctype = get_ctype_by_chreq(bts->network, rqd->ref.ra);

	/* check availability / allocate channel
	 *
	 * - First check for EMERGENCY call attempts,
	 * - then try to allocate SDCCH.
	 * - If SDCCH is not available, try a TCH/H (less bandwidth).
	 * - If there is still no channel available, try a TCH/F.
	 *
	 */

	if (rqd->reason == GSM_CHREQ_REASON_CALL) {
		 lchan = _select_sdcch_for_call(bts, rqd, lctype);
	} else if (rqd->reason != GSM_CHREQ_REASON_EMERG) {
		lchan = lchan_select_by_type(bts, GSM_LCHAN_SDCCH,
					     SELECT_FOR_MS_CHAN_REQ,
					     NULL);
	}
	/* else: Emergency calls will be put on a free TCH/H or TCH/F directly
	 * in the code below, all other channel requests will get an SDCCH first
	 * (if possible). */

	if (bts->chan_alloc_tch_signalling_policy == BTS_TCH_SIGNALLING_ALWAYS ||
	    (bts->chan_alloc_tch_signalling_policy == BTS_TCH_SIGNALLING_VOICE &&
	     gsm_chreq_reason_is_voicecall(rqd->reason)) ||
	    (bts->chan_alloc_tch_signalling_policy == BTS_TCH_SIGNALLING_EMERG &&
	     rqd->reason == GSM_CHREQ_REASON_EMERG)) {
		if (!lchan) {
			LOG_BTS(bts, DRSL, LOGL_NOTICE, "CHAN RQD[%s]: no resources for %s 0x%x, retrying with %s\n",
				get_value_string(gsm_chreq_descs, rqd->reason), gsm_lchant_name(GSM_LCHAN_SDCCH),
				rqd->ref.ra, gsm_lchant_name(GSM_LCHAN_TCH_H));
			lchan = lchan_select_by_type(bts, GSM_LCHAN_TCH_H,
						     SELECT_FOR_MS_CHAN_REQ,
						     NULL);
		}
		if (!lchan) {
			LOG_BTS(bts, DRSL, LOGL_NOTICE, "CHAN RQD[%s]: no resources for %s 0x%x, retrying with %s\n",
				get_value_string(gsm_chreq_descs, rqd->reason), gsm_lchant_name(GSM_LCHAN_SDCCH),
				rqd->ref.ra, gsm_lchant_name(GSM_LCHAN_TCH_F));
			lchan = lchan_select_by_type(bts, GSM_LCHAN_TCH_F,
						     SELECT_FOR_MS_CHAN_REQ,
						     NULL);
		}
	}
	if (!lchan) {
		LOG_BTS(bts, DRSL, LOGL_NOTICE, "CHAN RQD[%s]: no resources for %s 0x%x\n",
			get_value_string(gsm_chreq_descs, rqd->reason), gsm_lchant_name(lctype), rqd->ref.ra);
		rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_CHREQ_NO_CHANNEL));
		rsl_tx_imm_ass_rej(bts, &rqd->ref);
		llist_del(&rqd->entry);
		talloc_free(rqd);
		return;
	}

	/* save the RACH data as we need it after the CHAN ACT ACK */
	lchan->rqd_ref = talloc_zero(bts, struct gsm48_req_ref);
	OSMO_ASSERT(lchan->rqd_ref);

	*(lchan->rqd_ref) = rqd->ref;

	LOG_LCHAN(lchan, LOGL_DEBUG, "MS: Channel Request: reason=%s ra=0x%02x ta=%d\n",
		  gsm_chreq_name(rqd->reason), rqd->ref.ra, rqd->ta);
	info = (struct lchan_activate_info){
		.activ_for = ACTIVATE_FOR_MS_CHANNEL_REQUEST,
		.chreq_reason = rqd->reason,
		.ch_mode_rate = {
			.chan_mode = GSM48_CMODE_SIGN,
			.chan_rate = CH_RATE_SDCCH,
		},
		.ta = rqd->ta,
		.ta_known = true,
		.imm_ass_time = bts->imm_ass_time,
	};

	lchan_activate(lchan, &info);
	llist_del(&rqd->entry);
	talloc_free(rqd);
	return;
}

static void imm_ass_rate_ctr(struct gsm_lchan *lchan)
{
	struct gsm_bts *bts = lchan->ts->trx->bts;
	rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_CHREQ_SUCCESSFUL));
	switch (lchan->activate.info.chreq_reason) {
	case GSM_CHREQ_REASON_EMERG:
		rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_CHREQ_SUCCESSFUL_EMERG));
		break;
	case GSM_CHREQ_REASON_CALL:
		rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_CHREQ_SUCCESSFUL_CALL));
		break;
	case GSM_CHREQ_REASON_LOCATION_UPD:
		rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_CHREQ_SUCCESSFUL_LOCATION_UPD));
		break;
	case GSM_CHREQ_REASON_PAG:
		rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_CHREQ_SUCCESSFUL_PAG));
		break;
	case GSM_CHREQ_REASON_PDCH:
		rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_CHREQ_SUCCESSFUL_PDCH));
		break;
	case GSM_CHREQ_REASON_OTHER:
		rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_CHREQ_SUCCESSFUL_OTHER));
		break;
	default:
		rate_ctr_inc(rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_CHREQ_SUCCESSFUL_UNKNOWN));
		break;
	}
}

int rsl_tx_imm_assignment(struct gsm_lchan *lchan)
{
	int rc;
	struct gsm_bts *bts = lchan->ts->trx->bts;
	uint8_t buf[GSM_MACBLOCK_LEN];
	struct gsm48_imm_ass *ia = (struct gsm48_imm_ass *) buf;
	enum gsm_phys_chan_config pchan;

	/* create IMMEDIATE ASSIGN 04.08 message */
	memset(ia, 0, sizeof(*ia));
	/* we set ia->l2_plen once we know the length of the MA below */
	ia->proto_discr = GSM48_PDISC_RR;
	ia->msg_type = GSM48_MT_RR_IMM_ASS;
	ia->page_mode = GSM48_PM_SAME;

	/* In case the dyn TS is not ready yet, ts->pchan_is still reflects the previous pchan type; so get the pchan
	 * kind from lchan->type, which already reflects the target type. This only happens for dynamic timeslots.
	 * gsm_pchan_by_lchan_type() isn't always exact, which is fine for dyn TS with their limited pchan kinds. */
	if (lchan_state_is(lchan, LCHAN_ST_WAIT_TS_READY))
		pchan = gsm_pchan_by_lchan_type(lchan->type);
	else
		pchan = lchan->ts->pchan_is;
	rc = gsm48_lchan_and_pchan2chan_desc(&ia->chan_desc, lchan, pchan, lchan->tsc, true);
	if (rc) {
		LOG_LCHAN(lchan, LOGL_ERROR, "Error encoding Channel Number\n");
		return rc;
	}

	/* use request reference extracted from CHAN_RQD */
	memcpy(&ia->req_ref, lchan->rqd_ref, sizeof(ia->req_ref));
	ia->timing_advance = lchan->last_ta;
	if (!lchan->ts->hopping.enabled) {
		ia->mob_alloc_len = 0;
	} else {
		ia->mob_alloc_len = lchan->ts->hopping.ma_len;
		memcpy(ia->mob_alloc, lchan->ts->hopping.ma_data, ia->mob_alloc_len);
	}
	/* we need to subtract 1 byte from sizeof(*ia) since ia includes the l2_plen field */
	ia->l2_plen = GSM48_LEN2PLEN((sizeof(*ia)-1) + ia->mob_alloc_len);

	/* send IMMEDIATE ASSIGN CMD on RSL to BTS (to send on CCCH to MS) */
	rc = rsl_imm_assign_cmd(bts, sizeof(*ia)+ia->mob_alloc_len, (uint8_t *) ia);

	if (!rc)
		imm_ass_rate_ctr(lchan);

	return rc;
}

/* current load on the CCCH */
static int rsl_rx_ccch_load(struct msgb *msg)
{
	struct e1inp_sign_link *sign_link = msg->dst;
	struct abis_rsl_dchan_hdr *rslh = msgb_l2(msg);
	struct ccch_signal_data sd;

	sd.bts = sign_link->trx->bts;
	sd.rach_slot_count = UINT16_MAX;
	sd.rach_busy_count = UINT16_MAX;
	sd.rach_access_count = UINT16_MAX;

	switch (rslh->data[0]) {
	case RSL_IE_PAGING_LOAD:
		sd.pg_buf_space = rslh->data[1] << 8 | rslh->data[2];
		if (is_ipaccess_bts(sign_link->trx->bts) && sd.pg_buf_space == UINT16_MAX) {
			sd.pg_buf_space = paging_estimate_available_slots(sd.bts, sd.bts->ccch_load_ind_period);
		}
		paging_update_buffer_space(sign_link->trx->bts, sd.pg_buf_space);
		osmo_signal_dispatch(SS_CCCH, S_CCCH_PAGING_LOAD, &sd);
		break;
	case RSL_IE_RACH_LOAD:
		if (msgb_length(msg) >= 7) {
			int32_t busy_percent, access_percent;
			/* build data for signal */
			sd.rach_slot_count = rslh->data[2] << 8 | rslh->data[3];
			sd.rach_busy_count = rslh->data[4] << 8 | rslh->data[5];
			sd.rach_access_count = rslh->data[6] << 8 | rslh->data[7];
			/* update stats group */
			if (sd.rach_slot_count) {
				access_percent = (int32_t) sd.rach_access_count * 100 / (int32_t) sd.rach_slot_count;
				busy_percent = (int32_t) sd.rach_busy_count * 100 / (int32_t) sd.rach_slot_count;
			} else {
				access_percent = 0;
				busy_percent = 100;
			}

			osmo_stat_item_set(osmo_stat_item_group_get_item(sd.bts->bts_statg, BTS_STAT_RACH_BUSY), busy_percent);
			osmo_stat_item_set(osmo_stat_item_group_get_item(sd.bts->bts_statg, BTS_STAT_RACH_ACCESS), access_percent);
			/* dispatch signal */
			osmo_signal_dispatch(SS_CCCH, S_CCCH_RACH_LOAD, &sd);
		}
		break;
	default:
		break;
	}

	return 0;
}

/* 8.5.9 current load on the CBCH (Cell Broadcast) */
static int rsl_rx_cbch_load(struct msgb *msg)
{
	struct e1inp_sign_link *sign_link = msg->dst;
	struct abis_rsl_dchan_hdr *rslh = msgb_l2(msg);
	struct gsm_bts *bts = sign_link->trx->bts;
	bool cbch_extended = false;
	bool is_overflow = false;
	int8_t load_info;
	struct tlv_parsed tp;
	uint8_t slot_count;

	if (rsl_tlv_parse(&tp, rslh->data, msgb_l2len(msg) - sizeof(*rslh)) < 0) {
		LOGP(DRSL, LOGL_ERROR, "%s Failed to parse RSL %s\n",
		     gsm_trx_name(sign_link->trx), rsl_or_ipac_msg_name(rslh->c.msg_type));
		return -EINVAL;
	}

	if (!TLVP_PRESENT(&tp, RSL_IE_CBCH_LOAD_INFO)) {
		LOG_BTS(bts, DRSL, LOGL_ERROR, "CBCH LOAD IND without mandatory CBCH Load Info IE\n");
		return -1;
	}
	/* 9.4.43 */
	load_info = *TLVP_VAL(&tp, RSL_IE_CBCH_LOAD_INFO);
	if (load_info & 0x80)
		is_overflow = true;
	slot_count = load_info & 0x0F;

	if (TLVP_PRES_LEN(&tp, RSL_IE_SMSCB_CHAN_INDICATOR, 1) &&
	    (*TLVP_VAL(&tp, RSL_IE_SMSCB_CHAN_INDICATOR) & 0x0F) == 0x01)
		cbch_extended = true;

	return bts_smscb_rx_cbch_load_ind(bts, cbch_extended, is_overflow, slot_count);
}

/* Ericsson specific: Immediate Assign Sent */
static int rsl_rx_ericsson_imm_assign_sent(struct msgb *msg)
{
	struct e1inp_sign_link *sign_link = msg->dst;
	struct abis_rsl_dchan_hdr *dh = msgb_l2(msg);
	uint32_t tlli;

	LOGP(DRSL, LOGL_INFO, "IMM.ass sent\n");
	msgb_pull(msg, sizeof(*dh));

	/* FIXME: Move to TLV once we support defining TV types with V having len != 1 byte */
	if(msg->len < 5)
		LOGP(DRSL, LOGL_ERROR, "short IMM.ass sent message!\n");
	else if(msg->data[0] != RSL_IE_ERIC_MOBILE_ID)
		LOGP(DRSL, LOGL_ERROR, "unsupported IMM.ass message format! (please fix)\n");
	else {
		msgb_pull(msg, 1); /* drop previous data to use msg_pull_u32 */
		tlli = msgb_pull_u32(msg);
		pcu_tx_imm_ass_sent(sign_link->trx->bts, tlli);
	}
	return 0;
}

static int abis_rsl_rx_cchan(struct msgb *msg)
{
	struct e1inp_sign_link *sign_link = msg->dst;
	struct abis_rsl_dchan_hdr *rslh = msgb_l2(msg);
	struct rate_ctr_group *bts_ctrs = sign_link->trx->bts->bts_ctrs;
	int rc = 0;

	if (msgb_l2len(msg) < sizeof(*rslh))
		return -EINVAL;

	msg->lchan = lchan_lookup(sign_link->trx, rslh->chan_nr,
				  "Abis RSL rx CCHAN: ");

	switch (rslh->c.msg_type) {
	case RSL_MT_CHAN_RQD:
		/* MS has requested a channel on the RACH */
		rc = rsl_rx_chan_rqd(msg);
		break;
	case RSL_MT_CCCH_LOAD_IND:
		/* current load on the CCCH */
		rc = rsl_rx_ccch_load(msg);
		break;
	case RSL_MT_DELETE_IND:
		/* CCCH overloaded, IMM_ASSIGN was dropped */
		LOGPLCHAN(msg->lchan, DRSL, LOGL_NOTICE, "DELETE INDICATION (Downlink CCCH overload)\n");
		rate_ctr_inc(rate_ctr_group_get_ctr(bts_ctrs, BTS_CTR_RSL_DELETE_IND));
		break;
	case RSL_MT_CBCH_LOAD_IND:
		/* current load on the CBCH */
		rc = rsl_rx_cbch_load(msg);
		break;
	case RSL_MT_ERICSSON_IMM_ASS_SENT:
		rc = rsl_rx_ericsson_imm_assign_sent(msg);
		break;
	default:
		LOGP(DRSL, LOGL_NOTICE, "Unknown Abis RSL TRX message type "
			"0x%02x\n", rslh->c.msg_type);
		rate_ctr_inc(rate_ctr_group_get_ctr(bts_ctrs, BTS_CTR_RSL_UNKNOWN));
		return -EINVAL;
	}

	return rc;
}

static int rsl_rx_rll_err_ind(struct msgb *msg)
{
	struct tlv_parsed tp;
	struct abis_rsl_rll_hdr *rllh = msgb_l2(msg);
	uint8_t rlm_cause;

	if (rsl_tlv_parse(&tp, rllh->data, msgb_l2len(msg) - sizeof(*rllh)) < 0) {
		LOG_LCHAN(msg->lchan, LOGL_ERROR, "Failed to parse RSL %s\n",
			  rsl_or_ipac_msg_name(rllh->c.msg_type));
		return -EINVAL;
	}

	if (!TLVP_PRESENT(&tp, RSL_IE_RLM_CAUSE)) {
		LOG_LCHAN(msg->lchan, LOGL_ERROR, "ERROR INDICATION without mandatory cause.\n");
		return -1;
	}

	rlm_cause = *TLVP_VAL(&tp, RSL_IE_RLM_CAUSE);
	LOG_LCHAN(msg->lchan, LOGL_ERROR, "ERROR INDICATION cause=%s\n", rsl_rlm_cause_name(rlm_cause));

	rll_indication(msg->lchan, rllh->link_id, BSC_RLLR_IND_ERR_IND);

	rate_ctr_inc(rate_ctr_group_get_ctr(msg->lchan->ts->trx->bts->bts_ctrs, BTS_CTR_CHAN_RLL_ERR));

	osmo_fsm_inst_dispatch(msg->lchan->fi, LCHAN_EV_RLL_ERR_IND, &rlm_cause);

	return 0;
}

/*	ESTABLISH INDICATION, LOCATION AREA UPDATE REQUEST
	0x02, 0x06,
	0x01, 0x20,
	0x02, 0x00,
	0x0b, 0x00, 0x0f, 0x05, 0x08, ... */

static int abis_rsl_rx_rll(struct msgb *msg)
{
	struct e1inp_sign_link *sign_link = msg->dst;
	struct abis_rsl_rll_hdr *rllh = msgb_l2(msg);
	int rc = 0;
	uint8_t sapi;

	if (msgb_l2len(msg) < sizeof(*rllh))
		return -1;

	sapi = rllh->link_id & 0x7;
	msg->lchan = lchan_lookup(sign_link->trx, rllh->chan_nr, "Abis RSL rx RLL: ");
	if (OSMO_UNLIKELY(msg->lchan == NULL))
		return -1;

	switch (rllh->c.msg_type) {
	case RSL_MT_DATA_IND:
		LOG_LCHAN(msg->lchan, LOGL_DEBUG, "SAPI=%u DATA INDICATION\n", sapi);
		if (msgb_l2len(msg) >
		    sizeof(struct abis_rsl_common_hdr) + sizeof(*rllh) &&
		    rllh->data[0] == RSL_IE_L3_INFO) {
			msg->l3h = &rllh->data[3];
			return gsm0408_rcvmsg(msg, rllh->link_id);
		}
		break;
	case RSL_MT_EST_IND:
		LOG_LCHAN(msg->lchan, LOGL_DEBUG, "SAPI=%u ESTABLISH INDICATION\n", sapi);
		/* lchan is established, stop T3101 */

		/* Note: By definition the first Establish Indication must
		 * happen first on SAPI 0, once the connection on SAPI 0 is
		 * made, parallel connections on other SAPIs are permitted */
		if (sapi != 0 && msg->lchan->sapis[0] != LCHAN_SAPI_MS) {
			LOG_LCHAN(msg->lchan, LOGL_NOTICE,
				  "MS attempted to establish DCCH on SAPI=%d (expected SAPI=0)\n",
				  sapi);
			/* Note: We do not need to close the channel,
			 * since we might still get a proper Establish Ind.
			 * If not, T3101 will close the channel on timeout. */
			break;
		}

		/* Note: Check for MF SACCH on SAPI=0 (not permitted). By
		 * definition we establish a link in multiframe (MF) mode.
		 * (see also 3GPP TS 48.058, chapter 3.1. However, on SAPI=0
		 * SACCH is only allowed in UL mode, not in MF mode.
		 * (see also 3GPP TS 44.005, figure 5) So we have to drop such
		 * Establish Indications */
		if (sapi == 0 && (rllh->link_id >> 6 & 0x03) == 1) {
			LOG_LCHAN(msg->lchan, LOGL_NOTICE,
				  "MS attempted to establish an SACCH in MF mode on SAPI=0 (not permitted)\n");

			/* Note: We do not need to close the channel,
			 * since we might still get a proper Establish Ind.
			 * If not, T3101 will close the channel on timeout. */
			break;
		}

		msg->lchan->sapis[sapi] = LCHAN_SAPI_MS;
		osmo_fsm_inst_dispatch(msg->lchan->fi, LCHAN_EV_RLL_ESTABLISH_IND, msg);

		if (msgb_l2len(msg) >
		    sizeof(struct abis_rsl_common_hdr) + sizeof(*rllh) &&
		    rllh->data[0] == RSL_IE_L3_INFO) {
			msg->l3h = &rllh->data[3];
			return gsm0408_rcvmsg(msg, rllh->link_id);
		}
		break;
	case RSL_MT_EST_CONF:
		LOG_LCHAN(msg->lchan, LOGL_DEBUG, "SAPI=%u ESTABLISH CONFIRM\n", sapi);
		msg->lchan->sapis[sapi] = LCHAN_SAPI_NET;
		rll_indication(msg->lchan, rllh->link_id,
				  BSC_RLLR_IND_EST_CONF);
		break;
	case RSL_MT_REL_IND:
		/* BTS informs us of having received  DISC from MS */
		osmo_fsm_inst_dispatch(msg->lchan->fi, LCHAN_EV_RLL_REL_IND, &rllh->link_id);
		break;
	case RSL_MT_REL_CONF:
		/* BTS informs us of having received UA from MS,
		 * in response to DISC that we've sent earlier */
		osmo_fsm_inst_dispatch(msg->lchan->fi, LCHAN_EV_RLL_REL_CONF, &rllh->link_id);
		break;
	case RSL_MT_ERROR_IND:
		LOG_LCHAN(msg->lchan, LOGL_DEBUG, "SAPI=%u ERROR INDICATION\n", sapi);
		rc = rsl_rx_rll_err_ind(msg);
		break;
	case RSL_MT_UNIT_DATA_IND:
		LOG_LCHAN(msg->lchan, LOGL_NOTICE, "SAPI=%u UNIT DATA INDICATION:"
			  " unimplemented Abis RLL message type 0x%02x\n", sapi, rllh->c.msg_type);
		break;
	default:
		LOG_LCHAN(msg->lchan, LOGL_NOTICE, "SAPI=%u Unknown Abis RLL message type 0x%02x\n",
			  sapi, rllh->c.msg_type);
		rate_ctr_inc(rate_ctr_group_get_ctr(sign_link->trx->bts->bts_ctrs, BTS_CTR_RSL_UNKNOWN));
	}
	return rc;
}

/* Return an ip.access BTS speech mode value (uint8_t) or negative on error. */
int ipacc_speech_mode(enum gsm48_chan_mode tch_mode, enum gsm_chan_t type)
{
	switch (gsm48_chan_mode_to_non_vamos(tch_mode)) {
	case GSM48_CMODE_SPEECH_V1:
		switch (type) {
		case GSM_LCHAN_TCH_F:
			return 0x00;
		case GSM_LCHAN_TCH_H:
			return 0x03;
		default:
			break;
		}
		break;
	case GSM48_CMODE_SPEECH_EFR:
		switch (type) {
		case GSM_LCHAN_TCH_F:
			return 0x01;
		/* there's no half-rate EFR */
		default:
			break;
		}
		break;
	case GSM48_CMODE_SPEECH_AMR:
		switch (type) {
		case GSM_LCHAN_TCH_F:
			return 0x02;
		case GSM_LCHAN_TCH_H:
			return 0x05;
		default:
			break;
		}
		break;
	default:
		break;
	}
	return -EINVAL;
}

void ipacc_speech_mode_set_direction(uint8_t *speech_mode, bool send)
{
	const uint8_t recv_only_flag = 0x10;
	if (send)
		*speech_mode = *speech_mode & ~recv_only_flag;
	else
		*speech_mode = *speech_mode | recv_only_flag;
}

/* Return an ip.access BTS payload type value (uint8_t) or negative on error. */
int ipacc_payload_type(enum gsm48_chan_mode tch_mode, enum gsm_chan_t type)
{
	switch (gsm48_chan_mode_to_non_vamos(tch_mode)) {
	case GSM48_CMODE_SPEECH_V1:
		switch (type) {
		case GSM_LCHAN_TCH_F:
			return RTP_PT_GSM_FULL;
		case GSM_LCHAN_TCH_H:
			return RTP_PT_GSM_HALF;
		default:
			break;
		}
		break;
	case GSM48_CMODE_SPEECH_EFR:
		switch (type) {
		case GSM_LCHAN_TCH_F:
			return RTP_PT_GSM_EFR;
		/* there's no half-rate EFR */
		default:
			break;
		}
		break;
	case GSM48_CMODE_SPEECH_AMR:
		switch (type) {
		case GSM_LCHAN_TCH_F:
		case GSM_LCHAN_TCH_H:
			return RTP_PT_AMR;
		default:
			break;
		}
		break;
	default:
		break;
	}
	return -EINVAL;
}

const char *ip_to_a(uint32_t ip)
{
	struct in_addr ia;
	ia.s_addr = htonl(ip);
	return inet_ntoa(ia);
}

/* ip.access specific RSL extensions */
static void ipac_parse_rtp(struct gsm_lchan *lchan, struct tlv_parsed *tv, const char *label)
{
	struct in_addr ip;
	uint16_t port, conn_id;

	if (TLVP_PRESENT(tv, RSL_IE_IPAC_LOCAL_IP)) {
		ip.s_addr = tlvp_val32_unal(tv, RSL_IE_IPAC_LOCAL_IP);
		lchan->abis_ip.bound_ip = ntohl(ip.s_addr);
	}

	if (TLVP_PRESENT(tv, RSL_IE_IPAC_LOCAL_PORT)) {
		port = tlvp_val16_unal(tv, RSL_IE_IPAC_LOCAL_PORT);
		port = ntohs(port);
		lchan->abis_ip.bound_port = port;
	}

	if (TLVP_PRESENT(tv, RSL_IE_IPAC_CONN_ID)) {
		conn_id = tlvp_val16_unal(tv, RSL_IE_IPAC_CONN_ID);
		conn_id = ntohs(conn_id);
		lchan->abis_ip.conn_id = conn_id;
	}

	if (TLVP_PRESENT(tv, RSL_IE_IPAC_RTP_PAYLOAD2)) {
		lchan->abis_ip.rtp_payload2 =
				*TLVP_VAL(tv, RSL_IE_IPAC_RTP_PAYLOAD2);
	}

	if (TLVP_PRESENT(tv, RSL_IE_IPAC_SPEECH_MODE)) {
		lchan->abis_ip.speech_mode =
				*TLVP_VAL(tv, RSL_IE_IPAC_SPEECH_MODE);
	}

	/* Why would we receive the MGW IP and port back from the BTS, and why would we care?? */
	if (TLVP_PRESENT(tv, RSL_IE_IPAC_REMOTE_IP)) {
		ip.s_addr = tlvp_val32_unal(tv, RSL_IE_IPAC_REMOTE_IP);
		lchan->abis_ip.connect_ip = ntohl(ip.s_addr);
	}
	if (TLVP_PRESENT(tv, RSL_IE_IPAC_REMOTE_PORT)) {
		port = tlvp_val16_unal(tv, RSL_IE_IPAC_REMOTE_PORT);
		port = ntohs(port);
		lchan->abis_ip.connect_port = port;
	}

	LOG_LCHAN(lchan, LOGL_DEBUG, "Rx IPACC %s ACK:"
		  " BTS=%s:%u conn_id=%u rtp_payload2=0x%02x speech_mode=0x%02x\n",
		  label, ip_to_a(lchan->abis_ip.bound_ip), lchan->abis_ip.bound_port,
		  lchan->abis_ip.conn_id, lchan->abis_ip.rtp_payload2, lchan->abis_ip.speech_mode);
}

/*! Send Issue IPA RSL CRCX to configure the RTP port of the BTS.
 * \param[in] lchan Logical Channel for which we issue CRCX
 */
int rsl_tx_ipacc_crcx(const struct gsm_lchan *lchan)
{
	struct msgb *msg;
	struct abis_rsl_dchan_hdr *dh;

	int chan_nr = gsm_lchan2chan_nr(lchan, true);
	if (chan_nr < 0)
		return chan_nr;

	msg = rsl_msgb_alloc();

	dh = (struct abis_rsl_dchan_hdr *) msgb_put(msg, sizeof(*dh));
	init_dchan_hdr(dh, RSL_MT_IPAC_CRCX);
	dh->c.msg_discr = ABIS_RSL_MDISC_IPACCESS;
	dh->chan_nr = chan_nr;

	/* 0x1- == receive-only, 0x-1 == EFR codec */
	msgb_tv_put(msg, RSL_IE_IPAC_SPEECH_MODE, lchan->abis_ip.speech_mode);
	msgb_tv_put(msg, RSL_IE_IPAC_RTP_PAYLOAD, lchan->abis_ip.rtp_payload);

	LOG_LCHAN(lchan, LOGL_DEBUG, "Sending IPACC CRCX to BTS: speech_mode=0x%02x RTP_PAYLOAD=%d\n",
		  lchan->abis_ip.speech_mode, lchan->abis_ip.rtp_payload);

	msg->dst = rsl_chan_link(lchan);

	return abis_rsl_sendmsg(msg);
}

/*! Allocate buffer for IPA RSL MDCX and populate it with given parameters.
 * \param[in] lchan Logical Channel for which we make MDCX
 * \param[in] dest_ip The IP address to connect to
 * \param[in] dest_port The port to connect to
 */
struct msgb *rsl_make_ipacc_mdcx(const struct gsm_lchan *lchan, uint32_t dest_ip, uint16_t dest_port)
{
	struct msgb *msg;
	struct abis_rsl_dchan_hdr *dh;
	uint32_t *att_ip;

	int chan_nr = gsm_lchan2chan_nr(lchan, true);
	if (chan_nr < 0)
		return NULL;

	msg = rsl_msgb_alloc();

	dh = (struct abis_rsl_dchan_hdr *) msgb_put(msg, sizeof(*dh));
	init_dchan_hdr(dh, RSL_MT_IPAC_MDCX);
	dh->c.msg_discr = ABIS_RSL_MDISC_IPACCESS;
	dh->chan_nr = chan_nr;

	msgb_tv16_put(msg, RSL_IE_IPAC_CONN_ID, lchan->abis_ip.conn_id);
	msgb_v_put(msg, RSL_IE_IPAC_REMOTE_IP);
	att_ip = (uint32_t *)msgb_put(msg, sizeof(uint32_t));
	*att_ip = htonl(dest_ip);
	msgb_tv16_put(msg, RSL_IE_IPAC_REMOTE_PORT, dest_port);
	msgb_tv_put(msg, RSL_IE_IPAC_SPEECH_MODE, lchan->abis_ip.speech_mode);
	msgb_tv_put(msg, RSL_IE_IPAC_RTP_PAYLOAD, lchan->abis_ip.rtp_payload);
	if (lchan->abis_ip.rtp_payload2)
		msgb_tv_put(msg, RSL_IE_IPAC_RTP_PAYLOAD2, lchan->abis_ip.rtp_payload2);

	msg->dst = rsl_chan_link(lchan);

	return msg;
}

/*! Send IPA RSL MDCX to configure the RTP port the BTS sends to (MGW).
 * \param[in] lchan Logical Channel for which we issue MDCX
 * Remote (MGW) IP address, port and payload types for RTP are determined from lchan->abis_ip.
 */
int rsl_tx_ipacc_mdcx(const struct gsm_lchan *lchan)
{
	struct msgb *msg = rsl_make_ipacc_mdcx(lchan, lchan->abis_ip.connect_ip, lchan->abis_ip.connect_port);

	if (!msg)
		return -EINVAL;

	LOG_LCHAN(lchan, LOGL_DEBUG, "Sending IPACC MDCX to BTS:"
		  " %s:%u rtp_payload=%u rtp_payload2=%u conn_id=%u speech_mode=0x%02x\n",
		  ip_to_a(lchan->abis_ip.connect_ip),
		  lchan->abis_ip.connect_port,
		  lchan->abis_ip.rtp_payload,
		  lchan->abis_ip.rtp_payload2,
		  lchan->abis_ip.conn_id,
		  lchan->abis_ip.speech_mode);

	return abis_rsl_sendmsg(msg);
}

static int abis_rsl_rx_ipacc_crcx_ack(struct msgb *msg)
{
	struct abis_rsl_dchan_hdr *dh = msgb_l2(msg);
	struct tlv_parsed tv;
	struct gsm_lchan *lchan = msg->lchan;

	if (!lchan->fi_rtp) {
		LOG_LCHAN(msg->lchan, LOGL_ERROR, "Rx RSL IPACC: CRCX ACK message for unconfigured lchan\n");
		return -EINVAL;
	}

	/* the BTS has acknowledged a local bind, it now tells us the IP
	* address and port number to which it has bound the given logical
	* channel */

	if (rsl_tlv_parse(&tv, dh->data, msgb_l2len(msg) - sizeof(*dh)) < 0) {
		LOG_LCHAN(msg->lchan, LOGL_ERROR, "Failed to parse RSL %s\n",
			  rsl_or_ipac_msg_name(dh->c.msg_type));
		return -EINVAL;
	}

	if (!TLVP_PRESENT(&tv, RSL_IE_IPAC_LOCAL_PORT) ||
	    !TLVP_PRESENT(&tv, RSL_IE_IPAC_LOCAL_IP) ||
	    !TLVP_PRESENT(&tv, RSL_IE_IPAC_CONN_ID)) {
		LOGP(DRSL, LOGL_NOTICE, "mandatory IE missing\n");
		return -EINVAL;
	}

	ipac_parse_rtp(lchan, &tv, "CRCX");

	osmo_fsm_inst_dispatch(lchan->fi_rtp, LCHAN_RTP_EV_IPACC_CRCX_ACK, 0);

	return 0;
}

static int abis_rsl_rx_ipacc_crcx_nack(struct msgb *msg)
{
	struct e1inp_sign_link *sign_link = msg->dst;
	struct gsm_lchan *lchan = msg->lchan;

	rate_ctr_inc(rate_ctr_group_get_ctr(sign_link->trx->bts->bts_ctrs, BTS_CTR_RSL_IPA_NACK));

	if (!lchan->fi_rtp) {
		LOG_LCHAN(msg->lchan, LOGL_ERROR, "Rx RSL IPACC: CRCX NACK message for unconfigured lchan\n");
		return -EINVAL;
	}
	osmo_fsm_inst_dispatch(msg->lchan->fi_rtp, LCHAN_RTP_EV_IPACC_CRCX_NACK, 0);
	return 0;
}

static int abis_rsl_rx_ipacc_mdcx_ack(struct msgb *msg)
{
	struct abis_rsl_dchan_hdr *dh = msgb_l2(msg);
	struct tlv_parsed tv;
	struct gsm_lchan *lchan = msg->lchan;

	if (!lchan->fi_rtp) {
		LOG_LCHAN(msg->lchan, LOGL_ERROR, "Rx RSL IPACC: MDCX ACK message for unconfigured lchan\n");
		return -EINVAL;
	}

	/* the BTS has acknowledged a remote connect request and
	 * it now tells us the IP address and port number to which it has
	 * connected the given logical channel */

	if (rsl_tlv_parse(&tv, dh->data, msgb_l2len(msg) - sizeof(*dh)) < 0) {
		LOG_LCHAN(msg->lchan, LOGL_ERROR, "Failed to parse RSL %s\n",
			  rsl_or_ipac_msg_name(dh->c.msg_type));
		return -EINVAL;
	}

	ipac_parse_rtp(lchan, &tv, "MDCX");

	osmo_fsm_inst_dispatch(lchan->fi_rtp, LCHAN_RTP_EV_IPACC_MDCX_ACK, 0);

	return 0;
}

static int abis_rsl_rx_ipacc_mdcx_nack(struct msgb *msg)
{
	struct e1inp_sign_link *sign_link = msg->dst;
	struct gsm_lchan *lchan = msg->lchan;

	rate_ctr_inc(rate_ctr_group_get_ctr(sign_link->trx->bts->bts_ctrs, BTS_CTR_RSL_IPA_NACK));

	if (!lchan->fi_rtp) {
		LOG_LCHAN(msg->lchan, LOGL_ERROR, "Rx RSL IPACC: MDCX NACK message for unconfigured lchan\n");
		return -EINVAL;
	}
	osmo_fsm_inst_dispatch(msg->lchan->fi_rtp, LCHAN_RTP_EV_IPACC_MDCX_NACK, 0);
	return 0;
}

static int abis_rsl_rx_ipacc_dlcx_ind(struct msgb *msg)
{
	struct abis_rsl_dchan_hdr *dh = msgb_l2(msg);
	struct tlv_parsed tv;

	if (rsl_tlv_parse(&tv, dh->data, msgb_l2len(msg) - sizeof(*dh)) < 0) {
		LOG_LCHAN(msg->lchan, LOGL_ERROR, "Failed to parse RSL %s\n",
			  rsl_or_ipac_msg_name(dh->c.msg_type));
		return -EINVAL;
	}

	LOG_LCHAN(msg->lchan, LOGL_NOTICE, "Rx IPACC DLCX IND%s\n",
		  rsl_cause_name(&tv));

	return 0;
}

static int abis_rsl_rx_ipacc(struct msgb *msg)
{
	struct e1inp_sign_link *sign_link = msg->dst;
	struct abis_rsl_rll_hdr *rllh = msgb_l2(msg);
	int rc = 0;

	if (msgb_l2len(msg) < sizeof(*rllh))
		return -EINVAL;

	msg->lchan = lchan_lookup(sign_link->trx, rllh->chan_nr,
				  "Abis RSL rx IPACC: ");

	if (!msg->lchan) {
		LOGP(DRSL, LOGL_ERROR,
		     "Rx RSL IPACC: unable to match RSL message to an lchan: chan_nr=0x%x\n",
		     rllh->chan_nr);
		return -EINVAL;
	}

	if (!msg->lchan->fi) {
		LOG_LCHAN(msg->lchan, LOGL_ERROR, "Rx RSL IPACC: RSL message for unconfigured lchan\n");
		return -EINVAL;
	}

	LOG_LCHAN(msg->lchan, LOGL_DEBUG, "Rx %s\n", rsl_or_ipac_msg_name(rllh->c.msg_type));

	switch (rllh->c.msg_type) {
	case RSL_MT_IPAC_CRCX_ACK:
		rc = abis_rsl_rx_ipacc_crcx_ack(msg);
		break;
	case RSL_MT_IPAC_CRCX_NACK:
		/* somehow the BTS was unable to bind the lchan to its local
		 * port?!? */
		rc = abis_rsl_rx_ipacc_crcx_nack(msg);
		break;
	case RSL_MT_IPAC_MDCX_ACK:
		/* the BTS tells us that a connect operation was successful */
		rc = abis_rsl_rx_ipacc_mdcx_ack(msg);
		break;
	case RSL_MT_IPAC_MDCX_NACK:
		/* somehow the BTS was unable to connect the lchan to a remote
		 * port */
		rc = abis_rsl_rx_ipacc_mdcx_nack(msg);
		break;
	case RSL_MT_IPAC_DLCX_IND:
		rc = abis_rsl_rx_ipacc_dlcx_ind(msg);
		break;
	default:
		LOG_LCHAN(msg->lchan, LOGL_NOTICE, "Unknown ip.access msg_type 0x%02x\n",
			  rllh->c.msg_type);
		rate_ctr_inc(rate_ctr_group_get_ctr(sign_link->trx->bts->bts_ctrs, BTS_CTR_RSL_UNKNOWN));
		break;
	}

	return rc;
}

/*! Tx simplified channel (de-)activation message for non-standard Osmocom dyn TS PDCH type. */
static int send_osmocom_style_pdch_chan_act(struct gsm_bts_trx_ts *ts, bool activate)
{
	struct msgb *msg;
	struct abis_rsl_dchan_hdr *dh;

	msg = rsl_msgb_alloc();
	dh = (struct abis_rsl_dchan_hdr *) msgb_put(msg, sizeof(*dh));
	init_dchan_hdr(dh, activate ? RSL_MT_CHAN_ACTIV : RSL_MT_RF_CHAN_REL);

	dh->chan_nr = RSL_CHAN_OSMO_PDCH | (ts->nr & ~RSL_CHAN_NR_MASK);

	if (activate) {
		msgb_tv_put(msg, RSL_IE_ACT_TYPE, RSL_ACT_OSMO_PDCH);

		if (ts->trx->bts->type == GSM_BTS_TYPE_RBS2000
		    && ts->trx->bts->rbs2000.use_superchannel) {
			const uint8_t eric_pgsl_tmr[] = { 30, 1 };
			msgb_tv_fixed_put(msg, RSL_IE_ERIC_PGSL_TIMERS,
					  sizeof(eric_pgsl_tmr), eric_pgsl_tmr);
		}
	}

	msg->dst = ts->trx->rsl_link_primary;
	return abis_rsl_sendmsg(msg);
}

/*! Tx simplified channel (de-)activation message for non-standard ip.access dyn TS PDCH type. */
static int send_ipacc_style_pdch_act(struct gsm_bts_trx_ts *ts, bool activate)
{
	struct msgb *msg;
	struct abis_rsl_dchan_hdr *dh;

	int chan_nr = gsm_pchan2chan_nr(GSM_PCHAN_TCH_F, ts->nr, 0, false);
	if (chan_nr < 0)
		return chan_nr;

	msg = rsl_msgb_alloc();

	dh = (struct abis_rsl_dchan_hdr *) msgb_put(msg, sizeof(*dh));
	init_dchan_hdr(dh, activate ? RSL_MT_IPAC_PDCH_ACT : RSL_MT_IPAC_PDCH_DEACT);
	dh->c.msg_discr = ABIS_RSL_MDISC_DED_CHAN;
	dh->chan_nr = chan_nr;

	msg->dst = ts->trx->rsl_link_primary;
	return abis_rsl_sendmsg(msg);
}

int rsl_tx_dyn_ts_pdch_act_deact(struct gsm_bts_trx_ts *ts, bool activate)
{
	int rc;
	const char *what;
	const char *act;

	switch (ts->pchan_on_init) {
	case GSM_PCHAN_OSMO_DYN:
		what = "Osmocom dyn TS";
		act = activate? "PDCH Chan Activ" : "PDCH Chan RF Release";

		rc = send_osmocom_style_pdch_chan_act(ts, activate);
		break;

	case GSM_PCHAN_TCH_F_PDCH:
		what = "ip.access dyn TS";
		act = activate? "PDCH ACT" : "PDCH DEACT";

		rc = send_ipacc_style_pdch_act(ts, activate);
		break;

	default:
		what = "static timeslot";
		act = activate? "dynamic PDCH activation" : "dynamic PDCH deactivation";
		rc = -EINVAL;
		break;
	}

	if (rc)
		LOG_TS(ts, LOGL_ERROR, "Tx FAILED: %s: %s: %d (%s)\n",
		       what, act, rc, strerror(-rc));
	else
		LOG_TS(ts, LOGL_DEBUG, "Tx: %s: %s\n", what, act);
	return rc;
}

/* Entry-point where L2 RSL from BTS enters */
int abis_rsl_rcvmsg(struct msgb *msg)
{
	struct e1inp_sign_link *sign_link;
	struct abis_rsl_common_hdr *rslh;
	int rc = 0;

	if (!msg) {
		DEBUGP(DRSL, "Empty RSL msg?..\n");
		return -1;
	}

	if (msgb_l2len(msg) < sizeof(*rslh)) {
		DEBUGP(DRSL, "Truncated RSL message with l2len: %u\n", msgb_l2len(msg));
		msgb_free(msg);
		return -1;
	}

	sign_link = msg->dst;
	rslh = msgb_l2(msg);

	switch (rslh->msg_discr & 0xfe) {
	case ABIS_RSL_MDISC_RLL:
		rc = abis_rsl_rx_rll(msg);
		break;
	case ABIS_RSL_MDISC_DED_CHAN:
		rc = abis_rsl_rx_dchan(msg);
		break;
	case ABIS_RSL_MDISC_COM_CHAN:
		rc = abis_rsl_rx_cchan(msg);
		break;
	case ABIS_RSL_MDISC_TRX:
		rc = abis_rsl_rx_trx(msg);
		break;
	case ABIS_RSL_MDISC_LOC:
		LOGP(DRSL, LOGL_NOTICE, "unimplemented RSL msg disc 0x%02x\n",
			rslh->msg_discr);
		break;
	case ABIS_RSL_MDISC_IPACCESS:
		rc = abis_rsl_rx_ipacc(msg);
		break;
	default:
		LOGP(DRSL, LOGL_NOTICE, "unknown RSL message discriminator "
			"0x%02x\n", rslh->msg_discr);
		rate_ctr_inc(rate_ctr_group_get_ctr(sign_link->trx->bts->bts_ctrs, BTS_CTR_RSL_UNKNOWN));
		rc = -EINVAL;
	}
	msgb_free(msg);
	return rc;
}

/* Send an Osmocom-specific Abis RSL message for ETWS Primary Notification */
int rsl_etws_pn_command(struct gsm_bts *bts, uint8_t chan_nr, const uint8_t *data, int len)
{
	struct abis_rsl_dchan_hdr *dh;
	struct msgb *msg = rsl_msgb_alloc();
	if (!msg)
		return -1;
	dh = (struct abis_rsl_dchan_hdr *) msgb_put(msg, sizeof(*dh));
	init_dchan_hdr(dh, RSL_MT_OSMO_ETWS_CMD);
	dh->c.msg_discr = ABIS_RSL_MDISC_COM_CHAN;
	dh->chan_nr = chan_nr;

	msgb_tlv_put(msg, RSL_IE_SMSCB_MSG, len, data);

	msg->dst = bts->c0->rsl_link_primary;

	return abis_rsl_sendmsg(msg);
}

int rsl_sms_cb_command(struct gsm_bts *bts, uint8_t chan_number,
		       struct rsl_ie_cb_cmd_type cb_command,
		       bool use_extended_cbch, const uint8_t *data, int len)
{
	struct abis_rsl_dchan_hdr *dh;
	struct msgb *cb_cmd;

	cb_cmd = rsl_msgb_alloc();
	if (!cb_cmd)
		return -1;

	dh = (struct abis_rsl_dchan_hdr *) msgb_put(cb_cmd, sizeof(*dh));
	init_dchan_hdr(dh, RSL_MT_SMS_BC_CMD);
	dh->c.msg_discr = ABIS_RSL_MDISC_COM_CHAN;
	dh->chan_nr = chan_number; /* TODO: check the chan config */

	msgb_tv_put(cb_cmd, RSL_IE_CB_CMD_TYPE, *(uint8_t*)&cb_command);
	msgb_tlv_put(cb_cmd, RSL_IE_SMSCB_MSG, len, data);
	if (use_extended_cbch)
		msgb_tv_put(cb_cmd, RSL_IE_SMSCB_CHAN_INDICATOR, 0x01);

	cb_cmd->dst = bts->c0->rsl_link_primary;

	return abis_rsl_sendmsg(cb_cmd);
}

int rsl_nokia_si_begin(struct gsm_bts_trx *trx)
{
	struct abis_rsl_common_hdr *ch;
	struct msgb *msg = rsl_msgb_alloc();

	ch = (struct abis_rsl_common_hdr *) msgb_put(msg, sizeof(*ch));
	ch->msg_discr = ABIS_RSL_MDISC_TRX;
	ch->msg_type = 0x40; /* Nokia SI Begin */

	msg->dst = trx->rsl_link_primary;

	return abis_rsl_sendmsg(msg);
}

int rsl_nokia_si_end(struct gsm_bts_trx *trx)
{
	struct abis_rsl_common_hdr *ch;
	struct msgb *msg = rsl_msgb_alloc();

	ch = (struct abis_rsl_common_hdr *) msgb_put(msg, sizeof(*ch));
	ch->msg_discr = ABIS_RSL_MDISC_TRX;
	ch->msg_type = 0x41;  /* Nokia SI End */

	msgb_tv_put(msg, 0xFD, 0x00); /* Nokia Pagemode Info, No paging reorganisation required */

	msg->dst = trx->rsl_link_primary;

	return abis_rsl_sendmsg(msg);
}

int rsl_bs_power_control(struct gsm_bts_trx *trx, uint8_t channel, uint8_t reduction)
{
	struct abis_rsl_common_hdr *ch;
	struct msgb *msg = rsl_msgb_alloc();

	ch = (struct abis_rsl_common_hdr *) msgb_put(msg, sizeof(*ch));
	ch->msg_discr = ABIS_RSL_MDISC_DED_CHAN;
	ch->msg_type = RSL_MT_BS_POWER_CONTROL;

	msgb_tv_put(msg, RSL_IE_CHAN_NR, channel);
	msgb_tv_put(msg, RSL_IE_BS_POWER, reduction); /* reduction in 2dB steps */

	msg->dst = trx->rsl_link_primary;

	return abis_rsl_sendmsg(msg);
}

struct e1inp_sign_link *rsl_chan_link(const struct gsm_lchan *lchan)
{
	return lchan->ts->trx->rsl_link_primary;
}
