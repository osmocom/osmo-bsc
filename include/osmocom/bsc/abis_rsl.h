/* GSM Radio Signalling Link messages on the A-bis interface 
 * 3GPP TS 08.58 version 8.6.0 Release 1999 / ETSI TS 100 596 V8.6.0 */

/* (C) 2008 by Harald Welte <laforge@gnumonks.org>
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

#ifndef _RSL_H
#define _RSL_H

#include <stdbool.h>
#include <osmocom/gsm/protocol/gsm_08_58.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/gsm/sysinfo.h>
#include <osmocom/core/msgb.h>
#include <osmocom/bsc/gsm_data.h>

struct gsm_bts;
struct gsm_lchan;
struct gsm_bts_trx_ts;

#define GSM48_LEN2PLEN(a)	(((a) << 2) | 1)

const char *ip_to_a(uint32_t ip);

int rsl_bcch_info(const struct gsm_bts_trx *trx, enum osmo_sysinfo_type si_type, const uint8_t *data, int len);
int rsl_sacch_filling(struct gsm_bts_trx *trx, uint8_t type,
		      const uint8_t *data, int len);
int rsl_tx_chan_activ(struct gsm_lchan *lchan, uint8_t act_type, uint8_t ho_ref);
int rsl_chan_mode_modify_req(struct gsm_lchan *ts);
int rsl_encryption_cmd(struct msgb *msg);
int rsl_paging_cmd(struct gsm_bts *bts, uint8_t paging_group,
		   const struct osmo_mobile_identity *mi,
		   uint8_t chan_needed, bool is_gprs);
int rsl_imm_assign_cmd(struct gsm_bts *bts, uint8_t len, uint8_t *val);
int rsl_tx_imm_assignment(struct gsm_lchan *lchan);
int rsl_tx_imm_ass_rej(struct gsm_bts *bts, struct gsm48_req_ref *rqd_ref);
int gsm48_send_rr_ass_cmd(struct gsm_lchan *dest_lchan, struct gsm_lchan *lchan, uint8_t power_command);

int rsl_data_request(struct msgb *msg, uint8_t link_id);
int rsl_establish_request(struct gsm_lchan *lchan, uint8_t link_id);
int rsl_relase_request(struct gsm_lchan *lchan, uint8_t link_id);

/* Ericcson vendor specific RSL extensions */
int rsl_ericsson_imm_assign_cmd(struct gsm_bts *bts, uint32_t tlli, uint8_t len, uint8_t *val);

/* Siemens vendor-specific RSL extensions */
int rsl_siemens_mrpci(struct gsm_lchan *lchan, struct rsl_mrpci *mrpci);

/* ip.access specific RSL extensions */
struct msgb *rsl_make_ipacc_mdcx(const struct gsm_lchan *lchan, uint32_t dest_ip, uint16_t dest_port);
int rsl_tx_ipacc_crcx(const struct gsm_lchan *lchan);
int rsl_tx_ipacc_mdcx(const struct gsm_lchan *lchan);
int rsl_ipacc_mdcx_to_rtpsock(struct gsm_lchan *lchan);
int rsl_ipacc_pdch_activate(struct gsm_bts_trx_ts *ts, int act);

int abis_rsl_rcvmsg(struct msgb *msg);

int rsl_release_request(struct gsm_lchan *lchan, uint8_t link_id,
			enum rsl_rel_mode release_mode);

int rsl_lchan_mark_broken(struct gsm_lchan *lchan, const char *broken);

/* to be provided by external code */
int rsl_deact_sacch(struct gsm_lchan *lchan);

/* BCCH related code */
int rsl_ccch_conf_to_bs_cc_chans(int ccch_conf);
int rsl_ccch_conf_to_bs_ccch_sdcch_comb(int ccch_conf);

int rsl_sacch_info_modify(struct gsm_lchan *lchan, uint8_t type,
			  const uint8_t *data, int len);

int rsl_chan_bs_power_ctrl(struct gsm_lchan *lchan, unsigned int fpc, int db);
int rsl_chan_ms_power_ctrl(struct gsm_lchan *lchan);

/* SMSCB functionality */
int rsl_sms_cb_command(struct gsm_bts *bts, uint8_t chan_number,
		       struct rsl_ie_cb_cmd_type cb_command,
		       bool use_extended_cbch, const uint8_t *data, int len);
int rsl_etws_pn_command(struct gsm_bts *bts, uint8_t chan_nr, const uint8_t *data, int len);

/* some Nokia specific stuff */
int rsl_nokia_si_begin(struct gsm_bts_trx *trx);
int rsl_nokia_si_end(struct gsm_bts_trx *trx);

/* required for Nokia BTS power control */
int rsl_bs_power_control(struct gsm_bts_trx *trx, uint8_t channel, uint8_t reduction);


int rsl_release_sapis_from(struct gsm_lchan *lchan, int start,
				enum rsl_rel_mode release_mode);
int rsl_start_t3109(struct gsm_lchan *lchan);

int rsl_direct_rf_release(struct gsm_lchan *lchan);

int rsl_tx_dyn_ts_pdch_act_deact(struct gsm_bts_trx_ts *ts, bool activate);

int rsl_forward_layer3_info(struct gsm_lchan *lchan, const uint8_t *l3_info, uint8_t l3_info_len);

int ipacc_speech_mode(enum gsm48_chan_mode tch_mode, enum gsm_chan_t type);
void ipacc_speech_mode_set_direction(uint8_t *speech_mode, bool send);
int ipacc_payload_type(enum gsm48_chan_mode tch_mode, enum gsm_chan_t type);

int rsl_tx_rf_chan_release(struct gsm_lchan *lchan);

int abis_rsl_chan_rqd_queue_poll(struct gsm_bts *bts);

#endif /* RSL_MT_H */

