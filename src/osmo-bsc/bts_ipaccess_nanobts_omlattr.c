/* ip.access nanoBTS specific code, OML attribute table generator */

/* (C) 2016 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Philipp Maier
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
 */

#include <arpa/inet.h>
#include <osmocom/core/msgb.h>
#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/abis_nm.h>
#include <osmocom/bsc/bts.h>
#include <osmocom/gsm/bts_features.h>

/* 3GPP TS 52.021 section 8.6.1 Set BTS Attributes */
struct msgb *nanobts_gen_set_bts_attr(struct gsm_bts *bts)
{
	struct msgb *msgb;
	uint8_t buf[256];
	int rlt;
	msgb = msgb_alloc(1024, "nanobts_attr_bts");
	if (!msgb)
		return NULL;

	/* Interference level Boundaries: 0 .. X5 (3GPP TS 52.021 sec 9.4.25) */
	msgb_tv_fixed_put(msgb, NM_ATT_INTERF_BOUND,
			  sizeof(bts->interf_meas_params_cfg.bounds_dbm),
			  &bts->interf_meas_params_cfg.bounds_dbm[0]);
	/* Intave: Interference Averaging period (3GPP TS 52.021 sec 9.4.24) */
	msgb_tv_put(msgb, NM_ATT_INTAVE_PARAM, bts->interf_meas_params_cfg.avg_period);

	/* Connection Failure Criterion (3GPP TS 52.021 sec 9.4.14) */
	rlt = gsm_bts_get_radio_link_timeout(bts);
	if (rlt == -1) {
		/* Osmocom extension: Use infinite radio link timeout */
		buf[0] = 0xFF;
		buf[1] = 0x00;
	} else {
		/* conn fail based on SACCH error rate */
		buf[0] = 0x01;
		buf[1] = rlt;
	}
	msgb_tl16v_put(msgb, NM_ATT_CONN_FAIL_CRIT, 2, buf);

	/* T200 (3GPP TS 52.021 sec 9.4.53) */
	memcpy(buf, "\x1e\x24\x24\xa8\x34\x21\xa8", 7);
	msgb_tv_fixed_put(msgb, NM_ATT_T200, 7, buf);

	/* Max Timing Advance (3GPP TS 52.021 sec 9.4.31) */
	msgb_tv_put(msgb, NM_ATT_MAX_TA, 0x3f);

	/* Overload Period (3GPP TS 52.021 sec 9.4.39), seconds */
	memcpy(buf, "\x00\x01\x0a", 3);
	msgb_tv_fixed_put(msgb, NM_ATT_OVERL_PERIOD, 3, buf);

	/* CCCH Load Threshold (3GPP TS 12.21 sec 9.4.12), percent */
	msgb_tv_put(msgb, NM_ATT_CCCH_L_T, bts->ccch_load_ind_thresh);

	/* CCCH Load Indication Period (3GPP TS 12.21 sec 9.4.11), seconds */
	msgb_tv_put(msgb, NM_ATT_CCCH_L_I_P, bts->ccch_load_ind_period);

	/* RACH Busy Threshold (3GPP TS 12.21 sec 9.4.44), -dBm */
	buf[0] = 90;	/* -90 dBm as default "busy" threshold */
	if (bts->rach_b_thresh != -1)
		buf[0] = bts->rach_b_thresh & 0xff;
	msgb_tv_put(msgb, NM_ATT_RACH_B_THRESH, buf[0]);

	/* RACH Load Averaging Slots (3GPP TS 12.21 sec 9.4.45), 1000 slots */
	buf[0] = 0x03;
	buf[1] = 0xe8;
	if (bts->rach_ldavg_slots != -1) {
		buf[0] = (bts->rach_ldavg_slots >> 8) & 0x0f;
		buf[1] = bts->rach_ldavg_slots & 0xff;
	}
	msgb_tv_fixed_put(msgb, NM_ATT_LDAVG_SLOTS, 2, buf);

	/* BTS Air Timer (3GPP TS 12.21 sec 9.4.10), 10 milliseconds */
	msgb_tv_put(msgb, NM_ATT_BTS_AIR_TIMER, osmo_tdef_get(bts->network->T_defs, 3105, OSMO_TDEF_MS, -1)/10);

	/* NY1 (3GPP TS 12.21 sec 9.4.37), number of retransmissions of physical config */
	gsm_bts_check_ny1(bts);
	msgb_tv_put(msgb, NM_ATT_NY1, osmo_tdef_get(bts->network->T_defs, -3105, OSMO_TDEF_CUSTOM, -1));

	/* BCCH ARFCN (3GPP TS 12.21 sec 9.4.8) */
	buf[0] = (bts->c0->arfcn >> 8) & 0x0f;
	buf[1] = bts->c0->arfcn & 0xff;
	msgb_tv_fixed_put(msgb, NM_ATT_BCCH_ARFCN, 2, buf);

	/* BSIC (3GPP TS 12.21 sec 9.4.9) */
	msgb_tv_put(msgb, NM_ATT_BSIC, bts->bsic);

	abis_nm_ipaccess_cgi(buf, bts);
	msgb_tl16v_put(msgb, NM_ATT_IPACC_CGI, 7, buf);

	return msgb;
}

struct msgb *nanobts_gen_set_nse_attr(struct gsm_bts_sm *bts_sm)
{
	struct msgb *msgb;
	uint8_t buf[2];
	struct abis_nm_ipacc_att_ns_cfg ns_cfg;
	struct abis_nm_ipacc_att_bssgp_cfg bssgp_cfg;
	struct gsm_bts *bts = gsm_bts_sm_get_bts(bts_sm);
	msgb = msgb_alloc(1024, "nanobts_attr_bts");
	if (!msgb)
		return NULL;

	/* NSEI 925 */
	buf[0] = bts_sm->gprs.nse.nsei >> 8;
	buf[1] = bts_sm->gprs.nse.nsei & 0xff;
	msgb_tl16v_put(msgb, NM_ATT_IPACC_NSEI, 2, buf);

	osmo_static_assert(ARRAY_SIZE(bts_sm->gprs.nse.timer) == 7, nse_timer_array_wrong_size);
	ns_cfg = (struct abis_nm_ipacc_att_ns_cfg){
		.un_blocking_timer =	bts_sm->gprs.nse.timer[0],
		.un_blocking_retries =	bts_sm->gprs.nse.timer[1],
		.reset_timer =		bts_sm->gprs.nse.timer[2],
		.reset_retries =	bts_sm->gprs.nse.timer[3],
		.test_timer =		bts_sm->gprs.nse.timer[4],
		.alive_timer =		bts_sm->gprs.nse.timer[5],
		.alive_retries =	bts_sm->gprs.nse.timer[6],
	};
	msgb_tl16v_put(msgb, NM_ATT_IPACC_NS_CFG, sizeof(ns_cfg), (const uint8_t *)&ns_cfg);

	osmo_static_assert(ARRAY_SIZE(bts->gprs.cell.timer) == 11, cell_timer_array_wrong_size);
	bssgp_cfg = (struct abis_nm_ipacc_att_bssgp_cfg){
		.t1_s =			bts->gprs.cell.timer[0],
		.t1_blocking_retries =	bts->gprs.cell.timer[1],
		.t1_unblocking_retries = bts->gprs.cell.timer[2],
		.t2_s =			bts->gprs.cell.timer[3],
		.t2_retries =		bts->gprs.cell.timer[4],
		.t3_100ms =		bts->gprs.cell.timer[5],
		.t3_retries =		bts->gprs.cell.timer[6],
		.t4_100ms =		bts->gprs.cell.timer[7],
		.t4_retries =		bts->gprs.cell.timer[8],
		.t5_s =			bts->gprs.cell.timer[9],
		.t5_retries =		bts->gprs.cell.timer[10],
	};
	msgb_tl16v_put(msgb, NM_ATT_IPACC_BSSGP_CFG, sizeof(bssgp_cfg), (const uint8_t *)&bssgp_cfg);

	return msgb;
}

struct msgb *nanobts_gen_set_cell_attr(struct gsm_bts *bts)
{
	struct msgb *msgb;
	struct abis_nm_ipacc_att_rlc_cfg rlc_cfg;
	struct abis_nm_ipacc_att_rlc_cfg_2 rlc_cfg_2;
	uint8_t buf[2];
	msgb = msgb_alloc(1024, "nanobts_attr_bts");
	if (!msgb)
		return NULL;

	/* routing area code */
	buf[0] = bts->gprs.rac;
	msgb_tl16v_put(msgb, NM_ATT_IPACC_RAC, 1, buf);

	buf[0] = 5;	/* repeat time (50ms) */
	buf[1] = 3;	/* repeat count */
	msgb_tl16v_put(msgb, NM_ATT_IPACC_GPRS_PAGING_CFG, 2, buf);

	/* BVCI 925 */
	buf[0] = bts->gprs.cell.bvci >> 8;
	buf[1] = bts->gprs.cell.bvci & 0xff;
	msgb_tl16v_put(msgb, NM_ATT_IPACC_BVCI, 2, buf);

	/* all timers in seconds, unless otherwise stated */
	rlc_cfg = (struct abis_nm_ipacc_att_rlc_cfg){
		.t3142 =		20,	/* T3142 */
		.t3169 =		5,	/* T3169 */
		.t3191 =		5,	/* T3191 */
		.t3193_10ms =		160,	/* T3193 (units of 10ms) */
		.t3195 =		5,	/* T3195 */
		.n3101 =		10,	/* N3101 */
		.n3103 =		4,	/* N3103 */
		.n3105 =		8,	/* N3105 */
		.rlc_cv_countdown =	15,	/* RLC CV countdown */
	};
	msgb_tl16v_put(msgb, NM_ATT_IPACC_RLC_CFG, sizeof(rlc_cfg), (const uint8_t *)&rlc_cfg);

	if (bts->gprs.mode == BTS_GPRS_EGPRS) {
		buf[0] = 0x8f;
		buf[1] = 0xff;
	} else {
		buf[0] = 0x0f;
		buf[1] = 0x00;
	}
	msgb_tl16v_put(msgb, NM_ATT_IPACC_CODING_SCHEMES, 2, buf);

	rlc_cfg_2 = (struct abis_nm_ipacc_att_rlc_cfg_2){
		.t_dl_tbf_ext_10ms = htons(250), /* 0..500 */
		.t_ul_tbf_ext_10ms = htons(250), /* 0..500 */
		.initial_cs = 2, /* CS2 */
	};
	msgb_tl16v_put(msgb, NM_ATT_IPACC_RLC_CFG_2, sizeof(rlc_cfg_2), (const uint8_t *)&rlc_cfg_2);

#if 0
	/* EDGE model only, breaks older models.
	 * Should inquire the BTS capabilities */
	struct abis_nm_ipacc_att_rlc_cfg_3 rlc_cfg_3;
	rlc_cfg_3 = (struct abis_nm_ipacc_att_rlc_cfg_3){
		.initial_mcs = 2, /* MCS2 */
	};
	msgb_tl16v_put(msgb, NM_ATT_IPACC_RLC_CFG_3, sizeof(rlc_cfg_3), (const uint8_t *)&rlc_cfg_3);
#endif

	return msgb;
}

struct msgb *nanobts_gen_set_nsvc_attr(struct gsm_gprs_nsvc *nsvc)
{
	struct msgb *msgb;
	uint8_t buf[256];
	msgb = msgb_alloc(1024, "nanobts_attr_bts");
	if (!msgb)
		return NULL;

	/* 925 */
	buf[0] = nsvc->nsvci >> 8;
	buf[1] = nsvc->nsvci & 0xff;
	msgb_tl16v_put(msgb, NM_ATT_IPACC_NSVCI, 2, buf);

	switch (nsvc->remote.u.sa.sa_family) {
	case AF_INET6:
		/* all fields are encoded in network byte order */
		/* protocol family */
		buf[0] = OSMO_NSVC_ADDR_IPV6;
		/* padding */
		buf[1] = 0x00;
		/* local udp port */
		osmo_store16be(nsvc->local_port, &buf[2]);
		/* remote udp port */
		memcpy(&buf[4], &nsvc->remote.u.sin6.sin6_port, sizeof(uint16_t));
		/* remote ip address */
		memcpy(&buf[6], &nsvc->remote.u.sin6.sin6_addr, sizeof(struct in6_addr));
		msgb_tl16v_put(msgb, NM_ATT_OSMO_NS_LINK_CFG, 6 + sizeof(struct in6_addr), buf);
		break;
	case AF_INET:
		/* remote udp port */
		memcpy(&buf[0], &nsvc->remote.u.sin.sin_port, sizeof(uint16_t));
		/* remote ip address */
		memcpy(&buf[2], &nsvc->remote.u.sin.sin_addr, sizeof(struct in_addr));
		/* local udp port */
		osmo_store16be(nsvc->local_port, &buf[6]);
		msgb_tl16v_put(msgb, NM_ATT_IPACC_NS_LINK_CFG, 8, buf);
		break;
	default:
		break;
	}

	return msgb;
}

struct msgb *nanobts_gen_set_radio_attr(struct gsm_bts *bts,
				    struct gsm_bts_trx *trx)
{
	struct msgb *msgb;
	uint8_t buf[256];
	msgb = msgb_alloc(1024, "nanobts_attr_bts");
	if (!msgb)
		return NULL;

	/* number of -2dB reduction steps / Pn */
	msgb_tv_put(msgb, NM_ATT_RF_MAXPOWR_R, trx->max_power_red / 2);

	buf[0] = trx->arfcn >> 8;
	buf[1] = trx->arfcn & 0xff;
	msgb_tl16v_put(msgb, NM_ATT_ARFCN_LIST, 2, buf);

	return msgb;
}
