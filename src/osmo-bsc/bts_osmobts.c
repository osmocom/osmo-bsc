/* Osmocom OsmoBTS specific code */

/* (C) 2010-2012 by Harald Welte <laforge@gnumonks.org>
 * (C) 2021 by sysmocom - s.m.f.c. GmbH <info@sysmocom.de>
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

#include <arpa/inet.h>

#include <osmocom/gsm/tlv.h>

#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/signal.h>
#include <osmocom/bsc/abis_nm.h>
#include <osmocom/bsc/bts.h>
#include <osmocom/abis/e1_input.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/talloc.h>
#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/abis_nm.h>
#include <osmocom/bsc/abis_rsl.h>
#include <osmocom/bsc/debug.h>
#include <osmocom/abis/subchan_demux.h>
#include <osmocom/abis/ipaccess.h>
#include <osmocom/core/logging.h>

extern struct gsm_bts_model bts_model_nanobts;

static struct gsm_bts_model model_osmobts;

static void enc_osmo_meas_proc_params(struct msgb *msg, const struct gsm_power_ctrl_params *mp)
{
	struct osmo_preproc_ave_cfg *ave_cfg;
	uint8_t *ie_len;

	/* No averaging => no Measurement Averaging parameters */
	if (mp->ci_fr_meas.algo == GSM_PWR_CTRL_MEAS_AVG_ALGO_NONE &&
	    mp->ci_hr_meas.algo == GSM_PWR_CTRL_MEAS_AVG_ALGO_NONE &&
	    mp->ci_amr_fr_meas.algo == GSM_PWR_CTRL_MEAS_AVG_ALGO_NONE &&
	    mp->ci_amr_hr_meas.algo == GSM_PWR_CTRL_MEAS_AVG_ALGO_NONE &&
	    mp->ci_sdcch_meas.algo == GSM_PWR_CTRL_MEAS_AVG_ALGO_NONE &&
	    mp->ci_gprs_meas.algo == GSM_PWR_CTRL_MEAS_AVG_ALGO_NONE)
		return;

	/* (TLV) Measurement Averaging parameters for RxLev/RxQual */
	ie_len = msgb_tl_put(msg, RSL_IPAC_EIE_OSMO_MEAS_AVG_CFG);

	ave_cfg = (struct osmo_preproc_ave_cfg *) msgb_put(msg, sizeof(*ave_cfg));

#define ENC_PROC(PARAMS, TO, TYPE) do { \
	(TO)->TYPE.ave_enabled = (PARAMS)->TYPE##_meas.algo != GSM_PWR_CTRL_MEAS_AVG_ALGO_NONE; \
	if ((TO)->TYPE.ave_enabled) { \
		/* H_REQAVE and H_REQT */ \
		(TO)->TYPE.h_reqave = (PARAMS)->TYPE##_meas.h_reqave & 0x1f; \
		(TO)->TYPE.h_reqt = (PARAMS)->TYPE##_meas.h_reqt & 0x1f; \
		/* Averaging method and parameters */ \
		(TO)->TYPE.ave_method = ((PARAMS)->TYPE##_meas.algo - 1) & 0x07; \
		switch ((PARAMS)->TYPE##_meas.algo) { \
		case GSM_PWR_CTRL_MEAS_AVG_ALGO_OSMO_EWMA: \
			msgb_v_put(msg, (PARAMS)->TYPE##_meas.ewma.alpha); \
			break; \
		case GSM_PWR_CTRL_MEAS_AVG_ALGO_WEIGHTED: \
		case GSM_PWR_CTRL_MEAS_AVG_ALGO_MOD_MEDIAN: \
			/* FIXME: unknown format */ \
			break; \
		case GSM_PWR_CTRL_MEAS_AVG_ALGO_UNWEIGHTED: \
		case GSM_PWR_CTRL_MEAS_AVG_ALGO_NONE: \
			/* No parameters here */ \
			break; \
		} \
	} \
	} while (0)
	ENC_PROC(mp, ave_cfg, ci_fr);
	ENC_PROC(mp, ave_cfg, ci_hr);
	ENC_PROC(mp, ave_cfg, ci_amr_fr);
	ENC_PROC(mp, ave_cfg, ci_amr_hr);
	ENC_PROC(mp, ave_cfg, ci_sdcch);
	ENC_PROC(mp, ave_cfg, ci_gprs);
#undef ENC_PROC

	/* Update length part of the containing IE */
	*ie_len = msg->tail - (ie_len + 1);
}

/* Appends Osmocom specific extension IEs into RSL_IE_MS_POWER_PARAM */
void osmobts_enc_power_params_osmo_ext(struct msgb *msg, const struct gsm_power_ctrl_params *cp)
{
	struct osmo_preproc_pc_thresh *osmo_thresh;
	struct osmo_preproc_pc_comp *osmo_thresh_comp;
	uint8_t *ie_len;

	/* (TLV) Measurement Averaging Configure (C/I) */
	enc_osmo_meas_proc_params(msg, cp);

	/* (TLV) Thresholds (C/I) */
	ie_len = msgb_tl_put(msg, RSL_IPAC_EIE_OSMO_MS_PWR_CTL);
	osmo_thresh = (struct osmo_preproc_pc_thresh *) msgb_put(msg, sizeof(*osmo_thresh));
	#define ENC_THRESH_CI(TYPE) \
		osmo_thresh->l_##TYPE = cp->TYPE##_meas.lower_thresh; \
		osmo_thresh->u_##TYPE = cp->TYPE##_meas.upper_thresh
	ENC_THRESH_CI(ci_fr);
	ENC_THRESH_CI(ci_hr);
	ENC_THRESH_CI(ci_amr_fr);
	ENC_THRESH_CI(ci_amr_hr);
	ENC_THRESH_CI(ci_sdcch);
	ENC_THRESH_CI(ci_gprs);
	#undef ENC_THRESH_CI
	/* Update length part of the containing IE */
	*ie_len = msg->tail - (ie_len + 1);

	/* (TLV) PC Threshold Comparators (C/I) */
	ie_len = msgb_tl_put(msg, RSL_IPAC_EIE_OSMO_PC_THRESH_COMP);
	osmo_thresh_comp = (struct osmo_preproc_pc_comp *) msgb_put(msg, sizeof(*osmo_thresh_comp));
	#define ENC_THRESH_CI(TYPE) \
		osmo_thresh_comp->TYPE.lower_p = cp->TYPE##_meas.lower_cmp_p & 0x1f; \
		osmo_thresh_comp->TYPE.lower_n = cp->TYPE##_meas.lower_cmp_n & 0x1f; \
		osmo_thresh_comp->TYPE.upper_p = cp->TYPE##_meas.upper_cmp_p & 0x1f; \
		osmo_thresh_comp->TYPE.upper_n = cp->TYPE##_meas.upper_cmp_n & 0x1f
	ENC_THRESH_CI(ci_fr);
	ENC_THRESH_CI(ci_hr);
	ENC_THRESH_CI(ci_amr_fr);
	ENC_THRESH_CI(ci_amr_hr);
	ENC_THRESH_CI(ci_sdcch);
	ENC_THRESH_CI(ci_gprs);
	#undef ENC_THRESH_CI
	/* Update length part of the containing IE */
	*ie_len = msg->tail - (ie_len + 1);
}

static int power_ctrl_set_c0_power_red(const struct gsm_bts *bts,
				       const uint8_t red)
{
	struct abis_rsl_dchan_hdr *dh;
	struct msgb *msg;

	msg = rsl_msgb_alloc();
	if (msg == NULL)
		return -ENOMEM;

	LOGP(DRSL, LOGL_NOTICE, "%sabling BCCH carrier power reduction "
	     "operation mode for BTS%u (maximum %u dB)\n",
	     red ? "En" : "Dis", bts->nr, red);

	/* Abuse the standard BS POWER CONTROL message by specifying 'Common Channel'
	 * in the Protocol Discriminator field and 'BCCH' in the Channel Number IE. */
	dh = (struct abis_rsl_dchan_hdr *) msgb_put(msg, sizeof(*dh));
	dh->c.msg_discr = ABIS_RSL_MDISC_COM_CHAN;
	dh->c.msg_type = RSL_MT_BS_POWER_CONTROL;
	dh->ie_chan = RSL_IE_CHAN_NR;
	dh->chan_nr = RSL_CHAN_BCCH;

	msgb_tv_put(msg, RSL_IE_BS_POWER, red / 2);

	msg->dst = bts->c0->rsl_link_primary;

	return abis_rsl_sendmsg(msg);
}

int bts_model_osmobts_init(void)
{
	model_osmobts = bts_model_nanobts;
	model_osmobts.name = "osmo-bts";
	model_osmobts.type = GSM_BTS_TYPE_OSMOBTS;

	/* Unlike nanoBTS, osmo-bts does support SI2bis and SI2ter fine */
	model_osmobts.force_combined_si = false;

	/* Power control API */
	model_osmobts.power_ctrl_set_c0_power_red = &power_ctrl_set_c0_power_red;

	model_osmobts.features.data = &model_osmobts._features_data[0];
	model_osmobts.features.data_len =
				sizeof(model_osmobts._features_data);
	memset(model_osmobts.features.data, 0, model_osmobts.features.data_len);

	osmo_bts_set_feature(&model_osmobts.features, BTS_FEAT_GPRS);
	osmo_bts_set_feature(&model_osmobts.features, BTS_FEAT_EGPRS);
	osmo_bts_set_feature(&model_osmobts.features, BTS_FEAT_PAGING_COORDINATION);
	osmo_bts_set_feature(&model_osmobts.features, BTS_FEAT_IPV6_NSVC);
	osmo_bts_set_feature(&model_osmobts.features, BTS_FEAT_CCN);

	model_osmobts.nm_att_tlvdef.def[NM_ATT_OSMO_NS_LINK_CFG].type = TLV_TYPE_TL16V;

	return gsm_bts_model_register(&model_osmobts);
}
