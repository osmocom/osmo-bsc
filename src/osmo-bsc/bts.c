/* (C) 2008-2018 by Harald Welte <laforge@gnumonks.org>
 * (C) 2021 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
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

#include <osmocom/gsm/abis_nm.h>

#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/bts.h>
#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/nm_common_fsm.h>

const struct value_string bts_attribute_names[] = {
	OSMO_VALUE_STRING(BTS_TYPE_VARIANT),
	OSMO_VALUE_STRING(BTS_SUB_MODEL),
	OSMO_VALUE_STRING(TRX_PHY_VERSION),
	{ 0, NULL }
};

enum bts_attribute str2btsattr(const char *s)
{
	return get_string_value(bts_attribute_names, s);
}

const char *btsatttr2str(enum bts_attribute v)
{
	return get_value_string(bts_attribute_names, v);
}

const struct value_string osmo_bts_variant_names[_NUM_BTS_VARIANT + 1] = {
	{ BTS_UNKNOWN,		"unknown" },
	{ BTS_OSMO_LITECELL15,	"osmo-bts-lc15" },
	{ BTS_OSMO_OCTPHY,	"osmo-bts-octphy" },
	{ BTS_OSMO_SYSMO,	"osmo-bts-sysmo" },
	{ BTS_OSMO_TRX,		"omso-bts-trx" },
	{ 0, NULL }
};

enum gsm_bts_type_variant str2btsvariant(const char *arg)
{
	return get_string_value(osmo_bts_variant_names, arg);
}

const char *btsvariant2str(enum gsm_bts_type_variant v)
{
	return get_value_string(osmo_bts_variant_names, v);
}

const struct value_string bts_type_names[_NUM_GSM_BTS_TYPE + 1] = {
	{ GSM_BTS_TYPE_UNKNOWN,		"unknown" },
	{ GSM_BTS_TYPE_BS11,		"bs11" },
	{ GSM_BTS_TYPE_NANOBTS,		"nanobts" },
	{ GSM_BTS_TYPE_RBS2000,		"rbs2000" },
	{ GSM_BTS_TYPE_NOKIA_SITE,	"nokia_site" },
	{ GSM_BTS_TYPE_OSMOBTS,		"osmo-bts" },
	{ 0, NULL }
};

const struct value_string bts_type_descs[_NUM_GSM_BTS_TYPE+1] = {
	{ GSM_BTS_TYPE_UNKNOWN,		"Unknown BTS Type" },
	{ GSM_BTS_TYPE_BS11,		"Siemens BTS (BS-11 or compatible)" },
	{ GSM_BTS_TYPE_NANOBTS,		"ip.access nanoBTS or compatible" },
	{ GSM_BTS_TYPE_RBS2000,		"Ericsson RBS2000 Series" },
	{ GSM_BTS_TYPE_NOKIA_SITE,	"Nokia {Metro,Ultra,In}Site" },
	{ GSM_BTS_TYPE_OSMOBTS,		"Osmocom Base Transceiver Station" },
	{ 0,				NULL }
};

enum gsm_bts_type str2btstype(const char *arg)
{
	return get_string_value(bts_type_names, arg);
}

const char *btstype2str(enum gsm_bts_type type)
{
	return get_value_string(bts_type_names, type);
}

static void bts_init_cbch_state(struct bts_smscb_chan_state *cstate, struct gsm_bts *bts)
{
	cstate->bts = bts;
	INIT_LLIST_HEAD(&cstate->messages);
}

static LLIST_HEAD(bts_models);

struct gsm_bts_model *bts_model_find(enum gsm_bts_type type)
{
	struct gsm_bts_model *model;

	llist_for_each_entry(model, &bts_models, list) {
		if (model->type == type)
			return model;
	}

	return NULL;
}

int gsm_bts_model_register(struct gsm_bts_model *model)
{
	if (bts_model_find(model->type))
		return -EEXIST;

	tlv_def_patch(&model->nm_att_tlvdef, &abis_nm_att_tlvdef);
	llist_add_tail(&model->list, &bts_models);
	return 0;
}

static const uint8_t bts_cell_timer_default[] =
				{ 3, 3, 3, 3, 3, 10, 3, 10, 3, 10, 3 };
static const struct gprs_rlc_cfg rlc_cfg_default = {
	.parameter = {
		[RLC_T3142] = 20,
		[RLC_T3169] = 5,
		[RLC_T3191] = 5,
		[RLC_T3193] = 160, /* 10ms */
		[RLC_T3195] = 5,
		[RLC_N3101] = 10,
		[RLC_N3103] = 4,
		[RLC_N3105] = 8,
		[CV_COUNTDOWN] = 15,
		[T_DL_TBF_EXT] = 250 * 10, /* ms */
		[T_UL_TBF_EXT] = 250 * 10, /* ms */
	},
	.paging = {
		.repeat_time = 5 * 50, /* ms */
		.repeat_count = 3,
	},
	.cs_mask = 0x1fff,
	.initial_cs = 2,
	.initial_mcs = 6,
};

static int gsm_bts_talloc_destructor(struct gsm_bts *bts)
{
	bts->site_mgr->bts[0] = NULL;

	if (bts->gprs.cell.mo.fi) {
		osmo_fsm_inst_free(bts->gprs.cell.mo.fi);
		bts->gprs.cell.mo.fi = NULL;
	}

	if (bts->mo.fi) {
		osmo_fsm_inst_free(bts->mo.fi);
		bts->mo.fi = NULL;
	}
	return 0;
}

/* Initialize those parts that don't require osmo-bsc specific dependencies.
 * This part is shared among the thin programs in osmo-bsc/src/utils/.
 * osmo-bsc requires further initialization that pulls in more dependencies (see
 * bsc_bts_alloc_register()). */
struct gsm_bts *gsm_bts_alloc(struct gsm_network *net, struct gsm_bts_sm *bts_sm, uint8_t bts_num)
{
	struct gsm_bts *bts = talloc_zero(bts_sm, struct gsm_bts);
	struct gsm48_multi_rate_conf mr_cfg;
	int i;

	if (!bts)
		return NULL;

	talloc_set_destructor(bts, gsm_bts_talloc_destructor);

	bts->nr = bts_num;
	bts->num_trx = 0;
	INIT_LLIST_HEAD(&bts->trx_list);
	bts->network = net;

	bts->ms_max_power = 15;	/* dBm */

	bts->site_mgr = bts_sm;

	bts->mo.fi = osmo_fsm_inst_alloc(&nm_bts_fsm, bts, bts,
					      LOGL_INFO, NULL);
	osmo_fsm_inst_update_id_f(bts->mo.fi, "bts%d", bts->nr);
	gsm_mo_init(&bts->mo, bts, NM_OC_BTS, bts->nr, 0xff, 0xff);

	/* 3GPP TS 08.18, chapter 5.4.1: 0 is reserved for signalling */
	bts->gprs.cell.bvci = 2;
	memcpy(&bts->gprs.cell.timer, bts_cell_timer_default,
		sizeof(bts->gprs.cell.timer));
	memcpy(&bts->gprs.cell.rlc_cfg, &rlc_cfg_default,
		sizeof(bts->gprs.cell.rlc_cfg));
	bts->gprs.cell.mo.fi = osmo_fsm_inst_alloc(&nm_gprs_cell_fsm, bts,
						   &bts->gprs.cell, LOGL_INFO, NULL);
	osmo_fsm_inst_update_id_f(bts->gprs.cell.mo.fi, "gprs-cell%d", bts->nr);
	gsm_mo_init(&bts->gprs.cell.mo, bts, NM_OC_GPRS_CELL,
			bts->nr, 0xff, 0xff);

	/* init statistics */
	bts->bts_ctrs = rate_ctr_group_alloc(bts, &bts_ctrg_desc, bts->nr);
	if (!bts->bts_ctrs) {
		talloc_free(bts);
		return NULL;
	}
	bts->bts_statg = osmo_stat_item_group_alloc(bts, &bts_statg_desc, bts->nr);

	/* create our primary TRX */
	bts->c0 = gsm_bts_trx_alloc(bts);
	if (!bts->c0) {
		rate_ctr_group_free(bts->bts_ctrs);
		osmo_stat_item_group_free(bts->bts_statg);
		talloc_free(bts);
		return NULL;
	}
	bts->c0->ts[0].pchan_from_config = GSM_PCHAN_CCCH_SDCCH4; /* TODO: really?? */

	bts->ccch_load_ind_thresh = 10; /* 10% of Load: Start sending CCCH LOAD IND */
	bts->rach_b_thresh = -1;
	bts->rach_ldavg_slots = -1;

	bts->paging.free_chans_need = -1;
	INIT_LLIST_HEAD(&bts->paging.pending_requests);

	bts->features.data = &bts->_features_data[0];
	bts->features.data_len = sizeof(bts->_features_data);

	/* si handling */
	bts->bcch_change_mark = 1;
	bts->chan_load_avg = 0;

	/* timer overrides */
	bts->T3122 = 0; /* not overridden by default */
	bts->T3113_dynamic = true; /* dynamic by default */

	bts->dtxu = GSM48_DTX_SHALL_NOT_BE_USED;
	bts->dtxd = false;
	bts->gprs.ctrl_ack_type_use_block = true; /* use RLC/MAC control block */
	bts->neigh_list_manual_mode = NL_MODE_AUTOMATIC;
	bts->early_classmark_allowed_3g = true; /* 3g Early Classmark Sending controlled by bts->early_classmark_allowed param */
	bts->si_unused_send_empty = true;
	bts->chan_alloc_allow_tch_for_signalling = true;
	bts->si_common.cell_sel_par.cell_resel_hyst = 2; /* 4 dB */
	bts->si_common.cell_sel_par.rxlev_acc_min = 0;
	bts->si_common.si2quater_neigh_list.arfcn = bts->si_common.data.earfcn_list;
	bts->si_common.si2quater_neigh_list.meas_bw = bts->si_common.data.meas_bw_list;
	bts->si_common.si2quater_neigh_list.length = MAX_EARFCN_LIST;
	bts->si_common.si2quater_neigh_list.thresh_hi = 0;
	osmo_earfcn_init(&bts->si_common.si2quater_neigh_list);
	bts->si_common.neigh_list.data = bts->si_common.data.neigh_list;
	bts->si_common.neigh_list.data_len =
				sizeof(bts->si_common.data.neigh_list);
	bts->si_common.si5_neigh_list.data = bts->si_common.data.si5_neigh_list;
	bts->si_common.si5_neigh_list.data_len =
				sizeof(bts->si_common.data.si5_neigh_list);
	bts->si_common.cell_alloc.data = bts->si_common.data.cell_alloc;
	bts->si_common.cell_alloc.data_len =
				sizeof(bts->si_common.data.cell_alloc);
	bts->si_common.rach_control.re = 1; /* no re-establishment */
	bts->si_common.rach_control.tx_integer = 9;  /* 12 slots spread - 217/115 slots delay */
	bts->si_common.rach_control.max_trans = 3; /* 7 retransmissions */
	bts->si_common.rach_control.t2 = 4; /* no emergency calls */
	bts->si_common.chan_desc.mscr = 1; /* Indicate R99 MSC in SI3 */
	bts->si_common.chan_desc.att = 1; /* attachment required */
	bts->si_common.chan_desc.bs_pa_mfrms = RSL_BS_PA_MFRMS_5; /* paging frames */
	bts->si_common.chan_desc.bs_ag_blks_res = 1; /* reserved AGCH blocks */
	bts->si_common.chan_desc.t3212 = osmo_tdef_get(net->T_defs, 3212, OSMO_TDEF_CUSTOM, -1);
	bts->si_common.cell_options.pwrc = 0; /* PWRC not set */
	bts->si_common.cell_sel_par.acs = 0;
	bts->si_common.ncc_permitted = 0xff;
	gsm_bts_set_radio_link_timeout(bts, 32); /* Use RADIO LINK TIMEOUT of 32 */

	INIT_LLIST_HEAD(&bts->abis_queue);
	INIT_LLIST_HEAD(&bts->loc_list);
	INIT_LLIST_HEAD(&bts->neighbors);
	INIT_LLIST_HEAD(&bts->oml_fail_rep);
	INIT_LLIST_HEAD(&bts->chan_rqd_queue);

	/* Enable all codecs by default. These get reset to a more fine grained selection IF a
	 * 'codec-support' config appears in the config file (see bsc_vty.c). */
	bts->codec = (struct bts_codec_conf){
		.hr = 1,
		.efr = 1,
		.amr = 1,
	};

	/* Set reasonable defaults for AMR-FR and AMR-HR rate configuration.
	 * (see also 3GPP TS 28.062, Table 7.11.3.1.3-2) */
	mr_cfg = (struct gsm48_multi_rate_conf) {
		.m4_75 = 1,
		.m5_15 = 0,
		.m5_90 = 1,
		.m6_70 = 0,
		.m7_40 = 1,
		.m7_95 = 0,
		.m10_2 = 0,
		.m12_2 = 1
	};
	memcpy(bts->mr_full.gsm48_ie, &mr_cfg, sizeof(bts->mr_full.gsm48_ie));
	bts->mr_full.ms_mode[0].mode = 0;
	bts->mr_full.ms_mode[1].mode = 2;
	bts->mr_full.ms_mode[2].mode = 4;
	bts->mr_full.ms_mode[3].mode = 7;
	bts->mr_full.bts_mode[0].mode = 0;
	bts->mr_full.bts_mode[1].mode = 2;
	bts->mr_full.bts_mode[2].mode = 4;
	bts->mr_full.bts_mode[3].mode = 7;
	for (i = 0; i < 3; i++) {
		bts->mr_full.ms_mode[i].hysteresis = 8;
		bts->mr_full.ms_mode[i].threshold = 32;
		bts->mr_full.bts_mode[i].hysteresis = 8;
		bts->mr_full.bts_mode[i].threshold = 32;
	}
	bts->mr_full.num_modes = 4;

	mr_cfg = (struct gsm48_multi_rate_conf) {
		.m4_75 = 1,
		.m5_15 = 0,
		.m5_90 = 1,
		.m6_70 = 0,
		.m7_40 = 1,
		.m7_95 = 0,
		.m10_2 = 0,
		.m12_2 = 0
	};
	memcpy(bts->mr_half.gsm48_ie, &mr_cfg, sizeof(bts->mr_half.gsm48_ie));
	bts->mr_half.ms_mode[0].mode = 0;
	bts->mr_half.ms_mode[1].mode = 2;
	bts->mr_half.ms_mode[2].mode = 4;
	bts->mr_half.ms_mode[3].mode = 7;
	bts->mr_half.bts_mode[0].mode = 0;
	bts->mr_half.bts_mode[1].mode = 2;
	bts->mr_half.bts_mode[2].mode = 4;
	bts->mr_half.bts_mode[3].mode = 7;
	for (i = 0; i < 3; i++) {
		bts->mr_half.ms_mode[i].hysteresis = 8;
		bts->mr_half.ms_mode[i].threshold = 32;
		bts->mr_half.bts_mode[i].hysteresis = 8;
		bts->mr_half.bts_mode[i].threshold = 32;
	}
	bts->mr_half.num_modes = 3;

	bts_init_cbch_state(&bts->cbch_basic, bts);
	bts_init_cbch_state(&bts->cbch_extended, bts);

	acc_mgr_init(&bts->acc_mgr, bts);
	acc_ramp_init(&bts->acc_ramp, bts);

	/* Default RxQual threshold for ACCH repetition/overpower */
	bts->repeated_acch_policy.rxqual = 4;
	bts->temporary_overpower.rxqual = 4;

	/* MS Power Control parameters (defaults) */
	power_ctrl_params_def_reset(&bts->ms_power_ctrl, GSM_PWR_CTRL_DIR_UL);

	/* BS Power Control parameters (defaults) */
	power_ctrl_params_def_reset(&bts->bs_power_ctrl, GSM_PWR_CTRL_DIR_DL);

	/* Interference Measurement Parameters (defaults) */
	bts->interf_meas_params_cfg = interf_meas_params_def;

	bts->rach_max_delay = 63;

	/* SRVCC is enabled by default */
	bts->srvcc_fast_return_allowed = true;

	return bts;
}

static char ts2str[255];

char *gsm_bts_name(const struct gsm_bts *bts)
{
	if (!bts)
		snprintf(ts2str, sizeof(ts2str), "(bts=NULL)");
	else
		snprintf(ts2str, sizeof(ts2str), "(bts=%d)", bts->nr);

	return ts2str;
}

bool gsm_bts_matches_lai(const struct gsm_bts *bts, const struct osmo_location_area_id *lai)
{
	return osmo_plmn_cmp(&lai->plmn, &bts->network->plmn) == 0
		&& lai->lac == bts->location_area_code;
}

bool gsm_bts_matches_cell_id(const struct gsm_bts *bts, const struct gsm0808_cell_id *cell_id)
{
	const union gsm0808_cell_id_u *id = &cell_id->id;
	if (!bts || !cell_id)
		return false;

	switch (cell_id->id_discr) {
	case CELL_IDENT_WHOLE_GLOBAL:
		return gsm_bts_matches_lai(bts, &id->global.lai)
			&& id->global.cell_identity == bts->cell_identity;
	case CELL_IDENT_WHOLE_GLOBAL_PS:
		return gsm_bts_matches_lai(bts, &id->global_ps.rai.lac)
			&& id->global_ps.rai.rac == bts->gprs.rac
			&& id->global_ps.cell_identity == bts->cell_identity;
	case CELL_IDENT_LAC_AND_CI:
		return id->lac_and_ci.lac == bts->location_area_code
			&& id->lac_and_ci.ci == bts->cell_identity;
	case CELL_IDENT_CI:
		return id->ci == bts->cell_identity;
	case CELL_IDENT_NO_CELL:
		return false;
	case CELL_IDENT_LAI_AND_LAC:
		return gsm_bts_matches_lai(bts, &id->lai_and_lac);
	case CELL_IDENT_LAC:
		return id->lac == bts->location_area_code;
	case CELL_IDENT_BSS:
		return true;
	case CELL_IDENT_UTRAN_PLMN_LAC_RNC:
	case CELL_IDENT_UTRAN_RNC:
	case CELL_IDENT_UTRAN_LAC_RNC:
		return false;
	default:
		OSMO_ASSERT(false);
	}
}

/* Return a LAC+CI cell identity for the given BTS.
 * (For matching a BTS within the local BSS, the PLMN code is not important.) */
void gsm_bts_cell_id(struct gsm0808_cell_id *cell_id, const struct gsm_bts *bts)
{
	*cell_id = (struct gsm0808_cell_id){
		.id_discr = CELL_IDENT_LAC_AND_CI,
		.id.lac_and_ci = {
			.lac = bts->location_area_code,
			.ci = bts->cell_identity,
		},
	};
}

/* Same as gsm_bts_cell_id(), but return in a single-entry gsm0808_cell_id_list2. Useful for e.g.
 * gsm0808_cell_id_list_add() and gsm0808_cell_id_lists_same(). */
void gsm_bts_cell_id_list(struct gsm0808_cell_id_list2 *cell_id_list, const struct gsm_bts *bts)
{
	struct gsm0808_cell_id cell_id;
	struct gsm0808_cell_id_list2 add;
	int rc;
	gsm_bts_cell_id(&cell_id, bts);
	gsm0808_cell_id_to_list(&add, &cell_id);
	/* Since the target list is empty, this should always succeed. */
	(*cell_id_list) = (struct gsm0808_cell_id_list2){};
	rc = gsm0808_cell_id_list_add(cell_id_list, &add);
	OSMO_ASSERT(rc > 0);
}

/* return the gsm_lchan for the CBCH (if it exists at all) */
struct gsm_lchan *gsm_bts_get_cbch(struct gsm_bts *bts)
{
	struct gsm_lchan *lchan = NULL;
	struct gsm_bts_trx *trx = bts->c0;

	if (trx->ts[0].pchan_from_config == GSM_PCHAN_CCCH_SDCCH4_CBCH)
		lchan = &trx->ts[0].lchan[2];
	else {
		int i;
		for (i = 0; i < 8; i++) {
			if (trx->ts[i].pchan_from_config == GSM_PCHAN_SDCCH8_SACCH8C_CBCH) {
				lchan = &trx->ts[i].lchan[2];
				break;
			}
		}
	}

	return lchan;
}

int gsm_set_bts_type(struct gsm_bts *bts, enum gsm_bts_type type)
{
	struct gsm_bts_model *model;

	if (bts->type != GSM_BTS_TYPE_UNKNOWN && type != bts->type)
		return -EBUSY;

	model = bts_model_find(type);
	if (!model)
		return -EINVAL;

	bts->type = type;
	bts->model = model;

	if (model->start && !model->started) {
		int ret = model->start(bts->network);
		if (ret < 0)
			return ret;

		model->started = true;
	}

	if (model->bts_init) {
		int rc = model->bts_init(bts);
		if (rc < 0)
			return rc;
	}

	/* handle those TRX which are already allocated at the time we set the type */
	if (model->trx_init) {
		struct gsm_bts_trx *trx;
		llist_for_each_entry(trx, &bts->trx_list, list)
			model->trx_init(trx);
	}

	switch (bts->type) {
	case GSM_BTS_TYPE_OSMOBTS:
	case GSM_BTS_TYPE_NANOBTS:
		/* Set the default OML Stream ID to 0xff */
		bts->oml_tei = 0xff;
		bts->c0->nominal_power = 23;
		break;
	case GSM_BTS_TYPE_RBS2000:
		INIT_LLIST_HEAD(&bts->rbs2000.is.conn_groups);
		INIT_LLIST_HEAD(&bts->rbs2000.con.conn_groups);
		break;
	case GSM_BTS_TYPE_BS11:
	case GSM_BTS_TYPE_UNKNOWN:
	case GSM_BTS_TYPE_NOKIA_SITE:
		/* Set default BTS reset timer */
		bts->nokia.bts_reset_timer_cnf = 15;
	case _NUM_GSM_BTS_TYPE:
		break;
	}

	/* Enable dynamic Uplink power control by default (if supported) */
	if (model->power_ctrl_enc_rsl_params != NULL)
		bts->ms_power_ctrl.mode = GSM_PWR_CTRL_MODE_DYN_BTS;

	return 0;
}

int bts_gprs_mode_is_compat(struct gsm_bts *bts, enum bts_gprs_mode mode)
{
	if (mode != BTS_GPRS_NONE &&
	    !osmo_bts_has_feature(&bts->model->features, BTS_FEAT_GPRS)) {
		return 0;
	}
	if (mode == BTS_GPRS_EGPRS &&
	    !osmo_bts_has_feature(&bts->model->features, BTS_FEAT_EGPRS)) {
		return 0;
	}

	return 1;
}

struct gsm_bts_trx *gsm_bts_trx_num(const struct gsm_bts *bts, int num)
{
	struct gsm_bts_trx *trx;

	if (num >= bts->num_trx)
		return NULL;

	llist_for_each_entry(trx, &bts->trx_list, list) {
		if (trx->nr == num)
			return trx;
	}

	return NULL;
}

void bts_store_uptime(struct gsm_bts *bts)
{
	osmo_stat_item_set(osmo_stat_item_group_get_item(bts->bts_statg, BTS_STAT_UPTIME_SECONDS), bts_uptime(bts));
}

unsigned long long bts_uptime(const struct gsm_bts *bts)
{
	struct timespec tp;

	if (!bts->uptime || !bts->oml_link)
		return 0;

	if (osmo_clock_gettime(CLOCK_MONOTONIC, &tp) != 0) {
		LOGP(DNM, LOGL_ERROR, "BTS %u uptime computation failure: %s\n", bts->nr, strerror(errno));
		return 0;
	}

	/* monotonic clock helps to ensure that the conversion is valid */
	return difftime(tp.tv_sec, bts->uptime);
}

char *get_model_oml_status(const struct gsm_bts *bts)
{
	if (bts->model->oml_status)
		return bts->model->oml_status(bts);

	return "unknown";
}

/* reset the state of all MO in the BTS */
void gsm_bts_mo_reset(struct gsm_bts *bts)
{
	struct gsm_bts_trx *trx;
	unsigned int i;

	gsm_abis_mo_reset(&bts->mo);
	gsm_abis_mo_reset(&bts->gprs.cell.mo);

	llist_for_each_entry(trx, &bts->trx_list, list) {
		gsm_abis_mo_reset(&trx->mo);
		gsm_abis_mo_reset(&trx->bb_transc.mo);

		for (i = 0; i < ARRAY_SIZE(trx->ts); i++) {
			struct gsm_bts_trx_ts *ts = &trx->ts[i];
			gsm_abis_mo_reset(&ts->mo);
		}
	}
}

/* Assume there are only 256 possible bts */
osmo_static_assert(sizeof(((struct gsm_bts *) 0)->nr) == 1, _bts_nr_is_256);
static void depends_calc_index_bit(int bts_nr, int *idx, int *bit)
{
	*idx = bts_nr / (8 * 4);
	*bit = bts_nr % (8 * 4);
}

void bts_depend_mark(struct gsm_bts *bts, int dep)
{
	int idx, bit;
	depends_calc_index_bit(dep, &idx, &bit);

	bts->depends_on[idx] |= 1 << bit;
}

void bts_depend_clear(struct gsm_bts *bts, int dep)
{
	int idx, bit;
	depends_calc_index_bit(dep, &idx, &bit);

	bts->depends_on[idx] &= ~(1 << bit);
}

int bts_depend_is_depedency(struct gsm_bts *base, struct gsm_bts *other)
{
	int idx, bit;
	depends_calc_index_bit(other->nr, &idx, &bit);

	/* Check if there is a depends bit */
	return (base->depends_on[idx] & (1 << bit)) > 0;
}

static int bts_is_online(struct gsm_bts *bts)
{
	/* TODO: support E1 BTS too */
	if (!is_ipaccess_bts(bts))
		return 1;

	if (!bts->oml_link)
		return 0;

	return bts->mo.nm_state.operational == NM_OPSTATE_ENABLED;
}

int bts_depend_check(struct gsm_bts *bts)
{
	struct gsm_bts *other_bts;

	llist_for_each_entry(other_bts, &bts->network->bts_list, list) {
		if (!bts_depend_is_depedency(bts, other_bts))
			continue;
		if (bts_is_online(other_bts))
			continue;
		return 0;
	}
	return 1;
}

/* get the radio link timeout (based on SACCH decode errors, according
 * to algorithm specified in TS 05.08 section 5.2.  A value of -1
 * indicates we should use an infinitely long timeout, which only works
 * with OsmoBTS as the BTS implementation */
int gsm_bts_get_radio_link_timeout(const struct gsm_bts *bts)
{
	const struct gsm48_cell_options *cell_options = &bts->si_common.cell_options;

	if (bts->infinite_radio_link_timeout)
		return -1;
	else {
		/* Encoding as per Table 10.5.21 of TS 04.08 */
		return (cell_options->radio_link_timeout + 1) << 2;
	}
}

/* set the radio link timeout (based on SACCH decode errors, according
 * to algorithm specified in TS 05.08 Section 5.2.  A value of -1
 * indicates we should use an infinitely long timeout, which only works
 * with OsmoBTS as the BTS implementation */
void gsm_bts_set_radio_link_timeout(struct gsm_bts *bts, int value)
{
	struct gsm48_cell_options *cell_options = &bts->si_common.cell_options;

	if (value < 0)
		bts->infinite_radio_link_timeout = true;
	else {
		bts->infinite_radio_link_timeout = false;
		/* Encoding as per Table 10.5.21 of TS 04.08 */
		if (value < 4)
			value = 4;
		if (value > 64)
			value = 64;
		cell_options->radio_link_timeout = (value >> 2) - 1;
	}
}

void gsm_bts_all_ts_dispatch(struct gsm_bts *bts, uint32_t ts_ev, void *data)
{
	struct gsm_bts_trx *trx;
	llist_for_each_entry(trx, &bts->trx_list, list)
		gsm_trx_all_ts_dispatch(trx, ts_ev, data);
}

/* set all system information types for a BTS */
int gsm_bts_set_system_infos(struct gsm_bts *bts)
{
	struct gsm_bts_trx *trx;

	/* Generate a new ID */
	bts->bcch_change_mark += 1;
	bts->bcch_change_mark %= 0x7;

	llist_for_each_entry(trx, &bts->trx_list, list) {
		int rc;

		rc = gsm_bts_trx_set_system_infos(trx);
		if (rc != 0)
			return rc;
	}

	return 0;
}

int gsm_bts_set_c0_power_red(struct gsm_bts *bts, const uint8_t red)
{
	struct gsm_bts_trx *c0 = bts->c0;
	unsigned int tn;
	int rc;

	if (!osmo_bts_has_feature(&bts->features, BTS_FEAT_BCCH_POWER_RED))
		return -ENOTSUP;
	if (bts->model->power_ctrl_set_c0_power_red == NULL)
		return -ENOTSUP;

	rc = bts->model->power_ctrl_set_c0_power_red(bts, red);
	if (rc != 0)
		return rc;

	/* Timeslot 0 is always transmitting BCCH/CCCH */
	c0->ts[0].c0_max_power_red_db = 0;

	for (tn = 1; tn < ARRAY_SIZE(c0->ts); tn++) {
		struct gsm_bts_trx_ts *ts = &c0->ts[tn];
		struct gsm_bts_trx_ts *prev = ts - 1;

		switch (ts->pchan_is) {
		/* Not allowed on CCCH/BCCH */
		case GSM_PCHAN_CCCH:
			/* Preceeding timeslot shall not exceed 2 dB */
			if (prev->c0_max_power_red_db > 0)
				prev->c0_max_power_red_db = 2;
			/* fall-through */
		/* Not recommended on SDCCH/8 */
		case GSM_PCHAN_SDCCH8_SACCH8C:
		case GSM_PCHAN_SDCCH8_SACCH8C_CBCH:
			ts->c0_max_power_red_db = 0;
			break;
		default:
			ts->c0_max_power_red_db = red;
			break;
		}
	}

	/* Timeslot 7 is always preceding BCCH/CCCH */
	if (c0->ts[7].c0_max_power_red_db > 0)
		c0->ts[7].c0_max_power_red_db = 2;

	bts->c0_max_power_red_db = red;

	return 0;
}

void gsm_bts_stats_reset(struct gsm_bts *bts)
{
	osmo_stat_item_set(osmo_stat_item_group_get_item(bts->bts_statg, BTS_STAT_CHAN_CCCH_SDCCH4_USED), 0);
	osmo_stat_item_set(osmo_stat_item_group_get_item(bts->bts_statg, BTS_STAT_CHAN_CCCH_SDCCH4_TOTAL), 0);
	osmo_stat_item_set(osmo_stat_item_group_get_item(bts->bts_statg, BTS_STAT_CHAN_TCH_F_USED), 0);
	osmo_stat_item_set(osmo_stat_item_group_get_item(bts->bts_statg, BTS_STAT_CHAN_TCH_F_TOTAL), 0);
	osmo_stat_item_set(osmo_stat_item_group_get_item(bts->bts_statg, BTS_STAT_CHAN_TCH_H_USED), 0);
	osmo_stat_item_set(osmo_stat_item_group_get_item(bts->bts_statg, BTS_STAT_CHAN_TCH_H_TOTAL), 0);
	osmo_stat_item_set(osmo_stat_item_group_get_item(bts->bts_statg, BTS_STAT_CHAN_SDCCH8_USED), 0);
	osmo_stat_item_set(osmo_stat_item_group_get_item(bts->bts_statg, BTS_STAT_CHAN_SDCCH8_TOTAL), 0);
	osmo_stat_item_set(osmo_stat_item_group_get_item(bts->bts_statg, BTS_STAT_CHAN_TCH_F_PDCH_USED), 0);
	osmo_stat_item_set(osmo_stat_item_group_get_item(bts->bts_statg, BTS_STAT_CHAN_TCH_F_PDCH_TOTAL), 0);
	osmo_stat_item_set(osmo_stat_item_group_get_item(bts->bts_statg, BTS_STAT_CHAN_CCCH_SDCCH4_CBCH_USED), 0);
	osmo_stat_item_set(osmo_stat_item_group_get_item(bts->bts_statg, BTS_STAT_CHAN_CCCH_SDCCH4_CBCH_TOTAL), 0);
	osmo_stat_item_set(osmo_stat_item_group_get_item(bts->bts_statg, BTS_STAT_CHAN_SDCCH8_CBCH_USED), 0);
	osmo_stat_item_set(osmo_stat_item_group_get_item(bts->bts_statg, BTS_STAT_CHAN_SDCCH8_CBCH_TOTAL), 0);
	osmo_stat_item_set(osmo_stat_item_group_get_item(bts->bts_statg, BTS_STAT_CHAN_OSMO_DYN_USED), 0);
	osmo_stat_item_set(osmo_stat_item_group_get_item(bts->bts_statg, BTS_STAT_CHAN_OSMO_DYN_TOTAL), 0);
}

const struct rate_ctr_desc bts_ctr_description[] = {
	[BTS_CTR_CHREQ_TOTAL] = \
		{ "chreq:total",
		  "Received channel requests" },
	[BTS_CTR_CHREQ_ATTEMPTED_EMERG] = \
		{ "chreq:attempted_emerg",
		  "Received channel requests EMERG" },
	[BTS_CTR_CHREQ_ATTEMPTED_CALL] = \
		{ "chreq:attempted_call",
		  "Received channel requests CALL" },
	[BTS_CTR_CHREQ_ATTEMPTED_LOCATION_UPD] = \
		{ "chreq:attempted_location_upd",
		  "Received channel requests LOCATION_UPD" },
	[BTS_CTR_CHREQ_ATTEMPTED_PAG] = \
		{ "chreq:attempted_pag",
		  "Received channel requests PAG" },
	[BTS_CTR_CHREQ_ATTEMPTED_PDCH] = \
		{ "chreq:attempted_pdch",
		  "Received channel requests PDCH" },
	[BTS_CTR_CHREQ_ATTEMPTED_OTHER] = \
		{ "chreq:attempted_other",
		  "Received channel requests OTHER" },
	[BTS_CTR_CHREQ_ATTEMPTED_UNKNOWN] = \
		{ "chreq:attempted_unknown",
		  "Received channel requests UNKNOWN" },
	[BTS_CTR_CHREQ_SUCCESSFUL] = \
		{ "chreq:successful",
		  "Successful channel requests (immediate assign sent)" },
	[BTS_CTR_CHREQ_SUCCESSFUL_EMERG] = \
		{ "chreq:successful_emerg",
		  "Sent Immediate Assignment for EMERG" },
	[BTS_CTR_CHREQ_SUCCESSFUL_CALL] = \
		{ "chreq:successful_call",
		  "Sent Immediate Assignment for CALL" },
	[BTS_CTR_CHREQ_SUCCESSFUL_LOCATION_UPD] = \
		{ "chreq:successful_location_upd",
		  "Sent Immediate Assignment for LOCATION_UPD" },
	[BTS_CTR_CHREQ_SUCCESSFUL_PAG] = \
		{ "chreq:successful_pag",
		  "Sent Immediate Assignment for PAG" },
	[BTS_CTR_CHREQ_SUCCESSFUL_PDCH] = \
		{ "chreq:successful_pdch",
		  "Sent Immediate Assignment for PDCH" },
	[BTS_CTR_CHREQ_SUCCESSFUL_OTHER] = \
		{ "chreq:successful_other",
		  "Sent Immediate Assignment for OTHER" },
	[BTS_CTR_CHREQ_SUCCESSFUL_UNKNOWN] = \
		{ "chreq:successful_unknown",
		  "Sent Immediate Assignment for UNKNOWN" },
	[BTS_CTR_CHREQ_NO_CHANNEL] = \
		{ "chreq:no_channel",
		  "Sent to MS no channel available" },
	[BTS_CTR_CHREQ_MAX_DELAY_EXCEEDED] = \
		{ "chreq:max_delay_exceeded",
		  "Received channel requests with greater than permitted access delay" },
	[BTS_CTR_CHAN_RF_FAIL] = \
		{ "chan:rf_fail",
		  "Received a RF failure indication from BTS" },
	[BTS_CTR_CHAN_RF_FAIL_TCH] = \
		{ "chan:rf_fail_tch",
		  "Received a RF failure indication from BTS on a TCH channel" },
	[BTS_CTR_CHAN_RF_FAIL_SDCCH] = \
		{ "chan:rf_fail_sdcch",
		  "Received a RF failure indication from BTS on an SDCCH channel" },
	[BTS_CTR_CHAN_RLL_ERR] = \
		{ "chan:rll_err",
		  "Received a RLL failure with T200 cause from BTS" },
	[BTS_CTR_BTS_OML_FAIL] = \
		{ "oml_fail",
		  "Received a TEI down on a OML link" },
	[BTS_CTR_BTS_RSL_FAIL] = \
		{ "rsl_fail",
		  "Received a TEI down on a OML link" },
	[BTS_CTR_CODEC_AMR_F] = \
		{ "codec:amr_f",
		  "Count the usage of AMR/F codec by channel mode requested" },
	[BTS_CTR_CODEC_AMR_H] = \
		{ "codec:amr_h",
		  "Count the usage of AMR/H codec by channel mode requested" },
	[BTS_CTR_CODEC_EFR] = \
		{ "codec:efr",
		  "Count the usage of EFR codec by channel mode requested" },
	[BTS_CTR_CODEC_V1_FR] = \
		{ "codec:fr",
		  "Count the usage of FR codec by channel mode requested" },
	[BTS_CTR_CODEC_V1_HR] = \
		{ "codec:hr",
		  "Count the usage of HR codec by channel mode requested" },
	[BTS_CTR_PAGING_ATTEMPTED] = \
		{ "paging:attempted",
		  "Paging attempts for a subscriber" },
	[BTS_CTR_PAGING_ALREADY] = \
		{ "paging:already",
		  "Paging attempts ignored as subscriber was already being paged" },
	[BTS_CTR_PAGING_RESPONDED] = \
		{ "paging:responded",
		  "Paging attempts with successful paging response" },
	[BTS_CTR_PAGING_EXPIRED] = \
		{ "paging:expired",
		  "Paging Request expired because of timeout T3113" },
	[BTS_CTR_PAGING_NO_ACTIVE_PAGING] = \
		{ "paging:no_active_paging",
		  "Paging response without an active paging request (arrived after paging expiration?)" },
	[BTS_CTR_PAGING_MSC_FLUSH] = \
		{ "paging:msc_flush",
		  "Paging flushed due to MSC Reset BSSMAP message" },
	[BTS_CTR_CHAN_ACT_TOTAL] = \
		{ "chan_act:total",
		  "Total number of Channel Activations" },
	[BTS_CTR_CHAN_ACT_SDCCH] = \
		{ "chan_act:sdcch",
		  "Number of SDCCH Channel Activations" },
	[BTS_CTR_CHAN_ACT_TCH] = \
		{ "chan_act:tch",
		  "Number of TCH Channel Activations" },
	[BTS_CTR_CHAN_ACT_NACK] = \
		{ "chan_act:nack",
		  "Number of Channel Activations that the BTS NACKed" },
	[BTS_CTR_RSL_UNKNOWN] = \
		{ "rsl:unknown",
		  "Number of unknown/unsupported RSL messages received from BTS" },
	[BTS_CTR_RSL_IPA_NACK] = \
		{ "rsl:ipa_nack",
		  "Number of IPA (RTP/dyn-PDCH) related NACKs received from BTS" },
	[BTS_CTR_RSL_DELETE_IND] = \
		{ "rsl:delete_ind",
		  "Number of RSL DELETE INDICATION (DL CCCH overload)" },
	[BTS_CTR_MODE_MODIFY_NACK] = \
		{ "chan:mode_modify_nack",
		  "Number of Channel Mode Modify NACKs received from BTS" },

	/* lchan/TS BORKEN state counters */
	[BTS_CTR_LCHAN_BORKEN_FROM_UNUSED] = \
		{ "lchan_borken:from_state:unused",
		  "Transitions from lchan UNUSED state to BORKEN state" },
	[BTS_CTR_LCHAN_BORKEN_FROM_WAIT_ACTIV_ACK] = \
		{ "lchan_borken:from_state:wait_activ_ack",
		  "Transitions from lchan WAIT_ACTIV_ACK state to BORKEN state" },
	[BTS_CTR_LCHAN_BORKEN_FROM_WAIT_RF_RELEASE_ACK] = \
		{ "lchan_borken:from_state:wait_rf_release_ack",
		  "Transitions from lchan WAIT_RF_RELEASE_ACK state to BORKEN state" },
	[BTS_CTR_LCHAN_BORKEN_FROM_BORKEN] = \
		{ "lchan_borken:from_state:borken",
		  "Transitions from lchan BORKEN state to BORKEN state" },
	[BTS_CTR_LCHAN_BORKEN_FROM_WAIT_RR_CHAN_MODE_MODIFY_ACK] = \
		{ "lchan_borken:from_state:wait_rr_chan_mode_modify_ack",
		  "Transitions from lchan WAIT_RR_CHAN_MODE_MODIFY_ACK state to BORKEN state" },
	[BTS_CTR_LCHAN_BORKEN_FROM_WAIT_RSL_CHAN_MODE_MODIFY_ACK] = \
		{ "lchan_borken:from_state:wait_rsl_chan_mode_modify_ack",
		  "Transitions from lchan RSL_CHAN_MODE_MODIFY_ACK state to BORKEN state" },
	[BTS_CTR_LCHAN_BORKEN_FROM_UNKNOWN] = \
		{ "lchan_borken:from_state:unknown",
		  "Transitions from an unknown lchan state to BORKEN state" },
	[BTS_CTR_LCHAN_BORKEN_EV_CHAN_ACTIV_ACK] = \
		{ "lchan_borken:event:chan_activ_ack",
		  "CHAN_ACTIV_ACK received in the lchan BORKEN state" },
	[BTS_CTR_LCHAN_BORKEN_EV_CHAN_ACTIV_NACK] = \
		{ "lchan_borken:event:chan_activ_nack",
		  "CHAN_ACTIV_NACK received in the lchan BORKEN state" },
	[BTS_CTR_LCHAN_BORKEN_EV_RF_CHAN_REL_ACK] = \
		{ "lchan_borken:event:rf_chan_rel_ack",
		  "RF_CHAN_REL_ACK received in the lchan BORKEN state" },
	[BTS_CTR_LCHAN_BORKEN_EV_VTY] = \
		{ "lchan_borken:event:vty",
		  "VTY commands received in the lchan BORKEN state" },
	[BTS_CTR_LCHAN_BORKEN_EV_TEARDOWN] = \
		{ "lchan_borken:event:teardown",
		  "lchan in a BORKEN state is shutting down (BTS disconnected?)" },
	[BTS_CTR_LCHAN_BORKEN_EV_TS_ERROR] = \
		{ "lchan_borken:event:ts_error",
		  "LCHAN_EV_TS_ERROR received in a BORKEN state" },
	[BTS_CTR_TS_BORKEN_FROM_NOT_INITIALIZED] = \
		{ "ts_borken:from_state:not_initialized",
		  "Transitions from TS NOT_INITIALIZED state to BORKEN state" },
	[BTS_CTR_TS_BORKEN_FROM_UNUSED] = \
		{ "ts_borken:from_state:unused",
		  "Transitions from TS UNUSED state to BORKEN state" },
	[BTS_CTR_TS_BORKEN_FROM_WAIT_PDCH_ACT] = \
		{ "ts_borken:from_state:wait_pdch_act",
		  "Transitions from TS WAIT_PDCH_ACT state to BORKEN state" },
	[BTS_CTR_TS_BORKEN_FROM_PDCH] = \
		{ "ts_borken:from_state:pdch",
		  "Transitions from TS PDCH state to BORKEN state" },
	[BTS_CTR_TS_BORKEN_FROM_WAIT_PDCH_DEACT] = \
		{ "ts_borken:from_state:wait_pdch_deact",
		  "Transitions from TS WAIT_PDCH_DEACT state to BORKEN state" },
	[BTS_CTR_TS_BORKEN_FROM_IN_USE] = \
		{ "ts_borken:from_state:in_use",
		  "Transitions from TS IN_USE state to BORKEN state" },
	[BTS_CTR_TS_BORKEN_FROM_BORKEN] = \
		{ "ts_borken:from_state:borken",
		  "Transitions from TS BORKEN state to BORKEN state" },
	[BTS_CTR_TS_BORKEN_FROM_UNKNOWN] = \
		{ "ts_borken:from_state:unknown",
		  "Transitions from an unknown TS state to BORKEN state" },
	[BTS_CTR_TS_BORKEN_EV_PDCH_ACT_ACK_NACK] = \
		{ "ts_borken:event:pdch_act_ack_nack",
		  "PDCH_ACT_ACK/NACK received in the TS BORKEN state" },
	[BTS_CTR_TS_BORKEN_EV_PDCH_DEACT_ACK_NACK] = \
		{ "ts_borken:event:pdch_deact_ack_nack",
		  "PDCH_DEACT_ACK/NACK received in the TS BORKEN state" },
	[BTS_CTR_TS_BORKEN_EV_TEARDOWN] = \
		{ "ts_borken:event:teardown",
		  "TS in a BORKEN state is shutting down (BTS disconnected?)" },
	[BTS_CTR_ASSIGNMENT_ATTEMPTED] = \
		{ "assignment:attempted",
		  "Assignment attempts" },
	[BTS_CTR_ASSIGNMENT_ATTEMPTED_SIGN] = \
		{ "assignment:attempted_sign",
		  "Assignment of signaling lchan attempts" },
	[BTS_CTR_ASSIGNMENT_ATTEMPTED_SPEECH] = \
		{ "assignment:attempted_speech",
		  "Assignment of speech lchan attempts" },
	[BTS_CTR_ASSIGNMENT_COMPLETED] = \
		{ "assignment:completed",
		  "Assignment completed" },
	[BTS_CTR_ASSIGNMENT_COMPLETED_SIGN] = \
		{ "assignment:completed_sign",
		  "Assignment of signaling lchan completed" },
	[BTS_CTR_ASSIGNMENT_COMPLETED_SPEECH] = \
		{ "assignment:completed_speech",
		  "Assignment if speech lchan completed" },
	[BTS_CTR_ASSIGNMENT_STOPPED] = \
		{ "assignment:stopped",
		  "Connection ended during Assignment" },
	[BTS_CTR_ASSIGNMENT_STOPPED_SIGN] = \
		{ "assignment:stopped_sign",
		  "Connection ended during signaling lchan Assignment" },
	[BTS_CTR_ASSIGNMENT_STOPPED_SPEECH] = \
		{ "assignment:stopped_speech",
		  "Connection ended during speech lchan Assignment" },
	[BTS_CTR_ASSIGNMENT_NO_CHANNEL] = \
		{ "assignment:no_channel",
		  "Failure to allocate lchan for Assignment" },
	[BTS_CTR_ASSIGNMENT_NO_CHANNEL_SIGN] = \
		{ "assignment:no_channel_sign",
		  "Failure to allocate signaling lchan for Assignment" },
	[BTS_CTR_ASSIGNMENT_NO_CHANNEL_SPEECH] = \
		{ "assignment:no_channel_speech",
		  "Failure to allocate speech lchan for Assignment" },
	[BTS_CTR_ASSIGNMENT_TIMEOUT] = \
		{ "assignment:timeout",
		  "Assignment timed out" },
	[BTS_CTR_ASSIGNMENT_TIMEOUT_SIGN] = \
		{ "assignment:timeout_sign",
		  "Assignment of signaling lchan timed out" },
	[BTS_CTR_ASSIGNMENT_TIMEOUT_SPEECH] = \
		{ "assignment:timeout_speech",
		  "Assignment of speech lchan timed out" },
	[BTS_CTR_ASSIGNMENT_FAILED] = \
		{ "assignment:failed",
		  "Received Assignment Failure message" },
	[BTS_CTR_ASSIGNMENT_FAILED_SIGN] = \
		{ "assignment:failed_sign",
		  "Received Assignment Failure message on signaling lchan" },
	[BTS_CTR_ASSIGNMENT_FAILED_SPEECH] = \
		{ "assignment:failed_speech",
		  "Received Assignment Failure message on speech lchan" },
	[BTS_CTR_ASSIGNMENT_ERROR] = \
		{ "assignment:error",
		  "Assignment failed for other reason" },
	[BTS_CTR_ASSIGNMENT_ERROR_SIGN] = \
		{ "assignment:error_sign",
		  "Assignment of signaling lchan failed for other reason" },
	[BTS_CTR_ASSIGNMENT_ERROR_SPEECH] = \
		{ "assignment:error_speech",
		  "Assignment of speech lchan failed for other reason" },
	[BTS_CTR_LOCATION_UPDATE_ACCEPT] = \
		{ "location_update:accept",
		  "Location Update Accept" },
	[BTS_CTR_LOCATION_UPDATE_REJECT] = \
		{ "location_update:reject",
		  "Location Update Reject" },
	[BTS_CTR_LOCATION_UPDATE_DETACH] = \
		{ "location_update:detach",
		  "Location Update Detach" },
	[BTS_CTR_LOCATION_UPDATE_UNKNOWN] = \
		{ "location_update:unknown",
		  "Location Update UNKNOWN" },
	[BTS_CTR_HANDOVER_ATTEMPTED] = \
		{ "handover:attempted",
		  "Intra-BSC handover attempts" },
	[BTS_CTR_HANDOVER_COMPLETED] = \
		{ "handover:completed",
		  "Intra-BSC handover completed" },
	[BTS_CTR_HANDOVER_STOPPED] = \
		{ "handover:stopped",
		  "Connection ended during HO" },
	[BTS_CTR_HANDOVER_NO_CHANNEL] = \
		{ "handover:no_channel",
		  "Failure to allocate lchan for HO" },
	[BTS_CTR_HANDOVER_TIMEOUT] = \
		{ "handover:timeout",
		  "Handover timed out" },
	[BTS_CTR_HANDOVER_FAILED] = \
		{ "handover:failed",
		  "Received Handover Fail messages" },
	[BTS_CTR_HANDOVER_ERROR] = \
		{ "handover:error",
		  "Re-assignment failed for other reason" },

	[BTS_CTR_INTRA_CELL_HO_ATTEMPTED] = \
		{ "intra_cell_ho:attempted",
		  "Intra-Cell handover attempts" },
	[BTS_CTR_INTRA_CELL_HO_COMPLETED] = \
		{ "intra_cell_ho:completed",
		  "Intra-Cell handover completed" },
	[BTS_CTR_INTRA_CELL_HO_STOPPED] = \
		{ "intra_cell_ho:stopped",
		  "Connection ended during HO" },
	[BTS_CTR_INTRA_CELL_HO_NO_CHANNEL] = \
		{ "intra_cell_ho:no_channel",
		  "Failure to allocate lchan for HO" },
	[BTS_CTR_INTRA_CELL_HO_TIMEOUT] = \
		{ "intra_cell_ho:timeout",
		  "Handover timed out" },
	[BTS_CTR_INTRA_CELL_HO_FAILED] = \
		{ "intra_cell_ho:failed",
		  "Received Handover Fail messages" },
	[BTS_CTR_INTRA_CELL_HO_ERROR] = \
		{ "intra_cell_ho:error",
		  "Re-assignment failed for other reason" },

	[BTS_CTR_INTRA_BSC_HO_ATTEMPTED] = \
		{ "intra_bsc_ho:attempted",
		  "Intra-BSC inter-cell handover attempts" },
	[BTS_CTR_INTRA_BSC_HO_COMPLETED] = \
		{ "intra_bsc_ho:completed",
		  "Intra-BSC inter-cell handover completed" },
	[BTS_CTR_INTRA_BSC_HO_STOPPED] = \
		{ "intra_bsc_ho:stopped",
		  "Connection ended during HO" },
	[BTS_CTR_INTRA_BSC_HO_NO_CHANNEL] = \
		{ "intra_bsc_ho:no_channel",
		  "Failure to allocate lchan for HO" },
	[BTS_CTR_INTRA_BSC_HO_TIMEOUT] = \
		{ "intra_bsc_ho:timeout",
		  "Handover timed out" },
	[BTS_CTR_INTRA_BSC_HO_FAILED] = \
		{ "intra_bsc_ho:failed",
		  "Received Handover Fail messages" },
	[BTS_CTR_INTRA_BSC_HO_ERROR] = \
		{ "intra_bsc_ho:error",
		  "Intra-BSC inter-cell HO failed for other reason" },

	[BTS_CTR_INCOMING_INTRA_BSC_HO_ATTEMPTED] = \
		{ "incoming_intra_bsc_ho:attempted",
		  "Incoming intra-BSC inter-cell handover attempts" },
	[BTS_CTR_INCOMING_INTRA_BSC_HO_COMPLETED] = \
		{ "incoming_intra_bsc_ho:completed",
		  "Incoming intra-BSC inter-cell handover completed" },
	[BTS_CTR_INCOMING_INTRA_BSC_HO_STOPPED] = \
		{ "incoming_intra_bsc_ho:stopped",
		  "Connection ended during HO" },
	[BTS_CTR_INCOMING_INTRA_BSC_HO_NO_CHANNEL] = \
		{ "incoming_intra_bsc_ho:no_channel",
		  "Failure to allocate lchan for HO" },
	[BTS_CTR_INCOMING_INTRA_BSC_HO_TIMEOUT] = \
		{ "incoming_intra_bsc_ho:timeout",
		  "Handover timed out" },
	[BTS_CTR_INCOMING_INTRA_BSC_HO_FAILED] = \
		{ "incoming_intra_bsc_ho:failed",
		  "Received Handover Fail messages" },
	[BTS_CTR_INCOMING_INTRA_BSC_HO_ERROR] = \
		{ "incoming_intra_bsc_ho:error",
		  "Incoming intra-BSC inter-cell HO failed for other reason" },

	[BTS_CTR_INTER_BSC_HO_OUT_ATTEMPTED] = \
		{ "interbsc_ho_out:attempted",
		  "Attempts to handover to remote BSS" },
	[BTS_CTR_INTER_BSC_HO_OUT_COMPLETED] = \
		{ "interbsc_ho_out:completed",
		  "Handover to remote BSS completed" },
	[BTS_CTR_INTER_BSC_HO_OUT_STOPPED] = \
		{ "interbsc_ho_out:stopped",
		  "Connection ended during HO" },
	[BTS_CTR_INTER_BSC_HO_OUT_TIMEOUT] = \
		{ "interbsc_ho_out:timeout",
		  "Handover timed out" },
	[BTS_CTR_INTER_BSC_HO_OUT_FAILED] = \
		{ "interbsc_ho_out:failed",
		  "Received Handover Fail message" },
	[BTS_CTR_INTER_BSC_HO_OUT_ERROR] = \
		{ "interbsc_ho_out:error",
		  "Handover to remote BSS failed for other reason" },
	[BTS_CTR_INTER_BSC_HO_IN_ATTEMPTED] = \
		{ "interbsc_ho_in:attempted",
		  "Attempts to handover from remote BSS" },
	[BTS_CTR_INTER_BSC_HO_IN_COMPLETED] = \
		{ "interbsc_ho_in:completed",
		  "Handover from remote BSS completed" },
	[BTS_CTR_INTER_BSC_HO_IN_STOPPED] = \
		{ "interbsc_ho_in:stopped",
		  "Connection ended during HO" },
	[BTS_CTR_INTER_BSC_HO_IN_NO_CHANNEL] = \
		{ "interbsc_ho_in:no_channel",
		  "Failure to allocate lchan for HO" },
	[BTS_CTR_INTER_BSC_HO_IN_TIMEOUT] = \
		{ "interbsc_ho_in:timeout",
		  "Handover from remote BSS timed out" },
	[BTS_CTR_INTER_BSC_HO_IN_FAILED] = \
		{ "interbsc_ho_in:failed",
		  "Received Handover Fail message" },
	[BTS_CTR_INTER_BSC_HO_IN_ERROR] = \
		{ "interbsc_ho_in:error",
		  "Handover from remote BSS failed for other reason" },

	[BTS_CTR_SRVCC_ATTEMPTED] = \
		{ "srvcc:attempted",
		  "Intra-BSC handover attempts" },
	[BTS_CTR_SRVCC_COMPLETED] = \
		{ "srvcc:completed",
		  "Intra-BSC handover completed" },
	[BTS_CTR_SRVCC_STOPPED] = \
		{ "srvcc:stopped",
		  "Connection ended during HO" },
	[BTS_CTR_SRVCC_NO_CHANNEL] = \
		{ "srvcc:no_channel",
		  "Failure to allocate lchan for HO" },
	[BTS_CTR_SRVCC_TIMEOUT] = \
		{ "srvcc:timeout",
		   "Handover timed out" },
	[BTS_CTR_SRVCC_FAILED] = \
		{ "srvcc:failed",
		  "Received Handover Fail messages" },
	[BTS_CTR_SRVCC_ERROR] = \
		{ "srvcc:error",
		  "Re-assignment failed for other reason" },
};

const struct rate_ctr_group_desc bts_ctrg_desc = {
	"bts",
	"base transceiver station",
	OSMO_STATS_CLASS_GLOBAL,
	ARRAY_SIZE(bts_ctr_description),
	bts_ctr_description,
};

const struct osmo_stat_item_desc bts_stat_desc[] = {
	[BTS_STAT_UPTIME_SECONDS] = \
		{ "uptime:seconds",
		  "Seconds of uptime",
		  "s", 60, 0 },
	[BTS_STAT_CHAN_LOAD_AVERAGE] = \
		{ "chanloadavg",
		  "Channel load average",
		  "%", 60, 0 },
	[BTS_STAT_CHAN_CCCH_SDCCH4_USED] = \
		{ "chan_ccch_sdcch4:used",
		  "Number of CCCH+SDCCH4 channels used",
		  "", 60, 0 },
	[BTS_STAT_CHAN_CCCH_SDCCH4_TOTAL] = \
		{ "chan_ccch_sdcch4:total",
		  "Number of CCCH+SDCCH4 channels total",
		  "", 60, 0 },
	[BTS_STAT_CHAN_TCH_F_USED] = \
		{ "chan_tch_f:used",
		  "Number of TCH/F channels used",
		  "", 60, 0 },
	[BTS_STAT_CHAN_TCH_F_TOTAL] = \
		{ "chan_tch_f:total",
		  "Number of TCH/F channels total",
		  "", 60, 0 },
	[BTS_STAT_CHAN_TCH_H_USED] = \
		{ "chan_tch_h:used",
		  "Number of TCH/H channels used",
		  "", 60, 0 },
	[BTS_STAT_CHAN_TCH_H_TOTAL] = \
		{ "chan_tch_h:total",
		  "Number of TCH/H channels total",
		  "", 60, 0 },
	[BTS_STAT_CHAN_SDCCH8_USED] = \
		{ "chan_sdcch8:used",
		  "Number of SDCCH8 channels used",
		  "", 60, 0 },
	[BTS_STAT_CHAN_SDCCH8_TOTAL] = \
		{ "chan_sdcch8:total",
		  "Number of SDCCH8 channels total",
		  "", 60, 0 },
	[BTS_STAT_CHAN_TCH_F_PDCH_USED] = \
		{ "chan_tch_f_pdch:used",
		  "Number of TCH/F_PDCH channels used",
		  "", 60, 0 },
	[BTS_STAT_CHAN_TCH_F_PDCH_TOTAL] = \
		{ "chan_tch_f_pdch:total",
		  "Number of TCH/F_PDCH channels total",
		  "", 60, 0 },
	[BTS_STAT_CHAN_CCCH_SDCCH4_CBCH_USED] = \
		{ "chan_ccch_sdcch4_cbch:used",
		  "Number of CCCH+SDCCH4+CBCH channels used",
		  "", 60, 0 },
	[BTS_STAT_CHAN_CCCH_SDCCH4_CBCH_TOTAL] = \
		{ "chan_ccch_sdcch4_cbch:total",
		  "Number of CCCH+SDCCH4+CBCH channels total",
		  "", 60, 0 },
	[BTS_STAT_CHAN_SDCCH8_CBCH_USED] = \
		{ "chan_sdcch8_cbch:used",
		  "Number of SDCCH8+CBCH channels used",
		  "", 60, 0 },
	[BTS_STAT_CHAN_SDCCH8_CBCH_TOTAL] = \
		{ "chan_sdcch8_cbch:total",
		  "Number of SDCCH8+CBCH channels total",
		  "", 60, 0 },
	[BTS_STAT_CHAN_OSMO_DYN_USED] = \
		{ "chan_osmo_dyn:used",
		  "Number of TCH/F_TCH/H_SDCCH8_PDCH channels used",
		  "", 60, 0 },
	[BTS_STAT_CHAN_OSMO_DYN_TOTAL] = \
		{ "chan_osmo_dyn:total",
		  "Number of TCH/F_TCH/H_SDCCH8_PDCH channels total",
		  "", 60, 0 },
	[BTS_STAT_T3122] = \
		{ "T3122",
		  "T3122 IMMEDIATE ASSIGNMENT REJECT wait indicator",
		  "s", 60, GSM_T3122_DEFAULT },
	[BTS_STAT_RACH_BUSY] = \
		{ "rach_busy",
		  "RACH slots with signal above threshold",
		  "%", 60, 0 },
	[BTS_STAT_RACH_ACCESS] = \
		{ "rach_access",
		  "RACH slots with access bursts in them",
		  "%", 60, 0 },
	[BTS_STAT_OML_CONNECTED] = \
		{ "oml_connected",
		  "Number of OML links connected",
		  "", 16, 0   },
	[BTS_STAT_RSL_CONNECTED] = \
		{ "rsl_connected",
		  "Number of RSL links connected (same as num_trx:rsl_connected)",
		  "", 16, 0   },
	[BTS_STAT_LCHAN_BORKEN] = \
		{ "lchan_borken",
		  "Number of lchans in the BORKEN state",
		  "", 16, 0 },
	[BTS_STAT_TS_BORKEN] = \
		{ "ts_borken",
		  "Number of timeslots in the BORKEN state",
		  "", 16, 0 },
	[BTS_STAT_NUM_TRX_RSL_CONNECTED] = \
		{ "num_trx:rsl_connected",
		  "Number of TRX in this BTS where RSL is up",
		  "" },
	[BTS_STAT_NUM_TRX_TOTAL] = \
		{ "num_trx:total",
		  "Number of configured TRX in this BTS",
		  "" },
};

const struct osmo_stat_item_group_desc bts_statg_desc = {
	.group_name_prefix = "bts",
	.group_description = "base transceiver station",
	.class_id = OSMO_STATS_CLASS_GLOBAL,
	.num_items = ARRAY_SIZE(bts_stat_desc),
	.item_desc = bts_stat_desc,
};
