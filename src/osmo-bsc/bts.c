/* (C) 2008-2018 by Harald Welte <laforge@gnumonks.org>
 * (C) 2020 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
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
	{ GSM_BTS_TYPE_OSMOBTS,		"sysmobts" },
	{ 0, NULL }
};

const struct value_string bts_type_descs[_NUM_GSM_BTS_TYPE+1] = {
	{ GSM_BTS_TYPE_UNKNOWN,		"Unknown BTS Type" },
	{ GSM_BTS_TYPE_BS11,		"Siemens BTS (BS-11 or compatible)" },
	{ GSM_BTS_TYPE_NANOBTS,		"ip.access nanoBTS or compatible" },
	{ GSM_BTS_TYPE_RBS2000,		"Ericsson RBS2000 Series" },
	{ GSM_BTS_TYPE_NOKIA_SITE,	"Nokia {Metro,Ultra,In}Site" },
	{ GSM_BTS_TYPE_OSMOBTS,		"sysmocom sysmoBTS" },
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

static const uint8_t bts_nse_timer_default[] = { 3, 3, 3, 3, 30, 3, 10 };
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

/* Initialize those parts that don't require osmo-bsc specific dependencies.
 * This part is shared among the thin programs in osmo-bsc/src/utils/.
 * osmo-bsc requires further initialization that pulls in more dependencies (see
 * bsc_bts_alloc_register()). */
struct gsm_bts *gsm_bts_alloc(struct gsm_network *net, uint8_t bts_num)
{
	struct gsm_bts *bts = talloc_zero(net, struct gsm_bts);
	struct gsm48_multi_rate_conf mr_cfg;
	int i;

	if (!bts)
		return NULL;

	bts->nr = bts_num;
	bts->num_trx = 0;
	INIT_LLIST_HEAD(&bts->trx_list);
	bts->network = net;

	bts->ms_max_power = 15;	/* dBm */

	gsm_mo_init(&bts->mo, bts, NM_OC_BTS,
			bts->nr, 0xff, 0xff);
	gsm_mo_init(&bts->site_mgr.mo, bts, NM_OC_SITE_MANAGER,
			0xff, 0xff, 0xff);

	for (i = 0; i < ARRAY_SIZE(bts->gprs.nsvc); i++) {
		bts->gprs.nsvc[i].bts = bts;
		bts->gprs.nsvc[i].id = i;
		gsm_mo_init(&bts->gprs.nsvc[i].mo, bts, NM_OC_GPRS_NSVC,
				bts->nr, i, 0xff);
	}
	memcpy(&bts->gprs.nse.timer, bts_nse_timer_default,
		sizeof(bts->gprs.nse.timer));
	gsm_mo_init(&bts->gprs.nse.mo, bts, NM_OC_GPRS_NSE,
			bts->nr, 0xff, 0xff);
	memcpy(&bts->gprs.cell.timer, bts_cell_timer_default,
		sizeof(bts->gprs.cell.timer));
	gsm_mo_init(&bts->gprs.cell.mo, bts, NM_OC_GPRS_CELL,
			bts->nr, 0xff, 0xff);
	memcpy(&bts->gprs.cell.rlc_cfg, &rlc_cfg_default,
		sizeof(bts->gprs.cell.rlc_cfg));

	/* 3GPP TS 08.18, chapter 5.4.1: 0 is reserved for signalling */
	bts->gprs.cell.bvci = 2;

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
	bts->si_common.chan_desc.att = 1; /* attachment required */
	bts->si_common.chan_desc.bs_pa_mfrms = RSL_BS_PA_MFRMS_5; /* paging frames */
	bts->si_common.chan_desc.bs_ag_blks_res = 1; /* reserved AGCH blocks */
	bts->si_common.chan_desc.t3212 = osmo_tdef_get(net->T_defs, 3212, OSMO_TDEF_CUSTOM, -1);
	gsm_bts_set_radio_link_timeout(bts, 32); /* Use RADIO LINK TIMEOUT of 32 */

	INIT_LLIST_HEAD(&bts->abis_queue);
	INIT_LLIST_HEAD(&bts->loc_list);
	INIT_LLIST_HEAD(&bts->local_neighbors);
	INIT_LLIST_HEAD(&bts->oml_fail_rep);

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

static struct gsm_bts_ref *gsm_bts_ref_find(const struct llist_head *list, const struct gsm_bts *bts)
{
	struct gsm_bts_ref *ref;
	if (!bts)
		return NULL;
	llist_for_each_entry(ref, list, entry) {
		if (ref->bts == bts)
			return ref;
	}
	return NULL;
}

/* Add a BTS reference to the local_neighbors list.
 * Return 1 if added, 0 if such an entry already existed, and negative on errors. */
int gsm_bts_local_neighbor_add(struct gsm_bts *bts, struct gsm_bts *neighbor)
{
	struct gsm_bts_ref *ref;
	if (!bts || !neighbor)
		return -ENOMEM;

	if (bts == neighbor)
		return -EINVAL;

	/* Already got this entry? */
	ref = gsm_bts_ref_find(&bts->local_neighbors, neighbor);
	if (ref)
		return 0;

	ref = talloc_zero(bts, struct gsm_bts_ref);
	if (!ref)
		return -ENOMEM;
	ref->bts = neighbor;
	llist_add_tail(&ref->entry, &bts->local_neighbors);
	return 1;
}

/* Remove a BTS reference from the local_neighbors list.
 * Return 1 if removed, 0 if no such entry existed, and negative on errors. */
int gsm_bts_local_neighbor_del(struct gsm_bts *bts, const struct gsm_bts *neighbor)
{
	struct gsm_bts_ref *ref;
	if (!bts || !neighbor)
		return -ENOMEM;

	ref = gsm_bts_ref_find(&bts->local_neighbors, neighbor);
	if (!ref)
		return 0;

	llist_del(&ref->entry);
	talloc_free(ref);
	return 1;
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

	switch (bts->type) {
	case GSM_BTS_TYPE_NANOBTS:
	case GSM_BTS_TYPE_OSMOBTS:
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

unsigned long long bts_uptime(const struct gsm_bts *bts)
{
	struct timespec tp;

	if (!bts->uptime || !bts->oml_link) {
		LOGP(DNM, LOGL_ERROR, "BTS %u OML link uptime unavailable\n", bts->nr);
		return 0;
	}

	if (clock_gettime(CLOCK_MONOTONIC, &tp) != 0) {
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
	gsm_abis_mo_reset(&bts->site_mgr.mo);
	for (i = 0; i < ARRAY_SIZE(bts->gprs.nsvc); i++)
		gsm_abis_mo_reset(&bts->gprs.nsvc[i].mo);
	gsm_abis_mo_reset(&bts->gprs.nse.mo);
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


/* Count number of free TS of given pchan type */
int bts_count_free_ts(struct gsm_bts *bts, enum gsm_phys_chan_config pchan)
{
	struct gsm_bts_trx *trx;
	int count = 0;

	llist_for_each_entry(trx, &bts->trx_list, list)
		count += trx_count_free_ts(trx, pchan);

	return count;
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
