/* (C) 2008-2018 by Harald Welte <laforge@gnumonks.org>
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


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <stdbool.h>
#include <netinet/in.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/talloc.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/gsm/abis_nm.h>
#include <osmocom/core/statistics.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gsm/gsm48.h>

#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/bsc_msc_data.h>
#include <osmocom/bsc/abis_nm.h>
#include <osmocom/bsc/handover_cfg.h>

void *tall_bsc_ctx = NULL;

static LLIST_HEAD(bts_models);

void set_ts_e1link(struct gsm_bts_trx_ts *ts, uint8_t e1_nr,
		   uint8_t e1_ts, uint8_t e1_ts_ss)
{
	ts->e1_link.e1_nr = e1_nr;
	ts->e1_link.e1_ts = e1_ts;
	ts->e1_link.e1_ts_ss = e1_ts_ss;
}

static struct gsm_bts_model *bts_model_find(enum gsm_bts_type type)
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

const struct value_string bts_type_descs[_NUM_GSM_BTS_TYPE+1] = {
	{ GSM_BTS_TYPE_UNKNOWN,		"Unknown BTS Type" },
	{ GSM_BTS_TYPE_BS11,		"Siemens BTS (BS-11 or compatible)" },
	{ GSM_BTS_TYPE_NANOBTS,		"ip.access nanoBTS or compatible" },
	{ GSM_BTS_TYPE_RBS2000,		"Ericsson RBS2000 Series" },
	{ GSM_BTS_TYPE_NOKIA_SITE,	"Nokia {Metro,Ultra,In}Site" },
	{ GSM_BTS_TYPE_OSMOBTS,		"sysmocom sysmoBTS" },
	{ 0,				NULL }
};

struct gsm_bts_trx *gsm_bts_trx_by_nr(struct gsm_bts *bts, int nr)
{
	struct gsm_bts_trx *trx;

	llist_for_each_entry(trx, &bts->trx_list, list) {
		if (trx->nr == nr)
			return trx;
	}
	return NULL;
}

/* Search for a BTS in the given Location Area; optionally start searching
 * with start_bts (for continuing to search after the first result) */
struct gsm_bts *gsm_bts_by_lac(struct gsm_network *net, unsigned int lac,
				struct gsm_bts *start_bts)
{
	int i;
	struct gsm_bts *bts;
	int skip = 0;

	if (start_bts)
		skip = 1;

	for (i = 0; i < net->num_bts; i++) {
		bts = gsm_bts_num(net, i);

		if (skip) {
			if (start_bts == bts)
				skip = 0;
			continue;
		}

		if (lac == GSM_LAC_RESERVED_ALL_BTS || bts->location_area_code == lac)
			return bts;
	}
	return NULL;
}

static const struct value_string bts_gprs_mode_names[] = {
	{ BTS_GPRS_NONE,	"none" },
	{ BTS_GPRS_GPRS,	"gprs" },
	{ BTS_GPRS_EGPRS,	"egprs" },
	{ 0,			NULL }
};

enum bts_gprs_mode bts_gprs_mode_parse(const char *arg, int *valid)
{
	int rc;

	rc = get_string_value(bts_gprs_mode_names, arg);
	if (valid)
		*valid = rc != -EINVAL;
	return rc;
}

const char *bts_gprs_mode_name(enum bts_gprs_mode mode)
{
	return get_value_string(bts_gprs_mode_names, mode);
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

struct gsm_bts *gsm_bts_alloc_register(struct gsm_network *net, enum gsm_bts_type type,
					uint8_t bsic)
{
	struct gsm_bts_model *model = bts_model_find(type);
	struct gsm_bts *bts;

	if (!model && type != GSM_BTS_TYPE_UNKNOWN)
		return NULL;

	bts = gsm_bts_alloc(net, net->num_bts);
	if (!bts)
		return NULL;

	net->num_bts++;

	bts->type = type;
	bts->model = model;
	bts->bsic = bsic;
	bts->dtxu = GSM48_DTX_SHALL_NOT_BE_USED;
	bts->dtxd = false;
	bts->gprs.ctrl_ack_type_use_block = true; /* use RLC/MAC control block */
	bts->neigh_list_manual_mode = 0;
	bts->early_classmark_allowed_3g = true; /* 3g Early Classmark Sending controlled by bts->early_classmark_allowed param */
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
	bts->si_common.chan_desc.t3212 = net->t3212; /* Use network's current value */
	gsm_bts_set_radio_link_timeout(bts, 32); /* Use RADIO LINK TIMEOUT of 32 */

	llist_add_tail(&bts->list, &net->bts_list);

	INIT_LLIST_HEAD(&bts->abis_queue);

	INIT_LLIST_HEAD(&bts->loc_list);

	return bts;
}

void gprs_ra_id_by_bts(struct gprs_ra_id *raid, struct gsm_bts *bts)
{
	*raid = (struct gprs_ra_id){
		.mcc = bts->network->plmn.mcc,
		.mnc = bts->network->plmn.mnc,
		.mnc_3_digits = bts->network->plmn.mnc_3_digits,
		.lac = bts->location_area_code,
		.rac = bts->gprs.rac,
	};
}

void gsm48_ra_id_by_bts(struct gsm48_ra_id *buf, struct gsm_bts *bts)
{
	struct gprs_ra_id raid;

	gprs_ra_id_by_bts(&raid, bts);
	gsm48_encode_ra(buf, &raid);
}

int gsm_parse_reg(void *ctx, regex_t *reg, char **str, int argc, const char **argv)
{
	int ret;

	ret = 0;
	if (*str) {
		talloc_free(*str);
		*str = NULL;
	}
	regfree(reg);

	if (argc > 0) {
		*str = talloc_strdup(ctx, argv[0]);
		ret = regcomp(reg, argv[0], 0);

		/* handle compilation failures */
		if (ret != 0) {
			talloc_free(*str);
			*str = NULL;
		}
	}

	return ret;
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

bool classmark_is_r99(struct gsm_classmark *cm)
{
	int rev_lev = 0;
	if (cm->classmark1_set)
		rev_lev = cm->classmark1.rev_lev;
	else if (cm->classmark2_len > 0)
		rev_lev = (cm->classmark2[0] >> 5) & 0x3;
	return rev_lev >= 2;
}

static const struct osmo_stat_item_desc bts_stat_desc[] = {
	{ "chanloadavg", "Channel load average.", "%", 16, 0 },
	{ "T3122", "T3122 IMMEDIATE ASSIGNMENT REJECT wait indicator.", "s", 16, GSM_T3122_DEFAULT },
};

static const struct osmo_stat_item_group_desc bts_statg_desc = {
	.group_name_prefix = "bts",
	.group_description = "base transceiver station",
	.class_id = OSMO_STATS_CLASS_GLOBAL,
	.num_items = ARRAY_SIZE(bts_stat_desc),
	.item_desc = bts_stat_desc,
};

void gsm_abis_mo_reset(struct gsm_abis_mo *mo)
{
	mo->nm_state.operational = NM_OPSTATE_NULL;
	mo->nm_state.availability = NM_AVSTATE_POWER_OFF;
}

static void gsm_mo_init(struct gsm_abis_mo *mo, struct gsm_bts *bts,
			uint8_t obj_class, uint8_t p1, uint8_t p2, uint8_t p3)
{
	mo->bts = bts;
	mo->obj_class = obj_class;
	mo->obj_inst.bts_nr = p1;
	mo->obj_inst.trx_nr = p2;
	mo->obj_inst.ts_nr = p3;
	gsm_abis_mo_reset(mo);
}

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

enum gsm_bts_type str2btstype(const char *arg)
{
	return get_string_value(bts_type_names, arg);
}

const char *btstype2str(enum gsm_bts_type type)
{
	return get_value_string(bts_type_names, type);
}

const struct value_string gsm_chreq_descs[] = {
	{ GSM_CHREQ_REASON_EMERG,	"emergency call" },
	{ GSM_CHREQ_REASON_PAG,		"answer to paging" },
	{ GSM_CHREQ_REASON_CALL,	"call re-establishment" },
	{ GSM_CHREQ_REASON_LOCATION_UPD,"Location updating" },
	{ GSM_CHREQ_REASON_PDCH,	"one phase packet access" },
	{ GSM_CHREQ_REASON_OTHER,	"other" },
	{ 0,				NULL }
};

const struct value_string gsm_pchant_names[13] = {
	{ GSM_PCHAN_NONE,	"NONE" },
	{ GSM_PCHAN_CCCH,	"CCCH" },
	{ GSM_PCHAN_CCCH_SDCCH4,"CCCH+SDCCH4" },
	{ GSM_PCHAN_TCH_F,	"TCH/F" },
	{ GSM_PCHAN_TCH_H,	"TCH/H" },
	{ GSM_PCHAN_SDCCH8_SACCH8C, "SDCCH8" },
	{ GSM_PCHAN_PDCH,	"PDCH" },
	{ GSM_PCHAN_TCH_F_PDCH,	"TCH/F_PDCH" },
	{ GSM_PCHAN_UNKNOWN,	"UNKNOWN" },
	{ GSM_PCHAN_CCCH_SDCCH4_CBCH, "CCCH+SDCCH4+CBCH" },
	{ GSM_PCHAN_SDCCH8_SACCH8C_CBCH, "SDCCH8+CBCH" },
	{ GSM_PCHAN_TCH_F_TCH_H_PDCH, "TCH/F_TCH/H_PDCH" },
	{ 0,			NULL }
};

const struct value_string gsm_pchant_descs[13] = {
	{ GSM_PCHAN_NONE,	"Physical Channel not configured" },
	{ GSM_PCHAN_CCCH,	"FCCH + SCH + BCCH + CCCH (Comb. IV)" },
	{ GSM_PCHAN_CCCH_SDCCH4,
		"FCCH + SCH + BCCH + CCCH + 4 SDCCH + 2 SACCH (Comb. V)" },
	{ GSM_PCHAN_TCH_F,	"TCH/F + FACCH/F + SACCH (Comb. I)" },
	{ GSM_PCHAN_TCH_H,	"2 TCH/H + 2 FACCH/H + 2 SACCH (Comb. II)" },
	{ GSM_PCHAN_SDCCH8_SACCH8C, "8 SDCCH + 4 SACCH (Comb. VII)" },
	{ GSM_PCHAN_PDCH,	"Packet Data Channel for GPRS/EDGE" },
	{ GSM_PCHAN_TCH_F_PDCH,	"Dynamic TCH/F or GPRS PDCH" },
	{ GSM_PCHAN_UNKNOWN,	"Unknown / Unsupported channel combination" },
	{ GSM_PCHAN_CCCH_SDCCH4_CBCH, "FCCH + SCH + BCCH + CCCH + CBCH + 3 SDCCH + 2 SACCH (Comb. V)" },
	{ GSM_PCHAN_SDCCH8_SACCH8C_CBCH, "7 SDCCH + 4 SACCH + CBCH (Comb. VII)" },
	{ GSM_PCHAN_TCH_F_TCH_H_PDCH, "Dynamic TCH/F or TCH/H or GPRS PDCH" },
	{ 0,			NULL }
};

const char *gsm_pchan_name(enum gsm_phys_chan_config c)
{
	return get_value_string(gsm_pchant_names, c);
}

enum gsm_phys_chan_config gsm_pchan_parse(const char *name)
{
	return get_string_value(gsm_pchant_names, name);
}

/* TODO: move to libosmocore, next to gsm_chan_t_names? */
const char *gsm_lchant_name(enum gsm_chan_t c)
{
	return get_value_string(gsm_chan_t_names, c);
}

static const struct value_string lchan_s_names[] = {
	{ LCHAN_S_NONE,		"NONE" },
	{ LCHAN_S_ACT_REQ,	"ACTIVATION REQUESTED" },
	{ LCHAN_S_ACTIVE,	"ACTIVE" },
	{ LCHAN_S_INACTIVE,	"INACTIVE" },
	{ LCHAN_S_REL_REQ,	"RELEASE REQUESTED" },
	{ LCHAN_S_REL_ERR,	"RELEASE DUE ERROR" },
	{ LCHAN_S_BROKEN,	"BROKEN UNUSABLE" },
	{ 0,			NULL }
};

const char *gsm_lchans_name(enum gsm_lchan_state s)
{
	return get_value_string(lchan_s_names, s);
}

static const struct value_string chreq_names[] = {
	{ GSM_CHREQ_REASON_EMERG,	"EMERGENCY" },
	{ GSM_CHREQ_REASON_PAG,		"PAGING" },
	{ GSM_CHREQ_REASON_CALL,	"CALL" },
	{ GSM_CHREQ_REASON_LOCATION_UPD,"LOCATION_UPDATE" },
	{ GSM_CHREQ_REASON_OTHER,	"OTHER" },
	{ 0,				NULL }
};

const char *gsm_chreq_name(enum gsm_chreq_reason_t c)
{
	return get_value_string(chreq_names, c);
}

struct gsm_bts *gsm_bts_num(struct gsm_network *net, int num)
{
	struct gsm_bts *bts;

	if (num >= net->num_bts)
		return NULL;

	llist_for_each_entry(bts, &net->bts_list, list) {
		if (bts->nr == num)
			return bts;
	}

	return NULL;
}

struct gsm_bts_trx *gsm_bts_trx_alloc(struct gsm_bts *bts)
{
	struct gsm_bts_trx *trx = talloc_zero(bts, struct gsm_bts_trx);
	int k;

	if (!trx)
		return NULL;

	trx->bts = bts;
	trx->nr = bts->num_trx++;
	trx->mo.nm_state.administrative = NM_STATE_UNLOCKED;

	gsm_mo_init(&trx->mo, bts, NM_OC_RADIO_CARRIER,
		    bts->nr, trx->nr, 0xff);
	gsm_mo_init(&trx->bb_transc.mo, bts, NM_OC_BASEB_TRANSC,
		    bts->nr, trx->nr, 0xff);

	for (k = 0; k < TRX_NR_TS; k++) {
		struct gsm_bts_trx_ts *ts = &trx->ts[k];
		int l;

		ts->trx = trx;
		ts->nr = k;
		ts->pchan = GSM_PCHAN_NONE;
		ts->dyn.pchan_is = GSM_PCHAN_NONE;
		ts->dyn.pchan_want = GSM_PCHAN_NONE;
		ts->tsc = -1;

		gsm_mo_init(&ts->mo, bts, NM_OC_CHANNEL,
			    bts->nr, trx->nr, ts->nr);

		ts->hopping.arfcns.data_len = sizeof(ts->hopping.arfcns_data);
		ts->hopping.arfcns.data = ts->hopping.arfcns_data;
		ts->hopping.ma.data_len = sizeof(ts->hopping.ma_data);
		ts->hopping.ma.data = ts->hopping.ma_data;

		for (l = 0; l < TS_MAX_LCHAN; l++) {
			struct gsm_lchan *lchan;
			char *name;
			lchan = &ts->lchan[l];

			lchan->ts = ts;
			lchan->nr = l;
			lchan->type = GSM_LCHAN_NONE;

			name = gsm_lchan_name_compute(lchan);
			lchan->name = talloc_strdup(trx, name);
		}
	}

	if (trx->nr != 0)
		trx->nominal_power = bts->c0->nominal_power;

	llist_add_tail(&trx->list, &bts->trx_list);

	return trx;
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

struct gsm_bts *gsm_bts_alloc(struct gsm_network *net, uint8_t bts_num)
{
	struct gsm_bts *bts = talloc_zero(net, struct gsm_bts);
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

	/* init statistics */
	bts->bts_ctrs = rate_ctr_group_alloc(bts, &bts_ctrg_desc, bts->nr);
	if (!bts->bts_ctrs) {
		talloc_free(bts);
		return NULL;
	}
	bts->bts_statg = osmo_stat_item_group_alloc(bts, &bts_statg_desc, 0);

	/* create our primary TRX */
	bts->c0 = gsm_bts_trx_alloc(bts);
	if (!bts->c0) {
		rate_ctr_group_free(bts->bts_ctrs);
		osmo_stat_item_group_free(bts->bts_statg);
		talloc_free(bts);
		return NULL;
	}
	bts->c0->ts[0].pchan = GSM_PCHAN_CCCH_SDCCH4;

	bts->rach_b_thresh = -1;
	bts->rach_ldavg_slots = -1;

	bts->paging.free_chans_need = -1;
	INIT_LLIST_HEAD(&bts->paging.pending_requests);

	bts->features.data = &bts->_features_data[0];
	bts->features.data_len = sizeof(bts->_features_data);

	/* si handling */
	bts->bcch_change_mark = 1;
	bts->chan_load_avg = 0;

	bts->ho = ho_cfg_init(bts, net->ho);

	/* timer overrides */
	bts->T3122 = 0; /* not overriden by default */

	return bts;
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

static char ts2str[255];

char *gsm_trx_name(const struct gsm_bts_trx *trx)
{
	if (!trx)
		snprintf(ts2str, sizeof(ts2str), "(trx=NULL)");
	else
		snprintf(ts2str, sizeof(ts2str), "(bts=%d,trx=%d)",
			 trx->bts->nr, trx->nr);

	return ts2str;
}


char *gsm_ts_name(const struct gsm_bts_trx_ts *ts)
{
	snprintf(ts2str, sizeof(ts2str), "(bts=%d,trx=%d,ts=%d)",
		 ts->trx->bts->nr, ts->trx->nr, ts->nr);

	return ts2str;
}

/*! Log timeslot number with full pchan information */
char *gsm_ts_and_pchan_name(const struct gsm_bts_trx_ts *ts)
{
	switch (ts->pchan) {
	case GSM_PCHAN_TCH_F_TCH_H_PDCH:
		if (ts->dyn.pchan_is == ts->dyn.pchan_want)
			snprintf(ts2str, sizeof(ts2str),
				 "(bts=%d,trx=%d,ts=%d,pchan=%s as %s)",
				 ts->trx->bts->nr, ts->trx->nr, ts->nr,
				 gsm_pchan_name(ts->pchan),
				 gsm_pchan_name(ts->dyn.pchan_is));
		else
			snprintf(ts2str, sizeof(ts2str),
				 "(bts=%d,trx=%d,ts=%d,pchan=%s"
				 " switching %s -> %s)",
				 ts->trx->bts->nr, ts->trx->nr, ts->nr,
				 gsm_pchan_name(ts->pchan),
				 gsm_pchan_name(ts->dyn.pchan_is),
				 gsm_pchan_name(ts->dyn.pchan_want));
		break;
	case GSM_PCHAN_TCH_F_PDCH:
		if ((ts->flags & TS_F_PDCH_PENDING_MASK) == 0)
			snprintf(ts2str, sizeof(ts2str),
				 "(bts=%d,trx=%d,ts=%d,pchan=%s as %s)",
				 ts->trx->bts->nr, ts->trx->nr, ts->nr,
				 gsm_pchan_name(ts->pchan),
				 (ts->flags & TS_F_PDCH_ACTIVE)? "PDCH"
							       : "TCH/F");
		else
			snprintf(ts2str, sizeof(ts2str),
				 "(bts=%d,trx=%d,ts=%d,pchan=%s"
				 " switching %s -> %s)",
				 ts->trx->bts->nr, ts->trx->nr, ts->nr,
				 gsm_pchan_name(ts->pchan),
				 (ts->flags & TS_F_PDCH_ACTIVE)? "PDCH"
							       : "TCH/F",
				 (ts->flags & TS_F_PDCH_ACT_PENDING)? "PDCH"
								    : "TCH/F");
		break;
	default:
		snprintf(ts2str, sizeof(ts2str), "(bts=%d,trx=%d,ts=%d,pchan=%s)",
			 ts->trx->bts->nr, ts->trx->nr, ts->nr,
			 gsm_pchan_name(ts->pchan));
		break;
	}

	return ts2str;
}

char *gsm_lchan_name_compute(const struct gsm_lchan *lchan)
{
	struct gsm_bts_trx_ts *ts = lchan->ts;

	snprintf(ts2str, sizeof(ts2str), "(bts=%d,trx=%d,ts=%d,ss=%d)",
		 ts->trx->bts->nr, ts->trx->nr, ts->nr, lchan->nr);

	return ts2str;
}

/* obtain the MO structure for a given object instance */
static inline struct gsm_abis_mo *
gsm_objclass2mo(struct gsm_bts *bts, uint8_t obj_class,
	    const struct abis_om_obj_inst *obj_inst)
{
	struct gsm_bts_trx *trx;
	struct gsm_abis_mo *mo = NULL;

	switch (obj_class) {
	case NM_OC_BTS:
		mo = &bts->mo;
		break;
	case NM_OC_RADIO_CARRIER:
		if (obj_inst->trx_nr >= bts->num_trx) {
			return NULL;
		}
		trx = gsm_bts_trx_num(bts, obj_inst->trx_nr);
		mo = &trx->mo;
		break;
	case NM_OC_BASEB_TRANSC:
		if (obj_inst->trx_nr >= bts->num_trx) {
			return NULL;
		}
		trx = gsm_bts_trx_num(bts, obj_inst->trx_nr);
		mo = &trx->bb_transc.mo;
		break;
	case NM_OC_CHANNEL:
		if (obj_inst->trx_nr >= bts->num_trx) {
			return NULL;
		}
		trx = gsm_bts_trx_num(bts, obj_inst->trx_nr);
		if (obj_inst->ts_nr >= TRX_NR_TS)
			return NULL;
		mo = &trx->ts[obj_inst->ts_nr].mo;
		break;
	case NM_OC_SITE_MANAGER:
		mo = &bts->site_mgr.mo;
		break;
	case NM_OC_BS11:
		switch (obj_inst->bts_nr) {
		case BS11_OBJ_CCLK:
			mo = &bts->bs11.cclk.mo;
			break;
		case BS11_OBJ_BBSIG:
			if (obj_inst->ts_nr > bts->num_trx)
				return NULL;
			trx = gsm_bts_trx_num(bts, obj_inst->trx_nr);
			mo = &trx->bs11.bbsig.mo;
			break;
		case BS11_OBJ_PA:
			if (obj_inst->ts_nr > bts->num_trx)
				return NULL;
			trx = gsm_bts_trx_num(bts, obj_inst->trx_nr);
			mo = &trx->bs11.pa.mo;
			break;
		default:
			return NULL;
		}
		break;
	case NM_OC_BS11_RACK:
		mo = &bts->bs11.rack.mo;
		break;
	case NM_OC_BS11_ENVABTSE:
		if (obj_inst->trx_nr >= ARRAY_SIZE(bts->bs11.envabtse))
			return NULL;
		mo = &bts->bs11.envabtse[obj_inst->trx_nr].mo;
		break;
	case NM_OC_GPRS_NSE:
		mo = &bts->gprs.nse.mo;
		break;
	case NM_OC_GPRS_CELL:
		mo = &bts->gprs.cell.mo;
		break;
	case NM_OC_GPRS_NSVC:
		if (obj_inst->trx_nr >= ARRAY_SIZE(bts->gprs.nsvc))
			return NULL;
		mo = &bts->gprs.nsvc[obj_inst->trx_nr].mo;
		break;
	}
	return mo;
}

/* obtain the gsm_nm_state data structure for a given object instance */
struct gsm_nm_state *
gsm_objclass2nmstate(struct gsm_bts *bts, uint8_t obj_class,
		 const struct abis_om_obj_inst *obj_inst)
{
	struct gsm_abis_mo *mo;

	mo = gsm_objclass2mo(bts, obj_class, obj_inst);
	if (!mo)
		return NULL;

	return &mo->nm_state;
}

/* obtain the in-memory data structure of a given object instance */
void *
gsm_objclass2obj(struct gsm_bts *bts, uint8_t obj_class,
	     const struct abis_om_obj_inst *obj_inst)
{
	struct gsm_bts_trx *trx;
	void *obj = NULL;

	switch (obj_class) {
	case NM_OC_BTS:
		obj = bts;
		break;
	case NM_OC_RADIO_CARRIER:
		if (obj_inst->trx_nr >= bts->num_trx) {
			return NULL;
		}
		trx = gsm_bts_trx_num(bts, obj_inst->trx_nr);
		obj = trx;
		break;
	case NM_OC_BASEB_TRANSC:
		if (obj_inst->trx_nr >= bts->num_trx) {
			return NULL;
		}
		trx = gsm_bts_trx_num(bts, obj_inst->trx_nr);
		obj = &trx->bb_transc;
		break;
	case NM_OC_CHANNEL:
		if (obj_inst->trx_nr >= bts->num_trx) {
			return NULL;
		}
		trx = gsm_bts_trx_num(bts, obj_inst->trx_nr);
		if (obj_inst->ts_nr >= TRX_NR_TS)
			return NULL;
		obj = &trx->ts[obj_inst->ts_nr];
		break;
	case NM_OC_SITE_MANAGER:
		obj = &bts->site_mgr;
		break;
	case NM_OC_GPRS_NSE:
		obj = &bts->gprs.nse;
		break;
	case NM_OC_GPRS_CELL:
		obj = &bts->gprs.cell;
		break;
	case NM_OC_GPRS_NSVC:
		if (obj_inst->trx_nr >= ARRAY_SIZE(bts->gprs.nsvc))
			return NULL;
		obj = &bts->gprs.nsvc[obj_inst->trx_nr];
		break;
	}
	return obj;
}

/* See Table 10.5.25 of GSM04.08 */
uint8_t gsm_pchan2chan_nr(enum gsm_phys_chan_config pchan,
			  uint8_t ts_nr, uint8_t lchan_nr)
{
	uint8_t cbits, chan_nr;

	switch (pchan) {
	case GSM_PCHAN_TCH_F:
	case GSM_PCHAN_TCH_F_PDCH:
		OSMO_ASSERT(lchan_nr == 0);
		cbits = 0x01;
		break;
	case GSM_PCHAN_PDCH:
		OSMO_ASSERT(lchan_nr == 0);
		cbits = RSL_CHAN_OSMO_PDCH >> 3;
		break;
	case GSM_PCHAN_TCH_H:
		OSMO_ASSERT(lchan_nr < 2);
		cbits = 0x02;
		cbits += lchan_nr;
		break;
	case GSM_PCHAN_CCCH_SDCCH4:
	case GSM_PCHAN_CCCH_SDCCH4_CBCH:
		/*
		 * As a special hack for BCCH, lchan_nr == 4 may be passed
		 * here. This should never be sent in an RSL message.
		 * See osmo-bts-xxx/oml.c:opstart_compl().
		 */
		if (lchan_nr == CCCH_LCHAN)
			chan_nr = 0;
		else
			OSMO_ASSERT(lchan_nr < 4);
		cbits = 0x04;
		cbits += lchan_nr;
		break;
	case GSM_PCHAN_SDCCH8_SACCH8C:
	case GSM_PCHAN_SDCCH8_SACCH8C_CBCH:
		OSMO_ASSERT(lchan_nr < 8);
		cbits = 0x08;
		cbits += lchan_nr;
		break;
	default:
	case GSM_PCHAN_CCCH:
		OSMO_ASSERT(lchan_nr == 0);
		cbits = 0x10;
		break;
	}

	chan_nr = (cbits << 3) | (ts_nr & 0x7);

	return chan_nr;
}

uint8_t gsm_lchan2chan_nr(const struct gsm_lchan *lchan)
{
	enum gsm_phys_chan_config pchan = lchan->ts->pchan;
	if (pchan == GSM_PCHAN_TCH_F_TCH_H_PDCH)
		return gsm_lchan_as_pchan2chan_nr(lchan,
						  lchan->ts->dyn.pchan_is);
	return gsm_pchan2chan_nr(lchan->ts->pchan, lchan->ts->nr, lchan->nr);
}

uint8_t gsm_lchan_as_pchan2chan_nr(const struct gsm_lchan *lchan,
				   enum gsm_phys_chan_config as_pchan)
{
	if (lchan->ts->pchan == GSM_PCHAN_TCH_F_TCH_H_PDCH
	    && as_pchan == GSM_PCHAN_PDCH)
		return RSL_CHAN_OSMO_PDCH | (lchan->ts->nr & ~RSL_CHAN_NR_MASK);
	return gsm_pchan2chan_nr(as_pchan, lchan->ts->nr, lchan->nr);
}

/* return the gsm_lchan for the CBCH (if it exists at all) */
struct gsm_lchan *gsm_bts_get_cbch(struct gsm_bts *bts)
{
	struct gsm_lchan *lchan = NULL;
	struct gsm_bts_trx *trx = bts->c0;

	if (trx->ts[0].pchan == GSM_PCHAN_CCCH_SDCCH4_CBCH)
		lchan = &trx->ts[0].lchan[2];
	else {
		int i;
		for (i = 0; i < 8; i++) {
			if (trx->ts[i].pchan == GSM_PCHAN_SDCCH8_SACCH8C_CBCH) {
				lchan = &trx->ts[i].lchan[2];
				break;
			}
		}
	}

	return lchan;
}

/* determine logical channel based on TRX and channel number IE */
struct gsm_lchan *rsl_lchan_lookup(struct gsm_bts_trx *trx, uint8_t chan_nr,
				   int *rc)
{
	uint8_t ts_nr = chan_nr & 0x07;
	uint8_t cbits = chan_nr >> 3;
	uint8_t lch_idx;
	struct gsm_bts_trx_ts *ts = &trx->ts[ts_nr];
	bool ok = true;

	if (rc)
		*rc = -EINVAL;

	if (cbits == 0x01) {
		lch_idx = 0;	/* TCH/F */	
		if (ts->pchan != GSM_PCHAN_TCH_F &&
		    ts->pchan != GSM_PCHAN_PDCH &&
		    ts->pchan != GSM_PCHAN_TCH_F_PDCH
		    && !(ts->pchan == GSM_PCHAN_TCH_F_TCH_H_PDCH
			 && (ts->dyn.pchan_is == GSM_PCHAN_TCH_F
			     || ts->dyn.pchan_want == GSM_PCHAN_TCH_F)))
			ok = false;
	} else if ((cbits & 0x1e) == 0x02) {
		lch_idx = cbits & 0x1;	/* TCH/H */
		if (ts->pchan != GSM_PCHAN_TCH_H
		    && !(ts->pchan == GSM_PCHAN_TCH_F_TCH_H_PDCH
			 && (ts->dyn.pchan_is == GSM_PCHAN_TCH_H
			     || ts->dyn.pchan_want == GSM_PCHAN_TCH_H)))
			ok = false;
	} else if ((cbits & 0x1c) == 0x04) {
		lch_idx = cbits & 0x3;	/* SDCCH/4 */
		if (ts->pchan != GSM_PCHAN_CCCH_SDCCH4 &&
		    ts->pchan != GSM_PCHAN_CCCH_SDCCH4_CBCH)
			ok = false;
	} else if ((cbits & 0x18) == 0x08) {
		lch_idx = cbits & 0x7;	/* SDCCH/8 */
		if (ts->pchan != GSM_PCHAN_SDCCH8_SACCH8C &&
		    ts->pchan != GSM_PCHAN_SDCCH8_SACCH8C_CBCH)
			ok = false;
	} else if (cbits == 0x10 || cbits == 0x11 || cbits == 0x12) {
		lch_idx = 0;
		if (ts->pchan != GSM_PCHAN_CCCH &&
		    ts->pchan != GSM_PCHAN_CCCH_SDCCH4 &&
		    ts->pchan != GSM_PCHAN_CCCH_SDCCH4_CBCH)
			ok = false;
		/* FIXME: we should not return first sdcch4 !!! */
	} else if ((chan_nr & RSL_CHAN_NR_MASK) == RSL_CHAN_OSMO_PDCH) {
		lch_idx = 0;
		if (ts->pchan != GSM_PCHAN_TCH_F_TCH_H_PDCH)
			ok = false;
	} else
		return NULL;

	if (rc && ok)
		*rc = 0;

	return &ts->lchan[lch_idx];
}

static const uint8_t subslots_per_pchan[] = {
	[GSM_PCHAN_NONE] = 0,
	[GSM_PCHAN_CCCH] = 0,
	[GSM_PCHAN_PDCH] = 0,
	[GSM_PCHAN_CCCH_SDCCH4] = 4,
	[GSM_PCHAN_TCH_F] = 1,
	[GSM_PCHAN_TCH_H] = 2,
	[GSM_PCHAN_SDCCH8_SACCH8C] = 8,
	[GSM_PCHAN_CCCH_SDCCH4_CBCH] = 4,
	[GSM_PCHAN_SDCCH8_SACCH8C_CBCH] = 8,
	/*
	 * GSM_PCHAN_TCH_F_PDCH and GSM_PCHAN_TCH_F_TCH_H_PDCH should not be
	 * part of this, those TS are handled according to their dynamic state.
	 */
};

/*! Return the actual pchan type, also heeding dynamic TS. */
enum gsm_phys_chan_config ts_pchan(struct gsm_bts_trx_ts *ts)
{
	switch (ts->pchan) {
	case GSM_PCHAN_TCH_F_TCH_H_PDCH:
		return ts->dyn.pchan_is;
	case GSM_PCHAN_TCH_F_PDCH:
		if (ts->flags & TS_F_PDCH_ACTIVE)
			return GSM_PCHAN_PDCH;
		else
			return GSM_PCHAN_TCH_F;
	default:
		return ts->pchan;
	}
}

/*! According to ts->pchan and possibly ts->dyn_pchan, return the number of
 * logical channels available in the timeslot. */
uint8_t ts_subslots(struct gsm_bts_trx_ts *ts)
{
	return subslots_per_pchan[ts_pchan(ts)];
}

static bool pchan_is_tch(enum gsm_phys_chan_config pchan)
{
	switch (pchan) {
	case GSM_PCHAN_TCH_F:
	case GSM_PCHAN_TCH_H:
		return true;
	default:
		return false;
	}
}

bool ts_is_tch(struct gsm_bts_trx_ts *ts)
{
	return pchan_is_tch(ts_pchan(ts));
}
