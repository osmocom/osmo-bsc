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
#include <inttypes.h>
#include <netinet/in.h>
#include <talloc.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/byteswap.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/gsm/abis_nm.h>
#include <osmocom/core/statistics.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gsm/gsm48.h>
#include <osmocom/gsm/gsm0808_utils.h>

#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/osmo_bsc_lcls.h>
#include <osmocom/bsc/abis_rsl.h>
#include <osmocom/bsc/abis_nm.h>
#include <osmocom/bsc/handover_cfg.h>
#include <osmocom/bsc/timeslot_fsm.h>
#include <osmocom/bsc/lchan_fsm.h>
#include <osmocom/bsc/bts.h>
#include <osmocom/bsc/bsc_msc_data.h>

void *tall_bsc_ctx = NULL;

void set_ts_e1link(struct gsm_bts_trx_ts *ts, uint8_t e1_nr,
		   uint8_t e1_ts, uint8_t e1_ts_ss)
{
	ts->e1_link.e1_nr = e1_nr;
	ts->e1_link.e1_ts = e1_ts;
	ts->e1_link.e1_ts_ss = e1_ts_ss;
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

struct gsm_bts *gsm_bts_alloc_register(struct gsm_network *net, enum gsm_bts_type type,
					uint8_t bsic)
{
	struct gsm_bts_model *model = bts_model_find(type);
	struct gsm_bts_sm *bts_sm;
	struct gsm_bts *bts;

	if (!model && type != GSM_BTS_TYPE_UNKNOWN)
		return NULL;

	bts_sm = gsm_bts_sm_alloc(net, net->num_bts);
	if (!bts_sm)
		return NULL;
	bts = bts_sm->bts[0];

	net->num_bts++;

	bts->type = type;
	bts->model = model;
	bts->bsic = bsic;

	llist_add_tail(&bts->list, &net->bts_list);

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

void gsm_abis_mo_reset(struct gsm_abis_mo *mo)
{
	mo->nm_state.operational = NM_OPSTATE_NULL;
	mo->nm_state.availability = NM_AVSTATE_POWER_OFF;
	mo->nm_state.administrative = NM_STATE_LOCKED;
}

void gsm_mo_init(struct gsm_abis_mo *mo, struct gsm_bts *bts,
		 uint8_t obj_class, uint8_t p1, uint8_t p2, uint8_t p3)
{
	mo->bts = bts;
	mo->obj_class = obj_class;
	mo->obj_inst.bts_nr = p1;
	mo->obj_inst.trx_nr = p2;
	mo->obj_inst.ts_nr = p3;
	gsm_abis_mo_reset(mo);
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

const struct value_string gsm_pchant_names[] = {
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

const struct value_string gsm_pchan_ids[] = {
	{ GSM_PCHAN_NONE,	"NONE" },
	{ GSM_PCHAN_CCCH,	"CCCH" },
	{ GSM_PCHAN_CCCH_SDCCH4,"CCCH_SDCCH4" },
	{ GSM_PCHAN_TCH_F,	"TCH_F" },
	{ GSM_PCHAN_TCH_H,	"TCH_H" },
	{ GSM_PCHAN_SDCCH8_SACCH8C, "SDCCH8" },
	{ GSM_PCHAN_PDCH,	"PDCH" },
	{ GSM_PCHAN_TCH_F_PDCH,	"TCH_F_PDCH" },
	{ GSM_PCHAN_UNKNOWN,	"UNKNOWN" },
	{ GSM_PCHAN_CCCH_SDCCH4_CBCH, "CCCH_SDCCH4_CBCH" },
	{ GSM_PCHAN_SDCCH8_SACCH8C_CBCH, "SDCCH8_CBCH" },
	{ GSM_PCHAN_TCH_F_TCH_H_PDCH, "TCH_F_TCH_H_PDCH" },
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

struct gsm_bts *gsm_bts_num(const struct gsm_network *net, int num)
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

/* From a list of local BTSes that match the cell_id, return the Nth one, or NULL if there is no such
 * match. */
struct gsm_bts *gsm_bts_by_cell_id(const struct gsm_network *net,
				   const struct gsm0808_cell_id *cell_id,
				   int match_idx)
{
	struct gsm_bts *bts;
	int i = 0;
	llist_for_each_entry(bts, &net->bts_list, list) {
		if (!gsm_bts_matches_cell_id(bts, cell_id))
			continue;
		if (i < match_idx) {
			/* this is only the i'th match, we're looking for a later one... */
			i++;
			continue;
		}
		return bts;
	}
	return NULL;
}

static char ts2str[255];

char *gsm_ts_name(const struct gsm_bts_trx_ts *ts)
{
	snprintf(ts2str, sizeof(ts2str), "(bts=%d,trx=%d,ts=%d)",
		 ts->trx->bts->nr, ts->trx->nr, ts->nr);

	return ts2str;
}

/*! Log timeslot number with full pchan information */
char *gsm_ts_and_pchan_name(const struct gsm_bts_trx_ts *ts)
{
	if (!ts->fi)
		snprintf(ts2str, sizeof(ts2str),
			 "(bts=%d,trx=%d,ts=%d,pchan_from_config=%s, not allocated)",
			 ts->trx->bts->nr, ts->trx->nr, ts->nr,
			 gsm_pchan_name(ts->pchan_from_config));
	else if (ts->fi->state == TS_ST_NOT_INITIALIZED)
		snprintf(ts2str, sizeof(ts2str),
			 "(bts=%d,trx=%d,ts=%d,pchan_from_config=%s,state=%s)",
			 ts->trx->bts->nr, ts->trx->nr, ts->nr,
			 gsm_pchan_name(ts->pchan_from_config),
			 osmo_fsm_inst_state_name(ts->fi));
	else if (ts->pchan_is == ts->pchan_on_init)
		snprintf(ts2str, sizeof(ts2str),
			 "(bts=%d,trx=%d,ts=%d,pchan=%s,state=%s)",
			 ts->trx->bts->nr, ts->trx->nr, ts->nr,
			 gsm_pchan_name(ts->pchan_is),
			 osmo_fsm_inst_state_name(ts->fi));
	else
		snprintf(ts2str, sizeof(ts2str),
			 "(bts=%d,trx=%d,ts=%d,pchan_on_init=%s,pchan=%s,state=%s)",
			 ts->trx->bts->nr, ts->trx->nr, ts->nr,
			 gsm_pchan_name(ts->pchan_on_init),
			 gsm_pchan_name(ts->pchan_is),
			 osmo_fsm_inst_state_name(ts->fi));
	return ts2str;
}

char *gsm_lchan_name_compute(void *ctx, const struct gsm_lchan *lchan)
{
	struct gsm_bts_trx_ts *ts = lchan->ts;
	return talloc_asprintf(ctx, "(bts=%d,trx=%d,ts=%d,ss=%d)",
			       ts->trx->bts->nr, ts->trx->nr, ts->nr, lchan->nr);
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
		mo = &bts->site_mgr->mo;
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
		mo = &bts->site_mgr->gprs.nse.mo;
		break;
	case NM_OC_GPRS_CELL:
		mo = &bts->gprs.cell.mo;
		break;
	case NM_OC_GPRS_NSVC:
		if (obj_inst->trx_nr >= ARRAY_SIZE(bts->site_mgr->gprs.nsvc))
			return NULL;
		mo = &bts->site_mgr->gprs.nsvc[obj_inst->trx_nr].mo;
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
		obj = bts->site_mgr;
		break;
	case NM_OC_GPRS_NSE:
		obj = &bts->site_mgr->gprs.nse;
		break;
	case NM_OC_GPRS_CELL:
		obj = &bts->gprs.cell;
		break;
	case NM_OC_GPRS_NSVC:
		if (obj_inst->trx_nr >= ARRAY_SIZE(bts->site_mgr->gprs.nsvc))
			return NULL;
		obj = &bts->site_mgr->gprs.nsvc[obj_inst->trx_nr];
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
	/* Note: non-standard Osmocom style dyn TS PDCH mode chan_nr is only used within
	 * rsl_tx_dyn_ts_pdch_act_deact(). */
	return gsm_pchan2chan_nr(lchan->ts->pchan_is, lchan->ts->nr, lchan->nr);
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
	/* Dyn TS: maximum allowed subslots */
	[GSM_PCHAN_TCH_F_TCH_H_PDCH] = 2,
	[GSM_PCHAN_TCH_F_PDCH] = 1,
};

/*! According to ts->pchan and possibly ts->dyn_pchan, return the number of
 * logical channels available in the timeslot. */
uint8_t pchan_subslots(enum gsm_phys_chan_config pchan)
{
	if (pchan < 0 || pchan >= ARRAY_SIZE(subslots_per_pchan))
		return 0;
	return subslots_per_pchan[pchan];
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
	return pchan_is_tch(ts->pchan_is);
}

struct gsm_bts *conn_get_bts(struct gsm_subscriber_connection *conn) {
	if (!conn || !conn->lchan)
		return NULL;
	return conn->lchan->ts->trx->bts;
}

static void _chan_desc_fill_tail(struct gsm48_chan_desc *cd, const struct gsm_lchan *lchan)
{
	if (!lchan->ts->hopping.enabled) {
		uint16_t arfcn = lchan->ts->trx->arfcn & 0x3ff;
		cd->h0.tsc = gsm_ts_tsc(lchan->ts);
		cd->h0.h = 0;
		cd->h0.spare = 0;
		cd->h0.arfcn_high = arfcn >> 8;
		cd->h0.arfcn_low = arfcn & 0xff;
	} else {
		cd->h1.tsc = gsm_ts_tsc(lchan->ts);
		cd->h1.h = 1;
		cd->h1.maio_high = lchan->ts->hopping.maio >> 2;
		cd->h1.maio_low = lchan->ts->hopping.maio & 0x03;
		cd->h1.hsn = lchan->ts->hopping.hsn;
	}
}

void gsm48_lchan2chan_desc(struct gsm48_chan_desc *cd,
			   const struct gsm_lchan *lchan)
{
	cd->chan_nr = gsm_lchan2chan_nr(lchan);
	_chan_desc_fill_tail(cd, lchan);
}

/* like gsm48_lchan2chan_desc() above, but use ts->pchan_from_config to
 * return a channel description based on what is configured, rather than
 * what the current state of the pchan type is */
void gsm48_lchan2chan_desc_as_configured(struct gsm48_chan_desc *cd,
					 const struct gsm_lchan *lchan)
{
	cd->chan_nr = gsm_pchan2chan_nr(lchan->ts->pchan_from_config, lchan->ts->nr, lchan->nr);
	_chan_desc_fill_tail(cd, lchan);
}

uint8_t gsm_ts_tsc(const struct gsm_bts_trx_ts *ts)
{
	if (ts->tsc != -1)
		return ts->tsc;
	else
		return ts->trx->bts->bsic & 7;
}

bool nm_is_running(const struct gsm_nm_state *s) {
	if (s->operational != NM_OPSTATE_ENABLED)
		return false;
	if ((s->availability != NM_AVSTATE_OK) && (s->availability != 0xff))
		return false;
	if (s->administrative != NM_STATE_UNLOCKED)
		return false;
	return true;
}

/* determine the logical channel type based on the physical channel type */
int gsm_lchan_type_by_pchan(enum gsm_phys_chan_config pchan)
{
	switch (pchan) {
	case GSM_PCHAN_TCH_F:
		return GSM_LCHAN_TCH_F;
	case GSM_PCHAN_TCH_H:
		return GSM_LCHAN_TCH_H;
	case GSM_PCHAN_SDCCH8_SACCH8C:
	case GSM_PCHAN_SDCCH8_SACCH8C_CBCH:
	case GSM_PCHAN_CCCH_SDCCH4:
	case GSM_PCHAN_CCCH_SDCCH4_CBCH:
		return GSM_LCHAN_SDCCH;
	default:
		return -1;
	}
}

enum gsm_phys_chan_config gsm_pchan_by_lchan_type(enum gsm_chan_t type)
{
	switch (type) {
	case GSM_LCHAN_TCH_F:
		return GSM_PCHAN_TCH_F;
	case GSM_LCHAN_TCH_H:
		return GSM_PCHAN_TCH_H;
	case GSM_LCHAN_NONE:
	case GSM_LCHAN_PDTCH:
		/* TODO: so far lchan->type is NONE in PDCH mode. PDTCH is only
		 * used in osmo-bts. Maybe set PDTCH and drop the NONE case
		 * here. */
		return GSM_PCHAN_PDCH;
	default:
		return GSM_PCHAN_UNKNOWN;
	}
}

/* Can the timeslot in principle be used as this PCHAN kind? */
bool ts_is_capable_of_pchan(struct gsm_bts_trx_ts *ts, enum gsm_phys_chan_config pchan)
{
	switch (ts->pchan_on_init) {
	case GSM_PCHAN_TCH_F_PDCH:
		switch (pchan) {
		case GSM_PCHAN_TCH_F:
		case GSM_PCHAN_PDCH:
			return true;
		default:
			return false;
		}

	case GSM_PCHAN_TCH_F_TCH_H_PDCH:
		switch (pchan) {
		case GSM_PCHAN_TCH_F:
		case GSM_PCHAN_TCH_H:
		case GSM_PCHAN_PDCH:
			return true;
		default:
			return false;
		}

	case GSM_PCHAN_CCCH_SDCCH4_CBCH:
		switch (pchan) {
		case GSM_PCHAN_CCCH_SDCCH4_CBCH:
		case GSM_PCHAN_CCCH_SDCCH4:
		case GSM_PCHAN_CCCH:
			return true;
		default:
			return false;
		}

	case GSM_PCHAN_CCCH_SDCCH4:
		switch (pchan) {
		case GSM_PCHAN_CCCH_SDCCH4:
		case GSM_PCHAN_CCCH:
			return true;
		default:
			return false;
		}

	case GSM_PCHAN_SDCCH8_SACCH8C_CBCH:
		switch (pchan) {
		case GSM_PCHAN_SDCCH8_SACCH8C_CBCH:
		case GSM_PCHAN_SDCCH8_SACCH8C:
			return true;
		default:
			return false;
		}

	default:
		return ts->pchan_on_init == pchan;
	}
}

bool ts_is_capable_of_lchant(struct gsm_bts_trx_ts *ts, enum gsm_chan_t type)
{
	switch (ts->pchan_on_init) {

	case GSM_PCHAN_TCH_F:
		switch (type) {
		case GSM_LCHAN_TCH_F:
			return true;
		default:
			return false;
		}

	case GSM_PCHAN_TCH_H:
		switch (type) {
		case GSM_LCHAN_TCH_H:
			return true;
		default:
			return false;
		}

	case GSM_PCHAN_TCH_F_PDCH:
		switch (type) {
		case GSM_LCHAN_TCH_F:
		case GSM_LCHAN_PDTCH:
			return true;
		default:
			return false;
		}

	case GSM_PCHAN_TCH_F_TCH_H_PDCH:
		switch (type) {
		case GSM_LCHAN_TCH_F:
		case GSM_LCHAN_TCH_H:
		case GSM_LCHAN_PDTCH:
			return true;
		default:
			return false;
		}

	case GSM_PCHAN_PDCH:
		switch (type) {
		case GSM_LCHAN_PDTCH:
			return true;
		default:
			return false;
		}

	case GSM_PCHAN_CCCH:
		switch (type) {
		case GSM_LCHAN_CCCH:
			return true;
		default:
			return false;
		}
		break;

	case GSM_PCHAN_CCCH_SDCCH4_CBCH:
	case GSM_PCHAN_CCCH_SDCCH4:
	case GSM_PCHAN_SDCCH8_SACCH8C:
	case GSM_PCHAN_SDCCH8_SACCH8C_CBCH:
		switch (type) {
		case GSM_LCHAN_CCCH:
		case GSM_LCHAN_SDCCH:
			return true;
		default:
			return false;
		}

	default:
		return false;
	}
}

bool ts_is_usable(const struct gsm_bts_trx_ts *ts)
{
	if (!trx_is_usable(ts->trx)) {
		LOGP(DRLL, LOGL_DEBUG, "%s not usable\n", gsm_trx_name(ts->trx));
		return false;
	}

	if (!ts->fi)
		return false;

	switch (ts->fi->state) {
	case TS_ST_NOT_INITIALIZED:
	case TS_ST_BORKEN:
		return false;
	default:
		break;
	}

	return true;
}

void conn_update_ms_power_class(struct gsm_subscriber_connection *conn, uint8_t power_class)
{
	struct gsm_bts *bts = conn_get_bts(conn);

	/* MS Power class remains the same => do nothing */
	if (power_class == conn->ms_power_class)
		return;

	LOGP(DRLL, LOGL_DEBUG, "MS Power class update: %" PRIu8 " -> %" PRIu8 "\n",
	     conn->ms_power_class, power_class);

	conn->ms_power_class = power_class;

	/* If there's an associated lchan, attempt to update its max power to be
	   on track with band maximum values */
	if (bts && conn->lchan)
		lchan_update_ms_power_ctrl_level(conn->lchan, bts->ms_max_power);
}

void lchan_update_ms_power_ctrl_level(struct gsm_lchan *lchan, int ms_power_dbm)
{
	struct gsm_bts *bts = lchan->ts->trx->bts;
	struct gsm_subscriber_connection *conn = lchan->conn;
	int max_pwr_dbm_pwclass, new_pwr;
	bool send_pwr_ctrl_msg = false;

	LOG_LCHAN(lchan, LOGL_DEBUG,
		  "MS Power level update requested: %d dBm\n", ms_power_dbm);

	if (!conn)
		goto ms_power_default;

	if (conn->ms_power_class == 0)
		goto ms_power_default;

	if ((max_pwr_dbm_pwclass = (int)ms_class_gmsk_dbm(bts->band, conn->ms_power_class)) < 0) {
		LOG_LCHAN(lchan, LOGL_INFO,
			 "Failed getting max ms power for power class %" PRIu8
			 " on band %s, providing default max ms power\n",
			 conn->ms_power_class, gsm_band_name(bts->band));
		goto ms_power_default;
	}

	/* Current configured max pwr is above maximum one allowed on
	   current band + ms power class, so use that one. */
	if (ms_power_dbm > max_pwr_dbm_pwclass)
		ms_power_dbm = max_pwr_dbm_pwclass;

ms_power_default:
	if ((new_pwr = ms_pwr_ctl_lvl(bts->band, ms_power_dbm)) < 0) {
		LOG_LCHAN(lchan, LOGL_INFO,
			 "Failed getting max ms power level %d on band %s,"
			 " providing default max ms power\n",
			 ms_power_dbm, gsm_band_name(bts->band));
		return;
	}

	LOG_LCHAN(lchan, LOGL_DEBUG,
		  "MS Power level update (power class %" PRIu8 "): %" PRIu8 " -> %d\n",
		  conn ? conn->ms_power_class : 0, lchan->ms_power, new_pwr);

	/* If chan was already activated and max ms_power changes (due to power
	   classmark received), send an MS Power Control message */
	if (lchan->activate.activ_ack && new_pwr != lchan->ms_power)
		send_pwr_ctrl_msg = true;

	lchan->ms_power = new_pwr;

	if (send_pwr_ctrl_msg)
		rsl_chan_ms_power_ctrl(lchan);
}

const struct value_string lchan_activate_mode_names[] = {
	OSMO_VALUE_STRING(FOR_NONE),
	OSMO_VALUE_STRING(FOR_MS_CHANNEL_REQUEST),
	OSMO_VALUE_STRING(FOR_ASSIGNMENT),
	OSMO_VALUE_STRING(FOR_HANDOVER),
	OSMO_VALUE_STRING(FOR_VTY),
	{}
};

/* This may be specific to RR Channel Release, and the mappings were chosen by pure naive guessing without a proper
 * specification available. */
enum gsm48_rr_cause bsc_gsm48_rr_cause_from_gsm0808_cause(enum gsm0808_cause c)
{
	switch (c) {
	case GSM0808_CAUSE_PREEMPTION:
		return GSM48_RR_CAUSE_PREMPTIVE_REL;
	case GSM0808_CAUSE_RADIO_INTERFACE_MESSAGE_FAILURE:
	case GSM0808_CAUSE_INVALID_MESSAGE_CONTENTS:
	case GSM0808_CAUSE_INFORMATION_ELEMENT_OR_FIELD_MISSING:
	case GSM0808_CAUSE_INCORRECT_VALUE:
	case GSM0808_CAUSE_UNKNOWN_MESSAGE_TYPE:
	case GSM0808_CAUSE_UNKNOWN_INFORMATION_ELEMENT:
		return GSM48_RR_CAUSE_PROT_ERROR_UNSPC;
	case GSM0808_CAUSE_CALL_CONTROL:
	case GSM0808_CAUSE_HANDOVER_SUCCESSFUL:
	case GSM0808_CAUSE_BETTER_CELL:
	case GSM0808_CAUSE_DIRECTED_RETRY:
	case GSM0808_CAUSE_REDUCE_LOAD_IN_SERVING_CELL:
	case GSM0808_CAUSE_RELOCATION_TRIGGERED:
	case GSM0808_CAUSE_ALT_CHAN_CONFIG_REQUESTED:
		return GSM48_RR_CAUSE_NORMAL;
	default:
		return GSM48_RR_CAUSE_ABNORMAL_UNSPEC;
	}
}

/* Map RSL_ERR_* cause codes to gsm48_rr_cause codes.
 * The mappings were chosen by naive guessing without a proper specification available. */
enum gsm48_rr_cause bsc_gsm48_rr_cause_from_rsl_cause(uint8_t c)
{
	switch (c) {
	case RSL_ERR_NORMAL_UNSPEC:
		return GSM48_RR_CAUSE_NORMAL;
	case RSL_ERR_MAND_IE_ERROR:
		return GSM48_RR_CAUSE_INVALID_MAND_INF;
	case RSL_ERR_OPT_IE_ERROR:
		return GSM48_RR_CAUSE_COND_IE_ERROR;
	case RSL_ERR_INVALID_MESSAGE:
	case RSL_ERR_MSG_DISCR:
	case RSL_ERR_MSG_TYPE:
	case RSL_ERR_MSG_SEQ:
	case RSL_ERR_IE_ERROR:
	case RSL_ERR_IE_NONEXIST:
	case RSL_ERR_IE_LENGTH:
	case RSL_ERR_IE_CONTENT:
	case RSL_ERR_PROTO:
		return GSM48_RR_CAUSE_PROT_ERROR_UNSPC;
	default:
		return GSM48_RR_CAUSE_ABNORMAL_UNSPEC;
	}
}

/* Default MS/BS Power Control parameters (see 3GPP TS 45.008, table A.1) */
const struct gsm_power_ctrl_params power_ctrl_params_def = {
	/* Static Power Control is the safe default */
	.mode = GSM_PWR_CTRL_MODE_STATIC,

	/* BS Power reduction value / maximum (in dB) */
	.bs_power_val_db = 0,  /* no attenuation in static mode */
	.bs_power_max_db = 12, /* up to 12 dB in dynamic mode */

	/* Power increasing/reducing step size */
	.inc_step_size_db = 4, /* 2, 4, or 6 dB */
	.red_step_size_db = 2, /* 2 or 4 dB */

	/* RxLev measurement parameters */
	.rxlev_meas = {
		/* Thresholds for RxLev (see 3GPP TS 45.008, A.3.2.1) */
		.lower_thresh = 32, /* L_RXLEV_XX_P (-78 dBm) */
		.upper_thresh = 38, /* U_RXLEV_XX_P (-72 dBm) */

		/* Increase {UL,DL}_TXPWR if at least LOWER_CMP_P averages
		 * out of LOWER_CMP_N averages are lower than L_RXLEV_XX_P */
		.lower_cmp_p = 10, /* P1 as in 3GPP TS 45.008, A.3.2.1 (case a) */
		.lower_cmp_n = 12, /* N1 as in 3GPP TS 45.008, A.3.2.1 (case a) */
		/* Decrease {UL,DL}_TXPWR if at least UPPER_CMP_P averages
		 * out of UPPER_CMP_N averages are greater than L_RXLEV_XX_P */
		.upper_cmp_p = 19, /* P2 as in 3GPP TS 45.008, A.3.2.1 (case b) */
		.upper_cmp_n = 20, /* N2 as in 3GPP TS 45.008, A.3.2.1 (case b) */

		/* No averaging (filtering) by default */
		.algo = GSM_PWR_CTRL_MEAS_AVG_ALGO_NONE,

		/* Hreqave: the period over which an average is produced */
		.h_reqave = 4, /* TODO: investigate a reasonable default value */
		/* Hreqt: the number of averaged results maintained */
		.h_reqt = 6, /* TODO: investigate a reasonable default value */
	},

	/* RxQual measurement parameters */
	.rxqual_meas = {
		/* Thresholds for RxQual (see 3GPP TS 45.008, A.3.2.1) */
		.lower_thresh = 3, /* L_RXQUAL_XX_P (0.8% <= BER < 1.6%) */
		.upper_thresh = 0, /* U_RXQUAL_XX_P (BER < 0.2%) */

		/* Increase {UL,DL}_TXPWR if at least LOWER_CMP_P averages
		 * out of LOWER_CMP_N averages are lower than L_RXLEV_XX_P */
		.lower_cmp_p = 5, /* P3 as in 3GPP TS 45.008, A.3.2.1 (case c) */
		.lower_cmp_n = 7, /* N3 as in 3GPP TS 45.008, A.3.2.1 (case c) */
		/* Decrease {UL,DL}_TXPWR if at least UPPER_CMP_P averages
		 * out of UPPER_CMP_N averages are greater than L_RXLEV_XX_P */
		.upper_cmp_p = 15, /* P4 as in 3GPP TS 45.008, A.3.2.1 (case d) */
		.upper_cmp_n = 18, /* N4 as in 3GPP TS 45.008, A.3.2.1 (case d) */

		/* No averaging (filtering) by default */
		.algo = GSM_PWR_CTRL_MEAS_AVG_ALGO_NONE,

		/* Hreqave: the period over which an average is produced */
		.h_reqave = 4, /* TODO: investigate a reasonable default value */
		/* Hreqt: the number of averaged results maintained */
		.h_reqt = 6, /* TODO: investigate a reasonable default value */
	},
};
