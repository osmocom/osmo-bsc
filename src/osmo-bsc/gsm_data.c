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

osmo_static_assert(BTS_NR_MAX == ((2 << ((sizeof(gsm_bts_nr_t) * 8) - 1)) - 1), _gsm_bts_nr_t_size);

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
	struct gsm_bts *bts;
	int skip = 0;

	if (start_bts)
		skip = 1;

	llist_for_each_entry(bts, &net->bts_list, list) {
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
	gsm_set_bts_model(bts, model);
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
	{ GSM_CHREQ_REASON_CALL,	"call (re-)establishment" },
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
	{ GSM_PCHAN_TCH_F_PDCH,	"DYNAMIC/IPACCESS" },
	{ GSM_PCHAN_UNKNOWN,	"UNKNOWN" },
	{ GSM_PCHAN_CCCH_SDCCH4_CBCH, "CCCH+SDCCH4+CBCH" },
	{ GSM_PCHAN_SDCCH8_SACCH8C_CBCH, "SDCCH8+CBCH" },
	{ GSM_PCHAN_OSMO_DYN, "DYNAMIC/OSMOCOM" },
	/* make get_string_value() return GSM_PCHAN_TCH_F_PDCH for both "DYNAMIC/IPACCESS" and "TCH/F_PDCH" */
	{ GSM_PCHAN_TCH_F_PDCH,	"TCH/F_PDCH" },
	/* make get_string_value() return GSM_PCHAN_OSMO_DYN for both "DYNAMIC/OSMOCOM" and "TCH/F_TCH/H_SDCCH8_PDCH" */
	{ GSM_PCHAN_OSMO_DYN, "TCH/F_TCH/H_SDCCH8_PDCH" },
	/* When adding items here, you must also add matching items to gsm_pchant_descs[]! */
	{ 0,			NULL }
};

/* VTY command descriptions. These have to be in the same order as gsm_pchant_names[], so that the automatic VTY command
 * composition in bts_trx_vty_init() works out. */
const struct value_string gsm_pchant_descs[] = {
	{ GSM_PCHAN_NONE,	"Physical Channel not configured" },
	{ GSM_PCHAN_CCCH,	"FCCH + SCH + BCCH + CCCH (Comb. IV)" },
	{ GSM_PCHAN_CCCH_SDCCH4,
		"FCCH + SCH + BCCH + CCCH + 4 SDCCH + 2 SACCH (Comb. V)" },
	{ GSM_PCHAN_TCH_F,	"TCH/F + FACCH/F + SACCH (Comb. I)" },
	{ GSM_PCHAN_TCH_H,	"2 TCH/H + 2 FACCH/H + 2 SACCH (Comb. II)" },
	{ GSM_PCHAN_SDCCH8_SACCH8C, "8 SDCCH + 4 SACCH (Comb. VII)" },
	{ GSM_PCHAN_PDCH,	"Packet Data Channel for GPRS/EDGE" },
	{ GSM_PCHAN_TCH_F_PDCH,	"Dynamic TCH/F or GPRS PDCH"
				" (dynamic/ipaccess is an alias for tch/f_pdch)" },
	{ GSM_PCHAN_UNKNOWN,	"Unknown / Unsupported channel combination" },
	{ GSM_PCHAN_CCCH_SDCCH4_CBCH, "FCCH + SCH + BCCH + CCCH + CBCH + 3 SDCCH + 2 SACCH (Comb. V)" },
	{ GSM_PCHAN_SDCCH8_SACCH8C_CBCH, "7 SDCCH + 4 SACCH + CBCH (Comb. VII)" },
	{ GSM_PCHAN_OSMO_DYN,	"Dynamic TCH/F or TCH/H or SDCCH/8 or GPRS PDCH"
				" (dynamic/osmocom is an alias for tch/f_tch/h_sdcch8_pdch)" },
	/* These duplicate entries are needed to provide a description for both the DYNAMIC/... aliases and their
	 * explicit versions 'TCH/F_PDCH' / 'TCH/F_TCH/H_SDCCH8_PDCH', see bts_trx_vty_init() */
	{ GSM_PCHAN_TCH_F_PDCH,	"Dynamic TCH/F or GPRS PDCH"
				" (dynamic/ipaccess is an alias for tch/f_pdch)" },
	{ GSM_PCHAN_OSMO_DYN,	"Dynamic TCH/F or TCH/H or SDCCH/8 or GPRS PDCH"
				" (dynamic/osmocom is an alias for tch/f_tch/h_sdcch8_pdch)" },
	{ 0,			NULL }
};

osmo_static_assert(ARRAY_SIZE(gsm_pchant_names) == ARRAY_SIZE(gsm_pchant_descs), _pchan_vty_docs);

const char *gsm_pchan_name(enum gsm_phys_chan_config c)
{
	return get_value_string(gsm_pchant_names, c);
}

enum gsm_phys_chan_config gsm_pchan_parse(const char *name)
{
	return get_string_value(gsm_pchant_names, name);
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

struct gsm_bts *gsm_bts_num(const struct gsm_network *net, gsm_bts_nr_t num)
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

/* obtain the MO structure for a given object instance */
struct gsm_abis_mo *gsm_objclass2mo(struct gsm_bts *bts, uint8_t obj_class,
				    const struct abis_om_obj_inst *obj_inst)
{
	struct gsm_bts_trx *trx;

	switch (obj_class) {
	case NM_OC_BTS:
		return &bts->mo;
	case NM_OC_RADIO_CARRIER:
		trx = gsm_bts_trx_num(bts, obj_inst->trx_nr);
		return trx != NULL ? &trx->mo : NULL;
	case NM_OC_BASEB_TRANSC:
		trx = gsm_bts_trx_num(bts, obj_inst->trx_nr);
		return trx != NULL ? &trx->bb_transc.mo : NULL;
	case NM_OC_CHANNEL:
		if (obj_inst->ts_nr >= TRX_NR_TS)
			return NULL;
		trx = gsm_bts_trx_num(bts, obj_inst->trx_nr);
		return trx != NULL ? &trx->ts[obj_inst->ts_nr].mo : NULL;
	case NM_OC_SITE_MANAGER:
		return &bts->site_mgr->mo;
	case NM_OC_BS11:
		switch (obj_inst->bts_nr) {
		case BS11_OBJ_CCLK:
			return &bts->bs11.cclk.mo;
		case BS11_OBJ_BBSIG:
			trx = gsm_bts_trx_num(bts, obj_inst->trx_nr);
			return trx != NULL ? &trx->bs11.bbsig.mo : NULL;
		case BS11_OBJ_PA:
			trx = gsm_bts_trx_num(bts, obj_inst->trx_nr);
			return trx != NULL ? &trx->bs11.pa.mo : NULL;
		}
		break;
	case NM_OC_BS11_RACK:
		return &bts->bs11.rack.mo;
	case NM_OC_BS11_ENVABTSE:
		if (obj_inst->trx_nr >= ARRAY_SIZE(bts->bs11.envabtse))
			return NULL;
		return &bts->bs11.envabtse[obj_inst->trx_nr].mo;
	case NM_OC_GPRS_NSE:
		return &bts->site_mgr->gprs.nse.mo;
	case NM_OC_GPRS_CELL:
		return &bts->gprs.cell.mo;
	case NM_OC_GPRS_NSVC:
		if (obj_inst->trx_nr >= ARRAY_SIZE(bts->site_mgr->gprs.nsvc))
			return NULL;
		return &bts->site_mgr->gprs.nsvc[obj_inst->trx_nr].mo;
	}

	return NULL;
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
int gsm_pchan2chan_nr(enum gsm_phys_chan_config pchan,
		      uint8_t ts_nr, uint8_t lchan_nr, bool vamos_is_secondary)
{
	uint8_t cbits, chan_nr;

	switch (pchan) {
	case GSM_PCHAN_TCH_F:
	case GSM_PCHAN_TCH_F_PDCH:
		if (lchan_nr != 0)
			return -EINVAL;
		if (vamos_is_secondary)
			cbits = ABIS_RSL_CHAN_NR_CBITS_OSMO_VAMOS_Bm_ACCHs;
		else
			cbits = ABIS_RSL_CHAN_NR_CBITS_Bm_ACCHs;
		break;
	case GSM_PCHAN_PDCH:
		if (lchan_nr != 0)
			return -EINVAL;
		cbits = ABIS_RSL_CHAN_NR_CBITS_OSMO_PDCH;
		break;
	case GSM_PCHAN_TCH_H:
		if (lchan_nr >= 2)
			return -EINVAL;
		if (vamos_is_secondary)
			cbits = ABIS_RSL_CHAN_NR_CBITS_OSMO_VAMOS_Lm_ACCHs(lchan_nr);
		else
			cbits = ABIS_RSL_CHAN_NR_CBITS_Lm_ACCHs(lchan_nr);
		break;
	case GSM_PCHAN_CCCH_SDCCH4:
	case GSM_PCHAN_CCCH_SDCCH4_CBCH:
		/*
		 * As a special hack for BCCH, lchan_nr == 4 may be passed
		 * here. This should never be sent in an RSL message.
		 * See osmo-bts-xxx/oml.c:opstart_compl().
		 */
		if (lchan_nr == CCCH_LCHAN)
			lchan_nr = 0;
		else if (lchan_nr > 4)
			return -EINVAL;
		cbits = ABIS_RSL_CHAN_NR_CBITS_SDCCH4_ACCH(lchan_nr);
		break;
	case GSM_PCHAN_SDCCH8_SACCH8C:
	case GSM_PCHAN_SDCCH8_SACCH8C_CBCH:
		if (lchan_nr >= 8)
			return -EINVAL;
		cbits = ABIS_RSL_CHAN_NR_CBITS_SDCCH8_ACCH(lchan_nr);
		break;
	default:
	case GSM_PCHAN_CCCH:
		if (lchan_nr != 0)
			return -EINVAL;
		cbits = ABIS_RSL_CHAN_NR_CBITS_BCCH;
		break;
	}

	chan_nr = (cbits << 3) | (ts_nr & 0x7);

	return chan_nr;
}

/* For RSL, to talk to osmo-bts, we introduce Osmocom specific channel number cbits to indicate VAMOS secondary lchans.
 * However, in RR, which is sent to the MS, these special cbits must not be sent, but their "normal" equivalent; for RR
 * messages, pass allow_osmo_cbits = false. */
int gsm_lchan_and_pchan2chan_nr(const struct gsm_lchan *lchan, enum gsm_phys_chan_config pchan, bool allow_osmo_cbits)
{
	int rc;
	uint8_t lchan_nr = lchan->nr;

	/* Take care that we never send Osmocom specific cbits to non-Osmo BTS. */
	if (allow_osmo_cbits && lchan->vamos.is_secondary
	    && lchan->ts->trx->bts->model->type != GSM_BTS_TYPE_OSMOBTS) {
		LOG_LCHAN(lchan, LOGL_ERROR, "Cannot address VAMOS shadow lchan on this BTS type: %s\n",
			  get_value_string(bts_type_names, lchan->ts->trx->bts->model->type));
		return -ENOTSUP;
	}
	if (allow_osmo_cbits && lchan->ts->trx->bts->model->type != GSM_BTS_TYPE_OSMOBTS)
		allow_osmo_cbits = false;

	/* The VAMOS lchans are behind the primary ones in the ts->lchan[] array. They keep their lchan->nr as in the
	 * array, but on the wire they are the "shadow" lchans for the primary lchans. For example, for TCH/F, there is
	 * a primary ts->lchan[0] and a VAMOS ts->lchan[1]. Still, the VAMOS lchan should send chan_nr = 0. */
	if (lchan->vamos.is_secondary)
		lchan_nr -= lchan->ts->max_primary_lchans;
	rc = gsm_pchan2chan_nr(pchan, lchan->ts->nr, lchan_nr,
			       allow_osmo_cbits ? lchan->vamos.is_secondary : false);
	/* Log an error so that we don't need to add logging to each caller of this function */
	if (rc < 0)
		LOG_LCHAN(lchan, LOGL_ERROR,
			  "Error encoding Channel Number: pchan %s ts %u ss %u%s\n",
			  gsm_pchan_name(lchan->ts->pchan_from_config), lchan->ts->nr, lchan_nr,
			  lchan->vamos.is_secondary ? " (VAMOS shadow)" : "");
	return rc;
}

int gsm_lchan2chan_nr(const struct gsm_lchan *lchan, bool allow_osmo_cbits)
{
	return gsm_lchan_and_pchan2chan_nr(lchan, lchan->ts->pchan_is, allow_osmo_cbits);
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
	[GSM_PCHAN_OSMO_DYN] = 8,
	[GSM_PCHAN_TCH_F_PDCH] = 1,
};

/*! Return the maximum number of logical channels that may be used in a timeslot of the given physical channel
 * configuration. */
uint8_t pchan_subslots(enum gsm_phys_chan_config pchan)
{
	if (pchan < 0 || pchan >= ARRAY_SIZE(subslots_per_pchan))
		return 0;
	return subslots_per_pchan[pchan];
}

static const uint8_t subslots_per_pchan_vamos[] = {
	[GSM_PCHAN_NONE] = 0,
	[GSM_PCHAN_CCCH] = 0,
	[GSM_PCHAN_PDCH] = 0,
	[GSM_PCHAN_CCCH_SDCCH4] = 0,
	/* VAMOS: on a TCH/F, there may be a TCH/H shadow */
	[GSM_PCHAN_TCH_F] = 2,
	[GSM_PCHAN_TCH_H] = 2,
	[GSM_PCHAN_SDCCH8_SACCH8C] = 0,
	[GSM_PCHAN_CCCH_SDCCH4_CBCH] = 0,
	[GSM_PCHAN_SDCCH8_SACCH8C_CBCH] = 0,
	[GSM_PCHAN_OSMO_DYN] = 0,
	[GSM_PCHAN_TCH_F_PDCH] = 2,
};

/* Return the maximum number of VAMOS secondary lchans that may be used in a timeslot of the given physical channel
 * configuration. */
uint8_t pchan_subslots_vamos(enum gsm_phys_chan_config pchan)
{
	if (pchan < 0 || pchan >= ARRAY_SIZE(subslots_per_pchan_vamos))
		return 0;
	return subslots_per_pchan_vamos[pchan];
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

static void _chan_desc_fill_tail(struct gsm48_chan_desc *cd, const struct gsm_lchan *lchan,
				 uint8_t tsc)
{
	if (!lchan->ts->hopping.enabled) {
		uint16_t arfcn = lchan->ts->trx->arfcn & 0x3ff;
		cd->h0.tsc = tsc;
		cd->h0.h = 0;
		cd->h0.spare = 0;
		cd->h0.arfcn_high = arfcn >> 8;
		cd->h0.arfcn_low = arfcn & 0xff;
	} else {
		cd->h1.tsc = tsc;
		cd->h1.h = 1;
		cd->h1.maio_high = lchan->ts->hopping.maio >> 2;
		cd->h1.maio_low = lchan->ts->hopping.maio & 0x03;
		cd->h1.hsn = lchan->ts->hopping.hsn;
	}
}

int gsm48_lchan_and_pchan2chan_desc(struct gsm48_chan_desc *cd,
				    const struct gsm_lchan *lchan,
				    enum gsm_phys_chan_config pchan,
				    uint8_t tsc, bool allow_osmo_cbits)
{
	int chan_nr = gsm_lchan_and_pchan2chan_nr(lchan, pchan, allow_osmo_cbits);
	if (chan_nr < 0) {
		/* Log an error so that we don't need to add logging to each caller of this function */
		LOG_LCHAN(lchan, LOGL_ERROR,
			  "Error encoding Channel Number: pchan %s ts %u ss %u%s (rc = %d)\n",
			  gsm_pchan_name(pchan), lchan->ts->nr, lchan->nr,
			  lchan->vamos.is_secondary ? " (VAMOS shadow)" : "", chan_nr);
		return chan_nr;
	}
	cd->chan_nr = chan_nr;
	_chan_desc_fill_tail(cd, lchan, tsc);
	return 0;
}

int gsm48_lchan2chan_desc(struct gsm48_chan_desc *cd,
			  const struct gsm_lchan *lchan,
			  uint8_t tsc, bool allow_osmo_cbits)
{
	return gsm48_lchan_and_pchan2chan_desc(cd, lchan, lchan->ts->pchan_is, tsc, allow_osmo_cbits);
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
	if (s->availability != NM_AVSTATE_OK)
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
	case GSM_LCHAN_SDCCH:
		return GSM_PCHAN_SDCCH8_SACCH8C;
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

enum channel_rate chan_t_to_chan_rate(enum gsm_chan_t chan_t)
{
	switch (chan_t) {
	case GSM_LCHAN_SDCCH:
		return CH_RATE_SDCCH;
	case GSM_LCHAN_TCH_F:
		return CH_RATE_FULL;
	case GSM_LCHAN_TCH_H:
		return CH_RATE_HALF;
	default:
		/* For other channel types, the channel_rate value is never used. It is fine to return an invalid value,
		 * and callers don't actually need to check for this. */
		return -1;
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

	case GSM_PCHAN_OSMO_DYN:
		switch (pchan) {
		case GSM_PCHAN_TCH_F:
		case GSM_PCHAN_TCH_H:
		case GSM_PCHAN_PDCH:
		case GSM_PCHAN_SDCCH8_SACCH8C:
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

	case GSM_PCHAN_OSMO_DYN:
		switch (type) {
		case GSM_LCHAN_TCH_F:
		case GSM_LCHAN_TCH_H:
		case GSM_LCHAN_PDTCH:
		case GSM_LCHAN_SDCCH:
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
	if (!trx_is_usable(ts->trx))
		return false;

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

const struct value_string lchan_activate_mode_names[] = {
	OSMO_VALUE_STRING(ACTIVATE_FOR_NONE),
	OSMO_VALUE_STRING(ACTIVATE_FOR_MS_CHANNEL_REQUEST),
	OSMO_VALUE_STRING(ACTIVATE_FOR_ASSIGNMENT),
	OSMO_VALUE_STRING(ACTIVATE_FOR_HANDOVER),
	OSMO_VALUE_STRING(ACTIVATE_FOR_VGCS_CHANNEL),
	OSMO_VALUE_STRING(ACTIVATE_FOR_VTY),
	{}
};

const struct value_string lchan_modify_for_names[] = {
	OSMO_VALUE_STRING(MODIFY_FOR_NONE),
	OSMO_VALUE_STRING(MODIFY_FOR_ASSIGNMENT),
	OSMO_VALUE_STRING(MODIFY_FOR_VTY),
	{}
};

const struct value_string assign_for_names[] = {
	OSMO_VALUE_STRING(ASSIGN_FOR_NONE),
	OSMO_VALUE_STRING(ASSIGN_FOR_BSSMAP_REQ),
	OSMO_VALUE_STRING(ASSIGN_FOR_CONGESTION_RESOLUTION),
	OSMO_VALUE_STRING(ASSIGN_FOR_VTY),
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

/* Default Interference Measurement Parameters */
const struct gsm_interf_meas_params interf_meas_params_def = {
	.avg_period = 6, /* 6 SACCH periods */
	.bounds_dbm = {
		115, /*  0: -115 dBm */
		109, /* X1: -109 dBm */
		103, /* X2: -103 dBm */
		 97, /* X3:  -97 dBm */
		 91, /* X4:  -91 dBm */
		 85, /* X5:  -85 dBm */
	},
};

enum rsl_cmod_spd chan_mode_to_rsl_cmod_spd(enum gsm48_chan_mode chan_mode)
{
	switch (gsm48_chan_mode_to_non_vamos(chan_mode)) {
	case GSM48_CMODE_SIGN:
		return RSL_CMOD_SPD_SIGN;
	case GSM48_CMODE_SPEECH_V1:
	case GSM48_CMODE_SPEECH_EFR:
	case GSM48_CMODE_SPEECH_AMR:
		return RSL_CMOD_SPD_SPEECH;
	case GSM48_CMODE_DATA_14k5:
	case GSM48_CMODE_DATA_12k0:
	case GSM48_CMODE_DATA_6k0:
	case GSM48_CMODE_DATA_3k6:
		return RSL_CMOD_SPD_DATA;
	default:
		return -EINVAL;
	}
}

int gsm_audio_support_cmp(const struct gsm_audio_support *a, const struct gsm_audio_support *b)
{
	int rc;
	if (a == b)
		return 0;
	if (!a)
		return -1;
	if (!b)
		return 1;
	rc = OSMO_CMP(a->hr, b->hr);
	if (rc)
		return rc;
	return OSMO_CMP(a->ver, b->ver);
}
