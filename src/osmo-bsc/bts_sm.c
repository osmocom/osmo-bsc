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
#include <osmocom/bsc/bts_sm.h>
#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/nm_common_fsm.h>

static const uint8_t bts_nse_timer_default[] = { 3, 3, 3, 3, 30, 3, 10 };

static int gsm_bts_sm_talloc_destructor(struct gsm_bts_sm *bts_sm)
{
	if (bts_sm->gprs.nse.mo.fi) {
		osmo_fsm_inst_free(bts_sm->gprs.nse.mo.fi);
		bts_sm->gprs.nse.mo.fi = NULL;
	}

	if (bts_sm->mo.fi) {
		osmo_fsm_inst_free(bts_sm->mo.fi);
		bts_sm->mo.fi = NULL;
	}
	return 0;
}

struct gsm_bts_sm *gsm_bts_sm_alloc(struct gsm_network *net, uint8_t bts_num)
{
	struct gsm_bts_sm *bts_sm = talloc_zero(net, struct gsm_bts_sm);
	struct gsm_bts *bts;
	int i;
	if (!bts_sm)
		return NULL;

	talloc_set_destructor(bts_sm, gsm_bts_sm_talloc_destructor);
	bts_sm->mo.fi = osmo_fsm_inst_alloc(&nm_bts_sm_fsm, bts_sm, bts_sm,
					    LOGL_INFO, NULL);
	osmo_fsm_inst_update_id_f(bts_sm->mo.fi, "bts_sm");

	bts = gsm_bts_alloc(net, bts_sm, bts_num);
	if (!bts) {
		talloc_free(bts_sm);
		return NULL;
	}
	bts_sm->bts[0] = bts;

	gsm_mo_init(&bts_sm->mo, bts, NM_OC_SITE_MANAGER, 0xff, 0xff, 0xff);


	bts_sm->gprs.nse.mo.fi = osmo_fsm_inst_alloc(&nm_gprs_nse_fsm, bts_sm, &bts_sm->gprs.nse,
					      LOGL_INFO, NULL);
	osmo_fsm_inst_update_id_f(bts_sm->gprs.nse.mo.fi, "nse%d", bts_num);
	gsm_mo_init(&bts_sm->gprs.nse.mo, bts, NM_OC_GPRS_NSE, bts->nr, 0xff, 0xff);
	memcpy(&bts_sm->gprs.nse.timer, bts_nse_timer_default,
	       sizeof(bts_sm->gprs.nse.timer));

	for (i = 0; i < ARRAY_SIZE(bts_sm->gprs.nsvc); i++) {
		bts_sm->gprs.nsvc[i].bts = bts;
		bts_sm->gprs.nsvc[i].id = i;
		gsm_mo_init(&bts_sm->gprs.nsvc[i].mo, bts, NM_OC_GPRS_NSVC,
				bts->nr, i, 0xff);
	}
	memcpy(&bts_sm->gprs.nse.timer, bts_nse_timer_default,
		sizeof(bts_sm->gprs.nse.timer));
	gsm_mo_init(&bts_sm->gprs.nse.mo, bts, NM_OC_GPRS_NSE,
			bts->nr, 0xff, 0xff);

	return bts_sm;
}

void gsm_bts_sm_mo_reset(struct gsm_bts_sm *bts_sm)
{
	int i;
	gsm_abis_mo_reset(&bts_sm->mo);

	gsm_abis_mo_reset(&bts_sm->gprs.nse.mo);
	for (i = 0; i < ARRAY_SIZE(bts_sm->gprs.nsvc); i++)
		gsm_abis_mo_reset(&bts_sm->gprs.nsvc[i].mo);

	gsm_bts_mo_reset(bts_sm->bts[0]);
}
