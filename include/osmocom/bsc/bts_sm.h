/* BTS Site Manager */

/* (C) 2020 by sysmocom - s.m.f.c. GmbH <info@sysmocom.de>
 * Author: Pau Espin Pedrol <pespin@sysmocom.de>
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
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#pragma once

#include <unistd.h>
#include <stdint.h>

#include "osmocom/bsc/gsm_data.h"

struct gsm_bts;

struct gsm_gprs_nse {
	struct gsm_abis_mo mo;
	uint16_t nsei;
	uint8_t timer[7];
};

struct gsm_gprs_nsvc {
	struct gsm_bts *bts;
	/* data read via VTY config file, to configure the BTS
	 * via OML from BSC */
	int id;
	uint16_t nsvci;
	uint16_t local_port;	/* on the BTS */
	struct osmo_sockaddr remote;
	struct gsm_abis_mo mo;
};


/* BTS Site Manager */
struct gsm_bts_sm {
	struct gsm_bts *bts[1]; /* only one bts supported so far */
	struct gsm_abis_mo mo;
	/* nanoBTS and old versions of osmo-bts behaves this way due to
	   broken FSMs not following TS 12.21: they never do
	   Dependency->Offline transition, but they should be OPSTARTed
	   nevertheless during Dependnecy state to work. This field is
	   used by all dependent NM objects. */
	bool peer_has_no_avstate_offline;
	struct {
		struct gsm_gprs_nse nse;
		struct gsm_gprs_nsvc nsvc[2];
	} gprs;
};

static inline struct gsm_bts *gsm_bts_sm_get_bts(struct gsm_bts_sm *site_mgr) {
	return site_mgr->bts[0];
}

struct gsm_bts_sm *gsm_bts_sm_alloc(struct gsm_network *net, uint8_t bts_num);

void gsm_bts_sm_mo_reset(struct gsm_bts_sm *bts_sm);
