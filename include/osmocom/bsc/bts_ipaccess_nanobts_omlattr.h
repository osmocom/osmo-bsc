/* OML attribute table generator for ipaccess nanobts */

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

#pragma once

#include <stdint.h>
#include <osmocom/core/msgb.h>

struct gsm_bts_sm;
struct gsm_bts;
struct gsm_bts_trx;

struct msgb *nanobts_gen_set_bts_attr(struct gsm_bts *bts);
struct msgb *nanobts_gen_set_nse_attr(struct gsm_bts_sm *bts_sm);
struct msgb *nanobts_gen_set_cell_attr(struct gsm_bts *bts);
struct msgb *nanobts_gen_set_nsvc_attr(struct gsm_bts *bts);
struct msgb *nanobts_gen_set_radio_attr(struct gsm_bts *bts,
				    struct gsm_bts_trx *trx);
