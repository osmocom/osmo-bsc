/* GSM Network Management messages on the A-bis interface
 * 3GPP TS 12.21 version 8.0.0 Release 1999 / ETSI TS 100 623 V8.0.0 */

/* (C) 2008-2009 by Harald Welte <laforge@gnumonks.org>
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

#pragma once

#include <stdint.h>

#include <osmocom/core/msgb.h>

#include <osmocom/gsm/protocol/gsm_04_08.h>

struct gsm_bts;

int abis_osmo_rcvmsg(struct msgb *msg);
int abis_osmo_sendmsg(struct gsm_bts *bts, struct msgb *msg);

int abis_osmo_pcu_tx_anr_req(struct gsm_bts *bts, const struct gsm48_cell_desc *cell_desc_li, unsigned int num_cells);
