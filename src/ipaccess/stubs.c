/* Stubs required for linking */

/* (C) 2018 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
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

#include <stdbool.h>
struct gsm_bts;
struct gsm_bts_trx_ts;
struct msgb;
struct bsc_msc_data;

bool on_gsm_ts_init(struct gsm_bts_trx_ts *ts)
{
	/* No TS init required here. */
	return true;
}

int abis_rsl_rcvmsg(struct msgb *msg)
{
	/* No RSL handling here */
	return 0;
}

void paging_flush_bts(struct gsm_bts *bts, struct bsc_msc_data *msc)
{
	/* No paging flushing */
}
