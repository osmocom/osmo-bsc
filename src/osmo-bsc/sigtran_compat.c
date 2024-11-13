/* (C) 2024 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
#include "../../bscconfig.h"

#include <osmocom/bsc/sigtran_compat.h>

#ifndef SIGTRAN_PRIVATE_STRUCTS

static struct osmo_ss7_asp *ss7_as_select_asp_override(struct osmo_ss7_as *as)
{
	struct osmo_ss7_asp *asp;
	unsigned int i;

	/* FIXME: proper selection of the ASP based on the SLS! */
	for (i = 0; i < ARRAY_SIZE(as->cfg.asps); i++) {
		asp = as->cfg.asps[i];
		if (asp && osmo_ss7_asp_active(asp))
			break;
	}
	return asp;
}

static struct osmo_ss7_asp *ss7_as_select_asp_roundrobin(struct osmo_ss7_as *as)
{
	struct osmo_ss7_asp *asp;
	unsigned int i;
	unsigned int first_idx;

	first_idx = (as->cfg.last_asp_idx_sent + 1) % ARRAY_SIZE(as->cfg.asps);
	i = first_idx;
	do {
		asp = as->cfg.asps[i];
		if (asp && osmo_ss7_asp_active(asp))
			break;
		i = (i + 1) % ARRAY_SIZE(as->cfg.asps);
	} while (i != first_idx);
	as->cfg.last_asp_idx_sent = i;

	return asp;
}

/* returns NULL if multiple ASPs would need to be selected. */
static struct osmo_ss7_asp *ss7_as_select_asp_broadcast(struct osmo_ss7_as *as)
{
	struct osmo_ss7_asp *asp;
	struct osmo_ss7_asp *asp_found = NULL;

	for (unsigned int i = 0; i < ARRAY_SIZE(as->cfg.asps); i++) {
		asp = as->cfg.asps[i];
		if (!asp || !osmo_ss7_asp_active(asp))
			continue;
		if (asp_found) /* >1 ASPs selected, early return */
			return NULL;
		asp_found = asp;
	}
	return asp_found;
}

struct osmo_ss7_asp *osmo_ss7_as_select_asp(struct osmo_ss7_as *as)
{
	struct osmo_ss7_asp *asp = NULL;

	switch (as->cfg.mode) {
	case OSMO_SS7_AS_TMOD_OVERRIDE:
		asp = ss7_as_select_asp_override(as);
		break;
	case OSMO_SS7_AS_TMOD_LOADSHARE:
		/* TODO: actually use the SLS value to ensure same SLS goes
		 * through same ASP. Not strictly required by M3UA RFC, but
		 * would fit the overall principle. */
	case OSMO_SS7_AS_TMOD_ROUNDROBIN:
		asp = ss7_as_select_asp_roundrobin(as);
		break;
	case OSMO_SS7_AS_TMOD_BCAST:
		return ss7_as_select_asp_broadcast(as);
	case _NUM_OSMO_SS7_ASP_TMOD:
		OSMO_ASSERT(false);
	}

	if (!asp) {
		LOGPFSM(as->fi, "No selectable ASP in AS\n");
		return NULL;
	}
	return asp;
}

#endif
