/* OsmoBSC handover configuration implementation */
/* (C) 2017 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * (C) 2009-2010 by Harald Welte <laforge@gnumonks.org>
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr <nhofmeyr@sysmocom.de>
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
#include <talloc.h>

#include <osmocom/bsc/vty.h>
#include <osmocom/bsc/handover_cfg.h>
#include <osmocom/bsc/gsm_data.h>

struct handover_cfg {
	struct handover_cfg *higher_level_cfg;

#define HO_CFG_ONE_MEMBER(TYPE, NAME, DEFAULT_VAL, VTY0, VTY1, VTY2, VTY3, VTY4, VTY5, VTY6) \
	TYPE NAME; \
	bool has_##NAME;

	HO_CFG_ALL_MEMBERS
#undef HO_CFG_ONE_MEMBER
};

struct handover_cfg *ho_cfg_init(void *ctx, struct handover_cfg *higher_level_cfg)
{
	struct handover_cfg *ho = talloc_zero(ctx, struct handover_cfg);
	OSMO_ASSERT(ho);
	ho->higher_level_cfg = higher_level_cfg;
	return ho;
}

#define HO_CFG_ONE_MEMBER(TYPE, NAME, DEFAULT_VAL, VTY0, VTY1, VTY2, VTY_ARG_EVAL, VTY4, VTY5, VTY6) \
TYPE ho_get_##NAME(struct handover_cfg *ho) \
{ \
	if (ho->has_##NAME) \
		return ho->NAME; \
	if (ho->higher_level_cfg) \
		return ho_get_##NAME(ho->higher_level_cfg); \
	return VTY_ARG_EVAL(#DEFAULT_VAL); \
} \
\
void ho_set_##NAME(struct handover_cfg *ho, TYPE value) \
{ \
	ho->NAME = value; \
	ho->has_##NAME = true; \
} \
\
bool ho_isset_##NAME(struct handover_cfg *ho) \
{ \
	return ho->has_##NAME; \
} \
\
void ho_clear_##NAME(struct handover_cfg *ho) \
{ \
	ho->has_##NAME = false; \
} \
\
bool ho_isset_on_parent_##NAME(struct handover_cfg *ho) \
{ \
	return ho->higher_level_cfg \
		&& (ho_isset_##NAME(ho->higher_level_cfg) \
		    || ho_isset_on_parent_##NAME(ho->higher_level_cfg)); \
}

HO_CFG_ALL_MEMBERS
#undef HO_CFG_ONE_MEMBER
