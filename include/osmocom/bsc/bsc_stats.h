/* osmo-bsc statistics */
/* (C) 2021 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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

#include <osmocom/core/rate_ctr.h>

struct osmo_stat_item_group_desc;

/* OsmoBSC rate_ctr indexes */
enum {
	BSC_CTR_ASSIGNMENT_ATTEMPTED,
	BSC_CTR_ASSIGNMENT_COMPLETED,
	BSC_CTR_ASSIGNMENT_STOPPED,
	BSC_CTR_ASSIGNMENT_NO_CHANNEL,
	BSC_CTR_ASSIGNMENT_TIMEOUT,
	BSC_CTR_ASSIGNMENT_FAILED,
	BSC_CTR_ASSIGNMENT_ERROR,
	BSC_CTR_HANDOVER_ATTEMPTED,
	BSC_CTR_HANDOVER_COMPLETED,
	BSC_CTR_HANDOVER_STOPPED,
	BSC_CTR_HANDOVER_NO_CHANNEL,
	BSC_CTR_HANDOVER_TIMEOUT,
	BSC_CTR_HANDOVER_FAILED,
	BSC_CTR_HANDOVER_ERROR,
	BSC_CTR_INTRA_CELL_HO_ATTEMPTED,
	BSC_CTR_INTRA_CELL_HO_COMPLETED,
	BSC_CTR_INTRA_CELL_HO_STOPPED,
	BSC_CTR_INTRA_CELL_HO_NO_CHANNEL,
	BSC_CTR_INTRA_CELL_HO_TIMEOUT,
	BSC_CTR_INTRA_CELL_HO_FAILED,
	BSC_CTR_INTRA_CELL_HO_ERROR,
	BSC_CTR_INTRA_BSC_HO_ATTEMPTED,
	BSC_CTR_INTRA_BSC_HO_COMPLETED,
	BSC_CTR_INTRA_BSC_HO_STOPPED,
	BSC_CTR_INTRA_BSC_HO_NO_CHANNEL,
	BSC_CTR_INTRA_BSC_HO_TIMEOUT,
	BSC_CTR_INTRA_BSC_HO_FAILED,
	BSC_CTR_INTRA_BSC_HO_ERROR,
	BSC_CTR_INTER_BSC_HO_OUT_ATTEMPTED,
	BSC_CTR_INTER_BSC_HO_OUT_COMPLETED,
	BSC_CTR_INTER_BSC_HO_OUT_STOPPED,
	BSC_CTR_INTER_BSC_HO_OUT_TIMEOUT,
	BSC_CTR_INTER_BSC_HO_OUT_FAILED,
	BSC_CTR_INTER_BSC_HO_OUT_ERROR,
	BSC_CTR_INTER_BSC_HO_IN_ATTEMPTED,
	BSC_CTR_INTER_BSC_HO_IN_COMPLETED,
	BSC_CTR_INTER_BSC_HO_IN_STOPPED,
	BSC_CTR_INTER_BSC_HO_IN_NO_CHANNEL,
	BSC_CTR_INTER_BSC_HO_IN_FAILED,
	BSC_CTR_INTER_BSC_HO_IN_TIMEOUT,
	BSC_CTR_INTER_BSC_HO_IN_ERROR,
	BSC_CTR_SRVCC_ATTEMPTED,
	BSC_CTR_SRVCC_COMPLETED,
	BSC_CTR_SRVCC_STOPPED,
	BSC_CTR_SRVCC_NO_CHANNEL,
	BSC_CTR_SRVCC_TIMEOUT,
	BSC_CTR_SRVCC_FAILED,
	BSC_CTR_SRVCC_ERROR,
	BSC_CTR_PAGING_ATTEMPTED,
	BSC_CTR_PAGING_DETACHED,
	BSC_CTR_PAGING_RESPONDED,
	BSC_CTR_PAGING_NO_ACTIVE_PAGING,
	BSC_CTR_UNKNOWN_UNIT_ID,
	BSC_CTR_MSCPOOL_SUBSCR_NO_MSC,
	BSC_CTR_MSCPOOL_EMERG_FORWARDED,
	BSC_CTR_MSCPOOL_EMERG_LOST,
};

extern const struct rate_ctr_desc bsc_ctr_description[];
extern const struct rate_ctr_group_desc bsc_ctrg_desc;

/* OsmoBSC stat_item indexes */
enum {
	BSC_STAT_NUM_BTS_TOTAL,
	BSC_STAT_NUM_MSC_CONNECTED,
	BSC_STAT_NUM_MSC_TOTAL,
};

/* BTS counter index if a BTS could not be found
 * Currently we are limited to bts 0 - 255 in the VTY, but that might change in
 * the future so use 2**16 */
#define BTS_STAT_IDX_UNKNOWN (UINT16_MAX + 1)

extern const struct osmo_stat_item_group_desc bsc_statg_desc;
