/* (C) 2008-2010 by Harald Welte <laforge@gnumonks.org>
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

#include <osmocom/core/tdef.h>
#include <osmocom/gsm/gsm23236.h>

#include <osmocom/bsc/osmo_bsc.h>
#include <osmocom/bsc/gsm_04_08_rr.h>
#include <osmocom/bsc/handover_cfg.h>
#include <osmocom/bsc/chan_alloc.h>
#include <osmocom/bsc/neighbor_ident.h>
#include <osmocom/bsc/bts_setup_ramp.h>
#include <osmocom/bsc/paging.h>

static struct osmo_tdef gsm_network_T_defs[] = {
	{ .T = 4, .default_val = 5, .desc = "Timeout to receive BSSMAP RESET ACKNOWLEDGE from the MSC" },
	{ .T = 7, .default_val = 10, .desc = "inter-BSC/MSC Handover outgoing, BSSMAP HO Required to HO Command timeout" },
	{ .T = 8, .default_val = 10, .desc = "inter-BSC/MSC Handover outgoing, BSSMAP HO Command to final Clear timeout" },
	{ .T = 10, .default_val = 6, .desc = "RR Assignment" },
	{ .T = 101, .default_val = 10, .desc = "inter-BSC/MSC Handover incoming, BSSMAP HO Request to HO Accept" },
	{ .T = 3101, .default_val = 3, .desc = "RR Immediate Assignment" },
	{ .T = 3103, .default_val = 5, .desc = "Handover" },
	{ .T = 3105, .default_val = GSM_T3105_DEFAULT, .min_val = 1, .unit = OSMO_TDEF_MS, .desc = "Physical Information" },
	{ .T = 3107, .default_val = 5, .desc = "(unused)" },
	{ .T = 3109, .default_val = 5, .desc = "RSL SACCH deactivation" },
	{ .T = 3111, .default_val = 2, .desc = "Wait time before RSL RF Channel Release" },
	{ .T = 3113, .default_val = 7, .desc = "Paging"},
	{ .T = 3115, .default_val = 10, .desc = "(unused)" },
	{ .T = 3117, .default_val = 10, .desc = "(unused)" },
	{ .T = 3119, .default_val = 10, .desc = "(unused)" },
	{ .T = 3122, .default_val = GSM_T3122_DEFAULT, .desc = "Wait time after RR Immediate Assignment Reject" },
	{ .T = 3141, .default_val = 10, .desc = "(unused)" },
	{ .T = 3212, .default_val = 5, .unit = OSMO_TDEF_CUSTOM,
		.desc = "Periodic Location Update timer, sent to MS (1 = 6 minutes)" },
	{ .T = -4, .default_val = 60, .desc = "After Clear Request, wait for MSC to Clear Command (sanity)" },
	{ .T = -5, .default_val = 5, .desc = "Timeout to switch dynamic timeslot PCHAN modes"},
	{ .T = -6, .default_val = 5, .desc = "Timeout for RSL Channel Activate ACK after sending RSL Channel Activate" },
	{ .T = -7, .default_val = 5, .desc = "Timeout for RSL IPA CRCX ACK after sending RSL IPA CRCX" },
	{ .T = -8, .default_val = 5, .desc = "Timeout for RSL IPA MDCX ACK after sending RSL IPA MDCX" },
	{ .T = -9, .default_val = 5, .desc = "Timeout for availability of MGW endpoint" },
	{ .T = -10, .default_val = 5, .desc = "Timeout for fully configured MGW endpoint" },
	{ .T = -11, .default_val = 5, .desc = "Timeout for Perform Location Response from SMLC" },
	{ .T = -12, .default_val = 5, .desc = "Timeout for obtaining TA after BSSLAP TA Request" },
	{ .T = -13, .default_val = 5, .desc = "Timeout for RR Channel Mode Modify ACK (BSC <-> MS)" },
	{ .T = -14, .default_val = 5, .desc = "Timeout for RSL Channel Mode Modify ACK (BSC <-> BTS)" },
	{ .T = -16, .default_val = 1000, .unit = OSMO_TDEF_MS,
		.desc = "Granularity for all_allocated:* rate counters: amount of milliseconds that one counter increment"
			" represents. See also X17, X18" },
	{ .T = -17, .default_val = 0, .unit = OSMO_TDEF_MS,
		.desc = "Rounding threshold for all_allocated:* rate counters: round up to the next counter increment"
			" after this many milliseconds. If set to half of X16 (or 0), employ the usual round() behavior:"
			" round up after half of a granularity period. If set to 1, behave like ceil(): already"
			" increment the counter immediately when all channels are allocated. If set >= X16, behave like"
			" floor(): only increment after a full X16 period of all channels being occupied."
			" See also X16, X18" },
	{ .T = -18, .default_val = 60000, .unit = OSMO_TDEF_MS,
		.desc = "Forget-sum period for all_allocated:* rate counters:"
			" after this amount of idle time, forget internally cumulated time remainders. Zero to always"
			" keep remainders. See also X16, X17." },
	{ .T = -25, .default_val = 5, .desc = "Timeout for initial user data after an MSC initiated an SCCP connection to the BSS" },
	{ .T = -28, .default_val = 30, .desc = "Interval at which to try to recover a BORKEN lchan" },
	{ .T = -3105, .default_val = GSM_NY1_DEFAULT, .unit = OSMO_TDEF_CUSTOM,
		.desc = "Ny1: Maximum number of Physical Information (re)transmissions" },
	{ .T = -3111, .default_val = 4, .desc = "Wait time after lchan was released in error (should be T3111 + 2s)" },
	{ .T = -3113, .default_val = PAGING_THRESHOLD_X3113_DEFAULT_SEC,
		.desc = "Maximum Paging Request Transmit Delay Threshold: " \
			"If the estimated transmit delay of the messages in the paging queue surpasses this threshold, then new incoming "
			"paging requests will if possible replace a request in retransmission state from the queue or otherwise be discarded, "
			"hence limiting the size of the queue and maximum delay of its scheduled requests. "
			"X3113 also serves as the upper boundary for dynamic T3113 when estimating the expected maximum delay to get a response" },
	{ .T = -3210, .default_val = 20, .desc = "After L3 Complete, wait for MSC to confirm" },
	{}
};

struct osmo_tdef g_mgw_tdefs[] = {
	{ .T = -2427, .default_val = 5, .desc = "timeout for MGCP response from MGW" },
	{}
};

struct osmo_tdef_group bsc_tdef_group[] = {
	{ .name = "net", .tdefs = gsm_network_T_defs, .desc = "GSM network" },
	{ .name = "mgw", .tdefs = g_mgw_tdefs, .desc = "MGW (Media Gateway) interface" },
	{}
};

/* Initialize the bare minimum of struct gsm_network, minimizing required dependencies.
 * This part is shared among the thin programs in osmo-bsc/src/utils/.
 * osmo-bsc requires further initialization that pulls in more dependencies (see bsc_network_init()). */
struct gsm_network *gsm_network_init(void *ctx)
{
	struct gsm_network *net = talloc_zero(ctx, struct gsm_network);
	if (!net)
		return NULL;

	net->plmn = (struct osmo_plmn_id){
		.mcc = 1,
		.mnc = 1,
	};

	net->dyn_ts_allow_tch_f = true;

	/* Permit a compile-time default of A5/3 and A5/1 */
	net->a5_encryption_mask = (1 << 3) | (1 << 1);

	INIT_LLIST_HEAD(&net->subscr_conns);

	net->bsc_subscribers = bsc_subscr_store_alloc(net);

	INIT_LLIST_HEAD(&net->bts_list);
	net->num_bts = 0;

	net->T_defs = gsm_network_T_defs;
	osmo_tdefs_reset(net->T_defs);

	net->mgw.tdefs = g_mgw_tdefs;
	osmo_tdefs_reset(net->mgw.tdefs);

	net->null_nri_ranges = osmo_nri_ranges_alloc(net);
	net->nri_bitlen = OSMO_NRI_BITLEN_DEFAULT;

	bts_setup_ramp_init_network(net);

	return net;
}
