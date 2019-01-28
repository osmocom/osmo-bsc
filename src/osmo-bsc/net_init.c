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

#include <osmocom/bsc/osmo_bsc.h>
#include <osmocom/bsc/gsm_04_08_rr.h>
#include <osmocom/bsc/handover_cfg.h>
#include <osmocom/bsc/chan_alloc.h>
#include <osmocom/bsc/neighbor_ident.h>

static struct osmo_tdef gsm_network_T_defs[] = {
	{ .T=7, .default_val=10, .desc="inter-BSC Handover MO, HO Required to HO Command" },
	{ .T=8, .default_val=10, .desc="inter-BSC Handover MO, HO Command to final Clear" },
	{ .T=10, .default_val=6, .desc="RR Assignment" },
	{ .T=101, .default_val=10, .desc="inter-BSC Handover MT, HO Request to HO Accept" },
	{ .T=3101, .default_val=3, .desc="RR Immediate Assignment" },
	{ .T=3103, .default_val=5, .desc="Handover" },
	{ .T=3105, .default_val=100, .unit=OSMO_TDEF_MS, .desc="Physical Information" },
	{ .T=3107, .default_val=5, .desc="(unused)" },
	{ .T=3109, .default_val=5, .desc="RSL SACCH deactivation" },
	{ .T=3111, .default_val=2, .desc="Wait time before RSL RF Channel Release" },
	{ .T=993111, .default_val=4, .desc="Wait time after lchan was released in error (should be T3111 + 2s)" },
	{ .T=3113, .default_val=7, .desc="Paging"},
	{ .T=3115, .default_val=10, .desc="(unused)" },
	{ .T=3117, .default_val=10, .desc="(unused)" },
	{ .T=3119, .default_val=10, .desc="(unused)" },
	{ .T=3122, .default_val=GSM_T3122_DEFAULT, .desc="Wait time after RR Immediate Assignment Reject" },
	{ .T=3141, .default_val=10, .desc="(unused)" },
	{ .T=3212, .default_val=5, .unit=OSMO_TDEF_CUSTOM,
		.desc="Periodic Location Update timer, sent to MS (1 = 6 minutes)" },
	{ .T=993210, .default_val=20, .desc="After L3 Complete, wait for MSC to confirm" },
	{ .T=999, .default_val=60, .desc="After Clear Request, wait for MSC to Clear Command (sanity)" },
	{ .T=992427, .default_val=4, .desc="MGCP timeout (2427 is the default MGCP port number)" },
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

	net->bsc_subscribers = talloc_zero(net, struct llist_head);
	INIT_LLIST_HEAD(net->bsc_subscribers);

	INIT_LLIST_HEAD(&net->bts_list);
	net->num_bts = 0;

	net->T_defs = gsm_network_T_defs;
	osmo_tdefs_reset(net->T_defs);

	return net;
}
