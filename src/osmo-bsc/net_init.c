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

#include <osmocom/bsc/osmo_bsc.h>
#include <osmocom/bsc/bsc_msc_data.h>
#include <osmocom/bsc/gsm_04_08_utils.h>
#include <osmocom/bsc/handover_cfg.h>
#include <osmocom/bsc/chan_alloc.h>
#include <osmocom/bsc/neighbor_ident.h>

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

	/* Use 30 min periodic update interval as sane default */
	net->t3212 = 5;

	INIT_LLIST_HEAD(&net->subscr_conns);

	net->bsc_subscribers = talloc_zero(net, struct llist_head);
	INIT_LLIST_HEAD(net->bsc_subscribers);

	INIT_LLIST_HEAD(&net->bts_list);
	net->num_bts = 0;
	net->T3101 = GSM_T3101_DEFAULT;
	net->T3103 = GSM_T3103_DEFAULT;
	net->T3105 = GSM_T3105_DEFAULT;
	net->T3107 = GSM_T3107_DEFAULT;
	net->T3109 = GSM_T3109_DEFAULT;
	net->T3111 = GSM_T3111_DEFAULT;
	net->T3113 = GSM_T3113_DEFAULT;
	net->T3115 = GSM_T3115_DEFAULT;
	net->T3117 = GSM_T3117_DEFAULT;
	net->T3119 = GSM_T3119_DEFAULT;
	net->T3122 = GSM_T3122_DEFAULT;
	net->T3141 = GSM_T3141_DEFAULT;
	net->T10 = GSM_T10_DEFAULT;
	net->T7 = GSM_T7_DEFAULT;
	net->T8 = GSM_T8_DEFAULT;
	net->T101 = GSM_T101_DEFAULT;

	return net;
}
