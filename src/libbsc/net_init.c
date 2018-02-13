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

#include <osmocom/bsc/common_cs.h>
#include <osmocom/bsc/osmo_bsc.h>
#include <osmocom/bsc/bsc_msc_data.h>
#include <osmocom/bsc/gsm_04_08_utils.h>
#include <osmocom/bsc/handover_cfg.h>
#include <osmocom/bsc/chan_alloc.h>

/* XXX hard-coded for now */
#define T3122_CHAN_LOAD_SAMPLE_INTERVAL 1 /* in seconds */

static void update_t3122_chan_load_timer(void *data)
{
	struct gsm_network *net = data;
	struct gsm_bts *bts;

	llist_for_each_entry(bts, &net->bts_list, list)
		bts_update_t3122_chan_load(bts);

	/* Keep this timer ticking. */
	osmo_timer_schedule(&net->t3122_chan_load_timer, T3122_CHAN_LOAD_SAMPLE_INTERVAL, 0);
}

struct gsm_network *bsc_network_init(void *ctx,
				     uint16_t country_code,
				     uint16_t network_code)
{
	struct gsm_network *net;

	net = talloc_zero(ctx, struct gsm_network);
	if (!net)
		return NULL;

	net->country_code = country_code;
	net->network_code = network_code;

	/* Use 30 min periodic update interval as sane default */
	net->t3212 = 5;

	INIT_LLIST_HEAD(&net->trans_list);
	INIT_LLIST_HEAD(&net->subscr_conns);

	net->bsc_subscribers = talloc_zero(net, struct llist_head);
	INIT_LLIST_HEAD(net->bsc_subscribers);

	net->bsc_data = talloc_zero(net, struct osmo_bsc_data);
	if (!net->bsc_data) {
		talloc_free(net);
		return NULL;
	}

	/* Init back pointer */
	net->bsc_data->auto_off_timeout = -1;
	net->bsc_data->network = net;
	INIT_LLIST_HEAD(&net->bsc_data->mscs);

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

	net->ho = ho_cfg_init(net, NULL);

	INIT_LLIST_HEAD(&net->bts_list);

	/*
	 * At present all BTS in the network share one channel load timeout.
	 * If this becomes a problem for networks with a lot of BTS, this
	 * code could be refactored to run the timeout individually per BTS.
	 */
	osmo_timer_setup(&net->t3122_chan_load_timer, update_t3122_chan_load_timer, net);
	osmo_timer_schedule(&net->t3122_chan_load_timer, T3122_CHAN_LOAD_SAMPLE_INTERVAL, 0);

	/* init statistics */
	net->bsc_ctrs = rate_ctr_group_alloc(net, &bsc_ctrg_desc, 0);
	if (!net->bsc_ctrs) {
		talloc_free(net);
		return NULL;
	}

	gsm_net_update_ctype(net);

	return net;
}

