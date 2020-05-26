/* A hackish minimal BSC (+MSC +HLR) implementation */

/* (C) 2008-2018 by Harald Welte <laforge@gnumonks.org>
 * (C) 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
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

#include <osmocom/bsc/gsm_data.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/bsc/abis_rsl.h>
#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/misdn.h>
#include <osmocom/bsc/system_information.h>
#include <osmocom/bsc/paging.h>
#include <osmocom/bsc/signal.h>
#include <osmocom/bsc/chan_alloc.h>
#include <osmocom/core/talloc.h>
#include <osmocom/bsc/ipaccess.h>
#include <osmocom/gsm/sysinfo.h>
#include <osmocom/bsc/pcu_if.h>
#include <osmocom/bsc/bsc_msc_data.h>
#include <osmocom/bsc/handover_cfg.h>
#include <osmocom/bsc/gsm_04_08_rr.h>
#include <osmocom/bsc/neighbor_ident.h>

#include <osmocom/bsc/smscb.h>
#include <osmocom/gsm/protocol/gsm_48_049.h>

#include <time.h>
#include <limits.h>
#include <stdbool.h>

static const struct osmo_stat_item_desc bsc_stat_desc[] = {
	{ "num_bts:total", "Number of configured BTS for this BSC", "", 16, 0 },
};

static const struct osmo_stat_item_group_desc bsc_statg_desc = {
	.group_name_prefix = "bsc",
	.group_description = "base station controller",
	.class_id = OSMO_STATS_CLASS_GLOBAL,
	.num_items = ARRAY_SIZE(bsc_stat_desc),
	.item_desc = bsc_stat_desc,
};

int bsc_shutdown_net(struct gsm_network *net)
{
	struct gsm_bts *bts;

	llist_for_each_entry(bts, &net->bts_list, list) {
		LOGP(DNM, LOGL_NOTICE, "shutting down OML for BTS %u\n", bts->nr);
		osmo_signal_dispatch(SS_L_GLOBAL, S_GLOBAL_BTS_CLOSE_OM, bts);
	}

	return 0;
}

unsigned long long bts_uptime(const struct gsm_bts *bts)
{
	struct timespec tp;

	if (!bts->uptime || !bts->oml_link) {
		LOGP(DNM, LOGL_ERROR, "BTS %u OML link uptime unavailable\n", bts->nr);
		return 0;
	}

	if (clock_gettime(CLOCK_MONOTONIC, &tp) != 0) {
		LOGP(DNM, LOGL_ERROR, "BTS %u uptime computation failure: %s\n", bts->nr, strerror(errno));
		return 0;
	}

	/* monotonic clock helps to ensure that the conversion is valid */
	return difftime(tp.tv_sec, bts->uptime);
}

static int rsl_si(struct gsm_bts_trx *trx, enum osmo_sysinfo_type i, int si_len)
{
	struct gsm_bts *bts = trx->bts;
	int rc, j;

	if (si_len) {
		DEBUGP(DRR, "SI%s: %s\n", get_value_string(osmo_sitype_strs, i),
			osmo_hexdump(GSM_BTS_SI(bts, i), GSM_MACBLOCK_LEN));
	} else
		DEBUGP(DRR, "SI%s: OFF\n", get_value_string(osmo_sitype_strs, i));

	switch (i) {
	case SYSINFO_TYPE_5:
	case SYSINFO_TYPE_5bis:
	case SYSINFO_TYPE_5ter:
	case SYSINFO_TYPE_6:
		rc = rsl_sacch_filling(trx, osmo_sitype2rsl(i),
				       si_len ? GSM_BTS_SI(bts, i) : NULL, si_len);
		break;
	case SYSINFO_TYPE_2quater:
		if (si_len == 0) {
			rc = rsl_bcch_info(trx, i, NULL, 0);
			break;
		}
		rc = 0;
		for (j = 0; j <= bts->si2q_count; j++)
			rc = rsl_bcch_info(trx, i, (const uint8_t *)GSM_BTS_SI2Q(bts, j), GSM_MACBLOCK_LEN);
		break;
	default:
		rc = rsl_bcch_info(trx, i, si_len ? GSM_BTS_SI(bts, i) : NULL, si_len);
		break;
	}

	return rc;
}

/* set all system information types for a TRX */
int gsm_bts_trx_set_system_infos(struct gsm_bts_trx *trx)
{
	int i, rc;
	struct gsm_bts *bts = trx->bts;
	uint8_t gen_si[_MAX_SYSINFO_TYPE], n_si = 0, n;
	int si_len[_MAX_SYSINFO_TYPE];

	bts->si_common.cell_sel_par.ms_txpwr_max_ccch =
			ms_pwr_ctl_lvl(bts->band, bts->ms_max_power);
	bts->si_common.cell_sel_par.neci = bts->network->neci;

	/* Zero/forget the state of the dynamically computed SIs, leeping the static ones */
	bts->si_valid = bts->si_mode_static;

	/* First, we determine which of the SI messages we actually need */

	if (trx == bts->c0) {
		/* 1...4 are always present on a C0 TRX */
		gen_si[n_si++] = SYSINFO_TYPE_1;
		gen_si[n_si++] = SYSINFO_TYPE_2;
		gen_si[n_si++] = SYSINFO_TYPE_2bis;
		gen_si[n_si++] = SYSINFO_TYPE_2ter;
		gen_si[n_si++] = SYSINFO_TYPE_2quater;
		gen_si[n_si++] = SYSINFO_TYPE_3;
		gen_si[n_si++] = SYSINFO_TYPE_4;

		/* 13 is always present on a C0 TRX of a GPRS BTS */
		if (bts->gprs.mode != BTS_GPRS_NONE)
			gen_si[n_si++] = SYSINFO_TYPE_13;
	}

	/* 5 and 6 are always present on every TRX */
	gen_si[n_si++] = SYSINFO_TYPE_5;
	gen_si[n_si++] = SYSINFO_TYPE_5bis;
	gen_si[n_si++] = SYSINFO_TYPE_5ter;
	gen_si[n_si++] = SYSINFO_TYPE_6;

	/* Second, we generate the selected SI via RSL */

	for (n = 0; n < n_si; n++) {
		i = gen_si[n];
		/* Only generate SI if this SI is not in "static" (user-defined) mode */
		if (!(bts->si_mode_static & (1 << i))) {
			/* Set SI as being valid. gsm_generate_si() might unset
			 * it, if SI is not required. */
			bts->si_valid |= (1 << i);
			rc = gsm_generate_si(bts, i);
			if (rc < 0)
				goto err_out;
			si_len[i] = rc;
		} else {
			if (i == SYSINFO_TYPE_5 || i == SYSINFO_TYPE_5bis
			 || i == SYSINFO_TYPE_5ter)
				si_len[i] = 18;
			else if (i == SYSINFO_TYPE_6)
				si_len[i] = 11;
			else
				si_len[i] = 23;
		}
	}

	/* Third, we send the selected SI via RSL */

	for (n = 0; n < n_si; n++) {
		i = gen_si[n];
		/* 3GPP TS 08.58 §8.5.1 BCCH INFORMATION. If we don't currently
		 * have this SI, we send a zero-length RSL BCCH FILLING /
		 * SACCH FILLING in order to deactivate the SI, in case it
		 * might have previously been active */
		if (!GSM_BTS_HAS_SI(bts, i)) {
			if (bts->si_unused_send_empty)
				rc = rsl_si(trx, i, 0);
			else
				rc = 0; /* some nanoBTS fw don't like receiving empty unsupported SI */
		} else
			rc = rsl_si(trx, i, si_len[i]);
		if (rc < 0)
			return rc;
	}

	/* Make sure the PCU is aware (in case anything GPRS related has
	 * changed in SI */
	pcu_info_update(bts);

	return 0;
err_out:
	LOGP(DRR, LOGL_ERROR, "Cannot generate SI%s for BTS %u: error <%s>, "
	     "most likely a problem with neighbor cell list generation\n",
	     get_value_string(osmo_sitype_strs, i), bts->nr, strerror(-rc));
	return rc;
}

/* set all system information types for a BTS */
int gsm_bts_set_system_infos(struct gsm_bts *bts)
{
	struct gsm_bts_trx *trx;

	/* Generate a new ID */
	bts->bcch_change_mark += 1;
	bts->bcch_change_mark %= 0x7;

	llist_for_each_entry(trx, &bts->trx_list, list) {
		int rc;

		rc = gsm_bts_trx_set_system_infos(trx);
		if (rc != 0)
			return rc;
	}

	return 0;
}

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

static struct gsm_network *bsc_network_init(void *ctx)
{
	struct gsm_network *net = gsm_network_init(ctx);

	net->cbc = talloc_zero(net, struct bsc_cbc_link);
	if (!net->cbc) {
		talloc_free(net);
		return NULL;
	}

	/* Init back pointer */
	net->auto_off_timeout = -1;
	INIT_LLIST_HEAD(&net->mscs);

	net->ho = ho_cfg_init(net, NULL);
	net->hodec2.congestion_check_interval_s = HO_CFG_CONGESTION_CHECK_DEFAULT;
	net->neighbor_bss_cells = neighbor_ident_init(net);

	/* init statistics */
	net->bsc_ctrs = rate_ctr_group_alloc(net, &bsc_ctrg_desc, 0);
	if (!net->bsc_ctrs) {
		talloc_free(net);
		return NULL;
	}
	net->bsc_statg = osmo_stat_item_group_alloc(net, &bsc_statg_desc, 0);
	if (!net->bsc_statg) {
		rate_ctr_group_free(net->bsc_ctrs);
		talloc_free(net);
		return NULL;
	}

	INIT_LLIST_HEAD(&net->bts_rejected);
	gsm_net_update_ctype(net);

	/*
	 * At present all BTS in the network share one channel load timeout.
	 * If this becomes a problem for networks with a lot of BTS, this
	 * code could be refactored to run the timeout individually per BTS.
	 */
	osmo_timer_setup(&net->t3122_chan_load_timer, update_t3122_chan_load_timer, net);
	osmo_timer_schedule(&net->t3122_chan_load_timer, T3122_CHAN_LOAD_SAMPLE_INTERVAL, 0);

	net->cbc->net = net;
	/* no cbc_hostname: client not started by default */
	net->cbc->config.cbc_port = CBSP_TCP_PORT;
	/* listen_port == -1: server not started by default */
	net->cbc->config.listen_port = -1;
	net->cbc->config.listen_hostname = talloc_strdup(net->cbc, "127.0.0.1");

	return net;
}

int bsc_network_alloc(void)
{
	/* initialize our data structures */
	bsc_gsmnet = bsc_network_init(tall_bsc_ctx);
	if (!bsc_gsmnet)
		return -ENOMEM;

	return 0;
}

struct gsm_bts *bsc_bts_alloc_register(struct gsm_network *net, enum gsm_bts_type type, uint8_t bsic)
{
	struct gsm_bts *bts = gsm_bts_alloc_register(net, type, bsic);

	bts->ho = ho_cfg_init(bts, net->ho);

	return bts;
}
