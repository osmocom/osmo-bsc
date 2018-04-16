/* (C) 2008-2009 by Harald Welte <laforge@gnumonks.org>
 * (C) 2009-2011 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009-2011 by On-Waves
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
 * along with this program.  If not, see <http://www.gnu.org/lienses/>.
 *
 */

#include <osmocom/bsc/bss.h>
#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/osmo_bsc.h>
#include <osmocom/bsc/osmo_bsc_rf.h>
#include <osmocom/bsc/bsc_msc_data.h>
#include <osmocom/bsc/signal.h>
#include <osmocom/bsc/vty.h>
#include <osmocom/bsc/ipaccess.h>
#include <osmocom/bsc/ctrl.h>
#include <osmocom/bsc/osmo_bsc_sigtran.h>
#include <osmocom/bsc/handover_decision.h>
#include <osmocom/bsc/handover_decision_2.h>

#include <osmocom/ctrl/control_cmd.h>
#include <osmocom/ctrl/control_if.h>
#include <osmocom/ctrl/ports.h>
#include <osmocom/ctrl/control_vty.h>

#include <osmocom/core/application.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/stats.h>
#include <osmocom/gsm/protocol/gsm_12_21.h>

#include <osmocom/abis/abis.h>
#include <osmocom/bsc/abis_om2000.h>

#include <osmocom/mgcp_client/mgcp_client.h>

#define _GNU_SOURCE
#include <getopt.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>


#include "../../bscconfig.h"

struct gsm_network *bsc_gsmnet = 0;
static const char *config_file = "osmo-bsc.cfg";
static const char *rf_ctrl = NULL;
static int daemonize = 0;
static struct llist_head access_lists;

struct llist_head *bsc_access_lists(void)
{
	return &access_lists;
}

static void print_usage()
{
	printf("Usage: osmo-bsc\n");
}

static void print_help()
{
	printf("  Some useful help...\n");
	printf("  -h --help this text\n");
	printf("  -D --daemonize Fork the process into a background daemon\n");
	printf("  -d option --debug=DRLL:DCC:DMM:DRR:DRSL:DNM enable debugging\n");
	printf("  -s --disable-color\n");
	printf("  -T --timestamp. Print a timestamp in the debug output.\n");
	printf("  -c --config-file filename The config file to use.\n");
	printf("  -l --local=IP. The local address of the MGCP.\n");
	printf("  -e --log-level number. Set a global loglevel.\n");
	printf("  -r --rf-ctl NAME. A unix domain socket to listen for cmds.\n");
	printf("  -t --testmode. A special mode to provoke failures at the MSC.\n");
}

static void handle_options(int argc, char **argv)
{
	while (1) {
		int option_index = 0, c;
		static struct option long_options[] = {
			{"help", 0, 0, 'h'},
			{"debug", 1, 0, 'd'},
			{"daemonize", 0, 0, 'D'},
			{"config-file", 1, 0, 'c'},
			{"disable-color", 0, 0, 's'},
			{"timestamp", 0, 0, 'T'},
			{"local", 1, 0, 'l'},
			{"log-level", 1, 0, 'e'},
			{"rf-ctl", 1, 0, 'r'},
			{"testmode", 0, 0, 't'},
			{0, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "hd:DsTc:e:r:t",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			print_usage();
			print_help();
			exit(0);
		case 's':
			log_set_use_color(osmo_stderr_target, 0);
			break;
		case 'd':
			log_parse_category_mask(osmo_stderr_target, optarg);
			break;
		case 'D':
			daemonize = 1;
			break;
		case 'c':
			config_file = optarg;
			break;
		case 'T':
			log_set_print_timestamp(osmo_stderr_target, 1);
			break;
		case 'e':
			log_set_log_level(osmo_stderr_target, atoi(optarg));
			break;
		case 'r':
			rf_ctrl = optarg;
			break;
		default:
			/* ignore */
			break;
		}
	}
}

static int bsc_vty_go_parent(struct vty *vty)
{
	switch (vty->node) {
	case GSMNET_NODE:
		vty->node = CONFIG_NODE;
		vty->index = NULL;
		break;
	case BTS_NODE:
		vty->node = GSMNET_NODE;
		{
			/* set vty->index correctly ! */
			struct gsm_bts *bts = vty->index;
			vty->index = bts->network;
			vty->index_sub = NULL;
		}
		break;
	case TRX_NODE:
		vty->node = BTS_NODE;
		{
			/* set vty->index correctly ! */
			struct gsm_bts_trx *trx = vty->index;
			vty->index = trx->bts;
			vty->index_sub = &trx->bts->description;
		}
		break;
	case TS_NODE:
		vty->node = TRX_NODE;
		{
			/* set vty->index correctly ! */
			struct gsm_bts_trx_ts *ts = vty->index;
			vty->index = ts->trx;
			vty->index_sub = &ts->trx->description;
		}
		break;
	case OML_NODE:
	case OM2K_NODE:
		vty->node = ENABLE_NODE;
		/* NOTE: this only works because it's not part of the config
		 * tree, where outer commands are searched via vty_go_parent()
		 * and only (!) executed when a matching one is found.
		 */
		talloc_free(vty->index);
		vty->index = NULL;
		break;
	case OM2K_CON_GROUP_NODE:
		vty->node = BTS_NODE;
		{
			struct con_group *cg = vty->index;
			struct gsm_bts *bts = cg->bts;
			vty->index = bts;
			vty->index_sub = &bts->description;
		}
		break;
	case BSC_NODE:
	case MSC_NODE:
		vty->node = CONFIG_NODE;
		vty->index = NULL;
		break;
	default:
		osmo_ss7_vty_go_parent(vty);
	}

	return vty->node;
}

static int bsc_vty_is_config_node(struct vty *vty, int node)
{
	/* Check if libosmo-sccp declares the node in
	 * question as config node */
	if (osmo_ss7_is_config_node(vty, node))
		return 1;

	switch (node) {
	/* add items that are not config */
	case OML_NODE:
	case OM2K_NODE:
	case CONFIG_NODE:
		return 0;

	default:
		return 1;
	}
}

static struct vty_app_info vty_info = {
	.name 		= "OsmoBSC",
	.copyright	=
	"Copyright (C) 2008-2018 Harald Welte, Holger Freyther\r\n"
	"Contributions by Daniel Willmann, Jan Lübbe, Stefan Schmidt\r\n"
	"Dieter Spaar, Andreas Eversberg, Sylvain Munaut, Neels Hofmeyr\r\n\r\n"
	"License AGPLv3+: GNU AGPL version 3 or later <http://gnu.org/licenses/agpl-3.0.html>\r\n"
	"This is free software: you are free to change and redistribute it.\r\n"
	"There is NO WARRANTY, to the extent permitted by law.\r\n",
	.version	= PACKAGE_VERSION,
	.go_parent_cb	= bsc_vty_go_parent,
	.is_config_node	= bsc_vty_is_config_node,
};

extern int bsc_shutdown_net(struct gsm_network *net);
static void signal_handler(int signal)
{
	struct bsc_msc_data *msc;

	fprintf(stdout, "signal %u received\n", signal);

	switch (signal) {
	case SIGINT:
	case SIGTERM:
		bsc_shutdown_net(bsc_gsmnet);
		osmo_signal_dispatch(SS_L_GLOBAL, S_L_GLOBAL_SHUTDOWN, NULL);
		sleep(3);
		exit(0);
		break;
	case SIGABRT:
		/* in case of abort, we want to obtain a talloc report
		 * and then return to the caller, who will abort the process */
	case SIGUSR1:
		talloc_report(tall_vty_ctx, stderr);
		talloc_report_full(tall_bsc_ctx, stderr);
		break;
	case SIGUSR2:
		if (!bsc_gsmnet->bsc_data)
			return;
		llist_for_each_entry(msc, &bsc_gsmnet->bsc_data->mscs, entry)
			bsc_msc_lost(msc->msc_con);
		break;
	default:
		break;
	}
}

static const struct log_info_cat osmo_bsc_categories[] = {
	[DRLL] = {
		.name = "DRLL",
		.description = "A-bis Radio Link Layer (RLL)",
		.color = "\033[1;31m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DCC] = {
		.name = "DCC",
		.description = "Layer3 Call Control (CC)",
		.color = "\033[1;32m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DMM] = {
		.name = "DMM",
		.description = "Layer3 Mobility Management (MM)",
		.color = "\033[1;33m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DRR] = {
		.name = "DRR",
		.description = "Layer3 Radio Resource (RR)",
		.color = "\033[1;34m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DRSL] = {
		.name = "DRSL",
		.description = "A-bis Radio Signalling Link (RSL)",
		.color = "\033[1;35m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DNM] =	{
		.name = "DNM",
		.description = "A-bis Network Management / O&M (NM/OML)",
		.color = "\033[1;36m",
		.enabled = 1, .loglevel = LOGL_INFO,
	},
	[DPAG]	= {
		.name = "DPAG",
		.description = "Paging Subsystem",
		.color = "\033[1;38m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DMEAS] = {
		.name = "DMEAS",
		.description = "Radio Measurement Processing",
		.enabled = 0, .loglevel = LOGL_NOTICE,
	},
	[DMSC] = {
		.name = "DMSC",
		.description = "Mobile Switching Center",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DMGCP] = {
		.name = "DMGCP",
		.description = "Media Gateway Control Protocol",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DHO] = {
		.name = "DHO",
		.description = "Hand-Over Process",
		.color = "\033[1;38m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DHODEC] = {
		.name = "DHODEC",
		.description = "Hand-Over Decision",
		.color = "\033[1;38m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DREF] = {
		.name = "DREF",
		.description = "Reference Counting",
		.enabled = 0, .loglevel = LOGL_NOTICE,
	},
	[DNAT] = {
		.name = "DNAT",
		.description = "GSM 08.08 NAT/Multiplexer",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DCTRL] = {
		.name = "DCTRL",
		.description = "Control interface",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DFILTER] = {
		.name = "DFILTER",
		.description = "BSC/NAT IMSI based filtering",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
	[DPCU] = {
		.name = "DPCU",
		.description = "PCU Interface",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
};

static int filter_fn(const struct log_context *ctx, struct log_target *tar)
{
	const struct bsc_subscr *bsub = ctx->ctx[LOG_CTX_BSC_SUBSCR];

	if ((tar->filter_map & (1 << LOG_FLT_BSC_SUBSCR)) != 0
	    && bsub && bsub == tar->filter_data[LOG_FLT_BSC_SUBSCR])
		return 1;

	return 0;
}

const struct log_info log_info = {
	.filter_fn = filter_fn,
	.cat = osmo_bsc_categories,
	.num_cat = ARRAY_SIZE(osmo_bsc_categories),
};

extern void *tall_paging_ctx;
extern void *tall_fle_ctx;
extern void *tall_sigh_ctx;
extern void *tall_tqe_ctx;
extern void *tall_ctr_ctx;

int main(int argc, char **argv)
{
	struct bsc_msc_data *msc;
	struct osmo_bsc_data *data;
	int rc;

	tall_bsc_ctx = talloc_named_const(NULL, 1, "openbsc");
	msgb_talloc_ctx_init(tall_bsc_ctx, 0);
	vty_info.tall_ctx = tall_bsc_ctx;

	tall_paging_ctx = talloc_named_const(tall_bsc_ctx, 0, "paging_request");
	tall_fle_ctx = talloc_named_const(tall_bsc_ctx, 0, "bs11_file_list_entry");
	tall_sigh_ctx = talloc_named_const(tall_bsc_ctx, 0, "signal_handler");
	tall_tqe_ctx = talloc_named_const(tall_bsc_ctx, 0, "subch_txq_entry");
	tall_ctr_ctx = talloc_named_const(tall_bsc_ctx, 0, "counter");

	osmo_init_logging2(tall_bsc_ctx, &log_info);
	osmo_stats_init(tall_bsc_ctx);

	/* Allocate global gsm_network struct */
	rc = bsc_network_alloc();
	if (rc) {
		fprintf(stderr, "Allocation failed. exiting.\n");
		exit(1);
	}

	bsc_gsmnet->mgw.conf = talloc_zero(bsc_gsmnet, struct mgcp_client_conf);
	mgcp_client_conf_init(bsc_gsmnet->mgw.conf);

	bts_init();
	libosmo_abis_init(tall_bsc_ctx);

	/* enable filters */

	/* This needs to precede handle_options() */
	vty_init(&vty_info);
	bsc_vty_init(bsc_gsmnet);
	bsc_msg_lst_vty_init(tall_bsc_ctx, &access_lists, BSC_NODE);
	ctrl_vty_init(tall_bsc_ctx);

	/* Initalize SS7 */
	osmo_ss7_init();
	osmo_ss7_vty_init_asp(tall_bsc_ctx);

	INIT_LLIST_HEAD(&access_lists);

	/* parse options */
	handle_options(argc, argv);

	/* seed the PRNG */
	srand(time(NULL));

	/* Read the config */
	rc = bsc_network_configure(config_file);
	if (rc < 0) {
		fprintf(stderr, "Bootstrapping the network failed. exiting.\n");
		exit(1);
	}
	bsc_api_init(bsc_gsmnet, osmo_bsc_api());

	/* start control interface after reading config for
	 * ctrl_vty_get_bind_addr() */
	bsc_gsmnet->ctrl = bsc_controlif_setup(bsc_gsmnet,
					       ctrl_vty_get_bind_addr(),
					       OSMO_CTRL_PORT_NITB_BSC);
	if (!bsc_gsmnet->ctrl) {
		fprintf(stderr, "Failed to init the control interface. Exiting.\n");
		exit(1);
	}

	rc = bsc_ctrl_cmds_install(bsc_gsmnet);
	if (rc < 0) {
		fprintf(stderr, "Failed to install control commands. Exiting.\n");
		exit(1);
	}

	data = bsc_gsmnet->bsc_data;
	if (rf_ctrl)
		osmo_talloc_replace_string(data, &data->rf_ctrl_name, rf_ctrl);

	data->rf_ctrl = osmo_bsc_rf_create(data->rf_ctrl_name, bsc_gsmnet);
	if (!data->rf_ctrl) {
		fprintf(stderr, "Failed to create the RF service.\n");
		exit(1);
	}

	llist_for_each_entry(msc, &bsc_gsmnet->bsc_data->mscs, entry) {
		if (osmo_bsc_msc_init(msc) != 0) {
			LOGP(DNAT, LOGL_ERROR, "Failed to start up. Exiting.\n");
			exit(1);
		}
	}

	bsc_gsmnet->mgw.client = mgcp_client_init(bsc_gsmnet, bsc_gsmnet->mgw.conf);

	if (mgcp_client_connect(bsc_gsmnet->mgw.client)) {
		LOGP(DNM, LOGL_ERROR, "MGW connect failed at (%s:%u)\n",
		     bsc_gsmnet->mgw.conf->remote_addr,
		     bsc_gsmnet->mgw.conf->remote_port);
		exit(1);
	}

	if (osmo_bsc_sigtran_init(&bsc_gsmnet->bsc_data->mscs) != 0) {
		LOGP(DNM, LOGL_ERROR, "Failed to initalize sigtran backhaul.\n");
		exit(1);
	}

	if (osmo_bsc_audio_init(bsc_gsmnet) != 0) {
		LOGP(DMSC, LOGL_ERROR, "Failed to register audio support.\n");
		exit(1);
	}

	handover_decision_1_init();
	hodec2_init(bsc_gsmnet);

	signal(SIGINT, &signal_handler);
	signal(SIGTERM, &signal_handler);
	signal(SIGABRT, &signal_handler);
	signal(SIGUSR1, &signal_handler);
	signal(SIGUSR2, &signal_handler);
	osmo_init_ignore_signals();

	if (daemonize) {
		rc = osmo_daemonize();
		if (rc < 0) {
			perror("Error during daemonize");
			exit(1);
		}
	}

	while (1) {
		osmo_select_main(0);
	}

	return 0;
}
