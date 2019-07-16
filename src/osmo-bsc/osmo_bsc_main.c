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
#include <osmocom/bsc/timeslot_fsm.h>
#include <osmocom/bsc/lchan_fsm.h>
#include <osmocom/bsc/bsc_subscr_conn_fsm.h>
#include <osmocom/bsc/bsc_subscriber.h>
#include <osmocom/bsc/assignment_fsm.h>
#include <osmocom/bsc/handover_fsm.h>

#include <osmocom/ctrl/control_cmd.h>
#include <osmocom/ctrl/control_if.h>
#include <osmocom/ctrl/ports.h>
#include <osmocom/ctrl/control_vty.h>

#include <osmocom/core/application.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/stats.h>
#include <osmocom/gsm/protocol/gsm_12_21.h>
#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/ports.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/command.h>

#include <osmocom/mgcp_client/mgcp_client_endpoint_fsm.h>

#include <osmocom/abis/abis.h>
#include <osmocom/bsc/abis_om2000.h>
#include <osmocom/bsc/abis_nm.h>
#include <osmocom/bsc/abis_rsl.h>
#include <osmocom/bsc/chan_alloc.h>
#include <osmocom/bsc/e1_config.h>
#include <osmocom/bsc/codec_pref.h>

#include <osmocom/mgcp_client/mgcp_client.h>

#include <osmocom/sigtran/xua_msg.h>

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
static LLIST_HEAD(access_lists);

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
	printf("  -h --help 			This text.\n");
	printf("  -D --daemonize 		Fork the process into a background daemon.\n");
	printf("  -d  --debug option 		--debug=DRLL:DMM:DRR:DRSL:DNM enable debugging.\n");
	printf("  -s --disable-color		Disable coloring log in stderr.\n");
	printf("  -T --timestamp		Print a timestamp in the debug output.\n");
	printf("  -V --version               	Print the version of OsmoBSC.\n");
	printf("  -c --config-file filename	The config file to use.\n");
	printf("  -l --local IP			The local address of the MGCP.\n");
	printf("  -e --log-level number		Set a global loglevel.\n");
	printf("  -r --rf-ctl NAME		A unix domain socket to listen for cmds.\n");
	printf("  -t --testmode			A special mode to provoke failures at the MSC.\n");
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
			{"version", 0, 0, 'V' },
			{"local", 1, 0, 'l'},
			{"log-level", 1, 0, 'e'},
			{"rf-ctl", 1, 0, 'r'},
			{"testmode", 0, 0, 't'},
			{0, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "hd:DsTVc:e:r:t",
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
		case 'V':
			print_version(1);
			exit(0);
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

/* Callback function for NACK on the OML NM */
static int oml_msg_nack(struct nm_nack_signal_data *nack)
{
	if (nack->mt == NM_MT_GET_ATTR_NACK) {
		LOGP(DNM, LOGL_ERROR, "BTS%u does not support Get Attributes "
		     "OML message.\n", nack->bts->nr);
		return 0;
	}

	if (nack->mt == NM_MT_SET_BTS_ATTR_NACK)
		LOGP(DNM, LOGL_ERROR, "Failed to set BTS attributes. That is fatal. "
		     "Was the bts type and frequency properly specified?\n");
	else
		LOGP(DNM, LOGL_ERROR, "Got %s NACK going to drop the OML links.\n",
		     abis_nm_nack_name(nack->mt));

	if (!nack->bts) {
		LOGP(DNM, LOGL_ERROR, "Unknown bts. Can not drop it.\n");
		return 0;
	}

	if (is_ipaccess_bts(nack->bts))
		ipaccess_drop_oml_deferred(nack->bts);

	return 0;
}

/* Callback function to be called every time we receive a signal from NM */
static int nm_sig_cb(unsigned int subsys, unsigned int signal,
		     void *handler_data, void *signal_data)
{
	struct nm_nack_signal_data *nack;

	switch (signal) {
	case S_NM_NACK:
		nack = signal_data;
		return oml_msg_nack(nack);
	default:
		break;
	}
	return 0;
}

/* Produce a MA as specified in 10.5.2.21 */
static int generate_ma_for_ts(struct gsm_bts_trx_ts *ts)
{
	/* we have three bitvecs: the per-timeslot ARFCNs, the cell chan ARFCNs
	 * and the MA */
	struct bitvec *cell_chan = &ts->trx->bts->si_common.cell_alloc;
	struct bitvec *ts_arfcn = &ts->hopping.arfcns;
	struct bitvec *ma = &ts->hopping.ma;
	unsigned int num_cell_arfcns, bitnum, n_chan;
	int i;

	/* re-set the MA to all-zero */
	ma->cur_bit = 0;
	ts->hopping.ma_len = 0;
	memset(ma->data, 0, ma->data_len);

	if (!ts->hopping.enabled)
		return 0;

	/* count the number of ARFCNs in the cell channel allocation */
	num_cell_arfcns = 0;
	for (i = 0; i < 1024; i++) {
		if (bitvec_get_bit_pos(cell_chan, i))
			num_cell_arfcns++;
	}

	/* pad it to octet-aligned number of bits */
	ts->hopping.ma_len = num_cell_arfcns / 8;
	if (num_cell_arfcns % 8)
		ts->hopping.ma_len++;

	n_chan = 0;
	for (i = 0; i < 1024; i++) {
		if (!bitvec_get_bit_pos(cell_chan, i))
			continue;
		/* set the corresponding bit in the MA */
		bitnum = (ts->hopping.ma_len * 8) - 1 - n_chan;
		if (bitvec_get_bit_pos(ts_arfcn, i))
			bitvec_set_bit_pos(ma, bitnum, 1);
		else
			bitvec_set_bit_pos(ma, bitnum, 0);
		n_chan++;
	}

	/* ARFCN 0 is special: It is coded last in the bitmask */
	if (bitvec_get_bit_pos(cell_chan, 0)) {
		n_chan++;
		/* set the corresponding bit in the MA */
		bitnum = (ts->hopping.ma_len * 8) - 1 - n_chan;
		if (bitvec_get_bit_pos(ts_arfcn, 0))
			bitvec_set_bit_pos(ma, bitnum, 1);
		else
			bitvec_set_bit_pos(ma, bitnum, 0);
	}

	return 0;
}

static void bootstrap_rsl(struct gsm_bts_trx *trx)
{
	unsigned int i;

	LOGP(DRSL, LOGL_NOTICE, "bootstrapping RSL for BTS/TRX (%u/%u) "
		"on ARFCN %u using MCC-MNC %s LAC=%u CID=%u BSIC=%u\n",
		trx->bts->nr, trx->nr, trx->arfcn,
		osmo_plmn_name(&bsc_gsmnet->plmn),
		trx->bts->location_area_code,
		trx->bts->cell_identity, trx->bts->bsic);

	if (trx->bts->type == GSM_BTS_TYPE_NOKIA_SITE) {
		rsl_nokia_si_begin(trx);
	}

	/*
	 * Trigger ACC ramping before sending system information to BTS.
	 * This ensures that RACH control in system information is configured correctly.
	 * TRX 0 should be usable and unlocked, otherwise starting ACC ramping is pointless.
	 */
	if (trx_is_usable(trx) && trx->mo.nm_state.administrative == NM_STATE_UNLOCKED)
		acc_ramp_trigger(&trx->bts->acc_ramp);

	gsm_bts_trx_set_system_infos(trx);

	if (trx->bts->type == GSM_BTS_TYPE_NOKIA_SITE) {
		/* channel unspecific, power reduction in 2 dB steps */
		rsl_bs_power_control(trx, 0xFF, trx->max_power_red / 2);
		rsl_nokia_si_end(trx);
	}

	for (i = 0; i < ARRAY_SIZE(trx->ts); i++) {
		struct gsm_bts_trx_ts *ts = &trx->ts[i];
		generate_ma_for_ts(ts);
		OSMO_ASSERT(ts->fi);
		osmo_fsm_inst_dispatch(ts->fi, TS_EV_RSL_READY, NULL);
	}
}

static void all_ts_dispatch_event(struct gsm_bts_trx *trx, uint32_t event)
{
	int ts_i;
	for (ts_i = 0; ts_i < ARRAY_SIZE(trx->ts); ts_i++) {
		struct gsm_bts_trx_ts *ts = &trx->ts[ts_i];
		if (ts->fi)
			osmo_fsm_inst_dispatch(ts->fi, event, 0);
	}
}

/* Callback function to be called every time we receive a signal from INPUT */
static int inp_sig_cb(unsigned int subsys, unsigned int signal,
		      void *handler_data, void *signal_data)
{
	struct input_signal_data *isd = signal_data;
	struct gsm_bts_trx *trx = isd->trx;
	/* N. B: we rely on attribute order when parsing response in abis_nm_rx_get_attr_resp() */
	const uint8_t bts_attr[] = { NM_ATT_MANUF_ID, NM_ATT_SW_CONFIG, };
	const uint8_t trx_attr[] = { NM_ATT_MANUF_STATE, NM_ATT_SW_CONFIG, };

	/* we should not request more attributes than we're ready to handle */
	OSMO_ASSERT(sizeof(bts_attr) < MAX_BTS_ATTR);
	OSMO_ASSERT(sizeof(trx_attr) < MAX_BTS_ATTR);

	if (subsys != SS_L_INPUT)
		return -EINVAL;

	LOGP(DLMI, LOGL_DEBUG, "%s(): Input signal '%s' received\n", __func__,
		get_value_string(e1inp_signal_names, signal));
	switch (signal) {
	case S_L_INP_TEI_UP:
		if (isd->link_type == E1INP_SIGN_OML) {
			/* TODO: this is required for the Nokia BTS, hopping is configured
			   during OML, other MA is not set.  */
			struct gsm_bts_trx *cur_trx;
			/* was static in system_information.c */
			extern int generate_cell_chan_list(uint8_t *chan_list, struct gsm_bts *bts);
			uint8_t ca[20];
			/* has to be called before generate_ma_for_ts to
			  set bts->si_common.cell_alloc */
			generate_cell_chan_list(ca, trx->bts);

			/* Request generic BTS-level attributes */
			abis_nm_get_attr(trx->bts, NM_OC_BTS, 0xFF, 0xFF, 0xFF, bts_attr, sizeof(bts_attr));

			llist_for_each_entry(cur_trx, &trx->bts->trx_list, list) {
				int i;
				/* Request TRX-level attributes */
				abis_nm_get_attr(cur_trx->bts, NM_OC_BASEB_TRANSC, 0, cur_trx->nr, 0xFF,
						 trx_attr, sizeof(trx_attr));
				for (i = 0; i < ARRAY_SIZE(cur_trx->ts); i++)
					generate_ma_for_ts(&cur_trx->ts[i]);
			}
		}
		if (isd->link_type == E1INP_SIGN_RSL)
			bootstrap_rsl(trx);
		break;
	case S_L_INP_TEI_DN:
		LOGP(DLMI, LOGL_ERROR, "Lost some E1 TEI link: %d %p\n", isd->link_type, trx);

		if (isd->link_type == E1INP_SIGN_OML) {
			rate_ctr_inc(&trx->bts->bts_ctrs->ctr[BTS_CTR_BTS_OML_FAIL]);
			all_ts_dispatch_event(trx, TS_EV_OML_DOWN);
		} else if (isd->link_type == E1INP_SIGN_RSL) {
			rate_ctr_inc(&trx->bts->bts_ctrs->ctr[BTS_CTR_BTS_RSL_FAIL]);
			acc_ramp_abort(&trx->bts->acc_ramp);
			all_ts_dispatch_event(trx, TS_EV_RSL_DOWN);
		}

		gsm_bts_mo_reset(trx->bts);

		abis_nm_clear_queue(trx->bts);
		break;
	default:
		break;
	}

	return 0;
}

static int bootstrap_bts(struct gsm_bts *bts)
{
	int i, n;

	if (!bts->model)
		return -EFAULT;

	if (bts->model->start && !bts->model->started) {
		int ret = bts->model->start(bts->network);
		if (ret < 0)
			return ret;

		bts->model->started = true;
	}

	/* FIXME: What about secondary TRX of a BTS?  What about a BTS that has TRX
	 * in different bands? Why is 'band' a parameter of the BTS and not of the TRX? */
	switch (bts->band) {
	case GSM_BAND_1800:
		if (bts->c0->arfcn < 512 || bts->c0->arfcn > 885) {
			LOGP(DNM, LOGL_ERROR, "GSM1800 channel must be between 512-885.\n");
			return -EINVAL;
		}
		break;
	case GSM_BAND_1900:
		if (bts->c0->arfcn < 512 || bts->c0->arfcn > 810) {
			LOGP(DNM, LOGL_ERROR, "GSM1900 channel must be between 512-810.\n");
			return -EINVAL;
		}
		break;
	case GSM_BAND_900:
		if ((bts->c0->arfcn > 124 && bts->c0->arfcn < 955) ||
		    bts->c0->arfcn > 1023)  {
			LOGP(DNM, LOGL_ERROR, "GSM900 channel must be between 0-124, 955-1023.\n");
			return -EINVAL;
		}
		break;
	case GSM_BAND_850:
		if (bts->c0->arfcn < 128 || bts->c0->arfcn > 251) {
			LOGP(DNM, LOGL_ERROR, "GSM850 channel must be between 128-251.\n");
			return -EINVAL;
		}
		break;
	default:
		LOGP(DNM, LOGL_ERROR, "Unsupported frequency band.\n");
		return -EINVAL;
	}

	/* Control Channel Description is set from vty/config */

	/* Set ccch config by looking at ts config */
	for (n=0, i=0; i<8; i++)
		n += bts->c0->ts[i].pchan_is == GSM_PCHAN_CCCH ? 1 : 0;

	/* Indicate R99 MSC in SI3 */
	bts->si_common.chan_desc.mscr = 1;

	switch (n) {
	case 0:
		bts->si_common.chan_desc.ccch_conf = RSL_BCCH_CCCH_CONF_1_C;
		/* Limit reserved block to 2 on combined channel according to
		   3GPP TS 44.018 Table 10.5.2.11.1 */
		if (bts->si_common.chan_desc.bs_ag_blks_res > 2) {
			LOGP(DNM, LOGL_NOTICE, "CCCH is combined with SDCCHs, "
			     "reducing BS-AG-BLKS-RES value %d -> 2\n",
			     bts->si_common.chan_desc.bs_ag_blks_res);
			bts->si_common.chan_desc.bs_ag_blks_res = 2;
		}
		break;
	case 1:
		bts->si_common.chan_desc.ccch_conf = RSL_BCCH_CCCH_CONF_1_NC;
		break;
	case 2:
		bts->si_common.chan_desc.ccch_conf = RSL_BCCH_CCCH_CONF_2_NC;
		break;
	case 3:
		bts->si_common.chan_desc.ccch_conf = RSL_BCCH_CCCH_CONF_3_NC;
		break;
	case 4:
		bts->si_common.chan_desc.ccch_conf = RSL_BCCH_CCCH_CONF_4_NC;
		break;
	default:
		LOGP(DNM, LOGL_ERROR, "Unsupported CCCH timeslot configuration\n");
		return -EINVAL;
	}

	bts->si_common.cell_options.pwrc = 0; /* PWRC not set */

	bts->si_common.cell_sel_par.acs = 0;

	bts->si_common.ncc_permitted = 0xff;

	bts->chan_load_samples_idx = 0;

	/* ACC ramping is initialized from vty/config */

	/* Initialize the BTS state */
	gsm_bts_mo_reset(bts);

	return 0;
}

static int bsc_network_configure(const char *config_file)
{
	struct gsm_bts *bts;
	int rc;

	rc = vty_read_config_file(config_file, NULL);
	if (rc < 0) {
		LOGP(DNM, LOGL_FATAL, "Failed to parse the config file: '%s'\n", config_file);
		return rc;
	}

	/* start telnet after reading config for vty_get_bind_addr() */
	rc = telnet_init_dynif(tall_bsc_ctx, bsc_gsmnet, vty_get_bind_addr(),
			       OSMO_VTY_PORT_NITB_BSC);
	if (rc < 0)
		return rc;

	osmo_signal_register_handler(SS_NM, nm_sig_cb, NULL);
	osmo_signal_register_handler(SS_L_INPUT, inp_sig_cb, NULL);

	llist_for_each_entry(bts, &bsc_gsmnet->bts_list, list) {
		rc = bootstrap_bts(bts);
		if (rc < 0) {
			LOGP(DNM, LOGL_FATAL, "Error bootstrapping BTS\n");
			return rc;
		}
		rc = e1_reconfig_bts(bts);
		if (rc < 0) {
			LOGP(DNM, LOGL_FATAL, "Error enabling E1 input driver\n");
			return rc;
		}
	}

	return 0;
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
	[DCHAN] = {
		.name = "DCHAN",
		.description = "lchan FSM",
		.color = "\033[1;32m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DTS] = {
		.name = "DTS",
		.description = "timeslot FSM",
		.color = "\033[1;31m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DAS] = {
		.name = "DAS",
		.description = "assignment FSM",
		.color = "\033[1;33m",
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
	[DLCLS] = {
		.name = "DLCLS",
		.description = "Local Call, Local Switch",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},

};

static int filter_fn(const struct log_context *ctx, struct log_target *tar)
{
	const struct bsc_subscr *bsub_ctx = ctx->ctx[LOG_CTX_BSC_SUBSCR];
	const struct bsc_subscr *bsub_filter = tar->filter_data[LOG_FLT_BSC_SUBSCR];

	if ((tar->filter_map & (1 << LOG_FLT_BSC_SUBSCR)) != 0
	    && bsub_ctx && bsub_filter
	    && strncmp(bsub_ctx->imsi, bsub_filter->imsi, sizeof(bsub_ctx->imsi)) == 0)
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
extern void *tall_tqe_ctx;
extern void *tall_ctr_ctx;

int main(int argc, char **argv)
{
	struct bsc_msc_data *msc;
	struct osmo_bsc_data *data;
	int rc;

	tall_bsc_ctx = talloc_named_const(NULL, 1, "osmo-bsc");
	msgb_talloc_ctx_init(tall_bsc_ctx, 0);
	osmo_signal_talloc_ctx_init(tall_bsc_ctx);
	osmo_xua_msg_tall_ctx_init(tall_bsc_ctx);
	vty_info.tall_ctx = tall_bsc_ctx;

	tall_paging_ctx = talloc_named_const(tall_bsc_ctx, 0, "paging_request");
	tall_fle_ctx = talloc_named_const(tall_bsc_ctx, 0, "bs11_file_list_entry");
	tall_tqe_ctx = talloc_named_const(tall_bsc_ctx, 0, "subch_txq_entry");
	tall_ctr_ctx = talloc_named_const(tall_bsc_ctx, 0, "counter");

	osmo_init_logging2(tall_bsc_ctx, &log_info);
	osmo_stats_init(tall_bsc_ctx);
	rate_ctr_init(tall_bsc_ctx);

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
	bsc_msg_acc_lst_vty_init(tall_bsc_ctx, &access_lists, BSC_NODE);
	ctrl_vty_init(tall_bsc_ctx);
	logging_vty_add_deprecated_subsys(tall_bsc_ctx, "cc");
	logging_vty_add_deprecated_subsys(tall_bsc_ctx, "mgcp");

	/* Initalize SS7 */
	osmo_ss7_init();
	osmo_ss7_vty_init_asp(tall_bsc_ctx);
	osmo_sccp_vty_init();

	/* parse options */
	handle_options(argc, argv);

	/* seed the PRNG */
	srand(time(NULL));

	ts_fsm_init();
	lchan_fsm_init();
	bsc_subscr_conn_fsm_init();
	assignment_fsm_init();
	handover_fsm_init();

	/* Read the config */
	rc = bsc_network_configure(config_file);
	if (rc < 0) {
		fprintf(stderr, "Bootstrapping the network failed. exiting.\n");
		exit(1);
	}

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

	rc = check_codec_pref(&bsc_gsmnet->bsc_data->mscs);
	if (rc < 0)
		LOGP(DMSC, LOGL_ERROR, "Configuration contains mutually exclusive codec settings -- check configuration!\n");

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
		LOGP(DNM, LOGL_ERROR, "Failed to initialize sigtran backhaul.\n");
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
