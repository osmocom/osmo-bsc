/* OsmoBSC interface to quagga VTY, BTS node */
/* (C) 2009-2017 by Harald Welte <laforge@gnumonks.org>
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

#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/sockaddr_str.h>
#include <osmocom/vty/command.h>
#include <osmocom/vty/buffer.h>
#include <osmocom/vty/vty.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/stats.h>
#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/misc.h>
#include <osmocom/vty/tdef_vty.h>
#include <osmocom/ctrl/control_if.h>
#include <osmocom/gprs/gprs_ns.h>

#include <osmocom/bsc/vty.h>
#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/chan_alloc.h>
#include <osmocom/bsc/meas_rep.h>
#include <osmocom/bsc/system_information.h>
#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/paging.h>
#include <osmocom/bsc/pcu_if.h>
#include <osmocom/bsc/handover_vty.h>
#include <osmocom/bsc/gsm_04_08_rr.h>
#include <osmocom/bsc/neighbor_ident.h>
#include <osmocom/bsc/smscb.h>
#include <osmocom/bsc/bts.h>
#include <osmocom/bsc/bsc_stats.h>

#include <inttypes.h>

#include "../../bscconfig.h"

#define X(x) (1 << x)

/* FIXME: this should go to some common file */
static const struct value_string gprs_ns_timer_strs[] = {
	{ 0, "tns-block" },
	{ 1, "tns-block-retries" },
	{ 2, "tns-reset" },
	{ 3, "tns-reset-retries" },
	{ 4, "tns-test" },
	{ 5, "tns-alive" },
	{ 6, "tns-alive-retries" },
	{ 0, NULL }
};

static const struct value_string gprs_bssgp_cfg_strs[] = {
	{ 0,	"blocking-timer" },
	{ 1,	"blocking-retries" },
	{ 2,	"unblocking-retries" },
	{ 3,	"reset-timer" },
	{ 4,	"reset-retries" },
	{ 5,	"suspend-timer" },
	{ 6,	"suspend-retries" },
	{ 7,	"resume-timer" },
	{ 8,	"resume-retries" },
	{ 9,	"capability-update-timer" },
	{ 10,	"capability-update-retries" },
	{ 0,	NULL }
};

static const struct value_string bts_neigh_mode_strs[] = {
	{ NL_MODE_AUTOMATIC, "automatic" },
	{ NL_MODE_MANUAL, "manual" },
	{ NL_MODE_MANUAL_SI5SEP, "manual-si5" },
	{ 0, NULL }
};

static struct cmd_node bts_node = {
	BTS_NODE,
	"%s(config-net-bts)# ",
	1,
};

static struct cmd_node power_ctrl_node = {
	POWER_CTRL_NODE,
	"%s(config-power-ctrl)# ",
	1,
};

/* per-BTS configuration */
DEFUN_ATTR(cfg_bts,
	   cfg_bts_cmd,
	   "bts <0-255>",
	   "Select a BTS to configure\n"
	   BTS_NR_STR,
	   CMD_ATTR_IMMEDIATE)
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	int bts_nr = atoi(argv[0]);
	struct gsm_bts *bts;

	if (bts_nr > gsmnet->num_bts) {
		vty_out(vty, "%% The next unused BTS number is %u%s",
			gsmnet->num_bts, VTY_NEWLINE);
		return CMD_WARNING;
	} else if (bts_nr == gsmnet->num_bts) {
		/* allocate a new one */
		bts = bsc_bts_alloc_register(gsmnet, GSM_BTS_TYPE_UNKNOWN,
					     HARDCODED_BSIC);
	} else
		bts = gsm_bts_num(gsmnet, bts_nr);

	if (!bts) {
		vty_out(vty, "%% Unable to allocate BTS %u%s",
			gsmnet->num_bts, VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty->index = bts;
	vty->index_sub = &bts->description;
	vty->node = BTS_NODE;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_type,
	      cfg_bts_type_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "type TYPE", /* dynamically created */
	      "Set the BTS type\n" "Type\n")
{
	struct gsm_bts *bts = vty->index;
	int rc;

	rc = gsm_set_bts_type(bts, str2btstype(argv[0]));
	if (rc == -EBUSY)
		vty_out(vty, "%% Changing the type of an existing BTS is not supported.%s",
			VTY_NEWLINE);
	if (rc < 0)
		return CMD_WARNING;

	return CMD_SUCCESS;
}

DEFUN_DEPRECATED(cfg_bts_type_sysmobts,
		 cfg_bts_type_sysmobts_cmd,
		 "type sysmobts",
		 "Set the BTS type\n"
		 "Deprecated alias for 'osmo-bts'\n")
{
	const char *args[] = { "osmo-bts" };

	vty_out(vty, "%% BTS type 'sysmobts' is deprecated, "
		"use 'type osmo-bts' instead.%s", VTY_NEWLINE);

	return cfg_bts_type(self, vty, 1, args);
}

DEFUN_USRATTR(cfg_bts_band,
	      cfg_bts_band_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "band BAND",
	      "Set the frequency band of this BTS\n" "Frequency band\n")
{
	struct gsm_bts *bts = vty->index;
	int band = gsm_band_parse(argv[0]);

	if (band < 0) {
		vty_out(vty, "%% BAND %d is not a valid GSM band%s",
			band, VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts->band = band;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_dtxu,
	      cfg_bts_dtxu_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "dtx uplink [force]",
	      "Configure discontinuous transmission\n"
	      "Enable Uplink DTX for this BTS\n"
	      "MS 'shall' use DTXu instead of 'may' use (might not be supported by "
	      "older phones).\n")
{
	struct gsm_bts *bts = vty->index;

	bts->dtxu = (argc > 0) ? GSM48_DTX_SHALL_BE_USED : GSM48_DTX_MAY_BE_USED;
	if (!is_ipaccess_bts(bts))
		vty_out(vty, "%% DTX enabled on non-IP BTS: this configuration "
			"neither supported nor tested!%s", VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_no_dtxu,
	      cfg_bts_no_dtxu_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "no dtx uplink",
	      NO_STR "Configure discontinuous transmission\n"
	      "Disable Uplink DTX for this BTS\n")
{
	struct gsm_bts *bts = vty->index;

	bts->dtxu = GSM48_DTX_SHALL_NOT_BE_USED;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_dtxd,
	      cfg_bts_dtxd_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "dtx downlink",
	      "Configure discontinuous transmission\n"
	      "Enable Downlink DTX for this BTS\n")
{
	struct gsm_bts *bts = vty->index;

	bts->dtxd = true;
	if (!is_ipaccess_bts(bts))
		vty_out(vty, "%% DTX enabled on non-IP BTS: this configuration "
			"neither supported nor tested!%s", VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_no_dtxd,
	      cfg_bts_no_dtxd_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "no dtx downlink",
	      NO_STR "Configure discontinuous transmission\n"
	      "Disable Downlink DTX for this BTS\n")
{
	struct gsm_bts *bts = vty->index;

	bts->dtxd = false;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_ci,
	      cfg_bts_ci_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "cell_identity <0-65535>",
	      "Set the Cell identity of this BTS\n" "Cell Identity\n")
{
	struct gsm_bts *bts = vty->index;
	int ci = atoi(argv[0]);

	if (ci < 0 || ci > 0xffff) {
		vty_out(vty, "%% CI %d is not in the valid range (0-65535)%s",
			ci, VTY_NEWLINE);
		return CMD_WARNING;
	}
	bts->cell_identity = ci;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_lac,
	      cfg_bts_lac_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "location_area_code <0-65535>",
	      "Set the Location Area Code (LAC) of this BTS\n" "LAC\n")
{
	struct gsm_bts *bts = vty->index;
	int lac = atoi(argv[0]);

	if (lac < 0 || lac > 0xffff) {
		vty_out(vty, "%% LAC %d is not in the valid range (0-65535)%s",
			lac, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (lac == GSM_LAC_RESERVED_DETACHED || lac == GSM_LAC_RESERVED_ALL_BTS) {
		vty_out(vty, "%% LAC %d is reserved by GSM 04.08%s",
			lac, VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts->location_area_code = lac;

	return CMD_SUCCESS;
}


/* compatibility wrapper for old config files */
DEFUN_HIDDEN(cfg_bts_tsc,
      cfg_bts_tsc_cmd,
      "training_sequence_code <0-7>",
      "Set the Training Sequence Code (TSC) of this BTS\n" "TSC\n")
{
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_bsic,
	      cfg_bts_bsic_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "base_station_id_code <0-63>",
	      "Set the Base Station Identity Code (BSIC) of this BTS\n"
	      "BSIC of this BTS\n")
{
	struct gsm_bts *bts = vty->index;
	int bsic = atoi(argv[0]);

	if (bsic < 0 || bsic > 0x3f) {
		vty_out(vty, "%% BSIC %d is not in the valid range (0-255)%s",
			bsic, VTY_NEWLINE);
		return CMD_WARNING;
	}
	bts->bsic = bsic;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_unit_id,
	      cfg_bts_unit_id_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "ipa unit-id <0-65534> <0-255>",
	      "Abis/IP specific options\n"
	      "Set the IPA BTS Unit ID\n"
	      "Unit ID (Site)\n"
	      "Unit ID (BTS)\n")
{
	struct gsm_bts *bts = vty->index;
	int site_id = atoi(argv[0]);
	int bts_id = atoi(argv[1]);

	if (!is_ipaccess_bts(bts)) {
		vty_out(vty, "%% BTS is not of ip.access type%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts->ip_access.site_id = site_id;
	bts->ip_access.bts_id = bts_id;

	return CMD_SUCCESS;
}

DEFUN_DEPRECATED(cfg_bts_unit_id,
      cfg_bts_deprecated_unit_id_cmd,
      "ip.access unit_id <0-65534> <0-255>",
      "Abis/IP specific options\n"
      "Set the IPA BTS Unit ID\n"
      "Unit ID (Site)\n"
      "Unit ID (BTS)\n");

DEFUN_USRATTR(cfg_bts_rsl_ip,
	      cfg_bts_rsl_ip_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "ipa rsl-ip A.B.C.D",
	      "Abis/IP specific options\n"
	      "Set the IPA RSL IP Address of the BSC\n"
	      "Destination IP address for RSL connection\n")
{
	struct gsm_bts *bts = vty->index;
	struct in_addr ia;

	if (!is_ipaccess_bts(bts)) {
		vty_out(vty, "%% BTS is not of ip.access type%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	inet_aton(argv[0], &ia);
	bts->ip_access.rsl_ip = ntohl(ia.s_addr);

	return CMD_SUCCESS;
}

DEFUN_DEPRECATED(cfg_bts_rsl_ip,
      cfg_bts_deprecated_rsl_ip_cmd,
      "ip.access rsl-ip A.B.C.D",
      "Abis/IP specific options\n"
      "Set the IPA RSL IP Address of the BSC\n"
      "Destination IP address for RSL connection\n");

#define NOKIA_STR "Nokia *Site related commands\n"

DEFUN_USRATTR(cfg_bts_nokia_site_skip_reset,
	      cfg_bts_nokia_site_skip_reset_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "nokia_site skip-reset (0|1)",
	      NOKIA_STR
	      "Skip the reset step during bootstrap process of this BTS\n"
	      "Do NOT skip the reset\n" "Skip the reset\n")
{
	struct gsm_bts *bts = vty->index;

	if (bts->type != GSM_BTS_TYPE_NOKIA_SITE) {
		vty_out(vty, "%% BTS is not of Nokia *Site type%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts->nokia.skip_reset = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_bts_nokia_site_no_loc_rel_cnf,
	   cfg_bts_nokia_site_no_loc_rel_cnf_cmd,
	   "nokia_site no-local-rel-conf (0|1)",
	   NOKIA_STR
	   "Do not wait for RELease CONFirm message when releasing channel locally\n"
	   "Wait for RELease CONFirm\n" "Do not wait for RELease CONFirm\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct gsm_bts *bts = vty->index;

	if (!is_nokia_bts(bts)) {
		vty_out(vty, "%% BTS is not of Nokia *Site type%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts->nokia.no_loc_rel_cnf = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_bts_nokia_site_bts_reset_timer_cnf,
	   cfg_bts_nokia_site_bts_reset_timer_cnf_cmd,
	   "nokia_site bts-reset-timer  <15-100>",
	   NOKIA_STR
	   "The amount of time (in sec.) between BTS_RESET is sent,\n"
	   "and the BTS is being bootstrapped.\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct gsm_bts *bts = vty->index;

	if (!is_nokia_bts(bts)) {
		vty_out(vty, "%% BTS is not of Nokia *Site type%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts->nokia.bts_reset_timer_cnf = atoi(argv[0]);

	return CMD_SUCCESS;
}
#define OML_STR	"Organization & Maintenance Link\n"
#define IPA_STR "A-bis/IP Specific Options\n"

DEFUN_USRATTR(cfg_bts_stream_id,
	      cfg_bts_stream_id_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "oml ipa stream-id <0-255> line E1_LINE",
	      OML_STR IPA_STR
	      "Set the ipa Stream ID of the OML link of this BTS\n" "Stream Identifier\n"
	      "Virtual E1 Line Number\n" "Virtual E1 Line Number\n")
{
	struct gsm_bts *bts = vty->index;
	int stream_id = atoi(argv[0]), linenr = atoi(argv[1]);

	if (!is_ipaccess_bts(bts)) {
		vty_out(vty, "%% BTS is not of ip.access type%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts->oml_tei = stream_id;
	/* This is used by e1inp_bind_ops callback for each BTS model. */
	bts->oml_e1_link.e1_nr = linenr;

	return CMD_SUCCESS;
}

DEFUN_DEPRECATED(cfg_bts_stream_id,
      cfg_bts_deprecated_stream_id_cmd,
      "oml ip.access stream_id <0-255> line E1_LINE",
	OML_STR IPA_STR
      "Set the ip.access Stream ID of the OML link of this BTS\n"
      "Stream Identifier\n" "Virtual E1 Line Number\n" "Virtual E1 Line Number\n");

#define OML_E1_STR OML_STR "OML E1/T1 Configuration\n"

/* NOTE: This requires a full restart as bsc_network_configure() is executed
 * only once on startup from osmo_bsc_main.c */
DEFUN(cfg_bts_oml_e1,
      cfg_bts_oml_e1_cmd,
      "oml e1 line E1_LINE timeslot <1-31> sub-slot (0|1|2|3|full)",
	OML_E1_STR
      "E1/T1 line number to be used for OML\n"
      "E1/T1 line number to be used for OML\n"
      "E1/T1 timeslot to be used for OML\n"
      "E1/T1 timeslot to be used for OML\n"
      "E1/T1 sub-slot to be used for OML\n"
      "Use E1/T1 sub-slot 0\n"
      "Use E1/T1 sub-slot 1\n"
      "Use E1/T1 sub-slot 2\n"
      "Use E1/T1 sub-slot 3\n"
      "Use full E1 slot 3\n"
      )
{
	struct gsm_bts *bts = vty->index;

	parse_e1_link(&bts->oml_e1_link, argv[0], argv[1], argv[2]);

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_oml_e1_tei,
	      cfg_bts_oml_e1_tei_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "oml e1 tei <0-63>",
	      OML_E1_STR
	      "Set the TEI to be used for OML\n"
	      "TEI Number\n")
{
	struct gsm_bts *bts = vty->index;

	bts->oml_tei = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_bts_challoc,
	   cfg_bts_challoc_cmd,
	   "channel allocator (ascending|descending)",
	   "Channel Allocator\n" "Channel Allocator\n"
	   "Allocate Timeslots and Transceivers in ascending order\n"
	   "Allocate Timeslots and Transceivers in descending order\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct gsm_bts *bts = vty->index;

	if (!strcmp(argv[0], "ascending"))
		bts->chan_alloc_reverse = 0;
	else
		bts->chan_alloc_reverse = 1;

	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_bts_chan_alloc_interf,
	   cfg_bts_chan_alloc_interf_cmd,
	   "channel allocator avoid-interference (0|1)",
	   "Channel Allocator\n" "Channel Allocator\n"
	   "Configure whether reported interference levels from RES IND are used in channel allocation\n"
	   "Ignore interference levels (default). Always assign lchans in a deterministic order.\n"
	   "In channel allocation, prefer lchans with less interference.\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct gsm_bts *bts = vty->index;

	if (!strcmp(argv[0], "0"))
		bts->chan_alloc_avoid_interf = false;
	else
		bts->chan_alloc_avoid_interf = true;

	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_bts_chan_alloc_allow_tch_for_signalling,
	   cfg_bts_chan_alloc_allow_tch_for_signalling_cmd,
	   "channel allocator allow-tch-for-signalling (0|1)",
	   "Channel Allocator\n" "Channel Allocator\n"
	   "Configure whether TCH/H or TCH/F channels can be used to serve non-call-related signalling if SDCCHs are exhausted\n"
	   "Forbid use of TCH for non-call-related signalling purposes\n"
	   "Allow use of TCH for non-call-related signalling purposes (default)\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct gsm_bts *bts = vty->index;

	if (!strcmp(argv[0], "0"))
		bts->chan_alloc_allow_tch_for_signalling = false;
	else
		bts->chan_alloc_allow_tch_for_signalling = true;

	return CMD_SUCCESS;
}

#define RACH_STR "Random Access Control Channel\n"

DEFUN_USRATTR(cfg_bts_rach_tx_integer,
	      cfg_bts_rach_tx_integer_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "rach tx integer <0-15>",
	      RACH_STR
	      "Set the raw tx integer value in RACH Control parameters IE\n"
	      "Set the raw tx integer value in RACH Control parameters IE\n"
	      "Raw tx integer value in RACH Control parameters IE\n")
{
	struct gsm_bts *bts = vty->index;
	bts->si_common.rach_control.tx_integer = atoi(argv[0]) & 0xf;
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_rach_max_trans,
	      cfg_bts_rach_max_trans_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "rach max transmission (1|2|4|7)",
	      RACH_STR
	      "Set the maximum number of RACH burst transmissions\n"
	      "Set the maximum number of RACH burst transmissions\n"
	      "Maximum number of 1 RACH burst transmissions\n"
	      "Maximum number of 2 RACH burst transmissions\n"
	      "Maximum number of 4 RACH burst transmissions\n"
	      "Maximum number of 7 RACH burst transmissions\n")
{
	struct gsm_bts *bts = vty->index;
	bts->si_common.rach_control.max_trans = rach_max_trans_val2raw(atoi(argv[0]));
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_bts_rach_max_delay,
	   cfg_bts_rach_max_delay_cmd,
	   "rach max-delay <1-127>",
	   RACH_STR
	   "Set the max Access Delay IE value to accept in CHANnel ReQuireD\n"
	   "Maximum Access Delay IE value to accept in CHANnel ReQuireD\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct gsm_bts *bts = vty->index;
	bts->rach_max_delay = atoi(argv[0]);
	return CMD_SUCCESS;
}

#define REP_ACCH_STR "FACCH/SACCH repetition\n"

DEFUN_USRATTR(cfg_bts_rep_dl_facch,
	      cfg_bts_rep_dl_facch_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "repeat dl-facch (command|all)",
	      REP_ACCH_STR
	      "Enable DL-FACCH repetition for this BTS\n"
	      "command LAPDm frames only\n"
	      "all LAPDm frames\n")
{
	struct gsm_bts *bts = vty->index;

	if (bts->model->type != GSM_BTS_TYPE_OSMOBTS) {
		vty_out(vty, "%% repeated ACCH not supported by BTS %u%s",
			bts->nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!strcmp(argv[0], "command")) {
		bts->rep_acch_cap.dl_facch_cmd = true;
		bts->rep_acch_cap.dl_facch_all = false;
	} else {
		bts->rep_acch_cap.dl_facch_cmd = true;
		bts->rep_acch_cap.dl_facch_all = true;
	}
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_rep_no_dl_facch,
	      cfg_bts_rep_no_dl_facch_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "no repeat dl-facch",
	      NO_STR REP_ACCH_STR
	      "Disable DL-FACCH repetition for this BTS\n")
{
	struct gsm_bts *bts = vty->index;

	bts->rep_acch_cap.dl_facch_cmd = false;
	bts->rep_acch_cap.dl_facch_all = false;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_rep_ul_dl_sacch,
	      cfg_bts_rep_ul_dl_sacch_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "repeat (ul-sacch|dl-sacch)",
	      REP_ACCH_STR
	      "Enable UL-SACCH repetition for this BTS\n"
	      "Enable DL-SACCH repetition for this BTS\n")
{
	struct gsm_bts *bts = vty->index;

	if (bts->model->type != GSM_BTS_TYPE_OSMOBTS) {
		vty_out(vty, "%% repeated ACCH not supported by BTS %u%s",
			bts->nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (strcmp(argv[0], "ul-sacch") == 0)
		bts->rep_acch_cap.ul_sacch = true;
	else
		bts->rep_acch_cap.dl_sacch = true;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_rep_no_ul_dl_sacch,
	      cfg_bts_rep_no_ul_dl_sacch_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "no repeat (ul-sacch|dl-sacch)",
	      NO_STR REP_ACCH_STR
	      "Disable UL-SACCH repetition for this BTS\n"
	      "Disable DL-SACCH repetition for this BTS\n")
{
	struct gsm_bts *bts = vty->index;

	if (strcmp(argv[0], "ul-sacch") == 0)
		bts->rep_acch_cap.ul_sacch = false;
	else
		bts->rep_acch_cap.dl_sacch = false;

	return CMD_SUCCESS;
}

/* See 3GPP TS 45.008, section 8.2.4 */
#define RXQUAL_THRESH_CMD \
	"rxqual (0|1|2|3|4|5|6|7)"
#define RXQUAL_THRESH_CMD_DESC \
	"Set RxQual (BER) threshold (default 4)\n" \
	"BER >= 0% (always on)\n" \
	"BER >= 0.2%\n" \
	"BER >= 0.4%\n" \
	"BER >= 0.8%\n" \
	"BER >= 1.6% (default)\n" \
	"BER >= 3.2%\n" \
	"BER >= 6.4%\n" \
	"BER >= 12.8%\n"

DEFUN_USRATTR(cfg_bts_rep_rxqual,
	      cfg_bts_rep_rxqual_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "repeat " RXQUAL_THRESH_CMD,
	      REP_ACCH_STR RXQUAL_THRESH_CMD_DESC)
{
	struct gsm_bts *bts = vty->index;

	if (bts->model->type != GSM_BTS_TYPE_OSMOBTS) {
		vty_out(vty, "%% repeated ACCH not supported by BTS %u%s",
			bts->nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* See also: GSM 05.08, section 8.2.4 */
	bts->rep_acch_cap.rxqual = atoi(argv[0]);

	return CMD_SUCCESS;
}

#define TOP_ACCH_STR "Temporary ACCH overpower\n"

DEFUN_USRATTR(cfg_bts_top_dl_acch,
	      cfg_bts_top_dl_acch_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "overpower (dl-acch|dl-sacch|dl-facch) <1-4>",
	      TOP_ACCH_STR
	      "Enable overpower for both SACCH and FACCH\n"
	      "Enable overpower for SACCH only\n"
	      "Enable overpower for FACCH only\n"
	      "Overpower value in dB\n")
{
	struct gsm_bts *bts = vty->index;

	if (bts->model->type != GSM_BTS_TYPE_OSMOBTS) {
		vty_out(vty, "%% ACCH overpower is not supported by BTS %u%s",
			bts->nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts->top_acch_cap.sacch_enable = 0;
	bts->top_acch_cap.facch_enable = 0;

	if (!strcmp(argv[0], "dl-acch") || !strcmp(argv[0], "dl-sacch"))
		bts->top_acch_cap.sacch_enable = 1;
	if (!strcmp(argv[0], "dl-acch") || !strcmp(argv[0], "dl-facch"))
		bts->top_acch_cap.facch_enable = 1;

	bts->top_acch_cap.overpower_db = atoi(argv[1]);

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_top_no_dl_acch,
	      cfg_bts_top_no_dl_acch_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "no overpower dl-acch",
	      NO_STR TOP_ACCH_STR
	      "Disable ACCH overpower for this BTS\n")
{
	struct gsm_bts *bts = vty->index;

	bts->top_acch_cap.overpower_db = 0;
	bts->top_acch_cap.sacch_enable = 0;
	bts->top_acch_cap.facch_enable = 0;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_top_dl_acch_rxqual,
	      cfg_bts_top_dl_acch_rxqual_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "overpower " RXQUAL_THRESH_CMD,
	      TOP_ACCH_STR RXQUAL_THRESH_CMD_DESC)
{
	struct gsm_bts *bts = vty->index;

	if (bts->model->type != GSM_BTS_TYPE_OSMOBTS) {
		vty_out(vty, "%% ACCH overpower is not supported by BTS %u%s",
			bts->nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts->top_acch_cap.rxqual = atoi(argv[0]);

	return CMD_SUCCESS;
}

static const struct value_string top_acch_chan_mode_name[] = {
	{ TOP_ACCH_CHAN_MODE_ANY,		"any" },
	{ TOP_ACCH_CHAN_MODE_SPEECH_V3,		"speech-amr" },
	{ 0, NULL }
};

DEFUN_USRATTR(cfg_bts_top_dl_acch_chan_mode,
	      cfg_bts_top_dl_acch_chan_mode_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "overpower chan-mode (speech-amr|any)",
	      TOP_ACCH_STR
	      "Allow temporary overpower for specific Channel mode(s)\n"
	      "Speech channels using AMR codec (default)\n"
	      "Any kind of channel mode\n")
{
	struct gsm_bts *bts = vty->index;

	if (bts->model->type != GSM_BTS_TYPE_OSMOBTS) {
		vty_out(vty, "%% ACCH overpower is not supported by BTS %u%s",
			bts->nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts->top_acch_chan_mode = get_string_value(top_acch_chan_mode_name, argv[0]);

	return CMD_SUCCESS;
}

#define CD_STR "Channel Description\n"

DEFUN_USRATTR(cfg_bts_chan_desc_att,
	      cfg_bts_chan_desc_att_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "channel-description attach (0|1)",
	      CD_STR
	      "Set if attachment is required\n"
	      "Attachment is NOT required\n"
	      "Attachment is required (standard)\n")
{
	struct gsm_bts *bts = vty->index;
	bts->si_common.chan_desc.att = atoi(argv[0]);
	return CMD_SUCCESS;
}
ALIAS_DEPRECATED(cfg_bts_chan_desc_att,
		 cfg_bts_chan_dscr_att_cmd,
		 "channel-descrption attach (0|1)",
		 CD_STR
		 "Set if attachment is required\n"
		 "Attachment is NOT required\n"
		 "Attachment is required (standard)\n");

DEFUN_USRATTR(cfg_bts_chan_desc_bs_pa_mfrms,
	      cfg_bts_chan_desc_bs_pa_mfrms_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "channel-description bs-pa-mfrms <2-9>",
	      CD_STR
	      "Set number of multiframe periods for paging groups\n"
	      "Number of multiframe periods for paging groups\n")
{
	struct gsm_bts *bts = vty->index;
	int bs_pa_mfrms = atoi(argv[0]);

	bts->si_common.chan_desc.bs_pa_mfrms = bs_pa_mfrms - 2;
	return CMD_SUCCESS;
}
ALIAS_DEPRECATED(cfg_bts_chan_desc_bs_pa_mfrms,
		 cfg_bts_chan_dscr_bs_pa_mfrms_cmd,
		 "channel-descrption bs-pa-mfrms <2-9>",
		 CD_STR
		 "Set number of multiframe periods for paging groups\n"
		 "Number of multiframe periods for paging groups\n");

DEFUN_USRATTR(cfg_bts_chan_desc_bs_ag_blks_res,
	      cfg_bts_chan_desc_bs_ag_blks_res_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "channel-description bs-ag-blks-res <0-7>",
	      CD_STR
	      "Set number of blocks reserved for access grant\n"
	      "Number of blocks reserved for access grant\n")
{
	struct gsm_bts *bts = vty->index;
	int bs_ag_blks_res = atoi(argv[0]);

	bts->si_common.chan_desc.bs_ag_blks_res = bs_ag_blks_res;
	return CMD_SUCCESS;
}
ALIAS_DEPRECATED(cfg_bts_chan_desc_bs_ag_blks_res,
		 cfg_bts_chan_dscr_bs_ag_blks_res_cmd,
		 "channel-descrption bs-ag-blks-res <0-7>",
		 CD_STR
		 "Set number of blocks reserved for access grant\n"
		 "Number of blocks reserved for access grant\n");

#define CCCH_STR "Common Control Channel\n"

DEFUN_USRATTR(cfg_bts_ccch_load_ind_thresh,
	      cfg_bts_ccch_load_ind_thresh_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "ccch load-indication-threshold <0-100>",
	      CCCH_STR
	      "Percentage of CCCH load at which BTS sends RSL CCCH LOAD IND\n"
	      "CCCH Load Threshold in percent (Default: 10)\n")
{
	struct gsm_bts *bts = vty->index;
	bts->ccch_load_ind_thresh = atoi(argv[0]);
	return CMD_SUCCESS;
}

#define NM_STR "Network Management\n"

DEFUN_USRATTR(cfg_bts_rach_nm_b_thresh,
	      cfg_bts_rach_nm_b_thresh_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "rach nm busy threshold <0-255>",
	      RACH_STR NM_STR
	      "Set the NM Busy Threshold\n"
	      "Set the NM Busy Threshold\n"
	      "NM Busy Threshold in dB\n")
{
	struct gsm_bts *bts = vty->index;
	bts->rach_b_thresh = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_rach_nm_ldavg,
	      cfg_bts_rach_nm_ldavg_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "rach nm load average <0-65535>",
	      RACH_STR NM_STR
	      "Set the NM Loadaverage Slots value\n"
	      "Set the NM Loadaverage Slots value\n"
	      "NM Loadaverage Slots value\n")
{
	struct gsm_bts *bts = vty->index;
	bts->rach_ldavg_slots = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_cell_barred,
	      cfg_bts_cell_barred_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "cell barred (0|1)",
	      "Should this cell be barred from access?\n"
	      "Should this cell be barred from access?\n"
	      "Cell should NOT be barred\n"
	      "Cell should be barred\n")

{
	struct gsm_bts *bts = vty->index;

	bts->si_common.rach_control.cell_bar = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_rach_ec_allowed,
	      cfg_bts_rach_ec_allowed_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "rach emergency call allowed (0|1)",
	      RACH_STR
	      "Should this cell allow emergency calls?\n"
	      "Should this cell allow emergency calls?\n"
	      "Should this cell allow emergency calls?\n"
	      "Do NOT allow emergency calls\n"
	      "Allow emergency calls\n")
{
	struct gsm_bts *bts = vty->index;

	if (atoi(argv[0]) == 0)
		bts->si_common.rach_control.t2 |= 0x4;
	else
		bts->si_common.rach_control.t2 &= ~0x4;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_rach_re_allowed,
	      cfg_bts_rach_re_allowed_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "rach call-reestablishment allowed (0|1)",
	      RACH_STR
	      "Resume calls after radio link failure\n"
	      "Resume calls after radio link failure\n"
	      "Forbid MS to reestablish calls\n"
	      "Allow MS to try to reestablish calls\n")
{
	struct gsm_bts *bts = vty->index;

	if (atoi(argv[0]) == 0)
		bts->si_common.rach_control.re = 1;
	else
		bts->si_common.rach_control.re = 0;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_rach_ac_class,
	      cfg_bts_rach_ac_class_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "rach access-control-class (0|1|2|3|4|5|6|7|8|9|11|12|13|14|15) (barred|allowed)",
	      RACH_STR
	      "Set access control class\n"
	      "Access control class 0\n"
	      "Access control class 1\n"
	      "Access control class 2\n"
	      "Access control class 3\n"
	      "Access control class 4\n"
	      "Access control class 5\n"
	      "Access control class 6\n"
	      "Access control class 7\n"
	      "Access control class 8\n"
	      "Access control class 9\n"
	      "Access control class 11 for PLMN use\n"
	      "Access control class 12 for security services\n"
	      "Access control class 13 for public utilities (e.g. water/gas suppliers)\n"
	      "Access control class 14 for emergency services\n"
	      "Access control class 15 for PLMN staff\n"
	      "barred to use access control class\n"
	      "allowed to use access control class\n")
{
	struct gsm_bts *bts = vty->index;

	uint8_t control_class;
	uint8_t allowed = 0;

	if (strcmp(argv[1], "allowed") == 0)
		allowed = 1;

	control_class = atoi(argv[0]);
	if (control_class < 8)
		if (allowed)
			bts->si_common.rach_control.t3 &= ~(0x1 << control_class);
		else
			bts->si_common.rach_control.t3 |= (0x1 << control_class);
	else
		if (allowed)
			bts->si_common.rach_control.t2 &= ~(0x1 << (control_class - 8));
		else
			bts->si_common.rach_control.t2 |= (0x1 << (control_class - 8));

	if (control_class < 10)
		acc_mgr_perm_subset_changed(&bts->acc_mgr, &bts->si_common.rach_control);

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_ms_max_power,
	      cfg_bts_ms_max_power_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "ms max power <0-40>",
	      "MS Options\n"
	      "Maximum transmit power of the MS\n"
	      "Maximum transmit power of the MS\n"
	      "Maximum transmit power of the MS in dBm\n")
{
	struct gsm_bts *bts = vty->index;

	bts->ms_max_power = atoi(argv[0]);

	return CMD_SUCCESS;
}

#define CELL_STR "Cell Parameters\n"

DEFUN_USRATTR(cfg_bts_cell_resel_hyst,
	      cfg_bts_cell_resel_hyst_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "cell reselection hysteresis <0-14>",
	      CELL_STR "Cell re-selection parameters\n"
	      "Cell Re-Selection Hysteresis in dB\n"
	      "Cell Re-Selection Hysteresis in dB\n")
{
	struct gsm_bts *bts = vty->index;

	bts->si_common.cell_sel_par.cell_resel_hyst = atoi(argv[0])/2;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_rxlev_acc_min,
	      cfg_bts_rxlev_acc_min_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "rxlev access min <0-63>",
	      "Minimum RxLev needed for cell access\n"
	      "Minimum RxLev needed for cell access\n"
	      "Minimum RxLev needed for cell access\n"
	      "Minimum RxLev needed for cell access (better than -110dBm)\n")
{
	struct gsm_bts *bts = vty->index;

	bts->si_common.cell_sel_par.rxlev_acc_min = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_cell_bar_qualify,
	      cfg_bts_cell_bar_qualify_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "cell bar qualify (0|1)",
	      CELL_STR "Cell Bar Qualify\n" "Cell Bar Qualify\n"
	      "Set CBQ to 0\n" "Set CBQ to 1\n")
{
	struct gsm_bts *bts = vty->index;

	bts->si_common.cell_ro_sel_par.present = 1;
	bts->si_common.cell_ro_sel_par.cbq = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_cell_resel_ofs,
	      cfg_bts_cell_resel_ofs_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "cell reselection offset <0-126>",
	      CELL_STR "Cell Re-Selection Parameters\n"
	      "Cell Re-Selection Offset (CRO) in dB\n"
	      "Cell Re-Selection Offset (CRO) in dB\n")
{
	struct gsm_bts *bts = vty->index;

	bts->si_common.cell_ro_sel_par.present = 1;
	bts->si_common.cell_ro_sel_par.cell_resel_off = atoi(argv[0])/2;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_temp_ofs,
	      cfg_bts_temp_ofs_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "temporary offset <0-60>",
	      "Cell selection temporary negative offset\n"
	      "Cell selection temporary negative offset\n"
	      "Cell selection temporary negative offset in dB\n")
{
	struct gsm_bts *bts = vty->index;

	bts->si_common.cell_ro_sel_par.present = 1;
	bts->si_common.cell_ro_sel_par.temp_offs = atoi(argv[0])/10;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_temp_ofs_inf,
	      cfg_bts_temp_ofs_inf_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "temporary offset infinite",
	      "Cell selection temporary negative offset\n"
	      "Cell selection temporary negative offset\n"
	      "Sets cell selection temporary negative offset to infinity\n")
{
	struct gsm_bts *bts = vty->index;

	bts->si_common.cell_ro_sel_par.present = 1;
	bts->si_common.cell_ro_sel_par.temp_offs = 7;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_penalty_time,
	      cfg_bts_penalty_time_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "penalty time <20-620>",
	      "Cell selection penalty time\n"
	      "Cell selection penalty time\n"
	      "Cell selection penalty time in seconds (by 20s increments)\n")
{
	struct gsm_bts *bts = vty->index;

	bts->si_common.cell_ro_sel_par.present = 1;
	bts->si_common.cell_ro_sel_par.penalty_time = (atoi(argv[0])-20)/20;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_penalty_time_rsvd,
	      cfg_bts_penalty_time_rsvd_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "penalty time reserved",
	      "Cell selection penalty time\n"
	      "Cell selection penalty time\n"
	      "Set cell selection penalty time to reserved value 31, "
		    "(indicate that CELL_RESELECT_OFFSET is subtracted from C2 "
		    "and TEMPORARY_OFFSET is ignored)\n")
{
	struct gsm_bts *bts = vty->index;

	bts->si_common.cell_ro_sel_par.present = 1;
	bts->si_common.cell_ro_sel_par.penalty_time = 31;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_radio_link_timeout,
	      cfg_bts_radio_link_timeout_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "radio-link-timeout <4-64>",
	      "Radio link timeout criterion (BTS side)\n"
	      "Radio link timeout value (lost SACCH block)\n")
{
	struct gsm_bts *bts = vty->index;

	gsm_bts_set_radio_link_timeout(bts, atoi(argv[0]));

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_radio_link_timeout_inf,
	      cfg_bts_radio_link_timeout_inf_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "radio-link-timeout infinite",
	      "Radio link timeout criterion (BTS side)\n"
	      "Infinite Radio link timeout value (use only for BTS RF testing)\n")
{
	struct gsm_bts *bts = vty->index;

	if (bts->type != GSM_BTS_TYPE_OSMOBTS) {
		vty_out(vty, "%% infinite radio link timeout not supported by BTS %u%s", bts->nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty_out(vty, "%% INFINITE RADIO LINK TIMEOUT, USE ONLY FOR BTS RF TESTING%s", VTY_NEWLINE);
	gsm_bts_set_radio_link_timeout(bts, -1);

	return CMD_SUCCESS;
}

#define GPRS_TEXT	"GPRS Packet Network\n"

#define GPRS_CHECK_ENABLED(bts) \
	do { \
		if (bts->gprs.mode == BTS_GPRS_NONE) { \
			vty_out(vty, "%% GPRS is not enabled on BTS %u%s", \
				bts->nr, VTY_NEWLINE); \
			return CMD_WARNING; \
		} \
	} while (0)

DEFUN_USRATTR(cfg_bts_prs_bvci,
	      cfg_bts_gprs_bvci_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "gprs cell bvci <2-65535>",
	      GPRS_TEXT
	      "GPRS Cell Settings\n"
	      "GPRS BSSGP VC Identifier\n"
	      "GPRS BSSGP VC Identifier\n")
{
	/* ETSI TS 101 343: values 0 and 1 are reserved for signalling and PTM */
	struct gsm_bts *bts = vty->index;

	GPRS_CHECK_ENABLED(bts);

	bts->gprs.cell.bvci = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_gprs_nsei,
	      cfg_bts_gprs_nsei_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "gprs nsei <0-65535>",
	      GPRS_TEXT
	      "GPRS NS Entity Identifier\n"
	      "GPRS NS Entity Identifier\n")
{
	struct gsm_bts *bts = vty->index;

	GPRS_CHECK_ENABLED(bts);

	bts->site_mgr->gprs.nse.nsei = atoi(argv[0]);

	return CMD_SUCCESS;
}

#define NSVC_TEXT "Network Service Virtual Connection (NS-VC)\n" \
		"NSVC Logical Number\n"

DEFUN_USRATTR(cfg_bts_gprs_nsvci,
	      cfg_bts_gprs_nsvci_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "gprs nsvc <0-1> nsvci <0-65535>",
	      GPRS_TEXT NSVC_TEXT
	      "NS Virtual Connection Identifier\n"
	      "GPRS NS VC Identifier\n")
{
	struct gsm_bts *bts = vty->index;
	int idx = atoi(argv[0]);

	GPRS_CHECK_ENABLED(bts);

	bts->site_mgr->gprs.nsvc[idx].nsvci = atoi(argv[1]);

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_gprs_nsvc_lport,
	      cfg_bts_gprs_nsvc_lport_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "gprs nsvc <0-1> local udp port <0-65535>",
	      GPRS_TEXT NSVC_TEXT
	      "GPRS NS Local UDP Port\n"
	      "GPRS NS Local UDP Port\n"
	      "GPRS NS Local UDP Port\n"
	      "GPRS NS Local UDP Port Number\n")
{
	struct gsm_bts *bts = vty->index;
	int idx = atoi(argv[0]);

	GPRS_CHECK_ENABLED(bts);

	bts->site_mgr->gprs.nsvc[idx].local_port = atoi(argv[1]);

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_gprs_nsvc_rport,
	      cfg_bts_gprs_nsvc_rport_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "gprs nsvc <0-1> remote udp port <0-65535>",
	      GPRS_TEXT NSVC_TEXT
	      "GPRS NS Remote UDP Port\n"
	      "GPRS NS Remote UDP Port\n"
	      "GPRS NS Remote UDP Port\n"
	      "GPRS NS Remote UDP Port Number\n")
{
	struct gsm_bts *bts = vty->index;
	int idx = atoi(argv[0]);

	GPRS_CHECK_ENABLED(bts);

	/* sockaddr_in and sockaddr_in6 have the port at the same position */
	bts->site_mgr->gprs.nsvc[idx].remote.u.sin.sin_port = htons(atoi(argv[1]));

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_gprs_nsvc_rip,
	      cfg_bts_gprs_nsvc_rip_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "gprs nsvc <0-1> remote ip " VTY_IPV46_CMD,
	      GPRS_TEXT NSVC_TEXT
	      "GPRS NS Remote IP Address\n"
	      "GPRS NS Remote IP Address\n"
	      "GPRS NS Remote IPv4 Address\n"
	      "GPRS NS Remote IPv6 Address\n")
{
	struct gsm_bts *bts = vty->index;
	struct osmo_sockaddr_str remote;
	int idx = atoi(argv[0]);
	int ret;

	GPRS_CHECK_ENABLED(bts);

	ret = osmo_sockaddr_str_from_str2(&remote, argv[1]);
	if (ret) {
		vty_out(vty, "%% Invalid IP address %s%s", argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* Can't use osmo_sockaddr_str_to_sockaddr() because the port would be overridden */
	bts->site_mgr->gprs.nsvc[idx].remote.u.sas.ss_family = remote.af;
	switch (remote.af) {
	case AF_INET:
		osmo_sockaddr_str_to_in_addr(&remote, &bts->site_mgr->gprs.nsvc[idx].remote.u.sin.sin_addr);
		break;
	case AF_INET6:
		osmo_sockaddr_str_to_in6_addr(&remote, &bts->site_mgr->gprs.nsvc[idx].remote.u.sin6.sin6_addr);
		break;
	}

	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_bts_pag_free, cfg_bts_pag_free_cmd,
	   "paging free <-1-1024>",
	   "Paging options\n"
	   "Only page when having a certain amount of free slots\n"
	   "amount of required free paging slots. -1 to disable\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct gsm_bts *bts = vty->index;

	bts->paging.free_chans_need = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_gprs_ns_timer,
	      cfg_bts_gprs_ns_timer_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "gprs ns timer " NS_TIMERS " <0-255>",
	      GPRS_TEXT "Network Service\n"
	      "Network Service Timer\n"
	      NS_TIMERS_HELP "Timer Value\n")
{
	struct gsm_bts *bts = vty->index;
	int idx = get_string_value(gprs_ns_timer_strs, argv[0]);
	int val = atoi(argv[1]);

	GPRS_CHECK_ENABLED(bts);

	if (idx < 0 || idx >= ARRAY_SIZE(bts->site_mgr->gprs.nse.timer))
		return CMD_WARNING;

	bts->site_mgr->gprs.nse.timer[idx] = val;

	return CMD_SUCCESS;
}

#define BSSGP_TIMERS "(blocking-timer|blocking-retries|unblocking-retries|reset-timer|reset-retries|suspend-timer|suspend-retries|resume-timer|resume-retries|capability-update-timer|capability-update-retries)"
#define BSSGP_TIMERS_HELP	\
	"Tbvc-block timeout\n"			\
	"Tbvc-block retries\n"			\
	"Tbvc-unblock retries\n"		\
	"Tbvcc-reset timeout\n"			\
	"Tbvc-reset retries\n"			\
	"Tbvc-suspend timeout\n"		\
	"Tbvc-suspend retries\n"		\
	"Tbvc-resume timeout\n"			\
	"Tbvc-resume retries\n"			\
	"Tbvc-capa-update timeout\n"		\
	"Tbvc-capa-update retries\n"

DEFUN_USRATTR(cfg_bts_gprs_cell_timer,
	      cfg_bts_gprs_cell_timer_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "gprs cell timer " BSSGP_TIMERS " <0-255>",
	      GPRS_TEXT "Cell / BSSGP\n"
	      "Cell/BSSGP Timer\n"
	      BSSGP_TIMERS_HELP "Timer Value\n")
{
	struct gsm_bts *bts = vty->index;
	int idx = get_string_value(gprs_bssgp_cfg_strs, argv[0]);
	int val = atoi(argv[1]);

	GPRS_CHECK_ENABLED(bts);

	if (idx < 0 || idx >= ARRAY_SIZE(bts->gprs.cell.timer))
		return CMD_WARNING;

	bts->gprs.cell.timer[idx] = val;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_gprs_rac,
	      cfg_bts_gprs_rac_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "gprs routing area <0-255>",
	      GPRS_TEXT
	      "GPRS Routing Area Code\n"
	      "GPRS Routing Area Code\n"
	      "GPRS Routing Area Code\n")
{
	struct gsm_bts *bts = vty->index;

	GPRS_CHECK_ENABLED(bts);

	bts->gprs.rac = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_gprs_ctrl_ack,
	      cfg_bts_gprs_ctrl_ack_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "gprs control-ack-type-rach",
	      GPRS_TEXT
	      "Set GPRS Control Ack Type for PACKET CONTROL ACKNOWLEDGMENT message to "
	      "four access bursts format instead of default RLC/MAC control block\n")
{
	struct gsm_bts *bts = vty->index;

	GPRS_CHECK_ENABLED(bts);

	bts->gprs.ctrl_ack_type_use_block = false;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_gprs_ccn_active,
	      cfg_bts_gprs_ccn_active_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "gprs ccn-active (0|1|default)",
	      GPRS_TEXT
	      "Set CCN_ACTIVE in the GPRS Cell Options IE on the BCCH (SI13)\n"
	      "Disable\n" "Enable\n" "Default based on BTS type support\n")
{
	struct gsm_bts *bts = vty->index;

	bts->gprs.ccn.forced_vty = strcmp(argv[0], "default") != 0;

	if (bts->gprs.ccn.forced_vty)
		bts->gprs.ccn.active = argv[0][0] == '1';

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_gprs_pwr_ctrl_alpha,
	      cfg_bts_gprs_pwr_ctrl_alpha_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "gprs power-control alpha <0-10>",
	      GPRS_TEXT
	      "GPRS Global Power Control Parameters IE (SI13)\n"
	      "Set alpha\n"
	      "alpha for MS output power control in units of 0.1 (defaults to 0)\n")
{
	struct gsm_bts *bts = vty->index;

	bts->gprs.pwr_ctrl.alpha = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_no_bts_gprs_ctrl_ack,
	      cfg_no_bts_gprs_ctrl_ack_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "no gprs control-ack-type-rach",
	      NO_STR GPRS_TEXT
	      "Set GPRS Control Ack Type for PACKET CONTROL ACKNOWLEDGMENT message to "
	      "default RLC/MAC control block\n")
{
	struct gsm_bts *bts = vty->index;

	GPRS_CHECK_ENABLED(bts);

	bts->gprs.ctrl_ack_type_use_block = true;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_gprs_net_ctrl_ord,
	      cfg_bts_gprs_net_ctrl_ord_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "gprs network-control-order (nc0|nc1|nc2)",
	      GPRS_TEXT
	      "GPRS Network Control Order\n"
	      "MS controlled cell re-selection, no measurement reporting\n"
	      "MS controlled cell re-selection, MS sends measurement reports\n"
	      "Network controlled cell re-selection, MS sends measurement reports\n")
{
	struct gsm_bts *bts = vty->index;

	GPRS_CHECK_ENABLED(bts);

	bts->gprs.net_ctrl_ord = atoi(argv[0] + 2);

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_gprs_mode,
	      cfg_bts_gprs_mode_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "gprs mode (none|gprs|egprs)",
	      GPRS_TEXT
	      "GPRS Mode for this BTS\n"
	      "GPRS Disabled on this BTS\n"
	      "GPRS Enabled on this BTS\n"
	      "EGPRS (EDGE) Enabled on this BTS\n")
{
	struct gsm_bts *bts = vty->index;
	enum bts_gprs_mode mode = bts_gprs_mode_parse(argv[0], NULL);

	if (!bts_gprs_mode_is_compat(bts, mode)) {
		vty_out(vty, "%% This BTS type does not support %s%s", argv[0],
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts->gprs.mode = mode;

	return CMD_SUCCESS;
}

DEFUN_DEPRECATED(cfg_bts_gprs_11bit_rach_support_for_egprs,
	cfg_bts_gprs_11bit_rach_support_for_egprs_cmd,
	"gprs 11bit_rach_support_for_egprs (0|1)",
	GPRS_TEXT "EGPRS Packet Channel Request support\n"
	"Disable EGPRS Packet Channel Request support\n"
	"Enable EGPRS Packet Channel Request support\n")
{
	struct gsm_bts *bts = vty->index;

	vty_out(vty, "%% 'gprs 11bit_rach_support_for_egprs' is now deprecated: "
		"use '[no] gprs egprs-packet-channel-request' instead%s", VTY_NEWLINE);

	bts->gprs.egprs_pkt_chan_request = (argv[0][0] == '1');

	if (bts->gprs.mode == BTS_GPRS_NONE && bts->gprs.egprs_pkt_chan_request) {
		vty_out(vty, "%% (E)GPRS is not enabled (see 'gprs mode')%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (bts->gprs.mode != BTS_GPRS_EGPRS) {
		vty_out(vty, "%% EGPRS Packet Channel Request support requires "
			"EGPRS mode to be enabled (see 'gprs mode')%s", VTY_NEWLINE);
		/* Do not return here, keep the old behaviour. */
	}

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_gprs_egprs_pkt_chan_req,
	      cfg_bts_gprs_egprs_pkt_chan_req_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "gprs egprs-packet-channel-request",
	      GPRS_TEXT "EGPRS Packet Channel Request support")
{
	struct gsm_bts *bts = vty->index;

	if (bts->gprs.mode != BTS_GPRS_EGPRS) {
		vty_out(vty, "%% EGPRS Packet Channel Request support requires "
			"EGPRS mode to be enabled (see 'gprs mode')%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts->gprs.egprs_pkt_chan_request = true;
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_no_gprs_egprs_pkt_chan_req,
	      cfg_bts_no_gprs_egprs_pkt_chan_req_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "no gprs egprs-packet-channel-request",
	      NO_STR GPRS_TEXT "EGPRS Packet Channel Request support")
{
	struct gsm_bts *bts = vty->index;

	if (bts->gprs.mode != BTS_GPRS_EGPRS) {
		vty_out(vty, "%% EGPRS Packet Channel Request support requires "
			"EGPRS mode to be enabled (see 'gprs mode')%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts->gprs.egprs_pkt_chan_request = false;
	return CMD_SUCCESS;
}

#define SI_TEXT		"System Information Messages\n"
#define SI_TYPE_TEXT "(1|2|3|4|5|6|7|8|9|10|13|16|17|18|19|20|2bis|2ter|2quater|5bis|5ter)"
#define SI_TYPE_HELP 	"System Information Type 1\n"	\
			"System Information Type 2\n"	\
			"System Information Type 3\n"	\
			"System Information Type 4\n"	\
			"System Information Type 5\n"	\
			"System Information Type 6\n"	\
			"System Information Type 7\n"	\
			"System Information Type 8\n"	\
			"System Information Type 9\n"	\
			"System Information Type 10\n"	\
			"System Information Type 13\n"	\
			"System Information Type 16\n"	\
			"System Information Type 17\n"	\
			"System Information Type 18\n"	\
			"System Information Type 19\n"	\
			"System Information Type 20\n"	\
			"System Information Type 2bis\n"	\
			"System Information Type 2ter\n"	\
			"System Information Type 2quater\n"	\
			"System Information Type 5bis\n"	\
			"System Information Type 5ter\n"

DEFUN_USRATTR(cfg_bts_si_mode,
	      cfg_bts_si_mode_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "system-information " SI_TYPE_TEXT " mode (static|computed)",
	      SI_TEXT SI_TYPE_HELP
	      "System Information Mode\n"
	      "Static user-specified\n"
	      "Dynamic, BSC-computed\n")
{
	struct gsm_bts *bts = vty->index;
	int type;

	type = get_string_value(osmo_sitype_strs, argv[0]);
	if (type < 0) {
		vty_out(vty, "%% Error SI Type%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!strcmp(argv[1], "static"))
		bts->si_mode_static |= (1 << type);
	else
		bts->si_mode_static &= ~(1 << type);

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_si_static,
	      cfg_bts_si_static_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "system-information " SI_TYPE_TEXT " static HEXSTRING",
	      SI_TEXT SI_TYPE_HELP
	      "Static System Information filling\n"
	      "Static user-specified SI content in HEX notation\n")
{
	struct gsm_bts *bts = vty->index;
	int rc, type;

	type = get_string_value(osmo_sitype_strs, argv[0]);
	if (type < 0) {
		vty_out(vty, "%% Error SI Type%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!(bts->si_mode_static & (1 << type))) {
		vty_out(vty, "%% SI Type %s is not configured in static mode%s",
			get_value_string(osmo_sitype_strs, type), VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* Fill buffer with padding pattern */
	memset(GSM_BTS_SI(bts, type), 0x2b, GSM_MACBLOCK_LEN);

	/* Parse the user-specified SI in hex format, [partially] overwriting padding */
	rc = osmo_hexparse(argv[1], GSM_BTS_SI(bts, type), GSM_MACBLOCK_LEN);
	if (rc < 0 || rc > GSM_MACBLOCK_LEN) {
		vty_out(vty, "%% Error parsing HEXSTRING%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* Mark this SI as present */
	bts->si_valid |= (1 << type);

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_si_unused_send_empty,
	      cfg_bts_si_unused_send_empty_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "system-information unused-send-empty",
	      SI_TEXT
	      "Send BCCH Info with empty 'Full BCCH Info' TLV to notify disabled SI. "
	      "Some nanoBTS fw versions are known to fail upon receival of these messages.\n")
{
	struct gsm_bts *bts = vty->index;

	bts->si_unused_send_empty = true;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_no_si_unused_send_empty,
	      cfg_bts_no_si_unused_send_empty_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "no system-information unused-send-empty",
	      NO_STR SI_TEXT
	      "Avoid sending BCCH Info with empty 'Full BCCH Info' TLV to notify disabled SI. "
	      "Some nanoBTS fw versions are known to fail upon receival of these messages.\n")
{
	struct gsm_bts *bts = vty->index;

	if (!is_ipaccess_bts(bts) || is_osmobts(bts)) {
		vty_out(vty, "%% This command is only intended for ipaccess nanoBTS. See OS#3707.%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts->si_unused_send_empty = false;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_early_cm,
	      cfg_bts_early_cm_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "early-classmark-sending (allowed|forbidden)",
	      "Early Classmark Sending\n"
	      "Early Classmark Sending is allowed\n"
	      "Early Classmark Sending is forbidden\n")
{
	struct gsm_bts *bts = vty->index;

	if (!strcmp(argv[0], "allowed"))
		bts->early_classmark_allowed = true;
	else
		bts->early_classmark_allowed = false;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_early_cm_3g,
	      cfg_bts_early_cm_3g_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "early-classmark-sending-3g (allowed|forbidden)",
	      "3G Early Classmark Sending\n"
	      "3G Early Classmark Sending is allowed\n"
	      "3G Early Classmark Sending is forbidden\n")
{
	struct gsm_bts *bts = vty->index;

	if (!strcmp(argv[0], "allowed"))
		bts->early_classmark_allowed_3g = true;
	else
		bts->early_classmark_allowed_3g = false;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_neigh_mode,
	      cfg_bts_neigh_mode_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "neighbor-list mode (automatic|manual|manual-si5)",
	      "Neighbor List\n" "Mode of Neighbor List generation\n"
	      "Automatically from all BTS in this BSC\n" "Manual\n"
	      "Manual with different lists for SI2 and SI5\n")
{
	struct gsm_bts *bts = vty->index;
	int mode = get_string_value(bts_neigh_mode_strs, argv[0]);

	switch (mode) {
	case NL_MODE_MANUAL_SI5SEP:
	case NL_MODE_MANUAL:
		/* make sure we clear the current list when switching to
		 * manual mode */
		if (bts->neigh_list_manual_mode == 0)
			memset(&bts->si_common.data.neigh_list, 0,
				sizeof(bts->si_common.data.neigh_list));
		break;
	default:
		break;
	}

	bts->neigh_list_manual_mode = mode;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_neigh,
	      cfg_bts_neigh_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "neighbor-list (add|del) arfcn <0-1023>",
	      "Neighbor List\n" "Add to manual neighbor list\n"
	      "Delete from manual neighbor list\n" "ARFCN of neighbor\n"
	      "ARFCN of neighbor\n")
{
	struct gsm_bts *bts = vty->index;
	struct bitvec *bv = &bts->si_common.neigh_list;
	uint16_t arfcn = atoi(argv[1]);
	enum gsm_band unused;

	if (bts->neigh_list_manual_mode == NL_MODE_AUTOMATIC) {
		vty_out(vty, "%% Cannot configure neighbor list in "
			"automatic mode%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (gsm_arfcn2band_rc(arfcn, &unused) < 0) {
		vty_out(vty, "%% Invalid arfcn %" PRIu16 " detected%s", arfcn, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!strcmp(argv[0], "add"))
		bitvec_set_bit_pos(bv, arfcn, 1);
	else
		bitvec_set_bit_pos(bv, arfcn, 0);

	return CMD_SUCCESS;
}

/* help text should be kept in sync with EARFCN_*_INVALID defines */
DEFUN_USRATTR(cfg_bts_si2quater_neigh_add,
	      cfg_bts_si2quater_neigh_add_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "si2quater neighbor-list add earfcn <0-65535> thresh-hi <0-31> "
	      "thresh-lo <0-32> prio <0-8> qrxlv <0-32> meas <0-8>",
	      "SI2quater Neighbor List\n" "SI2quater Neighbor List\n"
	      "Add to manual SI2quater neighbor list\n"
	      "EARFCN of neighbor\n" "EARFCN of neighbor\n"
	      "threshold high bits\n" "threshold high bits\n"
	      "threshold low bits\n" "threshold low bits (32 means NA)\n"
	      "priority\n" "priority (8 means NA)\n"
	      "QRXLEVMIN\n" "QRXLEVMIN (32 means NA)\n"
	      "measurement bandwidth\n" "measurement bandwidth (8 means NA)\n")
{
	struct gsm_bts *bts = vty->index;
	struct osmo_earfcn_si2q *e = &bts->si_common.si2quater_neigh_list;
	uint16_t arfcn = atoi(argv[0]);
	uint8_t thresh_hi = atoi(argv[1]), thresh_lo = atoi(argv[2]),
		prio = atoi(argv[3]), qrx = atoi(argv[4]), meas = atoi(argv[5]);
	int r = bts_earfcn_add(bts, arfcn, thresh_hi, thresh_lo, prio, qrx, meas);

	switch (r) {
	case 1:
		vty_out(vty, "%% Warning: multiple threshold-high are not supported, overriding with %u%s",
			thresh_hi, VTY_NEWLINE);
		break;
	case EARFCN_THRESH_LOW_INVALID:
		vty_out(vty, "%% Warning: multiple threshold-low are not supported, overriding with %u%s",
			thresh_lo, VTY_NEWLINE);
		break;
	case EARFCN_QRXLV_INVALID + 1:
		vty_out(vty, "%% Warning: multiple QRXLEVMIN are not supported, overriding with %u%s",
			qrx, VTY_NEWLINE);
		break;
	case EARFCN_PRIO_INVALID:
		vty_out(vty, "%% Warning: multiple priorities are not supported, overriding with %u%s",
			prio, VTY_NEWLINE);
		break;
	default:
		if (r < 0) {
			vty_out(vty, "%% Unable to add ARFCN %u: %s%s", arfcn, strerror(-r), VTY_NEWLINE);
			return CMD_WARNING;
		}
	}

	if (si2q_num(bts) <= SI2Q_MAX_NUM)
		return CMD_SUCCESS;

	vty_out(vty, "%% Warning: not enough space in SI2quater (%u/%u used) for a given EARFCN %u%s",
		bts->si2q_count, SI2Q_MAX_NUM, arfcn, VTY_NEWLINE);
	osmo_earfcn_del(e, arfcn);

	return CMD_WARNING;
}

DEFUN_USRATTR(cfg_bts_si2quater_neigh_del,
	      cfg_bts_si2quater_neigh_del_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "si2quater neighbor-list del earfcn <0-65535>",
	      "SI2quater Neighbor List\n"
	      "SI2quater Neighbor List\n"
	      "Delete from SI2quater manual neighbor list\n"
	      "EARFCN of neighbor\n"
	      "EARFCN\n")
{
	struct gsm_bts *bts = vty->index;
	struct osmo_earfcn_si2q *e = &bts->si_common.si2quater_neigh_list;
	uint16_t arfcn = atoi(argv[0]);
	int r = osmo_earfcn_del(e, arfcn);
	if (r < 0) {
		vty_out(vty, "%% Unable to delete arfcn %u: %s%s", arfcn,
			strerror(-r), VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_si2quater_uarfcn_add,
	      cfg_bts_si2quater_uarfcn_add_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "si2quater neighbor-list add uarfcn <0-16383> <0-511> <0-1>",
	      "SI2quater Neighbor List\n"
	      "SI2quater Neighbor List\n" "Add to manual SI2quater neighbor list\n"
	      "UARFCN of neighbor\n" "UARFCN of neighbor\n" "scrambling code\n"
	      "diversity bit\n")
{
	struct gsm_bts *bts = vty->index;
	uint16_t arfcn = atoi(argv[0]), scramble = atoi(argv[1]);

	switch(bts_uarfcn_add(bts, arfcn, scramble, atoi(argv[2]))) {
	case -ENOMEM:
		vty_out(vty, "%% Unable to add UARFCN: max number of UARFCNs (%u) reached%s",
			MAX_EARFCN_LIST, VTY_NEWLINE);
		return CMD_WARNING;
	case -ENOSPC:
		vty_out(vty, "%% Warning: not enough space in SI2quater for a given UARFCN (%u, %u)%s",
			arfcn, scramble, VTY_NEWLINE);
		return CMD_WARNING;
	case -EADDRINUSE:
		vty_out(vty, "%% Unable to add UARFCN: (%u, %u) is already added%s",
			arfcn, scramble, VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_si2quater_uarfcn_del,
	      cfg_bts_si2quater_uarfcn_del_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "si2quater neighbor-list del uarfcn <0-16383> <0-511>",
	      "SI2quater Neighbor List\n"
	      "SI2quater Neighbor List\n"
	      "Delete from SI2quater manual neighbor list\n"
	      "UARFCN of neighbor\n"
	      "UARFCN\n"
	      "scrambling code\n")
{
	struct gsm_bts *bts = vty->index;

	if (bts_uarfcn_del(bts, atoi(argv[0]), atoi(argv[1])) < 0) {
		vty_out(vty, "%% Unable to delete uarfcn: pair not found%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_si5_neigh,
	      cfg_bts_si5_neigh_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "si5 neighbor-list (add|del) arfcn <0-1023>",
	      "SI5 Neighbor List\n"
	      "SI5 Neighbor List\n" "Add to manual SI5 neighbor list\n"
	      "Delete from SI5 manual neighbor list\n" "ARFCN of neighbor\n"
	      "ARFCN of neighbor\n")
{
	enum gsm_band unused;
	struct gsm_bts *bts = vty->index;
	struct bitvec *bv = &bts->si_common.si5_neigh_list;
	uint16_t arfcn = atoi(argv[1]);

	if (!bts->neigh_list_manual_mode) {
		vty_out(vty, "%% Cannot configure neighbor list in "
			"automatic mode%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (gsm_arfcn2band_rc(arfcn, &unused) < 0) {
		vty_out(vty, "%% Invalid arfcn %" PRIu16 " detected%s", arfcn, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!strcmp(argv[0], "add"))
		bitvec_set_bit_pos(bv, arfcn, 1);
	else
		bitvec_set_bit_pos(bv, arfcn, 0);

	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_bts_pcu_sock,
	   cfg_bts_pcu_sock_cmd,
	   "pcu-socket PATH",
	   "PCU Socket Path for using OsmoPCU co-located with BSC (legacy BTS)\n"
	   "Path in the file system for the unix-domain PCU socket\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct gsm_bts *bts = vty->index;
	int rc;

	osmo_talloc_replace_string(bts, &bts->pcu_sock_path, argv[0]);
	pcu_sock_exit(bts);
	rc = pcu_sock_init(bts->pcu_sock_path, bts);
	if (rc < 0) {
		vty_out(vty, "%% Error creating PCU socket `%s' for BTS %u%s",
			bts->pcu_sock_path, bts->nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_bts_acc_rotate,
	   cfg_bts_acc_rotate_cmd,
	   "access-control-class-rotate <0-10>",
	   "Enable Access Control Class allowed subset rotation\n"
	   "Size of the rotating allowed ACC 0-9 subset (default=10, no subset)\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct gsm_bts *bts = vty->index;
	int len_allowed_adm = atoi(argv[0]);
	acc_mgr_set_len_allowed_adm(&bts->acc_mgr, len_allowed_adm);
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_bts_acc_rotate_quantum,
	   cfg_bts_acc_rotate_quantum_cmd,
	   "access-control-class-rotate-quantum <1-65535>",
	   "Time between rotation of ACC 0-9 generated subsets\n"
	   "Time in seconds (default=" OSMO_STRINGIFY_VAL(ACC_MGR_QUANTUM_DEFAULT) ")\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct gsm_bts *bts = vty->index;
	uint32_t rotation_time_sec = (uint32_t)atoi(argv[0]);
	acc_mgr_set_rotation_time(&bts->acc_mgr, rotation_time_sec);
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_bts_acc_ramping,
	   cfg_bts_acc_ramping_cmd,
	   "access-control-class-ramping",
	   "Enable Access Control Class ramping\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct gsm_bts *bts = vty->index;
	struct gsm_bts_trx *trx;

	if (!acc_ramp_is_enabled(&bts->acc_ramp)) {
		acc_ramp_set_enabled(&bts->acc_ramp, true);
		/* Start ramping if at least one TRX is usable */
		llist_for_each_entry(trx, &bts->trx_list, list) {
			if (trx_is_usable(trx)) {
				acc_ramp_trigger(&bts->acc_ramp);
				break;
			}
		}
	}

	/*
	 * ACC ramping takes effect either when the BTS reconnects RSL,
	 * or when RF administrative state changes to 'unlocked'.
	 */
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_bts_no_acc_ramping,
	   cfg_bts_no_acc_ramping_cmd,
	   "no access-control-class-ramping",
	   NO_STR
	   "Disable Access Control Class ramping\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct gsm_bts *bts = vty->index;

	if (acc_ramp_is_enabled(&bts->acc_ramp)) {
		acc_ramp_abort(&bts->acc_ramp);
		acc_ramp_set_enabled(&bts->acc_ramp, false);
		if (gsm_bts_set_system_infos(bts) != 0) {
			vty_out(vty, "%% Filed to (re)generate System Information "
				"messages, check the logs%s", VTY_NEWLINE);
			return CMD_WARNING;
		}
	}

	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_bts_acc_ramping_step_interval,
	   cfg_bts_acc_ramping_step_interval_cmd,
	   "access-control-class-ramping-step-interval (<"
	   OSMO_STRINGIFY_VAL(ACC_RAMP_STEP_INTERVAL_MIN) "-"
	   OSMO_STRINGIFY_VAL(ACC_RAMP_STEP_INTERVAL_MAX) ">|dynamic)",
	   "Configure Access Control Class ramping step interval\n"
	   "Set a fixed step interval (in seconds)\n"
	   "Use dynamic step interval based on BTS channel load (deprecated, don't use, ignored)\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct gsm_bts *bts = vty->index;
	bool dynamic = (strcmp(argv[0], "dynamic") == 0);
	int error;

	if (dynamic) {
		vty_out(vty, "%% access-control-class-ramping-step-interval 'dynamic' value is deprecated, ignoring it%s", VTY_NEWLINE);
		return CMD_SUCCESS;
	}

	error = acc_ramp_set_step_interval(&bts->acc_ramp, atoi(argv[0]));
	if (error != 0) {
		if (error == -ERANGE)
			vty_out(vty, "%% Unable to set ACC ramp step interval: value out of range%s", VTY_NEWLINE);
		else
			vty_out(vty, "%% Unable to set ACC ramp step interval: unknown error%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_bts_acc_ramping_step_size,
	   cfg_bts_acc_ramping_step_size_cmd,
	   "access-control-class-ramping-step-size (<"
	   OSMO_STRINGIFY_VAL(ACC_RAMP_STEP_SIZE_MIN) "-"
	   OSMO_STRINGIFY_VAL(ACC_RAMP_STEP_SIZE_MAX) ">)",
	   "Configure Access Control Class ramping step size\n"
	   "Set the number of Access Control Classes to enable per ramping step\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct gsm_bts *bts = vty->index;
	int error;

	error = acc_ramp_set_step_size(&bts->acc_ramp, atoi(argv[0]));
	if (error != 0) {
		if (error == -ERANGE)
			vty_out(vty, "%% Unable to set ACC ramp step size: value out of range%s", VTY_NEWLINE);
		else
			vty_out(vty, "%% Unable to set ACC ramp step size: unknown error%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_bts_acc_ramping_chan_load,
	   cfg_bts_acc_ramping_chan_load_cmd,
	   "access-control-class-ramping-chan-load <0-100> <0-100>",
	   "Configure Access Control Class ramping channel load thresholds\n"
	   "Lower Channel load threshold (%) below which subset size of allowed broadcast ACCs can be increased\n"
	   "Upper channel load threshold (%) above which subset size of allowed broadcast ACCs can be decreased\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct gsm_bts *bts = vty->index;
	int rc;

	rc = acc_ramp_set_chan_load_thresholds(&bts->acc_ramp, atoi(argv[0]), atoi(argv[1]));
	if (rc < 0) {
		vty_out(vty, "%% Unable to set ACC channel load thresholds%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

#define EXCL_RFLOCK_STR "Exclude this BTS from the global RF Lock\n"

DEFUN_ATTR(cfg_bts_excl_rf_lock,
	   cfg_bts_excl_rf_lock_cmd,
	   "rf-lock-exclude",
	   EXCL_RFLOCK_STR,
	   CMD_ATTR_IMMEDIATE)
{
	struct gsm_bts *bts = vty->index;
	bts->excl_from_rf_lock = 1;
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_bts_no_excl_rf_lock,
	   cfg_bts_no_excl_rf_lock_cmd,
	   "no rf-lock-exclude",
	   NO_STR EXCL_RFLOCK_STR,
	   CMD_ATTR_IMMEDIATE)
{
	struct gsm_bts *bts = vty->index;
	bts->excl_from_rf_lock = 0;
	return CMD_SUCCESS;
}

#define FORCE_COMB_SI_STR "Force the generation of a single SI (no ter/bis)\n"

DEFUN_USRATTR(cfg_bts_force_comb_si,
	      cfg_bts_force_comb_si_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "force-combined-si",
	      FORCE_COMB_SI_STR)
{
	struct gsm_bts *bts = vty->index;
	bts->force_combined_si = 1;
	bts->force_combined_si_set = true;
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_no_force_comb_si,
	      cfg_bts_no_force_comb_si_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "no force-combined-si",
	      NO_STR FORCE_COMB_SI_STR)
{
	struct gsm_bts *bts = vty->index;
	bts->force_combined_si = 0;
	bts->force_combined_si_set = true;
	return CMD_SUCCESS;
}

static void _get_codec_from_arg(struct vty *vty, int argc, const char *argv[])
{
	struct gsm_bts *bts = vty->index;
	struct bts_codec_conf *codec = &bts->codec;
	int i;

	codec->hr = 0;
	codec->efr = 0;
	codec->amr = 0;
	for (i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "hr"))
			codec->hr = 1;
		if (!strcmp(argv[i], "efr"))
			codec->efr = 1;
		if (!strcmp(argv[i], "amr"))
			codec->amr = 1;
	}
}

#define CODEC_PAR_STR	" (hr|efr|amr)"
#define CODEC_HELP_STR	"Half Rate\n" \
			"Enhanced Full Rate\nAdaptive Multirate\n"

DEFUN_USRATTR(cfg_bts_codec0,
	      cfg_bts_codec0_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "codec-support fr",
	      "Codec Support settings\nFullrate\n")
{
	_get_codec_from_arg(vty, 0, argv);
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_codec1,
	      cfg_bts_codec1_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "codec-support fr" CODEC_PAR_STR,
	      "Codec Support settings\nFullrate\n"
	      CODEC_HELP_STR)
{
	_get_codec_from_arg(vty, 1, argv);
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_codec2,
	      cfg_bts_codec2_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "codec-support fr" CODEC_PAR_STR CODEC_PAR_STR,
	      "Codec Support settings\nFullrate\n"
	      CODEC_HELP_STR CODEC_HELP_STR)
{
	_get_codec_from_arg(vty, 2, argv);
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_codec3,
	      cfg_bts_codec3_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "codec-support fr" CODEC_PAR_STR CODEC_PAR_STR CODEC_PAR_STR,
	      "Codec Support settings\nFullrate\n"
	      CODEC_HELP_STR CODEC_HELP_STR CODEC_HELP_STR)
{
	_get_codec_from_arg(vty, 3, argv);
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_codec4,
	      cfg_bts_codec4_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "codec-support fr" CODEC_PAR_STR CODEC_PAR_STR CODEC_PAR_STR CODEC_PAR_STR,
	      "Codec Support settings\nFullrate\n"
	      CODEC_HELP_STR CODEC_HELP_STR CODEC_HELP_STR CODEC_HELP_STR)
{
	_get_codec_from_arg(vty, 4, argv);
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_bts_depends_on, cfg_bts_depends_on_cmd,
	   "depends-on-bts <0-255>",
	   "This BTS can only be started if another one is up\n"
	   BTS_NR_STR, CMD_ATTR_IMMEDIATE)
{
	struct gsm_bts *bts = vty->index;
	struct gsm_bts *other_bts;
	int dep = atoi(argv[0]);


	if (!is_ipaccess_bts(bts)) {
		vty_out(vty, "%% This feature is only available for IP systems.%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	other_bts = gsm_bts_num(bts->network, dep);
	if (!other_bts || !is_ipaccess_bts(other_bts)) {
		vty_out(vty, "%% This feature is only available for IP systems.%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (dep >= bts->nr) {
		vty_out(vty, "%% Need to depend on an already declared unit.%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts_depend_mark(bts, dep);
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_bts_no_depends_on, cfg_bts_no_depends_on_cmd,
	   "no depends-on-bts <0-255>",
	   NO_STR "This BTS can only be started if another one is up\n"
	   BTS_NR_STR, CMD_ATTR_IMMEDIATE)
{
	struct gsm_bts *bts = vty->index;
	int dep = atoi(argv[0]);

	bts_depend_clear(bts, dep);
	return CMD_SUCCESS;
}

#define AMR_TEXT "Adaptive Multi Rate settings\n"
#define AMR_MODE_TEXT "Codec modes to use with AMR codec\n"
#define AMR_START_TEXT "Initial codec to use with AMR\n" \
	"Automatically\nFirst codec\nSecond codec\nThird codec\nFourth codec\n"
#define AMR_TH_TEXT "AMR threshold between codecs\nMS side\nBTS side\n"
#define AMR_HY_TEXT "AMR hysteresis between codecs\nMS side\nBTS side\n"

static int get_amr_from_arg(struct vty *vty, int argc, const char *argv[], int full)
{
	struct gsm_bts *bts = vty->index;
	struct amr_multirate_conf *mr = (full) ? &bts->mr_full: &bts->mr_half;
	struct gsm48_multi_rate_conf *mr_conf =
				(struct gsm48_multi_rate_conf *) mr->gsm48_ie;
	int i;
	int mode;
	int mode_prev = -1;

	/* Check if mode parameters are in order */
	for (i = 0; i < argc; i++) {
		mode = atoi(argv[i]);
		if (mode_prev > mode) {
			vty_out(vty, "%% Modes must be listed in order%s",
				VTY_NEWLINE);
			return -1;
		}

		if (mode_prev == mode) {
			vty_out(vty, "%% Modes must be unique %s", VTY_NEWLINE);
			return -2;
		}
		mode_prev = mode;
	}

	/* Prepare the multirate configuration IE */
	mr->gsm48_ie[1] = 0;
	for (i = 0; i < argc; i++)
		mr->gsm48_ie[1] |= 1 << atoi(argv[i]);
	mr_conf->icmi = 0;

	/* Store actual mode identifier values */
	for (i = 0; i < argc; i++) {
		mr->ms_mode[i].mode = atoi(argv[i]);
		mr->bts_mode[i].mode = atoi(argv[i]);
	}
	mr->num_modes = argc;

	/* Trim excess threshold and hysteresis values from previous config */
	for (i = argc - 1; i < 4; i++) {
		mr->ms_mode[i].threshold = 0;
		mr->bts_mode[i].threshold = 0;
		mr->ms_mode[i].hysteresis = 0;
		mr->bts_mode[i].hysteresis = 0;
	}
	return 0;
}

static void get_amr_th_from_arg(struct vty *vty, int argc, const char *argv[], int full)
{
	struct gsm_bts *bts = vty->index;
	struct amr_multirate_conf *mr = (full) ? &bts->mr_full: &bts->mr_half;
	struct amr_mode *modes;
	int i;

	modes = argv[0][0]=='m' ? mr->ms_mode : mr->bts_mode;
	for (i = 0; i < argc - 1; i++)
		modes[i].threshold = atoi(argv[i + 1]);
}

static void get_amr_hy_from_arg(struct vty *vty, int argc, const char *argv[], int full)
{
	struct gsm_bts *bts = vty->index;
	struct amr_multirate_conf *mr = (full) ? &bts->mr_full: &bts->mr_half;
	struct amr_mode *modes;
	int i;

	modes = argv[0][0]=='m' ? mr->ms_mode : mr->bts_mode;
	for (i = 0; i < argc - 1; i++)
		modes[i].hysteresis = atoi(argv[i + 1]);
}

static void get_amr_start_from_arg(struct vty *vty, const char *argv[], int full)
{
	struct gsm_bts *bts = vty->index;
	struct amr_multirate_conf *mr = (full) ? &bts->mr_full: &bts->mr_half;
	struct gsm48_multi_rate_conf *mr_conf =
				(struct gsm48_multi_rate_conf *) mr->gsm48_ie;
	int num = 0, i;

	for (i = 0; i < ((full) ? 8 : 6); i++) {
		if ((mr->gsm48_ie[1] & (1 << i))) {
			num++;
		}
	}

	if (argv[0][0] == 'a' || num == 0) {
		mr_conf->icmi = 0;
		mr_conf->smod = 0;
	} else {
		mr_conf->icmi = 1;
		if (num < atoi(argv[0]))
			mr_conf->smod = num - 1;
		else
			mr_conf->smod = atoi(argv[0]) - 1;
	}
}

/* Give the current amr configuration a final consistency check by feeding the
 * the configuration into the gsm48 multirate IE generator function */
static int check_amr_config(struct vty *vty)
{
	int rc = 0;
	struct amr_multirate_conf *mr;
	const struct gsm48_multi_rate_conf *mr_conf;
	struct gsm_bts *bts = vty->index;
	int vty_rc = CMD_SUCCESS;

	mr = &bts->mr_full;
	mr_conf = (struct gsm48_multi_rate_conf*) mr->gsm48_ie;
	rc = gsm48_multirate_config(NULL, mr_conf, mr->ms_mode, mr->num_modes);
	if (rc != 0) {
		vty_out(vty,
			"%% Invalid AMR multirate configuration (tch-f, ms) - check parameters%s",
			VTY_NEWLINE);
		vty_rc = CMD_WARNING;
	}

	rc = gsm48_multirate_config(NULL, mr_conf, mr->bts_mode, mr->num_modes);
	if (rc != 0) {
		vty_out(vty,
			"%% Invalid AMR multirate configuration (tch-f, bts) - check parameters%s",
			VTY_NEWLINE);
		vty_rc = CMD_WARNING;
	}

	mr = &bts->mr_half;
	mr_conf = (struct gsm48_multi_rate_conf*) mr->gsm48_ie;
	rc = gsm48_multirate_config(NULL, mr_conf, mr->ms_mode, mr->num_modes);
	if (rc != 0) {
		vty_out(vty,
			"%% Invalid AMR multirate configuration (tch-h, ms) - check parameters%s",
			VTY_NEWLINE);
		vty_rc = CMD_WARNING;
	}

	rc = gsm48_multirate_config(NULL, mr_conf, mr->bts_mode, mr->num_modes);
	if (rc != 0) {
		vty_out(vty,
			"%% Invalid AMR multirate configuration (tch-h, bts) - check parameters%s",
			VTY_NEWLINE);
		vty_rc = CMD_WARNING;
	}

	return vty_rc;
}

#define AMR_TCHF_PAR_STR " (0|1|2|3|4|5|6|7)"
#define AMR_TCHF_HELP_STR "4,75k\n5,15k\n5,90k\n6,70k\n7,40k\n7,95k\n" \
	"10,2k\n12,2k\n"

#define AMR_TCHH_PAR_STR " (0|1|2|3|4|5)"
#define AMR_TCHH_HELP_STR "4,75k\n5,15k\n5,90k\n6,70k\n7,40k\n7,95k\n"

#define	AMR_TH_HELP_STR "Threshold between codec 1 and 2\n"
#define	AMR_HY_HELP_STR "Hysteresis between codec 1 and 2\n"

DEFUN_USRATTR(cfg_bts_amr_fr_modes1,
	      cfg_bts_amr_fr_modes1_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "amr tch-f modes" AMR_TCHF_PAR_STR,
	      AMR_TEXT "Full Rate\n" AMR_MODE_TEXT
	      AMR_TCHF_HELP_STR)
{
	if (get_amr_from_arg(vty, 1, argv, 1))
		return CMD_WARNING;
	return check_amr_config(vty);
}

DEFUN_USRATTR(cfg_bts_amr_fr_modes2,
	      cfg_bts_amr_fr_modes2_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "amr tch-f modes" AMR_TCHF_PAR_STR AMR_TCHF_PAR_STR,
	      AMR_TEXT "Full Rate\n" AMR_MODE_TEXT
	      AMR_TCHF_HELP_STR AMR_TCHF_HELP_STR)
{
	if (get_amr_from_arg(vty, 2, argv, 1))
		return CMD_WARNING;
	return check_amr_config(vty);
}

DEFUN_USRATTR(cfg_bts_amr_fr_modes3,
	      cfg_bts_amr_fr_modes3_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "amr tch-f modes" AMR_TCHF_PAR_STR AMR_TCHF_PAR_STR AMR_TCHF_PAR_STR,
	      AMR_TEXT "Full Rate\n" AMR_MODE_TEXT
	      AMR_TCHF_HELP_STR AMR_TCHF_HELP_STR AMR_TCHF_HELP_STR)
{
	if (get_amr_from_arg(vty, 3, argv, 1))
		return CMD_WARNING;
	return check_amr_config(vty);
}

DEFUN_USRATTR(cfg_bts_amr_fr_modes4,
	      cfg_bts_amr_fr_modes4_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "amr tch-f modes" AMR_TCHF_PAR_STR AMR_TCHF_PAR_STR AMR_TCHF_PAR_STR AMR_TCHF_PAR_STR,
	      AMR_TEXT "Full Rate\n" AMR_MODE_TEXT
	      AMR_TCHF_HELP_STR AMR_TCHF_HELP_STR AMR_TCHF_HELP_STR AMR_TCHF_HELP_STR)
{
	if (get_amr_from_arg(vty, 4, argv, 1))
		return CMD_WARNING;
	return check_amr_config(vty);
}

DEFUN_USRATTR(cfg_bts_amr_fr_start_mode,
	      cfg_bts_amr_fr_start_mode_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "amr tch-f start-mode (auto|1|2|3|4)",
	      AMR_TEXT "Full Rate\n" AMR_START_TEXT)
{
	get_amr_start_from_arg(vty, argv, 1);
	return check_amr_config(vty);
}

DEFUN_USRATTR(cfg_bts_amr_fr_thres1,
	      cfg_bts_amr_fr_thres1_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "amr tch-f threshold (ms|bts) <0-63>",
	      AMR_TEXT "Full Rate\n" AMR_TH_TEXT
	      AMR_TH_HELP_STR)
{
	get_amr_th_from_arg(vty, 2, argv, 1);
	return check_amr_config(vty);
}

DEFUN_USRATTR(cfg_bts_amr_fr_thres2,
	      cfg_bts_amr_fr_thres2_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "amr tch-f threshold (ms|bts) <0-63> <0-63>",
	      AMR_TEXT "Full Rate\n" AMR_TH_TEXT
	      AMR_TH_HELP_STR AMR_TH_HELP_STR)
{
	get_amr_th_from_arg(vty, 3, argv, 1);
	return check_amr_config(vty);
}

DEFUN_USRATTR(cfg_bts_amr_fr_thres3,
	      cfg_bts_amr_fr_thres3_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "amr tch-f threshold (ms|bts) <0-63> <0-63> <0-63>",
	      AMR_TEXT "Full Rate\n" AMR_TH_TEXT
	      AMR_TH_HELP_STR AMR_TH_HELP_STR AMR_TH_HELP_STR)
{
	get_amr_th_from_arg(vty, 4, argv, 1);
	return check_amr_config(vty);
}

DEFUN_USRATTR(cfg_bts_amr_fr_hyst1,
	      cfg_bts_amr_fr_hyst1_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "amr tch-f hysteresis (ms|bts) <0-15>",
	      AMR_TEXT "Full Rate\n" AMR_HY_TEXT
	      AMR_HY_HELP_STR)
{
	get_amr_hy_from_arg(vty, 2, argv, 1);
	return check_amr_config(vty);
}

DEFUN_USRATTR(cfg_bts_amr_fr_hyst2,
	      cfg_bts_amr_fr_hyst2_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "amr tch-f hysteresis (ms|bts) <0-15> <0-15>",
	      AMR_TEXT "Full Rate\n" AMR_HY_TEXT
	      AMR_HY_HELP_STR AMR_HY_HELP_STR)
{
	get_amr_hy_from_arg(vty, 3, argv, 1);
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_amr_fr_hyst3,
	      cfg_bts_amr_fr_hyst3_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "amr tch-f hysteresis (ms|bts) <0-15> <0-15> <0-15>",
	      AMR_TEXT "Full Rate\n" AMR_HY_TEXT
	      AMR_HY_HELP_STR AMR_HY_HELP_STR AMR_HY_HELP_STR)
{
	get_amr_hy_from_arg(vty, 4, argv, 1);
	return check_amr_config(vty);
}

DEFUN_USRATTR(cfg_bts_amr_hr_modes1,
	      cfg_bts_amr_hr_modes1_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "amr tch-h modes" AMR_TCHH_PAR_STR,
	      AMR_TEXT "Half Rate\n" AMR_MODE_TEXT
	      AMR_TCHH_HELP_STR)
{
	if (get_amr_from_arg(vty, 1, argv, 0))
		return CMD_WARNING;
	return check_amr_config(vty);
}

DEFUN_USRATTR(cfg_bts_amr_hr_modes2,
	      cfg_bts_amr_hr_modes2_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "amr tch-h modes" AMR_TCHH_PAR_STR AMR_TCHH_PAR_STR,
	      AMR_TEXT "Half Rate\n" AMR_MODE_TEXT
	      AMR_TCHH_HELP_STR AMR_TCHH_HELP_STR)
{
	if (get_amr_from_arg(vty, 2, argv, 0))
		return CMD_WARNING;
	return check_amr_config(vty);
}

DEFUN_USRATTR(cfg_bts_amr_hr_modes3,
	      cfg_bts_amr_hr_modes3_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "amr tch-h modes" AMR_TCHH_PAR_STR AMR_TCHH_PAR_STR AMR_TCHH_PAR_STR,
	      AMR_TEXT "Half Rate\n" AMR_MODE_TEXT
	      AMR_TCHH_HELP_STR AMR_TCHH_HELP_STR AMR_TCHH_HELP_STR)
{
	if (get_amr_from_arg(vty, 3, argv, 0))
		return CMD_WARNING;
	return check_amr_config(vty);
}

DEFUN_USRATTR(cfg_bts_amr_hr_modes4,
	      cfg_bts_amr_hr_modes4_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "amr tch-h modes" AMR_TCHH_PAR_STR AMR_TCHH_PAR_STR AMR_TCHH_PAR_STR AMR_TCHH_PAR_STR,
	      AMR_TEXT "Half Rate\n" AMR_MODE_TEXT
	      AMR_TCHH_HELP_STR AMR_TCHH_HELP_STR AMR_TCHH_HELP_STR AMR_TCHH_HELP_STR)
{
	if (get_amr_from_arg(vty, 4, argv, 0))
		return CMD_WARNING;
	return check_amr_config(vty);
}

DEFUN_USRATTR(cfg_bts_amr_hr_start_mode,
	      cfg_bts_amr_hr_start_mode_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "amr tch-h start-mode (auto|1|2|3|4)",
	      AMR_TEXT "Half Rate\n" AMR_START_TEXT)
{
	get_amr_start_from_arg(vty, argv, 0);
	return check_amr_config(vty);
}

DEFUN_USRATTR(cfg_bts_amr_hr_thres1,
	      cfg_bts_amr_hr_thres1_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "amr tch-h threshold (ms|bts) <0-63>",
	      AMR_TEXT "Half Rate\n" AMR_TH_TEXT
	      AMR_TH_HELP_STR)
{
	get_amr_th_from_arg(vty, 2, argv, 0);
	return check_amr_config(vty);
}

DEFUN_USRATTR(cfg_bts_amr_hr_thres2,
	      cfg_bts_amr_hr_thres2_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "amr tch-h threshold (ms|bts) <0-63> <0-63>",
	      AMR_TEXT "Half Rate\n" AMR_TH_TEXT
	      AMR_TH_HELP_STR AMR_TH_HELP_STR)
{
	get_amr_th_from_arg(vty, 3, argv, 0);
	return check_amr_config(vty);
}

DEFUN_USRATTR(cfg_bts_amr_hr_thres3,
	      cfg_bts_amr_hr_thres3_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "amr tch-h threshold (ms|bts) <0-63> <0-63> <0-63>",
	      AMR_TEXT "Half Rate\n" AMR_TH_TEXT
	      AMR_TH_HELP_STR AMR_TH_HELP_STR AMR_TH_HELP_STR)
{
	get_amr_th_from_arg(vty, 4, argv, 0);
	return check_amr_config(vty);
}

DEFUN_USRATTR(cfg_bts_amr_hr_hyst1,
	      cfg_bts_amr_hr_hyst1_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "amr tch-h hysteresis (ms|bts) <0-15>",
	      AMR_TEXT "Half Rate\n" AMR_HY_TEXT
	      AMR_HY_HELP_STR)
{
	get_amr_hy_from_arg(vty, 2, argv, 0);
	return check_amr_config(vty);
}

DEFUN_USRATTR(cfg_bts_amr_hr_hyst2,
	      cfg_bts_amr_hr_hyst2_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "amr tch-h hysteresis (ms|bts) <0-15> <0-15>",
	      AMR_TEXT "Half Rate\n" AMR_HY_TEXT
	      AMR_HY_HELP_STR AMR_HY_HELP_STR)
{
	get_amr_hy_from_arg(vty, 3, argv, 0);
	return check_amr_config(vty);
}

DEFUN_USRATTR(cfg_bts_amr_hr_hyst3,
	      cfg_bts_amr_hr_hyst3_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "amr tch-h hysteresis (ms|bts) <0-15> <0-15> <0-15>",
	      AMR_TEXT "Half Rate\n" AMR_HY_TEXT
	      AMR_HY_HELP_STR AMR_HY_HELP_STR AMR_HY_HELP_STR)
{
	get_amr_hy_from_arg(vty, 4, argv, 0);
	return check_amr_config(vty);
}

#define TNUM_STR "T-number, optionally preceded by 't' or 'T'\n"
DEFUN_ATTR(cfg_bts_t3113_dynamic, cfg_bts_t3113_dynamic_cmd,
	   "timer-dynamic TNNNN",
	   "Calculate T3113 dynamically based on channel config and load\n"
	   TNUM_STR,
	   CMD_ATTR_IMMEDIATE)
{
	struct osmo_tdef *d;
	struct gsm_bts *bts = vty->index;
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);

	d = osmo_tdef_vty_parse_T_arg(vty, gsmnet->T_defs, argv[0]);
	if (!d)
		return CMD_WARNING;

	switch (d->T) {
	case 3113:
		bts->T3113_dynamic = true;
		break;
	default:
		vty_out(vty, "%% T%d cannot be set to dynamic%s", d->T, VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_bts_no_t3113_dynamic, cfg_bts_no_t3113_dynamic_cmd,
	   "no timer-dynamic TNNNN",
	   NO_STR
	   "Set given timer to non-dynamic and use the default or user provided fixed value\n"
	   TNUM_STR,
	   CMD_ATTR_IMMEDIATE)
{
	struct osmo_tdef *d;
	struct gsm_bts *bts = vty->index;
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);

	d = osmo_tdef_vty_parse_T_arg(vty, gsmnet->T_defs, argv[0]);
	if (!d)
		return CMD_WARNING;

	switch (d->T) {
	case 3113:
		bts->T3113_dynamic = false;
		break;
	default:
		vty_out(vty, "%% T%d already is non-dynamic%s", d->T, VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_interf_meas_avg_period,
	      cfg_bts_interf_meas_avg_period_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "interference-meas avg-period <1-31>",
	      "Interference measurement parameters\n"
	      "Averaging period (Intave)\n"
	      "Number of SACCH multiframes\n")
{
	struct gsm_bts *bts = vty->index;

	bts->interf_meas_params_cfg.avg_period = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_interf_meas_level_bounds,
	      cfg_bts_interf_meas_level_bounds_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "interference-meas level-bounds "
		"<-120-0> <-120-0> <-120-0> <-120-0> <-120-0> <-120-0>",
	      "Interference measurement parameters\n"
	      "Interference level Boundaries. 3GPP do not specify whether these should be in ascending or descending"
	      " order (3GPP TS 48.058 9.3.21 / 3GPP TS 52.021 9.4.25). OsmoBSC supports either ordering, but possibly"
	      " some BTS models only return meaningful interference levels with one specific ordering.\n"
	      "Interference boundary 0 (dBm)\n"
	      "Interference boundary X1 (dBm)\n"
	      "Interference boundary X2 (dBm)\n"
	      "Interference boundary X3 (dBm)\n"
	      "Interference boundary X4 (dBm)\n"
	      "Interference boundary X5 (dBm)\n")
{
	struct gsm_bts *bts = vty->index;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(bts->interf_meas_params_cfg.bounds_dbm); i++) {
		bts->interf_meas_params_cfg.bounds_dbm[i] = abs(atoi(argv[i]));
	}
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_bts_srvcc_fast_return, cfg_bts_srvcc_fast_return_cmd,
	   "srvcc fast-return (allow|forbid)",
	   "SRVCC Configuration\n"
	   "Allow or forbid Fast Return to 4G on Channel Release in this BTS\n"
	   "Allow\n"
	   "Forbid\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct gsm_bts *bts = vty->index;

	bts->srvcc_fast_return_allowed = strcmp(argv[0], "allow") == 0;
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_bts_immediate_assignment, cfg_bts_immediate_assignment_cmd,
	   "immediate-assignment (post-chan-ack|pre-chan-ack|pre-ts-ack)",
	   "Configure time of Immediate Assignment after ChanRqd RACH (Abis optimization)\n"
	   "Send the Immediate Assignment after the Channel Activation ACK (normal sequence)\n"
	   "Send the Immediate Assignment directly after Channel Activation (early), without waiting for the ACK;"
	   " This may help with double allocations on high latency Abis links\n"
	   "EXPERIMENTAL: If a dynamic timeslot switch is necessary, send the Immediate Assignment even before the"
	   " timeslot is switched, i.e. even before the Channel Activation is sent (very early)\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct gsm_bts *bts = vty->index;

	if (!strcmp(argv[0], "pre-ts-ack"))
		bts->imm_ass_time = IMM_ASS_TIME_PRE_TS_ACK;
	else if (!strcmp(argv[0], "pre-chan-ack"))
		bts->imm_ass_time = IMM_ASS_TIME_PRE_CHAN_ACK;
	else
		bts->imm_ass_time = IMM_ASS_TIME_POST_CHAN_ACK;
	return CMD_SUCCESS;
}

#define BS_POWER_CONTROL_CMD \
	"bs-power-control"
#define MS_POWER_CONTROL_CMD \
	"ms-power-control"
#define POWER_CONTROL_CMD \
	"(" BS_POWER_CONTROL_CMD "|" MS_POWER_CONTROL_CMD ")"
#define POWER_CONTROL_DESC \
	"BS (Downlink) power control parameters\n" \
	"MS (Uplink) power control parameters\n"

#define BTS_POWER_CTRL_PARAMS(bts) \
	(strcmp(argv[0], BS_POWER_CONTROL_CMD) == 0) ? \
		&bts->bs_power_ctrl : &bts->ms_power_ctrl

DEFUN_USRATTR(cfg_bts_no_power_ctrl,
	      cfg_bts_no_power_ctrl_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "no " POWER_CONTROL_CMD,
	      NO_STR POWER_CONTROL_DESC)
{
	struct gsm_power_ctrl_params *params;
	struct gsm_bts *bts = vty->index;

	params = BTS_POWER_CTRL_PARAMS(bts);
	params->mode = GSM_PWR_CTRL_MODE_NONE;

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_power_ctrl,
      cfg_bts_power_ctrl_cmd,
      POWER_CONTROL_CMD,
      POWER_CONTROL_DESC)
{
	struct gsm_power_ctrl_params *params;
	struct gsm_bts *bts = vty->index;

	params = BTS_POWER_CTRL_PARAMS(bts);
	vty->node = POWER_CTRL_NODE;
	vty->index = params;

	/* Change the prefix to reflect MS/BS difference */
	if (params->dir == GSM_PWR_CTRL_DIR_UL)
		power_ctrl_node.prompt = "%s(config-ms-power-ctrl)# ";
	else
		power_ctrl_node.prompt = "%s(config-bs-power-ctrl)# ";

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_power_ctrl_mode,
	      cfg_power_ctrl_mode_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "mode (static|dyn-bts|dyn-bsc) [reset]",
	      "Power control mode\n"
	      "Instruct the MS/BTS to use a static power level\n"
	      "Power control to be performed dynamically by the BTS itself\n"
	      "Power control to be performed dynamically at this BSC\n"
	      "Reset to default parameters for the given mode\n")
{
	struct gsm_power_ctrl_params *params = vty->index;

	/* Do we need to reset? */
	if (argc > 1) {
		vty_out(vty, "%% Reset to default parameters%s", VTY_NEWLINE);
		power_ctrl_params_def_reset(params, params->dir);
	}

	if (strcmp(argv[0], "static") == 0)
		params->mode = GSM_PWR_CTRL_MODE_STATIC;
	else if (strcmp(argv[0], "dyn-bts") == 0)
		params->mode = GSM_PWR_CTRL_MODE_DYN_BTS;
	else if (strcmp(argv[0], "dyn-bsc") == 0) {
		if (params->dir == GSM_PWR_CTRL_DIR_DL) {
			vty_out(vty, "%% mode dyn-bsc not supported for Downlink.%s", VTY_NEWLINE);
			return CMD_WARNING;
		}
		params->mode = GSM_PWR_CTRL_MODE_DYN_BSC;
	}

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_power_ctrl_bs_power,
	      cfg_power_ctrl_bs_power_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "bs-power (static|dyn-max) <0-30>",
	      "BS Power IE value to be sent to the BTS\n"
	      "Fixed BS Power reduction value (for static mode)\n"
	      "Maximum BS Power reduction value (for dynamic mode)\n"
	      "BS Power reduction value (in dB, even numbers only)\n")
{
	struct gsm_power_ctrl_params *params = vty->index;
	bool dynamic = !strcmp(argv[0], "dyn-max");
	int value = atoi(argv[1]);

	if (params->dir != GSM_PWR_CTRL_DIR_DL) {
		vty_out(vty, "%% This command is only valid for "
			"'bs-power-control' node%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (value % 2 != 0) {
		vty_out(vty, "%% Incorrect BS Power reduction value, "
			"an even number is expected%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (dynamic) /* maximum value */
		params->bs_power_max_db = value;
	else /* static (fixed) value */
		params->bs_power_val_db = value;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_power_ctrl_ctrl_interval,
	      cfg_power_ctrl_ctrl_interval_cmd,
	      X(BSC_VTY_ATTR_VENDOR_SPECIFIC) |
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "ctrl-interval <0-31>",
	      "Set power control interval (for dynamic mode)\n"
	      "P_CON_INTERVAL, in units of 2 SACCH periods (0.96 seconds)(default=1)\n")
{
	struct gsm_power_ctrl_params *params = vty->index;

	params->ctrl_interval = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_power_ctrl_step_size,
	      cfg_power_ctrl_step_size_cmd,
	      X(BSC_VTY_ATTR_VENDOR_SPECIFIC) |
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "step-size inc <2-6> red <2-4>",
	      "Set power change step size (for dynamic mode)\n"
	      "Increase step size (default is 4 dB)\n"
	      "Step size (2, 4, or 6 dB)\n"
	      "Reduce step size (default is 2 dB)\n"
	      "Step size (2 or 4 dB)\n")
{
	struct gsm_power_ctrl_params *params = vty->index;
	int inc_step_size_db = atoi(argv[0]);
	int red_step_size_db = atoi(argv[1]);

	if (inc_step_size_db % 2 || red_step_size_db % 2) {
		vty_out(vty, "%% Power change step size must be "
			"an even number%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* Recommendation: POW_RED_STEP_SIZE <= POW_INCR_STEP_SIZE */
	if (red_step_size_db > inc_step_size_db) {
		vty_out(vty, "%% Increase step size (%d) should be greater "
			"than reduce step size (%d), consider changing it%s",
			inc_step_size_db, red_step_size_db, VTY_NEWLINE);
	}

	/* Recommendation: POW_INCR_STEP_SIZE <= (U_RXLEV_XX_P - L_RXLEV_XX_P) */
	const struct gsm_power_ctrl_meas_params *mp = &params->rxlev_meas;
	if (inc_step_size_db > (mp->upper_thresh - mp->lower_thresh)) {
		vty_out(vty, "%% Increase step size (%d) should be less or equal "
			"than/to the RxLev threshold window (%d, upper - lower), "
			"consider changing it%s", inc_step_size_db,
			mp->upper_thresh - mp->lower_thresh, VTY_NEWLINE);
	}

	params->inc_step_size_db = inc_step_size_db;
	params->red_step_size_db = red_step_size_db;

	return CMD_SUCCESS;
}

#define POWER_CONTROL_MEAS_RXLEV_DESC \
	"RxLev value (signal strength, 0 is worst, 63 is best)\n"
#define POWER_CONTROL_MEAS_RXQUAL_DESC \
	"RxQual value (signal quality, 0 is best, 7 is worst)\n"
#define POWER_CONTROL_MEAS_CI_DESC \
	"C/I value (Carrier-to-Interference (dB), 0 is worst, 30 is best)\n"

DEFUN_USRATTR(cfg_power_ctrl_rxlev_thresh,
	      cfg_power_ctrl_rxlev_thresh_cmd,
	      X(BSC_VTY_ATTR_VENDOR_SPECIFIC) |
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "rxlev-thresh lower <0-63> upper <0-63>",
	      "Set target RxLev thresholds (for dynamic mode)\n"
	      "Lower RxLev value (default is 32, i.e. -78 dBm)\n"
	      "Lower " POWER_CONTROL_MEAS_RXLEV_DESC
	      "Upper RxLev value (default is 38, i.e. -72 dBm)\n"
	      "Upper " POWER_CONTROL_MEAS_RXLEV_DESC)
{
	struct gsm_power_ctrl_params *params = vty->index;
	int lower = atoi(argv[0]);
	int upper = atoi(argv[1]);

	if (lower > upper) {
		vty_out(vty, "%% Lower 'rxlev-thresh' (%d) must be less than upper (%d)%s",
			lower, upper, VTY_NEWLINE);
		return CMD_WARNING;
	}

	params->rxlev_meas.lower_thresh = lower;
	params->rxlev_meas.upper_thresh = upper;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_power_ctrl_rxqual_thresh,
	      cfg_power_ctrl_rxqual_thresh_cmd,
	      X(BSC_VTY_ATTR_VENDOR_SPECIFIC) |
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "rxqual-thresh lower <0-7> upper <0-7>",
	      "Set target RxQual thresholds (for dynamic mode)\n"
	      "Lower RxQual value (default is 3, i.e. 0.8% <= BER < 1.6%)\n"
	      "Lower " POWER_CONTROL_MEAS_RXQUAL_DESC
	      "Upper RxQual value (default is 0, i.e. BER < 0.2%)\n"
	      "Upper " POWER_CONTROL_MEAS_RXQUAL_DESC)
{
	struct gsm_power_ctrl_params *params = vty->index;
	int lower = atoi(argv[0]);
	int upper = atoi(argv[1]);

	/* RxQual: 0 is best, 7 is worst, so upper must be less */
	if (upper > lower) {
		vty_out(vty, "%% Upper 'rxqual-rxqual' (%d) must be less than lower (%d)%s",
			upper, lower, VTY_NEWLINE);
		return CMD_WARNING;
	}

	params->rxqual_meas.lower_thresh = lower;
	params->rxqual_meas.upper_thresh = upper;

	return CMD_SUCCESS;
}

#define VTY_CMD_CI_TYPE "(fr-efr|hr|amr-fr|amr-hr|sdcch|gprs)"
#define VTY_CMD_CI_OR_ALL_TYPE "(fr-efr|hr|amr-fr|amr-hr|sdcch|gprs|all)"
#define VTY_DESC_CI_TYPE \
	"Channel Type FR/EFR\n" \
	"Channel Type HR\n" \
	"Channel Type AMR FR\n" \
	"Channel Type AMR HR\n" \
	"Channel Type SDCCH\n" \
	"Channel Type (E)GPRS\n"
#define VTY_DESC_CI_OR_ALL_TYPE VTY_DESC_CI_TYPE "All Channel Types\n"

static struct gsm_power_ctrl_meas_params *ci_thresh_by_conn_type(struct gsm_power_ctrl_params *params, const char *type)
{
	if (!strcmp(type, "fr-efr"))
		return &params->ci_fr_meas;
	if (!strcmp(type, "hr"))
		return &params->ci_hr_meas;
	if (!strcmp(type, "amr-fr"))
		return &params->ci_amr_fr_meas;
	if (!strcmp(type, "amr-hr"))
		return &params->ci_amr_hr_meas;
	if (!strcmp(type, "sdcch"))
		return &params->ci_sdcch_meas;
	if (!strcmp(type, "gprs"))
		return &params->ci_gprs_meas;
	OSMO_ASSERT(false);
	return NULL;
}

DEFUN_USRATTR(cfg_power_ctrl_ci_thresh,
	      cfg_power_ctrl_ci_thresh_cmd,
	      X(BSC_VTY_ATTR_VENDOR_SPECIFIC) |
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "ci-thresh " VTY_CMD_CI_TYPE " lower <0-30> upper <0-30>",
	      "Set target C/I thresholds (for dynamic mode), only available in ms-power-control\n"
	      VTY_DESC_CI_TYPE
	      "Lower C/I value\n"
	      "Lower " POWER_CONTROL_MEAS_RXQUAL_DESC
	      "Upper C/I value\n"
	      "Upper " POWER_CONTROL_MEAS_RXQUAL_DESC)
{
	struct gsm_power_ctrl_params *params = vty->index;
	const char *type = argv[0];
	int lower = atoi(argv[1]);
	int upper = atoi(argv[2]);
	struct gsm_power_ctrl_meas_params *meas_params;

	if (params->mode == GSM_PWR_CTRL_MODE_DYN_BSC) {
		vty_out(vty, "%% C/I based power loop not possible in dyn-bsc mode!%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (params->dir != GSM_PWR_CTRL_DIR_UL) {
		vty_out(vty, "%% C/I based power loop only possible in Uplink!%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (lower > upper) {
		vty_out(vty, "%% Lower 'rxqual-rxqual' (%d) must be less than upper (%d)%s",
			upper, lower, VTY_NEWLINE);
		return CMD_WARNING;
	}

	meas_params = ci_thresh_by_conn_type(params, type);

	meas_params->lower_thresh = lower;
	meas_params->upper_thresh = upper;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_power_ctrl_ci_thresh_disable,
	      cfg_power_ctrl_ci_thresh_disable_cmd,
	      X(BSC_VTY_ATTR_VENDOR_SPECIFIC) |
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "ci-thresh " VTY_CMD_CI_OR_ALL_TYPE " (enable|disable)",
	      "Set target C/I thresholds (for dynamic mode), only available in ms-power-control\n"
	      VTY_DESC_CI_OR_ALL_TYPE
	      "Enable C/I comparison in control loop\n"
	      "Disable C/I comparison in control loop\n")
{
	struct gsm_power_ctrl_params *params = vty->index;

	bool enable = strcmp(argv[1], "enable") == 0;

	if (strcmp(argv[0], "all") == 0) {
		params->ci_fr_meas.enabled = enable;
		params->ci_hr_meas.enabled = enable;
		params->ci_amr_fr_meas.enabled = enable;
		params->ci_amr_hr_meas.enabled = enable;
		params->ci_sdcch_meas.enabled = enable;
		params->ci_gprs_meas.enabled = enable;
	} else {
		struct gsm_power_ctrl_meas_params *meas_params = ci_thresh_by_conn_type(params, argv[0]);
		meas_params->enabled = enable;
	}

	return CMD_SUCCESS;
}

#define POWER_CONTROL_MEAS_THRESH_COMP_CMD(meas) \
	meas " lower <0-31> <0-31> upper <0-31> <0-31>"
#define POWER_CONTROL_MEAS_THRESH_COMP_DESC(meas, opt_param, lp, ln, up, un) \
	"Set " meas " threshold comparators (for dynamic mode)\n" \
	opt_param \
	"Lower " meas " threshold comparators (see 3GPP TS 45.008, A.3.2.1)\n" lp ln \
	"Upper " meas " threshold comparators (see 3GPP TS 45.008, A.3.2.1)\n" up un

DEFUN_USRATTR(cfg_power_ctrl_rxlev_thresh_comp,
	      cfg_power_ctrl_rxlev_thresh_comp_cmd,
	      X(BSC_VTY_ATTR_VENDOR_SPECIFIC) |
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      POWER_CONTROL_MEAS_THRESH_COMP_CMD("rxlev-thresh-comp"),
	      POWER_CONTROL_MEAS_THRESH_COMP_DESC("RxLev", /*empty*/,
		"P1 (default 10)\n", "N1 (default 12)\n",
		"P2 (default 10)\n", "N2 (default 12)\n"))
{
	struct gsm_power_ctrl_params *params = vty->index;
	int lower_cmp_p = atoi(argv[0]);
	int lower_cmp_n = atoi(argv[1]);
	int upper_cmp_p = atoi(argv[2]);
	int upper_cmp_n = atoi(argv[3]);

	if (lower_cmp_p > lower_cmp_n) {
		vty_out(vty, "%% Lower RxLev P1 %d must be less than N1 %d%s",
			lower_cmp_p, lower_cmp_n, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (upper_cmp_p > upper_cmp_n) {
		vty_out(vty, "%% Upper RxLev P2 %d must be less than N2 %d%s",
			upper_cmp_p, upper_cmp_n, VTY_NEWLINE);
		return CMD_WARNING;
	}

	params->rxlev_meas.lower_cmp_p = lower_cmp_p;
	params->rxlev_meas.lower_cmp_n = lower_cmp_n;
	params->rxlev_meas.upper_cmp_p = upper_cmp_p;
	params->rxlev_meas.upper_cmp_n = upper_cmp_n;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_power_ctrl_rxqual_thresh_comp,
	      cfg_power_ctrl_rxqual_thresh_comp_cmd,
	      X(BSC_VTY_ATTR_VENDOR_SPECIFIC) |
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      POWER_CONTROL_MEAS_THRESH_COMP_CMD("rxqual-thresh-comp"),
	      POWER_CONTROL_MEAS_THRESH_COMP_DESC("RxQual", /*empty*/,
		"P3 (default 5)\n", "N3 (default 7)\n",
		"P4 (default 15)\n", "N4 (default 18)\n"))
{
	struct gsm_power_ctrl_params *params = vty->index;
	int lower_cmp_p = atoi(argv[0]);
	int lower_cmp_n = atoi(argv[1]);
	int upper_cmp_p = atoi(argv[2]);
	int upper_cmp_n = atoi(argv[3]);

	if (lower_cmp_p > lower_cmp_n) {
		vty_out(vty, "%% Lower RxQual P3 %d must be less than N3 %d%s",
			lower_cmp_p, lower_cmp_n, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (upper_cmp_p > upper_cmp_n) {
		vty_out(vty, "%% Upper RxQual P4 %d must be less than N4 %d%s",
			upper_cmp_p, upper_cmp_n, VTY_NEWLINE);
		return CMD_WARNING;
	}

	params->rxqual_meas.lower_cmp_p = lower_cmp_p;
	params->rxqual_meas.lower_cmp_n = lower_cmp_n;
	params->rxqual_meas.upper_cmp_p = upper_cmp_p;
	params->rxqual_meas.upper_cmp_n = upper_cmp_n;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_power_ctrl_ci_thresh_comp,
	      cfg_power_ctrl_ci_thresh_comp_cmd,
	      X(BSC_VTY_ATTR_VENDOR_SPECIFIC) |
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      POWER_CONTROL_MEAS_THRESH_COMP_CMD("ci-thresh-comp " VTY_CMD_CI_TYPE),
	      POWER_CONTROL_MEAS_THRESH_COMP_DESC("Carrier-to_interference (C/I)",
		VTY_DESC_CI_TYPE,
		"Lower P (default 5)\n", "Lower N (default 7)\n",
		"Upper P (default 15)\n", "Upper N (default 18)\n"))
{
	struct gsm_power_ctrl_params *params = vty->index;
	struct gsm_power_ctrl_meas_params *meas_params;
	int lower_cmp_p = atoi(argv[1]);
	int lower_cmp_n = atoi(argv[2]);
	int upper_cmp_p = atoi(argv[3]);
	int upper_cmp_n = atoi(argv[4]);

	if (lower_cmp_p > lower_cmp_n) {
		vty_out(vty, "%% Lower C/I P %d must be less than N %d%s",
			lower_cmp_p, lower_cmp_n, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (upper_cmp_p > upper_cmp_n) {
		vty_out(vty, "%% Upper C/I P %d must be less than N %d%s",
			upper_cmp_p, upper_cmp_n, VTY_NEWLINE);
		return CMD_WARNING;
	}

	meas_params = ci_thresh_by_conn_type(params, argv[0]);

	meas_params->lower_cmp_p = lower_cmp_p;
	meas_params->lower_cmp_n = lower_cmp_n;
	meas_params->upper_cmp_p = upper_cmp_p;
	meas_params->upper_cmp_n = upper_cmp_n;

	return CMD_SUCCESS;
}

#define POWER_CONTROL_MEAS_AVG_CMD \
	"(rxlev-avg|rxqual-avg)"
#define POWER_CONTROL_MEAS_AVG_DESC \
	"RxLev (signal strength) measurement averaging (for dynamic mode)\n" \
	"RxQual (signal quality) measurement averaging (for dynamic mode)\n"

#define POWER_CONTROL_MEAS_AVG_PARAMS(params) \
	(strncmp(argv[0], "rxlev", 5) == 0) ? \
		&params->rxlev_meas : &params->rxqual_meas

DEFUN_USRATTR(cfg_power_ctrl_no_avg,
	      cfg_power_ctrl_no_avg_cmd,
	      X(BSC_VTY_ATTR_VENDOR_SPECIFIC) |
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "no " POWER_CONTROL_MEAS_AVG_CMD,
	      NO_STR POWER_CONTROL_MEAS_AVG_DESC)
{
	struct gsm_power_ctrl_params *params = vty->index;
	struct gsm_power_ctrl_meas_params *avg_params;

	avg_params = POWER_CONTROL_MEAS_AVG_PARAMS(params);
	avg_params->algo = GSM_PWR_CTRL_MEAS_AVG_ALGO_NONE;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_power_ctrl_avg_params,
	      cfg_power_ctrl_avg_params_cmd,
	      X(BSC_VTY_ATTR_VENDOR_SPECIFIC) |
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      POWER_CONTROL_MEAS_AVG_CMD " params hreqave <1-31> hreqt <1-31>",
	      POWER_CONTROL_MEAS_AVG_DESC "Configure general averaging parameters\n"
	      "Hreqave: the period over which an average is produced\n"
	      "Hreqave value (so that Hreqave * Hreqt < 32)\n"
	      "Hreqt: the number of averaged results that are maintained\n"
	      "Hreqt value (so that Hreqave * Hreqt < 32)\n")
{
	struct gsm_power_ctrl_params *params = vty->index;
	struct gsm_power_ctrl_meas_params *avg_params;
	int h_reqave = atoi(argv[1]);
	int h_reqt = atoi(argv[2]);

	if (h_reqave * h_reqt > 31) {
		vty_out(vty, "%% Hreqave (%d) * Hreqt (%d) = %d must be < 32%s",
			h_reqave, h_reqt, h_reqave * h_reqt, VTY_NEWLINE);
		return CMD_WARNING;
	}

	avg_params = POWER_CONTROL_MEAS_AVG_PARAMS(params);
	avg_params->h_reqave = h_reqave;
	avg_params->h_reqt = h_reqt;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_power_ctrl_avg_algo,
	      cfg_power_ctrl_avg_algo_cmd,
	      X(BSC_VTY_ATTR_VENDOR_SPECIFIC) |
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      /* FIXME: add algorithm specific parameters */
	      POWER_CONTROL_MEAS_AVG_CMD " algo (unweighted|weighted|mod-median)",
	      POWER_CONTROL_MEAS_AVG_DESC "Select the averaging algorithm\n"
	      "Un-weighted average\n" "Weighted average\n"
	      "Modified median calculation\n")
{
	struct gsm_power_ctrl_params *params = vty->index;
	struct gsm_power_ctrl_meas_params *avg_params;

	avg_params = POWER_CONTROL_MEAS_AVG_PARAMS(params);
	if (strcmp(argv[1], "unweighted") == 0)
		avg_params->algo = GSM_PWR_CTRL_MEAS_AVG_ALGO_UNWEIGHTED;
	else if (strcmp(argv[1], "weighted") == 0)
		avg_params->algo = GSM_PWR_CTRL_MEAS_AVG_ALGO_WEIGHTED;
	else if (strcmp(argv[1], "mod-median") == 0)
		avg_params->algo = GSM_PWR_CTRL_MEAS_AVG_ALGO_MOD_MEDIAN;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_power_ctrl_avg_osmo_ewma,
	      cfg_power_ctrl_avg_osmo_ewma_cmd,
	      X(BSC_VTY_ATTR_VENDOR_SPECIFIC) |
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      POWER_CONTROL_MEAS_AVG_CMD " algo osmo-ewma beta <1-99>",
	      POWER_CONTROL_MEAS_AVG_DESC "Select the averaging algorithm\n"
	      "Exponentially Weighted Moving Average (EWMA)\n"
	      "Smoothing factor (in %): beta = (100 - alpha)\n"
	      "1% - lowest smoothing, 99% - highest smoothing\n")
{
	struct gsm_power_ctrl_params *params = vty->index;
	struct gsm_power_ctrl_meas_params *avg_params;
	const struct gsm_bts *bts;

	if (params->dir == GSM_PWR_CTRL_DIR_UL)
		bts = container_of(params, struct gsm_bts, ms_power_ctrl);
	else
		bts = container_of(params, struct gsm_bts, bs_power_ctrl);

	if (bts->type != GSM_BTS_TYPE_OSMOBTS) {
		vty_out(vty, "%% EWMA is an OsmoBTS specific algorithm, "
			"it's not usable for other BTS types%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	avg_params = POWER_CONTROL_MEAS_AVG_PARAMS(params);
	avg_params->algo = GSM_PWR_CTRL_MEAS_AVG_ALGO_OSMO_EWMA;
	avg_params->ewma.alpha = 100 - atoi(argv[1]);

	return CMD_SUCCESS;
}

/* C/I related power control measurements */
#define POWER_CONTROL_CI_MEAS_AVG_DESC \
	"C/I (Carrier-to-Interference) measurement averaging (for dynamic mode)\n"

DEFUN_USRATTR(cfg_power_ctrl_no_ci_avg,
	      cfg_power_ctrl_no_ci_avg_cmd,
	      X(BSC_VTY_ATTR_VENDOR_SPECIFIC) |
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "no ci-avg " VTY_CMD_CI_TYPE,
	      NO_STR POWER_CONTROL_CI_MEAS_AVG_DESC VTY_DESC_CI_TYPE)
{
	struct gsm_power_ctrl_params *params = vty->index;
	struct gsm_power_ctrl_meas_params *avg_params;

	avg_params = ci_thresh_by_conn_type(params, argv[0]);
	avg_params->algo = GSM_PWR_CTRL_MEAS_AVG_ALGO_NONE;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_power_ctrl_ci_avg_params,
	      cfg_power_ctrl_ci_avg_params_cmd,
	      X(BSC_VTY_ATTR_VENDOR_SPECIFIC) |
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "ci-avg " VTY_CMD_CI_TYPE " params hreqave <1-31> hreqt <1-31>",
	      POWER_CONTROL_CI_MEAS_AVG_DESC VTY_DESC_CI_TYPE
	      "Configure general averaging parameters\n"
	      "Hreqave: the period over which an average is produced\n"
	      "Hreqave value (so that Hreqave * Hreqt < 32)\n"
	      "Hreqt: the number of averaged results that are maintained\n"
	      "Hreqt value (so that Hreqave * Hreqt < 32)\n")
{
	struct gsm_power_ctrl_params *params = vty->index;
	struct gsm_power_ctrl_meas_params *avg_params;
	int h_reqave = atoi(argv[1]);
	int h_reqt = atoi(argv[2]);

	if (h_reqave * h_reqt > 31) {
		vty_out(vty, "%% Hreqave (%d) * Hreqt (%d) = %d must be < 32%s",
			h_reqave, h_reqt, h_reqave * h_reqt, VTY_NEWLINE);
		return CMD_WARNING;
	}

	avg_params = ci_thresh_by_conn_type(params, argv[0]);
	avg_params->h_reqave = h_reqave;
	avg_params->h_reqt = h_reqt;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_power_ctrl_ci_avg_algo,
	      cfg_power_ctrl_ci_avg_algo_cmd,
	      X(BSC_VTY_ATTR_VENDOR_SPECIFIC) |
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      /* FIXME: add algorithm specific parameters */
	      "ci-avg " VTY_CMD_CI_TYPE " algo (unweighted|weighted|mod-median)",
	      POWER_CONTROL_CI_MEAS_AVG_DESC VTY_DESC_CI_TYPE
	      "Select the averaging algorithm\n"
	      "Un-weighted average\n" "Weighted average\n"
	      "Modified median calculation\n")
{
	struct gsm_power_ctrl_params *params = vty->index;
	struct gsm_power_ctrl_meas_params *avg_params;

	avg_params = ci_thresh_by_conn_type(params, argv[0]);
	if (strcmp(argv[1], "unweighted") == 0)
		avg_params->algo = GSM_PWR_CTRL_MEAS_AVG_ALGO_UNWEIGHTED;
	else if (strcmp(argv[1], "weighted") == 0)
		avg_params->algo = GSM_PWR_CTRL_MEAS_AVG_ALGO_WEIGHTED;
	else if (strcmp(argv[1], "mod-median") == 0)
		avg_params->algo = GSM_PWR_CTRL_MEAS_AVG_ALGO_MOD_MEDIAN;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_power_ctrl_ci_avg_osmo_ewma,
	      cfg_power_ctrl_ci_avg_osmo_ewma_cmd,
	      X(BSC_VTY_ATTR_VENDOR_SPECIFIC) |
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "ci-avg " VTY_CMD_CI_TYPE " algo osmo-ewma beta <1-99>",
	      POWER_CONTROL_CI_MEAS_AVG_DESC VTY_DESC_CI_TYPE
	      "Select the averaging algorithm\n"
	      "Exponentially Weighted Moving Average (EWMA)\n"
	      "Smoothing factor (in %): beta = (100 - alpha)\n"
	      "1% - lowest smoothing, 99% - highest smoothing\n")
{
	struct gsm_power_ctrl_params *params = vty->index;
	struct gsm_power_ctrl_meas_params *avg_params;
	const struct gsm_bts *bts;

	if (params->dir == GSM_PWR_CTRL_DIR_UL)
		bts = container_of(params, struct gsm_bts, ms_power_ctrl);
	else
		bts = container_of(params, struct gsm_bts, bs_power_ctrl);

	if (bts->type != GSM_BTS_TYPE_OSMOBTS) {
		vty_out(vty, "%% EWMA is an OsmoBTS specific algorithm, "
			"it's not usable for other BTS types%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	avg_params = ci_thresh_by_conn_type(params, argv[0]);
	avg_params->algo = GSM_PWR_CTRL_MEAS_AVG_ALGO_OSMO_EWMA;
	avg_params->ewma.alpha = 100 - atoi(argv[1]);

	return CMD_SUCCESS;
}

static void vty_out_neigh_list(struct vty *vty, struct bitvec *bv)
{
	int count = 0;
	int i;
	for (i = 0; i < 1024; i++) {
		if (!bitvec_get_bit_pos(bv, i))
			continue;
		vty_out(vty, " %u", i);
		count ++;
	}
	if (!count)
		vty_out(vty, " (none)");
	else
		vty_out(vty, " (%d)", count);
}

static void bts_dump_vty_cbch(struct vty *vty, const struct bts_smscb_chan_state *cstate)
{
	vty_out(vty, "  CBCH %s: %u messages, %u pages, %zu-entry sched_arr, %u%% load%s",
		bts_smscb_chan_state_name(cstate), llist_count(&cstate->messages),
		bts_smscb_chan_page_count(cstate), cstate->sched_arr_size,
		bts_smscb_chan_load_percent(cstate), VTY_NEWLINE);
}


static void bts_dump_vty_features(struct vty *vty, struct gsm_bts *bts)
{
	unsigned int i;
	bool no_features = true;
	vty_out(vty, "  Features:%s", VTY_NEWLINE);

	for (i = 0; i < _NUM_BTS_FEAT; i++) {
		if (osmo_bts_has_feature(&bts->features, i)) {
			vty_out(vty, "    %03u ", i);
			vty_out(vty, "%-40s%s", osmo_bts_features_desc(i), VTY_NEWLINE);
			no_features = false;
		}
	}

	if (no_features)
		vty_out(vty, "    (not available)%s", VTY_NEWLINE);
}

void bts_dump_vty(struct vty *vty, struct gsm_bts *bts)
{
	struct pchan_load pl;
	unsigned long long sec;
	struct gsm_bts_trx *trx;
	int ts_hopping_total;
	int ts_non_hopping_total;

	vty_out(vty, "BTS %u is of %s type in band %s, has CI %u LAC %u, "
		"BSIC %u (NCC=%u, BCC=%u) and %u TRX%s",
		bts->nr, btstype2str(bts->type), gsm_band_name(bts->band),
		bts->cell_identity,
		bts->location_area_code, bts->bsic,
		bts->bsic >> 3, bts->bsic & 7,
		bts->num_trx, VTY_NEWLINE);
	vty_out(vty, "  Description: %s%s",
		bts->description ? bts->description : "(null)", VTY_NEWLINE);

	vty_out(vty, "  ARFCNs:");
	ts_hopping_total = 0;
	ts_non_hopping_total = 0;
	llist_for_each_entry(trx, &bts->trx_list, list) {
		int ts_nr;
		int ts_hopping = 0;
		int ts_non_hopping = 0;
		for (ts_nr = 0; ts_nr < TRX_NR_TS; ts_nr++) {
			struct gsm_bts_trx_ts *ts = &trx->ts[ts_nr];
			if (ts->hopping.enabled)
				ts_hopping++;
			else
				ts_non_hopping++;
		}

		if (ts_non_hopping)
			vty_out(vty, " %u", trx->arfcn);
		ts_hopping_total += ts_hopping;
		ts_non_hopping_total += ts_non_hopping;
	}
	if (ts_hopping_total) {
		if (ts_non_hopping_total)
			vty_out(vty, " / Hopping on %d of %d timeslots",
				ts_hopping_total, ts_hopping_total + ts_non_hopping_total);
		else
			vty_out(vty, " Hopping on all %d timeslots", ts_hopping_total);
	}
	vty_out(vty, "%s", VTY_NEWLINE);

	if (strnlen(bts->pcu_version, MAX_VERSION_LENGTH))
		vty_out(vty, "  PCU version %s connected%s", bts->pcu_version,
			VTY_NEWLINE);
	vty_out(vty, "  BCCH carrier power reduction (maximum): %u dB%s",
		bts->c0_max_power_red_db, VTY_NEWLINE);
	vty_out(vty, "  MS Max power: %u dBm%s", bts->ms_max_power, VTY_NEWLINE);
	vty_out(vty, "  Minimum Rx Level for Access: %i dBm%s",
		rxlev2dbm(bts->si_common.cell_sel_par.rxlev_acc_min),
		VTY_NEWLINE);
	vty_out(vty, "  Cell Reselection Hysteresis: %u dBm%s",
		bts->si_common.cell_sel_par.cell_resel_hyst*2, VTY_NEWLINE);
	vty_out(vty, "  Access Control Class rotation allow mask: 0x%" PRIx16 "%s",
		bts->acc_mgr.allowed_subset_mask, VTY_NEWLINE);
	vty_out(vty, "  Access Control Class ramping: %senabled%s",
		acc_ramp_is_enabled(&bts->acc_ramp) ? "" : "not ", VTY_NEWLINE);
	if (acc_ramp_is_enabled(&bts->acc_ramp)) {
		vty_out(vty, "  Access Control Class ramping step interval: %u seconds%s",
			acc_ramp_get_step_interval(&bts->acc_ramp), VTY_NEWLINE);
		vty_out(vty, "  Access Control Class channel load thresholds: (%" PRIu8 ", %" PRIu8 ")%s",
			bts->acc_ramp.chan_load_lower_threshold,
			bts->acc_ramp.chan_load_upper_threshold, VTY_NEWLINE);
	        vty_out(vty, "  enabling %u Access Control Class%s per ramping step%s",
			acc_ramp_get_step_size(&bts->acc_ramp),
			acc_ramp_get_step_size(&bts->acc_ramp) > 1 ? "es" : "", VTY_NEWLINE);
	}
	vty_out(vty, "  RACH TX-Integer: %u%s", bts->si_common.rach_control.tx_integer,
		VTY_NEWLINE);
	vty_out(vty, "  RACH Max transmissions: %u%s",
		rach_max_trans_raw2val(bts->si_common.rach_control.max_trans),
		VTY_NEWLINE);
	vty_out(vty, "  RACH Max Delay (Max Access Delay IE in CHANnel ReQuireD): %u%s",
		bts->rach_max_delay, VTY_NEWLINE);
	if (bts->si_common.rach_control.cell_bar)
		vty_out(vty, "  CELL IS BARRED%s", VTY_NEWLINE);
	if (bts->dtxu != GSM48_DTX_SHALL_NOT_BE_USED)
		vty_out(vty, "  Uplink DTX: %s%s",
			(bts->dtxu != GSM48_DTX_SHALL_BE_USED) ?
			"enabled" : "forced", VTY_NEWLINE);
	else
		vty_out(vty, "  Uplink DTX: not enabled%s", VTY_NEWLINE);
	vty_out(vty, "  Downlink DTX: %senabled%s", bts->dtxd ? "" : "not ",
		VTY_NEWLINE);
	vty_out(vty, "  Channel Description Attachment: %s%s",
		(bts->si_common.chan_desc.att) ? "yes" : "no", VTY_NEWLINE);
	vty_out(vty, "  Channel Description BS-PA-MFRMS: %u%s",
		bts->si_common.chan_desc.bs_pa_mfrms + 2, VTY_NEWLINE);
	vty_out(vty, "  Channel Description BS-AG_BLKS-RES: %u%s",
		bts->si_common.chan_desc.bs_ag_blks_res, VTY_NEWLINE);
	vty_out(vty, "  System Information present: 0x%08x, static: 0x%08x%s",
		bts->si_valid, bts->si_mode_static, VTY_NEWLINE);
	vty_out(vty, "  Early Classmark Sending: 2G %s, 3G %s%s%s",
		bts->early_classmark_allowed ? "allowed" : "forbidden",
		bts->early_classmark_allowed_3g ? "allowed" : "forbidden",
		bts->early_classmark_allowed_3g && !bts->early_classmark_allowed ?
		" (forbidden by 2G bit)" : "",
		VTY_NEWLINE);
	if (bts->pcu_sock_path)
		vty_out(vty, "  PCU Socket Path: %s%s", bts->pcu_sock_path, VTY_NEWLINE);
	if (is_ipaccess_bts(bts))
		vty_out(vty, "  Unit ID: %u/%u/0, OML Stream ID 0x%02x%s",
			bts->ip_access.site_id, bts->ip_access.bts_id,
			bts->oml_tei, VTY_NEWLINE);
	else if (bts->type == GSM_BTS_TYPE_NOKIA_SITE)
		vty_out(vty, "  Skip Reset: %d%s",
			bts->nokia.skip_reset, VTY_NEWLINE);
	vty_out(vty, "  NM State: ");
	net_dump_nmstate(vty, &bts->mo.nm_state);
	vty_out(vty, "  Site Mgr NM State: ");
	net_dump_nmstate(vty, &bts->site_mgr->mo.nm_state);

	if (bts->gprs.mode != BTS_GPRS_NONE) {
		vty_out(vty, "  GPRS NSE: ");
		net_dump_nmstate(vty, &bts->site_mgr->gprs.nse.mo.nm_state);
		vty_out(vty, "  GPRS CELL: ");
		net_dump_nmstate(vty, &bts->gprs.cell.mo.nm_state);
		vty_out(vty, "  GPRS NSVC0: ");
		net_dump_nmstate(vty, &bts->site_mgr->gprs.nsvc[0].mo.nm_state);
		vty_out(vty, "  GPRS NSVC1: ");
		net_dump_nmstate(vty, &bts->site_mgr->gprs.nsvc[1].mo.nm_state);
	} else
		vty_out(vty, "  GPRS: not configured%s", VTY_NEWLINE);

	vty_out(vty, "  Paging: %u pending requests, %u free slots%s",
		paging_pending_requests_nr(bts),
		bts->paging.available_slots, VTY_NEWLINE);
	if (is_ipaccess_bts(bts)) {
		vty_out(vty, "  OML Link: ");
		e1isl_dump_vty_tcp(vty, bts->oml_link);
		vty_out(vty, "  OML Link state: %s", get_model_oml_status(bts));
		sec = bts_uptime(bts);
		if (sec)
			vty_out(vty, " %llu days %llu hours %llu min. %llu sec.",
				OSMO_SEC2DAY(sec), OSMO_SEC2HRS(sec), OSMO_SEC2MIN(sec), sec % 60);
		vty_out(vty, "%s", VTY_NEWLINE);
	} else {
		vty_out(vty, "  E1 Signalling Link:%s", VTY_NEWLINE);
		e1isl_dump_vty(vty, bts->oml_link);
	}

	vty_out(vty, "  Neighbor Cells: ");
	switch (bts->neigh_list_manual_mode) {
	default:
	case NL_MODE_AUTOMATIC:
		vty_out(vty, "Automatic");
		/* generate_bcch_chan_list() should populate si_common.neigh_list */
		break;
	case NL_MODE_MANUAL:
		vty_out(vty, "Manual");
		break;
	case NL_MODE_MANUAL_SI5SEP:
		vty_out(vty, "Manual/separate SI5");
		break;
	}
	vty_out(vty, ", ARFCNs:");
	vty_out_neigh_list(vty, &bts->si_common.neigh_list);
	if (bts->neigh_list_manual_mode == NL_MODE_MANUAL_SI5SEP) {
		vty_out(vty, " SI5:");
		vty_out_neigh_list(vty, &bts->si_common.si5_neigh_list);
	}
	vty_out(vty, "%s", VTY_NEWLINE);

	/* FIXME: chan_desc */
	memset(&pl, 0, sizeof(pl));
	bts_chan_load(&pl, bts);
	vty_out(vty, "  Current Channel Load:%s", VTY_NEWLINE);
	dump_pchan_load_vty(vty, "    ", &pl);

	bts_dump_vty_cbch(vty, &bts->cbch_basic);
	bts_dump_vty_cbch(vty, &bts->cbch_extended);

	vty_out(vty, "  Channel Requests        : %"PRIu64" total, %"PRIu64" no channel%s",
		rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_CHREQ_TOTAL)->current,
		rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_CHREQ_NO_CHANNEL)->current,
		VTY_NEWLINE);
	vty_out(vty, "  Channel Failures        : %"PRIu64" rf_failures, %"PRIu64" rll failures%s",
		rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_CHAN_RF_FAIL)->current,
		rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_CHAN_RLL_ERR)->current,
		VTY_NEWLINE);
	vty_out(vty, "  BTS failures            : %"PRIu64" OML, %"PRIu64" RSL%s",
		rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_BTS_OML_FAIL)->current,
		rate_ctr_group_get_ctr(bts->bts_ctrs, BTS_CTR_BTS_RSL_FAIL)->current,
		VTY_NEWLINE);

	vty_out_stat_item_group(vty, "  ", bts->bts_statg);

	bts_dump_vty_features(vty, bts);
}

static void config_write_bts_gprs(struct vty *vty, struct gsm_bts *bts)
{
	unsigned int i;
	struct gsm_bts_sm *bts_sm = bts->site_mgr;
	vty_out(vty, "  gprs mode %s%s", bts_gprs_mode_name(bts->gprs.mode),
		VTY_NEWLINE);
	if (bts->gprs.mode == BTS_GPRS_NONE)
		return;

	vty_out(vty, "  gprs routing area %u%s", bts->gprs.rac,
		VTY_NEWLINE);
	vty_out(vty, "  gprs network-control-order nc%u%s",
		bts->gprs.net_ctrl_ord, VTY_NEWLINE);
	if (!bts->gprs.ctrl_ack_type_use_block)
		vty_out(vty, "  gprs control-ack-type-rach%s", VTY_NEWLINE);
	if (bts->gprs.ccn.forced_vty)
		vty_out(vty, "  gprs ccn-active %d%s",
			bts->gprs.ccn.active ? 1 : 0, VTY_NEWLINE);
	vty_out(vty, "  gprs power-control alpha %u%s",
		bts->gprs.pwr_ctrl.alpha, VTY_NEWLINE);
	vty_out(vty, "  gprs cell bvci %u%s", bts->gprs.cell.bvci,
		VTY_NEWLINE);
	for (i = 0; i < ARRAY_SIZE(bts->gprs.cell.timer); i++)
		vty_out(vty, "  gprs cell timer %s %u%s",
			get_value_string(gprs_bssgp_cfg_strs, i),
			bts->gprs.cell.timer[i], VTY_NEWLINE);
	vty_out(vty, "  gprs nsei %u%s", bts_sm->gprs.nse.nsei,
		VTY_NEWLINE);
	for (i = 0; i < ARRAY_SIZE(bts_sm->gprs.nse.timer); i++)
		vty_out(vty, "  gprs ns timer %s %u%s",
			get_value_string(gprs_ns_timer_strs, i),
			bts_sm->gprs.nse.timer[i], VTY_NEWLINE);
	for (i = 0; i < ARRAY_SIZE(bts_sm->gprs.nsvc); i++) {
		const struct gsm_gprs_nsvc *nsvc = &bts_sm->gprs.nsvc[i];
		struct osmo_sockaddr_str remote;

		vty_out(vty, "  gprs nsvc %u nsvci %u%s", i,
			nsvc->nsvci, VTY_NEWLINE);

		vty_out(vty, "  gprs nsvc %u local udp port %u%s", i,
			nsvc->local_port, VTY_NEWLINE);

		/* Most likely, the remote address is not configured (AF_UNSPEC).
		 * Printing the port alone makes no sense, so let's just skip both. */
		if (osmo_sockaddr_str_from_sockaddr(&remote, &nsvc->remote.u.sas) != 0)
			continue;

		vty_out(vty, "  gprs nsvc %u remote ip %s%s",
			i, remote.ip, VTY_NEWLINE);
		vty_out(vty, "  gprs nsvc %u remote udp port %u%s",
			i, remote.port, VTY_NEWLINE);
	}

	/* EGPRS specific parameters */
	if (bts->gprs.mode == BTS_GPRS_EGPRS) {
		if (bts->gprs.egprs_pkt_chan_request)
			vty_out(vty, "  gprs egprs-packet-channel-request%s", VTY_NEWLINE);
	}
}

/* Write the model data if there is one */
static void config_write_bts_model(struct vty *vty, struct gsm_bts *bts)
{
	struct gsm_bts_trx *trx;

	if (!bts->model)
		return;

	if (bts->model->config_write_bts)
		bts->model->config_write_bts(vty, bts);

	llist_for_each_entry(trx, &bts->trx_list, list)
		config_write_trx_single(vty, trx);
}

static void write_amr_modes(struct vty *vty, const char *prefix,
	const char *name, struct amr_mode *modes, int num)
{
	int i;

	vty_out(vty, "  %s threshold %s", prefix, name);
	for (i = 0; i < num - 1; i++)
		vty_out(vty, " %d", modes[i].threshold);
	vty_out(vty, "%s", VTY_NEWLINE);
	vty_out(vty, "  %s hysteresis %s", prefix, name);
	for (i = 0; i < num - 1; i++)
		vty_out(vty, " %d", modes[i].hysteresis);
	vty_out(vty, "%s", VTY_NEWLINE);
}

static void config_write_bts_amr(struct vty *vty, struct gsm_bts *bts,
	struct amr_multirate_conf *mr, int full)
{
	struct gsm48_multi_rate_conf *mr_conf;
	const char *prefix = (full) ? "amr tch-f" : "amr tch-h";
	int i, num;

	if (!(mr->gsm48_ie[1]))
		return;

	mr_conf = (struct gsm48_multi_rate_conf *) mr->gsm48_ie;

	num = 0;
	vty_out(vty, "  %s modes", prefix);
	for (i = 0; i < ((full) ? 8 : 6); i++) {
		if ((mr->gsm48_ie[1] & (1 << i))) {
			vty_out(vty, " %d", i);
			num++;
		}
	}
	vty_out(vty, "%s", VTY_NEWLINE);
	if (num > 4)
		num = 4;
	if (num > 1) {
		write_amr_modes(vty, prefix, "ms", mr->ms_mode, num);
		write_amr_modes(vty, prefix, "bts", mr->bts_mode, num);
	}
	vty_out(vty, "  %s start-mode ", prefix);
	if (mr_conf->icmi) {
		num = 0;
		for (i = 0; i < ((full) ? 8 : 6) && num < 4; i++) {
			if ((mr->gsm48_ie[1] & (1 << i)))
				num++;
			if (mr_conf->smod == num - 1) {
				vty_out(vty, "%d%s", num, VTY_NEWLINE);
				break;
			}
		}
	} else
		vty_out(vty, "auto%s", VTY_NEWLINE);
}

/* TODO: generalize and move indention handling to libosmocore */
#define cfg_out(fmt, args...) \
	vty_out(vty, "%*s" fmt, indent, "", ##args);

static void config_write_power_ctrl_meas(struct vty *vty, unsigned int indent,
					 const struct gsm_power_ctrl_meas_params *mp,
					 const char *param, const char *param2)
{
	if (strcmp(param, "ci") == 0) {
		cfg_out("%s-thresh%s %s%s",
			param, param2, mp->enabled ? "enable" : "disable",
			VTY_NEWLINE);
	}

	cfg_out("%s-thresh%s lower %u upper %u%s",
		param, param2, mp->lower_thresh, mp->upper_thresh,
		VTY_NEWLINE);
	cfg_out("%s-thresh-comp%s lower %u %u upper %u %u%s",
		param, param2, mp->lower_cmp_p, mp->lower_cmp_n,
		mp->upper_cmp_p, mp->upper_cmp_n,
		VTY_NEWLINE);

	switch (mp->algo) {
	case GSM_PWR_CTRL_MEAS_AVG_ALGO_NONE:
		/* Do not print any averaging parameters */
		return; /* we're done */
	case GSM_PWR_CTRL_MEAS_AVG_ALGO_UNWEIGHTED:
		cfg_out("%s-avg%s algo unweighted%s", param, param2, VTY_NEWLINE);
		break;
	case GSM_PWR_CTRL_MEAS_AVG_ALGO_WEIGHTED:
		cfg_out("%s-avg%s algo weighted%s", param, param2, VTY_NEWLINE);
		break;
	case GSM_PWR_CTRL_MEAS_AVG_ALGO_MOD_MEDIAN:
		cfg_out("%s-avg%s algo mod-median%s", param, param2, VTY_NEWLINE);
		break;
	case GSM_PWR_CTRL_MEAS_AVG_ALGO_OSMO_EWMA:
		cfg_out("%s-avg%s algo osmo-ewma beta %u%s",
			param, param2, 100 - mp->ewma.alpha,
			VTY_NEWLINE);
		break;
	}

	cfg_out("%s-avg%s params hreqave %u hreqt %u%s",
		param, param2, mp->h_reqave, mp->h_reqt,
		VTY_NEWLINE);
}

static void config_write_power_ctrl(struct vty *vty, unsigned int indent,
				    const struct gsm_bts *bts,
				    const struct gsm_power_ctrl_params *cp)
{
	const char *node_name;

	if (cp->dir == GSM_PWR_CTRL_DIR_UL)
		node_name = "ms-power-control";
	else
		node_name = "bs-power-control";

	switch (cp->mode) {
	case GSM_PWR_CTRL_MODE_NONE:
		cfg_out("no %s%s", node_name, VTY_NEWLINE);
		break;
	case GSM_PWR_CTRL_MODE_STATIC:
		cfg_out("%s%s", node_name, VTY_NEWLINE);
		cfg_out(" mode static%s", VTY_NEWLINE);
		if (cp->dir == GSM_PWR_CTRL_DIR_DL && cp->bs_power_val_db != 0)
			cfg_out(" bs-power static %u%s", cp->bs_power_val_db, VTY_NEWLINE);
		break;
	case GSM_PWR_CTRL_MODE_DYN_BTS:
	case GSM_PWR_CTRL_MODE_DYN_BSC:
		cfg_out("%s%s", node_name, VTY_NEWLINE);
		cfg_out(" mode %s%s",
			cp->mode == GSM_PWR_CTRL_MODE_DYN_BTS ? "dyn-bts" : "dyn-bsc", VTY_NEWLINE);
		if (cp->dir == GSM_PWR_CTRL_DIR_DL)
			cfg_out(" bs-power dyn-max %u%s", cp->bs_power_max_db, VTY_NEWLINE);

		cfg_out(" ctrl-interval %u%s", cp->ctrl_interval, VTY_NEWLINE);
		cfg_out(" step-size inc %u red %u%s",
			cp->inc_step_size_db, cp->red_step_size_db,
			VTY_NEWLINE);

		/* Measurement processing / averaging parameters */
		config_write_power_ctrl_meas(vty, indent + 1, &cp->rxlev_meas, "rxlev", "");
		config_write_power_ctrl_meas(vty, indent + 1, &cp->rxqual_meas, "rxqual", "");
		if (cp->dir == GSM_PWR_CTRL_DIR_UL && is_osmobts(bts)
		    && cp->mode == GSM_PWR_CTRL_MODE_DYN_BTS) {
			config_write_power_ctrl_meas(vty, indent + 1, &cp->ci_fr_meas, "ci", " fr-efr");
			config_write_power_ctrl_meas(vty, indent + 1, &cp->ci_hr_meas, "ci", " hr");
			config_write_power_ctrl_meas(vty, indent + 1, &cp->ci_amr_fr_meas, "ci", " amr-fr");
			config_write_power_ctrl_meas(vty, indent + 1, &cp->ci_amr_hr_meas, "ci", " amr-hr");
			config_write_power_ctrl_meas(vty, indent + 1, &cp->ci_sdcch_meas, "ci", " sdcch");
			config_write_power_ctrl_meas(vty, indent + 1, &cp->ci_gprs_meas, "ci", " gprs");
		}
		break;
	}
}

#undef cfg_out

static void config_write_bts_single(struct vty *vty, struct gsm_bts *bts)
{
	int i;
	uint8_t tmp;

	vty_out(vty, " bts %u%s", bts->nr, VTY_NEWLINE);
	vty_out(vty, "  type %s%s", btstype2str(bts->type), VTY_NEWLINE);
	if (bts->description)
		vty_out(vty, "  description %s%s", bts->description, VTY_NEWLINE);
	vty_out(vty, "  band %s%s", gsm_band_name(bts->band), VTY_NEWLINE);
	vty_out(vty, "  cell_identity %u%s", bts->cell_identity, VTY_NEWLINE);
	vty_out(vty, "  location_area_code %u%s", bts->location_area_code,
		VTY_NEWLINE);
	if (bts->dtxu != GSM48_DTX_SHALL_NOT_BE_USED)
		vty_out(vty, "  dtx uplink%s%s",
			(bts->dtxu != GSM48_DTX_SHALL_BE_USED) ? "" : " force",
			VTY_NEWLINE);
	if (bts->dtxd)
		vty_out(vty, "  dtx downlink%s", VTY_NEWLINE);
	vty_out(vty, "  base_station_id_code %u%s", bts->bsic, VTY_NEWLINE);
	vty_out(vty, "  ms max power %u%s", bts->ms_max_power, VTY_NEWLINE);
	vty_out(vty, "  cell reselection hysteresis %u%s",
		bts->si_common.cell_sel_par.cell_resel_hyst*2, VTY_NEWLINE);
	vty_out(vty, "  rxlev access min %u%s",
		bts->si_common.cell_sel_par.rxlev_acc_min, VTY_NEWLINE);

	if (bts->si_common.cell_ro_sel_par.present) {
		struct osmo_gsm48_si_selection_params *sp;
		sp = &bts->si_common.cell_ro_sel_par;

		if (sp->cbq)
			vty_out(vty, "  cell bar qualify %u%s",
				sp->cbq, VTY_NEWLINE);

		if (sp->cell_resel_off)
			vty_out(vty, "  cell reselection offset %u%s",
				sp->cell_resel_off*2, VTY_NEWLINE);

		if (sp->temp_offs == 7)
			vty_out(vty, "  temporary offset infinite%s",
				VTY_NEWLINE);
		else if (sp->temp_offs)
			vty_out(vty, "  temporary offset %u%s",
				sp->temp_offs*10, VTY_NEWLINE);

		if (sp->penalty_time == 31)
			vty_out(vty, "  penalty time reserved%s",
				VTY_NEWLINE);
		else if (sp->penalty_time)
			vty_out(vty, "  penalty time %u%s",
				(sp->penalty_time*20)+20, VTY_NEWLINE);
	}

	if (gsm_bts_get_radio_link_timeout(bts) < 0)
		vty_out(vty, "  radio-link-timeout infinite%s", VTY_NEWLINE);
	else
		vty_out(vty, "  radio-link-timeout %d%s",
			gsm_bts_get_radio_link_timeout(bts), VTY_NEWLINE);

	vty_out(vty, "  channel allocator %s%s",
		bts->chan_alloc_reverse ? "descending" : "ascending",
		VTY_NEWLINE);
	if (bts->chan_alloc_avoid_interf)
		vty_out(vty, "  channel allocator avoid-interference 1%s", VTY_NEWLINE);
	if (!bts->chan_alloc_allow_tch_for_signalling)
		vty_out(vty, "  channel allocator allow-tch-for-signalling 0%s", VTY_NEWLINE);
	vty_out(vty, "  rach tx integer %u%s",
		bts->si_common.rach_control.tx_integer, VTY_NEWLINE);
	vty_out(vty, "  rach max transmission %u%s",
		rach_max_trans_raw2val(bts->si_common.rach_control.max_trans),
		VTY_NEWLINE);
	vty_out(vty, "  rach max-delay %u%s", bts->rach_max_delay, VTY_NEWLINE);

	vty_out(vty, "  channel-description attach %u%s",
		bts->si_common.chan_desc.att, VTY_NEWLINE);
	vty_out(vty, "  channel-description bs-pa-mfrms %u%s",
		bts->si_common.chan_desc.bs_pa_mfrms + 2, VTY_NEWLINE);
	vty_out(vty, "  channel-description bs-ag-blks-res %u%s",
		bts->si_common.chan_desc.bs_ag_blks_res, VTY_NEWLINE);

	if (bts->ccch_load_ind_thresh != 10)
		vty_out(vty, "  ccch load-indication-threshold %u%s",
			bts->ccch_load_ind_thresh, VTY_NEWLINE);
	if (bts->rach_b_thresh != -1)
		vty_out(vty, "  rach nm busy threshold %u%s",
			bts->rach_b_thresh, VTY_NEWLINE);
	if (bts->rach_ldavg_slots != -1)
		vty_out(vty, "  rach nm load average %u%s",
			bts->rach_ldavg_slots, VTY_NEWLINE);
	if (bts->si_common.rach_control.cell_bar)
		vty_out(vty, "  cell barred 1%s", VTY_NEWLINE);
	if ((bts->si_common.rach_control.t2 & 0x4) == 0)
		vty_out(vty, "  rach emergency call allowed 1%s", VTY_NEWLINE);
	if (bts->si_common.rach_control.re == 0)
		vty_out(vty, "  rach call-reestablishment allowed 1%s", VTY_NEWLINE);
	if ((bts->si_common.rach_control.t3) != 0)
		for (i = 0; i < 8; i++)
			if (bts->si_common.rach_control.t3 & (0x1 << i))
				vty_out(vty, "  rach access-control-class %d barred%s", i, VTY_NEWLINE);
	if ((bts->si_common.rach_control.t2 & 0xfb) != 0)
		for (i = 0; i < 8; i++)
			if ((i != 2) && (bts->si_common.rach_control.t2 & (0x1 << i)))
				vty_out(vty, "  rach access-control-class %d barred%s", i+8, VTY_NEWLINE);
	if (bts->acc_mgr.len_allowed_adm < 10)
		vty_out(vty, "  access-control-class-rotate %" PRIu8 "%s", bts->acc_mgr.len_allowed_adm, VTY_NEWLINE);
	if (bts->acc_mgr.rotation_time_sec != ACC_MGR_QUANTUM_DEFAULT)
		vty_out(vty, "  access-control-class-rotate-quantum %" PRIu32 "%s", bts->acc_mgr.rotation_time_sec, VTY_NEWLINE);
	vty_out(vty, "  %saccess-control-class-ramping%s", acc_ramp_is_enabled(&bts->acc_ramp) ? "" : "no ", VTY_NEWLINE);
	if (acc_ramp_is_enabled(&bts->acc_ramp)) {
		vty_out(vty, "  access-control-class-ramping-step-interval %u%s",
			acc_ramp_get_step_interval(&bts->acc_ramp), VTY_NEWLINE);
		vty_out(vty, "  access-control-class-ramping-step-size %u%s", acc_ramp_get_step_size(&bts->acc_ramp),
			VTY_NEWLINE);
		vty_out(vty, "  access-control-class-ramping-chan-load %u %u%s",
			bts->acc_ramp.chan_load_lower_threshold, bts->acc_ramp.chan_load_upper_threshold, VTY_NEWLINE);
	}
	if (!bts->si_unused_send_empty)
		vty_out(vty, "  no system-information unused-send-empty%s", VTY_NEWLINE);
	for (i = SYSINFO_TYPE_1; i < _MAX_SYSINFO_TYPE; i++) {
		if (bts->si_mode_static & (1 << i)) {
			vty_out(vty, "  system-information %s mode static%s",
				get_value_string(osmo_sitype_strs, i), VTY_NEWLINE);
			vty_out(vty, "  system-information %s static %s%s",
				get_value_string(osmo_sitype_strs, i),
				osmo_hexdump_nospc(GSM_BTS_SI(bts, i), GSM_MACBLOCK_LEN),
				VTY_NEWLINE);
		}
	}
	vty_out(vty, "  early-classmark-sending %s%s",
		bts->early_classmark_allowed ? "allowed" : "forbidden", VTY_NEWLINE);
	vty_out(vty, "  early-classmark-sending-3g %s%s",
		bts->early_classmark_allowed_3g ? "allowed" : "forbidden", VTY_NEWLINE);
	switch (bts->type) {
	case GSM_BTS_TYPE_NANOBTS:
	case GSM_BTS_TYPE_OSMOBTS:
		vty_out(vty, "  ipa unit-id %u %u%s",
			bts->ip_access.site_id, bts->ip_access.bts_id, VTY_NEWLINE);
		if (bts->ip_access.rsl_ip) {
			struct in_addr ia;
			ia.s_addr = htonl(bts->ip_access.rsl_ip);
			vty_out(vty, "  ipa rsl-ip %s%s", inet_ntoa(ia),
				VTY_NEWLINE);
		}
		vty_out(vty, "  oml ipa stream-id %u line %u%s",
			bts->oml_tei, bts->oml_e1_link.e1_nr, VTY_NEWLINE);
		break;
	case GSM_BTS_TYPE_NOKIA_SITE:
		vty_out(vty, "  nokia_site skip-reset %d%s", bts->nokia.skip_reset, VTY_NEWLINE);
		vty_out(vty, "  nokia_site no-local-rel-conf %d%s",
			bts->nokia.no_loc_rel_cnf, VTY_NEWLINE);
		vty_out(vty, "  nokia_site bts-reset-timer %d%s", bts->nokia.bts_reset_timer_cnf, VTY_NEWLINE);
		/* fall through: Nokia requires "oml e1" parameters also */
	default:
		config_write_e1_link(vty, &bts->oml_e1_link, "  oml ");
		vty_out(vty, "  oml e1 tei %u%s", bts->oml_tei, VTY_NEWLINE);
		break;
	}

	/* if we have a limit, write it */
	if (bts->paging.free_chans_need >= 0)
		vty_out(vty, "  paging free %d%s", bts->paging.free_chans_need, VTY_NEWLINE);

	vty_out(vty, "  neighbor-list mode %s%s",
		get_value_string(bts_neigh_mode_strs, bts->neigh_list_manual_mode), VTY_NEWLINE);
	if (bts->neigh_list_manual_mode != NL_MODE_AUTOMATIC) {
		for (i = 0; i < 1024; i++) {
			if (bitvec_get_bit_pos(&bts->si_common.neigh_list, i))
				vty_out(vty, "  neighbor-list add arfcn %u%s",
					i, VTY_NEWLINE);
		}
	}
	if (bts->neigh_list_manual_mode == NL_MODE_MANUAL_SI5SEP) {
		for (i = 0; i < 1024; i++) {
			if (bitvec_get_bit_pos(&bts->si_common.si5_neigh_list, i))
				vty_out(vty, "  si5 neighbor-list add arfcn %u%s",
					i, VTY_NEWLINE);
		}
	}

	for (i = 0; i < MAX_EARFCN_LIST; i++) {
		struct osmo_earfcn_si2q *e = &bts->si_common.si2quater_neigh_list;
		if (e->arfcn[i] != OSMO_EARFCN_INVALID) {
			vty_out(vty, "  si2quater neighbor-list add earfcn %u "
				"thresh-hi %u", e->arfcn[i], e->thresh_hi);

			vty_out(vty, " thresh-lo %u",
				e->thresh_lo_valid ? e->thresh_lo : 32);

			vty_out(vty, " prio %u",
				e->prio_valid ? e->prio : 8);

			vty_out(vty, " qrxlv %u",
				e->qrxlm_valid ? e->qrxlm : 32);

			tmp = e->meas_bw[i];
			vty_out(vty, " meas %u",
				(tmp != OSMO_EARFCN_MEAS_INVALID) ? tmp : 8);

			vty_out(vty, "%s", VTY_NEWLINE);
		}
	}

	for (i = 0; i < bts->si_common.uarfcn_length; i++) {
		vty_out(vty, "  si2quater neighbor-list add uarfcn %u %u %u%s",
			bts->si_common.data.uarfcn_list[i],
			bts->si_common.data.scramble_list[i] & ~(1 << 9),
			(bts->si_common.data.scramble_list[i] >> 9) & 1,
			VTY_NEWLINE);
	}

	neighbor_ident_vty_write_bts(vty, "  ", bts);

	vty_out(vty, "  codec-support fr");
	if (bts->codec.hr)
		vty_out(vty, " hr");
	if (bts->codec.efr)
		vty_out(vty, " efr");
	if (bts->codec.amr)
		vty_out(vty, " amr");
	vty_out(vty, "%s", VTY_NEWLINE);

	config_write_bts_amr(vty, bts, &bts->mr_full, 1);
	config_write_bts_amr(vty, bts, &bts->mr_half, 0);

	config_write_bts_gprs(vty, bts);

	if (bts->excl_from_rf_lock)
		vty_out(vty, "  rf-lock-exclude%s", VTY_NEWLINE);

	if (bts->force_combined_si_set)
		vty_out(vty, "  %sforce-combined-si%s",
			bts->force_combined_si ? "" : "no ", VTY_NEWLINE);

	for (i = 0; i < ARRAY_SIZE(bts->depends_on); ++i) {
		int j;

		if (bts->depends_on[i] == 0)
			continue;

		for (j = 0; j < sizeof(bts->depends_on[i]) * 8; ++j) {
			int bts_nr;

			if ((bts->depends_on[i] & (1<<j)) == 0)
				continue;

			bts_nr = (i * sizeof(bts->depends_on[i]) * 8) + j;
			vty_out(vty, "  depends-on-bts %d%s", bts_nr, VTY_NEWLINE);
		}
	}
	if (bts->pcu_sock_path)
		vty_out(vty, "  pcu-socket %s%s", bts->pcu_sock_path, VTY_NEWLINE);

	ho_vty_write_bts(vty, bts);

	if (bts->top_acch_cap.overpower_db > 0) {
		const struct abis_rsl_osmo_temp_ovp_acch_cap *top = \
			&bts->top_acch_cap;
		const char *mode = NULL;

		if (top->sacch_enable && top->facch_enable)
			mode = "dl-acch";
		else if (top->sacch_enable)
			mode = "dl-sacch";
		else if (top->facch_enable)
			mode = "dl-facch";
		else /* shall not happen */
			OSMO_ASSERT(0);

		vty_out(vty, "  overpower %s %u%s",
			mode, top->overpower_db, VTY_NEWLINE);
		vty_out(vty, "  overpower rxqual %u%s",
			top->rxqual, VTY_NEWLINE);
		vty_out(vty, "  overpower chan-mode %s%s",
			get_value_string(top_acch_chan_mode_name,
					 bts->top_acch_chan_mode),
			VTY_NEWLINE);
	}

	if (bts->rep_acch_cap.dl_facch_all)
		vty_out(vty, "  repeat dl-facch all%s", VTY_NEWLINE);
	else if (bts->rep_acch_cap.dl_facch_cmd)
		vty_out(vty, "  repeat dl-facch command%s", VTY_NEWLINE);
	if (bts->rep_acch_cap.dl_sacch)
		vty_out(vty, "  repeat dl-sacch%s", VTY_NEWLINE);
	if (bts->rep_acch_cap.ul_sacch)
		vty_out(vty, "  repeat ul-sacch%s", VTY_NEWLINE);
	if (bts->rep_acch_cap.ul_sacch
	    || bts->rep_acch_cap.dl_facch_cmd
	    || bts->rep_acch_cap.dl_facch_cmd)
		vty_out(vty, "  repeat rxqual %u%s", bts->rep_acch_cap.rxqual, VTY_NEWLINE);

	if (bts->interf_meas_params_cfg.avg_period != interf_meas_params_def.avg_period) {
		vty_out(vty, "  interference-meas avg-period %u%s",
			bts->interf_meas_params_cfg.avg_period,
			VTY_NEWLINE);
	}
	if (memcmp(bts->interf_meas_params_cfg.bounds_dbm,
		   interf_meas_params_def.bounds_dbm,
		   sizeof(interf_meas_params_def.bounds_dbm))) {
		vty_out(vty, "  interference-meas level-bounds "
			"%d %d %d %d %d %d%s",
			-1 * bts->interf_meas_params_cfg.bounds_dbm[0],
			-1 * bts->interf_meas_params_cfg.bounds_dbm[1],
			-1 * bts->interf_meas_params_cfg.bounds_dbm[2],
			-1 * bts->interf_meas_params_cfg.bounds_dbm[3],
			-1 * bts->interf_meas_params_cfg.bounds_dbm[4],
			-1 * bts->interf_meas_params_cfg.bounds_dbm[5],
			VTY_NEWLINE);
	}

	if (!bts->srvcc_fast_return_allowed)
		vty_out(vty, "  srvcc fast-return forbid%s", VTY_NEWLINE);

	switch (bts->imm_ass_time) {
	default:
	case IMM_ASS_TIME_POST_CHAN_ACK:
		/* default value */
		break;
	case IMM_ASS_TIME_PRE_CHAN_ACK:
		vty_out(vty, "  immediate-assignment pre-chan-ack%s", VTY_NEWLINE);
		break;
	case IMM_ASS_TIME_PRE_TS_ACK:
		vty_out(vty, "  immediate-assignment pre-ts-ack%s", VTY_NEWLINE);
		break;
	}

	/* BS/MS Power Control parameters */
	config_write_power_ctrl(vty, 2, bts, &bts->bs_power_ctrl);
	config_write_power_ctrl(vty, 2, bts, &bts->ms_power_ctrl);

	config_write_bts_model(vty, bts);
}

int config_write_bts(struct vty *v)
{
	struct gsm_network *gsmnet = gsmnet_from_vty(v);
	struct gsm_bts *bts;

	llist_for_each_entry(bts, &gsmnet->bts_list, list)
		config_write_bts_single(v, bts);

	return CMD_SUCCESS;
}

int bts_vty_init(void)
{
	cfg_bts_type_cmd.string =
		vty_cmd_string_from_valstr(tall_bsc_ctx,
					   bts_type_names,
					   "type (", "|", ")",
					   VTY_DO_LOWER);
	cfg_bts_type_cmd.doc =
		vty_cmd_string_from_valstr(tall_bsc_ctx,
					   bts_type_descs,
					   "BTS Vendor/Type\n",
					   "\n", "", 0);

	install_element(GSMNET_NODE, &cfg_bts_cmd);
	install_node(&bts_node, config_write_bts);
	install_element(BTS_NODE, &cfg_bts_type_cmd);
	install_element(BTS_NODE, &cfg_bts_type_sysmobts_cmd);
	install_element(BTS_NODE, &cfg_description_cmd);
	install_element(BTS_NODE, &cfg_no_description_cmd);
	install_element(BTS_NODE, &cfg_bts_band_cmd);
	install_element(BTS_NODE, &cfg_bts_ci_cmd);
	install_element(BTS_NODE, &cfg_bts_dtxu_cmd);
	install_element(BTS_NODE, &cfg_bts_dtxd_cmd);
	install_element(BTS_NODE, &cfg_bts_no_dtxu_cmd);
	install_element(BTS_NODE, &cfg_bts_no_dtxd_cmd);
	install_element(BTS_NODE, &cfg_bts_lac_cmd);
	install_element(BTS_NODE, &cfg_bts_tsc_cmd);
	install_element(BTS_NODE, &cfg_bts_bsic_cmd);
	install_element(BTS_NODE, &cfg_bts_unit_id_cmd);
	install_element(BTS_NODE, &cfg_bts_deprecated_unit_id_cmd);
	install_element(BTS_NODE, &cfg_bts_rsl_ip_cmd);
	install_element(BTS_NODE, &cfg_bts_deprecated_rsl_ip_cmd);
	install_element(BTS_NODE, &cfg_bts_nokia_site_skip_reset_cmd);
	install_element(BTS_NODE, &cfg_bts_nokia_site_no_loc_rel_cnf_cmd);
	install_element(BTS_NODE, &cfg_bts_nokia_site_bts_reset_timer_cnf_cmd);
	install_element(BTS_NODE, &cfg_bts_stream_id_cmd);
	install_element(BTS_NODE, &cfg_bts_deprecated_stream_id_cmd);
	install_element(BTS_NODE, &cfg_bts_oml_e1_cmd);
	install_element(BTS_NODE, &cfg_bts_oml_e1_tei_cmd);
	install_element(BTS_NODE, &cfg_bts_challoc_cmd);
	install_element(BTS_NODE, &cfg_bts_chan_alloc_interf_cmd);
	install_element(BTS_NODE, &cfg_bts_chan_alloc_allow_tch_for_signalling_cmd);
	install_element(BTS_NODE, &cfg_bts_rach_tx_integer_cmd);
	install_element(BTS_NODE, &cfg_bts_rach_max_trans_cmd);
	install_element(BTS_NODE, &cfg_bts_rach_max_delay_cmd);
	install_element(BTS_NODE, &cfg_bts_chan_desc_att_cmd);
	install_element(BTS_NODE, &cfg_bts_chan_dscr_att_cmd);
	install_element(BTS_NODE, &cfg_bts_chan_desc_bs_pa_mfrms_cmd);
	install_element(BTS_NODE, &cfg_bts_chan_dscr_bs_pa_mfrms_cmd);
	install_element(BTS_NODE, &cfg_bts_chan_desc_bs_ag_blks_res_cmd);
	install_element(BTS_NODE, &cfg_bts_chan_dscr_bs_ag_blks_res_cmd);
	install_element(BTS_NODE, &cfg_bts_ccch_load_ind_thresh_cmd);
	install_element(BTS_NODE, &cfg_bts_rach_nm_b_thresh_cmd);
	install_element(BTS_NODE, &cfg_bts_rach_nm_ldavg_cmd);
	install_element(BTS_NODE, &cfg_bts_cell_barred_cmd);
	install_element(BTS_NODE, &cfg_bts_rach_ec_allowed_cmd);
	install_element(BTS_NODE, &cfg_bts_rach_re_allowed_cmd);
	install_element(BTS_NODE, &cfg_bts_rach_ac_class_cmd);
	install_element(BTS_NODE, &cfg_bts_ms_max_power_cmd);
	install_element(BTS_NODE, &cfg_bts_cell_resel_hyst_cmd);
	install_element(BTS_NODE, &cfg_bts_rxlev_acc_min_cmd);
	install_element(BTS_NODE, &cfg_bts_cell_bar_qualify_cmd);
	install_element(BTS_NODE, &cfg_bts_cell_resel_ofs_cmd);
	install_element(BTS_NODE, &cfg_bts_temp_ofs_cmd);
	install_element(BTS_NODE, &cfg_bts_temp_ofs_inf_cmd);
	install_element(BTS_NODE, &cfg_bts_penalty_time_cmd);
	install_element(BTS_NODE, &cfg_bts_penalty_time_rsvd_cmd);
	install_element(BTS_NODE, &cfg_bts_radio_link_timeout_cmd);
	install_element(BTS_NODE, &cfg_bts_radio_link_timeout_inf_cmd);
	install_element(BTS_NODE, &cfg_bts_gprs_mode_cmd);
	install_element(BTS_NODE, &cfg_bts_gprs_11bit_rach_support_for_egprs_cmd);
	install_element(BTS_NODE, &cfg_bts_no_gprs_egprs_pkt_chan_req_cmd);
	install_element(BTS_NODE, &cfg_bts_gprs_egprs_pkt_chan_req_cmd);
	install_element(BTS_NODE, &cfg_bts_gprs_ns_timer_cmd);
	install_element(BTS_NODE, &cfg_bts_gprs_rac_cmd);
	install_element(BTS_NODE, &cfg_bts_gprs_net_ctrl_ord_cmd);
	install_element(BTS_NODE, &cfg_bts_gprs_ctrl_ack_cmd);
	install_element(BTS_NODE, &cfg_bts_gprs_ccn_active_cmd);
	install_element(BTS_NODE, &cfg_bts_gprs_pwr_ctrl_alpha_cmd);
	install_element(BTS_NODE, &cfg_no_bts_gprs_ctrl_ack_cmd);
	install_element(BTS_NODE, &cfg_bts_gprs_bvci_cmd);
	install_element(BTS_NODE, &cfg_bts_gprs_cell_timer_cmd);
	install_element(BTS_NODE, &cfg_bts_gprs_nsei_cmd);
	install_element(BTS_NODE, &cfg_bts_gprs_nsvci_cmd);
	install_element(BTS_NODE, &cfg_bts_gprs_nsvc_lport_cmd);
	install_element(BTS_NODE, &cfg_bts_gprs_nsvc_rport_cmd);
	install_element(BTS_NODE, &cfg_bts_gprs_nsvc_rip_cmd);
	install_element(BTS_NODE, &cfg_bts_pag_free_cmd);
	install_element(BTS_NODE, &cfg_bts_si_mode_cmd);
	install_element(BTS_NODE, &cfg_bts_si_static_cmd);
	install_element(BTS_NODE, &cfg_bts_si_unused_send_empty_cmd);
	install_element(BTS_NODE, &cfg_bts_no_si_unused_send_empty_cmd);
	install_element(BTS_NODE, &cfg_bts_early_cm_cmd);
	install_element(BTS_NODE, &cfg_bts_early_cm_3g_cmd);
	install_element(BTS_NODE, &cfg_bts_neigh_mode_cmd);
	install_element(BTS_NODE, &cfg_bts_neigh_cmd);
	install_element(BTS_NODE, &cfg_bts_si5_neigh_cmd);
	install_element(BTS_NODE, &cfg_bts_si2quater_neigh_add_cmd);
	install_element(BTS_NODE, &cfg_bts_si2quater_neigh_del_cmd);
	install_element(BTS_NODE, &cfg_bts_si2quater_uarfcn_add_cmd);
	install_element(BTS_NODE, &cfg_bts_si2quater_uarfcn_del_cmd);
	install_element(BTS_NODE, &cfg_bts_excl_rf_lock_cmd);
	install_element(BTS_NODE, &cfg_bts_no_excl_rf_lock_cmd);
	install_element(BTS_NODE, &cfg_bts_force_comb_si_cmd);
	install_element(BTS_NODE, &cfg_bts_no_force_comb_si_cmd);
	install_element(BTS_NODE, &cfg_bts_codec0_cmd);
	install_element(BTS_NODE, &cfg_bts_codec1_cmd);
	install_element(BTS_NODE, &cfg_bts_codec2_cmd);
	install_element(BTS_NODE, &cfg_bts_codec3_cmd);
	install_element(BTS_NODE, &cfg_bts_codec4_cmd);
	install_element(BTS_NODE, &cfg_bts_depends_on_cmd);
	install_element(BTS_NODE, &cfg_bts_no_depends_on_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_fr_modes1_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_fr_modes2_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_fr_modes3_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_fr_modes4_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_fr_thres1_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_fr_thres2_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_fr_thres3_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_fr_hyst1_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_fr_hyst2_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_fr_hyst3_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_fr_start_mode_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_hr_modes1_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_hr_modes2_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_hr_modes3_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_hr_modes4_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_hr_thres1_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_hr_thres2_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_hr_thres3_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_hr_hyst1_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_hr_hyst2_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_hr_hyst3_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_hr_start_mode_cmd);
	install_element(BTS_NODE, &cfg_bts_pcu_sock_cmd);
	install_element(BTS_NODE, &cfg_bts_acc_rotate_cmd);
	install_element(BTS_NODE, &cfg_bts_acc_rotate_quantum_cmd);
	install_element(BTS_NODE, &cfg_bts_acc_ramping_cmd);
	install_element(BTS_NODE, &cfg_bts_no_acc_ramping_cmd);
	install_element(BTS_NODE, &cfg_bts_acc_ramping_step_interval_cmd);
	install_element(BTS_NODE, &cfg_bts_acc_ramping_step_size_cmd);
	install_element(BTS_NODE, &cfg_bts_acc_ramping_chan_load_cmd);
	install_element(BTS_NODE, &cfg_bts_t3113_dynamic_cmd);
	install_element(BTS_NODE, &cfg_bts_no_t3113_dynamic_cmd);
	install_element(BTS_NODE, &cfg_bts_rep_dl_facch_cmd);
	install_element(BTS_NODE, &cfg_bts_rep_no_dl_facch_cmd);
	install_element(BTS_NODE, &cfg_bts_rep_ul_dl_sacch_cmd);
	install_element(BTS_NODE, &cfg_bts_rep_no_ul_dl_sacch_cmd);
	install_element(BTS_NODE, &cfg_bts_rep_rxqual_cmd);
	install_element(BTS_NODE, &cfg_bts_top_dl_acch_cmd);
	install_element(BTS_NODE, &cfg_bts_top_no_dl_acch_cmd);
	install_element(BTS_NODE, &cfg_bts_top_dl_acch_rxqual_cmd);
	install_element(BTS_NODE, &cfg_bts_top_dl_acch_chan_mode_cmd);
	install_element(BTS_NODE, &cfg_bts_interf_meas_avg_period_cmd);
	install_element(BTS_NODE, &cfg_bts_interf_meas_level_bounds_cmd);
	install_element(BTS_NODE, &cfg_bts_srvcc_fast_return_cmd);
	install_element(BTS_NODE, &cfg_bts_immediate_assignment_cmd);

	neighbor_ident_vty_init();
	/* See also handover commands added on bts level from handover_vty.c */

	install_element(BTS_NODE, &cfg_bts_power_ctrl_cmd);
	install_element(BTS_NODE, &cfg_bts_no_power_ctrl_cmd);
	install_node(&power_ctrl_node, dummy_config_write);
	install_element(POWER_CTRL_NODE, &cfg_power_ctrl_mode_cmd);
	install_element(POWER_CTRL_NODE, &cfg_power_ctrl_bs_power_cmd);
	install_element(POWER_CTRL_NODE, &cfg_power_ctrl_ctrl_interval_cmd);
	install_element(POWER_CTRL_NODE, &cfg_power_ctrl_step_size_cmd);
	install_element(POWER_CTRL_NODE, &cfg_power_ctrl_rxlev_thresh_cmd);
	install_element(POWER_CTRL_NODE, &cfg_power_ctrl_rxqual_thresh_cmd);
	install_element(POWER_CTRL_NODE, &cfg_power_ctrl_ci_thresh_disable_cmd);
	install_element(POWER_CTRL_NODE, &cfg_power_ctrl_ci_thresh_cmd);
	install_element(POWER_CTRL_NODE, &cfg_power_ctrl_rxlev_thresh_comp_cmd);
	install_element(POWER_CTRL_NODE, &cfg_power_ctrl_rxqual_thresh_comp_cmd);
	install_element(POWER_CTRL_NODE, &cfg_power_ctrl_ci_thresh_comp_cmd);
	install_element(POWER_CTRL_NODE, &cfg_power_ctrl_no_avg_cmd);
	install_element(POWER_CTRL_NODE, &cfg_power_ctrl_avg_params_cmd);
	install_element(POWER_CTRL_NODE, &cfg_power_ctrl_avg_algo_cmd);
	install_element(POWER_CTRL_NODE, &cfg_power_ctrl_avg_osmo_ewma_cmd);
	install_element(POWER_CTRL_NODE, &cfg_power_ctrl_no_ci_avg_cmd);
	install_element(POWER_CTRL_NODE, &cfg_power_ctrl_ci_avg_params_cmd);
	install_element(POWER_CTRL_NODE, &cfg_power_ctrl_ci_avg_algo_cmd);
	install_element(POWER_CTRL_NODE, &cfg_power_ctrl_ci_avg_osmo_ewma_cmd);


	return bts_trx_vty_init();
}
