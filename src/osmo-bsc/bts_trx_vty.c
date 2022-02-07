/* OsmoBSC interface to quagga VTY, TRX (and TS) node */
/* (C) 2009-2017 by Harald Welte <laforge@gnumonks.org>
 * (C) 2021 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
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
#include <osmocom/vty/command.h>
#include <osmocom/vty/buffer.h>
#include <osmocom/vty/vty.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/stats.h>
#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/misc.h>

#include <osmocom/bsc/vty.h>
#include <osmocom/bsc/gsm_data.h>
#include <osmocom/abis/e1_input.h>
#include <osmocom/bsc/system_information.h>
#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/timeslot_fsm.h>
#include <osmocom/bsc/lchan_fsm.h>
#include <osmocom/bsc/lchan_select.h>
#include <osmocom/bsc/bts.h>

#include <inttypes.h>

#include "../../bscconfig.h"

#define X(x) (1 << x)

static struct cmd_node trx_node = {
	TRX_NODE,
	"%s(config-net-bts-trx)# ",
	1,
};

static struct cmd_node ts_node = {
	TS_NODE,
	"%s(config-net-bts-trx-ts)# ",
	1,
};

/* utility functions */
void parse_e1_link(struct gsm_e1_subslot *e1_link, const char *line,
			  const char *ts, const char *ss)
{
	e1_link->e1_nr = atoi(line);
	e1_link->e1_ts = atoi(ts);
	if (!strcmp(ss, "full"))
		e1_link->e1_ts_ss = 255;
	else
		e1_link->e1_ts_ss = atoi(ss);
}

#define TRX_TEXT "Radio Transceiver\n"

/* per TRX configuration */
DEFUN_ATTR(cfg_trx,
	   cfg_trx_cmd,
	   "trx <0-255>",
	   TRX_TEXT
	   "Select a TRX to configure\n",
	   CMD_ATTR_IMMEDIATE)
{
	int trx_nr = atoi(argv[0]);
	struct gsm_bts *bts = vty->index;
	struct gsm_bts_trx *trx;

	if (trx_nr > bts->num_trx) {
		vty_out(vty, "%% The next unused TRX number in this BTS is %u%s",
			bts->num_trx, VTY_NEWLINE);
		return CMD_WARNING;
	} else if (trx_nr == bts->num_trx) {
		/* we need to allocate a new one */
		trx = gsm_bts_trx_alloc(bts);
	} else
		trx = gsm_bts_trx_num(bts, trx_nr);

	if (!trx)
		return CMD_WARNING;

	vty->index = trx;
	vty->node = TRX_NODE;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_trx_arfcn,
	      cfg_trx_arfcn_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "arfcn <0-1023>",
	      "Set the ARFCN for this TRX\n"
	      "Absolute Radio Frequency Channel Number\n")
{
	enum gsm_band unused;
	struct gsm_bts_trx *trx = vty->index;
	int arfcn = atoi(argv[0]);

	if (gsm_arfcn2band_rc(arfcn, &unused) < 0) {
		vty_out(vty, "%% Invalid arfcn %" PRIu16 " detected%s", arfcn, VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* FIXME: check if this ARFCN is supported by this TRX */

	trx->arfcn = arfcn;

	/* Update Cell Allocation (list of all the frequencies allocated to a cell) */
	if (generate_cell_chan_alloc(trx->bts) != 0) {
		vty_out(vty, "%% Failed to re-generate Cell Allocation%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* FIXME: patch ARFCN into SYSTEM INFORMATION */
	/* FIXME: use OML layer to update the ARFCN */
	/* FIXME: use RSL layer to update SYSTEM INFORMATION */

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_trx_nominal_power,
	      cfg_trx_nominal_power_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "nominal power <-20-100>",
	      "Nominal TRX RF Power in dBm\n"
	      "Nominal TRX RF Power in dBm\n"
	      "Nominal TRX RF Power in dBm\n")
{
	struct gsm_bts_trx *trx = vty->index;

	trx->nominal_power = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_trx_max_power_red,
	      cfg_trx_max_power_red_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "max_power_red <0-100>",
	      "Reduction of maximum BS RF Power (relative to nominal power)\n"
	      "Reduction of maximum BS RF Power in dB\n")
{
	int maxpwr_r = atoi(argv[0]);
	struct gsm_bts_trx *trx = vty->index;
	int upper_limit = 24;	/* default 12.21 max power red. */

	/* FIXME: check if our BTS type supports more than 12 */
	if (maxpwr_r < 0 || maxpwr_r > upper_limit) {
		vty_out(vty, "%% Power %d dB is not in the valid range%s",
			maxpwr_r, VTY_NEWLINE);
		return CMD_WARNING;
	}
	if (maxpwr_r & 1) {
		vty_out(vty, "%% Power %d dB is not an even value%s",
			maxpwr_r, VTY_NEWLINE);
		return CMD_WARNING;
	}

	trx->max_power_red = maxpwr_r;

	/* FIXME: make sure we update this using OML */

	return CMD_SUCCESS;
}

/* NOTE: This requires a full restart as bsc_network_configure() is executed
 * only once on startup from osmo_bsc_main.c */
DEFUN(cfg_trx_rsl_e1,
      cfg_trx_rsl_e1_cmd,
      "rsl e1 line E1_LINE timeslot <1-31> sub-slot (0|1|2|3|full)",
      "RSL Parameters\n"
      "E1/T1 interface to be used for RSL\n"
      "E1/T1 interface to be used for RSL\n"
      "E1/T1 Line Number to be used for RSL\n"
      "E1/T1 Timeslot to be used for RSL\n"
      "E1/T1 Timeslot to be used for RSL\n"
      "E1/T1 Sub-slot to be used for RSL\n"
      "E1/T1 Sub-slot 0 is to be used for RSL\n"
      "E1/T1 Sub-slot 1 is to be used for RSL\n"
      "E1/T1 Sub-slot 2 is to be used for RSL\n"
      "E1/T1 Sub-slot 3 is to be used for RSL\n"
      "E1/T1 full timeslot is to be used for RSL\n")
{
	struct gsm_bts_trx *trx = vty->index;

	parse_e1_link(&trx->rsl_e1_link, argv[0], argv[1], argv[2]);

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_trx_rsl_e1_tei,
	      cfg_trx_rsl_e1_tei_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "rsl e1 tei <0-63>",
	      "RSL Parameters\n"
	      "Set the TEI to be used for RSL\n"
	      "Set the TEI to be used for RSL\n"
	      "TEI to be used for RSL\n")
{
	struct gsm_bts_trx *trx = vty->index;

	trx->rsl_tei_primary = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_trx_rf_locked,
	   cfg_trx_rf_locked_cmd,
	   "rf_locked (0|1)",
	   "Set or unset the RF Locking (Turn off RF of the TRX)\n"
	   "TRX is NOT RF locked (active)\n"
	   "TRX is RF locked (turned off)\n",
	   CMD_ATTR_IMMEDIATE)
{
	int locked = atoi(argv[0]);
	struct gsm_bts_trx *trx = vty->index;

	gsm_trx_lock_rf(trx, locked, "vty");
	return CMD_SUCCESS;
}

/* per TS configuration */
DEFUN_ATTR(cfg_ts,
	   cfg_ts_cmd,
	   "timeslot <0-7>",
	   "Select a Timeslot to configure\n"
	   "Timeslot number\n",
	   CMD_ATTR_IMMEDIATE)
{
	int ts_nr = atoi(argv[0]);
	struct gsm_bts_trx *trx = vty->index;
	struct gsm_bts_trx_ts *ts;

	if (ts_nr >= TRX_NR_TS) {
		vty_out(vty, "%% A GSM TRX only has %u Timeslots per TRX%s",
			TRX_NR_TS, VTY_NEWLINE);
		return CMD_WARNING;
	}

	ts = &trx->ts[ts_nr];

	vty->index = ts;
	vty->node = TS_NODE;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_ts_pchan,
	      cfg_ts_pchan_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "phys_chan_config PCHAN", /* dynamically generated! */
	      "Physical Channel configuration (TCH/SDCCH/...)\n" "Physical Channel\n")
{
	struct gsm_bts_trx_ts *ts = vty->index;
	int pchanc;

	pchanc = gsm_pchan_parse(argv[0]);
	if (pchanc < 0)
		return CMD_WARNING;

	ts->pchan_from_config = pchanc;

	return CMD_SUCCESS;
}

/* used for backwards compatibility with old config files that still
 * have uppercase pchan type names. Also match older names for existing types.  */
DEFUN_HIDDEN(cfg_ts_pchan_compat,
      cfg_ts_pchan_compat_cmd,
      "phys_chan_config PCHAN",
      "Physical Channel configuration (TCH/SDCCH/...)\n" "Physical Channel\n")
{
	struct gsm_bts_trx_ts *ts = vty->index;
	int pchanc;

	pchanc = gsm_pchan_parse(argv[0]);
	if (pchanc < 0) {
		if (strcasecmp(argv[0], "tch/f_tch/h_pdch") == 0) {
			pchanc = GSM_PCHAN_OSMO_DYN;
		} else {
			vty_out(vty, "Unknown physical channel name '%s'%s", argv[0], VTY_NEWLINE);
			return CMD_ERR_NO_MATCH;
		}
	}

	ts->pchan_from_config = pchanc;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_ts_tsc,
	      cfg_ts_tsc_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "training_sequence_code <0-7>",
	      "Training Sequence Code of the Timeslot\n" "TSC\n")
{
	struct gsm_bts_trx_ts *ts = vty->index;
	const struct gsm_bts *bts = ts->trx->bts;

	if (bts->features_known && !osmo_bts_has_feature(&bts->features, BTS_FEAT_MULTI_TSC)) {
		vty_out(vty, "%% This BTS does not support a TSC != BCC, "
			"falling back to BCC%s", VTY_NEWLINE);
		ts->tsc = -1;
		return CMD_WARNING;
	}

	ts->tsc = atoi(argv[0]);

	return CMD_SUCCESS;
}

#define HOPPING_STR "Configure frequency hopping\n"

DEFUN_USRATTR(cfg_ts_hopping,
	      cfg_ts_hopping_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "hopping enabled (0|1)",
	      HOPPING_STR "Enable or disable frequency hopping\n"
	      "Disable frequency hopping\n" "Enable frequency hopping\n")
{
	struct gsm_bts_trx_ts *ts = vty->index;
	const struct gsm_bts *bts = ts->trx->bts;
	int enabled = atoi(argv[0]);

	if (enabled && bts->features_known && !osmo_bts_has_feature(&bts->features, BTS_FEAT_HOPPING)) {
		vty_out(vty, "%% BTS does not support freq. hopping%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	ts->hopping.enabled = enabled;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_ts_hsn,
	      cfg_ts_hsn_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "hopping sequence-number <0-63>",
	      HOPPING_STR
	      "Which hopping sequence to use for this channel\n"
	      "Hopping Sequence Number (HSN)\n")
{
	struct gsm_bts_trx_ts *ts = vty->index;

	ts->hopping.hsn = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_ts_maio,
	      cfg_ts_maio_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "hopping maio <0-63>",
	      HOPPING_STR
	      "Which hopping MAIO to use for this channel\n"
	      "Mobile Allocation Index Offset (MAIO)\n")
{
	struct gsm_bts_trx_ts *ts = vty->index;

	ts->hopping.maio = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_ts_arfcn_add,
	      cfg_ts_arfcn_add_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "hopping arfcn add <0-1023>",
	      HOPPING_STR "Configure hopping ARFCN list\n"
	      "Add an entry to the hopping ARFCN list\n" "ARFCN\n")
{
	enum gsm_band unused;
	struct gsm_bts_trx_ts *ts = vty->index;
	int arfcn = atoi(argv[0]);

	if (gsm_arfcn2band_rc(arfcn, &unused) < 0) {
		vty_out(vty, "%% Invalid arfcn %" PRIu16 " detected%s", arfcn, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (bitvec_get_bit_pos(&ts->hopping.arfcns, arfcn) == ONE) {
		vty_out(vty, "%% ARFCN %" PRIu16 " is already set%s", arfcn, VTY_NEWLINE);
		return CMD_WARNING;
	}

	bitvec_set_bit_pos(&ts->hopping.arfcns, arfcn, 1);

	/* Update Cell Allocation (list of all the frequencies allocated to a cell) */
	if (generate_cell_chan_alloc(ts->trx->bts) != 0) {
		vty_out(vty, "%% Failed to re-generate Cell Allocation%s", VTY_NEWLINE);
		bitvec_set_bit_pos(&ts->hopping.arfcns, arfcn, ZERO); /* roll-back */
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_ts_arfcn_del,
	      cfg_ts_arfcn_del_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "hopping arfcn del <0-1023>",
	      HOPPING_STR "Configure hopping ARFCN list\n"
	      "Delete an entry to the hopping ARFCN list\n" "ARFCN\n")
{
	enum gsm_band unused;
	struct gsm_bts_trx_ts *ts = vty->index;
	int arfcn = atoi(argv[0]);

	if (gsm_arfcn2band_rc(arfcn, &unused) < 0) {
		vty_out(vty, "%% Invalid arfcn %" PRIu16 " detected%s", arfcn, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (bitvec_get_bit_pos(&ts->hopping.arfcns, arfcn) != ONE) {
		vty_out(vty, "%% ARFCN %" PRIu16 " is not set%s", arfcn, VTY_NEWLINE);
		return CMD_WARNING;
	}

	bitvec_set_bit_pos(&ts->hopping.arfcns, arfcn, 0);

	/* Update Cell Allocation (list of all the frequencies allocated to a cell) */
	if (generate_cell_chan_alloc(ts->trx->bts) != 0) {
		vty_out(vty, "%% Failed to re-generate Cell Allocation%s", VTY_NEWLINE);
		/* It's unlikely to happen on removal, so we don't roll-back */
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_ts_arfcn_del_all,
	      cfg_ts_arfcn_del_all_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "hopping arfcn del-all",
	      HOPPING_STR "Configure hopping ARFCN list\n"
	      "Delete all previously configured entries\n")
{
	struct gsm_bts_trx_ts *ts = vty->index;

	bitvec_zero(&ts->hopping.arfcns);

	/* Update Cell Allocation (list of all the frequencies allocated to a cell) */
	if (generate_cell_chan_alloc(ts->trx->bts) != 0) {
		vty_out(vty, "%% Failed to re-generate Cell Allocation%s", VTY_NEWLINE);
		/* It's unlikely to happen on removal, so we don't roll-back */
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

/* NOTE: This will have an effect on newly created voice lchans since the E1
 * voice channels are handled by osmo-mgw and the information put in e1_link
 * here is only used to generate the MGCP messages for the mgw. */
DEFUN_ATTR(cfg_ts_e1_subslot,
	   cfg_ts_e1_subslot_cmd,
	   "e1 line E1_LINE timeslot <1-31> sub-slot (0|1|2|3|full)",
	   "E1/T1 channel connected to this on-air timeslot\n"
	   "E1/T1 channel connected to this on-air timeslot\n"
	   "E1/T1 line connected to this on-air timeslot\n"
	   "E1/T1 timeslot connected to this on-air timeslot\n"
	   "E1/T1 timeslot connected to this on-air timeslot\n"
	   "E1/T1 sub-slot connected to this on-air timeslot\n"
	   "E1/T1 sub-slot 0 connected to this on-air timeslot\n"
	   "E1/T1 sub-slot 1 connected to this on-air timeslot\n"
	   "E1/T1 sub-slot 2 connected to this on-air timeslot\n"
	   "E1/T1 sub-slot 3 connected to this on-air timeslot\n"
	   "Full E1/T1 timeslot connected to this on-air timeslot\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct gsm_bts_trx_ts *ts = vty->index;

	parse_e1_link(&ts->e1_link, argv[0], argv[1], argv[2]);

	return CMD_SUCCESS;
}

/* call vty_out() to print a string like " as TCH/H" for dynamic timeslots.
 * Don't do anything if the ts is not dynamic. */
static void vty_out_dyn_ts_status(struct vty *vty, struct gsm_bts_trx_ts *ts)
{
	enum gsm_phys_chan_config target;
	if (ts_is_pchan_switching(ts, &target)) {
		vty_out(vty, " switching %s -> %s", gsm_pchan_name(ts->pchan_is),
			gsm_pchan_name(target));
	} else if (ts->pchan_is != ts->pchan_on_init) {
		vty_out(vty, " as %s", gsm_pchan_name(ts->pchan_is));
	}
}

static void vty_out_dyn_ts_details(struct vty *vty, struct gsm_bts_trx_ts *ts)
{
	/* show dyn TS details, if applicable */
	switch (ts->pchan_on_init) {
	case GSM_PCHAN_OSMO_DYN:
		vty_out(vty, "  Osmocom Dyn TS:");
		vty_out_dyn_ts_status(vty, ts);
		vty_out(vty, VTY_NEWLINE);
		break;
	case GSM_PCHAN_TCH_F_PDCH:
		vty_out(vty, "  IPACC Dyn PDCH TS:");
		vty_out_dyn_ts_status(vty, ts);
		vty_out(vty, VTY_NEWLINE);
		break;
	default:
		/* no dyn ts */
		break;
	}
}

static void meas_rep_dump_uni_vty(struct vty *vty,
				  struct gsm_meas_rep_unidir *mru,
				  const char *prefix,
				  const char *dir)
{
	vty_out(vty, "%s  RXL-FULL-%s: %4d dBm, RXL-SUB-%s: %4d dBm ",
		prefix, dir, rxlev2dbm(mru->full.rx_lev),
			dir, rxlev2dbm(mru->sub.rx_lev));
	vty_out(vty, "RXQ-FULL-%s: %d, RXQ-SUB-%s: %d%s",
		dir, mru->full.rx_qual, dir, mru->sub.rx_qual,
		VTY_NEWLINE);
}

static void meas_rep_dump_vty(struct vty *vty, struct gsm_meas_rep *mr,
			      const char *prefix)
{
	vty_out(vty, "%sMeasurement Report:%s", prefix, VTY_NEWLINE);
	vty_out(vty, "%s  Flags: %s%s%s%s%s", prefix,
			mr->flags & MEAS_REP_F_UL_DTX ? "DTXu " : "",
			mr->flags & MEAS_REP_F_DL_DTX ? "DTXd " : "",
			mr->flags & MEAS_REP_F_FPC ? "FPC " : "",
			mr->flags & MEAS_REP_F_DL_VALID ? " " : "DLinval ",
			VTY_NEWLINE);
	if (mr->flags & MEAS_REP_F_MS_TO)
		vty_out(vty, "%s  MS Timing Offset: %d%s", prefix, mr->ms_timing_offset, VTY_NEWLINE);
	if (mr->flags & MEAS_REP_F_MS_L1)
		vty_out(vty, "%s  L1 MS Power: %u dBm, Timing Advance: %u%s",
			prefix, mr->ms_l1.pwr, mr->ms_l1.ta, VTY_NEWLINE);
	if (mr->flags & MEAS_REP_F_DL_VALID)
		meas_rep_dump_uni_vty(vty, &mr->dl, prefix, "dl");
	meas_rep_dump_uni_vty(vty, &mr->ul, prefix, "ul");
}

void lchan_dump_full_vty(struct vty *vty, struct gsm_lchan *lchan)
{
	int idx;

	vty_out(vty, "BTS %u, TRX %u, Timeslot %u, Lchan %u: Type %s%s",
		lchan->ts->trx->bts->nr, lchan->ts->trx->nr, lchan->ts->nr,
		lchan->nr, gsm_lchant_name(lchan->type), VTY_NEWLINE);

	if (lchan->activate.concluded) {
		vty_out(vty, "  Activated %s seconds ago%s",
			osmo_int_to_float_str_c(OTC_SELECT, gsm_lchan_active_duration_ms(lchan), 3),
			VTY_NEWLINE);
	}

	vty_out_dyn_ts_details(vty, lchan->ts);
	vty_out(vty, "  Connection: %u, State: %s%s%s%s",
		lchan->conn ? 1: 0, lchan_state_name(lchan),
		lchan->fi && lchan->fi->state == LCHAN_ST_BORKEN ? " Error reason: " : "",
		lchan->fi && lchan->fi->state == LCHAN_ST_BORKEN ? lchan->last_error : "",
		VTY_NEWLINE);
	vty_out(vty, "  BS Power: %u dBm, MS Power: %u dBm%s",
		lchan->ts->trx->nominal_power - lchan->ts->trx->max_power_red
		- lchan->bs_power_db,
		ms_pwr_dbm(lchan->ts->trx->bts->band, lchan->ms_power),
		VTY_NEWLINE);

	vty_out(vty, "  Interference Level: ");
	if (lchan->interf_dbm == INTERF_DBM_UNKNOWN)
		vty_out(vty, "unknown");
	else
		vty_out(vty, "%d dBm (%u)", lchan->interf_dbm, lchan->interf_band);
	vty_out(vty, "%s", VTY_NEWLINE);

	vty_out(vty, "  Channel Mode / Codec: %s%s",
		gsm48_chan_mode_name(lchan->current_ch_mode_rate.chan_mode),
		VTY_NEWLINE);
	if (!lchan_state_is(lchan, LCHAN_ST_UNUSED))
		vty_out(vty, "  Training Sequence: Set %d Code %u%s", (lchan->tsc_set > 0 ? lchan->tsc_set : 1), lchan->tsc, VTY_NEWLINE);
	if (lchan->vamos.enabled)
		vty_out(vty, "  VAMOS: enabled%s", VTY_NEWLINE);
	if (lchan->conn && lchan->conn->bsub) {
		vty_out(vty, "  Subscriber:%s", VTY_NEWLINE);
		bsc_subscr_dump_vty(vty, lchan->conn->bsub);
	} else
		vty_out(vty, "  No Subscriber%s", VTY_NEWLINE);
	if (is_ipaccess_bts(lchan->ts->trx->bts)) {
		struct in_addr ia;
		if (lchan->abis_ip.bound_ip) {
			ia.s_addr = htonl(lchan->abis_ip.bound_ip);
			vty_out(vty, "  Bound IP: %s Port %u RTP_TYPE2=%u CONN_ID=%u%s",
				inet_ntoa(ia), lchan->abis_ip.bound_port,
				lchan->abis_ip.rtp_payload2, lchan->abis_ip.conn_id,
				VTY_NEWLINE);
		}
		if (lchan->abis_ip.connect_ip) {
			ia.s_addr = htonl(lchan->abis_ip.connect_ip);
			vty_out(vty, "  Conn. IP: %s Port %u RTP_TYPE=%u SPEECH_MODE=0x%02x%s",
				inet_ntoa(ia), lchan->abis_ip.connect_port,
				lchan->abis_ip.rtp_payload, lchan->abis_ip.speech_mode,
				VTY_NEWLINE);
		}

	}

	/* we want to report the last measurement report */
	idx = calc_initial_idx(ARRAY_SIZE(lchan->meas_rep),
			       lchan->meas_rep_idx, 1);
	meas_rep_dump_vty(vty, &lchan->meas_rep[idx], "  ");
}

void lchan_dump_short_vty(struct vty *vty, struct gsm_lchan *lchan)
{
	struct gsm_meas_rep *mr;
	int idx;

	/* we want to report the last measurement report */
	idx = calc_initial_idx(ARRAY_SIZE(lchan->meas_rep),
			       lchan->meas_rep_idx, 1);
	mr =  &lchan->meas_rep[idx];

	vty_out(vty, "BTS %u, TRX %u, Timeslot %u %s",
		lchan->ts->trx->bts->nr, lchan->ts->trx->nr, lchan->ts->nr,
		gsm_pchan_name(lchan->ts->pchan_on_init));
	vty_out_dyn_ts_status(vty, lchan->ts);
	vty_out(vty, ", Lchan %u", lchan->nr);

	if (lchan_state_is(lchan, LCHAN_ST_UNUSED)) {
		vty_out(vty, ", Type %s, State %s - Interference Level: ",
			gsm_pchan_name(lchan->ts->pchan_is),
			lchan_state_name(lchan));
		if (lchan->interf_dbm == INTERF_DBM_UNKNOWN)
			vty_out(vty, "unknown");
		else
			vty_out(vty, "%d dBm (%u)", lchan->interf_dbm, lchan->interf_band);
		vty_out(vty, "%s", VTY_NEWLINE);
		return;
	}

	vty_out(vty, ", Type %s%s TSC-s%dc%u, State %s - L1 MS Power: %u dBm RXL-FULL-dl: %4d dBm RXL-FULL-ul: %4d dBm%s",
		gsm_lchant_name(lchan->type),
		lchan->vamos.enabled ? " (VAMOS)" : "",
		lchan->tsc_set > 0 ? lchan->tsc_set : 1,
		lchan->tsc,
		lchan_state_name(lchan),
		mr->ms_l1.pwr,
		rxlev2dbm(mr->dl.full.rx_lev),
		rxlev2dbm(mr->ul.full.rx_lev),
		VTY_NEWLINE);
}

void ts_dump_vty(struct vty *vty, struct gsm_bts_trx_ts *ts)
{
	vty_out(vty, "BTS %u, TRX %u, Timeslot %u, phys cfg %s (active %s)",
		ts->trx->bts->nr, ts->trx->nr, ts->nr,
		gsm_pchan_name(ts->pchan_on_init),
		gsm_pchan_name(ts->pchan_is));
	if (ts->pchan_is != ts->pchan_on_init)
		vty_out(vty, " (%s mode)", gsm_pchan_name(ts->pchan_is));
	vty_out(vty, ", TSC %u%s  NM State: ", gsm_ts_tsc(ts), VTY_NEWLINE);
	vty_out_dyn_ts_details(vty, ts);
	net_dump_nmstate(vty, &ts->mo.nm_state);
	if (!is_ipaccess_bts(ts->trx->bts))
		vty_out(vty, "  E1 Line %u, Timeslot %u, Subslot %u%s",
			ts->e1_link.e1_nr, ts->e1_link.e1_ts,
			ts->e1_link.e1_ts_ss, VTY_NEWLINE);
}

void e1isl_dump_vty(struct vty *vty, struct e1inp_sign_link *e1l)
{
	struct e1inp_line *line;

	if (!e1l) {
		vty_out(vty, "   None%s", VTY_NEWLINE);
		return;
	}

	line = e1l->ts->line;

	vty_out(vty, "    E1 Line %u, Type %s: Timeslot %u, Mode %s%s",
		line->num, line->driver->name, e1l->ts->num,
		e1inp_signtype_name(e1l->type), VTY_NEWLINE);
	vty_out(vty, "    E1 TEI %u, SAPI %u%s",
		e1l->tei, e1l->sapi, VTY_NEWLINE);
}

/*! Dump the IP addresses and ports of the input signal link's timeslot.
 *  This only makes sense for links connected with ipaccess.
 *  Example output: "(r=10.1.42.1:55416<->l=10.1.42.123:3003)" */
void e1isl_dump_vty_tcp(struct vty *vty, const struct e1inp_sign_link *e1l)
{
	if (e1l) {
		char *name = osmo_sock_get_name(NULL, e1l->ts->driver.ipaccess.fd.fd);
		vty_out(vty, "%s", name);
		talloc_free(name);
	}
	vty_out(vty, "%s", VTY_NEWLINE);
}

void trx_dump_vty(struct vty *vty, struct gsm_bts_trx *trx, bool print_rsl, bool show_connected)
{
	if (show_connected && !trx->rsl_link_primary)
		return;

	if (!show_connected && trx->rsl_link_primary)
		return;

	vty_out(vty, "TRX %u of BTS %u is on ARFCN %u%s",
		trx->nr, trx->bts->nr, trx->arfcn, VTY_NEWLINE);
	vty_out(vty, "  RF Nominal Power: %d dBm, reduced by %u dB, "
		"resulting BS power: %d dBm%s",
		trx->nominal_power, trx->max_power_red,
		trx->nominal_power - trx->max_power_red, VTY_NEWLINE);
	vty_out(vty, "  Radio Carrier NM State: ");
	net_dump_nmstate(vty, &trx->mo.nm_state);
	if (print_rsl)
		vty_out(vty, "  RSL State: %s%s", trx->rsl_link_primary? "connected" : "disconnected", VTY_NEWLINE);
	vty_out(vty, "  Baseband Transceiver NM State: ");
	net_dump_nmstate(vty, &trx->bb_transc.mo.nm_state);
	if (is_ipaccess_bts(trx->bts)) {
		vty_out(vty, "  ip.access stream ID: 0x%02x ", trx->rsl_tei_primary);
		e1isl_dump_vty_tcp(vty, trx->rsl_link_primary);
	} else {
		vty_out(vty, "  E1 Signalling Link:%s", VTY_NEWLINE);
		e1isl_dump_vty(vty, trx->rsl_link_primary);
	}
}

void config_write_e1_link(struct vty *vty, struct gsm_e1_subslot *e1_link,
				 const char *prefix)
{
	if (!e1_link->e1_ts)
		return;

	if (e1_link->e1_ts_ss == 255)
		vty_out(vty, "%se1 line %u timeslot %u sub-slot full%s",
			prefix, e1_link->e1_nr, e1_link->e1_ts, VTY_NEWLINE);
	else
		vty_out(vty, "%se1 line %u timeslot %u sub-slot %u%s",
			prefix, e1_link->e1_nr, e1_link->e1_ts,
			e1_link->e1_ts_ss, VTY_NEWLINE);
}


static void config_write_ts_single(struct vty *vty, struct gsm_bts_trx_ts *ts)
{
	vty_out(vty, "   timeslot %u%s", ts->nr, VTY_NEWLINE);
	if (ts->tsc != -1)
		vty_out(vty, "    training_sequence_code %u%s", ts->tsc, VTY_NEWLINE);
	if (ts->pchan_from_config != GSM_PCHAN_NONE)
		vty_out(vty, "    phys_chan_config %s%s",
			gsm_pchan_name(ts->pchan_from_config), VTY_NEWLINE);
	vty_out(vty, "    hopping enabled %u%s",
		ts->hopping.enabled, VTY_NEWLINE);
	if (ts->hopping.enabled) {
		unsigned int i;
		vty_out(vty, "    hopping sequence-number %u%s",
			ts->hopping.hsn, VTY_NEWLINE);
		vty_out(vty, "    hopping maio %u%s",
			ts->hopping.maio, VTY_NEWLINE);
		for (i = 0; i < ts->hopping.arfcns.data_len*8; i++) {
			if (!bitvec_get_bit_pos(&ts->hopping.arfcns, i))
				continue;
			vty_out(vty, "    hopping arfcn add %u%s",
				i, VTY_NEWLINE);
		}
	}
	config_write_e1_link(vty, &ts->e1_link, "    ");

	if (ts->trx->bts->model->config_write_ts)
		ts->trx->bts->model->config_write_ts(vty, ts);
}

void config_write_trx_single(struct vty *vty, struct gsm_bts_trx *trx)
{
	int i;

	vty_out(vty, "  trx %u%s", trx->nr, VTY_NEWLINE);
	vty_out(vty, "   rf_locked %u%s",
		trx->mo.force_rf_lock ? 1 : 0,
		VTY_NEWLINE);
	vty_out(vty, "   arfcn %u%s", trx->arfcn, VTY_NEWLINE);
	vty_out(vty, "   nominal power %u%s", trx->nominal_power, VTY_NEWLINE);
	vty_out(vty, "   max_power_red %u%s", trx->max_power_red, VTY_NEWLINE);
	config_write_e1_link(vty, &trx->rsl_e1_link, "   rsl ");
	vty_out(vty, "   rsl e1 tei %u%s", trx->rsl_tei_primary, VTY_NEWLINE);

	if (trx->bts->model->config_write_trx)
		trx->bts->model->config_write_trx(vty, trx);

	for (i = 0; i < TRX_NR_TS; i++)
		config_write_ts_single(vty, &trx->ts[i]);
}

int bts_trx_vty_init(void)
{
	cfg_ts_pchan_cmd.string =
		vty_cmd_string_from_valstr(tall_bsc_ctx,
					   gsm_pchant_names,
					   "phys_chan_config (", "|", ")",
					   VTY_DO_LOWER);
	cfg_ts_pchan_cmd.doc =
		vty_cmd_string_from_valstr(tall_bsc_ctx,
					   gsm_pchant_descs,
					   "Physical Channel Combination\n",
					   "\n", "", 0);

	install_element(BTS_NODE, &cfg_trx_cmd);
	install_node(&trx_node, dummy_config_write);
	install_element(TRX_NODE, &cfg_trx_arfcn_cmd);
	install_element(TRX_NODE, &cfg_description_cmd);
	install_element(TRX_NODE, &cfg_no_description_cmd);
	install_element(TRX_NODE, &cfg_trx_nominal_power_cmd);
	install_element(TRX_NODE, &cfg_trx_max_power_red_cmd);
	install_element(TRX_NODE, &cfg_trx_rsl_e1_cmd);
	install_element(TRX_NODE, &cfg_trx_rsl_e1_tei_cmd);
	install_element(TRX_NODE, &cfg_trx_rf_locked_cmd);

	install_element(TRX_NODE, &cfg_ts_cmd);
	install_node(&ts_node, dummy_config_write);
	install_element(TS_NODE, &cfg_ts_pchan_cmd);
	install_element(TS_NODE, &cfg_ts_pchan_compat_cmd);
	install_element(TS_NODE, &cfg_ts_tsc_cmd);
	install_element(TS_NODE, &cfg_ts_hopping_cmd);
	install_element(TS_NODE, &cfg_ts_hsn_cmd);
	install_element(TS_NODE, &cfg_ts_maio_cmd);
	install_element(TS_NODE, &cfg_ts_arfcn_add_cmd);
	install_element(TS_NODE, &cfg_ts_arfcn_del_cmd);
	install_element(TS_NODE, &cfg_ts_arfcn_del_all_cmd);
	install_element(TS_NODE, &cfg_ts_e1_subslot_cmd);

	return 0;
}
