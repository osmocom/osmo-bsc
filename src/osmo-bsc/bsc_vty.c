/* OsmoBSC interface to quagga VTY */
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
#include <osmocom/vty/command.h>
#include <osmocom/vty/buffer.h>
#include <osmocom/vty/vty.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/stats.h>
#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/misc.h>
#include <osmocom/vty/tdef_vty.h>
#include <osmocom/ctrl/control_if.h>
#include <osmocom/gsm/gsm23236.h>
#include <osmocom/gsm/gsm0502.h>

#include <osmocom/mgcp_client/mgcp_client_endpoint_fsm.h>
#include <osmocom/mgcp_client/mgcp_client_pool.h>

#include <osmocom/bsc/vty.h>
#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/abis_nm.h>
#include <osmocom/bsc/abis_om2000.h>
#include <osmocom/bsc/chan_alloc.h>
#include <osmocom/bsc/system_information.h>
#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/paging.h>
#include <osmocom/bsc/ipaccess.h>
#include <osmocom/bsc/abis_rsl.h>
#include <osmocom/bsc/osmo_bsc_rf.h>
#include <osmocom/bsc/handover_fsm.h>
#include <osmocom/bsc/handover_cfg.h>
#include <osmocom/bsc/handover_vty.h>
#include <osmocom/bsc/gsm_04_08_rr.h>
#include <osmocom/bsc/meas_feed.h>
#include <osmocom/bsc/timeslot_fsm.h>
#include <osmocom/bsc/lchan_fsm.h>
#include <osmocom/bsc/lchan_select.h>
#include <osmocom/bsc/smscb.h>
#include <osmocom/bsc/osmo_bsc.h>
#include <osmocom/bsc/bts.h>
#include <osmocom/bsc/bsc_subscr_conn_fsm.h>
#include <osmocom/bsc/assignment_fsm.h>
#include <osmocom/bsc/bssmap_reset.h>

#include <inttypes.h>

#include "../../bscconfig.h"

#define X(x) (1 << x)

const struct value_string bts_loc_fix_names[] = {
	{ BTS_LOC_FIX_INVALID,	"invalid" },
	{ BTS_LOC_FIX_2D,	"fix2d" },
	{ BTS_LOC_FIX_3D,	"fix3d" },
	{ 0, NULL }
};

static struct cmd_node net_node = {
	GSMNET_NODE,
	"%s(config-net)# ",
	1,
};

static struct gsm_network *vty_global_gsm_network = NULL;

struct gsm_network *gsmnet_from_vty(struct vty *v)
{
	/* It can't hurt to force callers to continue to pass the vty instance
	 * to this function, in case we'd like to retrieve the global
	 * gsm_network instance from the vty at some point in the future. But
	 * until then, just return the global pointer, which should have been
	 * initialized by common_cs_vty_init().
	 */
	OSMO_ASSERT(vty_global_gsm_network);
	return vty_global_gsm_network;
}

int dummy_config_write(struct vty *v)
{
	return CMD_SUCCESS;
}

/* resolve a gsm_bts_trx_ts basd on the given numeric identifiers */
static struct gsm_bts_trx_ts *vty_get_ts(struct vty *vty, const char *bts_str, const char *trx_str,
					 const char *ts_str)
{
	int bts_nr = atoi(bts_str);
	int trx_nr = atoi(trx_str);
	int ts_nr = atoi(ts_str);
	struct gsm_bts *bts;
	struct gsm_bts_trx *trx;
	struct gsm_bts_trx_ts *ts;

	bts = gsm_bts_num(gsmnet_from_vty(vty), bts_nr);
	if (!bts) {
		vty_out(vty, "%% No such BTS (%d)%s", bts_nr, VTY_NEWLINE);
		return NULL;
	}

	trx = gsm_bts_trx_num(bts, trx_nr);
	if (!trx) {
		vty_out(vty, "%% No such TRX (%d)%s", trx_nr, VTY_NEWLINE);
		return NULL;
	}

	ts = &trx->ts[ts_nr];

	return ts;
}

void net_dump_nmstate(struct vty *vty, struct gsm_nm_state *nms)
{
	vty_out(vty,"Oper '%s', Admin '%s', Avail '%s'%s",
		abis_nm_opstate_name(nms->operational),
		get_value_string(abis_nm_adm_state_names, nms->administrative),
		abis_nm_avail_name(nms->availability), VTY_NEWLINE);
}

void dump_pchan_load_vty(struct vty *vty, char *prefix,
				const struct pchan_load *pl)
{
	int i;
	int dumped = 0;

	for (i = 0; i < ARRAY_SIZE(pl->pchan); i++) {
		const struct load_counter *lc = &pl->pchan[i];
		unsigned int percent;

		if (lc->total == 0)
			continue;

		percent = (lc->used * 100) / lc->total;

		vty_out(vty, "%s%20s: %3u%% (%u/%u)%s", prefix,
			gsm_pchan_name(i), percent, lc->used, lc->total,
			VTY_NEWLINE);
		dumped ++;
	}
	if (!dumped)
		vty_out(vty, "%s(none)%s", prefix, VTY_NEWLINE);
}

static void net_dump_vty(struct vty *vty, struct gsm_network *net)
{
	struct pchan_load pl;
	int i;

	vty_out(vty, "BSC is on MCC-MNC %s and has %u BTS%s",
		osmo_plmn_name(&net->plmn), net->num_bts, VTY_NEWLINE);
	vty_out(vty, "%s", VTY_NEWLINE);
	vty_out(vty, "  Encryption:");
	for (i = 0; i < 8; i++) {
		if (net->a5_encryption_mask & (1 << i))
			vty_out(vty, " A5/%u", i);
	}
	vty_out(vty, "%s", VTY_NEWLINE);
	vty_out(vty, "  NECI (TCH/H): %u%s", net->neci,
		VTY_NEWLINE);
	vty_out(vty, "  Use TCH for Paging any: %d%s", net->pag_any_tch,
		VTY_NEWLINE);

	{
		struct gsm_bts *bts;
		unsigned int ho_active_count = 0;
		unsigned int ho_inactive_count = 0;

		llist_for_each_entry(bts, &net->bts_list, list) {
			if (ho_get_ho_active(bts->ho))
				ho_active_count ++;
			else
				ho_inactive_count ++;
		}

		if (ho_active_count && ho_inactive_count)
			vty_out(vty, "  Handover: On at %u BTS, Off at %u BTS%s",
				ho_active_count, ho_inactive_count, VTY_NEWLINE);
		else
			vty_out(vty, "  Handover: %s%s", ho_active_count ? "On" : "Off",
				VTY_NEWLINE);
	}

	network_chan_load(&pl, net);
	vty_out(vty, "  Current Channel Load:%s", VTY_NEWLINE);
	dump_pchan_load_vty(vty, "    ", &pl);

	/* show rf */
	if (net->rf_ctrl)
		vty_out(vty, "  Last RF Command: %s%s",
			net->rf_ctrl->last_state_command,
			VTY_NEWLINE);
	if (net->rf_ctrl)
		vty_out(vty, "  Last RF Lock Command: %s%s",
			net->rf_ctrl->last_rf_lock_ctrl_command,
			VTY_NEWLINE);
}

DEFUN(bsc_show_net, bsc_show_net_cmd, "show network",
	SHOW_STR "Display information about a GSM NETWORK\n")
{
	struct gsm_network *net = gsmnet_from_vty(vty);
	net_dump_vty(vty, net);

	return CMD_SUCCESS;
}
DEFUN(show_bts, show_bts_cmd, "show bts [<0-255>]",
	SHOW_STR "Display information about a BTS\n"
		"BTS number\n")
{
	struct gsm_network *net = gsmnet_from_vty(vty);
	int bts_nr;

	if (argc != 0) {
		/* use the BTS number that the user has specified */
		bts_nr = atoi(argv[0]);
		if (bts_nr >= net->num_bts) {
			vty_out(vty, "%% can't find BTS '%s'%s", argv[0],
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		bts_dump_vty(vty, gsm_bts_num(net, bts_nr));
		return CMD_SUCCESS;
	}
	/* print all BTS's */
	for (bts_nr = 0; bts_nr < net->num_bts; bts_nr++)
		bts_dump_vty(vty, gsm_bts_num(net, bts_nr));

	return CMD_SUCCESS;
}

DEFUN(show_bts_fail_rep, show_bts_fail_rep_cmd, "show bts <0-255> fail-rep [reset]",
	SHOW_STR "Display information about a BTS\n"
		"BTS number\n" "OML failure reports\n"
		"Clear the list of failure reports after showing them\n")
{
	struct gsm_network *net = gsmnet_from_vty(vty);
	struct bts_oml_fail_rep *entry;
	struct gsm_bts *bts;
	int bts_nr;

	bts_nr = atoi(argv[0]);
	if (bts_nr >= net->num_bts) {
		vty_out(vty, "%% can't find BTS '%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts = gsm_bts_num(net, bts_nr);
	if (llist_empty(&bts->oml_fail_rep)) {
		vty_out(vty, "No failure reports received.%s", VTY_NEWLINE);
		return CMD_SUCCESS;
	}

	llist_for_each_entry(entry, &bts->oml_fail_rep, list) {
		struct nm_fail_rep_signal_data *sd;
		char timestamp[20]; /* format like 2020-03-23 14:24:00 */
		enum abis_nm_pcause_type pcause;
		enum abis_mm_event_causes cause;

		strftime(timestamp, sizeof(timestamp), "%F %T", localtime(&entry->time));
		sd = abis_nm_fail_evt_rep_parse(entry->mb, bts);
		if (!sd) {
			vty_out(vty, "[%s] (failed to parse report)%s", timestamp, VTY_NEWLINE);
			continue;
		}
		pcause = sd->parsed.probable_cause[0];
		cause = osmo_load16be(sd->parsed.probable_cause + 1);

		vty_out(vty, "[%s] Type=%s, Severity=%s, ", timestamp, sd->parsed.event_type, sd->parsed.severity);
		vty_out(vty, "Probable cause=%s: ", get_value_string(abis_nm_pcause_type_names, pcause));
		if (pcause == NM_PCAUSE_T_MANUF)
			vty_out(vty, "%s, ", get_value_string(abis_mm_event_cause_names, cause));
		else
			vty_out(vty, "%04X, ", cause);
		vty_out(vty, "Additional text=%s%s", sd->parsed.additional_text, VTY_NEWLINE);

		talloc_free(sd);
	}

	/* Optionally clear the list */
	if (argc > 1) {
		while (!llist_empty(&bts->oml_fail_rep)) {
			struct bts_oml_fail_rep *old = llist_last_entry(&bts->oml_fail_rep, struct bts_oml_fail_rep,
									list);
			llist_del(&old->list);
			talloc_free(old);
		}
	}

	return CMD_SUCCESS;
}

DEFUN(show_rejected_bts, show_rejected_bts_cmd, "show rejected-bts",
	SHOW_STR "Display recently rejected BTS devices\n")
{
	struct gsm_bts_rejected *pos;

	/* empty list */
	struct llist_head *rejected = &gsmnet_from_vty(vty)->bts_rejected;
	if (llist_empty(rejected)) {
		vty_out(vty, "No BTS has been rejected.%s", VTY_NEWLINE);
		return CMD_SUCCESS;
	}

	/* table head */
	vty_out(vty, "Date                Site ID BTS ID IP%s", VTY_NEWLINE);
	vty_out(vty, "------------------- ------- ------ ---------------%s", VTY_NEWLINE);

	/* table body */
	llist_for_each_entry(pos, rejected, list) {
		/* timestamp formatted like: "2018-10-24 15:04:52" */
		char buf[20];
		strftime(buf, sizeof(buf), "%F %T", localtime(&pos->time));

		vty_out(vty, "%s %7u %6u %15s%s", buf, pos->site_id, pos->bts_id, pos->ip, VTY_NEWLINE);
	}
	return CMD_SUCCESS;
}

static int config_write_net(struct vty *vty)
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	int i;
	struct osmo_nri_range *r;

	vty_out(vty, "network%s", VTY_NEWLINE);
	vty_out(vty, " network country code %s%s", osmo_mcc_name(gsmnet->plmn.mcc), VTY_NEWLINE);
	vty_out(vty, " mobile network code %s%s",
		osmo_mnc_name(gsmnet->plmn.mnc, gsmnet->plmn.mnc_3_digits), VTY_NEWLINE);
	vty_out(vty, " encryption a5");
	for (i = 0; i < 8; i++) {
		if (gsmnet->a5_encryption_mask & (1 << i))
			vty_out(vty, " %u", i);
	}
	vty_out(vty, "%s", VTY_NEWLINE);
	vty_out(vty, " neci %u%s", gsmnet->neci, VTY_NEWLINE);
	vty_out(vty, " paging any use tch %d%s", gsmnet->pag_any_tch, VTY_NEWLINE);

	ho_vty_write_net(vty, gsmnet);

	if (!gsmnet->dyn_ts_allow_tch_f)
		vty_out(vty, " dyn_ts_allow_tch_f 0%s", VTY_NEWLINE);
	if (gsmnet->tz.override != 0) {
		if (gsmnet->tz.dst)
			vty_out(vty, " timezone %d %d %d%s",
				gsmnet->tz.hr, gsmnet->tz.mn, gsmnet->tz.dst,
				VTY_NEWLINE);
		else
			vty_out(vty, " timezone %d %d%s",
				gsmnet->tz.hr, gsmnet->tz.mn, VTY_NEWLINE);
	}

	/* Timer introspection commands (generic osmo_tdef API) */
	osmo_tdef_vty_groups_write(vty, " ");

	{
		uint16_t meas_port;
		char *meas_host;
		const char *meas_scenario;

		meas_feed_cfg_get(&meas_host, &meas_port);
		meas_scenario = meas_feed_scenario_get();

		if (meas_port)
			vty_out(vty, " meas-feed destination %s %u%s",
				meas_host, meas_port, VTY_NEWLINE);
		if (strlen(meas_scenario) > 0)
			vty_out(vty, " meas-feed scenario %s%s",
				meas_scenario, VTY_NEWLINE);
	}

	if (gsmnet->allow_unusable_timeslots)
		vty_out(vty, " allow-unusable-timeslots%s", VTY_NEWLINE);

	if (gsmnet->nri_bitlen != OSMO_NRI_BITLEN_DEFAULT)
		vty_out(vty, " nri bitlen %u%s", gsmnet->nri_bitlen, VTY_NEWLINE);

	llist_for_each_entry(r, &gsmnet->null_nri_ranges->entries, entry) {
		vty_out(vty, " nri null add %d", r->first);
		if (r->first != r->last)
			vty_out(vty, " %d", r->last);
		vty_out(vty, "%s", VTY_NEWLINE);
	}

	neighbor_ident_vty_write_network(vty, " ");

	return CMD_SUCCESS;
}

static void trx_dump_vty_all(struct vty *vty, struct gsm_bts_trx *trx)
{
	trx_dump_vty(vty, trx, true, true);
	trx_dump_vty(vty, trx, true, false);
}

static inline void print_all_trx(struct vty *vty, const struct gsm_bts *bts)
{
	uint8_t trx_nr;
	for (trx_nr = 0; trx_nr < bts->num_trx; trx_nr++)
		trx_dump_vty_all(vty, gsm_bts_trx_num(bts, trx_nr));
}

DEFUN(show_trx,
      show_trx_cmd,
      "show trx [<0-255>] [<0-255>]",
	SHOW_STR "Display information about a TRX\n"
	BTS_TRX_STR)
{
	struct gsm_network *net = gsmnet_from_vty(vty);
	struct gsm_bts *bts = NULL;
	int bts_nr, trx_nr;

	if (argc >= 1) {
		/* use the BTS number that the user has specified */
		bts_nr = atoi(argv[0]);
		if (bts_nr >= net->num_bts) {
			vty_out(vty, "%% can't find BTS '%s'%s", argv[0],
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		bts = gsm_bts_num(net, bts_nr);
	}
	if (argc >= 2) {
		trx_nr = atoi(argv[1]);
		if (trx_nr >= bts->num_trx) {
			vty_out(vty, "%% can't find TRX '%s'%s", argv[1],
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		trx_dump_vty_all(vty, gsm_bts_trx_num(bts, trx_nr));

		return CMD_SUCCESS;
	}
	if (bts) {
		/* print all TRX in this BTS */
		print_all_trx(vty, bts);
		return CMD_SUCCESS;
	}

	for (bts_nr = 0; bts_nr < net->num_bts; bts_nr++)
		print_all_trx(vty, gsm_bts_num(net, bts_nr));

	return CMD_SUCCESS;
}

DEFUN(show_ts,
      show_ts_cmd,
      "show timeslot [<0-255>] [<0-255>] [<0-7>]",
	SHOW_STR "Display information about a TS\n"
	BTS_TRX_TS_STR)
{
	struct gsm_network *net = gsmnet_from_vty(vty);
	struct gsm_bts *bts = NULL;
	struct gsm_bts_trx *trx = NULL;
	struct gsm_bts_trx_ts *ts = NULL;
	int bts_nr, trx_nr, ts_nr;

	if (argc >= 1) {
		/* use the BTS number that the user has specified */
		bts_nr = atoi(argv[0]);
		if (bts_nr >= net->num_bts) {
			vty_out(vty, "%% can't find BTS '%s'%s", argv[0],
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		bts = gsm_bts_num(net, bts_nr);
	}
	if (argc >= 2) {
		trx_nr = atoi(argv[1]);
		if (trx_nr >= bts->num_trx) {
			vty_out(vty, "%% can't find TRX '%s'%s", argv[1],
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		trx = gsm_bts_trx_num(bts, trx_nr);
	}
	if (argc >= 3) {
		ts_nr = atoi(argv[2]);
		if (ts_nr >= TRX_NR_TS) {
			vty_out(vty, "%% can't find TS '%s'%s", argv[2],
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		/* Fully Specified: print and exit */
		ts = &trx->ts[ts_nr];
		ts_dump_vty(vty, ts);
		return CMD_SUCCESS;
	}

	if (bts && trx) {
		/* Iterate over all TS in this TRX */
		for (ts_nr = 0; ts_nr < TRX_NR_TS; ts_nr++) {
			ts = &trx->ts[ts_nr];
			ts_dump_vty(vty, ts);
		}
	} else if (bts) {
		/* Iterate over all TRX in this BTS, TS in each TRX */
		for (trx_nr = 0; trx_nr < bts->num_trx; trx_nr++) {
			trx = gsm_bts_trx_num(bts, trx_nr);
			for (ts_nr = 0; ts_nr < TRX_NR_TS; ts_nr++) {
				ts = &trx->ts[ts_nr];
				ts_dump_vty(vty, ts);
			}
		}
	} else {
		/* Iterate over all BTS, TRX in each BTS, TS in each TRX */
		for (bts_nr = 0; bts_nr < net->num_bts; bts_nr++) {
			bts = gsm_bts_num(net, bts_nr);
			for (trx_nr = 0; trx_nr < bts->num_trx; trx_nr++) {
				trx = gsm_bts_trx_num(bts, trx_nr);
				for (ts_nr = 0; ts_nr < TRX_NR_TS; ts_nr++) {
					ts = &trx->ts[ts_nr];
					ts_dump_vty(vty, ts);
				}
			}
		}
	}

	return CMD_SUCCESS;
}

void bsc_subscr_dump_vty(struct vty *vty, struct bsc_subscr *bsub)
{
	if (strlen(bsub->imsi))
		vty_out(vty, "    IMSI: %s%s", bsub->imsi, VTY_NEWLINE);
	if (bsub->tmsi != GSM_RESERVED_TMSI)
		vty_out(vty, "    TMSI: 0x%08x%s", bsub->tmsi,
			VTY_NEWLINE);
	vty_out(vty, "    Use count: %s%s", osmo_use_count_to_str_c(OTC_SELECT, &bsub->use_count), VTY_NEWLINE);
}

static inline void print_all_trx_ext(struct vty *vty, bool show_connected)
{
	struct gsm_network *net = gsmnet_from_vty(vty);
	struct gsm_bts *bts = NULL;
	uint8_t bts_nr;
	for (bts_nr = 0; bts_nr < net->num_bts; bts_nr++) {
		uint8_t trx_nr;
		bts = gsm_bts_num(net, bts_nr);
		for (trx_nr = 0; trx_nr < bts->num_trx; trx_nr++)
			trx_dump_vty(vty, gsm_bts_trx_num(bts, trx_nr), false, show_connected);
	}
}

DEFUN(show_trx_con,
      show_trx_con_cmd,
      "show trx (connected|disconnected)",
      SHOW_STR "Display information about a TRX\n"
      "Show TRX with RSL connected\n"
      "Show TRX with RSL disconnected\n")
{
	if (!strcmp(argv[0], "connected"))
		print_all_trx_ext(vty, true);
	else
		print_all_trx_ext(vty, false);

	return CMD_SUCCESS;
}


static int dump_lchan_trx_ts(struct gsm_bts_trx_ts *ts, struct vty *vty,
			     void (*dump_cb)(struct vty *, struct gsm_lchan *),
			     bool all)
{
	struct gsm_lchan *lchan;
	ts_for_n_lchans(lchan, ts, ts->max_lchans_possible) {
		if (lchan_state_is(lchan, LCHAN_ST_UNUSED) && all == false)
			continue;
		dump_cb(vty, lchan);
	}

	return CMD_SUCCESS;
}

static int dump_lchan_trx(struct gsm_bts_trx *trx, struct vty *vty,
			  void (*dump_cb)(struct vty *, struct gsm_lchan *),
			  bool all)
{
	int ts_nr;

	for (ts_nr = 0; ts_nr < TRX_NR_TS; ts_nr++) {
		struct gsm_bts_trx_ts *ts = &trx->ts[ts_nr];
		dump_lchan_trx_ts(ts, vty, dump_cb, all);
	}

	return CMD_SUCCESS;
}

static int dump_lchan_bts(struct gsm_bts *bts, struct vty *vty,
			  void (*dump_cb)(struct vty *, struct gsm_lchan *),
			  bool all)
{
	int trx_nr;

	for (trx_nr = 0; trx_nr < bts->num_trx; trx_nr++) {
		struct gsm_bts_trx *trx = gsm_bts_trx_num(bts, trx_nr);
		dump_lchan_trx(trx, vty, dump_cb, all);
	}

	return CMD_SUCCESS;
}

static int lchan_summary(struct vty *vty, int argc, const char **argv,
			 void (*dump_cb)(struct vty *, struct gsm_lchan *),
			 bool all)
{
	struct gsm_network *net = gsmnet_from_vty(vty);
	struct gsm_bts *bts = NULL;
	struct gsm_bts_trx *trx = NULL;
	struct gsm_bts_trx_ts *ts = NULL;
	struct gsm_lchan *lchan;
	int bts_nr, trx_nr, ts_nr, lchan_nr;

	if (argc >= 1) {
		/* use the BTS number that the user has specified */
		bts_nr = atoi(argv[0]);
		if (bts_nr >= net->num_bts) {
			vty_out(vty, "%% can't find BTS %s%s", argv[0],
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		bts = gsm_bts_num(net, bts_nr);

		if (argc == 1)
			return dump_lchan_bts(bts, vty, dump_cb, all);
	}
	if (argc >= 2) {
		trx_nr = atoi(argv[1]);
		if (trx_nr >= bts->num_trx) {
			vty_out(vty, "%% can't find TRX %s%s", argv[1],
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		trx = gsm_bts_trx_num(bts, trx_nr);

		if (argc == 2)
			return dump_lchan_trx(trx, vty, dump_cb, all);
	}
	if (argc >= 3) {
		ts_nr = atoi(argv[2]);
		if (ts_nr >= TRX_NR_TS) {
			vty_out(vty, "%% can't find TS %s%s", argv[2],
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		ts = &trx->ts[ts_nr];

		if (argc == 3)
			return dump_lchan_trx_ts(ts, vty, dump_cb, all);
	}
	if (argc >= 4) {
		lchan_nr = atoi(argv[3]);
		if (lchan_nr >= TS_MAX_LCHAN) {
			vty_out(vty, "%% can't find LCHAN %s%s", argv[3],
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		lchan = &ts->lchan[lchan_nr];
		dump_cb(vty, lchan);
		return CMD_SUCCESS;
	}


	for (bts_nr = 0; bts_nr < net->num_bts; bts_nr++) {
		bts = gsm_bts_num(net, bts_nr);
		dump_lchan_bts(bts, vty, dump_cb, all);
	}

	return CMD_SUCCESS;
}


DEFUN(show_lchan,
      show_lchan_cmd,
      "show lchan [<0-255>] [<0-255>] [<0-7>] [<0-7>]",
	SHOW_STR "Display information about a logical channel\n"
	BTS_TRX_TS_LCHAN_STR)
{
	return lchan_summary(vty, argc, argv, lchan_dump_full_vty, true);
}

DEFUN(show_lchan_summary,
      show_lchan_summary_cmd,
      "show lchan summary [<0-255>] [<0-255>] [<0-7>] [<0-7>]",
	SHOW_STR "Display information about a logical channel\n"
        "Short summary (used lchans)\n"
	BTS_TRX_TS_LCHAN_STR)
{
	return lchan_summary(vty, argc, argv, lchan_dump_short_vty, false);
}

DEFUN(show_lchan_summary_all,
      show_lchan_summary_all_cmd,
      "show lchan summary-all [<0-255>] [<0-255>] [<0-7>] [<0-7>]",
	SHOW_STR "Display information about a logical channel\n"
        "Short summary (all lchans)\n"
	BTS_TRX_TS_LCHAN_STR)
{
	return lchan_summary(vty, argc, argv, lchan_dump_short_vty, true);
}

static void dump_one_subscr_conn(struct vty *vty, const struct gsm_subscriber_connection *conn)
{
	vty_out(vty, "conn ID=%u, MSC=%u, hodec2_fail=%d, mgw_ep=%s%s",
		conn->sccp.conn_id, conn->sccp.msc->nr, conn->hodec2.failures,
		osmo_mgcpc_ep_name(conn->user_plane.mgw_endpoint), VTY_NEWLINE);
	if (conn->lcls.global_call_ref_len) {
		vty_out(vty, " LCLS GCR: %s%s",
			osmo_hexdump_nospc(conn->lcls.global_call_ref, conn->lcls.global_call_ref_len),
			VTY_NEWLINE);
		vty_out(vty, " LCLS Config: %s, LCLS Control: %s, LCLS BSS Status: %s%s",
			gsm0808_lcls_config_name(conn->lcls.config),
			gsm0808_lcls_control_name(conn->lcls.control),
			osmo_fsm_inst_state_name(conn->lcls.fi),
			VTY_NEWLINE);
	}
	if (conn->lchan)
		lchan_dump_full_vty(vty, conn->lchan);
	if (conn->assignment.new_lchan)
		lchan_dump_full_vty(vty, conn->assignment.new_lchan);
}

DEFUN(show_subscr_conn,
      show_subscr_conn_cmd,
      "show conns",
      SHOW_STR "Display currently active subscriber connections\n")
{
	struct gsm_subscriber_connection *conn;
	struct gsm_network *net = gsmnet_from_vty(vty);
	bool no_conns = true;
	unsigned int count = 0;

	vty_out(vty, "Active subscriber connections: %s", VTY_NEWLINE);

	llist_for_each_entry(conn, &net->subscr_conns, entry) {
		dump_one_subscr_conn(vty, conn);
		no_conns = false;
		count++;
	}

	if (no_conns)
		vty_out(vty, "None%s", VTY_NEWLINE);

	return CMD_SUCCESS;
}

static int trigger_as(struct vty *vty, struct gsm_lchan *from_lchan, struct gsm_lchan *to_lchan)
{
	LOG_LCHAN(from_lchan, LOGL_NOTICE, "Manually triggering Assignment from VTY\n");
	if (!to_lchan) {
		to_lchan = lchan_select_by_type(from_lchan->ts->trx->bts, from_lchan->type);
		vty_out(vty, "Error: cannot find free lchan of type %s%s",
			gsm_lchant_name(from_lchan->type), VTY_NEWLINE);
	}
	if (reassignment_request_to_lchan(ACTIVATE_FOR_VTY, from_lchan, to_lchan, -1, -1)) {
		vty_out(vty, "Error: not allowed to start assignment for %s%s",
			gsm_lchan_name(from_lchan), VTY_NEWLINE);
		return CMD_WARNING;
	}
	return CMD_SUCCESS;
}

static int trigger_ho(struct vty *vty, struct gsm_lchan *from_lchan, struct gsm_bts *to_bts)
{
	struct handover_out_req req = {
		.from_hodec_id = HODEC_USER,
		.old_lchan = from_lchan,
	};
	bts_cell_ab(&req.target_cell_ab, to_bts);
	LOGP(DHO, LOGL_NOTICE, "%s (ARFCN %u) --> BTS %u Manually triggering Handover from VTY\n",
	     gsm_lchan_name(from_lchan), from_lchan->ts->trx->arfcn, to_bts->nr);
	handover_request(&req);
	return CMD_SUCCESS;
}

static int ho_or_as(struct vty *vty, const char *argv[], int argc)
{
	struct gsm_network *net = gsmnet_from_vty(vty);
	struct gsm_subscriber_connection *conn;
	struct gsm_bts *bts;
	struct gsm_bts *new_bts = NULL;
	unsigned int bts_nr = atoi(argv[0]);
	unsigned int trx_nr = atoi(argv[1]);
	unsigned int ts_nr = atoi(argv[2]);
	unsigned int ss_nr = atoi(argv[3]);
	const char *action;

	if (argc > 4) {
		unsigned int bts_nr_new = atoi(argv[4]);

		/* Lookup the BTS where we want to handover to */
		llist_for_each_entry(bts, &net->bts_list, list) {
			if (bts->nr == bts_nr_new) {
				new_bts = bts;
				break;
			}
		}

		if (!new_bts) {
			vty_out(vty, "%% Unable to trigger handover, specified bts #%u does not exist %s",
				bts_nr_new, VTY_NEWLINE);
			return CMD_WARNING;
		}
	}

	action = new_bts ? "handover" : "assignment";

	/* Find the connection/lchan that we want to handover */
	llist_for_each_entry(conn, &net->subscr_conns, entry) {
		struct gsm_bts *bts = conn_get_bts(conn);
		if (!bts)
			continue;
		if (bts->nr == bts_nr &&
		    conn->lchan->ts->trx->nr == trx_nr &&
		    conn->lchan->ts->nr == ts_nr && conn->lchan->nr == ss_nr) {
			vty_out(vty, "starting %s for lchan %s...%s", action, conn->lchan->name, VTY_NEWLINE);
			lchan_dump_full_vty(vty, conn->lchan);
			if (new_bts)
				return trigger_ho(vty, conn->lchan, new_bts);
			else
				return trigger_as(vty, conn->lchan, NULL);
		}
	}

	vty_out(vty, "%% Unable to trigger %s, specified connection (bts=%u,trx=%u,ts=%u,ss=%u) does not exist%s",
		action, bts_nr, trx_nr, ts_nr, ss_nr, VTY_NEWLINE);

	return CMD_WARNING;
}

/* tsc_set and tsc: -1 to automatically determine which TSC Set / which TSC to use. */
static int trigger_vamos_mode_modify(struct vty *vty, struct gsm_lchan *lchan, bool vamos, int tsc_set, int tsc)
{
	struct lchan_modify_info info = {
		.modify_for = MODIFY_FOR_VTY,
		.ch_mode_rate = lchan->current_ch_mode_rate,
		.requires_voice_stream = (lchan->fi_rtp != NULL),
		.vamos = vamos,
		.tsc_set = {
			.present = (tsc_set >= 0),
			.val = tsc_set,
		},
		.tsc = {
			.present = (tsc >= 0),
			.val = tsc,
		},
	};

	lchan_mode_modify(lchan, &info);
	return CMD_SUCCESS;
}

#define MANUAL_HANDOVER_STR "Manually trigger handover (for debugging)\n"
#define MANUAL_ASSIGNMENT_STR "Manually trigger assignment (for debugging)\n"

DEFUN(handover_subscr_conn,
      handover_subscr_conn_cmd,
      "bts <0-255> trx <0-255> timeslot <0-7> sub-slot <0-7> handover <0-255>",
      BTS_NR_TRX_TS_SS_STR2
      MANUAL_HANDOVER_STR
      "New " BTS_NR_STR)
{
	return ho_or_as(vty, argv, argc);
}

DEFUN(assignment_subscr_conn,
      assignment_subscr_conn_cmd,
      "bts <0-255> trx <0-255> timeslot <0-7> sub-slot <0-7> assignment",
      BTS_NR_TRX_TS_SS_STR2
      MANUAL_ASSIGNMENT_STR)
{
	return ho_or_as(vty, argv, argc);
}

static struct gsm_lchan *find_used_voice_lchan(struct vty *vty, int random_idx)
{
	struct gsm_bts *bts;
	struct gsm_network *network = gsmnet_from_vty(vty);

	while (1) {
		int count = 0;
		llist_for_each_entry(bts, &network->bts_list, list) {
			struct gsm_bts_trx *trx;

			llist_for_each_entry(trx, &bts->trx_list, list) {
				int i;
				for (i = 0; i < ARRAY_SIZE(trx->ts); i++) {
					struct gsm_bts_trx_ts *ts = &trx->ts[i];
					struct gsm_lchan *lchan;

					if (ts->fi->state != TS_ST_IN_USE)
						continue;

					ts_for_n_lchans(lchan, ts, ts->max_lchans_possible) {
						if (lchan_state_is(lchan, LCHAN_ST_ESTABLISHED)
						    && (lchan->type == GSM_LCHAN_TCH_F
							|| lchan->type == GSM_LCHAN_TCH_H)) {

							if (count == random_idx) {
								vty_out(vty, "Found voice call: %s%s",
									gsm_lchan_name(lchan),
									VTY_NEWLINE);
								lchan_dump_full_vty(vty, lchan);
								return lchan;
							}
							count ++;
						}
					}
				}
			}
		}

		if (!count)
			break;
		/* there are used lchans, but random_idx is > count. Iterate again. */
		random_idx %= count;
	}

	vty_out(vty, "%% Cannot find any ongoing voice calls%s", VTY_NEWLINE);
	return NULL;
}

static struct gsm_bts *find_other_bts_with_free_slots(struct vty *vty, struct gsm_bts *not_this_bts,
						      enum gsm_chan_t free_type)
{
	struct gsm_bts *bts;
	struct gsm_network *network = gsmnet_from_vty(vty);

	llist_for_each_entry(bts, &network->bts_list, list) {
		struct gsm_bts_trx *trx;

		if (bts == not_this_bts)
			continue;

		llist_for_each_entry(trx, &bts->trx_list, list) {
			struct gsm_lchan *lchan = lchan_select_by_type(bts, free_type);
			if (!lchan)
				continue;

			vty_out(vty, "Found unused %s slot: %s%s",
				gsm_lchant_name(free_type), gsm_lchan_name(lchan), VTY_NEWLINE);
			lchan_dump_full_vty(vty, lchan);
			return bts;
		}
	}
	vty_out(vty, "%% Cannot find any BTS (other than BTS %u) with free %s lchan%s",
		not_this_bts? not_this_bts->nr : 255, gsm_lchant_name(free_type), VTY_NEWLINE);
	return NULL;
}

DEFUN(handover_any, handover_any_cmd,
      "handover any",
      MANUAL_HANDOVER_STR
      "Pick any actively used TCH/F or TCH/H lchan and handover to any other BTS."
      " This is likely to fail if not all BTS are guaranteed to be reachable by the MS.\n")
{
	struct gsm_lchan *from_lchan;
	struct gsm_bts *to_bts;

	from_lchan = find_used_voice_lchan(vty, random());
	if (!from_lchan)
		return CMD_WARNING;

	to_bts = find_other_bts_with_free_slots(vty, from_lchan->ts->trx->bts, from_lchan->type);
	if (!to_bts)
		return CMD_WARNING;

	return trigger_ho(vty, from_lchan, to_bts);
}

DEFUN(assignment_any, assignment_any_cmd,
      "assignment any",
      MANUAL_ASSIGNMENT_STR
      "Pick any actively used TCH/F or TCH/H lchan and re-assign within the same BTS."
      " This will fail if no lchans of the same type are available besides the used one.\n")
{
	struct gsm_lchan *from_lchan;

	from_lchan = find_used_voice_lchan(vty, random());
	if (!from_lchan)
		return CMD_WARNING;

	return trigger_as(vty, from_lchan, NULL);
}

DEFUN(handover_any_to_arfcn_bsic, handover_any_to_arfcn_bsic_cmd,
      "handover any to " CELL_AB_VTY_PARAMS,
      MANUAL_HANDOVER_STR
      "Pick any actively used TCH/F or TCH/H lchan to handover to another cell."
      " This is likely to fail outside of a lab setup where you are certain that"
      " all MS are able to see the target cell.\n"
      "'to'\n"
      CELL_AB_VTY_DOC)
{
	struct cell_ab ab = {};
	struct handover_out_req req;
	struct gsm_lchan *from_lchan;

	from_lchan = find_used_voice_lchan(vty, random());
	if (!from_lchan)
		return CMD_WARNING;

	req = (struct handover_out_req){
		.from_hodec_id = HODEC_USER,
		.old_lchan = from_lchan,
	};

	neighbor_ident_vty_parse_arfcn_bsic(&ab, argv);
	req.target_cell_ab = ab;

	handover_request(&req);
	return CMD_SUCCESS;
}

static void paging_dump_vty(struct vty *vty, struct gsm_paging_request *pag)
{
	vty_out(vty, "Paging on BTS %u%s", pag->bts->nr, VTY_NEWLINE);
	bsc_subscr_dump_vty(vty, pag->bsub);
}

static void bts_paging_dump_vty(struct vty *vty, struct gsm_bts *bts)
{
	struct gsm_paging_request *pag;

	if (!bts->paging.bts)
		return;

	llist_for_each_entry(pag, &bts->paging.pending_requests, entry)
		paging_dump_vty(vty, pag);
}

DEFUN(show_paging,
      show_paging_cmd,
      "show paging [<0-255>]",
	SHOW_STR "Display information about paging requests of a BTS\n"
	BTS_NR_STR)
{
	struct gsm_network *net = gsmnet_from_vty(vty);
	struct gsm_bts *bts;
	int bts_nr;

	if (argc >= 1) {
		/* use the BTS number that the user has specified */
		bts_nr = atoi(argv[0]);
		if (bts_nr >= net->num_bts) {
			vty_out(vty, "%% can't find BTS %s%s", argv[0],
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		bts = gsm_bts_num(net, bts_nr);
		bts_paging_dump_vty(vty, bts);

		return CMD_SUCCESS;
	}
	for (bts_nr = 0; bts_nr < net->num_bts; bts_nr++) {
		bts = gsm_bts_num(net, bts_nr);
		bts_paging_dump_vty(vty, bts);
	}

	return CMD_SUCCESS;
}

DEFUN(show_paging_group,
      show_paging_group_cmd,
      "show paging-group <0-255> IMSI",
      SHOW_STR "Display the paging group\n"
      BTS_NR_STR "IMSI\n")
{
	struct gsm_network *net = gsmnet_from_vty(vty);
	struct gsm_bts *bts;
	unsigned int page_group;
	int bts_nr = atoi(argv[0]);

	if (bts_nr >= net->num_bts) {
		vty_out(vty, "%% can't find BTS %s%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts = gsm_bts_num(net, bts_nr);
	if (!bts) {
		vty_out(vty, "%% can't find BTS %s%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	page_group = gsm0502_calc_paging_group(&bts->si_common.chan_desc,
						str_to_imsi(argv[1]));
	vty_out(vty, "%% Paging group for IMSI %" PRIu64 " on BTS #%d is %u%s",
		str_to_imsi(argv[1]), bts->nr,
		page_group, VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_net_neci,
	      cfg_net_neci_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "neci (0|1)",
	      "New Establish Cause Indication\n"
	      "Don't set the NECI bit\n" "Set the NECI bit\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);

	gsmnet->neci = atoi(argv[0]);
	gsm_net_update_ctype(gsmnet);
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_net_pag_any_tch,
	      cfg_net_pag_any_tch_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "paging any use tch (0|1)",
	      "Assign a TCH when receiving a Paging Any request\n"
	      "Any Channel\n" "Use\n" "TCH\n"
	      "Do not use TCH for Paging Request Any\n"
	      "Do use TCH for Paging Request Any\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	gsmnet->pag_any_tch = atoi(argv[0]);
	gsm_net_update_ctype(gsmnet);
	return CMD_SUCCESS;
}

DEFUN_DEPRECATED(cfg_net_dtx,
		 cfg_net_dtx_cmd,
		 "dtx-used (0|1)",
		 ".HIDDEN\n""Obsolete\n""Obsolete\n")
{
	vty_out(vty, "%% 'dtx-used' is now deprecated: use dtx * "
		"configuration options of BTS instead%s", VTY_NEWLINE);
       return CMD_SUCCESS;
}

#define NRI_STR "Mapping of Network Resource Indicators to this MSC, for MSC pooling\n"
#define NULL_NRI_STR "Define NULL-NRI values that cause re-assignment of an MS to a different MSC, for MSC pooling.\n"
#define NRI_FIRST_LAST_STR "First value of the NRI value range, should not surpass the configured 'nri bitlen'.\n" \
	"Last value of the NRI value range, should not surpass the configured 'nri bitlen' and be larger than the" \
	" first value; if omitted, apply only the first value.\n"
#define NRI_ARGS_TO_STR_FMT "%s%s%s"
#define NRI_ARGS_TO_STR_ARGS(ARGC, ARGV) ARGV[0], (ARGC>1)? ".." : "", (ARGC>1)? ARGV[1] : ""
#define NRI_WARN(MSC, FORMAT, args...) do { \
		vty_out(vty, "%% Warning: msc %d: " FORMAT "%s", MSC->nr, ##args, VTY_NEWLINE); \
		LOGP(DMSC, LOGL_ERROR, "msc %d: " FORMAT "\n", MSC->nr, ##args); \
	} while (0)

DEFUN_ATTR(cfg_net_nri_bitlen,
	   cfg_net_nri_bitlen_cmd,
	   "nri bitlen <1-15>",
	   NRI_STR
	   "Set number of bits that an NRI has, to extract from TMSI identities (always starting just after the TMSI's most significant octet).\n"
	   "bit count (default: " OSMO_STRINGIFY_VAL(OSMO_NRI_BITLEN_DEFAULT) ")\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	gsmnet->nri_bitlen = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_net_nri_null_add,
	   cfg_net_nri_null_add_cmd,
	   "nri null add <0-32767> [<0-32767>]",
	   NRI_STR NULL_NRI_STR "Add NULL-NRI value (or range)\n"
	   NRI_FIRST_LAST_STR,
	   CMD_ATTR_IMMEDIATE)
{
	int rc;
	const char *message;
	rc = osmo_nri_ranges_vty_add(&message, NULL, bsc_gsmnet->null_nri_ranges, argc, argv,
				     bsc_gsmnet->nri_bitlen);
	if (message) {
		vty_out(vty, "%% %s: " NRI_ARGS_TO_STR_FMT, message, NRI_ARGS_TO_STR_ARGS(argc, argv));
	}
	if (rc < 0)
		return CMD_WARNING;
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_net_nri_null_del,
	   cfg_net_nri_null_del_cmd,
	   "nri null del <0-32767> [<0-32767>]",
	   NRI_STR NULL_NRI_STR "Remove NRI value or range from the NRI mapping for this MSC\n"
	   NRI_FIRST_LAST_STR,
	   CMD_ATTR_IMMEDIATE)
{
	int rc;
	const char *message;
	rc = osmo_nri_ranges_vty_del(&message, NULL, bsc_gsmnet->null_nri_ranges, argc, argv);
	if (message) {
		vty_out(vty, "%% %s: " NRI_ARGS_TO_STR_FMT "%s", message, NRI_ARGS_TO_STR_ARGS(argc, argv),
			VTY_NEWLINE);
	}
	if (rc < 0)
		return CMD_WARNING;
	return CMD_SUCCESS;
}

int print_counter(struct rate_ctr_group *bsc_ctrs, struct rate_ctr *ctr, const struct rate_ctr_desc *desc, void *data)
{
	struct vty *vty = data;
	vty_out(vty, "%25s: %10"PRIu64" %s%s", desc->name, ctr->current, desc->description, VTY_NEWLINE);
	return 0;
}

void openbsc_vty_print_statistics(struct vty *vty, struct gsm_network *net)
{
	rate_ctr_for_each_counter(net->bsc_ctrs, print_counter, vty);
}

DEFUN(drop_bts,
      drop_bts_cmd,
      "drop bts connection <0-65535> (oml|rsl)",
      "Debug/Simulation command to drop Abis/IP BTS\n"
      "Debug/Simulation command to drop Abis/IP BTS\n"
      "Debug/Simulation command to drop Abis/IP BTS\n"
      "BTS NR\n" "Drop OML Connection\n" "Drop RSL Connection\n")
{
	struct gsm_network *gsmnet;
	struct gsm_bts_trx *trx;
	struct gsm_bts *bts;
	unsigned int bts_nr;

	gsmnet = gsmnet_from_vty(vty);

	bts_nr = atoi(argv[0]);
	if (bts_nr >= gsmnet->num_bts) {
		vty_out(vty, "%% BTS number must be between 0 and %d. It was %d.%s",
			gsmnet->num_bts, bts_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts = gsm_bts_num(gsmnet, bts_nr);
	if (!bts) {
		vty_out(vty, "%% BTS Nr. %d could not be found.%s", bts_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!is_ipaccess_bts(bts)) {
		vty_out(vty, "%% This command only works for ipaccess.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}


	/* close all connections */
	if (strcmp(argv[1], "oml") == 0) {
		ipaccess_drop_oml(bts, "vty");
	} else if (strcmp(argv[1], "rsl") == 0) {
		/* close all rsl connections */
		llist_for_each_entry(trx, &bts->trx_list, list) {
			ipaccess_drop_rsl(trx, "vty");
		}
	} else {
		vty_out(vty, "%% Argument must be 'oml' or 'rsl'.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(restart_bts, restart_bts_cmd,
      "restart-bts <0-65535>",
      "Restart ip.access nanoBTS through OML\n"
      BTS_NR_STR)
{
	struct gsm_network *gsmnet;
	struct gsm_bts_trx *trx;
	struct gsm_bts *bts;
	unsigned int bts_nr;

	gsmnet = gsmnet_from_vty(vty);

	bts_nr = atoi(argv[0]);
	if (bts_nr >= gsmnet->num_bts) {
		vty_out(vty, "%% BTS number must be between 0 and %d. It was %d.%s",
			gsmnet->num_bts, bts_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts = gsm_bts_num(gsmnet, bts_nr);
	if (!bts) {
		vty_out(vty, "%% BTS Nr. %d could not be found.%s", bts_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!is_ipaccess_bts(bts) || is_osmobts(bts)) {
		vty_out(vty, "%% This command only works for ipaccess nanoBTS.%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* go from last TRX to c0 */
	llist_for_each_entry_reverse(trx, &bts->trx_list, list)
		abis_nm_ipaccess_restart(trx);

	return CMD_SUCCESS;
}

DEFUN(bts_resend_sysinfo,
      bts_resend_sysinfo_cmd,
      "bts <0-255> resend-system-information",
      "BTS Specific Commands\n" BTS_NR_STR
      "Re-generate + re-send BCCH SYSTEM INFORMATION\n")
{
	struct gsm_network *gsmnet;
	struct gsm_bts *bts;
	unsigned int bts_nr;

	gsmnet = gsmnet_from_vty(vty);

	bts_nr = atoi(argv[0]);
	if (bts_nr >= gsmnet->num_bts) {
		vty_out(vty, "%% BTS number must be between 0 and %d. It was %d.%s",
			gsmnet->num_bts, bts_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts = gsm_bts_num(gsmnet, bts_nr);
	if (!bts) {
		vty_out(vty, "%% BTS Nr. %d could not be found.%s", bts_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (gsm_bts_set_system_infos(bts) != 0) {
		vty_out(vty, "%% Filed to (re)generate System Information "
			"messages, check the logs%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(bts_resend_power_ctrl_params,
      bts_resend_power_ctrl_params_cmd,
      "bts <0-255> resend-power-control-defaults",
      "BTS Specific Commands\n" BTS_NR_STR
      "Re-generate + re-send default MS/BS Power control parameters\n")
{
	const struct gsm_bts_trx *trx;
	const struct gsm_bts *bts;
	int bts_nr = atoi(argv[0]);

	bts = gsm_bts_num(gsmnet_from_vty(vty), bts_nr);
	if (!bts) {
		vty_out(vty, "%% No such BTS (%d)%s", bts_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (bts->model->power_ctrl_send_def_params == NULL) {
		vty_out(vty, "%% Sending default MS/BS Power control parameters "
			"for BTS%d is not implemented%s", bts_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	llist_for_each_entry(trx, &bts->trx_list, list) {
		if (bts->model->power_ctrl_send_def_params(trx) != 0) {
			vty_out(vty, "%% Failed to send default MS/BS Power control parameters "
				"to BTS%d/TRX%d%s", bts_nr, trx->nr, VTY_NEWLINE);
			return CMD_WARNING;
		}
	}

	return CMD_SUCCESS;
}

DEFUN(bts_c0_power_red,
      bts_c0_power_red_cmd,
      "bts <0-255> c0-power-reduction <0-6>",
      "BTS Specific Commands\n" BTS_NR_STR
      "BCCH carrier power reduction operation\n"
      "Power reduction value (in dB, even numbers only)\n")
{
	int bts_nr = atoi(argv[0]);
	int red = atoi(argv[1]);
	struct gsm_bts *bts;
	int rc;

	bts = gsm_bts_num(gsmnet_from_vty(vty), bts_nr);
	if (!bts) {
		vty_out(vty, "%% No such BTS (%d)%s", bts_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (red % 2 != 0) {
		vty_out(vty, "%% Incorrect BCCH power reduction value, "
			"an even number is expected%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	rc = gsm_bts_set_c0_power_red(bts, red);
	if (rc == -ENOTSUP) {
		vty_out(vty, "%% BCCH carrier power reduction operation mode "
			"is not supported for BTS%u%s", bts_nr, VTY_NEWLINE);
		return CMD_WARNING;
	} else if (rc != 0) {
		vty_out(vty, "%% Failed to %sable BCCH carrier power reduction "
			"operation mode for BTS%u%s", red ? "en" : "dis",
			bts_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

/* this command is now hidden, as it's a low-level debug hack, and people should
 * instead use osmo-cbc these days */
DEFUN_HIDDEN(smscb_cmd, smscb_cmd_cmd,
	"bts <0-255> smscb-command (normal|schedule|default) <1-4> HEXSTRING",
	"BTS related commands\n" BTS_NR_STR
	"SMS Cell Broadcast\n"
	"Normal (one-shot) SMSCB Message; sent once over Abis+Um\n"
	"Schedule (one-shot) SMSCB Message; sent once over Abis+Um\n"
	"Default (repeating) SMSCB Message; sent once over Abis, unlimited ovrer Um\n"
	"Last Valid Block\n"
	"Hex Encoded SMSCB message (up to 88 octets)\n")
{
	struct gsm_bts *bts;
	int bts_nr = atoi(argv[0]);
	const char *type_str = argv[1];
	int last_block = atoi(argv[2]);
	struct rsl_ie_cb_cmd_type cb_cmd;
	uint8_t buf[88];
	int rc;

	bts = gsm_bts_num(gsmnet_from_vty(vty), bts_nr);
	if (!bts) {
		vty_out(vty, "%% No such BTS (%d)%s", bts_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}
	if (!gsm_bts_get_cbch(bts)) {
		vty_out(vty, "%% BTS %d doesn't have a CBCH%s", bts_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}
	rc = osmo_hexparse(argv[3], buf, sizeof(buf));
	if (rc < 0 || rc > sizeof(buf)) {
		vty_out(vty, "%% Error parsing HEXSTRING%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	cb_cmd.spare = 0;
	cb_cmd.def_bcast = 0;
	if (!strcmp(type_str, "normal"))
		cb_cmd.command = RSL_CB_CMD_TYPE_NORMAL;
	else if (!strcmp(type_str, "schedule"))
		cb_cmd.command = RSL_CB_CMD_TYPE_SCHEDULE;
	else if (!strcmp(type_str, "default"))
		cb_cmd.command = RSL_CB_CMD_TYPE_DEFAULT;
	else {
		vty_out(vty, "%% Error parsing type%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	switch (last_block) {
	case 1:
		cb_cmd.last_block = RSL_CB_CMD_LASTBLOCK_1;
		break;
	case 2:
		cb_cmd.last_block = RSL_CB_CMD_LASTBLOCK_2;
		break;
	case 3:
		cb_cmd.last_block = RSL_CB_CMD_LASTBLOCK_3;
		break;
	case 4:
		cb_cmd.last_block = RSL_CB_CMD_LASTBLOCK_4;
		break;
	default:
		vty_out(vty, "%% Error parsing LASTBLOCK%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* SDCCH4 might not be correct here if the CBCH is on a SDCCH8? */
	rsl_sms_cb_command(bts, RSL_CHAN_SDCCH4_ACCH, cb_cmd, false, buf, rc);

	return CMD_SUCCESS;
}

DEFUN(pdch_act, pdch_act_cmd,
	"bts <0-255> trx <0-255> timeslot <0-7> pdch (activate|deactivate)",
	BTS_NR_TRX_TS_STR2
	"Packet Data Channel\n"
	"Activate Dynamic PDCH/TCH (-> PDCH mode)\n"
	"Deactivate Dynamic PDCH/TCH (-> TCH mode)\n")
{
	struct gsm_bts_trx_ts *ts;
	int activate;

	ts = vty_get_ts(vty, argv[0], argv[1], argv[2]);
	if (!ts || !ts->fi || ts->fi->state == TS_ST_NOT_INITIALIZED || ts->fi->state == TS_ST_BORKEN) {
		vty_out(vty, "%% Timeslot is not usable%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!is_ipaccess_bts(ts->trx->bts)) {
		vty_out(vty, "%% This command only works for ipaccess BTS%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (ts->pchan_on_init != GSM_PCHAN_OSMO_DYN
	    && ts->pchan_on_init != GSM_PCHAN_TCH_F_PDCH) {
		vty_out(vty, "%% Timeslot %u is not dynamic TCH/F_TCH/H_SDCCH8_PDCH or TCH/F_PDCH%s",
			ts->nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!strcmp(argv[3], "activate"))
		activate = 1;
	else
		activate = 0;

	if (activate && ts->fi->state != TS_ST_UNUSED) {
		vty_out(vty, "%% Timeslot %u is still in use%s",
			ts->nr, VTY_NEWLINE);
		return CMD_WARNING;
	} else if (!activate && ts->fi->state != TS_ST_PDCH) {
		vty_out(vty, "%% Timeslot %u is not in PDCH mode%s",
			ts->nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	LOG_TS(ts, LOGL_NOTICE, "telnet VTY user asks to %s\n", activate ? "PDCH ACT" : "PDCH DEACT");
	ts->pdch_act_allowed = activate;
	osmo_fsm_inst_state_chg(ts->fi, activate ? TS_ST_WAIT_PDCH_ACT : TS_ST_WAIT_PDCH_DEACT, 4, 0);

	return CMD_SUCCESS;

}


/* Activate / Deactivate a single lchan with a specific codec mode */
static int lchan_act_single(struct vty *vty, struct gsm_lchan *lchan, const char *codec_str, int amr_mode, int activate)
{
	struct lchan_activate_info info = {0};
	uint16_t amr_modes[8] =
	    { GSM0808_SC_CFG_AMR_4_75, GSM0808_SC_CFG_AMR_4_75_5_90_7_40_12_20, GSM0808_SC_CFG_AMR_5_90,
	      GSM0808_SC_CFG_AMR_6_70, GSM0808_SC_CFG_AMR_7_40, GSM0808_SC_CFG_AMR_7_95, GSM0808_SC_CFG_AMR_10_2,
	      GSM0808_SC_CFG_AMR_12_2 };

	if (activate) {
		if (!codec_str) {
			vty_out(vty, "%% Error: need a channel type argument to activate%s", VTY_NEWLINE);
			return CMD_WARNING;
		}

		LOG_LCHAN(lchan, LOGL_NOTICE, "attempt from VTY to activate lchan %s with codec %s\n",
			  gsm_lchan_name(lchan), codec_str);
		if (!lchan->fi) {
			vty_out(vty, "%% Cannot activate: Channel not initialized%s", VTY_NEWLINE);
			return CMD_WARNING;
		}

		int lchan_t;
		if (lchan->fi->state != LCHAN_ST_UNUSED) {
			vty_out(vty, "%% Cannot activate: Channel busy!%s", VTY_NEWLINE);
			return CMD_WARNING;
		}

		/* pick a suitable lchan type */
		lchan_t = gsm_lchan_type_by_pchan(lchan->ts->pchan_is);
		if (lchan_t < 0) {
			if (lchan->ts->pchan_on_init == GSM_PCHAN_TCH_F_PDCH && !strcmp(codec_str, "fr"))
				lchan_t = GSM_LCHAN_TCH_F;
			else if (lchan->ts->pchan_on_init == GSM_PCHAN_OSMO_DYN && !strcmp(codec_str, "hr"))
				lchan_t = GSM_LCHAN_TCH_H;
			else if ((lchan->ts->pchan_on_init == GSM_PCHAN_TCH_F_PDCH
				  || lchan->ts->pchan_on_init == GSM_PCHAN_OSMO_DYN)
				 && !strcmp(codec_str, "fr"))
				lchan_t = GSM_LCHAN_TCH_F;
			else {
				vty_out(vty, "%% Cannot activate: Invalid lchan type (%s)!%s",
					gsm_pchan_name(lchan->ts->pchan_on_init), VTY_NEWLINE);
				return CMD_WARNING;
			}
		}

		/* configure the lchan */
		lchan_select_set_type(lchan, lchan_t);
		if (!strcmp(codec_str, "hr") || !strcmp(codec_str, "fr")) {
			info.ch_mode_rate.chan_mode = GSM48_CMODE_SPEECH_V1;
		} else if (!strcmp(codec_str, "efr")) {
			info.ch_mode_rate.chan_mode = GSM48_CMODE_SPEECH_EFR;
		} else if (!strcmp(codec_str, "amr")) {
			if (amr_mode == -1) {
				vty_out(vty, "%% AMR requires specification of AMR mode%s", VTY_NEWLINE);
				return CMD_WARNING;
			}
			info.ch_mode_rate.chan_mode = GSM48_CMODE_SPEECH_AMR;
			info.ch_mode_rate.s15_s0 = amr_modes[amr_mode];
		} else if (!strcmp(codec_str, "sig")) {
			info.ch_mode_rate.chan_mode = GSM48_CMODE_SIGN;
		} else {
			vty_out(vty, "%% Invalid channel mode specified!%s", VTY_NEWLINE);
			return CMD_WARNING;
		}

		info.activ_for = ACTIVATE_FOR_VTY;
		info.requires_voice_stream = false;
		info.ch_mode_rate.chan_rate = chan_t_to_chan_rate(lchan_t);

		if (activate == 2 || lchan->vamos.is_secondary) {
			info.vamos = true;
			if (lchan->vamos.is_secondary) {
				info.tsc_set.present = true;
				info.tsc_set.val = 1;
			}
			info.tsc.present = true;
			info.tsc.val = 0;
			info.ch_mode_rate.chan_mode = gsm48_chan_mode_to_vamos(info.ch_mode_rate.chan_mode);
		}

		vty_out(vty, "%% activating lchan %s as %s%s", gsm_lchan_name(lchan), gsm_chan_t_name(lchan->type),
			VTY_NEWLINE);
		lchan_activate(lchan, &info);
	} else {
		LOG_LCHAN(lchan, LOGL_NOTICE, "attempt from VTY to release lchan %s\n", gsm_lchan_name(lchan));
		if (!lchan->fi) {
			vty_out(vty, "%% Cannot release: Channel not initialized%s", VTY_NEWLINE);
			return CMD_WARNING;
		}
		vty_out(vty, "%% Asking for release of %s in state %s%s", gsm_lchan_name(lchan),
			osmo_fsm_inst_state_name(lchan->fi), VTY_NEWLINE);
		lchan_release(lchan, !!(lchan->conn), false, 0,
			      gscon_last_eutran_plmn(lchan->conn));
	}

	return CMD_SUCCESS;
}

/* Activate / Deactivate a single lchan with a specific codec mode */
static int lchan_act_trx(struct vty *vty, struct gsm_bts_trx *trx, int activate)
{
	int ts_nr;
	struct gsm_bts_trx_ts *ts;
	struct gsm_lchan *lchan;
	char *codec_str;
	bool skip_next = false;

	for (ts_nr = 0; ts_nr < TRX_NR_TS; ts_nr++) {
		ts = &trx->ts[ts_nr];
		ts_for_n_lchans(lchan, ts, ts->max_lchans_possible) {
			switch (ts->pchan_on_init) {
			case GSM_PCHAN_SDCCH8_SACCH8C:
			case GSM_PCHAN_CCCH_SDCCH4_CBCH:
			case GSM_PCHAN_SDCCH8_SACCH8C_CBCH:
			case GSM_PCHAN_CCCH:
			case GSM_PCHAN_CCCH_SDCCH4:
				codec_str = "sig";
				break;
			case GSM_PCHAN_TCH_F:
			case GSM_PCHAN_TCH_F_PDCH:
			case GSM_PCHAN_OSMO_DYN:
				codec_str = "fr";
				break;
			case GSM_PCHAN_TCH_H:
				codec_str = "hr";
				break;
			default:
				codec_str = NULL;
			}

			if (codec_str && skip_next == false) {
				lchan_act_single(vty, lchan, codec_str, -1, activate);

				/* We use GSM_PCHAN_OSMO_DYN slots as TCH_F for this test, so we
				 * must not use the TCH_H reserved lchan in subslot 1. */
				if (ts->pchan_on_init == GSM_PCHAN_OSMO_DYN)
					skip_next = true;
			}
			else {
				vty_out(vty, "%% omitting lchan %s%s", gsm_lchan_name(lchan), VTY_NEWLINE);
				skip_next = false;
			}
		}
	}

	return CMD_SUCCESS;
}

static int lchan_act_deact(struct vty *vty, const char **argv, int argc)
{
	struct gsm_bts_trx_ts *ts;
	struct gsm_lchan *lchan;
	bool vamos = (strcmp(argv[3], "vamos-sub-slot") == 0);
	int ss_nr = atoi(argv[4]);
	const char *act_str = NULL;
	const char *codec_str = NULL;
	int activate;
	int amr_mode = -1;

	if (argc > 5)
		act_str = argv[5];
	if (argc > 6)
		codec_str = argv[6];
	if (argc > 7)
		amr_mode = atoi(argv[7]);

	ts = vty_get_ts(vty, argv[0], argv[1], argv[2]);
	if (!ts)
		return CMD_WARNING;

	if (ss_nr >= ts->max_primary_lchans) {
		vty_out(vty, "Invalid sub-slot number %d for this timeslot type: %s (%u)%s", ss_nr,
			gsm_pchan_name(ts->pchan_on_init), ts->max_primary_lchans, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (vamos && !osmo_bts_has_feature(&ts->trx->bts->features, BTS_FEAT_VAMOS)) {
		vty_out(vty, "BTS does not support VAMOS%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (vamos)
		ss_nr += ts->max_primary_lchans;

	lchan = &ts->lchan[ss_nr];

	if (!act_str)
		activate = 0;
	else if (!strcmp(act_str, "activate"))
		activate = 1;
	else if (!strcmp(act_str, "activate-vamos"))
		activate = 2;
	else
		return CMD_WARNING;

	return lchan_act_single(vty, lchan, codec_str, amr_mode, activate);
}

/* Debug/Measurement command to activate a given logical channel
 * manually in a given mode/codec.  This is useful for receiver
 * performance testing (FER/RBER/...) */
DEFUN(lchan_act, lchan_act_cmd,
	"bts <0-255> trx <0-255> timeslot <0-7> (sub-slot|vamos-sub-slot) <0-7> (activate|activate-vamos) (hr|fr|efr|amr|sig) [<0-7>]",
	BTS_NR_TRX_TS_STR2
	"Primary sub-slot\n" "VAMOS secondary shadow subslot, range <0-1>, only valid for TCH type timeslots\n"
	SS_NR_STR
	"Manual Channel Activation (e.g. for BER test)\n"
	"Manual Channel Activation, in VAMOS mode\n"
	"Half-Rate v1\n" "Full-Rate\n" "Enhanced Full Rate\n" "Adaptive Multi-Rate\n" "Signalling\n" "AMR Mode\n")
{
	return lchan_act_deact(vty, argv, argc);
}

DEFUN(lchan_deact, lchan_deact_cmd,
	"bts <0-255> trx <0-255> timeslot <0-7> (sub-slot|vamos-sub-slot) <0-7> deactivate",
	BTS_NR_TRX_TS_STR2
	"Primary sub-slot\n" "VAMOS secondary shadow subslot, range <0-1>, only valid for TCH type timeslots\n"
	SS_NR_STR
	"Manual Channel Deactivation (e.g. for BER test)\n")
{
	return lchan_act_deact(vty, argv, argc);
}

#define ACTIVATE_ALL_LCHANS_STR "Manual Channel Activation of all logical channels (e.g. for BER test)\n"
#define DEACTIVATE_ALL_LCHANS_STR "Manual Channel Deactivation of all logical channels (e.g. for BER test)\n"

/* Similar to lchan_act, but activates all lchans on the network at once,
 * this is intended to perform lab tests / measurements. */
DEFUN_HIDDEN(lchan_act_bts, lchan_act_all_cmd,
	     "(activate-all-lchan|deactivate-all-lchan)",
	     ACTIVATE_ALL_LCHANS_STR
	     DEACTIVATE_ALL_LCHANS_STR)
{
	struct gsm_network *net = gsmnet_from_vty(vty);
	const char *act_str = argv[0];
	int activate;
	int bts_nr;
	struct gsm_bts *bts;
	int trx_nr;
	struct gsm_bts_trx *trx;

	if (!strcmp(act_str, "activate-all-lchan"))
		activate = 1;
	else
		activate = 0;

	for (bts_nr = 0; bts_nr < net->num_bts; bts_nr++) {
		bts = gsm_bts_num(gsmnet_from_vty(vty), bts_nr);
		for (trx_nr = 0; trx_nr < bts->num_trx; trx_nr++) {
			trx = gsm_bts_trx_num(bts, trx_nr);
			lchan_act_trx(vty, trx, activate);
		}
	}

	vty_out(vty, "%% All channels have been %s on all BTS/TRX, please "
		     "make sure that the radio link timeout is set to %s%s",
		activate ? "activated" : "deactivated",
		activate ? "'infinite'" : "its old value (e.g. 'oml')",
		VTY_NEWLINE);

	return CMD_SUCCESS;
}

/* Similar to lchan_act, but activates all lchans on the specified BTS at once,
 * this is intended to perform lab tests / measurements. */
DEFUN_HIDDEN(lchan_act_all_bts, lchan_act_all_bts_cmd,
	     "bts <0-255> (activate-all-lchan|deactivate-all-lchan)",
	     "BTS Specific Commands\n" BTS_NR_STR
	     ACTIVATE_ALL_LCHANS_STR
	     DEACTIVATE_ALL_LCHANS_STR)
{
	int bts_nr = atoi(argv[0]);
	const char *act_str = argv[1];
	int activate;
	struct gsm_bts *bts;
	int trx_nr;
	struct gsm_bts_trx *trx;

	if (!strcmp(act_str, "activate-all-lchan"))
		activate = 1;
	else
		activate = 0;

	bts = gsm_bts_num(gsmnet_from_vty(vty), bts_nr);
	if (!bts) {
		vty_out(vty, "%% No such BTS (%d)%s", bts_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	for (trx_nr = 0; trx_nr < bts->num_trx; trx_nr++) {
		trx = gsm_bts_trx_num(bts, trx_nr);
		lchan_act_trx(vty, trx, activate);
	}

	vty_out(vty, "%% All channels have been %s on all TRX of BTS%d, please "
		     "make sure that the radio link timeout is set to %s%s",
		activate ? "activated" : "deactivated", bts_nr,
		activate ? "'infinite'" : "its old value (e.g. 'oml')",
		VTY_NEWLINE);

	return CMD_SUCCESS;
}

/* Similar to lchan_act, but activates all lchans on the specified BTS at once,
 * this is intended to perform lab tests / measurements. */
DEFUN_HIDDEN(lchan_act_all_trx, lchan_act_all_trx_cmd,
	     "bts <0-255> trx <0-255> (activate-all-lchan|deactivate-all-lchan)",
	     "BTS for manual command\n" BTS_NR_STR
	     "TRX for manual command\n" TRX_NR_STR
	     ACTIVATE_ALL_LCHANS_STR
	     DEACTIVATE_ALL_LCHANS_STR)
{
	int bts_nr = atoi(argv[0]);
	int trx_nr = atoi(argv[1]);
	const char *act_str = argv[2];
	int activate;
	struct gsm_bts *bts;
	struct gsm_bts_trx *trx;

	if (!strcmp(act_str, "activate-all-lchan"))
		activate = 1;
	else
		activate = 0;

	bts = gsm_bts_num(gsmnet_from_vty(vty), bts_nr);
	if (!bts) {
		vty_out(vty, "%% No such BTS (%d)%s", bts_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	trx = gsm_bts_trx_num(bts, trx_nr);
	if (!trx) {
		vty_out(vty, "%% No such TRX (%d)%s", trx_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	lchan_act_trx(vty, trx, activate);

	vty_out(vty, "%% All channels have been %s on BTS%d/TRX%d, please "
		     "make sure that the radio link timeout is set to %s%s",
		activate ? "activated" : "deactivated", bts_nr, trx_nr,
		activate ? "'infinite'" : "its old value (e.g. 'oml')",
		VTY_NEWLINE);

	return CMD_SUCCESS;
}

DEFUN(lchan_set_mspower, lchan_set_mspower_cmd,
      "bts <0-255> trx <0-255> timeslot <0-7> sub-slot <0-7> ms-power <0-40> [verify]\n",
      BTS_NR_TRX_TS_SS_STR2
      "Manually force MS Uplink Power Level in dBm on the lchan (for testing)\n"
      "Set transmit power of the MS in dBm\n"
      "Check requested level against BAND and UE Power Class.\n")
{
	struct gsm_bts *bts;
	struct gsm_bts_trx *trx;
	struct gsm_bts_trx_ts *ts;
	struct gsm_lchan *lchan;
	int bts_nr = atoi(argv[0]);
	int trx_nr = atoi(argv[1]);
	int ss_nr = atoi(argv[3]);
	bool verify = (argc > 5);

	bts = gsm_bts_num(gsmnet_from_vty(vty), bts_nr);
	if (!bts) {
		vty_out(vty, "%% No such BTS (%d)%s", bts_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	trx = gsm_bts_trx_num(bts, trx_nr);
	if (!trx) {
		vty_out(vty, "%% No such TRX (%d)%s", trx_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	ts = vty_get_ts(vty, argv[0], argv[1], argv[2]);
	if (!ts) {
		vty_out(vty, "%% No such TS (%d)%s", atoi(argv[2]), VTY_NEWLINE);
		return CMD_WARNING;
	}
	if (ss_nr >= ts->max_primary_lchans) {
		vty_out(vty, "%% Invalid sub-slot number for this timeslot type%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	lchan = &ts->lchan[ss_nr];
	if (!lchan->fi)
		return CMD_WARNING;

	if (verify) {
		lchan_update_ms_power_ctrl_level(lchan, atoi(argv[4]));
		return CMD_SUCCESS;
	}
	lchan->ms_power = ms_pwr_ctl_lvl(ts->trx->bts->band, atoi(argv[4]));
	rsl_chan_ms_power_ctrl(lchan);
	return CMD_SUCCESS;
}

DEFUN(vamos_modify_lchan, vamos_modify_lchan_cmd,
      "bts <0-255> trx <0-255> timeslot <0-7> sub-slot <0-7> modify (vamos|non-vamos) " TSC_ARGS_OPT,
      BTS_NR_TRX_TS_SS_STR2
      "Manually send Channel Mode Modify (for debugging)\n"
      "Enable VAMOS channel mode\n" "Disable VAMOS channel mode\n"
      TSC_ARGS_DOC)
{
	struct gsm_bts_trx_ts *ts;
	struct gsm_lchan *lchan;
	int ss_nr = atoi(argv[3]);
	const char *vamos_str = argv[4];
	/* argv[5] is the "tsc" string from TSC_ARGS_OPT */
	int tsc_set = (argc > 6) ? atoi(argv[6]) : -1;
	int tsc = (argc > 7) ? atoi(argv[7]) : -1;

	ts = vty_get_ts(vty, argv[0], argv[1], argv[2]);
	if (!ts)
		return CMD_WARNING;

	if (ss_nr >= ts->max_primary_lchans) {
		vty_out(vty, "%% Invalid sub-slot number for this timeslot type%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!osmo_bts_has_feature(&ts->trx->bts->features, BTS_FEAT_VAMOS)) {
		vty_out(vty, "%% BTS does not support VAMOS%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	lchan = &ts->lchan[ss_nr];

	return trigger_vamos_mode_modify(vty, lchan, strcmp(vamos_str, "vamos") == 0, tsc_set, tsc);
}

/* Debug command to send lchans from state LCHAN_ST_UNUSED to state
 * LCHAN_ST_BORKEN and vice versa. */
DEFUN_HIDDEN(lchan_set_borken, lchan_set_borken_cmd,
	     "bts <0-255> trx <0-255> timeslot <0-7> sub-slot <0-7> (borken|unused)",
	     BTS_NR_TRX_TS_SS_STR2
	     "send lchan to state LCHAN_ST_BORKEN (for debugging)\n"
	     "send lchan to state LCHAN_ST_UNUSED (for debugging)\n")
{
	struct gsm_bts_trx_ts *ts;
	struct gsm_lchan *lchan;
	int ss_nr = atoi(argv[3]);
	ts = vty_get_ts(vty, argv[0], argv[1], argv[2]);
	if (!ts)
		return CMD_WARNING;

	lchan = &ts->lchan[ss_nr];
	if (!lchan->fi)
		return CMD_WARNING;

	if (!strcmp(argv[4], "borken")) {
		if (lchan->fi->state == LCHAN_ST_UNUSED) {
			osmo_fsm_inst_state_chg(lchan->fi, LCHAN_ST_BORKEN, 0, 0);
		} else {
			vty_out(vty,
				"%% lchan is in state %s, only lchans that are in state %s may be moved to state %s manually%s",
				osmo_fsm_state_name(lchan->fi->fsm, lchan->fi->state),
				osmo_fsm_state_name(lchan->fi->fsm, LCHAN_ST_UNUSED),
				osmo_fsm_state_name(lchan->fi->fsm, LCHAN_ST_BORKEN), VTY_NEWLINE);
			return CMD_WARNING;
		}
	} else {
		if (lchan->fi->state == LCHAN_ST_BORKEN) {
			rate_ctr_inc(rate_ctr_group_get_ctr(lchan->ts->trx->bts->bts_ctrs, BTS_CTR_LCHAN_BORKEN_EV_VTY));
			osmo_fsm_inst_state_chg(lchan->fi, LCHAN_ST_UNUSED, 0, 0);
		} else {
			vty_out(vty,
				"%% lchan is in state %s, only lchans that are in state %s may be moved to state %s manually%s",
				osmo_fsm_state_name(lchan->fi->fsm, lchan->fi->state),
				osmo_fsm_state_name(lchan->fi->fsm, LCHAN_ST_BORKEN),
				osmo_fsm_state_name(lchan->fi->fsm, LCHAN_ST_UNUSED), VTY_NEWLINE);
			return CMD_WARNING;
		}
	}

	return CMD_SUCCESS;
}

DEFUN(lchan_mdcx, lchan_mdcx_cmd,
	"bts <0-255> trx <0-255> timeslot <0-7> sub-slot <0-7> mdcx A.B.C.D <0-65535>",
	BTS_NR_TRX_TS_SS_STR2
	"Modify RTP Connection\n" "MGW IP Address\n" "MGW UDP Port\n")
{
	struct gsm_bts_trx_ts *ts;
	struct gsm_lchan *lchan;
	int ss_nr = atoi(argv[3]);
	int port = atoi(argv[5]);
	struct in_addr ia;
	inet_aton(argv[4], &ia);

	ts = vty_get_ts(vty, argv[0], argv[1], argv[2]);
	if (!ts)
		return CMD_WARNING;

	lchan = &ts->lchan[ss_nr];

	if (!is_ipaccess_bts(lchan->ts->trx->bts)) {
		vty_out(vty, "%% BTS is not of ip.access type%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (ss_nr >= ts->max_primary_lchans) {
		vty_out(vty, "%% subslot index %d too large for physical channel %s (%u slots)%s",
			ss_nr, gsm_pchan_name(ts->pchan_is), ts->max_primary_lchans,
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty_out(vty, "%% connecting RTP of %s to %s:%u%s", gsm_lchan_name(lchan),
		inet_ntoa(ia), port, VTY_NEWLINE);
	lchan->abis_ip.connect_ip = ia.s_addr;
	lchan->abis_ip.connect_port = port;
	rsl_tx_ipacc_mdcx(lchan);
	return CMD_SUCCESS;
}

DEFUN(lchan_reassign, lchan_reassign_cmd,
	"bts <0-255> trx <0-255> timeslot <0-7> (sub-slot|vamos-sub-slot) <0-7> "
	"reassign-to trx <0-255> timeslot <0-7> (sub-slot|vamos-sub-slot) <0-7> "
	TSC_ARGS_OPT,
	BTS_NR_TRX_TS_STR2
	"Primary sub-slot\n" "VAMOS secondary shadow subslot, range <0-1>, only valid for TCH type timeslots\n"
	SS_NR_STR
	"Trigger Assignment to an unused lchan on the same cell\n"
	"Target TRX\nTRX nr\nTarget timeslot\ntimeslot nr\n"
	"Primary sub-slot\n" "VAMOS secondary shadow subslot, range <0-1>, only valid for TCH type timeslots\n"
	SS_NR_STR
	TSC_ARGS_DOC)
{
	const char *bts_str = argv[0];
	const char *from_trx_str = argv[1];
	const char *from_ts_str = argv[2];
	bool from_vamos = (strcmp(argv[3], "vamos-sub-slot") == 0);
	int from_ss_nr = atoi(argv[4]);
	const char *to_trx_str = argv[5];
	const char *to_ts_str = argv[6];
	bool to_vamos = (strcmp(argv[7], "vamos-sub-slot") == 0);
	int to_ss_nr = atoi(argv[8]);
	int tsc_set = (argc > 10) ? atoi(argv[10]) : -1;
	int tsc = (argc > 11) ? atoi(argv[11]) : -1;

	struct gsm_bts_trx_ts *from_ts;
	struct gsm_bts_trx_ts *to_ts;
	struct gsm_lchan *from_lchan;
	struct gsm_lchan *to_lchan;

	from_ts = vty_get_ts(vty, bts_str, from_trx_str, from_ts_str);
	if (!from_ts)
		return CMD_WARNING;
	to_ts = vty_get_ts(vty, bts_str, to_trx_str, to_ts_str);
	if (!to_ts)
		return CMD_WARNING;

	if (!ts_is_capable_of_pchan(to_ts, from_ts->pchan_is)) {
		vty_out(vty, "cannot re-assign, target timeslot has mismatching physical channel config: %s -> %s%s",
			gsm_pchan_name(from_ts->pchan_is), gsm_pchan_name(to_ts->pchan_on_init), VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (from_ss_nr >= from_ts->max_primary_lchans) {
		vty_out(vty, "cannot re-assign, invalid source subslot number: %d%s",
			from_ss_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (to_ss_nr >= to_ts->max_primary_lchans) {
		vty_out(vty, "cannot re-assign, invalid target subslot number: %d%s",
			to_ss_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (from_vamos)
		from_ss_nr += from_ts->max_primary_lchans;
	from_lchan = &from_ts->lchan[from_ss_nr];

	if (to_vamos)
		to_ss_nr += to_ts->max_primary_lchans;
	to_lchan = &to_ts->lchan[to_ss_nr];

	if (!lchan_state_is(from_lchan, LCHAN_ST_ESTABLISHED)) {
		vty_out(vty, "cannot re-assign, source lchan is not in ESTABLISHED state%s", VTY_NEWLINE);
		return CMD_WARNING;
	}
	if (!to_lchan->fi) {
		vty_out(vty, "cannot re-assign, target lchan is not initialized%s", VTY_NEWLINE);
		return CMD_WARNING;
	}
	if (!lchan_state_is(to_lchan, LCHAN_ST_UNUSED)) {
		vty_out(vty, "cannot re-assign, target lchan is already in use%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* Set lchan type, so that activation will work out. */
	lchan_select_set_type(to_lchan, chan_mode_to_chan_type(from_lchan->current_ch_mode_rate.chan_mode,
							       from_lchan->current_ch_mode_rate.chan_rate));

	LOG_LCHAN(from_lchan, LOGL_NOTICE, "VTY requests re-assignment of this lchan to %s%s\n",
		  gsm_lchan_name(to_lchan), to_lchan->vamos.is_secondary ? " (to VAMOS mode)" : "");
	LOG_LCHAN(to_lchan, LOGL_NOTICE, "VTY requests re-assignment of %s to this lchan%s TSC %d/%d\n",
		  gsm_lchan_name(from_lchan), to_lchan->vamos.is_secondary ? " (to VAMOS mode)" : "",
		  tsc_set, tsc);
	if (reassignment_request_to_lchan(ASSIGN_FOR_VTY, from_lchan, to_lchan, tsc_set, tsc)) {
		vty_out(vty, "failed to request re-assignment%s", VTY_NEWLINE);
		return CMD_WARNING;
	}
	return CMD_SUCCESS;
}

DEFUN(ctrl_trap, ctrl_trap_cmd,
	"ctrl-interface generate-trap TRAP VALUE",
	"Commands related to the CTRL Interface\n"
	"Generate a TRAP for test purpose\n"
	"Identity/Name of the TRAP variable\n"
	"Value of the TRAP variable\n")
{
	struct gsm_network *net = gsmnet_from_vty(vty);

	ctrl_cmd_send_trap(net->ctrl, argv[0], (char *) argv[1]);
	return CMD_SUCCESS;
}

#define NETWORK_STR "Configure the GSM network\n"
#define CODE_CMD_STR "Code commands\n"
#define NAME_CMD_STR "Name Commands\n"
#define NAME_STR "Name to use\n"

DEFUN_ATTR(cfg_net,
	   cfg_net_cmd,
	   "network", NETWORK_STR,
	   CMD_ATTR_IMMEDIATE)
{
	vty->index = gsmnet_from_vty(vty);
	vty->node = GSMNET_NODE;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_net_ncc,
	      cfg_net_ncc_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "network country code <1-999>",
	      "Set the GSM network country code\n"
	      "Country commands\n"
	      CODE_CMD_STR
	      "Network Country Code to use\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	uint16_t mcc;

	if (osmo_mcc_from_str(argv[0], &mcc)) {
		vty_out(vty, "%% Error decoding MCC: %s%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	gsmnet->plmn.mcc = mcc;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_net_mnc,
	      cfg_net_mnc_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "mobile network code <0-999>",
	      "Set the GSM mobile network code\n"
	      "Network Commands\n"
	      CODE_CMD_STR
	      "Mobile Network Code to use\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	uint16_t mnc;
	bool mnc_3_digits;

	if (osmo_mnc_from_str(argv[0], &mnc, &mnc_3_digits)) {
		vty_out(vty, "%% Error decoding MNC: %s%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	gsmnet->plmn.mnc = mnc;
	gsmnet->plmn.mnc_3_digits = mnc_3_digits;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_net_encryption,
	      cfg_net_encryption_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "encryption a5 <0-4> [<0-4>] [<0-4>] [<0-4>] [<0-4>]",
	      "Encryption options\n"
	      "GSM A5 Air Interface Encryption\n"
	      "A5/n Algorithm Number\n"
	      "A5/n Algorithm Number\n"
	      "A5/n Algorithm Number\n"
	      "A5/n Algorithm Number\n"
	      "A5/n Algorithm Number\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	unsigned int i;

	gsmnet->a5_encryption_mask = 0;
	for (i = 0; i < argc; i++)
		gsmnet->a5_encryption_mask |= (1 << atoi(argv[i]));

	return CMD_SUCCESS;
}

DEFUN_DEPRECATED(cfg_net_dyn_ts_allow_tch_f,
      cfg_net_dyn_ts_allow_tch_f_cmd,
      "dyn_ts_allow_tch_f (0|1)",
      "Allow or disallow allocating TCH/F on TCH_F_TCH_H_PDCH timeslots\n"
      "Disallow TCH/F on TCH_F_TCH_H_PDCH (default)\n"
      "Allow TCH/F on TCH_F_TCH_H_PDCH\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	gsmnet->dyn_ts_allow_tch_f = atoi(argv[0]) ? true : false;
	vty_out(vty, "%% dyn_ts_allow_tch_f is deprecated, rather use msc/codec-list to pick codecs%s",
		VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_net_timezone,
	   cfg_net_timezone_cmd,
	   "timezone <-19-19> (0|15|30|45)",
	   "Set the Timezone Offset of the network\n"
	   "Timezone offset (hours)\n"
	   "Timezone offset (00 minutes)\n"
	   "Timezone offset (15 minutes)\n"
	   "Timezone offset (30 minutes)\n"
	   "Timezone offset (45 minutes)\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct gsm_network *net = vty->index;
	int tzhr = atoi(argv[0]);
	int tzmn = atoi(argv[1]);

	net->tz.hr = tzhr;
	net->tz.mn = tzmn;
	net->tz.dst = 0;
	net->tz.override = 1;

	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_net_timezone_dst,
	   cfg_net_timezone_dst_cmd,
	   "timezone <-19-19> (0|15|30|45) <0-2>",
	   "Set the Timezone Offset of the network\n"
	   "Timezone offset (hours)\n"
	   "Timezone offset (00 minutes)\n"
	   "Timezone offset (15 minutes)\n"
	   "Timezone offset (30 minutes)\n"
	   "Timezone offset (45 minutes)\n"
	   "DST offset (hours)\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct gsm_network *net = vty->index;
	int tzhr = atoi(argv[0]);
	int tzmn = atoi(argv[1]);
	int tzdst = atoi(argv[2]);

	net->tz.hr = tzhr;
	net->tz.mn = tzmn;
	net->tz.dst = tzdst;
	net->tz.override = 1;

	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_net_no_timezone,
	   cfg_net_no_timezone_cmd,
	   "no timezone",
	   NO_STR
	   "Disable network timezone override, use system tz\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct gsm_network *net = vty->index;

	net->tz.override = 0;

	return CMD_SUCCESS;
}

/* FIXME: changing this value would not affect generated System Information */
DEFUN(cfg_net_per_loc_upd, cfg_net_per_loc_upd_cmd,
      "periodic location update <6-1530>",
      "Periodic Location Updating Interval\n"
      "Periodic Location Updating Interval\n"
      "Periodic Location Updating Interval\n"
      "Periodic Location Updating Interval in Minutes\n")
{
	struct gsm_network *net = vty->index;
	struct osmo_tdef *d = osmo_tdef_get_entry(net->T_defs, 3212);

	OSMO_ASSERT(d);
	d->val = atoi(argv[0]) / 6;
	vty_out(vty, "T%d = %lu %s (%s)%s", d->T, d->val, "* 6min", d->desc, VTY_NEWLINE);
	return CMD_SUCCESS;
}

/* FIXME: changing this value would not affect generated System Information */
DEFUN(cfg_net_no_per_loc_upd, cfg_net_no_per_loc_upd_cmd,
      "no periodic location update",
      NO_STR
      "Periodic Location Updating Interval\n"
      "Periodic Location Updating Interval\n"
      "Periodic Location Updating Interval\n")
{
	struct gsm_network *net = vty->index;
	struct osmo_tdef *d = osmo_tdef_get_entry(net->T_defs, 3212);

	OSMO_ASSERT(d);
	d->val = 0;
	vty_out(vty, "T%d = %lu %s (%s)%s", d->T, d->val, "* 6min", d->desc, VTY_NEWLINE);
	return CMD_SUCCESS;
}

#define MEAS_FEED_STR "Measurement Report export\n"

DEFUN_ATTR(cfg_net_meas_feed_dest, cfg_net_meas_feed_dest_cmd,
	   "meas-feed destination ADDR <0-65535>",
	   MEAS_FEED_STR "Where to forward Measurement Report feeds\n" "address or hostname\n" "port number\n",
	   CMD_ATTR_IMMEDIATE)
{
	int rc;
	const char *host = argv[0];
	uint16_t port = atoi(argv[1]);

	rc = meas_feed_cfg_set(host, port);
	if (rc < 0)
		return CMD_WARNING;

	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_net_meas_feed_scenario, cfg_net_meas_feed_scenario_cmd,
	   "meas-feed scenario NAME",
	   MEAS_FEED_STR "Set a name to include in the Measurement Report feeds\n" "Name string, up to 31 characters\n",
	   CMD_ATTR_IMMEDIATE)
{
	meas_feed_scenario_set(argv[0]);

	return CMD_SUCCESS;
}

static void legacy_timers(struct vty *vty, const char **T_arg)
{
	if (!strcmp((*T_arg), "T993111") || !strcmp((*T_arg), "t993111")) {
		vty_out(vty, "%% Legacy: timer T993111 is now X3111%s", VTY_NEWLINE);
		(*T_arg) = "X3111";
	} else if (!strcmp((*T_arg), "T993210") || !strcmp((*T_arg), "t993210")) {
		vty_out(vty, "%% Legacy: timer T993210 is now X3210%s", VTY_NEWLINE);
		(*T_arg) = "X3210";
	} else if (!strcmp((*T_arg), "T999") || !strcmp((*T_arg), "t999")) {
		vty_out(vty, "%% Legacy: timer T999 is now X4%s", VTY_NEWLINE);
		(*T_arg) = "X4";
	}
}

/* LEGACY TIMER COMMAND. The proper commands are added by osmo_tdef_vty_groups_init(), using explicit timer group
 * naming. The old groupless timer command accesses the 'net' group only, but is still available. */
DEFUN_HIDDEN(show_timer, show_timer_cmd,
      "show timer " OSMO_TDEF_VTY_ARG_T,
      SHOW_STR "Show timers\n"
      OSMO_TDEF_VTY_DOC_T)
{
	struct gsm_network *net = gsmnet_from_vty(vty);
	const char *T_arg = argv[0];
	if (T_arg)
		legacy_timers(vty, &T_arg);
	return osmo_tdef_vty_show_cmd(vty, net->T_defs, T_arg, NULL);
}

/* LEGACY TIMER COMMAND. The proper commands are added by osmo_tdef_vty_groups_init(), using explicit timer group
 * naming. The old groupless timer command accesses the 'net' group only, but is still available. */
DEFUN_HIDDEN(cfg_net_timer, cfg_net_timer_cmd,
      "timer " OSMO_TDEF_VTY_ARG_T " " OSMO_TDEF_VTY_ARG_VAL_OPTIONAL,
      "Configure or show timers\n"
      OSMO_TDEF_VTY_DOC_SET)
{
	struct gsm_network *net = gsmnet_from_vty(vty);
	const char *mod_argv[argc];
	memcpy(mod_argv, argv, sizeof(mod_argv));
	legacy_timers(vty, &mod_argv[0]);
	/* If any arguments are missing, redirect to 'show' */
	if (argc < 2)
		return show_timer(self, vty, argc, mod_argv);
	return osmo_tdef_vty_set_cmd(vty, net->T_defs, mod_argv);
}

DEFUN(cfg_net_allow_unusable_timeslots, cfg_net_allow_unusable_timeslots_cmd,
      "allow-unusable-timeslots",
      "Don't refuse to start with mutually exclusive codec settings\n")
{
	struct gsm_network *net = gsmnet_from_vty(vty);
	net->allow_unusable_timeslots = true;
	LOGP(DMSC, LOGL_ERROR, "Configuration contains 'allow-unusable-timeslots'. OsmoBSC will start up even if the"
			       " configuration has unusable codec settings!\n");
	return CMD_SUCCESS;
}

static struct bsc_msc_data *bsc_msc_data(struct vty *vty)
{
	return vty->index;
}

static struct cmd_node bsc_node = {
	BSC_NODE,
	"%s(config-bsc)# ",
	1,
};

static struct cmd_node msc_node = {
	MSC_NODE,
	"%s(config-msc)# ",
	1,
};

#define MSC_NR_RANGE "<0-1000>"

DEFUN_ATTR(cfg_net_msc,
	   cfg_net_msc_cmd,
	   "msc [" MSC_NR_RANGE "]", "Configure MSC details\n" "MSC connection to configure\n",
	   CMD_ATTR_IMMEDIATE)
{
	int index = argc == 1 ? atoi(argv[0]) : 0;
	struct bsc_msc_data *msc;

	msc = osmo_msc_data_alloc(bsc_gsmnet, index);
	if (!msc) {
		vty_out(vty, "%% Failed to allocate MSC data.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty->index = msc;
	vty->node = MSC_NODE;
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_net_bsc,
	   cfg_net_bsc_cmd,
	   "bsc", "Configure BSC\n",
	   CMD_ATTR_IMMEDIATE)
{
	vty->node = BSC_NODE;
	return CMD_SUCCESS;
}

static void write_msc_amr_options(struct vty *vty, struct bsc_msc_data *msc)
{
#define WRITE_AMR(vty, msc, name, var) \
	vty_out(vty, " amr-config %s %s%s", \
		name, msc->amr_conf.var ? "allowed" : "forbidden", \
		VTY_NEWLINE);

	WRITE_AMR(vty, msc, "12_2k", m12_2);
	WRITE_AMR(vty, msc, "10_2k", m10_2);
	WRITE_AMR(vty, msc, "7_95k", m7_95);
	WRITE_AMR(vty, msc, "7_40k", m7_40);
	WRITE_AMR(vty, msc, "6_70k", m6_70);
	WRITE_AMR(vty, msc, "5_90k", m5_90);
	WRITE_AMR(vty, msc, "5_15k", m5_15);
	WRITE_AMR(vty, msc, "4_75k", m4_75);
#undef WRITE_AMR

	if (msc->amr_octet_aligned)
		vty_out(vty, " amr-payload octet-aligned%s", VTY_NEWLINE);
	else
		vty_out(vty, " amr-payload bandwith-efficient%s", VTY_NEWLINE);
}

static void msc_write_nri(struct vty *vty, struct bsc_msc_data *msc, bool verbose);

static void write_msc(struct vty *vty, struct bsc_msc_data *msc)
{
	vty_out(vty, "msc %d%s", msc->nr, VTY_NEWLINE);
	if (msc->core_plmn.mnc != GSM_MCC_MNC_INVALID)
		vty_out(vty, " core-mobile-network-code %s%s",
			osmo_mnc_name(msc->core_plmn.mnc, msc->core_plmn.mnc_3_digits), VTY_NEWLINE);
	if (msc->core_plmn.mcc != GSM_MCC_MNC_INVALID)
		vty_out(vty, " core-mobile-country-code %s%s",
			osmo_mcc_name(msc->core_plmn.mcc), VTY_NEWLINE);

	if (msc->audio_length != 0) {
		int i;

		vty_out(vty, " codec-list ");
		for (i = 0; i < msc->audio_length; ++i) {
			if (i != 0)
				vty_out(vty, " ");

			if (msc->audio_support[i]->hr)
				vty_out(vty, "hr%.1u", msc->audio_support[i]->ver);
			else
				vty_out(vty, "fr%.1u", msc->audio_support[i]->ver);
		}
		vty_out(vty, "%s", VTY_NEWLINE);

	}

	vty_out(vty, " allow-emergency %s%s", msc->allow_emerg ?
					"allow" : "deny", VTY_NEWLINE);

	/* write amr options */
	write_msc_amr_options(vty, msc);

	/* write sccp connection configuration */
	if (msc->a.bsc_addr_name) {
		vty_out(vty, " bsc-addr %s%s",
			msc->a.bsc_addr_name, VTY_NEWLINE);
	}
	if (msc->a.msc_addr_name) {
		vty_out(vty, " msc-addr %s%s",
			msc->a.msc_addr_name, VTY_NEWLINE);
	}
	vty_out(vty, " asp-protocol %s%s", osmo_ss7_asp_protocol_name(msc->a.asp_proto), VTY_NEWLINE);
	vty_out(vty, " lcls-mode %s%s", get_value_string(bsc_lcls_mode_names, msc->lcls_mode),
		VTY_NEWLINE);

	if (msc->lcls_codec_mismatch_allow)
		vty_out(vty, " lcls-codec-mismatch allowed%s", VTY_NEWLINE);
	else
		vty_out(vty, " lcls-codec-mismatch forbidden%s", VTY_NEWLINE);

	/* write MGW configuration */
	mgcp_client_config_write(vty, " ");

	if (msc->x_osmo_ign_configured) {
		if (!msc->x_osmo_ign)
			vty_out(vty, " no mgw x-osmo-ign%s", VTY_NEWLINE);
		else
			vty_out(vty, " mgw x-osmo-ign call-id%s", VTY_NEWLINE);
	}

	if (msc->use_osmux != OSMUX_USAGE_OFF) {
		vty_out(vty, " osmux %s%s", msc->use_osmux == OSMUX_USAGE_ON ? "on" : "only",
			VTY_NEWLINE);
	}

	msc_write_nri(vty, msc, false);

	if (!msc->allow_attach)
		vty_out(vty, " no allow-attach%s", VTY_NEWLINE);
}

static int config_write_msc(struct vty *vty)
{
	struct bsc_msc_data *msc;

	llist_for_each_entry(msc, &bsc_gsmnet->mscs, entry)
		write_msc(vty, msc);

	return CMD_SUCCESS;
}

static int config_write_bsc(struct vty *vty)
{
	vty_out(vty, "bsc%s", VTY_NEWLINE);
	vty_out(vty, " mid-call-timeout %d%s", bsc_gsmnet->mid_call_timeout, VTY_NEWLINE);
	if (bsc_gsmnet->rf_ctrl_name)
		vty_out(vty, " bsc-rf-socket %s%s",
			bsc_gsmnet->rf_ctrl_name, VTY_NEWLINE);

	if (bsc_gsmnet->auto_off_timeout != -1)
		vty_out(vty, " bsc-auto-rf-off %d%s",
			bsc_gsmnet->auto_off_timeout, VTY_NEWLINE);

	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_net_bsc_ncc,
	   cfg_net_bsc_ncc_cmd,
	   "core-mobile-network-code <1-999>",
	   "Use this network code for the core network\n" "MNC value\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct bsc_msc_data *data = bsc_msc_data(vty);
	uint16_t mnc;
	bool mnc_3_digits;

	if (osmo_mnc_from_str(argv[0], &mnc, &mnc_3_digits)) {
		vty_out(vty, "%% Error decoding MNC: %s%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}
	data->core_plmn.mnc = mnc;
	data->core_plmn.mnc_3_digits = mnc_3_digits;
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_net_bsc_mcc,
	   cfg_net_bsc_mcc_cmd,
	   "core-mobile-country-code <1-999>",
	   "Use this country code for the core network\n" "MCC value\n",
	   CMD_ATTR_IMMEDIATE)
{
	uint16_t mcc;
	struct bsc_msc_data *data = bsc_msc_data(vty);
	if (osmo_mcc_from_str(argv[0], &mcc)) {
		vty_out(vty, "%% Error decoding MCC: %s%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}
	data->core_plmn.mcc = mcc;
	return CMD_SUCCESS;
}

DEFUN_DEPRECATED(cfg_net_bsc_lac,
		 cfg_net_bsc_lac_cmd,
		 "core-location-area-code <0-65535>",
		 "Legacy configuration that no longer has any effect\n-\n")
{
	vty_out(vty, "%% Deprecated 'core-location-area-code' config no longer has any effect%s", VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN_DEPRECATED(cfg_net_bsc_ci,
		 cfg_net_bsc_ci_cmd,
		 "core-cell-identity <0-65535>",
		 "Legacy configuration that no longer has any effect\n-\n")
{
	vty_out(vty, "%% Deprecated 'core-cell-identity' config no longer has any effect%s", VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN_DEPRECATED(cfg_net_bsc_rtp_base,
      cfg_net_bsc_rtp_base_cmd,
      "ip.access rtp-base <1-65000>",
      "deprecated\n" "deprecated, RTP is handled by the MGW\n" "deprecated\n")
{
	vty_out(vty, "%% deprecated: 'ip.access rtp-base' has no effect, RTP is handled by the MGW%s", VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_net_bsc_codec_list,
	      cfg_net_bsc_codec_list_cmd,
	      BSC_VTY_ATTR_NEW_LCHAN,
	      "codec-list .LIST",
	      "Set the allowed audio codecs\n"
	      "List of audio codecs, e.g. fr3 fr1 hr3\n")
{
	struct bsc_msc_data *data = bsc_msc_data(vty);
	int i;

	/* check all given arguments first */
	for (i = 0; i < argc; ++i) {
		/* check for hrX or frX */
		if (strlen(argv[i]) != 3
				|| argv[i][1] != 'r'
				|| (argv[i][0] != 'h' && argv[i][0] != 'f')
				|| argv[i][2] < 0x30
				|| argv[i][2] > 0x39)
			goto error;
	}

	/* free the old list... if it exists */
	if (data->audio_support) {
		talloc_free(data->audio_support);
		data->audio_support = NULL;
		data->audio_length = 0;
	}

	/* create a new array */
	data->audio_support =
		talloc_zero_array(bsc_gsmnet, struct gsm_audio_support *, argc);
	data->audio_length = argc;

	for (i = 0; i < argc; ++i) {
		data->audio_support[i] = talloc_zero(data->audio_support,
				struct gsm_audio_support);
		data->audio_support[i]->ver = atoi(argv[i] + 2);

		if (strncmp("hr", argv[i], 2) == 0)
			data->audio_support[i]->hr = 1;
		else if (strncmp("fr", argv[i], 2) == 0)
			data->audio_support[i]->hr = 0;
	}

	return CMD_SUCCESS;

error:
	vty_out(vty, "Codec name must be hrX or frX. Was '%s'%s",
			argv[i], VTY_NEWLINE);
	return CMD_ERR_INCOMPLETE;
}

#define LEGACY_STR "This command has no effect, it is kept to support legacy config files\n"

DEFUN_DEPRECATED(deprecated_ussd_text,
      cfg_net_msc_welcome_ussd_cmd,
      "bsc-welcome-text .TEXT", LEGACY_STR LEGACY_STR)
{
	vty_out(vty, "%% osmo-bsc no longer supports USSD notification. These commands have no effect:%s"
		"%%   bsc-welcome-text, bsc-msc-lost-text, mid-call-text, bsc-grace-text, missing-msc-text%s",
		VTY_NEWLINE, VTY_NEWLINE);
	return CMD_WARNING;
}

DEFUN_DEPRECATED(deprecated_no_ussd_text,
      cfg_net_msc_no_welcome_ussd_cmd,
      "no bsc-welcome-text",
      NO_STR LEGACY_STR)
{
	return CMD_SUCCESS;
}

ALIAS_DEPRECATED(deprecated_ussd_text,
      cfg_net_msc_lost_ussd_cmd,
      "bsc-msc-lost-text .TEXT", LEGACY_STR LEGACY_STR);

ALIAS_DEPRECATED(deprecated_no_ussd_text,
      cfg_net_msc_no_lost_ussd_cmd,
      "no bsc-msc-lost-text", NO_STR LEGACY_STR);

ALIAS_DEPRECATED(deprecated_ussd_text,
      cfg_net_msc_grace_ussd_cmd,
      "bsc-grace-text .TEXT", LEGACY_STR LEGACY_STR);

ALIAS_DEPRECATED(deprecated_no_ussd_text,
      cfg_net_msc_no_grace_ussd_cmd,
      "no bsc-grace-text", NO_STR LEGACY_STR);

ALIAS_DEPRECATED(deprecated_ussd_text,
      cfg_net_bsc_missing_msc_ussd_cmd,
      "missing-msc-text .TEXT", LEGACY_STR LEGACY_STR);

ALIAS_DEPRECATED(deprecated_no_ussd_text,
      cfg_net_bsc_no_missing_msc_text_cmd,
      "no missing-msc-text", NO_STR LEGACY_STR);

DEFUN_DEPRECATED(cfg_net_msc_type,
      cfg_net_msc_type_cmd,
      "type (normal|local)",
      LEGACY_STR LEGACY_STR)
{
	vty_out(vty, "%% 'msc' / 'type' config is deprecated and no longer has any effect%s",
		VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_net_msc_emerg,
	   cfg_net_msc_emerg_cmd,
	   "allow-emergency (allow|deny)",
	   "Allow CM ServiceRequests with type emergency\n"
	   "Allow\n" "Deny\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct bsc_msc_data *data = bsc_msc_data(vty);
	data->allow_emerg = strcmp("allow", argv[0]) == 0;
	return CMD_SUCCESS;
}

#define AMR_CONF_STR "AMR Multirate Configuration\n"
#define AMR_COMMAND(name) \
	DEFUN_USRATTR(cfg_net_msc_amr_##name,				\
	  cfg_net_msc_amr_##name##_cmd,BSC_VTY_ATTR_NEW_LCHAN, 		\
	  "amr-config " #name "k (allowed|forbidden)",			\
	  AMR_CONF_STR "Bitrate\n" "Allowed\n" "Forbidden\n")		\
{									\
	struct bsc_msc_data *msc = bsc_msc_data(vty);			\
									\
	msc->amr_conf.m##name = strcmp(argv[0], "allowed") == 0;	\
	return CMD_SUCCESS;						\
}

AMR_COMMAND(12_2)
AMR_COMMAND(10_2)
AMR_COMMAND(7_95)
AMR_COMMAND(7_40)
AMR_COMMAND(6_70)
AMR_COMMAND(5_90)
AMR_COMMAND(5_15)
AMR_COMMAND(4_75)

/* Make sure only standard SSN numbers are used. If no ssn number is
 * configured, silently apply the default SSN */
static void enforce_standard_ssn(struct vty *vty, struct osmo_sccp_addr *addr)
{
	if (addr->presence & OSMO_SCCP_ADDR_T_SSN) {
		if (addr->ssn != OSMO_SCCP_SSN_BSSAP)
			vty_out(vty,
				"setting an SSN (%u) different from the standard (%u) is not allowed, will use standard SSN for address: %s%s",
				addr->ssn, OSMO_SCCP_SSN_BSSAP, osmo_sccp_addr_dump(addr), VTY_NEWLINE);
	}

	addr->presence |= OSMO_SCCP_ADDR_T_SSN;
	addr->ssn = OSMO_SCCP_SSN_BSSAP;
}

DEFUN(cfg_msc_cs7_bsc_addr,
      cfg_msc_cs7_bsc_addr_cmd,
      "bsc-addr NAME",
      "Calling Address (local address of this BSC)\n" "SCCP address name\n")
{
	struct bsc_msc_data *msc = bsc_msc_data(vty);
	const char *bsc_addr_name = argv[0];
	struct osmo_ss7_instance *ss7;

	ss7 = osmo_sccp_addr_by_name(&msc->a.bsc_addr, bsc_addr_name);
	if (!ss7) {
		vty_out(vty, "Error: No such SCCP addressbook entry: '%s'%s", bsc_addr_name, VTY_NEWLINE);
		return CMD_ERR_INCOMPLETE;
	}

	/* Prevent mixing addresses from different CS7/SS7 instances */
	if (msc->a.cs7_instance_valid) {
		if (msc->a.cs7_instance != ss7->cfg.id) {
			vty_out(vty,
				"Error: SCCP addressbook entry from mismatching CS7 instance: '%s'%s",
				bsc_addr_name, VTY_NEWLINE);
			return CMD_ERR_INCOMPLETE;
		}
	}

	msc->a.cs7_instance = ss7->cfg.id;
	msc->a.cs7_instance_valid = true;
	enforce_standard_ssn(vty, &msc->a.bsc_addr);
	msc->a.bsc_addr_name = talloc_strdup(msc, bsc_addr_name);
	return CMD_SUCCESS;
}

DEFUN(cfg_msc_cs7_msc_addr,
      cfg_msc_cs7_msc_addr_cmd,
      "msc-addr NAME",
      "Called Address (remote address of the MSC)\n" "SCCP address name\n")
{
	struct bsc_msc_data *msc = bsc_msc_data(vty);
	const char *msc_addr_name = argv[0];
	struct osmo_ss7_instance *ss7;

	ss7 = osmo_sccp_addr_by_name(&msc->a.msc_addr, msc_addr_name);
	if (!ss7) {
		vty_out(vty, "Error: No such SCCP addressbook entry: '%s'%s", msc_addr_name, VTY_NEWLINE);
		return CMD_ERR_INCOMPLETE;
	}

	/* Prevent mixing addresses from different CS7/SS7 instances */
	if (msc->a.cs7_instance_valid) {
		if (msc->a.cs7_instance != ss7->cfg.id) {
			vty_out(vty,
				"Error: SCCP addressbook entry from mismatching CS7 instance: '%s'%s",
				msc_addr_name, VTY_NEWLINE);
			return CMD_ERR_INCOMPLETE;
		}
	}

	msc->a.cs7_instance = ss7->cfg.id;
	msc->a.cs7_instance_valid = true;
	enforce_standard_ssn(vty, &msc->a.msc_addr);
	msc->a.msc_addr_name = talloc_strdup(msc, msc_addr_name);
	return CMD_SUCCESS;
}

DEFUN(cfg_msc_cs7_asp_proto,
      cfg_msc_cs7_asp_proto_cmd,
      "asp-protocol (m3ua|sua|ipa)",
      "A interface protocol to use for this MSC)\n"
      "MTP3 User Adaptation\n"
      "SCCP User Adaptation\n"
      "IPA Multiplex (SCCP Lite)\n")
{
	struct bsc_msc_data *msc = bsc_msc_data(vty);

	msc->a.asp_proto = get_string_value(osmo_ss7_asp_protocol_vals, argv[0]);
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_net_msc_lcls_mode,
	      cfg_net_msc_lcls_mode_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "lcls-mode (disabled|mgw-loop|bts-loop)",
	      "Configure 3GPP LCLS (Local Call, Local Switch)\n"
	      "Disable LCLS for all calls of this MSC\n"
	      "Enable LCLS with looping traffic in MGW\n"
	      "Enable LCLS with looping traffic between BTS\n")
{
	struct bsc_msc_data *data = bsc_msc_data(vty);
	data->lcls_mode = get_string_value(bsc_lcls_mode_names, argv[0]);
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_net_msc_lcls_mismtch,
	      cfg_net_msc_lcls_mismtch_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "lcls-codec-mismatch (allowed|forbidden)",
	      "Allow 3GPP LCLS (Local Call, Local Switch) when call legs use different codec/rate\n"
	      "Allow LCLS only only for calls that use the same codec/rate on both legs\n"
	      "Do not Allow LCLS for calls that use a different codec/rate on both legs\n")
{
	struct bsc_msc_data *data = bsc_msc_data(vty);

	if (strcmp(argv[0], "allowed") == 0)
		data->lcls_codec_mismatch_allow = true;
	else
		data->lcls_codec_mismatch_allow = false;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_msc_mgw_x_osmo_ign,
	      cfg_msc_mgw_x_osmo_ign_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "mgw x-osmo-ign call-id",
	      MGCP_CLIENT_MGW_STR
	      "Set a (non-standard) X-Osmo-IGN header in all CRCX messages for RTP streams"
	      " associated with this MSC, useful for A/SCCPlite MSCs, since osmo-bsc cannot know"
	      " the MSC's chosen CallID. This is enabled by default for A/SCCPlite connections,"
	      " disabled by default for all others.\n"
	      "Send 'X-Osmo-IGN: C' to ignore CallID mismatches. See OsmoMGW.\n")
{
	struct bsc_msc_data *msc = bsc_msc_data(vty);
	msc->x_osmo_ign |= MGCP_X_OSMO_IGN_CALLID;
	msc->x_osmo_ign_configured = true;
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_msc_no_mgw_x_osmo_ign,
	      cfg_msc_no_mgw_x_osmo_ign_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "no mgw x-osmo-ign",
	      NO_STR
	      MGCP_CLIENT_MGW_STR
	      "Do not send X-Osmo-IGN MGCP header to this MSC\n")
{
	struct bsc_msc_data *msc = bsc_msc_data(vty);
	msc->x_osmo_ign = 0;
	msc->x_osmo_ign_configured = true;
	return CMD_SUCCESS;
}

#define OSMUX_STR "RTP multiplexing\n"
DEFUN_USRATTR(cfg_msc_osmux,
	      cfg_msc_osmux_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "osmux (on|off|only)",
	      OSMUX_STR "Enable OSMUX\n" "Disable OSMUX\n" "Only use OSMUX\n")
{
	struct bsc_msc_data *msc = bsc_msc_data(vty);
	if (strcmp(argv[0], "off") == 0)
		msc->use_osmux = OSMUX_USAGE_OFF;
	else if (strcmp(argv[0], "on") == 0)
		msc->use_osmux = OSMUX_USAGE_ON;
	else if (strcmp(argv[0], "only") == 0)
		msc->use_osmux = OSMUX_USAGE_ONLY;

	return CMD_SUCCESS;
}

ALIAS_DEPRECATED(deprecated_ussd_text,
      cfg_net_bsc_mid_call_text_cmd,
      "mid-call-text .TEXT",
      LEGACY_STR LEGACY_STR);

DEFUN_ATTR(cfg_net_bsc_mid_call_timeout,
	   cfg_net_bsc_mid_call_timeout_cmd,
	   "mid-call-timeout NR",
	   "Switch from Grace to Off in NR seconds.\n" "Timeout in seconds\n",
	   CMD_ATTR_IMMEDIATE)
{
	bsc_gsmnet->mid_call_timeout = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_rf_socket,
      cfg_net_rf_socket_cmd,
      "bsc-rf-socket PATH",
      "Set the filename for the RF control interface.\n" "RF Control path\n")
{
	osmo_talloc_replace_string(bsc_gsmnet, &bsc_gsmnet->rf_ctrl_name, argv[0]);
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_net_rf_off_time,
	   cfg_net_rf_off_time_cmd,
	   "bsc-auto-rf-off <1-65000>",
	   "Disable RF on MSC Connection\n" "Timeout\n",
	   CMD_ATTR_IMMEDIATE)
{
	bsc_gsmnet->auto_off_timeout = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_net_no_rf_off_time,
	   cfg_net_no_rf_off_time_cmd,
	   "no bsc-auto-rf-off",
	   NO_STR "Disable RF on MSC Connection\n",
	   CMD_ATTR_IMMEDIATE)
{
	bsc_gsmnet->auto_off_timeout = -1;
	return CMD_SUCCESS;
}

DEFUN(show_statistics,
      show_statistics_cmd,
      "show statistics",
      SHOW_STR "Statistics about the BSC\n")
{
	openbsc_vty_print_statistics(vty, bsc_gsmnet);
	return CMD_SUCCESS;
}

DEFUN(show_mscs,
      show_mscs_cmd,
      "show mscs",
      SHOW_STR "MSC Connections and State\n")
{
	struct bsc_msc_data *msc;
	llist_for_each_entry(msc, &bsc_gsmnet->mscs, entry) {
		vty_out(vty, "%d %s %s ",
			msc->a.cs7_instance,
			osmo_ss7_asp_protocol_name(msc->a.asp_proto),
			osmo_sccp_inst_addr_name(msc->a.sccp, &msc->a.bsc_addr));
		vty_out(vty, "%s%s",
			osmo_sccp_inst_addr_name(msc->a.sccp, &msc->a.msc_addr),
			VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}

DEFUN(show_pos,
      show_pos_cmd,
      "show position",
      SHOW_STR "Position information of the BTS\n")
{
	struct gsm_bts *bts;
	struct bts_location *curloc;
	struct tm time;
	char timestr[50];

	llist_for_each_entry(bts, &bsc_gsmnet->bts_list, list) {
		if (llist_empty(&bts->loc_list)) {
			vty_out(vty, "BTS Nr: %d position invalid%s", bts->nr,
				VTY_NEWLINE);
			continue;
		}
		curloc = llist_entry(bts->loc_list.next, struct bts_location, list);
		if (gmtime_r(&curloc->tstamp, &time) == NULL) {
			vty_out(vty, "Time conversion failed for BTS %d%s", bts->nr,
				VTY_NEWLINE);
			continue;
		}
		if (asctime_r(&time, timestr) == NULL) {
			vty_out(vty, "Time conversion failed for BTS %d%s", bts->nr,
				VTY_NEWLINE);
			continue;
		}
		/* Last character in asctime is \n */
		timestr[strlen(timestr)-1] = 0;

		vty_out(vty, "BTS Nr: %d position: %s time: %s%s", bts->nr,
			get_value_string(bts_loc_fix_names, curloc->valid), timestr,
			VTY_NEWLINE);
		vty_out(vty, " lat: %f lon: %f height: %f%s", curloc->lat, curloc->lon,
			curloc->height, VTY_NEWLINE);
	}
	return CMD_SUCCESS;
}

DEFUN(gen_position_trap,
      gen_position_trap_cmd,
      "generate-location-state-trap <0-255>",
      "Generate location state report\n"
      "BTS to report\n")
{
	int bts_nr;
	struct gsm_bts *bts;
	struct gsm_network *net = bsc_gsmnet;

	bts_nr = atoi(argv[0]);
	if (bts_nr >= net->num_bts) {
		vty_out(vty, "%% can't find BTS '%s'%s", argv[0],
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts = gsm_bts_num(net, bts_nr);
	bsc_gen_location_state_trap(bts);
	return CMD_SUCCESS;
}

DEFUN(logging_fltr_imsi,
      logging_fltr_imsi_cmd,
      "logging filter imsi IMSI",
	LOGGING_STR FILTER_STR
      "Filter log messages by IMSI\n" "IMSI to be used as filter\n")
{
	struct bsc_subscr *bsc_subscr;
	struct log_target *tgt = osmo_log_vty2tgt(vty);
	const char *imsi = argv[0];

	if (!tgt)
		return CMD_WARNING;

	bsc_subscr = bsc_subscr_find_or_create_by_imsi(bsc_gsmnet->bsc_subscribers, imsi, __func__);

	if (!bsc_subscr) {
		vty_out(vty, "%% failed to enable logging for subscriber with IMSI(%s)%s",
			imsi, VTY_NEWLINE);
		return CMD_WARNING;
	}

	log_set_filter_bsc_subscr(tgt, bsc_subscr);
	/* log_set_filter has grabbed its own reference  */
	bsc_subscr_put(bsc_subscr, __func__);

	return CMD_SUCCESS;
}

static void dump_one_sub(struct vty *vty, struct bsc_subscr *bsub)
{
	vty_out(vty, " %15s  %08x  %s%s", bsub->imsi, bsub->tmsi, osmo_use_count_to_str_c(OTC_SELECT, &bsub->use_count),
		VTY_NEWLINE);
}

DEFUN(show_subscr_all,
	show_subscr_all_cmd,
	"show subscriber all",
	SHOW_STR "Display information about subscribers\n" "All Subscribers\n")
{
	struct bsc_subscr *bsc_subscr;

	vty_out(vty, " IMSI             TMSI      Use%s", VTY_NEWLINE);
	/*           " 001010123456789  ffffffff  1" */

	llist_for_each_entry(bsc_subscr, bsc_gsmnet->bsc_subscribers, entry)
		dump_one_sub(vty, bsc_subscr);

	return CMD_SUCCESS;
}

DEFUN_DEPRECATED(cfg_net_msc_ping_time, cfg_net_msc_ping_time_cmd,
      "timeout-ping ARG", LEGACY_STR "-\n")
{
	vty_out(vty, "%% timeout-ping / timeout-pong config is deprecated and has no effect%s",
		VTY_NEWLINE);
	return CMD_WARNING;
}

ALIAS_DEPRECATED(cfg_net_msc_ping_time, cfg_net_msc_no_ping_time_cmd,
      "no timeout-ping [ARG]", NO_STR LEGACY_STR "-\n");

ALIAS_DEPRECATED(cfg_net_msc_ping_time, cfg_net_msc_pong_time_cmd,
      "timeout-pong ARG", LEGACY_STR "-\n");

DEFUN_DEPRECATED(cfg_net_msc_dest, cfg_net_msc_dest_cmd,
      "dest A.B.C.D <1-65000> <0-255>", LEGACY_STR "-\n" "-\n" "-\n")
{
	vty_out(vty, "%% dest config is deprecated and has no effect%s", VTY_NEWLINE);
	return CMD_WARNING;
}

ALIAS_DEPRECATED(cfg_net_msc_dest, cfg_net_msc_no_dest_cmd,
      "no dest A.B.C.D <1-65000> <0-255>", NO_STR LEGACY_STR "-\n" "-\n" "-\n");

DEFUN_USRATTR(cfg_net_msc_amr_octet_align,
	      cfg_net_msc_amr_octet_align_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "amr-payload (octet-aligned|bandwith-efficient",
	      "Set AMR payload framing mode\n"
	      "payload fields aligned on octet boundaries\n"
	      "payload fields packed (AoIP)\n")
{
	struct bsc_msc_data *data = bsc_msc_data(vty);

	if (strcmp(argv[0], "octet-aligned") == 0)
		data->amr_octet_aligned = true;
	else if (strcmp(argv[0], "bandwith-efficient") == 0)
		data->amr_octet_aligned = false;

	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_msc_nri_add, cfg_msc_nri_add_cmd,
	   "nri add <0-32767> [<0-32767>]",
	   NRI_STR "Add NRI value or range to the NRI mapping for this MSC\n"
	   NRI_FIRST_LAST_STR,
	   CMD_ATTR_IMMEDIATE)
{
	struct bsc_msc_data *msc = bsc_msc_data(vty);
	struct bsc_msc_data *other_msc;
	bool before;
	int rc;
	const char *message;
	struct osmo_nri_range add_range;

	rc = osmo_nri_ranges_vty_add(&message, &add_range, msc->nri_ranges, argc, argv, bsc_gsmnet->nri_bitlen);
	if (message) {
		NRI_WARN(msc, "%s: " NRI_ARGS_TO_STR_FMT, message, NRI_ARGS_TO_STR_ARGS(argc, argv));
	}
	if (rc < 0)
		return CMD_WARNING;

	/* Issue a warning about NRI range overlaps (but still allow them).
	 * Overlapping ranges will map to whichever MSC comes fist in the bsc_gsmnet->mscs llist,
	 * which is not necessarily in the order of increasing msc->nr. */
	before = true;
	llist_for_each_entry(other_msc, &bsc_gsmnet->mscs, entry) {
		if (other_msc == msc) {
			before = false;
			continue;
		}
		if (osmo_nri_range_overlaps_ranges(&add_range, other_msc->nri_ranges)) {
			NRI_WARN(msc, "NRI range [%d..%d] overlaps between msc %d and msc %d."
				 " For overlaps, msc %d has higher priority than msc %d",
				 add_range.first, add_range.last, msc->nr, other_msc->nr,
				 before ? other_msc->nr : msc->nr, before ? msc->nr : other_msc->nr);
		}
	}
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_msc_nri_del, cfg_msc_nri_del_cmd,
	   "nri del <0-32767> [<0-32767>]",
	   NRI_STR "Remove NRI value or range from the NRI mapping for this MSC\n"
	   NRI_FIRST_LAST_STR,
	   CMD_ATTR_IMMEDIATE)
{
	struct bsc_msc_data *msc = bsc_msc_data(vty);
	int rc;
	const char *message;

	rc = osmo_nri_ranges_vty_del(&message, NULL, msc->nri_ranges, argc, argv);
	if (message) {
		NRI_WARN(msc, "%s: " NRI_ARGS_TO_STR_FMT, message, NRI_ARGS_TO_STR_ARGS(argc, argv));
	}
	if (rc < 0)
		return CMD_WARNING;
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_msc_allow_attach, cfg_msc_allow_attach_cmd,
	   "allow-attach",
	   "Allow this MSC to attach new subscribers (default).\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct bsc_msc_data *msc = bsc_msc_data(vty);
	msc->allow_attach = true;
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_msc_no_allow_attach, cfg_msc_no_allow_attach_cmd,
	   "no allow-attach",
	   NO_STR
	   "Do not assign new subscribers to this MSC."
	   " Useful if an MSC in an MSC pool is configured to off-load subscribers."
	   " The MSC will still be operational for already IMSI-Attached subscribers,"
	   " but the NAS node selection function will skip this MSC for new subscribers\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct bsc_msc_data *msc = bsc_msc_data(vty);
	msc->allow_attach = false;
	return CMD_SUCCESS;
}

static void msc_write_nri(struct vty *vty, struct bsc_msc_data *msc, bool verbose)
{
	struct osmo_nri_range *r;

	if (verbose) {
		vty_out(vty, "msc %d%s", msc->nr, VTY_NEWLINE);
		if (llist_empty(&msc->nri_ranges->entries)) {
			vty_out(vty, " %% no NRI mappings%s", VTY_NEWLINE);
			return;
		}
	}

	llist_for_each_entry(r, &msc->nri_ranges->entries, entry) {
		if (osmo_nri_range_validate(r, 255))
			vty_out(vty, " %% INVALID RANGE:");
		vty_out(vty, " nri add %d", r->first);
		if (r->first != r->last)
			vty_out(vty, " %d", r->last);
		vty_out(vty, "%s", VTY_NEWLINE);
	}
}

DEFUN(cfg_msc_show_nri, cfg_msc_show_nri_cmd,
      "show nri",
      SHOW_STR NRI_STR)
{
	struct bsc_msc_data *msc = bsc_msc_data(vty);
	msc_write_nri(vty, msc, true);
	return CMD_SUCCESS;
}

DEFUN(show_nri, show_nri_cmd,
      "show nri [" MSC_NR_RANGE "]",
      SHOW_STR NRI_STR "Optional MSC number to limit to\n")
{
	struct bsc_msc_data *msc;
	if (argc > 0) {
		int msc_nr = atoi(argv[0]);
		msc = osmo_msc_data_find(bsc_gsmnet, msc_nr);
		if (!msc) {
			vty_out(vty, "%% No such MSC%s", VTY_NEWLINE);
			return CMD_SUCCESS;
		}
		msc_write_nri(vty, msc, true);
		return CMD_SUCCESS;
	}

	llist_for_each_entry(msc, &bsc_gsmnet->mscs, entry) {
		msc_write_nri(vty, msc, true);
	}
	return CMD_SUCCESS;
}

/* Hidden since it exists only for use by ttcn3 tests */
DEFUN_HIDDEN(mscpool_roundrobin_next, mscpool_roundrobin_next_cmd,
	     "mscpool roundrobin next " MSC_NR_RANGE,
	     "MSC pooling: load balancing across multiple MSCs.\n"
	     "Adjust current state of the MSC round-robin algorithm (for testing).\n"
	     "Set the MSC nr to direct the next new subscriber to (for testing).\n"
	     "MSC number, as in the config file; if the number does not exist,"
	     " the round-robin continues to the next valid number.\n")
{
	bsc_gsmnet->mscs_round_robin_next_nr = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(msc_bssmap_reset, msc_bssmap_reset_cmd,
      "msc " MSC_NR_RANGE " bssmap reset",
      "Query or manipulate a specific A-interface link\n"
      "MSC nr\n"
      "Query or manipulate BSSMAP layer of A-interface\n"
      "Flip this MSC to disconnected state and re-send BSSMAP RESET\n")
{
	int msc_nr = atoi(argv[0]);
	struct bsc_msc_data *msc;

	msc = osmo_msc_data_find(bsc_gsmnet, msc_nr);

	if (!msc) {
		vty_out(vty, "%% No such MSC: nr %d\n", msc_nr);
		return CMD_WARNING;
	}

	LOGP(DMSC, LOGL_NOTICE, "(msc%d) VTY requests BSSMAP RESET\n", msc_nr);
	bssmap_reset_resend_reset(msc->a.bssmap_reset);
	return CMD_SUCCESS;
}

int bsc_vty_init(struct gsm_network *network)
{
	OSMO_ASSERT(vty_global_gsm_network == NULL);
	vty_global_gsm_network = network;

	osmo_stats_vty_add_cmds();

	install_element(CONFIG_NODE, &cfg_net_cmd);
	install_node(&net_node, config_write_net);
	install_element(GSMNET_NODE, &cfg_net_ncc_cmd);
	install_element(GSMNET_NODE, &cfg_net_mnc_cmd);
	install_element(GSMNET_NODE, &cfg_net_encryption_cmd);
	install_element(GSMNET_NODE, &cfg_net_timezone_cmd);
	install_element(GSMNET_NODE, &cfg_net_timezone_dst_cmd);
	install_element(GSMNET_NODE, &cfg_net_no_timezone_cmd);
	install_element(GSMNET_NODE, &cfg_net_per_loc_upd_cmd);
	install_element(GSMNET_NODE, &cfg_net_no_per_loc_upd_cmd);
	install_element(GSMNET_NODE, &cfg_net_dyn_ts_allow_tch_f_cmd);
	install_element(GSMNET_NODE, &cfg_net_meas_feed_dest_cmd);
	install_element(GSMNET_NODE, &cfg_net_meas_feed_scenario_cmd);
	install_element(GSMNET_NODE, &cfg_net_timer_cmd);
	install_element(GSMNET_NODE, &cfg_net_allow_unusable_timeslots_cmd);

	/* Timer configuration commands (generic osmo_tdef API) */
	osmo_tdef_vty_groups_init(GSMNET_NODE, bsc_tdef_group);

	install_element_ve(&bsc_show_net_cmd);
	install_element_ve(&show_bts_cmd);
	install_element_ve(&show_bts_fail_rep_cmd);
	install_element_ve(&show_rejected_bts_cmd);
	install_element_ve(&show_trx_cmd);
	install_element_ve(&show_trx_con_cmd);
	install_element_ve(&show_ts_cmd);
	install_element_ve(&show_lchan_cmd);
	install_element_ve(&show_lchan_summary_cmd);
	install_element_ve(&show_lchan_summary_all_cmd);
	install_element_ve(&show_timer_cmd);

	install_element_ve(&show_subscr_conn_cmd);

	install_element_ve(&show_paging_cmd);
	install_element_ve(&show_paging_group_cmd);

	install_element(ENABLE_NODE, &handover_any_cmd);
	install_element(ENABLE_NODE, &assignment_any_cmd);
	install_element(ENABLE_NODE, &handover_any_to_arfcn_bsic_cmd);
	/* See also handover commands added on net level from handover_vty.c */

	logging_vty_add_cmds();
	osmo_talloc_vty_add_cmds();

	install_element(GSMNET_NODE, &cfg_net_neci_cmd);
	install_element(GSMNET_NODE, &cfg_net_dtx_cmd);
	install_element(GSMNET_NODE, &cfg_net_pag_any_tch_cmd);
	install_element(GSMNET_NODE, &cfg_net_nri_bitlen_cmd);
	install_element(GSMNET_NODE, &cfg_net_nri_null_add_cmd);
	install_element(GSMNET_NODE, &cfg_net_nri_null_del_cmd);

	bts_vty_init();
        mgcp_client_pool_vty_init(GSMNET_NODE, MGW_NODE, " ", vty_global_gsm_network->mgw.mgw_pool);

	install_element(ENABLE_NODE, &drop_bts_cmd);
	install_element(ENABLE_NODE, &restart_bts_cmd);
	install_element(ENABLE_NODE, &bts_resend_sysinfo_cmd);
	install_element(ENABLE_NODE, &bts_resend_power_ctrl_params_cmd);
	install_element(ENABLE_NODE, &bts_c0_power_red_cmd);
	install_element(ENABLE_NODE, &pdch_act_cmd);
	install_element(ENABLE_NODE, &lchan_act_cmd);
	install_element(ENABLE_NODE, &lchan_deact_cmd);
	install_element(ENABLE_NODE, &lchan_act_all_cmd);
	install_element(ENABLE_NODE, &lchan_act_all_bts_cmd);
	install_element(ENABLE_NODE, &lchan_act_all_trx_cmd);
	install_element(ENABLE_NODE, &vamos_modify_lchan_cmd);
	install_element(ENABLE_NODE, &lchan_mdcx_cmd);
	install_element(ENABLE_NODE, &lchan_set_borken_cmd);
	install_element(ENABLE_NODE, &lchan_reassign_cmd);
	install_element(ENABLE_NODE, &lchan_set_mspower_cmd);

	install_element(ENABLE_NODE, &handover_subscr_conn_cmd);
	install_element(ENABLE_NODE, &assignment_subscr_conn_cmd);
	install_element(ENABLE_NODE, &smscb_cmd_cmd);
	install_element(ENABLE_NODE, &ctrl_trap_cmd);

	abis_nm_vty_init();
	abis_om2k_vty_init();
	e1inp_vty_init();
	osmo_fsm_vty_add_cmds();

	ho_vty_init();
	cbc_vty_init();
	smscb_vty_init();

	install_element(CONFIG_NODE, &cfg_net_msc_cmd);
	install_element(CONFIG_NODE, &cfg_net_bsc_cmd);

	install_node(&bsc_node, config_write_bsc);
	install_element(BSC_NODE, &cfg_net_bsc_mid_call_text_cmd);
	install_element(BSC_NODE, &cfg_net_bsc_mid_call_timeout_cmd);
	install_element(BSC_NODE, &cfg_net_rf_socket_cmd);
	install_element(BSC_NODE, &cfg_net_rf_off_time_cmd);
	install_element(BSC_NODE, &cfg_net_no_rf_off_time_cmd);
	install_element(BSC_NODE, &cfg_net_bsc_missing_msc_ussd_cmd);
	install_element(BSC_NODE, &cfg_net_bsc_no_missing_msc_text_cmd);

	install_node(&msc_node, config_write_msc);
	install_element(MSC_NODE, &cfg_net_bsc_ncc_cmd);
	install_element(MSC_NODE, &cfg_net_bsc_mcc_cmd);
	install_element(MSC_NODE, &cfg_net_bsc_lac_cmd);
	install_element(MSC_NODE, &cfg_net_bsc_ci_cmd);
	install_element(MSC_NODE, &cfg_net_bsc_rtp_base_cmd);
	install_element(MSC_NODE, &cfg_net_bsc_codec_list_cmd);
	install_element(MSC_NODE, &cfg_net_msc_dest_cmd);
	install_element(MSC_NODE, &cfg_net_msc_no_dest_cmd);
	install_element(MSC_NODE, &cfg_net_msc_welcome_ussd_cmd);
	install_element(MSC_NODE, &cfg_net_msc_no_welcome_ussd_cmd);
	install_element(MSC_NODE, &cfg_net_msc_lost_ussd_cmd);
	install_element(MSC_NODE, &cfg_net_msc_no_lost_ussd_cmd);
	install_element(MSC_NODE, &cfg_net_msc_grace_ussd_cmd);
	install_element(MSC_NODE, &cfg_net_msc_no_grace_ussd_cmd);
	install_element(MSC_NODE, &cfg_net_msc_type_cmd);
	install_element(MSC_NODE, &cfg_net_msc_emerg_cmd);
	install_element(MSC_NODE, &cfg_net_msc_amr_12_2_cmd);
	install_element(MSC_NODE, &cfg_net_msc_amr_10_2_cmd);
	install_element(MSC_NODE, &cfg_net_msc_amr_7_95_cmd);
	install_element(MSC_NODE, &cfg_net_msc_amr_7_40_cmd);
	install_element(MSC_NODE, &cfg_net_msc_amr_6_70_cmd);
	install_element(MSC_NODE, &cfg_net_msc_amr_5_90_cmd);
	install_element(MSC_NODE, &cfg_net_msc_amr_5_15_cmd);
	install_element(MSC_NODE, &cfg_net_msc_amr_4_75_cmd);
	install_element(MSC_NODE, &cfg_net_msc_amr_octet_align_cmd);
	install_element(MSC_NODE, &cfg_net_msc_lcls_mode_cmd);
	install_element(MSC_NODE, &cfg_net_msc_lcls_mismtch_cmd);
	install_element(MSC_NODE, &cfg_msc_cs7_bsc_addr_cmd);
	install_element(MSC_NODE, &cfg_msc_cs7_msc_addr_cmd);
	install_element(MSC_NODE, &cfg_msc_cs7_asp_proto_cmd);
	install_element(MSC_NODE, &cfg_msc_nri_add_cmd);
	install_element(MSC_NODE, &cfg_msc_nri_del_cmd);
	install_element(MSC_NODE, &cfg_msc_show_nri_cmd);
	install_element(MSC_NODE, &cfg_msc_allow_attach_cmd);
	install_element(MSC_NODE, &cfg_msc_no_allow_attach_cmd);

	/* Deprecated: ping time config, kept to support legacy config files. */
	install_element(MSC_NODE, &cfg_net_msc_no_ping_time_cmd);
	install_element(MSC_NODE, &cfg_net_msc_ping_time_cmd);
	install_element(MSC_NODE, &cfg_net_msc_pong_time_cmd);

	install_element_ve(&show_statistics_cmd);
	install_element_ve(&show_mscs_cmd);
	install_element_ve(&show_pos_cmd);
	install_element_ve(&logging_fltr_imsi_cmd);
	install_element_ve(&show_subscr_all_cmd);
	install_element_ve(&show_nri_cmd);

	install_element(ENABLE_NODE, &gen_position_trap_cmd);
	install_element(ENABLE_NODE, &mscpool_roundrobin_next_cmd);
	install_element(ENABLE_NODE, &msc_bssmap_reset_cmd);

	install_element(CFG_LOG_NODE, &logging_fltr_imsi_cmd);

	mgcp_client_vty_init(network, MSC_NODE, network->mgw.conf);
	install_element(MSC_NODE, &cfg_msc_mgw_x_osmo_ign_cmd);
	install_element(MSC_NODE, &cfg_msc_no_mgw_x_osmo_ign_cmd);
	install_element(MSC_NODE, &cfg_msc_osmux_cmd);

	return 0;
}
