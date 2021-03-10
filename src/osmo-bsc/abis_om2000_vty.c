/* VTY interface for A-bis OM2000 */

/* (C) 2010-2018 by Harald Welte <laforge@gnumonks.org>
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

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>

#include <arpa/inet.h>

#include <osmocom/bsc/gsm_data.h>
#include <osmocom/core/msgb.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/core/talloc.h>
#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/signal.h>
#include <osmocom/bsc/abis_om2000.h>
#include <osmocom/bsc/bts.h>
#include <osmocom/bsc/vty.h>

#include <osmocom/vty/vty.h>
#include <osmocom/vty/command.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/telnet_interface.h>

#define X(x) (1 << x)

static struct cmd_node om2k_node = {
	OM2K_NODE,
	"%s(om2k)# ",
	1,
};

static struct cmd_node om2k_con_group_node = {
	OM2K_CON_GROUP_NODE,
	"%s(om2k-con-group)# ",
	1,
};

struct con_group;

struct oml_node_state {
	struct gsm_bts *bts;
	struct abis_om2k_mo mo;
	struct con_group *cg;
};

static int dummy_config_write(struct vty *v)
{
	return CMD_SUCCESS;
}

/* FIXME: auto-generate those strings from the value_string lists */
#define OM2K_OBJCLASS_VTY "(trxc|tg|ts|tf|is|con|dp|mctr|cf|tx|rx)"
#define OM2K_OBJCLASS_VTY_HELP 	"TRX Controller\n"	\
				"Trunk Group\n"		\
				"Timeslot\n"		\
				"Timing Function\n"	\
				"Interface Switch\n"	\
				"Abis Concentrator\n"	\
				"Digital Path\n"	\
				"Multi Carrier Transceiver\n" \
				"Central Function\n"	\
				"Transmitter\n"		\
				"Receiver\n"
#define OM2K_VTY_HELP "Configure OM2K specific parameters\n"

DEFUN(om2k_class_inst, om2k_class_inst_cmd,
	"bts <0-255> om2000 class " OM2K_OBJCLASS_VTY
					" <0-255> <0-255> <0-255>",
	"BTS related commands\n" "BTS Number\n"
	"Manipulate the OM2000 managed objects\n"
	"Object Class\n" 	OM2K_OBJCLASS_VTY_HELP
	"BTS Number\n" "Associated SO Instance\n" "Instance Number\n")
{
	struct gsm_bts *bts;
	struct oml_node_state *oms;
	int bts_nr = atoi(argv[0]);

	bts = gsm_bts_num(gsmnet_from_vty(vty), bts_nr);
	if (!bts) {
		vty_out(vty, "%% No such BTS (%d)%s", bts_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (bts->type != GSM_BTS_TYPE_RBS2000) {
		vty_out(vty, "%% BTS %d not an Ericsson RBS%s",
			bts_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	oms = talloc_zero(tall_bsc_ctx, struct oml_node_state);
	if (!oms)
		return CMD_WARNING;

	oms->bts = bts;
	oms->mo.class = get_string_value(om2k_mo_class_short_vals, argv[1]);
	oms->mo.bts = atoi(argv[2]);
	oms->mo.assoc_so = atoi(argv[3]);
	oms->mo.inst = atoi(argv[4]);

	vty->index = oms;
	vty->node = OM2K_NODE;

	return CMD_SUCCESS;

}

DEFUN(om2k_classnum_inst, om2k_classnum_inst_cmd,
	"bts <0-255> om2000 class <0-255> <0-255> <0-255> <0-255>",
	"BTS related commands\n" "BTS Number\n"
	"Manipulate the OML managed objects\n"
	"Object Class\n" "Object Class\n"
	"BTS Number\n" "Associated SO Instance\n" "Instance Number\n")
{
	struct gsm_bts *bts;
	struct oml_node_state *oms;
	int bts_nr = atoi(argv[0]);

	bts = gsm_bts_num(gsmnet_from_vty(vty), bts_nr);
	if (!bts) {
		vty_out(vty, "%% No such BTS (%d)%s", bts_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	oms = talloc_zero(tall_bsc_ctx, struct oml_node_state);
	if (!oms)
		return CMD_WARNING;

	oms->bts = bts;
	oms->mo.class = atoi(argv[1]);
	oms->mo.bts = atoi(argv[2]);
	oms->mo.assoc_so = atoi(argv[3]);
	oms->mo.inst = atoi(argv[4]);

	vty->index = oms;
	vty->node = OM2K_NODE;

	return CMD_SUCCESS;
}

DEFUN(om2k_reset, om2k_reset_cmd,
	"reset-command",
	"Reset the MO\n")
{
	struct oml_node_state *oms = vty->index;

	abis_om2k_tx_reset_cmd(oms->bts, &oms->mo);
	return CMD_SUCCESS;
}

DEFUN(om2k_start, om2k_start_cmd,
	"start-request",
	"Start the MO\n")
{
	struct oml_node_state *oms = vty->index;

	abis_om2k_tx_start_req(oms->bts, &oms->mo);
	return CMD_SUCCESS;
}

DEFUN(om2k_status, om2k_status_cmd,
	"status-request",
	"Get the MO Status\n")
{
	struct oml_node_state *oms = vty->index;

	abis_om2k_tx_status_req(oms->bts, &oms->mo);
	return CMD_SUCCESS;
}

DEFUN(om2k_connect, om2k_connect_cmd,
	"connect-command",
	"Connect the MO\n")
{
	struct oml_node_state *oms = vty->index;

	abis_om2k_tx_connect_cmd(oms->bts, &oms->mo);
	return CMD_SUCCESS;
}

DEFUN(om2k_disconnect, om2k_disconnect_cmd,
	"disconnect-command",
	"Disconnect the MO\n")
{
	struct oml_node_state *oms = vty->index;

	abis_om2k_tx_disconnect_cmd(oms->bts, &oms->mo);
	return CMD_SUCCESS;
}

DEFUN(om2k_enable, om2k_enable_cmd,
	"enable-request",
	"Enable the MO\n")
{
	struct oml_node_state *oms = vty->index;

	abis_om2k_tx_enable_req(oms->bts, &oms->mo);
	return CMD_SUCCESS;
}

DEFUN(om2k_disable, om2k_disable_cmd,
	"disable-request",
	"Disable the MO\n")
{
	struct oml_node_state *oms = vty->index;

	abis_om2k_tx_disable_req(oms->bts, &oms->mo);
	return CMD_SUCCESS;
}

DEFUN(om2k_op_info, om2k_op_info_cmd,
	"operational-info <0-1>",
	"Set operational information\n"
	"Set operational info to 0 or 1\n")
{
	struct oml_node_state *oms = vty->index;
	int oper = atoi(argv[0]);

	abis_om2k_tx_op_info(oms->bts, &oms->mo, oper);
	return CMD_SUCCESS;
}

DEFUN(om2k_test, om2k_test_cmd,
	"test-request",
	"Test the MO\n")
{
	struct oml_node_state *oms = vty->index;

	abis_om2k_tx_test_req(oms->bts, &oms->mo);
	return CMD_SUCCESS;
}

DEFUN(om2k_cap_req, om2k_cap_req_cmd,
	"capabilities-request",
	"Request MO capabilities\n")
{
	struct oml_node_state *oms = vty->index;

	abis_om2k_tx_cap_req(oms->bts, &oms->mo);
	return CMD_SUCCESS;
}

DEFUN(om2k_arb, om2k_arb_cmd,
	"arbitrary <0-65535> [HEXSTRING]",
	"Send arbitrary OM2k message\n"
	"Command identifier\n"
	"Hex Encoded payload\n")
{
	struct oml_node_state *oms = vty->index;
	uint8_t buf[128];
	int rc;
	int cmd = atoi(argv[0]);

	if (argc >= 2) {
		rc = osmo_hexparse(argv[1], buf, sizeof(buf));
		if (rc < 0 || rc > sizeof(buf)) {
			vty_out(vty, "Error parsing HEXSTRING%s", VTY_NEWLINE);
			return CMD_WARNING;
		}
	} else {
		rc = 0;
	}

	abis_om2k_tx_arb(oms->bts, &oms->mo, cmd, buf, rc);

	return CMD_SUCCESS;
}



static struct con_group *con_group_find_or_create(struct gsm_bts *bts, uint8_t cg)
{
	struct con_group *ent;

	llist_for_each_entry(ent, &bts->rbs2000.con.conn_groups, list) {
		if (ent->cg == cg)
			return ent;
	}

	ent = talloc_zero(bts, struct con_group);
	ent->bts = bts;
	ent->cg = cg;
	INIT_LLIST_HEAD(&ent->paths);
	llist_add_tail(&ent->list, &bts->rbs2000.con.conn_groups);

	return ent;
}

static int con_group_del(struct gsm_bts *bts, uint8_t cg_id)
{
	struct con_group *cg, *cg2;

	llist_for_each_entry_safe(cg, cg2, &bts->rbs2000.con.conn_groups, list) {
		if (cg->cg == cg_id) {
			llist_del(&cg->list);
			talloc_free(cg);
			return 0;
		};
	}
	return -ENOENT;
}

static void con_group_add_path(struct con_group *cg, uint16_t ccp,
				uint8_t ci, uint8_t tag, uint8_t tei)
{
	struct con_path *cp = talloc_zero(cg, struct con_path);

	cp->ccp = ccp;
	cp->ci = ci;
	cp->tag = tag;
	cp->tei = tei;
	llist_add(&cp->list, &cg->paths);
}

static int con_group_del_path(struct con_group *cg, uint16_t ccp,
				uint8_t ci, uint8_t tag, uint8_t tei)
{
	struct con_path *cp, *cp2;
	llist_for_each_entry_safe(cp, cp2, &cg->paths, list) {
		if (cp->ccp == ccp && cp->ci == ci && cp->tag == tag &&
		    cp->tei == tei) {
			llist_del(&cp->list);
			talloc_free(cp);
			return 0;
		}
	}
	return -ENOENT;
}

DEFUN_ATTR(cfg_om2k_con_group, cfg_om2k_con_group_cmd,
	   "con-connection-group <1-31>",
	   "Configure a CON (Concentrator) Connection Group\n"
	   "CON Connection Group Number\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct gsm_bts *bts = vty->index;
	struct con_group *cg;
	uint8_t cgid = atoi(argv[0]);

	if (bts->type != GSM_BTS_TYPE_RBS2000) {
		vty_out(vty, "%% CON MO only exists in RBS2000%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	cg = con_group_find_or_create(bts, cgid);
	if (!cg) {
		vty_out(vty, "%% Cannot create CON Group%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty->node = OM2K_CON_GROUP_NODE;
	vty->index = cg;

	return CMD_SUCCESS;
}

DEFUN_ATTR(del_om2k_con_group, del_om2k_con_group_cmd,
	   "del-connection-group <1-31>",
	   "Delete a CON (Concentrator) Connection Group\n"
	   "CON Connection Group Number\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct gsm_bts *bts = vty->index;
	int rc;
	uint8_t cgid = atoi(argv[0]);

	if (bts->type != GSM_BTS_TYPE_RBS2000) {
		vty_out(vty, "%% CON MO only exists in RBS2000%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	rc = con_group_del(bts, cgid);
	if (rc != 0) {
		vty_out(vty, "%% Cannot delete CON Group%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

#define CON_PATH_HELP	"CON Path (In/Out)\n"				\
			"Add CON Path to Concentration Group\n"		\
			"Delete CON Path from Concentration Group\n"	\
			"CON Connection Point\n"				\
			"Contiguity Index\n"				\

DEFUN_USRATTR(cfg_om2k_con_path_dec, cfg_om2k_con_path_dec_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "con-path (add|del) <0-2047> <0-255> deconcentrated <0-63>",
	      CON_PATH_HELP "De-concentrated in/outlet\n" "TEI Value\n")
{
	struct con_group *cg = vty->index;
	uint16_t ccp = atoi(argv[1]);
	uint8_t ci = atoi(argv[2]);
	uint8_t tei = atoi(argv[3]);

	if (!strcmp(argv[0], "add"))
		con_group_add_path(cg, ccp, ci, 0, tei);
	else {
		if (con_group_del_path(cg, ccp, ci, 0, tei) < 0) {
			vty_out(vty, "%% No matching CON Path%s",
				VTY_NEWLINE);
			return CMD_WARNING;
		}
	}

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_om2k_con_path_conc, cfg_om2k_con_path_conc_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "con-path (add|del) <0-2047> <0-255> concentrated <1-16>",
	      CON_PATH_HELP "Concentrated in/outlet\n" "Tag Number\n")
{
	struct con_group *cg = vty->index;
	uint16_t ccp = atoi(argv[1]);
	uint8_t ci = atoi(argv[2]);
	uint8_t tag = atoi(argv[3]);

	if (!strcmp(argv[0], "add"))
		con_group_add_path(cg, ccp, ci, tag, 0xff);
	else {
		if (con_group_del_path(cg, ccp, ci, tag, 0xff) < 0) {
			vty_out(vty, "%% No matching CON list entry%s",
				VTY_NEWLINE);
			return CMD_WARNING;
		}
	}

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_alt_mode, cfg_bts_alt_mode_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "abis-lower-transport (single-timeslot|super-channel)",
	      "Configure thee Abis Lower Transport\n"
	      "Single Timeslot (classic Abis)\n"
	      "SuperChannel (Packet Abis)\n")
{
	struct gsm_bts *bts = vty->index;

	if (bts->type != GSM_BTS_TYPE_RBS2000) {
		vty_out(vty, "%% Command only works for RBS2000%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!strcmp(argv[0], "super-channel"))
		bts->rbs2000.use_superchannel = 1;
	else
		bts->rbs2000.use_superchannel = 0;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_om2k_sync, cfg_bts_om2k_sync_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "om2000 sync-source (internal|external)",
	      OM2K_VTY_HELP
	      "TF Synchronization Source\n"
	      "Use Internal (E1)\n"
	      "USe External (GPS)\n")
{
	struct gsm_bts *bts = vty->index;
	if (bts->type != GSM_BTS_TYPE_RBS2000) {
		vty_out(vty, "%% Command only works for RBS2000%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}
	if (!strcmp(argv[0], "internal"))
		bts->rbs2000.sync_src = OM2K_SYNC_SRC_INTERNAL;
	else if (!strcmp(argv[0], "external"))
		bts->rbs2000.sync_src = OM2K_SYNC_SRC_EXTERNAL;
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_om2k_version_limit, cfg_bts_om2k_version_limit_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "om2000 version-limit (oml|rsl) gen <0-99> rev <0-99>",
	      OM2K_VTY_HELP
	      "Configure optional maximum protocol version to negotiate\n"
	      "Limit OML IWD version\n" "Limit RSL IWD version\n"
	      "Generation limit\n"
	      "Generation number to limit to (inclusive)\n"
	      "Revision limit\n"
	      "Revision number to limit to (inclusive)\n")
{
	struct gsm_bts *bts = vty->index;
	int iwd;

	if (bts->type != GSM_BTS_TYPE_RBS2000) {
		vty_out(vty, "%% Command only works for RBS2000%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!strcmp(argv[0], "oml"))
		iwd = 0;
	else if (!strcmp(argv[0], "rsl"))
		iwd = 1;
	else {
		vty_out(vty, "%% Invalid IWD%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts->rbs2000.om2k_version[iwd].limit = (atoi(argv[1]) << 8) | atoi(argv[2]);

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_is_conn_list, cfg_bts_is_conn_list_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "is-connection-list (add|del) <0-2047> <0-2047> <0-255>",
	      "Interface Switch Connection List\n"
	      "Add to IS list\n" "Delete from IS list\n"
	      "ICP1\n" "ICP2\n" "Contiguity Index\n")
{
	struct gsm_bts *bts = vty->index;
	uint16_t icp1 = atoi(argv[1]);
	uint16_t icp2 = atoi(argv[2]);
	uint8_t ci = atoi(argv[3]);
	struct is_conn_group *grp, *grp2;

	if (bts->type != GSM_BTS_TYPE_RBS2000) {
		vty_out(vty, "%% IS MO only exists in RBS2000%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!strcmp(argv[0], "add")) {
		grp = talloc_zero(bts, struct is_conn_group);
		grp->icp1 = icp1;
		grp->icp2 = icp2;
		grp->ci = ci;
		llist_add_tail(&grp->list, &bts->rbs2000.is.conn_groups);
	} else {
		llist_for_each_entry_safe(grp, grp2, &bts->rbs2000.is.conn_groups, list) {
			if (grp->icp1 == icp1 && grp->icp2 == icp2
			    && grp->ci == ci) {
				llist_del(&grp->list);
				talloc_free(grp);
				return CMD_SUCCESS;
			}
		}
		vty_out(vty, "%% No matching IS Conn Group found!%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}


DEFUN(om2k_conf_req, om2k_conf_req_cmd,
	"configuration-request",
	"Send the configuration request for current MO\n")
{
	struct oml_node_state *oms = vty->index;
	struct gsm_bts *bts = oms->bts;
	struct gsm_bts_trx *trx = NULL;
	struct gsm_bts_trx_ts *ts = NULL;

	switch (oms->mo.class) {
	case OM2K_MO_CLS_IS:
		abis_om2k_tx_is_conf_req(bts);
		break;
	case OM2K_MO_CLS_CON:
		abis_om2k_tx_con_conf_req(bts);
		break;
	case OM2K_MO_CLS_TS:
		trx = gsm_bts_trx_num(bts, oms->mo.assoc_so);
		if (!trx) {
			vty_out(vty, "%% BTS %u has no TRX %u%s", bts->nr,
				oms->mo.assoc_so, VTY_NEWLINE);
			return CMD_WARNING;
		}
		if (oms->mo.inst >= ARRAY_SIZE(trx->ts)) {
			vty_out(vty, "%% Timeslot %u out of range%s",
				oms->mo.inst, VTY_NEWLINE);
			return CMD_WARNING;
		}
		ts = &trx->ts[oms->mo.inst];
		abis_om2k_tx_ts_conf_req(ts);
		break;
	case OM2K_MO_CLS_RX:
	case OM2K_MO_CLS_TX:
	case OM2K_MO_CLS_TRXC:
		trx = gsm_bts_trx_num(bts, oms->mo.inst);
		if (!trx) {
			vty_out(vty, "%% BTS %u has no TRX %u%s", bts->nr,
				oms->mo.inst, VTY_NEWLINE);
			return CMD_WARNING;
		}
		switch (oms->mo.class) {
		case OM2K_MO_CLS_RX:
			abis_om2k_tx_rx_conf_req(trx);
			break;
		case OM2K_MO_CLS_TX:
			abis_om2k_tx_tx_conf_req(trx);
			break;
		default:
			break;
		}
		break;
	case OM2K_MO_CLS_TF:
		abis_om2k_tx_tf_conf_req(bts);
		break;
	default:
		vty_out(vty, "%% Don't know how to configure MO%s",
			VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}

static void dump_con_group(struct vty *vty, struct con_group *cg)
{
	struct con_path *cp;

	llist_for_each_entry(cp, &cg->paths, list) {
		vty_out(vty, "   con-path add %u %u ", cp->ccp, cp->ci);
		if (cp->tei == 0xff) {
			vty_out(vty, "concentrated %u%s", cp->tag,
				VTY_NEWLINE);
		} else {
			vty_out(vty, "deconcentrated %u%s", cp->tei,
				VTY_NEWLINE);
		}
	}
}

void abis_om2k_config_write_bts(struct vty *vty, struct gsm_bts *bts)
{
	struct is_conn_group *igrp;
	struct con_group *cgrp;
	unsigned int i;

	llist_for_each_entry(igrp, &bts->rbs2000.is.conn_groups, list)
		vty_out(vty, "  is-connection-list add %u %u %u%s",
			igrp->icp1, igrp->icp2, igrp->ci, VTY_NEWLINE);

	llist_for_each_entry(cgrp, &bts->rbs2000.con.conn_groups, list) {
		vty_out(vty, "  con-connection-group %u%s", cgrp->cg,
			VTY_NEWLINE);
		dump_con_group(vty, cgrp);
	}
	if (bts->rbs2000.use_superchannel)
		vty_out(vty, "  abis-lower-transport super-channel%s",
			VTY_NEWLINE);
	for (i = 0; i < 2; i++)
		if (bts->rbs2000.om2k_version[i].limit)
			vty_out(vty, "  om2000 version-limit %s gen %02d rev %02d%s",
				i ? "rsl" : "oml",
				(bts->rbs2000.om2k_version[i].limit >> 8),
				(bts->rbs2000.om2k_version[i].limit & 0xff),
				VTY_NEWLINE);
	vty_out(vty, "  om2000 sync-source %s%s",
		bts->rbs2000.sync_src != OM2K_SYNC_SRC_EXTERNAL
		? "internal" : "external",
		VTY_NEWLINE);
}

static void vty_dump_om2k_mo(struct vty *vty, const struct om2k_mo *mo, const char *pfx)
{
	unsigned int pfx_len = strlen(pfx);
	const char *mo_name = abis_om2k_mo_name(&mo->addr);
	unsigned int pfx_mo_len = pfx_len + strlen(mo_name);
	unsigned int pfx2_len;
	char pfx2[23];
	int i;

	/* generate padding after MO class to align the state names in the same column */
	if (pfx_mo_len > sizeof(pfx2)-1)
		pfx2_len = 0;
	else
		pfx2_len = sizeof(pfx2)-1 - pfx_mo_len;
	for (i = 0; i < pfx2_len; i++)
		pfx2[i] = ' ';
	pfx2[pfx2_len] = '\0';

	vty_out(vty, "%s%s%s %s%s", pfx, mo_name, pfx2,
		mo->fsm ? osmo_fsm_inst_state_name(mo->fsm) : "[NULL]",
		VTY_NEWLINE);
}

DEFUN(show_om2k_mo, show_om2k_mo_cmd,
	"show bts <0-255> om2k-mo",
	SHOW_STR "Display information about a BTS\n"
	"BTS number\n" "OM2000 Managed Object information\n")
{
	struct gsm_network *net = gsmnet_from_vty(vty);
	int bts_nr = atoi(argv[0]);
	struct gsm_bts *bts = gsm_bts_num(net, bts_nr);
	struct gsm_bts_trx *trx;

	if (!bts) {
		vty_out(vty, "%% can't find BTS '%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (bts->type != GSM_BTS_TYPE_RBS2000) {
		vty_out(vty, "%% BTS is not using OM2000%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty_out(vty, "BTS %3u OM2K-FSM state %s%s", bts->nr,
		osmo_fsm_inst_state_name(bts->rbs2000.bts_fi), VTY_NEWLINE);
	vty_dump_om2k_mo(vty, &bts->rbs2000.cf.om2k_mo, " ");
	vty_dump_om2k_mo(vty, &bts->rbs2000.con.om2k_mo, " ");
	vty_dump_om2k_mo(vty, &bts->rbs2000.is.om2k_mo, " ");
	vty_dump_om2k_mo(vty, &bts->rbs2000.dp.om2k_mo, " ");
	vty_dump_om2k_mo(vty, &bts->rbs2000.tf.om2k_mo, " ");
	vty_dump_om2k_mo(vty, &bts->rbs2000.mctr.om2k_mo, " ");


	llist_for_each_entry(trx, &bts->trx_list, list) {
		int tn;

		vty_out(vty, " TRX %u OM2K-FSM state  %s%s", trx->nr,
			osmo_fsm_inst_state_name(trx->rbs2000.trx_fi), VTY_NEWLINE);
		vty_dump_om2k_mo(vty, &trx->rbs2000.trxc.om2k_mo, "  ");
		vty_dump_om2k_mo(vty, &trx->rbs2000.rx.om2k_mo, "  ");
		vty_dump_om2k_mo(vty, &trx->rbs2000.tx.om2k_mo, "  ");

		for (tn = 0; tn < ARRAY_SIZE(trx->ts); tn++) {
			struct gsm_bts_trx_ts *ts = &trx->ts[tn];
			vty_dump_om2k_mo(vty, &ts->rbs2000.om2k_mo, "   ");
		}
	}

	return CMD_SUCCESS;
}

int abis_om2k_vty_init(void)
{
	install_element_ve(&show_om2k_mo_cmd);
	install_element(ENABLE_NODE, &om2k_class_inst_cmd);
	install_element(ENABLE_NODE, &om2k_classnum_inst_cmd);
	install_node(&om2k_node, dummy_config_write);

	install_element(OM2K_NODE, &om2k_reset_cmd);
	install_element(OM2K_NODE, &om2k_start_cmd);
	install_element(OM2K_NODE, &om2k_status_cmd);
	install_element(OM2K_NODE, &om2k_connect_cmd);
	install_element(OM2K_NODE, &om2k_disconnect_cmd);
	install_element(OM2K_NODE, &om2k_enable_cmd);
	install_element(OM2K_NODE, &om2k_disable_cmd);
	install_element(OM2K_NODE, &om2k_op_info_cmd);
	install_element(OM2K_NODE, &om2k_test_cmd);
	install_element(OM2K_NODE, &om2k_cap_req_cmd);
	install_element(OM2K_NODE, &om2k_conf_req_cmd);
	install_element(OM2K_NODE, &om2k_arb_cmd);

	install_node(&om2k_con_group_node, dummy_config_write);
	install_element(OM2K_CON_GROUP_NODE, &cfg_om2k_con_path_dec_cmd);
	install_element(OM2K_CON_GROUP_NODE, &cfg_om2k_con_path_conc_cmd);

	install_element(BTS_NODE, &cfg_bts_is_conn_list_cmd);
	install_element(BTS_NODE, &cfg_bts_alt_mode_cmd);
	install_element(BTS_NODE, &cfg_bts_om2k_sync_cmd);
	install_element(BTS_NODE, &cfg_bts_om2k_version_limit_cmd);
	install_element(BTS_NODE, &cfg_om2k_con_group_cmd);
	install_element(BTS_NODE, &del_om2k_con_group_cmd);

	return 0;
}
