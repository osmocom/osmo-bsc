/*
 * (C) 2011 by Daniel Willmann <daniel@totalueberwachung.de>
 * (C) 2011 by On-Waves
 * (C) 2011-2015 by Holger Hans Peter Freyther
 * (C) 2013-2015 by sysmocom s.f.m.c. GmbH
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
#include <errno.h>
#include <time.h>

#include <osmocom/gsm/ipa.h>

#include <osmocom/ctrl/control_cmd.h>
#include <osmocom/ctrl/control_if.h>

#include <osmocom/vty/command.h>
#include <osmocom/vty/misc.h>

#include <osmocom/gsm/gsm48.h>
#include <osmocom/bsc/ipaccess.h>
#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/abis_nm.h>
#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/chan_alloc.h>
#include <osmocom/bsc/osmo_bsc_rf.h>
#include <osmocom/bsc/bsc_msc_data.h>
#include <osmocom/bsc/bts.h>
#include <osmocom/bsc/a_reset.h>
#include <osmocom/bsc/ctrl.h>
#include <osmocom/bsc/handover_ctrl.h>
#include <osmocom/bsc/neighbor_ident.h>

static int verify_net_apply_config_file(struct ctrl_cmd *cmd, const char *value, void *_data)
{
	FILE *cfile;

	if (!cmd->value || cmd->value[0] == '\0')
		return -1;

	cfile = fopen(cmd->value, "r");
	if (!cfile)
		return -1;

	fclose(cfile);

	return 0;
}
static int set_net_apply_config_file(struct ctrl_cmd *cmd, void *_data)
{
	int rc;
	FILE *cfile;
	unsigned cmd_ret = CTRL_CMD_ERROR;

	LOGP(DCTRL, LOGL_NOTICE, "Applying VTY snippet from %s...\n", cmd->value);
	cfile = fopen(cmd->value, "r");
	if (!cfile) {
		LOGP(DCTRL, LOGL_NOTICE, "Applying VTY snippet from %s: fopen() failed: %d\n",
		     cmd->value, errno);
		cmd->reply = "NoFile";
		return cmd_ret;
	}

	rc = vty_read_config_filep(cfile, NULL);
	LOGP(DCTRL, LOGL_NOTICE, "Applying VTY snippet from %s returned %d\n", cmd->value, rc);
	if (rc) {
		cmd->reply = talloc_asprintf(cmd, "ParseError=%d", rc);
		if (!cmd->reply)
			cmd->reply = "OOM";
		goto close_ret;
	}

	rc = neighbors_check_cfg();
	if (rc) {
		cmd->reply = talloc_asprintf(cmd, "Errors in neighbor configuration");
		if (!cmd->reply)
			cmd->reply = "OOM";
		goto close_ret;
	}

	cmd->reply = "OK";
	cmd_ret = CTRL_CMD_REPLY;
close_ret:
	fclose(cfile);
	return cmd_ret;
}
CTRL_CMD_DEFINE_WO(net_apply_config_file, "apply-config-file");

static int verify_net_write_config_file(struct ctrl_cmd *cmd, const char *value, void *_data)
{
	return 0;
}
static int set_net_write_config_file(struct ctrl_cmd *cmd, void *_data)
{
	const char *cfile_name;
	unsigned cmd_ret = CTRL_CMD_ERROR;

	if (strcmp(cmd->value, "overwrite"))
		host_config_set(cmd->value);

	cfile_name = host_config_file();

	LOGP(DCTRL, LOGL_NOTICE, "Writing VTY config to file %s...\n", cfile_name);
	if (osmo_vty_write_config_file(cfile_name) < 0)
		goto ret;

	cmd->reply = "OK";
	cmd_ret = CTRL_CMD_REPLY;
ret:
	return cmd_ret;
}
CTRL_CMD_DEFINE_WO(net_write_config_file, "write-config-file");

CTRL_CMD_DEFINE(net_mcc, "mcc");
static int get_net_mcc(struct ctrl_cmd *cmd, void *_data)
{
	struct gsm_network *net = cmd->node;
	cmd->reply = talloc_asprintf(cmd, "%s", osmo_mcc_name(net->plmn.mcc));
	if (!cmd->reply) {
		cmd->reply = "OOM";
		return CTRL_CMD_ERROR;
	}
	return CTRL_CMD_REPLY;
}
static int set_net_mcc(struct ctrl_cmd *cmd, void *_data)
{
	struct gsm_network *net = cmd->node;
	uint16_t mcc;
	if (osmo_mcc_from_str(cmd->value, &mcc))
		return -1;
	net->plmn.mcc = mcc;
	return get_net_mcc(cmd, _data);
}
static int verify_net_mcc(struct ctrl_cmd *cmd, const char *value, void *_data)
{
	if (osmo_mcc_from_str(value, NULL))
		return -1;
	return 0;
}

CTRL_CMD_DEFINE(net_mnc, "mnc");
static int get_net_mnc(struct ctrl_cmd *cmd, void *_data)
{
	struct gsm_network *net = cmd->node;
	cmd->reply = talloc_asprintf(cmd, "%s", osmo_mnc_name(net->plmn.mnc, net->plmn.mnc_3_digits));
	if (!cmd->reply) {
		cmd->reply = "OOM";
		return CTRL_CMD_ERROR;
	}
	return CTRL_CMD_REPLY;
}
static int set_net_mnc(struct ctrl_cmd *cmd, void *_data)
{
	struct gsm_network *net = cmd->node;
	struct osmo_plmn_id plmn = net->plmn;
	if (osmo_mnc_from_str(cmd->value, &plmn.mnc, &plmn.mnc_3_digits)) {
		cmd->reply = "Error while decoding MNC";
		return CTRL_CMD_ERROR;
	}
	net->plmn = plmn;
	return get_net_mnc(cmd, _data);
}
static int verify_net_mnc(struct ctrl_cmd *cmd, const char *value, void *_data)
{
	if (osmo_mnc_from_str(value, NULL, NULL))
		return -1;
	return 0;
}

static int set_net_apply_config(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_network *net = cmd->node;
	struct gsm_bts *bts;

	llist_for_each_entry(bts, &net->bts_list, list) {
		if (!is_ipa_abisip_bts(bts))
			continue;

		/*
		 * The ip.access nanoBTS seems to be unreliable on BSSGP
		 * so let's us just reboot it. For the sysmoBTS we can just
		 * restart the process as all state is gone.
		 */
		if (!is_osmobts(bts) && strcmp(cmd->value, "restart") == 0) {
			struct gsm_bts_trx *trx;
			llist_for_each_entry_reverse(trx, &bts->trx_list, list)
				abis_nm_ipaccess_restart(trx);
		} else
			ipaccess_drop_oml(bts, "ctrl net.apply-configuration");
	}

	cmd->reply = "Tried to drop the BTS";
	return CTRL_CMD_REPLY;
}

CTRL_CMD_DEFINE_WO_NOVRF(net_apply_config, "apply-configuration");

static int verify_net_mcc_mnc_apply(struct ctrl_cmd *cmd, const char *value, void *d)
{
	char *tmp, *saveptr, *mcc, *mnc;
	int rc = 0;

	tmp = talloc_strdup(cmd, value);
	if (!tmp)
		return 1;

	mcc = strtok_r(tmp, ",", &saveptr);
	mnc = strtok_r(NULL, ",", &saveptr);

	if (osmo_mcc_from_str(mcc, NULL) || osmo_mnc_from_str(mnc, NULL, NULL))
		rc = -1;

	talloc_free(tmp);
	return rc;
}

static int set_net_mcc_mnc_apply(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_network *net = cmd->node;
	char *tmp, *saveptr, *mcc_str, *mnc_str;
	struct osmo_plmn_id plmn;

	tmp = talloc_strdup(cmd, cmd->value);
	if (!tmp)
		goto oom;

	mcc_str = strtok_r(tmp, ",", &saveptr);
	mnc_str = strtok_r(NULL, ",", &saveptr);

	if (osmo_mcc_from_str(mcc_str, &plmn.mcc)) {
		cmd->reply = "Error while decoding MCC";
		talloc_free(tmp);
		return CTRL_CMD_ERROR;
	}

	if (osmo_mnc_from_str(mnc_str, &plmn.mnc, &plmn.mnc_3_digits)) {
		cmd->reply = "Error while decoding MNC";
		talloc_free(tmp);
		return CTRL_CMD_ERROR;
	}

	talloc_free(tmp);

	if (!osmo_plmn_cmp(&net->plmn, &plmn)) {
		cmd->reply = "Nothing changed";
		return CTRL_CMD_REPLY;
	}

	net->plmn = plmn;

	return set_net_apply_config(cmd, data);

oom:
	cmd->reply = "OOM";
	return CTRL_CMD_ERROR;
}
CTRL_CMD_DEFINE_WO(net_mcc_mnc_apply, "mcc-mnc-apply");

static int get_net_rf_lock(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_network *net = cmd->node;
	struct gsm_bts *bts;
	const char *policy_name;

	policy_name = osmo_bsc_rf_get_policy_name(net->rf_ctrl->policy);

	llist_for_each_entry(bts, &net->bts_list, list) {
		struct gsm_bts_trx *trx;

		/* Exclude the BTS from the global lock */
		if (bts->excl_from_rf_lock)
			continue;

		llist_for_each_entry(trx, &bts->trx_list, list) {
			if (trx->mo.nm_state.availability == NM_AVSTATE_OK &&
			    trx->mo.nm_state.operational != NM_OPSTATE_DISABLED) {
				cmd->reply = talloc_asprintf(cmd,
						"state=on,policy=%s,bts=%u,trx=%u",
						policy_name, bts->nr, trx->nr);
				return CTRL_CMD_REPLY;
			}
		}
	}

	cmd->reply = talloc_asprintf(cmd, "state=off,policy=%s",
			policy_name);
	return CTRL_CMD_REPLY;
}

#define TIME_FORMAT_RFC2822 "%a, %d %b %Y %T %z"

static int set_net_rf_lock(struct ctrl_cmd *cmd, void *data)
{
	int locked = atoi(cmd->value);
	struct gsm_network *net = cmd->node;
	time_t now = time(NULL);
	char now_buf[64];
	struct osmo_bsc_rf *rf;

	if (!net) {
		cmd->reply = "net not found.";
		return CTRL_CMD_ERROR;
	}

	rf = net->rf_ctrl;

	if (!rf) {
		cmd->reply = "RF Ctrl is not enabled in the BSC Configuration";
		return CTRL_CMD_ERROR;
	}

	talloc_free(rf->last_rf_lock_ctrl_command);
	strftime(now_buf, sizeof(now_buf), TIME_FORMAT_RFC2822, gmtime(&now));
	rf->last_rf_lock_ctrl_command =
		talloc_asprintf(rf, "rf_locked %u (%s)", locked, now_buf);

	osmo_bsc_rf_schedule_lock(rf, locked == 1 ? '0' : '1');

	cmd->reply = talloc_asprintf(cmd, "%u", locked);
	if (!cmd->reply) {
		cmd->reply = "OOM";
		return CTRL_CMD_ERROR;
	}

	return CTRL_CMD_REPLY;
}

static int verify_net_rf_lock(struct ctrl_cmd *cmd, const char *value, void *data)
{
	int locked = atoi(cmd->value);

	if ((locked != 0) && (locked != 1))
		return 1;

	return 0;
}
CTRL_CMD_DEFINE(net_rf_lock, "rf_locked");

static int get_net_bts_num(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_network *net = cmd->node;

	cmd->reply = talloc_asprintf(cmd, "%u", net->num_bts);
	return CTRL_CMD_REPLY;
}
CTRL_CMD_DEFINE_RO(net_bts_num, "number-of-bts");

/* Return a list of the states of each TRX for all BTS:
 * <bts_nr>,<trx_nr>,<opstate>,<adminstate>,<rf_policy>,<rsl_status>;<bts_nr>,<trx_nr>,...;...;
 * For details on the string, see bsc_rf_states_c();
 */
static int get_net_rf_states(struct ctrl_cmd *cmd, void *data)
{
	cmd->reply = bsc_rf_states_c(cmd);
	if (!cmd->reply) {
		cmd->reply = "OOM";
		return CTRL_CMD_ERROR;
	}
	return CTRL_CMD_REPLY;
}
CTRL_CMD_DEFINE_RO(net_rf_states, "rf_states");

CTRL_CMD_DEFINE(net_timezone, "timezone");
static int get_net_timezone(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_network *net = (struct gsm_network *)cmd->node;

	struct gsm_tz *tz = &net->tz;
	if (tz->override)
		cmd->reply = talloc_asprintf(cmd, "%d,%d,%d",
			       tz->hr, tz->mn, tz->dst);
	else
		cmd->reply = talloc_asprintf(cmd, "off");

	if (!cmd->reply) {
		cmd->reply = "OOM";
		return CTRL_CMD_ERROR;
	}

	return CTRL_CMD_REPLY;
}

static int set_net_timezone(struct ctrl_cmd *cmd, void *data)
{
	char *saveptr, *hourstr, *minstr, *dststr, *tmp = 0;
	int override = 0;
	struct gsm_network *net = (struct gsm_network *)cmd->node;
	struct gsm_tz *tz = &net->tz;

	tmp = talloc_strdup(cmd, cmd->value);
	if (!tmp)
		goto oom;

	hourstr = strtok_r(tmp, ",", &saveptr);
	minstr = strtok_r(NULL, ",", &saveptr);
	dststr = strtok_r(NULL, ",", &saveptr);

	if (hourstr != NULL) {
		override = strcasecmp(hourstr, "off") != 0;
		if (override) {
			tz->hr  = atol(hourstr);
			tz->mn  = minstr ? atol(minstr) : 0;
			tz->dst = dststr ? atol(dststr) : 0;
		}
	}

	tz->override = override;


	talloc_free(tmp);
	tmp = NULL;

	return get_net_timezone(cmd, data);

oom:
	cmd->reply = "OOM";
	return CTRL_CMD_ERROR;
}

static int verify_net_timezone(struct ctrl_cmd *cmd, const char *value, void *data)
{
	char *saveptr, *hourstr, *minstr, *dststr, *tmp;
	int override, tz_hours, tz_mins, tz_dst;

	tmp = talloc_strdup(cmd, value);
	if (!tmp)
		return 1;

	hourstr = strtok_r(tmp, ",", &saveptr);
	minstr = strtok_r(NULL, ",", &saveptr);
	dststr = strtok_r(NULL, ",", &saveptr);

	if (hourstr == NULL)
		goto err;

	override = strcasecmp(hourstr, "off") != 0;

	if (!override) {
		talloc_free(tmp);
		return 0;
	}

	if (minstr == NULL || dststr == NULL)
		goto err;

	tz_hours = atol(hourstr);
	tz_mins = atol(minstr);
	tz_dst = atol(dststr);

	talloc_free(tmp);
	tmp = NULL;

	if ((tz_hours < -19) || (tz_hours > 19) ||
	       (tz_mins < 0) || (tz_mins >= 60) || (tz_mins % 15 != 0) ||
	       (tz_dst < 0) || (tz_dst > 2))
		goto err;

	return 0;

err:
	talloc_free(tmp);
	cmd->reply = talloc_strdup(cmd, "The format is <hours>,<mins>,<dst> or 'off' where -19 <= hours <= 19, mins in {0, 15, 30, 45}, and 0 <= dst <= 2");
	return 1;
}

CTRL_CMD_DEFINE_RO(bts_connection_status, "bts_connection_status");
static int bts_connection_status = 0;

static int get_bts_connection_status(struct ctrl_cmd *cmd, void *data)
{
	if (bts_connection_status)
		cmd->reply = "connected";
	else
		cmd->reply = "disconnected";
	return CTRL_CMD_REPLY;
}

static int bts_connection_status_trap_cb(unsigned int subsys, unsigned int signal, void *handler_data, void *signal_data)
{
	struct ctrl_cmd *cmd;
	struct gsm_network *gsmnet = (struct gsm_network *)handler_data;
	struct gsm_bts *bts;
	int bts_current_status;

	if (signal != S_L_INP_TEI_DN && signal != S_L_INP_TEI_UP) {
		return 0;
	}

	bts_current_status = 0;
	/* Check if OML on at least one BTS is up */
	llist_for_each_entry(bts, &gsmnet->bts_list, list) {
		if (bts->oml_link) {
			bts_current_status = 1;
			break;
		}
	}
	if (bts_connection_status == 0 && bts_current_status == 1) {
		LOGP(DCTRL, LOGL_DEBUG, "BTS connection (re)established, sending TRAP.\n");
	} else if (bts_connection_status == 1 && bts_current_status == 0) {
		LOGP(DCTRL, LOGL_DEBUG, "No more BTS connected, sending TRAP.\n");
	} else {
		return 0;
	}

	cmd = ctrl_cmd_create(tall_bsc_ctx, CTRL_TYPE_TRAP);
	if (!cmd) {
		LOGP(DCTRL, LOGL_ERROR, "Trap creation failed.\n");
		return 0;
	}

	bts_connection_status = bts_current_status;

	cmd->id = "0";
	cmd->variable = "bts_connection_status";

	get_bts_connection_status(cmd, NULL);

	ctrl_cmd_send_to_all(gsmnet->ctrl, cmd);

	talloc_free(cmd);

	return 0;
}

CTRL_CMD_DEFINE_RO(msc_connection_status, "connection_status");
static int get_msc_connection_status(struct ctrl_cmd *cmd, void *data)
{
	struct bsc_msc_data *msc = (struct bsc_msc_data *)cmd->node;

	if (msc == NULL) {
		cmd->reply = "msc not found";
		return CTRL_CMD_ERROR;
	}
	if (a_reset_conn_ready(msc))
		cmd->reply = "connected";
	else
		cmd->reply = "disconnected";
	return CTRL_CMD_REPLY;
}

/* Backwards compat. */
CTRL_CMD_DEFINE_RO(msc0_connection_status, "msc_connection_status");

static int get_msc0_connection_status(struct ctrl_cmd *cmd, void *data)
{
	struct bsc_msc_data *msc = osmo_msc_data_find(bsc_gsmnet, 0);
	void *old_node = cmd->node;
	int rc;

	cmd->node = msc;
	rc = get_msc_connection_status(cmd, data);
	cmd->node = old_node;

	return rc;
}

static int msc_connection_status_trap_cb(unsigned int subsys, unsigned int signal, void *handler_data, void *signal_data)
{
	struct ctrl_cmd *cmd;
	struct gsm_network *gsmnet = (struct gsm_network *)handler_data;
	struct bsc_msc_data *msc = (struct bsc_msc_data *)signal_data;

	if (signal == S_MSC_LOST) {
		LOGP(DCTRL, LOGL_DEBUG, "MSC connection lost, sending TRAP.\n");
	} else if (signal == S_MSC_CONNECTED) {
		LOGP(DCTRL, LOGL_DEBUG, "MSC connection (re)established, sending TRAP.\n");
	} else {
		return 0;
	}

	cmd = ctrl_cmd_create(tall_bsc_ctx, CTRL_TYPE_TRAP);
	if (!cmd) {
		LOGP(DCTRL, LOGL_ERROR, "Trap creation failed.\n");
		return 0;
	}

	cmd->id = "0";
	cmd->variable = talloc_asprintf(cmd, "msc.%d.connection_status", msc->nr);
	cmd->node = msc;

	get_msc_connection_status(cmd, NULL);

	ctrl_cmd_send_to_all(gsmnet->ctrl, cmd);

	if (msc->nr == 0) {
		/* Backwards compat. */
		cmd->variable = "msc_connection_status";
		ctrl_cmd_send_to_all(gsmnet->ctrl, cmd);
	}

	talloc_free(cmd);

	return 0;
}

static int msc_signal_handler(unsigned int subsys, unsigned int signal,
			void *handler_data, void *signal_data)
{
	struct msc_signal_data *msc;
	struct gsm_network *net;
	struct gsm_bts *bts;

	if (subsys != SS_MSC)
		return 0;
	if (signal != S_MSC_AUTHENTICATED)
		return 0;

	msc = signal_data;

	net = msc->data->network;
	llist_for_each_entry(bts, &net->bts_list, list)
		ctrl_generate_bts_location_state_trap(bts, msc->data);

	return 0;
}

/* Obtain SS7 application server currently handling given MSC (DPC) */
static struct osmo_ss7_as *msc_get_ss7_as(struct bsc_msc_data *msc)
{
	struct osmo_ss7_route *rt;
	struct osmo_ss7_as *as;
	struct osmo_ss7_instance *ss7 = osmo_sccp_get_ss7(msc->a.sccp);
	rt = osmo_ss7_route_lookup(ss7, msc->a.msc_addr.pc);
	if (!rt)
		return NULL;
	as = osmo_ss7_route_get_dest_as(rt);
	if (!as)
		return NULL;
	return as;
}

static int _ss7_as_send(struct osmo_ss7_as *as, struct msgb *msg)
{
	struct osmo_ss7_asp *asp;
	unsigned int i;

	/* FIXME: unify with xua_as_transmit_msg() and perform proper ASP lookup */
	for (i = 0; i < ARRAY_SIZE(as->cfg.asps); i++) {
		asp = as->cfg.asps[i];
		if (!asp)
			continue;
		/* FIXME: deal with multiple ASPs per AS */
		return osmo_ss7_asp_send(asp, msg);
	}
	msgb_free(msg);
	return -1;
}

int bsc_sccplite_msc_send(struct bsc_msc_data *msc, struct msgb *msg)
{
	struct osmo_ss7_as *as;

	as = msc_get_ss7_as(msc);
	if (!as) {
		msgb_free(msg);
		return -1;
	}

	/* don't attempt to send CTRL on a non-SCCPlite AS */
	if (as->cfg.proto != OSMO_SS7_ASP_PROT_IPA) {
		msgb_free(msg);
		return 0;
	}

	return _ss7_as_send(as, msg);
}

/* Encode a CTRL command and send it to the given ASP
 * \param[in] asp ASP through which we shall send the encoded message
 * \param[in] cmd decoded CTRL command to be encoded and sent. Ownership is *NOT*
 *		  transferred, to permit caller to send the same CMD to several ASPs.
 *		  Caller must hence free 'cmd' itself.
 * \returns 0 on success; negative on error */
static int sccplite_asp_ctrl_cmd_send(struct osmo_ss7_asp *asp, struct ctrl_cmd *cmd)
{
	/* this is basically like libosmoctrl:ctrl_cmd_send(), not for a dedicated
	 * CTRL connection but for the CTRL piggy-back on the IPA/SCCPlite link */
	struct msgb *msg;

	/* don't attempt to send CTRL on a non-SCCPlite ASP */
	if (osmo_ss7_asp_get_proto(asp) != OSMO_SS7_ASP_PROT_IPA)
		return 0;

	msg = ctrl_cmd_make(cmd);
	if (!msg)
		return -1;

	ipa_prepend_header_ext(msg, IPAC_PROTO_EXT_CTRL);
	ipa_prepend_header(msg, IPAC_PROTO_OSMO);

	return osmo_ss7_asp_send(asp, msg);
}

/* Ownership of 'cmd' is *NOT* transferred, to permit caller to send the same CMD to several ASPs.
 * Caller must hence free 'cmd' itself. */
static int sccplite_msc_ctrl_cmd_send(struct bsc_msc_data *msc, struct ctrl_cmd *cmd)
{
	struct msgb *msg;

	msg = ctrl_cmd_make(cmd);
	if (!msg)
		return -1;

	ipa_prepend_header_ext(msg, IPAC_PROTO_EXT_CTRL);
	ipa_prepend_header(msg, IPAC_PROTO_OSMO);

	return bsc_sccplite_msc_send(msc, msg);
}

/* receive + process a CTRL command from the piggy-back on the IPA/SCCPlite link.
 * Transfers msg ownership. */
int bsc_sccplite_rx_ctrl(struct osmo_ss7_asp *asp, struct msgb *msg)
{
	struct ctrl_cmd *cmd;
	bool parse_failed;
	int rc;

	/* caller has already ensured ipaccess_head + ipaccess_head_ext */
	OSMO_ASSERT(msg->l2h);

	/* prase raw (ASCII) CTRL command into ctrl_cmd */
	cmd = ctrl_cmd_parse3(asp, msg, &parse_failed);
	OSMO_ASSERT(cmd);
	msgb_free(msg);
	if (cmd->type == CTRL_TYPE_ERROR && parse_failed)
		goto send_reply;

	/* handle the CTRL command */
	ctrl_cmd_handle(bsc_gsmnet->ctrl, cmd, bsc_gsmnet);

send_reply:
	rc = sccplite_asp_ctrl_cmd_send(asp, cmd);
	talloc_free(cmd);
	return rc;
}


void osmo_bsc_send_trap(struct ctrl_cmd *cmd, struct bsc_msc_data *msc_data)
{
	struct ctrl_cmd *trap;
	struct ctrl_handle *ctrl;

	ctrl = msc_data->network->ctrl;

	trap = ctrl_cmd_trap(cmd);
	if (!trap) {

		LOGP(DCTRL, LOGL_ERROR, "Failed to create trap.\n");
		return;
	}

	ctrl_cmd_send_to_all(ctrl, trap);
	sccplite_msc_ctrl_cmd_send(msc_data, trap);

	talloc_free(trap);
}

CTRL_CMD_DEFINE_WO_NOVRF(net_notification, "notification");
static int set_net_notification(struct ctrl_cmd *cmd, void *data)
{
	struct ctrl_cmd *trap;
	struct gsm_network *net;

	net = cmd->node;

	trap = ctrl_cmd_create(tall_bsc_ctx, CTRL_TYPE_TRAP);
	if (!trap) {
		LOGP(DCTRL, LOGL_ERROR, "Trap creation failed\n");
		goto handled;
	}

	trap->id = "0";
	trap->variable = "notification";
	trap->reply = talloc_strdup(trap, cmd->value);

	/*
	 * This should only be sent to local systems. In the future
	 * we might even ask for systems to register to receive
	 * the notifications.
	 */
	ctrl_cmd_send_to_all(net->ctrl, trap);
	talloc_free(trap);

handled:
	return CTRL_CMD_HANDLED;
}

CTRL_CMD_DEFINE_WO_NOVRF(net_inform_msc, "inform-msc-v1");
static int set_net_inform_msc(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_network *net;
	struct bsc_msc_data *msc;

	net = cmd->node;
	llist_for_each_entry(msc, &net->mscs, entry) {
		struct ctrl_cmd *trap;

		trap = ctrl_cmd_create(tall_bsc_ctx, CTRL_TYPE_TRAP);
		if (!trap) {
			LOGP(DCTRL, LOGL_ERROR, "Trap creation failed\n");
			continue;
		}

		trap->id = "0";
		trap->variable = "inform-msc-v1";
		trap->reply = talloc_strdup(trap, cmd->value);
		sccplite_msc_ctrl_cmd_send(msc, trap);
		talloc_free(trap);
	}


	return CTRL_CMD_HANDLED;
}

/* Return full information about all logical channels.
 * format: show-lchan.full
 * result format: New line delimited list of <bts>,<trx>,<ts>,<lchan>,<type>,<connection>,<state>,<last error>,<bs power>,
 *  <ms power>,<interference dbm>, <interference band>,<channel mode>,<imsi>,<tmsi>,<ipa bound ip>,<ipa bound port>,
 *  <ipa bound conn id>,<ipa conn ip>,<ipa conn port>,<ipa conn speech mode>
 */
static int get_net_show_lchan_full(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_network *net = cmd->node;
	int bts_nr;
	bool first_bts = true;
	char *bts_dump;

	cmd->reply = talloc_strdup(cmd, "");
	if (!cmd->reply) {
		cmd->reply = "OOM";
		return CTRL_CMD_ERROR;
	}

	for (bts_nr = 0; bts_nr < net->num_bts; bts_nr++) {
		bts_dump = bts_lchan_dump_full_ctrl(cmd, gsm_bts_num(net, bts_nr));
		if (!bts_dump) {
			cmd->reply = "OOM";
			return CTRL_CMD_ERROR;
		}
		if (!strlen(bts_dump))
			continue;
		cmd->reply = talloc_asprintf_append(cmd->reply, first_bts ? "%s" : "\n%s", bts_dump);
		if (!cmd->reply) {
			cmd->reply = "OOM";
			return CTRL_CMD_ERROR;
		}
		first_bts = false;
	}

	return CTRL_CMD_REPLY;
}
CTRL_CMD_DEFINE_RO(net_show_lchan_full, "show-lchan full");

static int bsc_base_ctrl_cmds_install(struct gsm_network *net)
{
	int rc = 0;
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_apply_config_file);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_write_config_file);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_mnc);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_mcc);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_apply_config);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_mcc_mnc_apply);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_rf_lock);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_bts_num);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_rf_states);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_timezone);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_bts_connection_status);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_msc0_connection_status);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_notification);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_inform_msc);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_show_lchan_full);

	rc |= ctrl_cmd_install(CTRL_NODE_MSC, &cmd_msc_connection_status);

	rc |= osmo_signal_register_handler(SS_L_INPUT, &bts_connection_status_trap_cb, net);
	rc |= osmo_signal_register_handler(SS_MSC, &msc_connection_status_trap_cb, net);
	rc |= osmo_signal_register_handler(SS_MSC, msc_signal_handler, NULL);

	return rc;
}


int bsc_ctrl_cmds_install(struct gsm_network *net)
{
	int rc;

	rc = bsc_base_ctrl_cmds_install(net);
	if (rc)
		goto end;
	rc = bsc_ho_ctrl_cmds_install(net);
	if (rc)
		goto end;
	rc = bsc_bts_ctrl_cmds_install();
	if (rc)
		goto end;
end:
	return rc;
}
