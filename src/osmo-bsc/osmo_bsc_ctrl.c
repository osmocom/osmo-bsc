/* (C) 2011 by Daniel Willmann <daniel@totalueberwachung.de>
 * (C) 2011 by Holger Hans Peter Freyther
 * (C) 2011 by On-Waves
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

#include <osmocom/ctrl/control_cmd.h>
#include <osmocom/bsc/ctrl.h>
#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/osmo_bsc.h>
#include <osmocom/bsc/osmo_bsc_rf.h>
#include <osmocom/bsc/bsc_msc_data.h>
#include <osmocom/bsc/signal.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/signal.h>

#include <osmocom/ctrl/control_if.h>

#include <osmocom/gsm/protocol/ipaccess.h>
#include <osmocom/gsm/ipa.h>

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

/* Obtain SS7 application server currently handling given MSC (DPC) */
static struct osmo_ss7_as *msc_get_ss7_as(struct bsc_msc_data *msc)
{
	struct osmo_ss7_route *rt;
	struct osmo_ss7_instance *ss7 = osmo_sccp_get_ss7(msc->a.sccp);
	rt = osmo_ss7_route_lookup(ss7, msc->a.msc_addr.pc);
	if (!rt)
		return NULL;
	return rt->dest.as;
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
	if (as->cfg.proto != OSMO_SS7_ASP_PROT_IPA)
		return 0;

	return _ss7_as_send(as, msg);
}

/* Encode a CTRL command and send it to the given ASP
 * \param[in] asp ASP through which we shall send the encoded message
 * \param[in] cmd decoded CTRL command to be encoded and sent. Ownership is *NOT*
 * 		  transferred, to permit caller to send the same CMD to several ASPs.
 * 		  Caller must hence free 'cmd' itself.
 * \returns 0 on success; negative on error */
static int sccplite_asp_ctrl_cmd_send(struct osmo_ss7_asp *asp, struct ctrl_cmd *cmd)
{
	/* this is basically like libosmoctrl:ctrl_cmd_send(), not for a dedicated
	 * CTRL connection but for the CTRL piggy-back on the IPA/SCCPlite link */
	struct msgb *msg;

	/* don't attempt to send CTRL on a non-SCCPlite ASP */
	if (asp->cfg.proto != OSMO_SS7_ASP_PROT_IPA)
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

CTRL_CMD_DEFINE_RO(msc_connection_status, "connection_status");
static int get_msc_connection_status(struct ctrl_cmd *cmd, void *data)
{
	struct bsc_msc_data *msc = (struct bsc_msc_data *)cmd->node;
	struct osmo_ss7_as *as;
	const char *as_state_name;

	if (msc == NULL) {
		cmd->reply = "msc not found";
		return CTRL_CMD_ERROR;
	}
	as = msc_get_ss7_as(msc);
	if (!as) {
		cmd->reply = "AS not found for MSC";
		return CTRL_CMD_ERROR;
	}

	as_state_name = osmo_fsm_inst_state_name(as->fi);
	if (!strcmp(as_state_name, "AS_ACTIVE"))
		cmd->reply = "connected";
	else
		cmd->reply = "disconnected";
	return CTRL_CMD_REPLY;
}

/* Backwards compat. */
CTRL_CMD_DEFINE_RO(msc0_connection_status, "msc_connection_status");
static int msc_connection_status = 0; /* XXX unused */

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

	if (signal == S_MSC_LOST && msc_connection_status == 1) {
		LOGP(DCTRL, LOGL_DEBUG, "MSC connection lost, sending TRAP.\n");
		msc_connection_status = 0;
	} else if (signal == S_MSC_CONNECTED && msc_connection_status == 0) {
		LOGP(DCTRL, LOGL_DEBUG, "MSC connection (re)established, sending TRAP.\n");
		msc_connection_status = 1;
	} else {
		return 0;
	}

	cmd = ctrl_cmd_create(tall_bsc_ctx, CTRL_TYPE_TRAP);
	if (!cmd) {
		LOGP(DCTRL, LOGL_ERROR, "Trap creation failed.\n");
		return 0;
	}

	cmd->id = "0";
	cmd->variable = "msc_connection_status";

	get_msc0_connection_status(cmd, NULL);

	ctrl_cmd_send_to_all(gsmnet->ctrl, cmd);

	talloc_free(cmd);

	return 0;
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

static int get_bts_loc(struct ctrl_cmd *cmd, void *data);

static void generate_location_state_trap(struct gsm_bts *bts, struct bsc_msc_data *msc)
{
	struct ctrl_cmd *cmd;
	const char *oper, *admin, *policy;

	cmd = ctrl_cmd_create(msc, CTRL_TYPE_TRAP);
	if (!cmd) {
		LOGP(DCTRL, LOGL_ERROR, "Failed to create TRAP command.\n");
		return;
	}

	cmd->id = "0";
	cmd->variable = talloc_asprintf(cmd, "bts.%i.location-state", bts->nr);

	/* Prepare the location reply */
	cmd->node = bts;
	get_bts_loc(cmd, NULL);

	oper = osmo_bsc_rf_get_opstate_name(osmo_bsc_rf_get_opstate_by_bts(bts));
	admin = osmo_bsc_rf_get_adminstate_name(osmo_bsc_rf_get_adminstate_by_bts(bts));
	policy = osmo_bsc_rf_get_policy_name(osmo_bsc_rf_get_policy_by_bts(bts));

	cmd->reply = talloc_asprintf_append(cmd->reply,
				",%s,%s,%s,%s,%s",
				oper, admin, policy,
				osmo_mcc_name(bts->network->plmn.mcc),
				osmo_mnc_name(bts->network->plmn.mnc,
					      bts->network->plmn.mnc_3_digits));

	osmo_bsc_send_trap(cmd, msc);
	talloc_free(cmd);
}

void bsc_gen_location_state_trap(struct gsm_bts *bts)
{
	struct bsc_msc_data *msc;

	llist_for_each_entry(msc, &bts->network->bsc_data->mscs, entry)
		generate_location_state_trap(bts, msc);
}

static int location_equal(struct bts_location *a, struct bts_location *b)
{
	return ((a->tstamp == b->tstamp) && (a->valid == b->valid) && (a->lat == b->lat) &&
		(a->lon == b->lon) && (a->height == b->height));
}

static void cleanup_locations(struct llist_head *locations)
{
	struct bts_location *myloc, *tmp;
	int invalpos = 0, i = 0;

	LOGP(DCTRL, LOGL_DEBUG, "Checking position list.\n");
	llist_for_each_entry_safe(myloc, tmp, locations, list) {
		i++;
		if (i > 3) {
			LOGP(DCTRL, LOGL_DEBUG, "Deleting old position.\n");
			llist_del(&myloc->list);
			talloc_free(myloc);
		} else if (myloc->valid == BTS_LOC_FIX_INVALID) {
			/* Only capture the newest of subsequent invalid positions */
			invalpos++;
			if (invalpos > 1) {
				LOGP(DCTRL, LOGL_DEBUG, "Deleting subsequent invalid position.\n");
				invalpos--;
				i--;
				llist_del(&myloc->list);
				talloc_free(myloc);
			}
		} else {
			invalpos = 0;
		}
	}
	LOGP(DCTRL, LOGL_DEBUG, "Found %i positions.\n", i);
}

CTRL_CMD_DEFINE(bts_loc, "location");
static int get_bts_loc(struct ctrl_cmd *cmd, void *data)
{
	struct bts_location *curloc;
	struct gsm_bts *bts = (struct gsm_bts *) cmd->node;
	if (!bts) {
		cmd->reply = "bts not found.";
		return CTRL_CMD_ERROR;
	}

	if (llist_empty(&bts->loc_list)) {
		cmd->reply = talloc_asprintf(cmd, "0,invalid,0,0,0");
		return CTRL_CMD_REPLY;
	} else {
		curloc = llist_entry(bts->loc_list.next, struct bts_location, list);
	}

	cmd->reply = talloc_asprintf(cmd, "%lu,%s,%f,%f,%f", curloc->tstamp,
			get_value_string(bts_loc_fix_names, curloc->valid), curloc->lat, curloc->lon, curloc->height);
	if (!cmd->reply) {
		cmd->reply = "OOM";
		return CTRL_CMD_ERROR;
	}

	return CTRL_CMD_REPLY;
}

static int set_bts_loc(struct ctrl_cmd *cmd, void *data)
{
	char *saveptr, *lat, *lon, *height, *tstamp, *valid, *tmp;
	struct bts_location *curloc, *lastloc;
	int ret;
	struct gsm_bts *bts = (struct gsm_bts *) cmd->node;
	if (!bts) {
		cmd->reply = "bts not found.";
		return CTRL_CMD_ERROR;
	}

	tmp = talloc_strdup(cmd, cmd->value);
	if (!tmp)
		goto oom;

	curloc = talloc_zero(tall_bsc_ctx, struct bts_location);
	if (!curloc) {
		talloc_free(tmp);
		goto oom;
	}
	INIT_LLIST_HEAD(&curloc->list);


	tstamp = strtok_r(tmp, ",", &saveptr);
	valid = strtok_r(NULL, ",", &saveptr);
	lat = strtok_r(NULL, ",", &saveptr);
	lon = strtok_r(NULL, ",", &saveptr);
	height = strtok_r(NULL, "\0", &saveptr);

	curloc->tstamp = atol(tstamp);
	curloc->valid = get_string_value(bts_loc_fix_names, valid);
	curloc->lat = atof(lat);
	curloc->lon = atof(lon);
	curloc->height = atof(height);
	talloc_free(tmp);

	lastloc = llist_entry(bts->loc_list.next, struct bts_location, list);

	/* Add location to the end of the list */
	llist_add(&curloc->list, &bts->loc_list);

	ret = get_bts_loc(cmd, data);

	if (!location_equal(curloc, lastloc))
		bsc_gen_location_state_trap(bts);

	cleanup_locations(&bts->loc_list);

	return ret;

oom:
	cmd->reply = "OOM";
	return CTRL_CMD_ERROR;
}

static int verify_bts_loc(struct ctrl_cmd *cmd, const char *value, void *data)
{
	char *saveptr, *latstr, *lonstr, *heightstr, *tstampstr, *validstr, *tmp;
	time_t tstamp;
	int valid;
	double lat, lon, height __attribute__((unused));

	tmp = talloc_strdup(cmd, value);
	if (!tmp)
		return 1;

	tstampstr = strtok_r(tmp, ",", &saveptr);
	validstr = strtok_r(NULL, ",", &saveptr);
	latstr = strtok_r(NULL, ",", &saveptr);
	lonstr = strtok_r(NULL, ",", &saveptr);
	heightstr = strtok_r(NULL, "\0", &saveptr);

	if ((tstampstr == NULL) || (validstr == NULL) || (latstr == NULL) ||
			(lonstr == NULL) || (heightstr == NULL))
		goto err;

	tstamp = atol(tstampstr);
	valid = get_string_value(bts_loc_fix_names, validstr);
	lat = atof(latstr);
	lon = atof(lonstr);
	height = atof(heightstr);
	talloc_free(tmp);
	tmp = NULL;

	if (((tstamp == 0) && (valid != BTS_LOC_FIX_INVALID)) || (lat < -90) || (lat > 90) ||
			(lon < -180) || (lon > 180) || (valid < 0)) {
		goto err;
	}

	return 0;

err:
	talloc_free(tmp);
	cmd->reply = talloc_strdup(cmd, "The format is <unixtime>,(invalid|fix2d|fix3d),<lat>,<lon>,<height>");
	return 1;
}

CTRL_CMD_DEFINE(net_timezone, "timezone");
static int get_net_timezone(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_network *net = (struct gsm_network*)cmd->node;

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
	struct gsm_network *net = (struct gsm_network*)cmd->node;
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
	llist_for_each_entry(msc, &net->bsc_data->mscs, entry) {
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
		generate_location_state_trap(bts, msc->data);

	return 0;
}

int bsc_ctrl_cmds_install(struct gsm_network *net)
{
	int rc;

	rc = bsc_base_ctrl_cmds_install();
	if (rc)
		goto end;
	rc = ctrl_cmd_install(CTRL_NODE_BTS, &cmd_bts_loc);
	if (rc)
		goto end;
	rc = ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_timezone);
	if (rc)
		goto end;
	rc = ctrl_cmd_install(CTRL_NODE_MSC, &cmd_msc_connection_status);
	if (rc)
		goto end;
	rc = ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_msc0_connection_status);
	if (rc)
		goto end;
	rc = osmo_signal_register_handler(SS_MSC, &msc_connection_status_trap_cb, net);
	if (rc)
		goto end;
	rc = osmo_signal_register_handler(SS_MSC, msc_signal_handler, NULL);
	if (rc)
		goto end;
	rc = ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_bts_connection_status);
	if (rc)
		goto end;
	rc = ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_notification);
	if (rc)
		goto end;
	rc = ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_inform_msc);
	if (rc)
		goto end;
	rc = osmo_signal_register_handler(SS_L_INPUT, &bts_connection_status_trap_cb, net);

end:
	return rc;
}
