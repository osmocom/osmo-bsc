/* CBSP (Cell Broadcast Service Protocol) Handling for OsmoBSC */
/*
 * (C) 2019 by Harald Welte <laforge@gnumonks.org>
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


#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/vty.h>
#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/smscb.h>
#include <osmocom/bsc/bsc_msc_data.h>
#include <osmocom/bsc/bts.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/socket.h>
#include <osmocom/gsm/cbsp.h>

/*********************************************************************************
 * cbc
 *********************************************************************************/
static struct bsc_cbc_link *vty_cbc_data(struct vty *vty)
{
	return bsc_gsmnet->cbc;
}

DEFUN(cfg_cbc, cfg_cbc_cmd,
	"cbc", "Configure CBSP Link to Cell Broadcast Centre\n")
{
	vty->node = CBC_NODE;
	return CMD_SUCCESS;
}

DEFUN(cfg_cbc_mode, cfg_cbc_mode_cmd,
	"mode (server|client|disabled)",
	"Set OsmoBSC as CBSP server or client\n"
	"CBSP Server: listen for inbound TCP connections from a remote Cell Broadcast Centre\n"
	"CBSP Client: establish outbound TCP connection to a remote Cell Broadcast Centre\n"
	"Disable CBSP link\n")
{
	struct bsc_cbc_link *cbc = vty_cbc_data(vty);
	cbc->mode = get_string_value(bsc_cbc_link_mode_names, argv[0]);
	OSMO_ASSERT(cbc->mode >= 0);

	/* Immediately restart/stop CBSP only when coming from a telnet session. The settings from the config file take
	 * effect in osmo_bsc_main.c's invocation of bsc_cbc_link_restart(). */
	if (vty->type != VTY_FILE)
		bsc_cbc_link_restart();

	return CMD_SUCCESS;
}

DEFUN(cfg_cbc_server, cfg_cbc_server_cmd,
	"server", "Configure OsmoBSC's CBSP server role\n")
{
	vty->node = CBC_SERVER_NODE;
	return CMD_SUCCESS;
}

DEFUN(cfg_cbc_server_local_ip, cfg_cbc_server_local_ip_cmd,
	"local-ip " VTY_IPV46_CMD,
	"Set IP Address to listen on for inbound CBSP from a Cell Broadcast Centre\n"
	"IPv4 address\n" "IPv6 address\n")
{
	struct bsc_cbc_link *cbc = vty_cbc_data(vty);
	osmo_sockaddr_str_from_str(&cbc->server.local_addr, argv[0], cbc->server.local_addr.port);
	return CMD_SUCCESS;
}

DEFUN(cfg_cbc_server_local_port, cfg_cbc_server_local_port_cmd,
	"local-port <1-65535>",
	"Set TCP port to listen on for inbound CBSP from a Cell Broadcast Centre\n"
	"CBSP port number (Default: " OSMO_STRINGIFY_VAL(CBSP_TCP_PORT) ")\n")
{
	struct bsc_cbc_link *cbc = vty_cbc_data(vty);
	cbc->server.local_addr.port = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_cbc_client, cfg_cbc_client_cmd,
	"client", "Configure OsmoBSC's CBSP client role\n")
{
	vty->node = CBC_CLIENT_NODE;
	return CMD_SUCCESS;
}

DEFUN(cfg_cbc_client_remote_ip, cfg_cbc_client_remote_ip_cmd,
	"remote-ip " VTY_IPV46_CMD,
	"Set IP Address of the Cell Broadcast Centre, to establish CBSP link to\n"
	"IPv4 address\n" "IPv6 address\n")
{
	struct bsc_cbc_link *cbc = vty_cbc_data(vty);
	osmo_sockaddr_str_from_str(&cbc->client.remote_addr, argv[0], cbc->client.remote_addr.port);
	return CMD_SUCCESS;
}

DEFUN(cfg_cbc_client_remote_port, cfg_cbc_client_remote_port_cmd,
	"remote-port <1-65535>",
	"Set TCP port of the Cell Broadcast Centre, to establish CBSP link to\n"
	"CBSP port number (Default: " OSMO_STRINGIFY_VAL(CBSP_TCP_PORT) ")\n")
{
	struct bsc_cbc_link *cbc = vty_cbc_data(vty);
	cbc->client.remote_addr.port = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_cbc_client_local_ip, cfg_cbc_client_local_ip_cmd,
	"local-ip " VTY_IPV46_CMD,
	"Set local bind address for the outbound CBSP link to the Cell Broadcast Centre\n"
	"IPv4 address\n" "IPv6 address\n")
{
	struct bsc_cbc_link *cbc = vty_cbc_data(vty);
	osmo_sockaddr_str_from_str(&cbc->client.local_addr, argv[0], cbc->client.local_addr.port);
	return CMD_SUCCESS;
}

DEFUN(cfg_cbc_client_local_port, cfg_cbc_client_local_port_cmd,
	"local-port <1-65535>",
	"Set local bind port for the outbound CBSP link to the Cell Broadcast Centre\n"
	"port number\n")
{
	struct bsc_cbc_link *cbc = vty_cbc_data(vty);
	cbc->client.local_addr.port = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_cbc_client_no_local_ip, cfg_cbc_client_no_local_ip_cmd,
	"no local-ip",
	NO_STR "Remove local IP address bind config for the CBSP client mode\n")
{
	struct bsc_cbc_link *cbc = vty_cbc_data(vty);
	cbc->client.local_addr = (struct osmo_sockaddr_str){ .port = cbc->client.local_addr.port };
	return CMD_SUCCESS;
}

DEFUN(cfg_cbc_client_no_local_port, cfg_cbc_client_no_local_port_cmd,
	"no local-port",
	NO_STR "Remove local TCP port bind config for the CBSP client mode\n")
{
	struct bsc_cbc_link *cbc = vty_cbc_data(vty);
	cbc->client.local_addr.port = 0;
	return CMD_SUCCESS;
}

static struct cmd_node cbc_node = {
	CBC_NODE,
	"%s(config-cbc)# ",
	1,
};

static struct cmd_node cbc_server_node = {
	CBC_SERVER_NODE,
	"%s(config-cbc-server)# ",
	1,
};

static struct cmd_node cbc_client_node = {
	CBC_CLIENT_NODE,
	"%s(config-cbc-client)# ",
	1,
};

static int config_write_cbc(struct vty *vty)
{
	struct bsc_cbc_link *cbc = vty_cbc_data(vty);

	bool default_server_local;
	bool default_client_remote;
	bool default_client_local;

	default_server_local = !osmo_sockaddr_str_cmp(&cbc->server.local_addr,
						      &bsc_cbc_default_server_local_addr);
	default_client_remote = !osmo_sockaddr_str_is_set(&cbc->client.remote_addr);
	default_client_local = !osmo_sockaddr_str_is_set(&cbc->client.local_addr);

	/* If all reflects default values, skip the 'cbc' section */
	if (cbc->mode == BSC_CBC_LINK_MODE_DISABLED
	    && default_server_local
	    && default_client_remote && default_client_local)
		return 0;

	vty_out(vty, "cbc%s", VTY_NEWLINE);
	vty_out(vty, " mode %s%s", bsc_cbc_link_mode_name(cbc->mode), VTY_NEWLINE);

	if (!default_server_local) {
		vty_out(vty, " server%s", VTY_NEWLINE);

		if (strcmp(cbc->server.local_addr.ip, bsc_cbc_default_server_local_addr.ip))
			vty_out(vty, "  local-ip %s%s", cbc->server.local_addr.ip, VTY_NEWLINE);
		if (cbc->server.local_addr.port != bsc_cbc_default_server_local_addr.port)
			vty_out(vty, "  local-port %u%s", cbc->server.local_addr.port, VTY_NEWLINE);
	}

	if (!(default_client_remote && default_client_local)) {
		vty_out(vty, " client%s", VTY_NEWLINE);

		if (osmo_sockaddr_str_is_set(&cbc->client.remote_addr)) {
			vty_out(vty, "  remote-ip %s%s", cbc->client.remote_addr.ip, VTY_NEWLINE);
			if (cbc->client.remote_addr.port != CBSP_TCP_PORT)
				vty_out(vty, "  remote-port %u%s", cbc->client.remote_addr.port, VTY_NEWLINE);
		}

		if (cbc->client.local_addr.ip[0])
			vty_out(vty, "  local-ip %s%s", cbc->client.local_addr.ip, VTY_NEWLINE);
		if (cbc->client.local_addr.port)
			vty_out(vty, "  local-port %u%s", cbc->client.local_addr.port, VTY_NEWLINE);
	}

	return 0;
}

DEFUN(show_cbc, show_cbc_cmd,
	"show cbc",
	SHOW_STR "Display state of CBC / CBSP\n")
{
	struct bsc_cbc_link *cbc = vty_cbc_data(vty);

	switch (cbc->mode) {
	case BSC_CBC_LINK_MODE_DISABLED:
		vty_out(vty, "CBSP link is disabled%s", VTY_NEWLINE);
		break;

	case BSC_CBC_LINK_MODE_SERVER:
		vty_out(vty, "OsmoBSC is configured as CBSP Server on " OSMO_SOCKADDR_STR_FMT "%s",
			OSMO_SOCKADDR_STR_FMT_ARGS(&cbc->server.local_addr), VTY_NEWLINE);
		vty_out(vty, "CBSP Server Connection: %s%s",
			cbc->server.sock_name ? cbc->server.sock_name : "Disconnected", VTY_NEWLINE);
		break;

	case BSC_CBC_LINK_MODE_CLIENT:
		vty_out(vty, "OsmoBSC is configured as CBSP Client to remote CBC at " OSMO_SOCKADDR_STR_FMT "%s",
			OSMO_SOCKADDR_STR_FMT_ARGS(&cbc->client.remote_addr), VTY_NEWLINE);
		vty_out(vty, "CBSP Client Connection: %s%s",
			cbc->client.sock_name ? cbc->client.sock_name : "Disconnected", VTY_NEWLINE);
		break;
	}
	return CMD_SUCCESS;
}

/* --- Deprecated 'cbc' commands for backwards compat --- */

DEFUN_DEPRECATED(cfg_cbc_remote_ip, cfg_cbc_remote_ip_cmd,
	"remote-ip A.B.C.D",
	"IP Address of the Cell Broadcast Centre\n"
	"IP Address of the Cell Broadcast Centre\n")
{
	struct bsc_cbc_link *cbc = vty_cbc_data(vty);
	vty_out(vty, "%% cbc/remote-ip config is deprecated, instead use cbc/client/remote-ip and cbc/ mode%s",
		VTY_NEWLINE);
	osmo_sockaddr_str_from_str(&cbc->client.remote_addr, argv[0], cbc->client.remote_addr.port);
	cbc->mode = BSC_CBC_LINK_MODE_CLIENT;
	if (vty->type != VTY_FILE)
		bsc_cbc_link_restart();
	return CMD_SUCCESS;
}
DEFUN_DEPRECATED(cfg_cbc_no_remote_ip, cfg_cbc_no_remote_ip_cmd,
	"no remote-ip",
	NO_STR "Remove IP address of CBC; disables outbound CBSP connections\n")
{
	struct bsc_cbc_link *cbc = vty_cbc_data(vty);
	vty_out(vty, "%% cbc/remote-ip config is deprecated, instead use cbc/client/remote-ip and cbc/mode%s",
		VTY_NEWLINE);
	if (cbc->mode == BSC_CBC_LINK_MODE_CLIENT) {
		cbc->mode = BSC_CBC_LINK_MODE_DISABLED;
		if (vty->type != VTY_FILE)
			bsc_cbc_link_restart();
	}
	return CMD_SUCCESS;
}

DEFUN_DEPRECATED(cfg_cbc_remote_port, cfg_cbc_remote_port_cmd,
	"remote-port <1-65535>",
	"TCP Port number of the Cell Broadcast Centre (Default: 48049)\n"
	"TCP Port number of the Cell Broadcast Centre (Default: 48049)\n")
{
	struct bsc_cbc_link *cbc = vty_cbc_data(vty);
	vty_out(vty, "%% cbc/remote-port config is deprecated, instead use cbc/client/remote-port%s",
		VTY_NEWLINE);
	cbc->client.remote_addr.port = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN_DEPRECATED(cfg_cbc_listen_port, cfg_cbc_listen_port_cmd,
	"listen-port <1-65535>",
	"Local TCP port at which BSC listens for incoming CBSP connections from CBC\n"
	"Local TCP port at which BSC listens for incoming CBSP connections from CBC\n")
{
	struct bsc_cbc_link *cbc = vty_cbc_data(vty);
	vty_out(vty, "%% cbc/listen-port config is deprecated, instead use cbc/server/local-port and cbc/mode%s",
		VTY_NEWLINE);
	cbc->mode = BSC_CBC_LINK_MODE_SERVER;
	cbc->server.local_addr.port = atoi(argv[0]);
	if (vty->type != VTY_FILE)
		bsc_cbc_link_restart();
	return CMD_SUCCESS;
}

DEFUN_DEPRECATED(cfg_cbc_no_listen_port, cfg_cbc_no_listen_port_cmd,
	"no listen-port",
	NO_STR "Remove CBSP Listen Port; disables inbound CBSP connections\n")
{
	struct bsc_cbc_link *cbc = vty_cbc_data(vty);
	vty_out(vty, "%% cbc/listen-port config is deprecated, instead use cbc/server/local-port and cbc/mode%s",
		VTY_NEWLINE);
	if (cbc->mode == BSC_CBC_LINK_MODE_SERVER) {
		cbc->mode = BSC_CBC_LINK_MODE_DISABLED;
		if (vty->type != VTY_FILE)
			bsc_cbc_link_restart();
	}
	return CMD_SUCCESS;
}

DEFUN_DEPRECATED(cfg_cbc_listen_ip, cfg_cbc_listen_ip_cmd,
	"listen-ip A.B.C.D",
	"Local IP Address where BSC listens for incoming CBC connections (Default: 127.0.0.1)\n"
	"Local IP Address where BSC listens for incoming CBC connections\n")
{
	struct bsc_cbc_link *cbc = vty_cbc_data(vty);
	vty_out(vty, "%% cbc/listen-ip config is deprecated, instead use cbc/server/local-ip%s",
		VTY_NEWLINE);
	osmo_sockaddr_str_from_str(&cbc->server.local_addr, argv[0], cbc->server.local_addr.port);
	return CMD_SUCCESS;
}

void cbc_vty_init(void)
{
	install_element_ve(&show_cbc_cmd);

	install_element(CONFIG_NODE, &cfg_cbc_cmd);
	install_node(&cbc_node, config_write_cbc);
	install_element(CBC_NODE, &cfg_cbc_mode_cmd);

	install_element(CBC_NODE, &cfg_cbc_server_cmd);
	install_node(&cbc_server_node, NULL);
	install_element(CBC_SERVER_NODE, &cfg_cbc_server_local_ip_cmd);
	install_element(CBC_SERVER_NODE, &cfg_cbc_server_local_port_cmd);

	install_element(CBC_NODE, &cfg_cbc_client_cmd);
	install_node(&cbc_client_node, NULL);
	install_element(CBC_CLIENT_NODE, &cfg_cbc_client_remote_ip_cmd);
	install_element(CBC_CLIENT_NODE, &cfg_cbc_client_remote_port_cmd);
	install_element(CBC_CLIENT_NODE, &cfg_cbc_client_local_ip_cmd);
	install_element(CBC_CLIENT_NODE, &cfg_cbc_client_local_port_cmd);
	install_element(CBC_CLIENT_NODE, &cfg_cbc_client_no_local_ip_cmd);
	install_element(CBC_CLIENT_NODE, &cfg_cbc_client_no_local_port_cmd);

	/* Deprecated, for backwards compat */
	install_element(CBC_NODE, &cfg_cbc_remote_ip_cmd);
	install_element(CBC_NODE, &cfg_cbc_no_remote_ip_cmd);
	install_element(CBC_NODE, &cfg_cbc_remote_port_cmd);
	install_element(CBC_NODE, &cfg_cbc_listen_port_cmd);
	install_element(CBC_NODE, &cfg_cbc_no_listen_port_cmd);
	install_element(CBC_NODE, &cfg_cbc_listen_ip_cmd);
}


/*********************************************************************************
 * smscb
 *********************************************************************************/
static void vty_dump_smscb_chan_state(struct vty *vty, const struct bts_smscb_chan_state *cs)
{
	const struct bts_smscb_message *sm;

	vty_out(vty, "%s CBCH:%s", cs == &cs->bts->cbch_basic ? "BASIC" : "EXTENDED", VTY_NEWLINE);

	vty_out(vty, " MsgId | SerNo | Pg |      Category | Perd | #Tx  | #Req | DCS%s", VTY_NEWLINE);
	vty_out(vty, "-------|-------|----|---------------|------|------|------|----%s", VTY_NEWLINE);
	llist_for_each_entry(sm, &cs->messages, list) {
		vty_out(vty, "  %04x |  %04x | %2u | %13s | %4u | %4u | %4u | %02x%s",
			sm->input.msg_id, sm->input.serial_nr, sm->num_pages,
			get_value_string(cbsp_category_names, sm->input.category),
			sm->input.rep_period, sm->bcast_count, sm->input.num_bcast_req,
			sm->input.dcs, VTY_NEWLINE);
	}
	vty_out(vty, "%s", VTY_NEWLINE);
}

DEFUN(bts_show_cbs, bts_show_cbs_cmd,
	"show bts <0-255> smscb [(basic|extended)]",
	SHOW_STR "Display information about a BTS\n" "BTS number\n"
	"SMS Cell Broadcast State\n"
	"Show only information related to CBCH BASIC\n"
	"Show only information related to CBCH EXTENDED\n")
{
	struct gsm_network *net = gsmnet_from_vty(vty);
	int bts_nr = atoi(argv[0]);
	struct gsm_bts *bts;

	if (bts_nr >= net->num_bts) {
		vty_out(vty, "%% can't find BTS '%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}
	bts = gsm_bts_num(net, bts_nr);

	if (argc < 2 || !strcmp(argv[1], "basic"))
		vty_dump_smscb_chan_state(vty, &bts->cbch_basic);
	if (argc < 2 || !strcmp(argv[1], "extended"))
		vty_dump_smscb_chan_state(vty, &bts->cbch_extended);

	return CMD_SUCCESS;
}

void smscb_vty_init(void)
{
	install_element_ve(&bts_show_cbs_cmd);
}
