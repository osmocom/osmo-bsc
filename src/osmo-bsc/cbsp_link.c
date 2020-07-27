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

#include <osmocom/core/talloc.h>
#include <osmocom/core/socket.h>
#include <osmocom/gsm/cbsp.h>

/* if a CBC IP/port has been configured, we continuously try to re-establish the TCP
 * connection (as a client) to the CBC.  If none has been configured, and we have a listen
 * TCP port, we expect the CBC to connect to us.  If neither of the two is configured,
 * CBSP is effectively disabled */

/*********************************************************************************
 * CBSP Server (inbound TCP connection from CBC)
 *********************************************************************************/

static int cbsp_srv_closed_cb(struct osmo_stream_srv *conn)
{
	struct bsc_cbc_link *cbc = osmo_stream_srv_get_data(conn);
	//struct osmo_fd *ofd = osmo_stream_srv_get_ofd(conn);

	LOGP(DCBS, LOGL_NOTICE, "CBSP Server lost connection from %s\n", cbc->server.sock_name);
	talloc_free(cbc->server.sock_name);
	cbc->server.sock_name = NULL;
	cbc->server.srv = NULL;
	return 0;
}

static int cbsp_srv_cb(struct osmo_stream_srv *conn)
{
	struct bsc_cbc_link *cbc = osmo_stream_srv_get_data(conn);
	struct osmo_fd *ofd = osmo_stream_srv_get_ofd(conn);
	struct osmo_cbsp_decoded *decoded;
	struct msgb *msg;
	int rc;

	/* READ */
	rc = osmo_cbsp_recv_buffered(cbc, ofd->fd, &msg, &cbc->server.msg);
	if (rc <= 0) {
		if (rc == -EAGAIN || rc == -EINTR) {
			/* more data needs to be read */
			return 0;
		} else if (rc == -EPIPE || rc == -ECONNRESET) {
			/* lost connection */
		} else if (rc == 0) {
			/* connection closed */
		}
		osmo_stream_srv_destroy(conn);
		cbc->server.srv = NULL;
		return -EBADF;
	}
	OSMO_ASSERT(msg);
	decoded = osmo_cbsp_decode(conn, msg);
	if (decoded) {
		LOGP(DCBS, LOGL_DEBUG, "Received CBSP %s\n",
			get_value_string(cbsp_msg_type_names, decoded->msg_type));
		cbsp_rx_decoded(cbc, decoded);
		talloc_free(decoded);
	} else {
		LOGP(DCBS, LOGL_ERROR, "Unable to decode CBSP %s: '%s'\n",
			msgb_hexdump(msg), osmo_cbsp_errstr);
	}
	msgb_free(msg);
	return 0;

}

static int cbsp_srv_link_accept_cb(struct osmo_stream_srv_link *link, int fd)
{
	struct bsc_cbc_link *cbc = osmo_stream_srv_link_get_data(link);
	struct osmo_stream_srv *srv;

	LOGP(DCBS, LOGL_INFO, "CBSP Server received inbound connection from CBC: %s\n",
		osmo_sock_get_name2(fd));

	if (cbc->server.srv) {
		LOGP(DCBS, LOGL_NOTICE, "CBSP Server refusing further connection (%s) "
		     "while we already have another connection (%s)\n",
		     osmo_sock_get_name2(fd), cbc->server.sock_name);
		return -1;
	}

	srv = osmo_stream_srv_create(cbc, link, fd, cbsp_srv_cb, cbsp_srv_closed_cb, cbc);
	if (!srv) {
		LOGP(DCBS, LOGL_ERROR, "Unable to create stream server for %s\n",
			osmo_sock_get_name2(fd));
		return -1;
	}

	cbc->server.srv = srv;
	if (cbc->server.sock_name)
		talloc_free(cbc->server.sock_name);
	cbc->server.sock_name = osmo_sock_get_name(cbc, fd);
	LOGP(DCBS, LOGL_NOTICE, "CBSP Server link established from CBC %s\n", cbc->server.sock_name);
	/* TODO: introduce ourselves to the peer using some osmcoom extensions */
	cbsp_tx_restart(cbc, false);
	return 0;
}

/*********************************************************************************
 * CBSP Client (outbound TCP connection to CBC)
 *********************************************************************************/

static int cbsp_client_connect_cb(struct osmo_stream_cli *cli)
{
	struct bsc_cbc_link *cbc = osmo_stream_cli_get_data(cli);
	struct osmo_fd *ofd = osmo_stream_cli_get_ofd(cli);

	if (cbc->client.sock_name)
		talloc_free(cbc->client.sock_name);
	cbc->client.sock_name = osmo_sock_get_name(cbc, ofd->fd);

	LOGP(DCBS, LOGL_NOTICE, "CBSP Client connected to CBC: %s\n", cbc->client.sock_name);

	/* TODO: introduce ourselves to the peer using some osmcoom extensions */
	cbsp_tx_restart(cbc, false);

	return 0;
}

static int cbsp_client_disconnect_cb(struct osmo_stream_cli *cli)
{
	struct bsc_cbc_link *cbc = osmo_stream_cli_get_data(cli);

	LOGP(DCBS, LOGL_NOTICE, "CBSP Client lost connection to %s\n", cbc->client.sock_name);
	talloc_free(cbc->client.sock_name);
	cbc->client.sock_name = NULL;
	return 0;
}

static int cbsp_client_read_cb(struct osmo_stream_cli *cli)
{
	struct bsc_cbc_link *cbc = osmo_stream_cli_get_data(cli);
	struct osmo_fd *ofd = osmo_stream_cli_get_ofd(cli);
	struct osmo_cbsp_decoded *decoded;
	struct msgb *msg = NULL;
	int rc;

	/* READ */
	rc = osmo_cbsp_recv_buffered(cbc, ofd->fd, &msg, &cbc->client.msg);
	if (rc <= 0) {
		if (rc == -EAGAIN || rc == -EINTR) {
			/* more data needs to be read */
			return 0;
		} else if (rc == -EPIPE || rc == -ECONNRESET) {
			/* lost connection */
		} else if (rc == 0) {
			/* connection closed */
		}
		osmo_stream_cli_reconnect(cli);
		return -EBADF;
	}
	OSMO_ASSERT(msg);
	decoded = osmo_cbsp_decode(cli, msg);
	if (decoded) {
		LOGP(DCBS, LOGL_DEBUG, "Received CBSP %s\n",
			get_value_string(cbsp_msg_type_names, decoded->msg_type));
		cbsp_rx_decoded(cbc, decoded);
		talloc_free(decoded);
	} else {
		LOGP(DCBS, LOGL_ERROR, "Unable to decode CBSP %s: '%s'\n",
			msgb_hexdump(msg), osmo_cbsp_errstr);
	}
	msgb_free(msg);
	return 0;
}

int bsc_cbc_link_restart(void)
{
	struct bsc_cbc_link *cbc = bsc_gsmnet->cbc;

	/* shut down client, if no longer configured */
	if (cbc->client.cli && !cbc->config.cbc_hostname) {
		LOGP(DCBS, LOGL_NOTICE, "Stopping CBSP client\n");
		osmo_stream_cli_close(cbc->client.cli);
		osmo_stream_cli_destroy(cbc->client.cli);
		cbc->client.cli = NULL;
	}

	/* shut down server, if no longer configured */
	if (cbc->config.listen_port == -1) {
		if (cbc->server.srv || cbc->server.link)
			LOGP(DCBS, LOGL_NOTICE, "Stopping CBSP server\n");
		if (cbc->server.srv) {
			osmo_stream_srv_destroy(cbc->server.srv);
			cbc->server.srv = NULL;
		}
		if (cbc->server.link) {
			osmo_stream_srv_link_close(cbc->server.link);
			osmo_stream_srv_link_destroy(cbc->server.link);
			cbc->server.link = NULL;
		}
	}

	/* start client, if configured */
	if (cbc->config.cbc_hostname) {
		LOGP(DCBS, LOGL_NOTICE, "Starting CBSP Client (to CBC at %s:%u)\n",
			cbc->config.cbc_hostname, cbc->config.cbc_port);
		if (!cbc->client.cli) {
			cbc->client.cli = osmo_stream_cli_create(cbc);
			osmo_stream_cli_set_data(cbc->client.cli, cbc);
			osmo_stream_cli_set_connect_cb(cbc->client.cli, cbsp_client_connect_cb);
			osmo_stream_cli_set_disconnect_cb(cbc->client.cli, cbsp_client_disconnect_cb);
			osmo_stream_cli_set_read_cb(cbc->client.cli, cbsp_client_read_cb);
		}
		/* CBC side */
		osmo_stream_cli_set_addr(cbc->client.cli, cbc->config.cbc_hostname);
		osmo_stream_cli_set_port(cbc->client.cli, cbc->config.cbc_port);
		/* Close/Reconnect? */
		osmo_stream_cli_open(cbc->client.cli);
	}

	/* start server, if configured */
	if (cbc->config.listen_port != -1) {
		LOGP(DCBS, LOGL_NOTICE, "Starting CBSP Server (bound to %s:%u)\n",
			cbc->config.listen_hostname, cbc->config.listen_port);
		if (!cbc->server.link) {
			LOGP(DCBS, LOGL_NOTICE, "Creating CBSP Server\n");
			cbc->server.link = osmo_stream_srv_link_create(cbc);
			osmo_stream_srv_link_set_data(cbc->server.link, cbc);
			osmo_stream_srv_link_set_accept_cb(cbc->server.link, cbsp_srv_link_accept_cb);

			osmo_stream_srv_link_set_addr(cbc->server.link, cbc->config.listen_hostname);
			osmo_stream_srv_link_set_port(cbc->server.link, cbc->config.listen_port);

			if (osmo_stream_srv_link_open(cbc->server.link) < 0) {
				LOGP(DCBS, LOGL_ERROR, "Cannot open CBSP Server link on %s:%u\n",
				     cbc->config.listen_hostname, cbc->config.listen_port);
			}
		}
	}
	return 0;
}

/*! Encode + Transmit a 'decoded' CBSP message over given CBC link
 *  \param[in] cbc Data structure representing the BSCs link to the CBC
 *  \param[in] cbsp Decoded CBSP message to be transmitted. Ownership is transferred.
 *  \return 0 on success, negative otherwise */
int cbsp_tx_decoded(struct bsc_cbc_link *cbc, struct osmo_cbsp_decoded *cbsp)
{
	struct msgb *msg;

	msg = osmo_cbsp_encode(cbc, cbsp);
	if (!msg) {
		LOGP(DCBS, LOGL_ERROR, "Unable to encode CBSP Message Type %s: %s\n",
			get_value_string(cbsp_msg_type_names, cbsp->msg_type), osmo_cbsp_errstr);
		talloc_free(cbsp);
		return -1;
	}
	if (cbc->client.cli)
		osmo_stream_cli_send(cbc->client.cli, msg);
	else if (cbc->server.srv)
		osmo_stream_srv_send(cbc->server.srv, msg);
	else {
		LOGP(DCBS, LOGL_ERROR, "Discarding CBSP Message, link is down: %s\n", msgb_hexdump(msg));
		msgb_free(msg);
	}

	talloc_free(cbsp);
	return 0;
}

static struct bsc_cbc_link *vty_cbc_data(struct vty *vty)
{
	return bsc_gsmnet->cbc;
}

/*********************************************************************************
 * VTY Interface (Configuration + Introspection)
 *********************************************************************************/

DEFUN(cfg_cbc, cfg_cbc_cmd,
	"cbc", "Configure CBSP Link to Cell Broadcast Centre\n")
{
	vty->node = CBC_NODE;
	return CMD_SUCCESS;
}

DEFUN(cfg_cbc_remote_ip, cfg_cbc_remote_ip_cmd,
	"remote-ip A.B.C.D",
	"IP Address of the Cell Broadcast Centre\n"
	"IP Address of the Cell Broadcast Centre\n")
{
	struct bsc_cbc_link *cbc = vty_cbc_data(vty);
	osmo_talloc_replace_string(cbc, &cbc->config.cbc_hostname, argv[0]);
	return CMD_SUCCESS;
}
DEFUN(cfg_cbc_no_remote_ip, cfg_cbc_no_remote_ip_cmd,
	"no remote-ip",
	NO_STR "Remove IP address of CBC; disables outbound CBSP connections\n")
{
	struct bsc_cbc_link *cbc = vty_cbc_data(vty);
	talloc_free(cbc->config.cbc_hostname);
	cbc->config.cbc_hostname = NULL;
	return CMD_SUCCESS;
}

DEFUN(cfg_cbc_remote_port, cfg_cbc_remote_port_cmd,
	"remote-port <1-65535>",
	"TCP Port number of the Cell Broadcast Centre (Default: 48049)\n"
	"TCP Port number of the Cell Broadcast Centre (Default: 48049)\n")
{
	struct bsc_cbc_link *cbc = vty_cbc_data(vty);
	cbc->config.cbc_port = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_cbc_listen_port, cfg_cbc_listen_port_cmd,
	"listen-port <1-65535>",
	"Local TCP port at which BSC listens for incoming CBSP connections from CBC\n"
	"Local TCP port at which BSC listens for incoming CBSP connections from CBC\n")
{
	struct bsc_cbc_link *cbc = vty_cbc_data(vty);
	cbc->config.listen_port = atoi(argv[0]);
	return CMD_SUCCESS;
}
DEFUN(cfg_cbc_no_listen_port, cfg_cbc_no_listen_port_cmd,
	"no listen-port",
	NO_STR "Remove CBSP Listen Port; disables inbound CBSP connections\n")
{
	struct bsc_cbc_link *cbc = vty_cbc_data(vty);
	cbc->config.listen_port = -1;
	return CMD_SUCCESS;
}

DEFUN(cfg_cbc_listen_ip, cfg_cbc_listen_ip_cmd,
	"listen-ip A.B.C.D",
	"Local IP Address where BSC listens for incoming CBC connections (Default: 0.0.0.0)\n"
	"Local IP Address where BSC listens for incoming CBC connections\n")
{
	struct bsc_cbc_link *cbc = vty_cbc_data(vty);
	osmo_talloc_replace_string(cbc, &cbc->config.listen_hostname, argv[0]);
	return CMD_SUCCESS;
}

static struct cmd_node cbc_node = {
	CBC_NODE,
	"%s(config-cbc)# ",
	1,
};

static int config_write_cbc(struct vty *vty)
{
	struct bsc_cbc_link *cbc = vty_cbc_data(vty);

	vty_out(vty, "cbc%s", VTY_NEWLINE);

	if (cbc->config.cbc_hostname) {
		vty_out(vty, " remote-ip %s%s", cbc->config.cbc_hostname, VTY_NEWLINE);
		vty_out(vty, " remote-port %u%s", cbc->config.cbc_port, VTY_NEWLINE);
	} else
		vty_out(vty, " no remote-ip%s", VTY_NEWLINE);

	if (cbc->config.listen_port >= 0) {
		vty_out(vty, " listen-port %u%s", cbc->config.listen_port, VTY_NEWLINE);
		vty_out(vty, " listen-ip %s%s", cbc->config.listen_hostname, VTY_NEWLINE);
	} else
		vty_out(vty, " no listen-port%s", VTY_NEWLINE);

	return 0;
}

DEFUN(show_cbc, show_cbc_cmd,
	"show cbc",
	SHOW_STR "Display state of CBC / CBSP\n")
{
	struct bsc_cbc_link *cbc = vty_cbc_data(vty);

	if (!cbc->config.cbc_hostname)
		vty_out(vty, "CBSP Client Config: Disabled%s", VTY_NEWLINE);
	else {
		vty_out(vty, "CBSP Client Config: CBC IP=%s, CBC Port=%u%s",
			cbc->config.cbc_hostname, cbc->config.cbc_port, VTY_NEWLINE);
		vty_out(vty, "CBSP Client Connection: %s%s",
			cbc->client.sock_name ? cbc->client.sock_name : "Disconnected", VTY_NEWLINE);
	}
	if (cbc->config.listen_port < 0)
		vty_out(vty, "CBSP Server Config: Disabled%s\n", VTY_NEWLINE);
	else {
		vty_out(vty, "CBSP Server Config: Listen IP=%s, Port=%u%s\n",
			cbc->config.listen_hostname, cbc->config.listen_port, VTY_NEWLINE);
		vty_out(vty, "CBSP Server Connection: %s%s",
			cbc->server.sock_name ? cbc->server.sock_name : "Disconnected", VTY_NEWLINE);
	}
	return CMD_SUCCESS;
}

void cbc_vty_init(void)
{
	install_element(VIEW_NODE, &show_cbc_cmd);
	install_element(CONFIG_NODE, &cfg_cbc_cmd);
	install_node(&cbc_node, config_write_cbc);
	install_element(CBC_NODE, &cfg_cbc_remote_ip_cmd);
	install_element(CBC_NODE, &cfg_cbc_no_remote_ip_cmd);
	install_element(CBC_NODE, &cfg_cbc_remote_port_cmd);
	install_element(CBC_NODE, &cfg_cbc_listen_port_cmd);
	install_element(CBC_NODE, &cfg_cbc_no_listen_port_cmd);
	install_element(CBC_NODE, &cfg_cbc_listen_ip_cmd);
}
