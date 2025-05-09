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

const struct value_string bsc_cbc_link_mode_names[] = {
	{ BSC_CBC_LINK_MODE_DISABLED, "disabled" },
	{ BSC_CBC_LINK_MODE_SERVER, "server" },
	{ BSC_CBC_LINK_MODE_CLIENT, "client" },
	{}
};

const struct osmo_sockaddr_str bsc_cbc_default_server_local_addr = {
	.af = AF_INET,
	.ip = "127.0.0.1",
	.port = CBSP_TCP_PORT,
};

/*********************************************************************************
 * CBSP Server (inbound TCP connection from CBC)
 *********************************************************************************/

static int cbsp_srv_closed_cb(struct osmo_stream_srv *conn)
{
	struct bsc_cbc_link *cbc = osmo_stream_srv_get_data(conn);

	LOGP(DCBS, LOGL_NOTICE, "CBSP Server lost connection from %s\n", cbc->server.sock_name);
	talloc_free(cbc->server.sock_name);
	cbc->server.sock_name = NULL;
	cbc->server.srv = NULL;
	return 0;
}

static int cbsp_srv_read_cb(struct osmo_stream_srv *conn, int res, struct msgb *msg)
{
	struct bsc_cbc_link *cbc = osmo_stream_srv_get_data(conn);
	struct osmo_cbsp_decoded *decoded;

	if (res <= 0) {
		if (res == -EAGAIN || res == -EINTR) {
			msgb_free(msg);
			return 0;
		}
		/*
		if (rc == -EPIPE || rc == -ECONNRESET) {
			// lost connection
		} else if (rc == 0) {
			// connection closed
		} */
		msgb_free(msg);
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

	srv = osmo_stream_srv_create2(cbc, link, fd, cbc);
	if (!srv) {
		LOGP(DCBS, LOGL_ERROR, "Unable to create stream server for %s\n",
			osmo_sock_get_name2(fd));
		return -1;
	}
	osmo_stream_srv_set_name(srv, "cbsp");
	osmo_stream_srv_set_read_cb(srv, cbsp_srv_read_cb);
	osmo_stream_srv_set_closed_cb(srv, cbsp_srv_closed_cb);
	osmo_stream_srv_set_segmentation_cb(srv, osmo_cbsp_segmentation_cb);

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

	if (cbc->client.sock_name)
		talloc_free(cbc->client.sock_name);
	cbc->client.sock_name = osmo_sock_get_name(cbc, osmo_stream_cli_get_fd(cli));

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

static int cbsp_client_read_cb(struct osmo_stream_cli *cli, int res, struct msgb *msg)
{
	struct bsc_cbc_link *cbc = osmo_stream_cli_get_data(cli);
	struct osmo_cbsp_decoded *decoded;

	if (res <= 0) {
		if (res == -EAGAIN || res == -EINTR) {
			msgb_free(msg);
			return 0;
		}
		/*
		if (rc == -EPIPE || rc == -ECONNRESET) {
			// lost connection
		} else if (rc == 0) {
			// connection closed
		} */
		msgb_free(msg);
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
	if (cbc->client.cli && cbc->mode != BSC_CBC_LINK_MODE_CLIENT) {
		LOGP(DCBS, LOGL_NOTICE, "Stopping CBSP client\n");
		osmo_stream_cli_close(cbc->client.cli);
		osmo_stream_cli_destroy(cbc->client.cli);
		cbc->client.cli = NULL;
	}

	/* shut down server, if no longer configured */
	if (cbc->mode != BSC_CBC_LINK_MODE_SERVER) {
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

	switch (cbc->mode) {
	case BSC_CBC_LINK_MODE_CLIENT:
		if (!osmo_sockaddr_str_is_nonzero(&cbc->client.remote_addr)) {
			LOGP(DCBS, LOGL_ERROR,
			     "Cannot start CBSP in client mode: invalid remote-ip or -port in 'cbc' / 'client')\n");
			return -1;
		}

		LOGP(DCBS, LOGL_NOTICE, "Starting CBSP Client (to CBC at " OSMO_SOCKADDR_STR_FMT ")\n",
		     OSMO_SOCKADDR_STR_FMT_ARGS(&cbc->client.remote_addr));
		if (!cbc->client.cli) {
			cbc->client.cli = osmo_stream_cli_create(cbc);
			OSMO_ASSERT(cbc->client.cli);
			osmo_stream_cli_set_name(cbc->client.cli, "cbsp");
			osmo_stream_cli_set_data(cbc->client.cli, cbc);
			osmo_stream_cli_set_connect_cb(cbc->client.cli, cbsp_client_connect_cb);
			osmo_stream_cli_set_disconnect_cb(cbc->client.cli, cbsp_client_disconnect_cb);
			osmo_stream_cli_set_read_cb2(cbc->client.cli, cbsp_client_read_cb);
			osmo_stream_cli_set_segmentation_cb(cbc->client.cli, osmo_cbsp_segmentation_cb);
		}
		/* CBC side */
		osmo_stream_cli_set_addr(cbc->client.cli, cbc->client.remote_addr.ip);
		osmo_stream_cli_set_port(cbc->client.cli, cbc->client.remote_addr.port);
		/* local side */
		if (osmo_sockaddr_str_is_set(&cbc->client.local_addr)) {
			osmo_stream_cli_set_local_addr(cbc->client.cli, cbc->client.local_addr.ip);
			osmo_stream_cli_set_local_port(cbc->client.cli, cbc->client.local_addr.port);
		}
		/* Close/Reconnect? */
		if (osmo_stream_cli_open(cbc->client.cli) < 0) {
			LOGP(DCBS, LOGL_ERROR, "Cannot open CBSP client link to " OSMO_SOCKADDR_STR_FMT "\n",
			     OSMO_SOCKADDR_STR_FMT_ARGS(&cbc->client.remote_addr));
			return -1;
		}
		return 0;

	case BSC_CBC_LINK_MODE_SERVER:
		if (!osmo_sockaddr_str_is_set(&cbc->server.local_addr)) {
			LOGP(DCBS, LOGL_ERROR,
			     "Cannot start CBSP in server mode: invalid local-ip or -port in 'cbc' / 'server')\n");
			return -1;
		}
		LOGP(DCBS, LOGL_NOTICE, "Starting CBSP Server (listening at " OSMO_SOCKADDR_STR_FMT ")\n",
		     OSMO_SOCKADDR_STR_FMT_ARGS(&cbc->server.local_addr));
		if (!cbc->server.link) {
			LOGP(DCBS, LOGL_NOTICE, "Creating CBSP Server\n");
			cbc->server.link = osmo_stream_srv_link_create(cbc);
			OSMO_ASSERT(cbc->server.link);
			osmo_stream_srv_link_set_name(cbc->server.link, "cbsp");
			osmo_stream_srv_link_set_data(cbc->server.link, cbc);
			osmo_stream_srv_link_set_accept_cb(cbc->server.link, cbsp_srv_link_accept_cb);

			osmo_stream_srv_link_set_addr(cbc->server.link, cbc->server.local_addr.ip);
			osmo_stream_srv_link_set_port(cbc->server.link, cbc->server.local_addr.port);

			if (osmo_stream_srv_link_open(cbc->server.link) < 0) {
				LOGP(DCBS, LOGL_ERROR, "Cannot open CBSP Server link at " OSMO_SOCKADDR_STR_FMT ")\n",
				     OSMO_SOCKADDR_STR_FMT_ARGS(&cbc->server.local_addr));
				return -1;
			}
		}
		return 0;

	default:
		return 0;
	}
}

/*! Encode + Transmit a 'decoded' CBSP message over given CBC link
 *  \param[in] cbc Data structure representing the BSCs link to the CBC
 *  \param[in] cbsp Decoded CBSP message to be transmitted. Ownership is transferred.
 *  \return 0 on success, negative otherwise */
int cbsp_tx_decoded(struct bsc_cbc_link *cbc, struct osmo_cbsp_decoded *cbsp)
{
	struct msgb *msg;

	if (!cbc->client.cli && !cbc->server.srv) {
		LOGP(DCBS, LOGL_INFO, "Discarding Tx CBSP Message Type %s, link is down\n",
			 get_value_string(cbsp_msg_type_names, cbsp->msg_type));
		talloc_free(cbsp);
		return 0;
	}

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

	talloc_free(cbsp);
	return 0;
}
