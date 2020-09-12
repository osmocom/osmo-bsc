/* (C) 2017 by Sysmocom s.f.m.c. GmbH
 * All Rights Reserved
 *
 * Author: Philipp Maier
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

#pragma once

#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/bsc_msc_data.h>

/* Allocate resources to make a new connection oriented sigtran connection
 * (not the connection ittself!) */
enum bsc_con osmo_bsc_sigtran_new_conn(struct gsm_subscriber_connection *conn, struct bsc_msc_data *msc);
struct gsm_subscriber_connection *bsc_conn_by_bsub(struct bsc_subscr *bsub);

/* Open a new connection oriented sigtran connection */
int osmo_bsc_sigtran_open_conn(struct gsm_subscriber_connection *conn, struct msgb *msg);

/* Send data to MSC */
int osmo_bsc_sigtran_send(struct gsm_subscriber_connection *conn, struct msgb *msg);

/* Initialize osmo sigtran backhaul */
int osmo_bsc_sigtran_init(struct llist_head *mscs);

/* Close all open sigtran connections and channels */
void osmo_bsc_sigtran_reset(const struct bsc_msc_data *msc);

/* Send reset-ack to MSC */
void osmo_bsc_sigtran_tx_reset_ack(const struct bsc_msc_data *msc);

/* receive + process a CTRL command from the piggy-back on the IPA/SCCPlite link */
int bsc_sccplite_rx_ctrl(struct osmo_ss7_asp *asp, struct msgb *msg);

/* receive + process a MGCP message from the piggy-back on the IPA/SCCPlite link */
int bsc_sccplite_rx_mgcp(struct osmo_ss7_asp *asp, struct msgb *msg);

/* send a message via SCCPLite to given MSC */
int bsc_sccplite_msc_send(struct bsc_msc_data *msc, struct msgb *msg);

/* we received some data on the UDP proxy socket from the MGW. Pass it to MSC via IPA */
int bsc_sccplite_mgcp_proxy_cb(struct osmo_fd *ofd, unsigned int what);
