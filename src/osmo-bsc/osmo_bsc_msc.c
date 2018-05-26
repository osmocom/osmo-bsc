/*
 * Handle the connection to the MSC. This include ping/timeout/reconnect
 * (C) 2008-2018 by Harald Welte <laforge@gnumonks.org>
 * (C) 2009-2015 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009-2015 by On-Waves
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
#include <osmocom/ctrl/control_if.h>
#include <osmocom/crypt/auth.h>
#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/ipaccess.h>
#include <osmocom/bsc/bsc_msc_data.h>
#include <osmocom/bsc/osmo_bsc_sigtran.h>
#include <osmocom/bsc/signal.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/socket.h>

#include <osmocom/gsm/gsm0808.h>

#include <osmocom/abis/ipa.h>

#include <osmocom/mgcp_client/mgcp_client.h>

#include <sys/socket.h>
#include <netinet/tcp.h>
#include <unistd.h>

int osmo_bsc_msc_init(struct bsc_msc_data *msc)
{
	struct gsm_network *net = msc->network;
	uint16_t mgw_port;
	int rc;

	/* FIXME: This is a leftover from the old architecture that used
	 * sccp-lite with osmocom specific authentication. Since we now
	 * changed to AoIP the connected status and the authentication
	 * status is managed differently. However osmo_bsc_filter.c still
	 * needs the flags to be set to one. See also: OS#3112 */
	msc->is_authenticated = 1;

	if (net->mgw.conf->remote_port == -1)
		mgw_port = 2427;
	else
		mgw_port = net->mgw.conf->remote_port;

	rc = osmo_sock_init2_ofd(&msc->mgcp_ipa.ofd, AF_INET, SOCK_DGRAM, IPPROTO_UDP,
				 msc->mgcp_ipa.local_addr, msc->mgcp_ipa.local_port,
				 net->mgw.conf->remote_addr, mgw_port,
				 OSMO_SOCK_F_BIND | OSMO_SOCK_F_CONNECT);
	if (rc < 0) {
		LOGP(DMSC, LOGL_ERROR, "msc %u: Could not create/connect/bind MGCP proxy socket: %d\n",
			msc->nr, rc);
		return rc;
	}

	return 0;
}

struct bsc_msc_data *osmo_msc_data_find(struct gsm_network *net, int nr)
{
	struct bsc_msc_data *msc_data;

	llist_for_each_entry(msc_data, &net->bsc_data->mscs, entry)
		if (msc_data->nr == nr)
			return msc_data;
	return NULL;
}

struct bsc_msc_data *osmo_msc_data_alloc(struct gsm_network *net, int nr)
{
	struct bsc_msc_data *msc_data;
	unsigned int i;

	/* check if there is already one */
	msc_data = osmo_msc_data_find(net, nr);
	if (msc_data)
		return msc_data;

	msc_data = talloc_zero(net, struct bsc_msc_data);
	if (!msc_data)
		return NULL;

	llist_add_tail(&msc_data->entry, &net->bsc_data->mscs);

	/* Init back pointer */
	msc_data->network = net;

	msc_data->core_plmn = (struct osmo_plmn_id){
		.mcc = GSM_MCC_MNC_INVALID,
		.mnc = GSM_MCC_MNC_INVALID,
	};
	msc_data->core_ci = -1;
	msc_data->core_lac = -1;
	msc_data->rtp_base = 4000;

	msc_data->nr = nr;
	msc_data->allow_emerg = 1;
	msc_data->a.asp_proto = OSMO_SS7_ASP_PROT_M3UA;

	/* Defaults for the audio setup */
	msc_data->amr_conf.m5_90 = 1;

	/* Allow the full set of possible codecs by default */
	msc_data->audio_length = 5;
	msc_data->audio_support =
	    talloc_zero_array(msc_data, struct gsm_audio_support *,
			      msc_data->audio_length);
	for (i = 0; i < msc_data->audio_length; i++) {
		msc_data->audio_support[i] =
		    talloc_zero(msc_data->audio_support,
				struct gsm_audio_support);
	}
	msc_data->audio_support[0]->ver = 1;
	msc_data->audio_support[0]->hr = 0;
	msc_data->audio_support[1]->ver = 1;
	msc_data->audio_support[1]->hr = 1;
	msc_data->audio_support[2]->ver = 2;
	msc_data->audio_support[2]->hr = 0;
	msc_data->audio_support[3]->ver = 3;
	msc_data->audio_support[3]->hr = 0;
	msc_data->audio_support[4]->ver = 3;
	msc_data->audio_support[4]->hr = 1;

	osmo_fd_setup(&msc_data->mgcp_ipa.ofd, -1, BSC_FD_READ, &bsc_sccplite_mgcp_proxy_cb, msc_data, 0);
	msc_data->mgcp_ipa.local_addr = talloc_strdup(msc_data, "0.0.0.0");
	msc_data->mgcp_ipa.local_port = 0; /* dynamic */

	return msc_data;
}

