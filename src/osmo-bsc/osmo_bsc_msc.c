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
#include <osmocom/bsc/bts.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/socket.h>

#include <osmocom/gsm/gsm0808.h>
#include <osmocom/gsm/gsm23236.h>

#include <osmocom/abis/ipa.h>

#include <osmocom/mgcp_client/mgcp_client.h>

#include <sys/socket.h>
#include <netinet/tcp.h>
#include <unistd.h>

static const struct rate_ctr_desc msc_ctr_description[] = {
	/* Rx message counters  (per specific message) */
	[MSC_CTR_BSSMAP_RX_UDT_RESET_ACKNOWLEDGE] = {"bssmap:rx:udt:reset:ack", "Number of received BSSMAP UDT RESET ACKNOWLEDGE messages"},
	[MSC_CTR_BSSMAP_RX_UDT_RESET] =             {"bssmap:rx:udt:reset:request", "Number of received BSSMAP UDT RESET messages"},
	[MSC_CTR_BSSMAP_RX_UDT_PAGING] =            {"bssmap:rx:udt:paging", "Number of received BSSMAP UDT PAGING messages"},
	[MSC_CTR_BSSMAP_RX_UDT_UNKNOWN] =           {"bssmap:rx:udt:err_unknown", "Number of received BSSMAP unknown UDT messages"},
	[MSC_CTR_BSSMAP_RX_DT1_CLEAR_CMD] =         {"bssmap:rx:dt1:clear:cmd", "Number of received BSSMAP DT1 CLEAR CMD messages"},
	[MSC_CTR_BSSMAP_RX_DT1_CIPHER_MODE_CMD] =   {"bssmap:rx:dt1:cipher_mode:cmd", "Number of received BSSMAP DT1 CIPHER MODE CMD messages"},
	[MSC_CTR_BSSMAP_RX_DT1_ASSIGMENT_RQST] =    {"bssmap:rx:dt1:assignment:rqst", "Number of received BSSMAP DT1 ASSIGMENT RQST messages"},
	[MSC_CTR_BSSMAP_RX_DT1_LCLS_CONNECT_CTRL] = {"bssmap:rx:dt1:lcls_connect_ctrl:cmd", "Number of received BSSMAP DT1 LCLS CONNECT CTRL messages"},
	[MSC_CTR_BSSMAP_RX_DT1_HANDOVER_CMD] =      {"bssmap:rx:dt1:handover:cmd", "Number of received BSSMAP DT1 HANDOVER CMD messages"},
	[MSC_CTR_BSSMAP_RX_DT1_CLASSMARK_RQST] =    {"bssmap:rx:dt1:classmark:rqst", "Number of received BSSMAP DT1 CLASSMARK RQST messages"},
	[MSC_CTR_BSSMAP_RX_DT1_CONFUSION] =         {"bssmap:rx:dt1:confusion", "Number of received BSSMAP DT1 CONFUSION messages"},
	[MSC_CTR_BSSMAP_RX_DT1_COMMON_ID] =         {"bssmap:rx:dt1:common_id", "Number of received BSSMAP DT1 COMMON ID messages"},
	[MSC_CTR_BSSMAP_RX_DT1_UNKNOWN] =           {"bssmap:rx:dt1:err_unknown", "Number of received BSSMAP unknown DT1 messages"},
	[MSC_CTR_BSSMAP_RX_DT1_DTAP] =              {"bssmap:rx:dt1:dtap:good", "Number of received BSSMAP DTAP messages"},
	[MSC_CTR_BSSMAP_RX_DT1_DTAP_ERROR] =        {"bssmap:rx:dt1:dtap:error", "Number of received BSSMAP DTAP messages with errors"},
	[MSC_CTR_BSSMAP_RX_DT1_PERFORM_LOCATION_REQUEST] = {"bssmap:rx:dt1:location:request", "Number of received BSSMAP Perform Location Request messages"},
	[MSC_CTR_BSSMAP_RX_DT1_PERFORM_LOCATION_ABORT] = {"bssmap:tx:dt1:location:abort", "Number of received BSSMAP Perform Location Abort messages"},

	/* Tx message counters (per message type)
	 *
	 * The counters here follow the logic of the osmo_bsc_sigtran_send() function
	 * which receives DT1 messages from the upper layers and actually sends them to the MSC.
	 * These counters cover all messages passed to the function by the upper layers: */
	[MSC_CTR_BSSMAP_TX_BSS_MANAGEMENT] =     {"bssmap:tx:type:bss_management", "Number of transmitted BSS MANAGEMENT messages"},
	[MSC_CTR_BSSMAP_TX_DTAP] =               {"bssmap:tx:type:dtap", "Number of transmitted DTAP messages"},
	[MSC_CTR_BSSMAP_TX_UNKNOWN] =            {"bssmap:tx:type:err_unknown", "Number of transmitted messages with unknown type (an error in our code?)"},
	[MSC_CTR_BSSMAP_TX_SHORT] =              {"bssmap:tx:type:err_short", "Number of transmitted messages which are too short (an error in our code?)"},
	/* The next counters are also counted in the osmo_bsc_sigtran_send() function and
	 * sum up to the exactly same number as the counters above but instead of message
	 * classes they split by the result of the sending attempt: */
	[MSC_CTR_BSSMAP_TX_ERR_CONN_NOT_READY] = {"bssmap:tx:result:err_conn_not_ready", "Number of BSSMAP messages we tried to send when the connection was not ready yet"},
	[MSC_CTR_BSSMAP_TX_ERR_SEND] =           {"bssmap:tx:result:err_send", "Number of socket errors while sending BSSMAP messages"},
	[MSC_CTR_BSSMAP_TX_SUCCESS] =            {"bssmap:tx:result:success", "Number of successfully sent BSSMAP messages"},

	/* Tx message counters (per specific message)
	 *
	 * Theoretically, the DT1 counters should sum up to the same number as the Tx counters
	 * above but since these counters are coming from the upper layers, there might be
	 * some difference if we forget some code path. */
	[MSC_CTR_BSSMAP_TX_UDT_RESET] =                     {"bssmap:tx:udt:reset:request", "Number of transmitted BSSMAP UDT RESET messages"},
	[MSC_CTR_BSSMAP_TX_UDT_RESET_ACK] =                 {"bssmap:tx:udt:reset:ack", "Number of transmitted BSSMAP UDT RESET ACK messages"},
	[MSC_CTR_BSSMAP_TX_DT1_CLEAR_RQST] =                {"bssmap:tx:dt1:clear:rqst", "Number of transmitted BSSMAP DT1 CLEAR RQSTtx  messages"},
	[MSC_CTR_BSSMAP_TX_DT1_CLEAR_COMPLETE] =            {"bssmap:tx:dt1:clear:complete", "Number of transmitted BSSMAP DT1 CLEAR COMPLETE messages"},
	[MSC_CTR_BSSMAP_TX_DT1_ASSIGMENT_FAILURE] =         {"bssmap:tx:dt1:assigment:failure", "Number of transmitted BSSMAP DT1 ASSIGMENT FAILURE messages"},
	[MSC_CTR_BSSMAP_TX_DT1_ASSIGMENT_COMPLETE] =        {"bssmap:tx:dt1:assigment:complete", "Number of transmitted BSSMAP DT1 ASSIGMENT COMPLETE messages"},
	[MSC_CTR_BSSMAP_TX_DT1_SAPI_N_REJECT] =             {"bssmap:tx:dt1:sapi_n:reject", "Number of transmitted BSSMAP DT1 SAPI N REJECT messages"},
	[MSC_CTR_BSSMAP_TX_DT1_CIPHER_COMPLETE] =           {"bssmap:tx:dt1:cipher_mode:complete", "Number of transmitted BSSMAP DT1 CIPHER COMPLETE messages"},
	[MSC_CTR_BSSMAP_TX_DT1_CIPHER_REJECT] =             {"bssmap:tx:dt1:cipher_mode:reject", "Number of transmitted BSSMAP DT1 CIPHER REJECT messages"},
	[MSC_CTR_BSSMAP_TX_DT1_CLASSMARK_UPDATE] =          {"bssmap:tx:dt1:classmark:update", "Number of transmitted BSSMAP DT1 CLASSMARK UPDATE messages"},
	[MSC_CTR_BSSMAP_TX_DT1_LCLS_CONNECT_CTRL_ACK] =     {"bssmap:tx:dt1:lcls_connect_ctrl:ack", "Number of transmitted BSSMAP DT1 LCLS CONNECT CTRL ACK messages"},
	[MSC_CTR_BSSMAP_TX_DT1_HANDOVER_REQUIRED] =         {"bssmap:tx:dt1:handover:required", "Number of transmitted BSSMAP DT1 HANDOVER REQUIRED messages"},
	[MSC_CTR_BSSMAP_TX_DT1_HANDOVER_PERFORMED] =        {"bssmap:tx:dt1:handover:performed", "Number of transmitted BSSMAP DT1 HANDOVER PERFORMED messages"},
	[MSC_CTR_BSSMAP_TX_DT1_HANDOVER_RQST_ACKNOWLEDGE] = {"bssmap:tx:dt1:handover:rqst_acknowledge", "Number of transmitted BSSMAP DT1 HANDOVER RQST ACKNOWLEDGE messages"},
	[MSC_CTR_BSSMAP_TX_DT1_HANDOVER_DETECT] =           {"bssmap:tx:dt1:handover:detect", "Number of transmitted BSSMAP DT1 HANDOVER DETECT messages"},
	[MSC_CTR_BSSMAP_TX_DT1_HANDOVER_COMPLETE] =         {"bssmap:tx:dt1:handover:complete", "Number of transmitted BSSMAP DT1 HANDOVER COMPLETE messages"},
	[MSC_CTR_BSSMAP_TX_DT1_HANDOVER_FAILURE] =          {"bssmap:tx:dt1:handover:failure", "Number of transmitted BSSMAP DT1 HANDOVER FAILURE messages"},
	[MSC_CTR_BSSMAP_TX_DT1_DTAP] =                      {"bssmap:tx:dt1:dtap", "Number of transmitted BSSMAP DT1 DTAP messages"},
	[MSC_CTR_BSSMAP_TX_DT1_PERFORM_LOCATION_RESPONSE_SUCCESS] = {"bssmap:tx:dt1:location:response_success",
		"Number of transmitted BSSMAP Perform Location Response messages containing a location estimate"},
	[MSC_CTR_BSSMAP_TX_DT1_PERFORM_LOCATION_RESPONSE_FAILURE] = {"bssmap:tx:dt1:location:response_failure",
		"Number of transmitted BSSMAP Perform Location Response messages containing a failure cause"},

	/* Indicators for MSC pool usage */
	[MSC_CTR_MSCPOOL_SUBSCR_NEW] = {
		"mscpool:subscr:new",
		"Complete Layer 3 requests assigned to this MSC by round-robin (no NRI was assigned yet).",
	},
	[MSC_CTR_MSCPOOL_SUBSCR_REATTACH] = {
		"mscpool:subscr:reattach",
		"Complete Layer 3 requests assigned to this MSC by round-robin because the subscriber indicates a"
		" NULL-NRI (previously assigned by another MSC).",
	},
	[MSC_CTR_MSCPOOL_SUBSCR_KNOWN] = {
		"mscpool:subscr:known",
		"Complete Layer 3 requests directed to this MSC because the subscriber indicates an NRI of this MSC.",
	},
	[MSC_CTR_MSCPOOL_SUBSCR_PAGED] = {
		"mscpool:subscr:paged",
		"Paging Response directed to this MSC because the subscriber was recently paged by this MSC.",
	},
	[MSC_CTR_MSCPOOL_SUBSCR_ATTACH_LOST] = {
		"mscpool:subscr:attach_lost",
		"A subscriber indicates an NRI value matching this MSC, but the MSC is not connected:"
		" a re-attach to another MSC (if available) was forced, with possible service failure.",
	},
	[MSC_CTR_MSCPOOL_EMERG_FORWARDED] = {
		"mscpool:emerg:forwarded",
		"Emergency call requests forwarded to this MSC.",
	},
};

static const struct rate_ctr_group_desc msc_ctrg_desc = {
	"msc",
	"mobile switching center",
	OSMO_STATS_CLASS_GLOBAL,
	ARRAY_SIZE(msc_ctr_description),
	msc_ctr_description,
};

static const struct osmo_stat_item_desc msc_stat_desc[] = {
	{ "msc_links:active", "Number of active MSC links", "", 16, 0 },
	{ "msc_links:total", "Number of configured MSC links", "", 16, 0 },
};

static const struct osmo_stat_item_group_desc msc_statg_desc = {
	.group_name_prefix = "msc",
	.group_description = "mobile switching center",
	.class_id = OSMO_STATS_CLASS_GLOBAL,
	.num_items = ARRAY_SIZE(msc_stat_desc),
	.item_desc = msc_stat_desc,
};

int osmo_bsc_msc_init(struct bsc_msc_data *msc)
{
	struct gsm_network *net = msc->network;
	uint16_t mgw_port;
	int rc;

	if (net->mgw.conf->remote_port >= 0)
		mgw_port = net->mgw.conf->remote_port;
	else
		mgw_port = MGCP_CLIENT_REMOTE_PORT_DEFAULT;

	rc = osmo_sock_init2_ofd(&msc->mgcp_ipa.ofd, AF_UNSPEC, SOCK_DGRAM, IPPROTO_UDP,
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

	llist_for_each_entry(msc_data, &net->mscs, entry)
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

	/* init statistics */
	msc_data->msc_ctrs = rate_ctr_group_alloc(net, &msc_ctrg_desc, nr);
	if (!msc_data->msc_ctrs) {
		talloc_free(msc_data);
		return NULL;
	}
	msc_data->msc_statg = osmo_stat_item_group_alloc(net, &msc_statg_desc, nr);
	if (!msc_data->msc_statg) {
		rate_ctr_group_free(msc_data->msc_ctrs);
		talloc_free(msc_data);
		return NULL;
	}

	llist_add_tail(&msc_data->entry, &net->mscs);

	/* Init back pointer */
	msc_data->network = net;

	msc_data->core_plmn = (struct osmo_plmn_id){
		.mcc = GSM_MCC_MNC_INVALID,
		.mnc = GSM_MCC_MNC_INVALID,
	};

	msc_data->nr = nr;
	msc_data->allow_emerg = 1;
	msc_data->a.asp_proto = OSMO_SS7_ASP_PROT_M3UA;

	/* Defaults for the audio setup */
	msc_data->amr_conf.m5_90 = 1;
	msc_data->amr_octet_aligned = true;

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

	osmo_fd_setup(&msc_data->mgcp_ipa.ofd, -1, OSMO_FD_READ, &bsc_sccplite_mgcp_proxy_cb, msc_data, 0);
	msc_data->mgcp_ipa.local_addr = NULL; /* = INADDR(6)_ANY */
	msc_data->mgcp_ipa.local_port = 0; /* dynamic */

	msc_data->nri_ranges = osmo_nri_ranges_alloc(msc_data);
	msc_data->allow_attach = true;

	return msc_data;
}

struct osmo_cell_global_id *cgi_for_msc(struct bsc_msc_data *msc, struct gsm_bts *bts)
{
	static struct osmo_cell_global_id cgi;

	if (!bts)
		return NULL;

	cgi.lai.plmn = msc->network->plmn;
	if (msc->core_plmn.mcc != GSM_MCC_MNC_INVALID)
		cgi.lai.plmn.mcc = msc->core_plmn.mcc;
	if (msc->core_plmn.mnc != GSM_MCC_MNC_INVALID) {
		cgi.lai.plmn.mnc = msc->core_plmn.mnc;
		cgi.lai.plmn.mnc_3_digits = msc->core_plmn.mnc_3_digits;
	}
	cgi.lai.lac = bts->location_area_code;
	cgi.cell_identity = bts->cell_identity;

	return &cgi;
}
