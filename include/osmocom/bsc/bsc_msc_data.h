/*
 * Data for the true BSC
 *
 * (C) 2010-2015 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010-2015 by On-Waves
 * (C) 2018 by Harald Welte <laforge@gnumonks.org>
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

/*
 * NOTE: This is about a *remote* MSC for OsmoBSC and is not part of libmsc.
 */

#ifndef _OSMO_MSC_DATA_H
#define _OSMO_MSC_DATA_H

#include "debug.h"
#include "osmo_bsc_lcls.h"
#include "osmux.h"

#include <osmocom/core/timer.h>
#include <osmocom/core/select.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>


#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/sigtran/sccp_helpers.h>
#include <osmocom/sigtran/protocol/sua.h>
#include <osmocom/sigtran/protocol/m3ua.h>
#include <osmocom/core/fsm.h>
#include <osmocom/gsm/gsm23003.h>

#include <errno.h>

struct osmo_bsc_rf;
struct gsm_network;

/* Constants for the MSC rate counters */
enum {
	/* Rx message counters */
	MSC_CTR_BSSMAP_RX_UDT_RESET_ACKNOWLEDGE,
	MSC_CTR_BSSMAP_RX_UDT_RESET,
	MSC_CTR_BSSMAP_RX_UDT_PAGING,
	MSC_CTR_BSSMAP_RX_UDT_UNKNOWN,
	MSC_CTR_BSSMAP_RX_DT1_CLEAR_CMD,
	MSC_CTR_BSSMAP_RX_DT1_CIPHER_MODE_CMD,
	MSC_CTR_BSSMAP_RX_DT1_ASSIGMENT_RQST,
	MSC_CTR_BSSMAP_RX_DT1_LCLS_CONNECT_CTRL,
	MSC_CTR_BSSMAP_RX_DT1_HANDOVER_CMD,
	MSC_CTR_BSSMAP_RX_DT1_CLASSMARK_RQST,
	MSC_CTR_BSSMAP_RX_DT1_CONFUSION,
	MSC_CTR_BSSMAP_RX_DT1_COMMON_ID,
	MSC_CTR_BSSMAP_RX_DT1_UNKNOWN,
	MSC_CTR_BSSMAP_RX_DT1_DTAP,
	MSC_CTR_BSSMAP_RX_DT1_DTAP_ERROR,
	MSC_CTR_BSSMAP_RX_DT1_PERFORM_LOCATION_REQUEST,
	MSC_CTR_BSSMAP_RX_DT1_PERFORM_LOCATION_ABORT,

	/* Tx message counters (per connection type) */
	MSC_CTR_BSSMAP_TX_BSS_MANAGEMENT,
	MSC_CTR_BSSMAP_TX_DTAP,
	MSC_CTR_BSSMAP_TX_UNKNOWN,
	MSC_CTR_BSSMAP_TX_SHORT,
	MSC_CTR_BSSMAP_TX_ERR_CONN_NOT_READY,
	MSC_CTR_BSSMAP_TX_ERR_SEND,
	MSC_CTR_BSSMAP_TX_SUCCESS,

	/* Tx message counters (per message type) */
	MSC_CTR_BSSMAP_TX_UDT_RESET,
	MSC_CTR_BSSMAP_TX_UDT_RESET_ACK,
	MSC_CTR_BSSMAP_TX_DT1_CLEAR_RQST,
	MSC_CTR_BSSMAP_TX_DT1_CLEAR_COMPLETE,
	MSC_CTR_BSSMAP_TX_DT1_ASSIGMENT_FAILURE,
	MSC_CTR_BSSMAP_TX_DT1_ASSIGMENT_COMPLETE,
	MSC_CTR_BSSMAP_TX_DT1_SAPI_N_REJECT,
	MSC_CTR_BSSMAP_TX_DT1_CIPHER_COMPLETE,
	MSC_CTR_BSSMAP_TX_DT1_CIPHER_REJECT,
	MSC_CTR_BSSMAP_TX_DT1_CLASSMARK_UPDATE,
	MSC_CTR_BSSMAP_TX_DT1_LCLS_CONNECT_CTRL_ACK,
	MSC_CTR_BSSMAP_TX_DT1_HANDOVER_REQUIRED,
	MSC_CTR_BSSMAP_TX_DT1_HANDOVER_PERFORMED,
	MSC_CTR_BSSMAP_TX_DT1_HANDOVER_RQST_ACKNOWLEDGE,
	MSC_CTR_BSSMAP_TX_DT1_HANDOVER_DETECT,
	MSC_CTR_BSSMAP_TX_DT1_HANDOVER_COMPLETE,
	MSC_CTR_BSSMAP_TX_DT1_HANDOVER_FAILURE,
	MSC_CTR_BSSMAP_TX_DT1_DTAP,
	MSC_CTR_BSSMAP_TX_DT1_PERFORM_LOCATION_RESPONSE_SUCCESS,
	MSC_CTR_BSSMAP_TX_DT1_PERFORM_LOCATION_RESPONSE_FAILURE,

	MSC_CTR_MSCPOOL_SUBSCR_NEW,
	MSC_CTR_MSCPOOL_SUBSCR_REATTACH,
	MSC_CTR_MSCPOOL_SUBSCR_KNOWN,
	MSC_CTR_MSCPOOL_SUBSCR_PAGED,
	MSC_CTR_MSCPOOL_SUBSCR_ATTACH_LOST,
	MSC_CTR_MSCPOOL_EMERG_FORWARDED,
};

/* Constants for the MSC stats */
enum {
	MSC_STAT_MSC_LINKS_ACTIVE,
	MSC_STAT_MSC_LINKS_TOTAL,
};

/*! /brief Information on a remote MSC for libbsc.
 */
struct bsc_msc_data {
	struct llist_head entry;

	/* Back pointer */
	struct gsm_network *network;

	int allow_emerg;

	/* Connection data */
	struct osmo_plmn_id core_plmn;
	int core_lac;
	int core_ci;

	/* audio codecs */
	struct gsm48_multi_rate_conf amr_conf;
	bool amr_octet_aligned;
	struct gsm_audio_support **audio_support;
	int audio_length;
	enum bsc_lcls_mode lcls_mode;
	bool lcls_codec_mismatch_allow;

	int nr;

	/* structures for keeping rate counters and gauge stats */
	struct rate_ctr_group *msc_ctrs;
	struct osmo_stat_item_group *msc_statg;

	/* Sigtran connection data */
	struct {
		uint32_t cs7_instance;
		bool cs7_instance_valid;
		struct osmo_sccp_instance *sccp;
		struct osmo_sccp_user *sccp_user;

		/* IPA or M3UA or SUA? */
		enum osmo_ss7_asp_protocol asp_proto;

		/* Holds a copy of the our local MSC address,
		 * this will be the sccp-address that is associated
		 * with the A interface of this particular BSC,
		 * this address is filled up by the VTY interface */
		struct osmo_sccp_addr bsc_addr;
		char *bsc_addr_name;

		/* Holds a copy of the MSC address. This is the
		 * address of the MSC that handles the calls of
		 * this BSC. The address is configured via the
		 * VTY interface */
		struct osmo_sccp_addr msc_addr;
		char *msc_addr_name;

		/* Pointer to the osmo-fsm that controls the
		 * BSSMAP RESET procedure */
		struct bssmap_reset *bssmap_reset;
	} a;

	uint32_t x_osmo_ign;
	bool x_osmo_ign_configured;

	/* Whether we want to use Osmux against this MSC. Controlled via VTY */
	enum osmux_usage use_osmux;
	/* Whether we detected the MSC supports Osmux (during BSSMAP_RESET) */
	bool remote_supports_osmux;

	/* Proxy between IPA/SCCPlite encapsulated MGCP and UDP */
	struct {
		/* local (BSC) IP address to be used */
		char *local_addr;
		/* local (BSC) UDP port to be used to talk with MGW */
		uint16_t local_port;
		/* UDP socket for proxying MGCP via SCCPlite/IPA */
		struct osmo_fd ofd;
	} mgcp_ipa;

	struct osmo_nri_ranges *nri_ranges;
	bool allow_attach;
};

int osmo_bsc_msc_init(struct bsc_msc_data *msc);
int osmo_bsc_sccp_init(struct gsm_network *gsmnet);

int osmo_bsc_audio_init(struct gsm_network *network);

struct bsc_msc_data *osmo_msc_data_find(struct gsm_network *, int);
struct bsc_msc_data *osmo_msc_data_alloc(struct gsm_network *, int);


struct osmo_cell_global_id *cgi_for_msc(struct bsc_msc_data *msc, struct gsm_bts *bts);

/* Helper function to calculate the port number for a given
 * timeslot/multiplex. This functionality is needed to support
 * the sccp-lite scenario where the MGW is handled externally */
static inline int mgcp_timeslot_to_port(int multiplex, int timeslot, int base)
{
	if (timeslot == 0) {
		LOGP(DLMGCP, LOGL_ERROR, "Timeslot should not be 0\n");
		timeslot = 255;
	}

	return base + (timeslot + (32 * multiplex)) * 2;
}

static inline int mgcp_port_to_cic(uint16_t port, uint16_t base)
{
	if (port < base)
		return -EINVAL;
	return (port - base) / 2;
}

static inline bool msc_is_aoip(const struct bsc_msc_data *msc)
{
	switch (msc->a.asp_proto) {
	case OSMO_SS7_ASP_PROT_SUA:
	case OSMO_SS7_ASP_PROT_M3UA:
		return true;
	default:
		return false;
	}
}

static inline bool msc_is_sccplite(const struct bsc_msc_data *msc)
{
	switch (msc->a.asp_proto) {
	case OSMO_SS7_ASP_PROT_IPA:
		return true;
	default:
		return false;
	}
}

#endif
