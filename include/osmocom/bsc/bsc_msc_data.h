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
#include <osmocom/gsm/protocol/gsm_04_08.h>


#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/sigtran/sccp_helpers.h>
#include <osmocom/sigtran/protocol/sua.h>
#include <osmocom/sigtran/protocol/m3ua.h>
#include <osmocom/core/fsm.h>
#include <osmocom/gsm/gsm23003.h>

#include <regex.h>
#include <errno.h>

struct osmo_bsc_rf;
struct gsm_network;

enum {
	MSC_CON_TYPE_NORMAL,
	MSC_CON_TYPE_LOCAL,
};

/*! /brief Information on a remote MSC for libbsc.
 */
struct bsc_msc_data {
	struct llist_head entry;

	/* Back pointer */
	struct gsm_network *network;

	int allow_emerg;
	int type;

	/* local call routing */
	char *local_pref;
	regex_t local_pref_reg;


	/* Connection data */
	struct osmo_plmn_id core_plmn;
	int core_lac;
	int core_ci;
	int rtp_base;
	bool is_authenticated;

	/* audio codecs */
	struct gsm48_multi_rate_conf amr_conf;
	bool amr_octet_aligned;
	struct gsm_audio_support **audio_support;
	int audio_length;
	enum bsc_lcls_mode lcls_mode;
	bool lcls_codec_mismatch_allow;

	/* ussd welcome text */
	char *ussd_welcome_txt;

	int nr;

	/* ussd msc connection lost text */
	char *ussd_msc_lost_txt;

	/* ussd text when MSC has entered the grace period */
	char *ussd_grace_txt;

	char *acc_lst_name;

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
		struct osmo_fsm_inst *reset_fsm;
	} a;

	uint32_t x_osmo_ign;
	bool x_osmo_ign_configured;

	/* Whether we want to use Osmux against this MSC. Controlled via VTY */
	enum osmux_usage use_osmux;
};

/*
 * Per BSC data.
 */
struct osmo_bsc_data {
	struct gsm_network *network;

	/* msc configuration */
	struct llist_head mscs;

	/* rf ctl related bits */
	char *mid_call_txt;
	int mid_call_timeout;
	char *rf_ctrl_name;
	struct osmo_bsc_rf *rf_ctrl;
	int auto_off_timeout;

	/* ussd text when there is no MSC available */
	char *ussd_no_msc_txt;

	char *acc_lst_name;
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


#endif
