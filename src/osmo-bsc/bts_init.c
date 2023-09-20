/* (C) 2011 by Harald Welte <laforge@gnumonks.org>
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
#include <osmocom/bsc/bss.h>
#include <osmocom/bsc/bts.h>
#include <osmocom/bsc/vty.h>
#include <osmocom/core/utils.h>

void bts_grprs_tdef_groups_init(void);

int bts_init(void)
{
	bts_grprs_tdef_groups_init();

	bts_model_bs11_init();
	bts_model_rbs2k_init();
	bts_model_nanobts_init();
	bts_model_nokia_site_init();
	bts_model_osmobts_init();
	/* Your new BTS here. */
	return 0;
}

/* The following tdef arrays are copied to each BTS instance and used for per-BTS tdef groups after being
 * initialized via bts_tdef_vty_groups_init() (see: bsc_bts_alloc_register()) */
static struct osmo_tdef bts_gprs_rlc_timer_templates[] = {
	{ .T = 3142, .default_val = 20,
	  .desc = "Used during packet access on CCCH/while in dedicated mode. Started after the receipt of "
		  "IMMEDIATE ASSIGNMENT REJECT or DTM REJECT or EC IMMEDIATE ASSIGNMENT REJECT",
	  .max_val = UINT8_MAX },
	{ .T = 3169, .default_val = 5,
	  .desc = "Release radio resource (TFI, USF) timer (linked to N3103, N3103)", .max_val = UINT8_MAX },
	{ .T = 3191, .default_val = 5,
	  .desc = "Downlink TBF (Temporary Block Flow) Release downlink RLC data block retransmission timer", .max_val = UINT8_MAX },
	{ .T = 3193, .default_val = 1600, .desc = "Downlink TBF Release timer", .unit = OSMO_TDEF_MS,
	  .max_val = UINT8_MAX * 10 },
	{ .T = 3195, .default_val = 5,
	  .desc = "Timer for TFI release on N3105 overflow (unresponsive MS)", .max_val = UINT8_MAX },
	{ .T = GSM_BTS_TDEF_ID_COUNTDOWN_VALUE, .default_val = 15,
	  .desc = "CV: Countdown value/remaining blocks to transmit", .unit = OSMO_TDEF_CUSTOM, .max_val = UINT8_MAX },
	{ .T = GSM_BTS_TDEF_ID_UL_TBF_EXT, .default_val = 2500,
	  .desc = "\"In the extended uplink TBF mode, the uplink TBF may be maintained during temporary inactive periods, "
		  "where the mobile station has no RLC information to send.\" (3GPP TS 44.060 Version 6.14.0)",
	  .unit = OSMO_TDEF_MS, .max_val = 500 * 10 },
	{ .T = GSM_BTS_TDEF_ID_DL_TBF_DELAYED, .default_val = 2500,
	  .desc = "A delayed release of the downlink TBF is when the release of the downlink TBF is delayed following the transmission of a final data block, "
		  "rather than instantly releasing the TBF",
	  .unit = OSMO_TDEF_MS, .max_val = 500 * 10 },
	{ .T = 3101, .default_val = 10,
	  .desc = "N3101: Maximum USFs without response from the MS", .unit = OSMO_TDEF_CUSTOM,
	   .min_val = GSM_RLCMACN3101_STRICT_LOWER_BOUND + 1, .max_val = UINT8_MAX },
	{ .T = 3103, .default_val = 4,
	  .desc = "N3103: Maximum PACKET UPLINK ACK/NACK messages within a TBF unacknowledged by MS",
	  .unit = OSMO_TDEF_CUSTOM, .max_val = UINT8_MAX },
	{ .T = 3105, .default_val = 8,
	  .desc = "N3105: Maximum allocated data blocks without RLC/MAC control reply from MS",
	  .unit = OSMO_TDEF_CUSTOM, .max_val = UINT8_MAX },
	{}
};

static struct osmo_tdef bts_gprs_ns_timer_templates[] = {
	{ .T = GSM_BTS_TDEF_ID_TNS_BLOCK, .default_val = 3, .min_val = 0, .max_val = UINT8_MAX,
	  .desc = "Tns-block: Guards the blocking and unblocking procedures" },
	{ .T = GSM_BTS_TDEF_ID_TNS_BLOCK_RETRIES, .default_val = 3, .min_val = 0, .max_val = UINT8_MAX,
	  .desc = "NS-BLOCK-RETRIES: Blocking procedure retries", .unit = OSMO_TDEF_CUSTOM },
	{ .T = GSM_BTS_TDEF_ID_TNS_RESET, .default_val = 3, .min_val = 0, .max_val = UINT8_MAX,
	  .desc = "Tns-reset: Guards the reset procedure" },
	{ .T = GSM_BTS_TDEF_ID_TNS_RESET_RETRIES, .default_val = 3, .min_val = 0, .max_val = UINT8_MAX,
	  .desc = "Reset procedure retries", .unit = OSMO_TDEF_CUSTOM },
	{ .T = GSM_BTS_TDEF_ID_TNS_TEST, .default_val = 30, .min_val = 0, .max_val = UINT8_MAX,
	  .desc = "Tns-test: Periodicity of the NS-VC test procedure" },
	{ .T = GSM_BTS_TDEF_ID_TNS_ALIVE, .default_val = 3, .min_val = 0, .max_val = UINT8_MAX,
	  .desc = "Tns-alive: Guards the NS-VC test procedure" },
	{ .T = GSM_BTS_TDEF_ID_TNS_ALIVE_RETRIES, .default_val = 10, .min_val = 0, .max_val = UINT8_MAX,
	  .desc = "NS-ALIVE-RETRIES: Retries for the the NS-VC test procedure", .unit = OSMO_TDEF_CUSTOM },
	{}
};


/* This is only used by bts_vty.c to init the default values for the templates */
struct osmo_tdef_group bts_gprs_timer_template_groups[_NUM_OSMO_BSC_BTS_TDEF_GROUPS + 1] = {
	[OSMO_BSC_BTS_TDEF_GROUPS_RLC] = {
		.name = BTS_VTY_RLC_STR, .tdefs = bts_gprs_rlc_timer_templates, .desc = BTS_VTY_RLC_DESC_STR },
	[OSMO_BSC_BTS_TDEF_GROUPS_NS] = {
		.name = BTS_VTY_NS_STR, .tdefs = bts_gprs_ns_timer_templates, .desc = BTS_VTY_NS_DESC_STR },
	/* Additional per-BTS timer groups here, set as above using 'enum gprs_bts_tdef_groups' */
	{}
};

/* Init per-BTS timer groups with group templates */
void bts_gprs_timer_groups_init(struct gsm_bts *bts)
{
	enum gsm_gprs_bts_tdef_groups gbtg;
	for (gbtg = 0; gbtg < ARRAY_SIZE(bts_gprs_timer_template_groups); gbtg++)
		bts->timer_groups[gbtg] = bts_gprs_timer_template_groups[gbtg];
	/* Init per-BTS RLC timers */
	bts->timer_groups[OSMO_BSC_BTS_TDEF_GROUPS_RLC].tdefs = talloc_memdup(bts, bts_gprs_rlc_timer_templates, sizeof(bts_gprs_rlc_timer_templates));
	OSMO_ASSERT(bts->timer_groups[OSMO_BSC_BTS_TDEF_GROUPS_RLC].tdefs);
	/* Init per-BTS NS timers */
	bts->timer_groups[OSMO_BSC_BTS_TDEF_GROUPS_NS].tdefs = talloc_memdup(bts, bts_gprs_ns_timer_templates, sizeof(bts_gprs_ns_timer_templates));
	OSMO_ASSERT(bts->timer_groups[OSMO_BSC_BTS_TDEF_GROUPS_NS].tdefs);
}

/* Init default values for all per-BTS timer templates */
void bts_grprs_tdef_groups_init(void)
{
	struct osmo_tdef_group *g;
	/* Set values in per-BTS timer templates to defaults */
	osmo_tdef_groups_for_each(g, bts_gprs_timer_template_groups)
		osmo_tdefs_reset(g->tdefs);
}
