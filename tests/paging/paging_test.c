/*
 * (C) 2022 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
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
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/application.h>
#include <osmocom/core/utils.h>
#include <osmocom/gsm/protocol/gsm_12_21.h>
#include <osmocom/gsm/gsm23003.h>
#include <osmocom/gsm/rsl.h>

#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/bts.h>
#include <osmocom/bsc/abis_nm.h>
#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/bss.h>

struct timespec *clk_monotonic_override;
unsigned int _sent_pg_cmd_rsl;

static void clock_debug(char *str)
{
	struct timeval tv;
	osmo_gettimeofday(&tv, NULL);
	fprintf(stderr, "sys={%lu.%06lu}: %s\n",
		tv.tv_sec, tv.tv_usec, str);
}


static void clock_set(uint64_t sec, uint64_t usec)
{
	osmo_gettimeofday_override_time.tv_sec = sec;
	osmo_gettimeofday_override_time.tv_usec = usec;
	clk_monotonic_override->tv_sec = sec;
	clk_monotonic_override->tv_nsec = usec * 1000;
}

static void clock_inc(unsigned int sec, unsigned int usec)
{
	osmo_gettimeofday_override_add(sec, usec);
	osmo_clock_override_add(CLOCK_MONOTONIC, sec, usec * 1000);
}

#define bts_init(net) _bts_init(net, __func__)
static inline struct gsm_bts *_bts_init(struct gsm_network *net, const char *msg)
{
	struct gsm_bts_sm *bts_sm = gsm_bts_sm_alloc(net, 0);
	struct gsm_bts *bts = bts_sm->bts[0];
	if (!bts) {
		fprintf(stderr, "BTS allocation failure in %s()\n", msg);
		exit(1);
	}
	fprintf(stderr, "BTS allocation OK in %s()\n", msg);

	bts->network = net;

	/* Make sure trx_is_usable() returns true for bts->c0: */
	bts->c0->mo.nm_state.operational = NM_OPSTATE_ENABLED;
	bts->c0->mo.nm_state.availability = NM_AVSTATE_OK;
	bts->c0->mo.nm_state.administrative = NM_STATE_UNLOCKED;
	bts->c0->bb_transc.mo.nm_state.operational = NM_OPSTATE_ENABLED;
	bts->c0->bb_transc.mo.nm_state.availability = NM_AVSTATE_OK;
	bts->c0->bb_transc.mo.nm_state.administrative = NM_STATE_UNLOCKED;
	bts->c0->rsl_link_primary = (struct e1inp_sign_link *)(intptr_t)0x01; /* Fake RSL is UP */

	return bts;
}

#define bts_del(bts) _bts_del(bts, __func__)
static inline void _bts_del(struct gsm_bts *bts, const char *msg)
{
	/* no need to llist_del(&bts->list), we never registered the bts there. */
	talloc_free(bts->site_mgr);
	fprintf(stderr, "BTS deallocated OK in %s()\n", msg);
}

static void emu_bsc_paging_cmd_from_msc(struct gsm_network *net, struct gsm_bts *bts, const char *imsi)
{
	int ret;
	struct bsc_paging_params params = {
		.reason = BSC_PAGING_FROM_CN,
		.msc = NULL,
		.tmsi = GSM_RESERVED_TMSI,
		.imsi = {
			.type = GSM_MI_TYPE_IMSI,
		}
	};
	OSMO_STRLCPY_ARRAY(params.imsi.imsi, imsi);
	params.bsub = bsc_subscr_find_or_create_by_imsi(net->bsc_subscribers, params.imsi.imsi,
							 BSUB_USE_PAGING_START);
	ret = paging_request_bts(&params, bts);
	OSMO_ASSERT(ret == 1);
}

static void test_paging500(struct gsm_network *net)
{
	fprintf(stderr, "===%s===\n", __func__);
	int i;
	clock_set(0, 0);
	_sent_pg_cmd_rsl = 0;
	struct gsm_bts *bts = bts_init(net);

	for (i = 0; i < 500; i++) {
		char imsi[32];
		snprintf(imsi, sizeof(imsi), "1234%06u", i);
		emu_bsc_paging_cmd_from_msc(net, bts, imsi);
	}

	while (_sent_pg_cmd_rsl < 500) {
		osmo_timers_prepare();
		int nearest_ms = osmo_timers_nearest_ms();
		if (nearest_ms == -1)
			nearest_ms = 250;
		clock_inc(0, nearest_ms*1000);
		clock_debug("select()");
		osmo_select_main_ctx(0);
		if (llist_empty(&bts->paging.pending_requests)) {
			fprintf(stderr, "ERROR: some request timed out before being sent! %u\n", _sent_pg_cmd_rsl);
			OSMO_ASSERT(0);
		}
	}

	bts_del(bts);
}

static void test_paging500_combined(struct gsm_network *net)
{
	fprintf(stderr, "===%s===\n", __func__);
	int i;
	clock_set(0, 0);
	_sent_pg_cmd_rsl = 0;
	struct gsm_bts *bts = bts_init(net);
	bts->si_common.chan_desc.ccch_conf = RSL_BCCH_CCCH_CONF_1_C;

	for (i = 0; i < 500; i++) {
		char imsi[32];
		snprintf(imsi, sizeof(imsi), "1234%06u", i);
		emu_bsc_paging_cmd_from_msc(net, bts, imsi);
	}

	while (_sent_pg_cmd_rsl < 500) {
		osmo_timers_prepare();
		int nearest_ms = osmo_timers_nearest_ms();
		if (nearest_ms == -1)
			nearest_ms = 250;
		clock_inc(0, nearest_ms*1000);
		clock_debug("select()");
		osmo_select_main_ctx(0);
		if (llist_empty(&bts->paging.pending_requests)) {
			fprintf(stderr, "ERROR: some request timed out before being sent! %u\n", _sent_pg_cmd_rsl);
			OSMO_ASSERT(0);
		}
	}

	bts_del(bts);
}

static void test_paging500_samepgroup(struct gsm_network *net)
{
	fprintf(stderr, "===%s===\n", __func__);
	int i;
	clock_set(0, 0);
	_sent_pg_cmd_rsl = 0;
	struct gsm_bts *bts = bts_init(net);

	unsigned int num_pgroups = gsm48_number_of_paging_subchannels(&bts->si_common.chan_desc);
	fprintf(stderr, "Number of paging groups: %u\n", num_pgroups);

	for (i = 0; i < 500; i++) {
		char imsi[32];
		snprintf(imsi, sizeof(imsi), "1234%08u", i*num_pgroups);
		emu_bsc_paging_cmd_from_msc(net, bts, imsi);
	}

	while (_sent_pg_cmd_rsl < 500) {
		osmo_timers_prepare();
		int nearest_ms = osmo_timers_nearest_ms();
		if (nearest_ms == -1)
			nearest_ms = 250;
		clock_inc(0, nearest_ms*1000);
		clock_debug("select()");
		osmo_select_main_ctx(0);
		if (llist_empty(&bts->paging.pending_requests)) {
			fprintf(stderr, "ERROR: some request timed out before being sent! %u\n", _sent_pg_cmd_rsl);
			OSMO_ASSERT(0);
		}
	}

	bts_del(bts);
}

static const struct log_info_cat log_categories[] = {
	[DPAG] = {
		.name = "DPAG",
		.description = "",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
};

static const struct log_info log_info = {
	.cat = log_categories,
	.num_cat = ARRAY_SIZE(log_categories),
};

int main(int argc, char **argv)
{
	struct gsm_network *net;

	osmo_gettimeofday_override = true;
	osmo_clock_override_enable(CLOCK_MONOTONIC, true);
	clk_monotonic_override = osmo_clock_override_gettimespec(CLOCK_MONOTONIC);
	clock_set(0, 0);

	tall_bsc_ctx = talloc_named_const(NULL, 0, "paging_test");
	osmo_init_logging2(tall_bsc_ctx, &log_info);
	log_set_log_level(osmo_stderr_target, LOGL_DEBUG);
	log_set_print_category_hex(osmo_stderr_target, 0);
	log_set_print_category(osmo_stderr_target, 0);
	log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_NONE);
	log_set_use_color(osmo_stderr_target, 0);
	log_parse_category_mask(osmo_stderr_target, "DPAG,1:");
	osmo_fsm_log_addr(false);

	bsc_network_alloc();
	net = bsc_gsmnet;
	if (!net) {
		fprintf(stderr, "Network init failure.\n");
		return EXIT_FAILURE;
	}

	test_paging500(net);
	test_paging500_samepgroup(net);
	test_paging500_combined(net);

	return EXIT_SUCCESS;
}

/* override, requires '-Wl,--wrap=abis_rsl_sendmsg'.
 * Catch RSL messages sent towards the BTS. */
int __real_abis_rsl_sendmsg(struct msgb *msg);
int __wrap_abis_rsl_sendmsg(struct msgb *msg)
{
	struct abis_rsl_cchan_hdr *cch = (struct abis_rsl_cchan_hdr *) msg->data;
	struct tlv_parsed tp;
	struct osmo_mobile_identity mi;
	int rc;
	char mi_str[64];

	switch (cch->c.msg_type) {
	case RSL_MT_PAGING_CMD:
		if (rsl_tlv_parse(&tp, msgb_data(msg) + sizeof(*cch), msgb_length(msg) - sizeof(*cch)) < 0) {
			LOGP(DRSL, LOGL_ERROR, "%s(): rsl_tlv_parse() failed\n", __func__);
			OSMO_ASSERT(0);
		}
		rc = osmo_mobile_identity_decode(&mi, TLVP_VAL(&tp, RSL_IE_MS_IDENTITY), TLVP_LEN(&tp, RSL_IE_MS_IDENTITY), true);
		OSMO_ASSERT(rc == 0);
		mi_str[0] = '\0';
		osmo_mobile_identity_to_str_buf(mi_str, sizeof(mi_str), &mi);
		fprintf(stderr, "abis_rsl_sendmsg: Paging CMD %s\n", mi_str);
		_sent_pg_cmd_rsl++;
		break;
	default:
		fprintf(stderr, "abis_rsl_sendmsg: unknown rsl message=0x%x\n", cch->c.msg_type);
	}
	msgb_free(msg);
	return 0;
}
