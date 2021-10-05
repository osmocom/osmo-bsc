/*
 * BSC Message filtering
 *
 * (C) 2013 by sysmocom s.f.m.c. GmbH
 * Written by Jacob Erlbeck <jerlbeck@sysmocom.de>
 * (C) 2010-2013 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010-2013 by On-Waves
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
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */


#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/gsm_data.h>

#include <osmocom/bsc/osmo_bsc.h>
#include <osmocom/bsc/bsc_msc_data.h>

#include <osmocom/gsm/gad.h>
#include <osmocom/core/application.h>
#include <osmocom/core/backtrace.h>
#include <osmocom/core/talloc.h>

#include <stdio.h>
#include <search.h>

void *ctx = NULL;

enum test {
	TEST_SCAN_TO_BTS,
};

/* GSM 04.08 MM INFORMATION test message */
static uint8_t gsm48_mm_info_nn_tzt[] = {
	0x05, 0x32, 0x45, 0x08, 0x80, 0x4f, 0x77, 0xeb,
	0x1a, 0xb6, 0x97, 0xe7, 0x47, 0x31, 0x90, 0x61,
	0x11, 0x02, 0x73, 0x00,
};

static uint8_t gsm48_mm_info_nn_tzt_out[] = {
	0x05, 0x32, 0x45, 0x08, 0x80, 0x4f, 0x77, 0xeb,
	0x1a, 0xb6, 0x97, 0xe7, 0x47, 0x31, 0x90, 0x61,
	0x11, 0x02, 0x73, 0x1a,
};

static uint8_t gsm48_mm_info_nn_tzt_dst[] = {
	0x05, 0x32, 0x45, 0x08, 0x80, 0x4f, 0x77, 0xeb,
	0x1a, 0xb6, 0x97, 0xe7, 0x47, 0x31, 0x90, 0x61,
	0x11, 0x02, 0x73, 0x00, 0x49, 0x01, 0x00,
};

static uint8_t gsm48_mm_info_nn_tzt_dst_out[] = {
	0x05, 0x32, 0x45, 0x08, 0x80, 0x4f, 0x77, 0xeb,
	0x1a, 0xb6, 0x97, 0xe7, 0x47, 0x31, 0x90, 0x61,
	0x11, 0x02, 0x73, 0x1a, 0x49, 0x01, 0x02,
};

struct test_definition {
	const uint8_t *data;
	const uint16_t length;
	const int dir;
	const int result;
	const uint8_t *out_data;
	const uint16_t out_length;
	const char* params;
	const int n_params;
};

static int get_int(const char *params, size_t nmemb, const char *key, int def, int *is_set)
{
	const char *kv = NULL;

	kv = strstr(params, key);
	if (kv) {
		kv += strlen(key) + 1;
		fprintf(stderr, "get_int(%s) -> %d\n", key, atoi(kv));
		if (is_set)
			*is_set = 1;
	}

	return kv ? atoi(kv) : def;
}

static const struct test_definition test_scan_defs[] = {
	{
		.data = gsm48_mm_info_nn_tzt_dst,
		.length = ARRAY_SIZE(gsm48_mm_info_nn_tzt),
		.dir = TEST_SCAN_TO_BTS,
		.result = 0,
		.out_data = gsm48_mm_info_nn_tzt_dst_out,
		.out_length = ARRAY_SIZE(gsm48_mm_info_nn_tzt_out),
		.params = "tz_hr=-5 tz_mn=15 tz_dst=2",
		.n_params = 3,
	},
	{
		.data = gsm48_mm_info_nn_tzt_dst,
		.length = ARRAY_SIZE(gsm48_mm_info_nn_tzt_dst),
		.dir = TEST_SCAN_TO_BTS,
		.result = 0,
		.out_data = gsm48_mm_info_nn_tzt_dst_out,
		.out_length = ARRAY_SIZE(gsm48_mm_info_nn_tzt_dst_out),
		.params = "tz_hr=-5 tz_mn=15 tz_dst=2",
		.n_params = 3,
	},
};

static void test_scan(void)
{
	int i;

	struct gsm_network *net = gsm_network_init(ctx);
	struct gsm_subscriber_connection *conn = talloc_zero(net, struct gsm_subscriber_connection);

	bsc_gsmnet = net;
	conn->network = net;

	/* start testing with proper messages */
	printf("Testing BTS<->MSC message scan.\n");
	for (i = 0; i < ARRAY_SIZE(test_scan_defs); ++i) {
		const struct test_definition *test_def = &test_scan_defs[i];
		int result;
		struct msgb *msg = msgb_alloc(4096, "test-message");
		int is_set = 0;

		net->tz.hr = get_int(test_def->params, test_def->n_params, "tz_hr", 0, &is_set);
		net->tz.mn = get_int(test_def->params, test_def->n_params, "tz_mn", 0, &is_set);
		net->tz.dst = get_int(test_def->params, test_def->n_params, "tz_dst", 0, &is_set);
		net->tz.override = 1;

		printf("Going to test item: %d\n", i);
		msg->l3h = msgb_put(msg, test_def->length);
		memcpy(msg->l3h, test_def->data, test_def->length);

		switch (test_def->dir) {
		case TEST_SCAN_TO_BTS:
			/* override timezone of msg coming from the MSC */
			result = bsc_scan_msc_msg(conn, msg);
			break;
		default:
			abort();
			break;
		}

		if (result != test_def->result) {
			printf("FAIL: Not the expected result, got: %d wanted: %d\n",
				result, test_def->result);
			goto out;
		}

		if (msgb_l3len(msg) != test_def->out_length) {
			printf("FAIL: Not the expected message size, got: %d wanted: %d\n",
				msgb_l3len(msg), test_def->out_length);
			goto out;
		}

		if (memcmp(msgb_l3(msg), test_def->out_data, test_def->out_length) != 0) {
			printf("FAIL: Not the expected message\n");
			goto out;
		}

out:
		msgb_free(msg);
	}

	talloc_free(net);
	bsc_gsmnet = NULL;
}

static const struct log_info_cat log_categories[] = {
	[DNM] = {
		.name = "DNM",
		.description = "A-bis Network Management / O&M (NM/OML)",
		.color = "\033[1;36m",
		.enabled = 1, .loglevel = LOGL_INFO,
	},
	[DMSC] = {
		.name = "DMSC",
		.description = "Mobile Switching Center",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DCTRL] = {
		.name = "DCTRL",
		.description = "Control interface",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DFILTER] = {
		.name = "DFILTER",
		.description = "BSC/NAT IMSI based filtering",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
};

static const struct log_info log_info = {
	.cat = log_categories,
	.num_cat = ARRAY_SIZE(log_categories),
};

int main(int argc, char **argv)
{
	ctx = talloc_named_const(NULL, 0, "bsc-test");
	msgb_talloc_ctx_init(ctx, 0);
	osmo_init_logging2(ctx, &log_info);

	test_scan();

	printf("Testing execution completed.\n");
	talloc_free(ctx);
	return 0;
}

struct gsm_subscriber_connection *bsc_subscr_con_allocate(struct gsm_network *net) {
	OSMO_ASSERT(0);
}

void bsc_sapi_n_reject(struct gsm_subscriber_connection *conn, uint8_t dlci, enum gsm0808_cause cause) {}
void bsc_cipher_mode_compl(struct gsm_subscriber_connection *conn, struct msgb *msg, uint8_t chosen_encr) {}
int bsc_compl_l3(struct gsm_lchan *lchan, struct msgb *msg, uint16_t chosen_channel)
{ return 0; }
void bsc_dtap(struct gsm_subscriber_connection *conn, uint8_t link_id, struct msgb *msg) {}
void bsc_assign_compl(struct gsm_subscriber_connection *conn, uint8_t rr_cause) {}
void bsc_assign_fail(struct gsm_subscriber_connection *conn, uint8_t cause, uint8_t *rr_cause) {}
void bsc_cm_update(struct gsm_subscriber_connection *conn,
		   const uint8_t *cm2, uint8_t cm2_len,
		   const uint8_t *cm3, uint8_t cm3_len) {}
void gscon_submit_rsl_dtap(struct gsm_subscriber_connection *conn,
			   struct msgb *msg, int link_id, int allow_sacch) {}
void ts_fsm_alloc(struct gsm_bts_trx_ts *ts) {}
void lchan_activate(struct gsm_lchan *lchan, void *info) {}
bool neighbor_ident_bts_entry_exists(uint8_t from_bts) { return false; }
const char *handover_status(struct gsm_subscriber_connection *conn) { return "x"; }
int rsl_chan_ms_power_ctrl(struct gsm_lchan *lchan) { return 0; }
void pcu_info_update(struct gsm_bts *bts) {};
int rsl_sacch_filling(struct gsm_bts_trx *trx, uint8_t type, const uint8_t *data, int len) { return 0; }
int rsl_bcch_info(const struct gsm_bts_trx *trx, enum osmo_sysinfo_type si_type, const uint8_t *data, int len)
{ return 0; }
int gsm_generate_si(struct gsm_bts *bts, enum osmo_sysinfo_type si_type) { return 0; }
