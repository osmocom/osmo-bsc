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
#include <osmocom/bsc/bss.h>
#include <osmocom/bsc/bts.h>
#include <osmocom/bsc/timeslot_fsm.h>
#include <osmocom/bsc/lchan_fsm.h>
#include <osmocom/bsc/assignment_fsm.h>
#include <osmocom/bsc/bsc_subscr_conn_fsm.h>

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

static void test_fsm_ids_with_pchan_names(void)
{
	struct gsm_network *net;
	struct gsm_bts *bts;
	struct gsm_bts_trx *trx;
	struct gsm_bts_trx_ts *ts;
	struct gsm_lchan *lchan;
	enum gsm_phys_chan_config pchan;
	struct gsm_subscriber_connection *conn;

	rate_ctr_init(ctx);
	tall_bsc_ctx = ctx;
	bsc_network_alloc();
	net = bsc_gsmnet;

	/* Have a BTS so that we have trx, timeslots, lchans that have FSMs to check the id of */
	bts = bsc_bts_alloc_register(net, GSM_BTS_TYPE_UNKNOWN, HARDCODED_BSIC);
	trx = gsm_bts_trx_alloc(bts);

	printf("\nTesting FSM ids that contain pchan names\n");
	ts = &trx->ts[0];
	lchan = &ts->lchan[0];

	conn = bsc_subscr_con_allocate(net);
	conn->lchan = lchan;
	conn->assignment.new_lchan = lchan;
	conn->sccp.conn_id = 123;
	conn->bsub = bsc_subscr_find_or_create_by_tmsi(net->bsc_subscribers, 0x423, "test");
	gscon_update_id(conn);

	/* dirty dirty hack, to just point at some fi so we can update the id */
	conn->assignment.fi = trx->ts[1].fi;

	for (pchan = 0; pchan < _GSM_PCHAN_MAX; pchan++) {
		ts->pchan_from_config = pchan;
		/* trigger ID update in ts and lchan */
		osmo_fsm_inst_dispatch(ts->fi, TS_EV_OML_READY, NULL);

		if (lchan->fi)
			assignment_fsm_update_id(conn);

		printf("pchan=%s:\n  ts->fi->id = %s\n  lchan->fi->id = %s\n  assignment.fi->id = %s\n",
		       gsm_pchan_name(pchan),
		       ts->fi->id,
		       lchan->fi ? lchan->fi->id : "null",
		       lchan->fi ? conn->assignment.fi->id : "null");

		osmo_fsm_inst_dispatch(ts->fi, TS_EV_OML_DOWN, NULL);
	}

	talloc_free(net);
	bsc_gsmnet = NULL;
	printf("\n");
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
	test_fsm_ids_with_pchan_names();

	printf("Testing execution completed.\n");
	talloc_free(ctx);
	return 0;
}
