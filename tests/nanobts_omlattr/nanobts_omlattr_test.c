/* Test OML attribute generator */

/* (C) 2016 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
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
 */

#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/bts_ipaccess_nanobts_omlattr.h>
#include <osmocom/bsc/bts.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/application.h>
#include <osmocom/core/sockaddr_str.h>

#include <stdio.h>
#include <string.h>

extern struct gsm_bts_model bts_model_nanobts;

static void test_nanobts_attr_bts_get(struct gsm_bts *bts, uint8_t *expected)
{
	struct msgb *msgb;

	printf("Testing nanobts_attr_bts_get()...\n");

	msgb = nanobts_attr_bts_get(bts);
	printf("result=  %s\n", osmo_hexdump_nospc(msgb->data, msgb->len));
	printf("expected=%s\n", osmo_hexdump_nospc(expected, msgb->len));
	OSMO_ASSERT(msgb_eq_data_print(msgb, expected, msgb->len));
	msgb_free(msgb);

	printf("ok.\n");
	printf("\n");
}

static void test_nanobts_attr_nse_get(struct gsm_bts *bts, uint8_t *expected)
{
	struct msgb *msgb;

	printf("Testing nanobts_attr_nse_get()...\n");

	msgb = nanobts_attr_nse_get(bts->site_mgr);
	printf("result=  %s\n", osmo_hexdump_nospc(msgb->data, msgb->len));
	printf("expected=%s\n", osmo_hexdump_nospc(expected, msgb->len));
	OSMO_ASSERT(msgb_eq_data_print(msgb, expected, msgb->len));
	msgb_free(msgb);

	printf("ok.\n");
	printf("\n");
}

static void test_nanobts_attr_cell_get(struct gsm_bts *bts, uint8_t *expected)
{
	struct msgb *msgb;

	printf("Testing nanobts_attr_cell_get()...\n");

	msgb = nanobts_attr_cell_get(bts);
	printf("result=  %s\n", osmo_hexdump_nospc(msgb->data, msgb->len));
	printf("expected=%s\n", osmo_hexdump_nospc(expected, msgb->len));
	OSMO_ASSERT(msgb_eq_data_print(msgb, expected, msgb->len));
	msgb_free(msgb);

	printf("ok.\n");
	printf("\n");
}

static void test_nanobts_attr_nsvc_get(struct gsm_bts *bts, uint8_t *expected)
{
	struct msgb *msgb;

	printf("Testing nanobts_attr_nsvc_get()...\n");

	msgb = nanobts_attr_nsvc_get(bts);
	printf("result=  %s\n", osmo_hexdump_nospc(msgb->data, msgb->len));
	printf("expected=%s\n", osmo_hexdump_nospc(expected, msgb->len));
	OSMO_ASSERT(msgb_eq_data_print(msgb, expected, msgb->len));
	msgb_free(msgb);

	printf("ok.\n");
	printf("\n");
}

static void test_nanobts_attr_radio_get(struct gsm_bts *bts,
					struct gsm_bts_trx *trx,
					uint8_t *expected)
{
	struct msgb *msgb;

	printf("Testing nanobts_attr_nsvc_get()...\n");

	msgb = nanobts_attr_radio_get(bts, trx);
	printf("result=  %s\n", osmo_hexdump_nospc(msgb->data, msgb->len));
	printf("expected=%s\n", osmo_hexdump_nospc(expected, msgb->len));
	OSMO_ASSERT(msgb_eq_data_print(msgb, expected, msgb->len));
	msgb_free(msgb);

	printf("ok.\n");
	printf("\n");
}

static const struct log_info_cat log_categories[] = {
};

static const struct log_info log_info = {
	.cat = log_categories,
	.num_cat = ARRAY_SIZE(log_categories),
};

static struct osmo_tdef gsm_network_T_defs[] = {
	{ .T=3105, .default_val=100, .val=13, .unit=OSMO_TDEF_MS, .desc="Physical Information" },
	{ .T=3212, .default_val=5, .unit=OSMO_TDEF_CUSTOM,
		.desc="Periodic Location Update timer, sent to MS (1 = 6 minutes)" },
	{}
};

int main(int argc, char **argv)
{
	void *ctx;

	struct gsm_bts *bts;
	struct gsm_network *net;
	struct gsm_bts_trx *trx;

	ctx = talloc_named_const(NULL, 0, "ctx");

	osmo_init_logging2(ctx, &log_info);
	log_set_log_level(osmo_stderr_target, LOGL_INFO);

	/* Allocate environmental structs (bts, net, trx) */
	net = talloc_zero(ctx, struct gsm_network);
	INIT_LLIST_HEAD(&net->bts_list);
	net->T_defs = gsm_network_T_defs;
	gsm_bts_model_register(&bts_model_nanobts);
	bts = gsm_bts_alloc_register(net, GSM_BTS_TYPE_NANOBTS, 63);
	OSMO_ASSERT(bts);
	bts->network = net;
	trx = talloc_zero(ctx, struct gsm_bts_trx);

	/* Parameters needed by nanobts_attr_bts_get() */
	bts->rach_b_thresh = -1;
	bts->rach_ldavg_slots = -1;
	bts->c0->arfcn = 866;
	bts->cell_identity = 1337;
	bts->network->plmn = (struct osmo_plmn_id){ .mcc=1, .mnc=1 };
	bts->location_area_code = 1;
	bts->gprs.rac = 0;
	uint8_t attr_bts_expected[] =
	    { 0x19, 0x73, 0x6d, 0x67, 0x61, 0x5b, 0x55, 0x18, 0x06, 0x0e, 0x00,
		0x02, 0x01, 0x20, 0x33, 0x1e, 0x24, 0x24, 0xa8, 0x34, 0x21,
		0xa8, 0x1f, 0x3f, 0x25,
		0x00, 0x01, 0x0a, 0x0c, 0x0a, 0x0b, 0x01, 0x2a, 0x5a, 0x2b,
		0x03, 0xe8, 0x0a, 0x01,
		0x23, 0x0a, 0x08, 0x03, 0x62, 0x09, 0x3f, 0x99, 0x00, 0x07,
		0x00, 0xf1, 0x10, 0x00,
		0x01, 0x05, 0x39
	};

	/* Parameters needed to test nanobts_attr_nse_get() */
	bts->site_mgr->gprs.nse.nsei = 101;
	uint8_t attr_nse_expected[] =
	    { 0x9d, 0x00, 0x02, 0x00, 0x65, 0xa0, 0x00, 0x07, 0x03, 0x03, 0x03,
		0x03, 0x1e, 0x03, 0x0a, 0xa1, 0x00, 0x0b, 0x03, 0x03, 0x03,
		0x03, 0x03, 0x0a, 0x03,
		0x0a, 0x03, 0x0a, 0x03
	};

	/* Parameters needed to test nanobts_attr_cell_get() */
	bts->gprs.rac = 0x00;
	bts->gprs.cell.bvci = 2;
	bts->gprs.mode = BTS_GPRS_GPRS;
	uint8_t attr_cell_expected[] =
	    { 0x9a, 0x00, 0x01, 0x00, 0x9c, 0x00, 0x02, 0x05, 0x03, 0x9e, 0x00,
		0x02, 0x00, 0x02, 0xa3, 0x00, 0x09, 0x14, 0x05, 0x05, 0xa0,
		0x05, 0x0a, 0x04, 0x08,
		0x0f, 0xa8, 0x00, 0x02, 0x0f, 0x00, 0xa9, 0x00, 0x05, 0x00,
		0xfa, 0x00, 0xfa, 0x02
	};

	/* Parameters needed to test nanobts_attr_nsvc_get() */
	struct osmo_sockaddr_str addr;
	osmo_sockaddr_str_from_str(&addr, "10.9.1.101", 23000);
	osmo_sockaddr_str_to_sockaddr(&addr, &bts->site_mgr->gprs.nsvc[0].remote.u.sas);
	bts->site_mgr->gprs.nsvc[0].nsvci = 0x65;
	bts->site_mgr->gprs.nsvc[0].local_port = 0x5a3c;
	uint8_t attr_nscv_expected[] =
	    { 0x9f, 0x00, 0x02, 0x00, 0x65, 0xa2, 0x00, 0x08, 0x59, 0xd8, 0x0a,
		0x09, 0x01, 0x65, 0x5a, 0x3c
	};

	/* Parameters needed to test nanobts_attr_radio_get() */
	trx->arfcn = 866;
	trx->max_power_red = 22;
	bts->c0->max_power_red = 22;
	uint8_t attr_radio_expected[] =
	    { 0x2d, 0x0b, 0x05, 0x00, 0x02, 0x03, 0x62 };

	/* Run tests */
	test_nanobts_attr_bts_get(bts, attr_bts_expected);
	test_nanobts_attr_nse_get(bts, attr_nse_expected);
	test_nanobts_attr_cell_get(bts, attr_cell_expected);
	test_nanobts_attr_nsvc_get(bts, attr_nscv_expected);
	test_nanobts_attr_radio_get(bts, trx, attr_radio_expected);

	/* NSVC IPv6 test */
	struct osmo_sockaddr_str addr6;
	osmo_sockaddr_str_from_str(&addr6, "fd00:5678:9012:3456:7890:1234:5678:9012", 23010);
	osmo_sockaddr_str_to_sockaddr(&addr6, &bts->site_mgr->gprs.nsvc[0].remote.u.sas);
	bts->site_mgr->gprs.nsvc[0].nsvci = 0x65;
	bts->site_mgr->gprs.nsvc[0].local_port = 0x5a3c;
	uint8_t attr_nscv6_expected[] =
	      /*                             |- oml attr  |-16bit length */
	    { 0x9f, 0x00, 0x02, 0x00, 0x65, 0xfd, 0x00, 0x16,
	      /* 1b type, 1b padding, 2b local port, 2b remote port */
	      0x29, 0x00, 0x5a, 0x3c, 0x59, 0xe2,
	      /* 128bit / 16b ipv6 address */
	      0xfd, 0x00, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56,
	      0x78, 0x90, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12,
	    };
	test_nanobts_attr_nsvc_get(bts, attr_nscv6_expected);


	printf("Done\n");
	talloc_free(bts);
	talloc_free(net);
	talloc_free(trx);
	talloc_report_full(ctx, stderr);
	/* Expecting something like:
	 * full talloc report on 'ctx' (total    813 bytes in   6 blocks)
	 *     logging                        contains    813 bytes in   5 blocks (ref 0) 0x60b0000000a0
	 * 	struct log_target              contains    196 bytes in   2 blocks (ref 0) 0x6110000000a0
	 * 	    struct log_category            contains     36 bytes in   1 blocks (ref 0) 0x60d0000003e0
	 * 	struct log_info                contains    616 bytes in   2 blocks (ref 0) 0x60d000000310
	 * 	    struct log_info_cat            contains    576 bytes in   1 blocks (ref 0) 0x6170000000e0
	 * That's the root ctx + 5x logging: */
	OSMO_ASSERT(talloc_total_blocks(ctx) == 6);
	talloc_free(ctx);
	return 0;
}
