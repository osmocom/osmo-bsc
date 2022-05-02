/* simple test for the gsm0408 formatting functions */
/*
 * (C) 2008 by Holger Hans Peter Freyther <zecke@selfish.org>
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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <arpa/inet.h>

#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/system_information.h>
#include <osmocom/bsc/abis_rsl.h>
#include <osmocom/bsc/bts.h>
#include <osmocom/bsc/bss.h>

#include <osmocom/core/application.h>
#include <osmocom/core/byteswap.h>
#include <osmocom/gsm/sysinfo.h>
#include <osmocom/gsm/gsm48.h>

#include <osmocom/bsc/gsm_04_08_rr.h>

#define COMPARE(result, op, value) \
    if (!((result) op (value))) {\
	fprintf(stderr, "Compare failed. Was %x should be %x in %s:%d\n",result, value, __FILE__, __LINE__); \
	exit(-1); \
    }

#define COMPARE_STR(result, value) \
	if (strcmp(result, value) != 0) { \
		fprintf(stderr, "Compare failed. Was %s should be %s in %s:%d\n",result, value, __FILE__, __LINE__); \
		exit(-1); \
	}

#define DBG(...)

#define VERIFY(res, cmp, wanted)					\
	if (!(res cmp wanted)) {					\
		printf("ASSERT failed: %s:%d Wanted: %d %s %d\n",	\
			__FILE__, __LINE__, (int) res, # cmp, (int) wanted);	\
	}

static inline void gen(struct gsm_bts *bts, const char *s)
{
	int r;

	bts->si_valid = 0;
	bts->si_valid |= (1 << SYSINFO_TYPE_2quater);

	printf("generating SI2quater for %zu EARFCNs and %zu UARFCNs...\n",
	       si2q_earfcn_count(&bts->si_common.si2quater_neigh_list), bts->si_common.uarfcn_length);

	r = gsm_generate_si(bts, SYSINFO_TYPE_2quater);
	if (r > 0)
		for (bts->si2q_index = 0; bts->si2q_index < bts->si2q_count + 1; bts->si2q_index++)
			printf("generated %s SI2quater [%02u/%02u]: [%d] %s\n",
			       GSM_BTS_HAS_SI(bts, SYSINFO_TYPE_2quater) ? "valid" : "invalid",
			       bts->si2q_index, bts->si2q_count, r,
			       osmo_hexdump((void *)GSM_BTS_SI2Q(bts, bts->si2q_index), GSM_MACBLOCK_LEN));
	else
		printf("%s() failed to generate SI2quater: %s\n", s, strerror(-r));
}

static inline void del_earfcn_b(struct gsm_bts *bts, uint16_t earfcn)
{
	struct osmo_earfcn_si2q *e = &bts->si_common.si2quater_neigh_list;
	int r = osmo_earfcn_del(e, earfcn);
	if (r)
		printf("failed to remove EARFCN %u: %s\n", earfcn, strerror(-r));
	else
		printf("removed EARFCN %u - ", earfcn);

	gen(bts, __func__);
}

static inline void add_earfcn_b(struct gsm_bts *bts, uint16_t earfcn, uint8_t bw)
{
	struct osmo_earfcn_si2q *e = &bts->si_common.si2quater_neigh_list;
	int r = osmo_earfcn_add(e, earfcn, bw);
	if (r)
		printf("failed to add EARFCN %u: %s\n", earfcn, strerror(-r));
	else
		printf("added EARFCN %u - ", earfcn);

	gen(bts, __func__);
}

static inline void _bts_uarfcn_add(struct gsm_bts *bts, uint16_t arfcn, uint16_t scramble, bool diversity)
{
	int r;

	bts->u_offset = 0;

	r = bts_uarfcn_add(bts, arfcn, scramble, diversity);
	if (r < 0)
		printf("failed to add UARFCN to SI2quater: %s\n", strerror(-r));
	else {
		bts->si2q_count = si2q_num(bts) - 1;
		gen(bts, __func__);
	}
}

#define bts_init(net) _bts_init(net, __func__)
static inline struct gsm_bts *_bts_init(struct gsm_network *net, const char *msg)
{
	struct gsm_bts_sm *bts_sm = gsm_bts_sm_alloc(net, 0);
	struct gsm_bts *bts = bts_sm->bts[0];
	if (!bts) {
		printf("BTS allocation failure in %s()\n", msg);
		exit(1);
	}
	printf("BTS allocation OK in %s()\n", msg);

	bts->network = net;

	return bts;
}

#define bts_del(bts) _bts_del(bts, __func__)
static inline void _bts_del(struct gsm_bts *bts, const char *msg)
{
	if (osmo_timer_pending(&bts->acc_mgr.rotate_timer))
		osmo_timer_del(&bts->acc_mgr.rotate_timer);
	/* no need to llist_del(&bts->list), we never registered the bts there. */
	talloc_free(bts->site_mgr);
	printf("BTS deallocated OK in %s()\n", msg);
}

static inline void test_si2q_segfault(struct gsm_network *net)
{
	struct gsm_bts *bts = bts_init(net);
	printf("Test SI2quater UARFCN (same scrambling code and diversity):\n");

	_bts_uarfcn_add(bts, 10564, 319, 0);
	_bts_uarfcn_add(bts, 10612, 319, 0);
	gen(bts, __func__);

	bts_del(bts);
}

static inline void test_si2q_mu(struct gsm_network *net)
{
	struct gsm_bts *bts = bts_init(net);
	printf("Test SI2quater multiple UARFCNs:\n");

	_bts_uarfcn_add(bts, 10564, 318, 0);
	_bts_uarfcn_add(bts, 10612, 319, 0);
	_bts_uarfcn_add(bts, 10612, 31, 0);
	_bts_uarfcn_add(bts, 10612, 19, 0);
	_bts_uarfcn_add(bts, 10613, 64, 0);
	_bts_uarfcn_add(bts, 10613, 164, 0);
	_bts_uarfcn_add(bts, 10613, 14, 0);

	bts_del(bts);
}

static inline void test_si2q_u(struct gsm_network *net)
{
	struct gsm_bts *bts = bts_init(net);
	printf("Testing SYSINFO_TYPE_2quater UARFCN generation:\n");

	/* first generate invalid SI as no UARFCN added */
	gen(bts, __func__);

	/* subsequent calls should produce valid SI if there's enough memory */
	_bts_uarfcn_add(bts, 1982, 13, 1);
	_bts_uarfcn_add(bts, 1982, 44, 0);
	_bts_uarfcn_add(bts, 1982, 61, 1);
	_bts_uarfcn_add(bts, 1982, 89, 1);
	_bts_uarfcn_add(bts, 1982, 113, 0);
	_bts_uarfcn_add(bts, 1982, 123, 0);
	_bts_uarfcn_add(bts, 1982, 56, 1);
	_bts_uarfcn_add(bts, 1982, 72, 1);
	_bts_uarfcn_add(bts, 1982, 223, 1);
	_bts_uarfcn_add(bts, 1982, 14, 0);
	_bts_uarfcn_add(bts, 1982, 88, 0);

	bts_del(bts);
}

static inline void test_si2q_e(struct gsm_network *net)
{
	struct gsm_bts *bts = bts_init(net);
	printf("Testing SYSINFO_TYPE_2quater EARFCN generation:\n");

	bts->si_common.si2quater_neigh_list.arfcn = bts->si_common.data.earfcn_list;
	bts->si_common.si2quater_neigh_list.meas_bw = bts->si_common.data.meas_bw_list;
	bts->si_common.si2quater_neigh_list.length = MAX_EARFCN_LIST;
	bts->si_common.si2quater_neigh_list.thresh_hi = 5;

	osmo_earfcn_init(&bts->si_common.si2quater_neigh_list);

	/* first generate invalid SI as no EARFCN added */
	gen(bts, __func__);

	/* subsequent calls should produce valid SI if there's enough memory and EARFCNs */
	add_earfcn_b(bts, 1917, 5);
	del_earfcn_b(bts, 1917);
	add_earfcn_b(bts, 1917, 1);
	add_earfcn_b(bts, 1932, OSMO_EARFCN_MEAS_INVALID);
	add_earfcn_b(bts, 1937, 2);
	add_earfcn_b(bts, 1945, OSMO_EARFCN_MEAS_INVALID);
	add_earfcn_b(bts, 1965, OSMO_EARFCN_MEAS_INVALID);
	add_earfcn_b(bts, 1967, 4);
	add_earfcn_b(bts, 1982, 3);

	bts_del(bts);
}

static inline void test_si2q_long(struct gsm_network *net)
{
	struct gsm_bts *bts = bts_init(net);
	printf("Testing SYSINFO_TYPE_2quater combined EARFCN & UARFCN generation:\n");

	bts->si_common.si2quater_neigh_list.arfcn = bts->si_common.data.earfcn_list;
	bts->si_common.si2quater_neigh_list.meas_bw = bts->si_common.data.meas_bw_list;
	bts->si_common.si2quater_neigh_list.length = MAX_EARFCN_LIST;
	bts->si_common.si2quater_neigh_list.thresh_hi = 5;

	osmo_earfcn_init(&bts->si_common.si2quater_neigh_list);

	bts_earfcn_add(bts, 1922, 11, 22, 8,32, 8);
	bts_earfcn_add(bts, 1922, 11, 22, 8, 32, 8);
	bts_earfcn_add(bts, 1924, 11, 12, 6, 11, 5);
	bts_earfcn_add(bts, 1923, 11, 12, 6, 11, 5);
	bts_earfcn_add(bts, 1925, 11, 12, 6, 11, 5);
	bts_earfcn_add(bts, 2111, 11, 12, 6, 11, 5);
	bts_earfcn_add(bts, 2112, 11, 12, 6, 11, 4);
	bts_earfcn_add(bts, 2113, 11, 12, 6, 11, 3);
	bts_earfcn_add(bts, 2114, 11, 12, 6, 11, 2);
	bts_earfcn_add(bts, 2131, 11, 12, 6, 11, 5);
	bts_earfcn_add(bts, 2132, 11, 12, 6, 11, 4);
	bts_earfcn_add(bts, 2133, 11, 12, 6, 11, 3);
	bts_earfcn_add(bts, 2134, 11, 12, 6, 11, 2);
	bts_earfcn_add(bts, 2121, 11, 12, 6, 11, 5);
	bts_earfcn_add(bts, 2122, 11, 12, 6, 11, 4);
	bts_earfcn_add(bts, 2123, 11, 12, 6, 11, 3);
	bts_earfcn_add(bts, 2124, 11, 12, 6, 11, 2);
	_bts_uarfcn_add(bts, 1976, 13, 1);
	_bts_uarfcn_add(bts, 1976, 38, 1);
	_bts_uarfcn_add(bts, 1976, 44, 1);
	_bts_uarfcn_add(bts, 1976, 120, 1);
	_bts_uarfcn_add(bts, 1976, 140, 1);
	_bts_uarfcn_add(bts, 1976, 163, 1);
	_bts_uarfcn_add(bts, 1976, 166, 1);
	_bts_uarfcn_add(bts, 1976, 217, 1);
	_bts_uarfcn_add(bts, 1976, 224, 1);
	_bts_uarfcn_add(bts, 1976, 225, 1);
	_bts_uarfcn_add(bts, 1976, 226, 1);

	bts_del(bts);
}

static void test_si_ba_ind(struct gsm_network *net)
{
	struct gsm_bts *bts = bts_init(net);

	const struct gsm48_system_information_type_2 *si2 =
		(struct gsm48_system_information_type_2 *) GSM_BTS_SI(bts, SYSINFO_TYPE_2);
	const struct gsm48_system_information_type_2bis *si2bis =
		(struct gsm48_system_information_type_2bis *) GSM_BTS_SI(bts, SYSINFO_TYPE_2bis);
	const struct gsm48_system_information_type_2ter *si2ter =
		(struct gsm48_system_information_type_2ter *) GSM_BTS_SI(bts, SYSINFO_TYPE_2ter);
	const struct gsm48_system_information_type_5 *si5 =
		(struct gsm48_system_information_type_5 *) GSM_BTS_SI(bts, SYSINFO_TYPE_5);
	const struct gsm48_system_information_type_5bis *si5bis =
		(struct gsm48_system_information_type_5bis *) GSM_BTS_SI(bts, SYSINFO_TYPE_5bis);
	const struct gsm48_system_information_type_5ter *si5ter =
		(struct gsm48_system_information_type_5ter *) GSM_BTS_SI(bts, SYSINFO_TYPE_5ter);

	int rc;

	bts->c0->arfcn = 23;

	printf("Testing if BA-IND is set as expected in SI2xxx and SI5xxx\n");

	rc = gsm_generate_si(bts, SYSINFO_TYPE_2);
	OSMO_ASSERT(rc > 0);
	printf("SI2: %s\n", osmo_hexdump((uint8_t *)si2, rc));
	/* Validate BA-IND == 0 */
	OSMO_ASSERT(!(si2->bcch_frequency_list[0] & 0x10));

	rc = gsm_generate_si(bts, SYSINFO_TYPE_2bis);
	OSMO_ASSERT(rc > 0);
	printf("SI2bis: %s\n", osmo_hexdump((uint8_t *)si2bis, rc));
	/* Validate BA-IND == 0 */
	OSMO_ASSERT(!(si2bis->bcch_frequency_list[0] & 0x10));

	rc = gsm_generate_si(bts, SYSINFO_TYPE_2ter);
	OSMO_ASSERT(rc > 0);
	printf("SI2ter: %s\n", osmo_hexdump((uint8_t *)si2ter, rc));
	/* Validate BA-IND == 0 */
	OSMO_ASSERT(!(si2ter->ext_bcch_frequency_list[0] & 0x10));

	rc = gsm_generate_si(bts, SYSINFO_TYPE_5);
	OSMO_ASSERT(rc > 0);
	printf("SI5: %s\n", osmo_hexdump((uint8_t *)si5, rc));
	/* Validate BA-IND == 1 */
	OSMO_ASSERT(si5->bcch_frequency_list[0] & 0x10);

	rc = gsm_generate_si(bts, SYSINFO_TYPE_5bis);
	OSMO_ASSERT(rc > 0);
	printf("SI5bis: %s\n", osmo_hexdump((uint8_t *)si5bis, rc));
	/* Validate BA-IND == 1 */
	OSMO_ASSERT(si5bis->bcch_frequency_list[0] & 0x10);

	rc = gsm_generate_si(bts, SYSINFO_TYPE_5ter);
	OSMO_ASSERT(rc > 0);
	printf("SI5ter: %s\n", osmo_hexdump((uint8_t *)si5ter, rc));
	/* Validate BA-IND == 1 */
	OSMO_ASSERT(si5ter->bcch_frequency_list[0] & 0x10);

	bts_del(bts);
}

struct test_gsm48_ra_id_by_bts {
	struct osmo_plmn_id plmn;
	uint16_t lac;
	uint8_t rac;
	struct gsm48_ra_id expect;
};
static const struct test_gsm48_ra_id_by_bts test_gsm48_ra_id_by_bts_data[] = {
	{
		.plmn = { .mcc = 1, .mnc = 2, .mnc_3_digits = false },
		.lac = 3,
		.rac = 4,
		.expect = {
			.digits = { 0x00, 0xf1, 0x20 },
			.lac = 0x0300, /* network byte order of 3 */
			.rac = 4,
		},
	},
	{
		.plmn = { .mcc = 1, .mnc = 2, .mnc_3_digits = true },
		.lac = 3,
		.rac = 4,
		.expect = {
			.digits = { 0x00, 0x21, 0x00 },
			.lac = 0x0300, /* network byte order of 3 */
			.rac = 4,
		},
	},
	{
		.plmn = { .mcc = 0, .mnc = 0, .mnc_3_digits = false },
		.lac = 0,
		.rac = 0,
		.expect = {
			.digits = { 0x00, 0xf0, 0x00 },
		},
	},
	{
		.plmn = { .mcc = 0, .mnc = 0, .mnc_3_digits = true },
		.lac = 0,
		.rac = 0,
		.expect = {
			.digits = {},
		},
	},
	{
		.plmn = { .mcc = 999, .mnc = 999, .mnc_3_digits = false },
		.lac = 65535,
		.rac = 255,
		.expect = {
			.digits = { 0x99, 0x99, 0x99 },
			.lac = 0xffff,
			.rac = 0xff,
		},
	},
	{
		.plmn = { .mcc = 909, .mnc = 90, .mnc_3_digits = false },
		.lac = 0xabcd,
		.rac = 0xab,
		.expect = {
			.digits = { 0x09, 0xf9, 0x09 },
			.lac = 0xcdab,
			.rac = 0xab,
		},
	},
	{
		.plmn = { .mcc = 909, .mnc = 90, .mnc_3_digits = true },
		.lac = 0xabcd,
		.rac = 0xab,
		.expect = {
			.digits = { 0x09, 0x09, 0x90 },
			.lac = 0xcdab,
			.rac = 0xab,
		},
	},
};

static void test_gsm48_ra_id_by_bts()
{
	int i;
	bool pass = true;

	for (i = 0; i < ARRAY_SIZE(test_gsm48_ra_id_by_bts_data); i++) {
		struct gsm_network net;
		struct gsm_bts bts;
		const struct test_gsm48_ra_id_by_bts *t = &test_gsm48_ra_id_by_bts_data[i];
		struct gsm48_ra_id result = {};
		bool ok;

		net.plmn = t->plmn;
		bts.network = &net;
		bts.location_area_code = t->lac;
		bts.gprs.rac = t->rac;

		gsm48_ra_id_by_bts(&result, &bts);

		ok = (t->expect.digits[0] == result.digits[0])
		     && (t->expect.digits[1] == result.digits[1])
		     && (t->expect.digits[2] == result.digits[2])
		     && (t->expect.lac == result.lac)
		     && (t->expect.rac == result.rac);
		printf("%s[%d]: digits='%02x%02x%02x' lac=0x%04x=htons(%u) rac=0x%02x=%u %s\n",
		       __func__, i,
		       result.digits[0], result.digits[1], result.digits[2],
		       result.lac, osmo_ntohs(result.lac), result.rac, result.rac,
		       ok ? "pass" : "FAIL");
		pass = pass && ok;
	}

	OSMO_ASSERT(pass);
}

static void test_gsm48_multirate_config()
{
	struct gsm48_multi_rate_conf *gsm48_ie;
	struct amr_multirate_conf mr;
	int rc;
	struct msgb *msg = msgb_alloc(32, "test_gsm48_multirate_config");

	memset(&mr, 0, sizeof(mr));

	/* Use some made up threshold and hysteresis values */
	mr.ms_mode[0].threshold = 11;
	mr.ms_mode[1].threshold = 12;
	mr.ms_mode[2].threshold = 13;
	mr.ms_mode[0].hysteresis = 15;
	mr.ms_mode[1].hysteresis = 12;
	mr.ms_mode[2].hysteresis = 8;

	gsm48_ie = (struct gsm48_multi_rate_conf *)&mr.gsm48_ie;
	gsm48_ie->ver = 1;
	gsm48_ie->m5_90 = 1;
	gsm48_ie->m7_40 = 1;
	gsm48_ie->m7_95 = 1;
	gsm48_ie->m12_2 = 1;

	/* Test #1: Normal configuration with 4 active set members */
	mr.ms_mode[0].mode = 2;
	mr.ms_mode[1].mode = 4;
	mr.ms_mode[2].mode = 5;
	mr.ms_mode[3].mode = 7;
	msgb_trim(msg, 0);
	rc = gsm48_multirate_config(msg, gsm48_ie, mr.ms_mode, 4);
	OSMO_ASSERT(rc == 0);
	printf("gsm48_multirate_config(): rc=%i, lv=%s\n", rc,
	       osmo_hexdump_nospc(msg->data, msg->len));

	/* Test #2: 4 active set members, but wrong mode order: */
	mr.ms_mode[3].mode = 2;
	mr.ms_mode[2].mode = 4;
	mr.ms_mode[1].mode = 5;
	mr.ms_mode[0].mode = 7;
	msgb_trim(msg, 0);
	rc = gsm48_multirate_config(msg, gsm48_ie, mr.ms_mode, 4);
	OSMO_ASSERT(rc == -EINVAL);

	/* Test #3: Normal configuration with 3 active set members */
	mr.ms_mode[0].mode = 2;
	mr.ms_mode[1].mode = 4;
	mr.ms_mode[2].mode = 5;
	mr.ms_mode[3].mode = 7;
	gsm48_ie->m12_2 = 0;
	mr.ms_mode[2].threshold = 0;
	mr.ms_mode[2].hysteresis = 0;

	msgb_trim(msg, 0);
	rc = gsm48_multirate_config(msg, gsm48_ie, mr.ms_mode, 3);
	OSMO_ASSERT(rc == 0);
	printf("gsm48_multirate_config(): rc=%i, lv=%s\n", rc,
	       osmo_hexdump_nospc(msg->data, msg->len));

	/* Test #4: 3 active set members, but wrong mode order: */
	mr.ms_mode[0].mode = 2;
	mr.ms_mode[2].mode = 4;
	mr.ms_mode[1].mode = 5;
	msgb_trim(msg, 0);
	rc = gsm48_multirate_config(msg, gsm48_ie, mr.ms_mode, 3);
	OSMO_ASSERT(rc == -EINVAL);

	/* Test #5: Normal configuration with 2 active set members */
	mr.ms_mode[0].mode = 2;
	mr.ms_mode[1].mode = 4;
	mr.ms_mode[2].mode = 5;
	mr.ms_mode[3].mode = 7;
	gsm48_ie->m7_95 = 0;
	mr.ms_mode[1].threshold = 0;
	mr.ms_mode[1].hysteresis = 0;

	msgb_trim(msg, 0);
	rc = gsm48_multirate_config(msg, gsm48_ie, mr.ms_mode, 2);
	OSMO_ASSERT(rc == 0);
	printf("gsm48_multirate_config(): rc=%i, lv=%s\n", rc,
	       osmo_hexdump_nospc(msg->data, msg->len));

	/* Test #6: 2 active set members, but wrong mode order: */
	mr.ms_mode[1].mode = 2;
	mr.ms_mode[0].mode = 4;
	msgb_trim(msg, 0);
	rc = gsm48_multirate_config(msg, gsm48_ie, mr.ms_mode, 2);
	OSMO_ASSERT(rc == -EINVAL);

	/* Test #7: Normal configuration with 1 active set member */
	mr.ms_mode[0].mode = 2;
	mr.ms_mode[1].mode = 4;
	mr.ms_mode[2].mode = 5;
	mr.ms_mode[3].mode = 7;
	gsm48_ie->m7_40 = 0;
	mr.ms_mode[0].threshold = 0;
	mr.ms_mode[0].hysteresis = 0;

	msgb_trim(msg, 0);
	rc = gsm48_multirate_config(msg, gsm48_ie, mr.ms_mode, 1);
	OSMO_ASSERT(rc == 0);
	printf("gsm48_multirate_config(): rc=%i, lv=%s\n", rc,
	       osmo_hexdump_nospc(msg->data, msg->len));

	/* Test #8: 0 active set members: */
	mr.ms_mode[0].mode = 0;
	msgb_trim(msg, 0);
	rc = gsm48_multirate_config(msg, gsm48_ie, mr.ms_mode, 1);
	OSMO_ASSERT(rc == -EINVAL);

	msgb_free(msg);
}

/* Similar to list_arfcn() from system_information.c, but uses printf().
 * Another difference is that the text is printed even if n is 0. */
static void print_cell_chan_desc(uint8_t *cd, const char *text)
{
	struct gsm_sysinfo_freq freq[1024];
	unsigned int n = 0, i;

	memset(freq, 0, sizeof(freq));
	gsm48_decode_freq_list(freq, cd, 16, 0xce, 1);

	printf("%s:", text);
	for (i = 0; i < 1024; i++) {
		if (!freq[i].mask)
			continue;
		printf(" %u", i);
		n++;
	}
	if (!n)
		printf(" (empty set)");
	printf("\n");
}

static void test_cell_chan_desc(struct gsm_network *net)
{
	struct gsm_bts *bts = bts_init(net);
	uint8_t cell_chan_desc[16];

	printf("Testing generation of the Cell Channel Description IE:\n");

	bts_model_unknown_init();
	bts->type = GSM_BTS_TYPE_UNKNOWN;
	bts->model = bts_model_find(bts->type);
	OSMO_ASSERT(bts->model != NULL);

	bts->band = GSM_BAND_900;
	bts->c0->arfcn = 10; /* BCCH carrier */

	/* Case a) only the BCCH carrier */
	bitvec_set_bit_pos(&bts->si_common.cell_alloc, bts->c0->arfcn, ONE);

	OSMO_ASSERT(generate_cell_chan_list(&cell_chan_desc[0], bts) == 0);
	print_cell_chan_desc(&cell_chan_desc[0], "Case a) only the BCCH carrier");

	/* Case b) more carriers from P-GSM band */
	bitvec_set_bit_pos(&bts->si_common.cell_alloc, 1, ONE);
	bitvec_set_bit_pos(&bts->si_common.cell_alloc, 3, ONE);
	bitvec_set_bit_pos(&bts->si_common.cell_alloc, 64, ONE);
	bitvec_set_bit_pos(&bts->si_common.cell_alloc, 99, ONE);
	bitvec_set_bit_pos(&bts->si_common.cell_alloc, 124, ONE);

	OSMO_ASSERT(generate_cell_chan_list(&cell_chan_desc[0], bts) == 0);
	print_cell_chan_desc(&cell_chan_desc[0], "Case b) more carriers from P-GSM band");

	/* Case c) more carriers from E-GSM band */
	bitvec_set_bit_pos(&bts->si_common.cell_alloc, 0, ONE);
	bitvec_set_bit_pos(&bts->si_common.cell_alloc, 975, ONE);
	bitvec_set_bit_pos(&bts->si_common.cell_alloc, 1001, ONE);
	bitvec_set_bit_pos(&bts->si_common.cell_alloc, 1023, ONE);

	OSMO_ASSERT(generate_cell_chan_list(&cell_chan_desc[0], bts) == 0);
	print_cell_chan_desc(&cell_chan_desc[0], "Case c) more carriers from E-GSM band");

	bts_del(bts);
}

static const struct log_info_cat log_categories[] = {
};

static const struct log_info log_info = {
	.cat = log_categories,
	.num_cat = ARRAY_SIZE(log_categories),
};

int main(int argc, char **argv)
{
	struct gsm_network *net;

	tall_bsc_ctx = talloc_named_const(NULL, 0, "gsm0408_test");

	osmo_init_logging2(tall_bsc_ctx, &log_info);
	log_set_log_level(osmo_stderr_target, LOGL_INFO);

	net = gsm_network_init(tall_bsc_ctx);
	if (!net) {
		printf("Network init failure.\n");
		return EXIT_FAILURE;
	}
	bsc_gsmnet = net;

	test_si2q_segfault(net);
	test_si2q_e(net);
	test_si2q_u(net);
	test_si2q_mu(net);
	test_si2q_long(net);

	test_si_ba_ind(net);

	test_gsm48_ra_id_by_bts();

	test_gsm48_multirate_config();

	test_cell_chan_desc(net);

	printf("Done.\n");

	return EXIT_SUCCESS;
}
