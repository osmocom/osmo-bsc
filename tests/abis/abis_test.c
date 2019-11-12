/*
 * (C) 2012 by Holger Hans Peter Freyther <zecke@selfish.org>
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

#include <osmocom/core/application.h>
#include <osmocom/core/utils.h>
#include <osmocom/gsm/protocol/gsm_12_21.h>
#include <osmocom/gsm/gsm23003.h>

#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/abis_nm.h>
#include <osmocom/bsc/debug.h>

static const uint8_t load_config[] = {
	0x42, 0x12, 0x00, 0x08, 0x31, 0x36, 0x38, 0x64,
	0x34, 0x37, 0x32, 0x00, 0x13, 0x00, 0x0b, 0x76,
	0x32, 0x30, 0x30, 0x62, 0x31, 0x34, 0x33, 0x64,
	0x30, 0x00, 0x42, 0x12, 0x00, 0x08, 0x31, 0x36,
	0x38, 0x64, 0x34, 0x37, 0x32, 0x00, 0x13, 0x00,
	0x0b, 0x76, 0x32, 0x30, 0x30, 0x62, 0x31, 0x34,
	0x33, 0x64, 0x31, 0x00
};

static void test_sw_selection(void)
{
	struct abis_nm_sw_desc descr[8], tmp;
	uint16_t len0, len1;
	int rc, pos;

	rc = abis_nm_get_sw_conf(load_config, ARRAY_SIZE(load_config),
				&descr[0], ARRAY_SIZE(descr));
	if (rc != 2) {
		printf("%s(): FAILED to parse the File Id/File version: %d\n",
		       __func__, rc);
		abort();
	}

	len0 = abis_nm_sw_desc_len(&descr[0], true);
	printf("len: %u\n", len0);
	printf("file_id:  %s\n", osmo_hexdump(descr[0].file_id, descr[0].file_id_len));
	printf("file_ver: %s\n", osmo_hexdump(descr[0].file_version, descr[0].file_version_len));

	len1 = abis_nm_sw_desc_len(&descr[1], true);
	printf("len: %u\n", len1);
	printf("file_id:  %s\n", osmo_hexdump(descr[1].file_id, descr[1].file_id_len));
	printf("file_ver: %s\n", osmo_hexdump(descr[1].file_version, descr[1].file_version_len));

	/* start */
	pos = abis_nm_select_newest_sw(descr, rc);
	if (pos != 1) {
		printf("Selected the wrong version: %d\n", pos);
		abort();
	}
	printf("SELECTED: %d\n", pos);

	/* shuffle */
	tmp = descr[0];
	descr[0] = descr[1];
	descr[1] = tmp;
	pos = abis_nm_select_newest_sw(descr, rc);
	if (pos != 0) {
		printf("Selected the wrong version: %d\n", pos);
		abort();
	}
	printf("SELECTED: %d\n", pos);
	printf("%s(): OK\n", __func__);
}

struct test_abis_nm_ipaccess_cgi {
	struct osmo_plmn_id plmn;
	uint16_t lac;
	uint16_t cell_identity;
	const char *expect;
};
static const struct test_abis_nm_ipaccess_cgi test_abis_nm_ipaccess_cgi_data[] = {
	{
		.plmn = { .mcc = 1, .mnc = 2, .mnc_3_digits = false },
		.lac = 3,
		.cell_identity = 4,
		.expect = "00f120" "0003" "0004",
	},
	{
		.plmn = { .mcc = 1, .mnc = 2, .mnc_3_digits = true },
		.lac = 3,
		.cell_identity = 4,
		.expect = "002100" "0003" "0004",
	},
	{
		.plmn = { .mcc = 0, .mnc = 0, .mnc_3_digits = false },
		.lac = 0,
		.cell_identity = 0,
		.expect = "00f000" "0000" "0000",
	},
	{
		.plmn = { .mcc = 0, .mnc = 0, .mnc_3_digits = true },
		.lac = 0,
		.cell_identity = 0,
		.expect = "000000" "0000" "0000",
	},
	{
		.plmn = { .mcc = 999, .mnc = 999, .mnc_3_digits = false },
		.lac = 65535,
		.cell_identity = 65535,
		.expect = "999999" "ffff" "ffff",
	},
	{
		.plmn = { .mcc = 909, .mnc = 90, .mnc_3_digits = false },
		.lac = 0xabcd,
		.cell_identity = 0x2345,
		.expect = "09f909" "abcd" "2345",
	},
	{
		.plmn = { .mcc = 909, .mnc = 90, .mnc_3_digits = true },
		.lac = 0xabcd,
		.cell_identity = 0x2345,
		.expect = "090990" "abcd" "2345",
	},
};

static void test_abis_nm_ipaccess_cgi()
{
	int i;
	bool pass = true;

	for (i = 0; i < ARRAY_SIZE(test_abis_nm_ipaccess_cgi_data); i++) {
		struct gsm_network net;
		struct gsm_bts bts;
		const struct test_abis_nm_ipaccess_cgi *t = &test_abis_nm_ipaccess_cgi_data[i];
		uint8_t result_buf[7] = {};
		char *result;
		bool ok;

		net.plmn = t->plmn;
		bts.network = &net;
		bts.location_area_code = t->lac;
		bts.cell_identity = t->cell_identity;

		abis_nm_ipaccess_cgi(result_buf, &bts);
		result = osmo_hexdump_nospc(result_buf, sizeof(result_buf));

		ok = (strcmp(result, t->expect) == 0);
		printf("%s[%d]: result=%s %s\n", __func__, i, result, ok ? "pass" : "FAIL");
		pass = pass && ok;
	}

	OSMO_ASSERT(pass);
}


static const struct log_info_cat log_categories[] = {
};

static const struct log_info log_info = {
	.cat = log_categories,
	.num_cat = ARRAY_SIZE(log_categories),
};

int main(int argc, char **argv)
{
	osmo_init_logging2(NULL, &log_info);

	test_sw_selection();
	test_abis_nm_ipaccess_cgi();

	return EXIT_SUCCESS;
}

struct gsm_subscriber_connection *bsc_subscr_con_allocate(struct gsm_network *net) {
	OSMO_ASSERT(0);
}

bool on_gsm_ts_init(struct gsm_bts_trx_ts *ts) { return true; }
void ts_fsm_alloc(struct gsm_bts_trx_ts *ts) {}
int rsl_chan_ms_power_ctrl(struct gsm_lchan *lchan) { return 0; }
