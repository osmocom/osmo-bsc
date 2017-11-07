/*
 * (C) 2017 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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

#include <osmocom/core/application.h>

#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/osmo_bsc.h>
#include <osmocom/bsc/signal.h>
#include <osmocom/bsc/bsc_subscriber.h>
#include <osmocom/bsc/bsc_msc_data.h>
#include <osmocom/bsc/common_bsc.h>
#include <osmocom/bsc/osmo_bsc_rf.h>

struct msgb *msgb_from_hex(const char *label, uint16_t size, const char *hex)
{
	struct msgb *msg = msgb_alloc(size, label);
	unsigned char *rc;
	msg->l2h = msg->l3h = msg->head;
	rc = msgb_put(msg, osmo_hexparse(hex, msg->head, msgb_tailroom(msg)));
	OSMO_ASSERT(rc == msg->l2h);
	return msg;
}

uint16_t gl_expect_lac = 0;

/* override, requires '-Wl,--wrap=bsc_grace_paging_request' */
int __real_bsc_grace_paging_request(enum signal_rf rf_policy, struct bsc_subscr *subscr, int chan_needed,
				    struct bsc_msc_data *msc);
int __wrap_bsc_grace_paging_request(enum signal_rf rf_policy, struct bsc_subscr *subscr, int chan_needed,
				    struct bsc_msc_data *msc)
{
	if (subscr->lac == GSM_LAC_RESERVED_ALL_BTS)
		fprintf(stderr, "BSC paging started on entire BSS (%u)\n", subscr->lac);
	else
		fprintf(stderr, "BSC paging started with LAC %u\n", subscr->lac);
	OSMO_ASSERT(gl_expect_lac == subscr->lac);
	return 0;
}

struct {
	const char *msg;
	uint16_t expect_lac;
	int expect_rc;
} cell_identifier_tests[] = {
	{
		"001652080859512069000743940904010844601a03050065",
		/*                                         ^^^^^^ Cell Identifier List: LAC */
		0x65, 0
	},
	{
		"001452080859512069000743940904010844601a0106",
		/*                                         ^^ Cell Identifier List: BSS */
		GSM_LAC_RESERVED_ALL_BTS, 0
	},
	{
		"001952080859512069000743940904010844601a060415f5490065",
		/*                                         ^^^^^^^^^^^^ Cell Identifier List: LAI */
		GSM_LAC_RESERVED_ALL_BTS, 0
	},
};

void test_cell_identifier()
{
	int i;
	int rc;
	struct gsm_network *net;
	struct bsc_msc_data *msc;

	net = bsc_network_init(NULL, 1, 1, NULL);
	net->bsc_data->rf_ctrl = talloc_zero(NULL, struct osmo_bsc_rf);
	net->bsc_data->rf_ctrl->policy = S_RF_ON;

	msc = talloc_zero(net, struct bsc_msc_data);
	msc->network = net;

	log_set_log_level(osmo_stderr_target, LOGL_DEBUG);

	for (i = 0; i < ARRAY_SIZE(cell_identifier_tests); i++) {
		struct msgb *msg;
		fprintf(stderr, "\n%d:\n", i);
		msg = msgb_from_hex("test_cell_identifier", 1024, cell_identifier_tests[i].msg);

		gl_expect_lac = cell_identifier_tests[i].expect_lac;
		rc = bsc_handle_udt(msc, msg, msgb_l2len(msg));

		fprintf(stderr, "bsc_handle_udt() returned %d\n", rc);
		OSMO_ASSERT(rc == cell_identifier_tests[i].expect_rc);

		msgb_free(msg);
	}
}

int main(int argc, char **argv)
{
	osmo_init_logging(&log_info);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_timestamp(osmo_stderr_target, 0);
	log_set_print_filename(osmo_stderr_target, 0);
	log_set_print_category(osmo_stderr_target, 1);

	test_cell_identifier();

	return 0;
}
