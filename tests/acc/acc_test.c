/*
 * (C) 2020 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
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

#include <osmocom/core/application.h>
#include <osmocom/core/utils.h>
#include <osmocom/gsm/protocol/gsm_12_21.h>
#include <osmocom/gsm/gsm23003.h>

#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/bts.h>
#include <osmocom/bsc/abis_nm.h>
#include <osmocom/bsc/debug.h>

static void clock_debug(char* str)
{
	struct timespec ts;
	struct timeval tv;
	osmo_clock_gettime(CLOCK_MONOTONIC, &ts);
	osmo_gettimeofday(&tv, NULL);
	fprintf(stderr, "sys={%lu.%06lu}: %s\n",
		tv.tv_sec, tv.tv_usec, str);
}

#define bts_init(net) _bts_init(net, __func__)
static inline struct gsm_bts *_bts_init(struct gsm_network *net, const char *msg)
{
	struct gsm_bts *bts = gsm_bts_alloc(net, 0);
	if (!bts) {
		fprintf(stderr, "BTS allocation failure in %s()\n", msg);
		exit(1);
	}
	fprintf(stderr, "BTS allocation OK in %s()\n", msg);

	bts->network = net;

	return bts;
}

#define bts_del(bts) _bts_del(bts, __func__)
static inline void _bts_del(struct gsm_bts *bts, const char *msg)
{
	osmo_stat_item_group_free(bts->bts_statg);
	rate_ctr_group_free(bts->bts_ctrs);
	if (osmo_timer_pending(&bts->acc_mgr.rotate_timer))
		osmo_timer_del(&bts->acc_mgr.rotate_timer);
	/* no need to llist_del(&bts->list), we never registered the bts there. */
	talloc_free(bts);
	fprintf(stderr, "BTS deallocated OK in %s()\n", msg);
}

static void do_allowed_len_adm_loop(struct acc_mgr *acc_mgr, uint8_t jump)
{
	int i;
	fprintf(stderr, "%s(%" PRIu8 ")\n", __func__, jump);
	/* Test decreasing the administrative (VTY) max subset size */
	for (i = 10; i >= 0; i -= jump) {
		acc_mgr_set_len_allowed_adm(acc_mgr, i);
	}
	if (i != 0)
		acc_mgr_set_len_allowed_adm(acc_mgr, 0);
	/* Test increasing the administrative (VTY) max subset size */
	for (i = 0; i <= 10; i += jump) {
		acc_mgr_set_len_allowed_adm(acc_mgr, i);
	}
	if (i != 10)
		acc_mgr_set_len_allowed_adm(acc_mgr, 10);
}

static void do_allowed_len_ramp_loop(struct acc_mgr *acc_mgr, uint8_t jump)
{
	int i;
	fprintf(stderr, "%s(%" PRIu8 ")\n", __func__, jump);
	/* Test decreasing the administrative (VTY) max subset size */
	for (i = 10; i >= 0; i -= jump) {
		acc_mgr_set_len_allowed_ramp(acc_mgr, i);
	}
	if (i != 0)
		acc_mgr_set_len_allowed_ramp(acc_mgr, 0);
	/* Test increasing the administrative (VTY) max subset size */
	for (i = 0; i <= 10; i += jump) {
		acc_mgr_set_len_allowed_ramp(acc_mgr, i);
	}
	if (i != 10)
		acc_mgr_set_len_allowed_ramp(acc_mgr, 10);
}

static void test_acc_mgr_no_ramp(struct gsm_network *net)
{
	fprintf(stderr, "===%s===\n", __func__);
	struct gsm_bts *bts = bts_init(net);
	struct acc_mgr *acc_mgr = &bts->acc_mgr;

	/* Validate are all allowed by default after allocation: */
	OSMO_ASSERT(acc_mgr_get_len_allowed_adm(acc_mgr) == 10);
	OSMO_ASSERT(acc_mgr_get_len_allowed_ramp(acc_mgr) == 10);
	OSMO_ASSERT(acc_mgr->rotation_time_sec == ACC_MGR_QUANTUM_DEFAULT);
	OSMO_ASSERT(acc_mgr->allowed_subset_mask == 0x3ff);
	OSMO_ASSERT(acc_mgr->allowed_subset_mask_count == 10);
	OSMO_ASSERT(acc_mgr->allowed_permanent_count == 10);


	do_allowed_len_adm_loop(acc_mgr, 1);
	do_allowed_len_adm_loop(acc_mgr, 4);

	/* Now permantenly barr some ACC */
	fprintf(stderr, "*** Barring some ACCs ***\n");
	bts->si_common.rach_control.t2 |= 0x02;
	bts->si_common.rach_control.t3 |= 0xa5;
	acc_mgr_perm_subset_changed(acc_mgr, &bts->si_common.rach_control);

	do_allowed_len_adm_loop(acc_mgr, 1);
	do_allowed_len_adm_loop(acc_mgr, 4);

	fprintf(stderr, "*** Barring ALL ACCs ***\n");
	bts->si_common.rach_control.t2 |= 0x03;
	bts->si_common.rach_control.t3 |= 0xff;
	acc_mgr_perm_subset_changed(acc_mgr, &bts->si_common.rach_control);

	fprintf(stderr, "*** Barring zero ACCs ***\n");
	bts->si_common.rach_control.t2 = 0xfc;
	bts->si_common.rach_control.t3 = 0x00;
	acc_mgr_perm_subset_changed(acc_mgr, &bts->si_common.rach_control);

	bts_del(bts);
}

static void test_acc_mgr_manual_ramp(struct gsm_network *net)
{
	fprintf(stderr, "===%s===\n", __func__);
	struct gsm_bts *bts = bts_init(net);
	struct acc_mgr *acc_mgr = &bts->acc_mgr;

	/* Validate are all allowed by default after allocation: */
	OSMO_ASSERT(acc_mgr_get_len_allowed_adm(acc_mgr) == 10);
	OSMO_ASSERT(acc_mgr_get_len_allowed_ramp(acc_mgr) == 10);
	OSMO_ASSERT(acc_mgr->rotation_time_sec == ACC_MGR_QUANTUM_DEFAULT);
	OSMO_ASSERT(acc_mgr->allowed_subset_mask == 0x3ff);
	OSMO_ASSERT(acc_mgr->allowed_subset_mask_count == 10);
	OSMO_ASSERT(acc_mgr->allowed_permanent_count == 10);

	do_allowed_len_ramp_loop(acc_mgr, 1);
	do_allowed_len_ramp_loop(acc_mgr, 4);

	/* Now permantenly barr some ACC */
	fprintf(stderr, "*** Barring some ACCs ***\n");
	bts->si_common.rach_control.t2 |= 0x01;
	bts->si_common.rach_control.t3 |= 0xb3;
	acc_mgr_perm_subset_changed(acc_mgr, &bts->si_common.rach_control);

	do_allowed_len_ramp_loop(acc_mgr, 1);
	do_allowed_len_ramp_loop(acc_mgr, 4);

	fprintf(stderr, "*** Barring ALL ACCs ***\n");
	bts->si_common.rach_control.t2 |= 0x03;
	bts->si_common.rach_control.t3 |= 0xff;
	acc_mgr_perm_subset_changed(acc_mgr, &bts->si_common.rach_control);
	do_allowed_len_ramp_loop(acc_mgr, 1);
	do_allowed_len_ramp_loop(acc_mgr, 4);

	fprintf(stderr, "*** Barring zero ACCs ***\n");
	bts->si_common.rach_control.t2 = 0xfc;
	bts->si_common.rach_control.t3 = 0x00;
	acc_mgr_perm_subset_changed(acc_mgr, &bts->si_common.rach_control);
	do_allowed_len_ramp_loop(acc_mgr, 1);
	do_allowed_len_ramp_loop(acc_mgr, 4);

	fprintf(stderr, "*** Barring some ACCs + adm len 4 ***\n");
	acc_mgr_set_len_allowed_adm(acc_mgr, 4);
	bts->si_common.rach_control.t2 = 0xfd;
	bts->si_common.rach_control.t3 = 0xb3;
	acc_mgr_perm_subset_changed(acc_mgr, &bts->si_common.rach_control);
	do_allowed_len_ramp_loop(acc_mgr, 1);
	do_allowed_len_ramp_loop(acc_mgr, 4);

	bts_del(bts);
}

static void test_acc_mgr_rotate(struct gsm_network *net)
{
	fprintf(stderr, "===%s===\n", __func__);
	int i;
	struct gsm_bts *bts = bts_init(net);
	struct acc_mgr *acc_mgr = &bts->acc_mgr;

	osmo_gettimeofday_override_time = (struct timeval) {0, 0};

	/* Validate are all allowed by default after allocation: */
	OSMO_ASSERT(acc_mgr_get_len_allowed_adm(acc_mgr) == 10);
	OSMO_ASSERT(acc_mgr_get_len_allowed_ramp(acc_mgr) == 10);
	OSMO_ASSERT(acc_mgr->rotation_time_sec == ACC_MGR_QUANTUM_DEFAULT);
	OSMO_ASSERT(acc_mgr->allowed_subset_mask == 0x3ff);
	OSMO_ASSERT(acc_mgr->allowed_subset_mask_count == 10);
	OSMO_ASSERT(acc_mgr->allowed_permanent_count == 10);

	/* Test that rotation won't go over permanently barred ACC*/
	fprintf(stderr, "*** Barring one ACC ***\n");
	bts->si_common.rach_control.t2 |= 0x02;
	acc_mgr_perm_subset_changed(acc_mgr, &bts->si_common.rach_control);


	acc_mgr_set_rotation_time(acc_mgr, 2);
	acc_mgr_set_len_allowed_adm(acc_mgr, 4);

	for (i = 0; i < 20; i++) {
		osmo_gettimeofday_override_time.tv_sec += 2;
		clock_debug("select()");
		osmo_select_main(0);
	}

	bts_del(bts);
}

static void test_acc_ramp_fixed(struct gsm_network *net)
{
	fprintf(stderr, "===%s===\n", __func__);
	int i;
	struct gsm_bts *bts = bts_init(net);
	struct acc_mgr *acc_mgr = &bts->acc_mgr;
	struct acc_ramp *acc_ramp = &bts->acc_ramp;

	/* Validate are all allowed by default after allocation: */
	OSMO_ASSERT(acc_ramp_is_enabled(acc_ramp) == false);
	OSMO_ASSERT(acc_ramp_get_step_size(acc_ramp) == ACC_RAMP_STEP_SIZE_DEFAULT);
	OSMO_ASSERT(acc_ramp_get_step_interval(acc_ramp) == ACC_RAMP_STEP_INTERVAL_MIN);
	OSMO_ASSERT(acc_ramp_step_interval_is_dynamic(acc_ramp) == true);

	/* Set super high rotation time so it doesn't interfer here: */
	acc_mgr_set_rotation_time(acc_mgr, 5000);

	//acc_ramp_set_step_interval_dynamic(acc_ramp);
	OSMO_ASSERT(acc_ramp_set_step_interval(acc_ramp, 1) == -ERANGE);
	OSMO_ASSERT(acc_ramp_set_step_interval(acc_ramp, 50) == 0);
	acc_ramp_set_step_size(acc_ramp, 1);
	acc_ramp_set_enabled(acc_ramp, true);

	osmo_gettimeofday_override_time = (struct timeval) {0, 0};
	acc_ramp_trigger(acc_ramp);

	for (i = 0; i < 9; i++) {
		osmo_gettimeofday_override_time.tv_sec += 50;
		clock_debug("select()");
		osmo_select_main(0);
	}

	bts_del(bts);
}

static void test_acc_ramp_fixed2(struct gsm_network *net)
{
	fprintf(stderr, "===%s===\n", __func__);
	int i;
	struct gsm_bts *bts = bts_init(net);
	struct acc_mgr *acc_mgr = &bts->acc_mgr;
	struct acc_ramp *acc_ramp = &bts->acc_ramp;

	/* Validate are all allowed by default after allocation: */
	OSMO_ASSERT(acc_ramp_is_enabled(acc_ramp) == false);
	OSMO_ASSERT(acc_ramp_get_step_size(acc_ramp) == ACC_RAMP_STEP_SIZE_DEFAULT);
	OSMO_ASSERT(acc_ramp_get_step_interval(acc_ramp) == ACC_RAMP_STEP_INTERVAL_MIN);
	OSMO_ASSERT(acc_ramp_step_interval_is_dynamic(acc_ramp) == true);

	/* Set super high rotation time so it doesn't interfer here: */
	acc_mgr_set_rotation_time(acc_mgr, 5000);
	/* Set adm len to test that ramping won't go over it */
	acc_mgr_set_len_allowed_adm(acc_mgr, 7);

	acc_ramp_set_step_size(acc_ramp, 3);
	acc_ramp_set_enabled(acc_ramp, true);

	osmo_gettimeofday_override_time = (struct timeval) {0, 0};
	acc_ramp_trigger(acc_ramp);

	for (i = 0; i < 3; i++) {
		osmo_gettimeofday_override_time.tv_sec += ACC_RAMP_STEP_INTERVAL_MIN;
		clock_debug("select()");
		osmo_select_main(0);
	}

	bts_del(bts);
}

static void test_acc_ramp_fixed3(struct gsm_network *net)
{
	fprintf(stderr, "===%s===\n", __func__);
	int i;
	struct gsm_bts *bts = bts_init(net);
	struct acc_mgr *acc_mgr = &bts->acc_mgr;
	struct acc_ramp *acc_ramp = &bts->acc_ramp;

	/* Validate are all allowed by default after allocation: */
	OSMO_ASSERT(acc_ramp_is_enabled(acc_ramp) == false);
	OSMO_ASSERT(acc_ramp_get_step_size(acc_ramp) == ACC_RAMP_STEP_SIZE_DEFAULT);
	OSMO_ASSERT(acc_ramp_get_step_interval(acc_ramp) == ACC_RAMP_STEP_INTERVAL_MIN);
	OSMO_ASSERT(acc_ramp_step_interval_is_dynamic(acc_ramp) == true);

	/* Set super high rotation time so it doesn't interfer here: */
	acc_mgr_set_rotation_time(acc_mgr, 5000);
	/* Test that ramping won't go over permanently barred ACC*/
	fprintf(stderr, "*** Barring some ACCs ***\n");
	bts->si_common.rach_control.t2 |= 0x02;
	bts->si_common.rach_control.t3 |= 0xa5;
	acc_mgr_perm_subset_changed(acc_mgr, &bts->si_common.rach_control);

	acc_ramp_set_step_size(acc_ramp, 1);
	acc_ramp_set_enabled(acc_ramp, true);

	osmo_gettimeofday_override_time = (struct timeval) {0, 0};
	acc_ramp_trigger(acc_ramp);

	for (i = 0; i < 9; i++) {
		osmo_gettimeofday_override_time.tv_sec += ACC_RAMP_STEP_INTERVAL_MIN;
		clock_debug("select()");
		osmo_select_main(0);
	}

	bts_del(bts);
}

static void test_acc_ramp_dynamic(struct gsm_network *net)
{
	fprintf(stderr, "===%s===\n", __func__);
	char buf[128];
	unsigned int step_sec;
	struct gsm_bts *bts = bts_init(net);
	struct acc_mgr *acc_mgr = &bts->acc_mgr;
	struct acc_ramp *acc_ramp = &bts->acc_ramp;

	/* Validate are all allowed by default after allocation: */
	OSMO_ASSERT(acc_ramp_is_enabled(acc_ramp) == false);
	OSMO_ASSERT(acc_ramp_get_step_size(acc_ramp) == ACC_RAMP_STEP_SIZE_DEFAULT);
	OSMO_ASSERT(acc_ramp_get_step_interval(acc_ramp) == ACC_RAMP_STEP_INTERVAL_MIN);
	OSMO_ASSERT(acc_ramp_step_interval_is_dynamic(acc_ramp) == true);

	/* Set super high rotation time so it doesn't interfer here: */
	acc_mgr_set_rotation_time(acc_mgr, 5000);

	acc_ramp_set_step_interval_dynamic(acc_ramp);
	acc_ramp_set_step_size(acc_ramp, 1);
	acc_ramp_set_enabled(acc_ramp, true);

	bts->chan_load_avg = 0; /*set 70% channel load */

	osmo_gettimeofday_override_time = (struct timeval) {0, 0};
	acc_ramp_trigger(acc_ramp);

	while (osmo_timer_pending(&acc_ramp->step_timer)) {
		bts->chan_load_avg += 10;
		step_sec = ((bts->chan_load_avg * ACC_RAMP_STEP_INTERVAL_MAX) / 100);
		osmo_gettimeofday_override_time.tv_sec += step_sec;
		snprintf(buf, sizeof(buf), "select(): load=%" PRIu8 " -> step_sec=%u",
			 bts->chan_load_avg, step_sec);
		clock_debug(buf);
		osmo_select_main(0);
	}

	bts_del(bts);
}

static void test_acc_ramp_fixed_rotate(struct gsm_network *net)
{
	fprintf(stderr, "===%s===\n", __func__);
	struct gsm_bts *bts = bts_init(net);
	struct acc_mgr *acc_mgr = &bts->acc_mgr;
	struct acc_ramp *acc_ramp = &bts->acc_ramp;

	/* Validate are all allowed by default after allocation: */
	OSMO_ASSERT(acc_ramp_is_enabled(acc_ramp) == false);
	OSMO_ASSERT(acc_ramp_get_step_size(acc_ramp) == ACC_RAMP_STEP_SIZE_DEFAULT);
	OSMO_ASSERT(acc_ramp_get_step_interval(acc_ramp) == ACC_RAMP_STEP_INTERVAL_MIN);
	OSMO_ASSERT(acc_ramp_step_interval_is_dynamic(acc_ramp) == true);

	OSMO_ASSERT(acc_ramp_set_step_interval(acc_ramp, 250) == 0);
	acc_mgr_set_rotation_time(acc_mgr, 100);
	/* Test that ramping + rotation won't go over permanently barred ACC*/
	fprintf(stderr, "*** Barring one ACC ***\n");
	bts->si_common.rach_control.t2 |= 0x02;
	acc_mgr_perm_subset_changed(acc_mgr, &bts->si_common.rach_control);

	acc_ramp_set_step_size(acc_ramp, 1);
	acc_ramp_set_enabled(acc_ramp, true);

	osmo_gettimeofday_override_time = (struct timeval) {0, 0};
	acc_ramp_trigger(acc_ramp);

	while (true) {
		if (osmo_timer_pending(&acc_mgr->rotate_timer)) {
			if ((osmo_gettimeofday_override_time.tv_sec + 50) % 250 == 0)
				osmo_gettimeofday_override_time.tv_sec += 50;
			else
				osmo_gettimeofday_override_time.tv_sec += 100;
		} else if (osmo_timer_pending(&acc_ramp->step_timer)) {
			osmo_gettimeofday_override_time.tv_sec -= osmo_gettimeofday_override_time.tv_sec % 250;
			osmo_gettimeofday_override_time.tv_sec += 250;
		} else {
			/* Once ramping is done, adm level is big enough and hence
			 * rotation is not needed and will be disabled. We are then done
			 */
			break;
		}
		clock_debug("select()");
		osmo_select_main(0);
	}

	bts_del(bts);
}

static const struct log_info_cat log_categories[] = {
	[DRSL] = {
		.name = "DRSL",
		.description = "A-bis Radio Signalling Link (RSL)",
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
	osmo_gettimeofday_override_time = (struct timeval) {0, 0};

	tall_bsc_ctx = talloc_named_const(NULL, 0, "gsm0408_test");
	osmo_init_logging2(tall_bsc_ctx, &log_info);
	log_set_log_level(osmo_stderr_target, LOGL_INFO);
	log_set_print_category_hex(osmo_stderr_target, false);
	log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_NONE);
	log_set_use_color(osmo_stderr_target, 0);

	net = gsm_network_init(tall_bsc_ctx);
	if (!net) {
		fprintf(stderr, "Network init failure.\n");
		return EXIT_FAILURE;
	}

	test_acc_mgr_no_ramp(net);
	test_acc_mgr_manual_ramp(net);
	test_acc_mgr_rotate(net);
	test_acc_ramp_fixed(net);
	test_acc_ramp_fixed2(net);
	test_acc_ramp_fixed3(net);
	test_acc_ramp_dynamic(net);
	test_acc_ramp_fixed_rotate(net);

	return EXIT_SUCCESS;
}

/* Whenever ACC code changes the set of barred ACCs, gsm_bts_set_system_infos()
 * is called which ends up calling pcu_info_update */
void pcu_info_update(struct gsm_bts *bts) {
	struct gsm48_rach_control rach_control = {0};

	acc_mgr_apply_acc(&bts->acc_mgr, &rach_control);
	fprintf(stderr, "%s(): t2=0x%02" PRIx8 " t3=0x%02" PRIx8 "\n",
		__func__, rach_control.t2, rach_control.t3);
}


struct gsm_subscriber_connection *bsc_subscr_con_allocate(struct gsm_network *net) {
	OSMO_ASSERT(0);
}

bool on_gsm_ts_init(struct gsm_bts_trx_ts *ts) { return true; }
void ts_fsm_alloc(struct gsm_bts_trx_ts *ts) {}
int rsl_chan_ms_power_ctrl(struct gsm_lchan *lchan) { return 0; }
int rsl_sacch_filling(struct gsm_bts_trx *trx, uint8_t type, const uint8_t *data, int len) { return 0; }
int rsl_bcch_info(const struct gsm_bts_trx *trx, enum osmo_sysinfo_type si_type, const uint8_t *data, int len)
{ return 0; }
int gsm_generate_si(struct gsm_bts *bts, enum osmo_sysinfo_type si_type) { return 0; }
