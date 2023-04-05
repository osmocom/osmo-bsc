/* (C) 2008 by Jan Luebbe <jluebbe@debian.org>
 * (C) 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2014 by Alexander Chemeris <Alexander.Chemeris@fairwaves.co>
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
#include <osmocom/bsc/bsc_subscriber.h>

#include <osmocom/core/application.h>
#include <osmocom/core/utils.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

struct bsc_subscr_store *bsc_subscribers;

#define VERBOSE_ASSERT(val, expect_op, fmt) \
	do { \
		printf(#val " == " fmt "\n", (val)); \
		OSMO_ASSERT((val) expect_op); \
	} while (0);

#define BSUB_USE "test"

static void assert_bsc_subscr(const struct bsc_subscr *bsub, const char *imsi)
{
	struct bsc_subscr *sfound;
	OSMO_ASSERT(bsub);
	OSMO_ASSERT(strcmp(bsub->imsi, imsi) == 0);

	sfound = bsc_subscr_find_by_imsi(bsc_subscribers, imsi, BSUB_USE);
	OSMO_ASSERT(sfound == bsub);

	bsc_subscr_put(sfound, BSUB_USE);
}

static void test_bsc_subscr(void)
{
	struct bsc_subscr *s1, *s2, *s3;
	const char *imsi1 = "1234567890";
	const char *imsi2 = "9876543210";
	const char *imsi3 = "5656565656";

	printf("Test BSC subscriber allocation and deletion\n");

	/* Check for emptiness */
	VERBOSE_ASSERT(llist_count(&bsc_subscribers->bsub_list), == 0, "%d");
	OSMO_ASSERT(bsc_subscr_find_by_imsi(bsc_subscribers, imsi1, BSUB_USE) == NULL);
	OSMO_ASSERT(bsc_subscr_find_by_imsi(bsc_subscribers, imsi2, BSUB_USE) == NULL);
	OSMO_ASSERT(bsc_subscr_find_by_imsi(bsc_subscribers, imsi3, BSUB_USE) == NULL);

	/* Allocate entry 1 */
	s1 = bsc_subscr_find_or_create_by_imsi(bsc_subscribers, imsi1, BSUB_USE);
	VERBOSE_ASSERT(llist_count(&bsc_subscribers->bsub_list), == 1, "%d");
	assert_bsc_subscr(s1, imsi1);
	VERBOSE_ASSERT(llist_count(&bsc_subscribers->bsub_list), == 1, "%d");
	OSMO_ASSERT(bsc_subscr_find_by_imsi(bsc_subscribers, imsi2, BSUB_USE) == NULL);

	/* Allocate entry 2 */
	s2 = bsc_subscr_find_or_create_by_imsi(bsc_subscribers, imsi2, BSUB_USE);
	bsc_subscr_set_tmsi(s2, 0x73517351);
	VERBOSE_ASSERT(llist_count(&bsc_subscribers->bsub_list), == 2, "%d");

	/* Allocate entry 3 */
	s3 = bsc_subscr_find_or_create_by_imsi(bsc_subscribers, imsi3, BSUB_USE);
	VERBOSE_ASSERT(llist_count(&bsc_subscribers->bsub_list), == 3, "%d");

	/* Check entries */
	assert_bsc_subscr(s1, imsi1);
	assert_bsc_subscr(s2, imsi2);
	assert_bsc_subscr(s3, imsi3);

	/* Free entry 1 */
	bsc_subscr_put(s1, BSUB_USE);
	s1 = NULL;
	VERBOSE_ASSERT(llist_count(&bsc_subscribers->bsub_list), == 2, "%d");
	OSMO_ASSERT(bsc_subscr_find_by_imsi(bsc_subscribers, imsi1, BSUB_USE) == NULL);

	assert_bsc_subscr(s2, imsi2);
	assert_bsc_subscr(s3, imsi3);

	/* Free entry 2 */
	bsc_subscr_put(s2, BSUB_USE);
	s2 = NULL;
	VERBOSE_ASSERT(llist_count(&bsc_subscribers->bsub_list), == 1, "%d");
	OSMO_ASSERT(bsc_subscr_find_by_imsi(bsc_subscribers, imsi1, BSUB_USE) == NULL);
	OSMO_ASSERT(bsc_subscr_find_by_imsi(bsc_subscribers, imsi2, BSUB_USE) == NULL);
	assert_bsc_subscr(s3, imsi3);

	/* Free entry 3 */
	bsc_subscr_put(s3, BSUB_USE);
	s3 = NULL;
	VERBOSE_ASSERT(llist_count(&bsc_subscribers->bsub_list), == 0, "%d");
	OSMO_ASSERT(bsc_subscr_find_by_imsi(bsc_subscribers, imsi3, BSUB_USE) == NULL);

	OSMO_ASSERT(llist_empty(&bsc_subscribers->bsub_list));
}

static const struct log_info_cat log_categories[] = {
	[DREF] = {
		.name = "DREF",
		.description = "Reference Counting",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
};

static const struct log_info log_info = {
	.cat = log_categories,
	.num_cat = ARRAY_SIZE(log_categories),
};

int main()
{
	void *ctx = talloc_named_const(NULL, 0, "bsc_subscr_test");
	printf("Testing BSC subscriber core code.\n");
	osmo_init_logging2(ctx, &log_info);
	log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_NONE);
	log_set_print_timestamp2(osmo_stderr_target, LOG_TIMESTAMP_NONE);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_category_hex(osmo_stderr_target, 0);
	log_set_print_category(osmo_stderr_target, 1);

	bsc_subscribers = bsc_subscr_store_alloc(ctx);

	test_bsc_subscr();

	printf("Done\n");
	return 0;
}
