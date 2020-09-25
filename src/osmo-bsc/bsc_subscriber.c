/* GSM subscriber details for use in BSC land */

/*
 * (C) 2016 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 *
 * Author: Neels Hofmeyr <nhofmeyr@sysmocom.de>
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

#include <talloc.h>
#include <string.h>
#include <limits.h>

#include <osmocom/gsm/gsm48.h>
#include <osmocom/core/logging.h>

#include <osmocom/bsc/bsc_subscriber.h>
#include <osmocom/bsc/debug.h>

static void bsc_subscr_free(struct bsc_subscr *bsub);

static int bsub_use_cb(struct osmo_use_count_entry *e, int32_t old_use_count, const char *file, int line)
{
	struct bsc_subscr *bsub = e->use_count->talloc_object;
	int32_t total;
	int level;

	if (!e->use)
		return -EINVAL;

	total = osmo_use_count_total(&bsub->use_count);

	if (total == 0
	    || (total == 1 && old_use_count == 0 && e->count == 1))
		level = LOGL_INFO;
	else
		level = LOGL_DEBUG;

	LOGPSRC(DREF, level, file, line, "%s: %s %s: now used by %s\n",
		bsc_subscr_name(bsub),
		(e->count - old_use_count) > 0? "+" : "-", e->use,
		osmo_use_count_to_str_c(OTC_SELECT, &bsub->use_count));

	if (e->count < 0)
		return -ERANGE;

	if (total == 0)
		bsc_subscr_free(bsub);
	return 0;
}

static struct bsc_subscr *bsc_subscr_alloc(struct llist_head *list)
{
	struct bsc_subscr *bsub;

	bsub = talloc_zero(list, struct bsc_subscr);
	if (!bsub)
		return NULL;

	bsub->tmsi = GSM_RESERVED_TMSI;
	bsub->use_count = (struct osmo_use_count){
		.talloc_object = bsub,
		.use_cb = bsub_use_cb,
	};

	llist_add_tail(&bsub->entry, list);

	return bsub;
}

struct bsc_subscr *bsc_subscr_find_by_imsi(struct llist_head *list,
					   const char *imsi,
					   const char *use_token)
{
	struct bsc_subscr *bsub;

	if (!imsi || !*imsi)
		return NULL;

	llist_for_each_entry(bsub, list, entry) {
		if (!strcmp(bsub->imsi, imsi)) {
			bsc_subscr_get(bsub, use_token);
			return bsub;
		}
	}
	return NULL;
}

struct bsc_subscr *bsc_subscr_find_by_tmsi(struct llist_head *list,
					   uint32_t tmsi,
					   const char *use_token)
{
	struct bsc_subscr *bsub;

	if (tmsi == GSM_RESERVED_TMSI)
		return NULL;

	llist_for_each_entry(bsub, list, entry) {
		if (bsub->tmsi == tmsi) {
			bsc_subscr_get(bsub, use_token);
			return bsub;
		}
	}
	return NULL;
}

struct bsc_subscr *bsc_subscr_find_by_mi(struct llist_head *list, const struct osmo_mobile_identity *mi,
					 const char *use_token)
{
	if (!mi)
		return NULL;
	switch (mi->type) {
	case GSM_MI_TYPE_IMSI:
		return bsc_subscr_find_by_imsi(list, mi->imsi, use_token);
	case GSM_MI_TYPE_TMSI:
		return bsc_subscr_find_by_tmsi(list, mi->tmsi, use_token);
	default:
		return NULL;
	}
}

void bsc_subscr_set_imsi(struct bsc_subscr *bsub, const char *imsi)
{
	if (!bsub)
		return;
	osmo_strlcpy(bsub->imsi, imsi, sizeof(bsub->imsi));
}

struct bsc_subscr *bsc_subscr_find_or_create_by_imsi(struct llist_head *list,
						     const char *imsi,
						     const char *use_token)
{
	struct bsc_subscr *bsub;
	bsub = bsc_subscr_find_by_imsi(list, imsi, use_token);
	if (bsub)
		return bsub;
	bsub = bsc_subscr_alloc(list);
	if (!bsub)
		return NULL;
	bsc_subscr_set_imsi(bsub, imsi);
	bsc_subscr_get(bsub, use_token);
	return bsub;
}

struct bsc_subscr *bsc_subscr_find_or_create_by_tmsi(struct llist_head *list,
						     uint32_t tmsi,
						     const char *use_token)
{
	struct bsc_subscr *bsub;
	bsub = bsc_subscr_find_by_tmsi(list, tmsi, use_token);
	if (bsub)
		return bsub;
	bsub = bsc_subscr_alloc(list);
	if (!bsub)
		return NULL;
	bsub->tmsi = tmsi;
	bsc_subscr_get(bsub, use_token);
	return bsub;
}

struct bsc_subscr *bsc_subscr_find_or_create_by_mi(struct llist_head *list, const struct osmo_mobile_identity *mi,
						   const char *use_token)
{
	if (!mi)
		return NULL;
	switch (mi->type) {
	case GSM_MI_TYPE_IMSI:
		return bsc_subscr_find_or_create_by_imsi(list, mi->imsi, use_token);
	case GSM_MI_TYPE_TMSI:
		return bsc_subscr_find_or_create_by_tmsi(list, mi->tmsi, use_token);
	default:
		return NULL;
	}
}

static int bsc_subscr_name_buf(char *buf, size_t buflen, struct bsc_subscr *bsub)
{
	struct osmo_strbuf sb = { .buf = buf, .len = buflen };
	OSMO_STRBUF_PRINTF(sb, "subscr");
	if (!bsub) {
		OSMO_STRBUF_PRINTF(sb, "-null");
		return sb.chars_needed;
	}
	if (bsub->imsi[0])
		OSMO_STRBUF_PRINTF(sb, "-IMSI-%s", bsub->imsi);
	if (bsub->tmsi != GSM_RESERVED_TMSI)
		OSMO_STRBUF_PRINTF(sb, "-TMSI-0x%08x", bsub->tmsi);
	return sb.chars_needed;
}

static char *bsc_subscr_name_c(void *ctx, struct bsc_subscr *bsub)
{
	OSMO_NAME_C_IMPL(ctx, 64, "ERROR", bsc_subscr_name_buf, bsub)
}

const char *bsc_subscr_name(struct bsc_subscr *bsub)
{
	return bsc_subscr_name_c(OTC_SELECT, bsub);
}

/* Like bsc_subscr_name() but returns only characters approved by osmo_identifier_valid(), useful for
 * osmo_fsm_inst IDs. */
const char *bsc_subscr_id(struct bsc_subscr *bsub)
{
	return bsc_subscr_name(bsub);
}

static void bsc_subscr_free(struct bsc_subscr *bsub)
{
	llist_del(&bsub->entry);
	talloc_free(bsub);
}

#define BSUB_USE_LOG_FILTER "log_filter"

void log_set_filter_bsc_subscr(struct log_target *target,
			       struct bsc_subscr *bsc_subscr)
{
	struct bsc_subscr **fsub = (void*)&target->filter_data[LOG_FLT_BSC_SUBSCR];

	/* free the old data */
	if (*fsub) {
		bsc_subscr_put(*fsub, BSUB_USE_LOG_FILTER);
		*fsub = NULL;
	}

	if (bsc_subscr) {
		target->filter_map |= (1 << LOG_FLT_BSC_SUBSCR);
		*fsub = bsc_subscr;
		bsc_subscr_get(*fsub, BSUB_USE_LOG_FILTER);
	} else
		target->filter_map &= ~(1 << LOG_FLT_BSC_SUBSCR);
}
