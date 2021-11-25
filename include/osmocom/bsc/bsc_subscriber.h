/* GSM subscriber details for use in BSC land */

#pragma once

#include <stdint.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/use_count.h>
#include <osmocom/gsm/protocol/gsm_23_003.h>
#include <osmocom/gsm/gsm48.h>

struct log_target;

struct bsc_subscr {
	struct llist_head entry;
	struct osmo_use_count use_count;

	char imsi[GSM23003_IMSI_MAX_DIGITS+1];
	uint32_t tmsi;

	uint32_t active_paging_requests;
};

const char *bsc_subscr_name(struct bsc_subscr *bsub);
const char *bsc_subscr_id(struct bsc_subscr *bsub);

struct bsc_subscr *bsc_subscr_find_or_create_by_imsi(struct llist_head *list,
						     const char *imsi,
						     const char *use_token);
struct bsc_subscr *bsc_subscr_find_or_create_by_tmsi(struct llist_head *list,
						     uint32_t tmsi,
						     const char *use_token);
struct bsc_subscr *bsc_subscr_find_or_create_by_mi(struct llist_head *list, const struct osmo_mobile_identity *mi,
						   const char *use_token);

struct bsc_subscr *bsc_subscr_find_by_imsi(struct llist_head *list,
					   const char *imsi,
					   const char *use_token);
struct bsc_subscr *bsc_subscr_find_by_tmsi(struct llist_head *list,
					   uint32_t tmsi,
					   const char *use_token);
struct bsc_subscr *bsc_subscr_find_by_mi(struct llist_head *list, const struct osmo_mobile_identity *mi,
					 const char *use_token);

void bsc_subscr_set_imsi(struct bsc_subscr *bsub, const char *imsi);

#define bsc_subscr_get(bsc_subscr, use) \
	OSMO_ASSERT(osmo_use_count_get_put(&(bsc_subscr)->use_count, use, 1) == 0)
#define bsc_subscr_put(bsc_subscr, use) \
	OSMO_ASSERT(osmo_use_count_get_put(&(bsc_subscr)->use_count, use, -1) == 0)

void log_set_filter_bsc_subscr(struct log_target *target,
			       struct bsc_subscr *bsub);
