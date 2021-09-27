/* API to count total, allocated and free channels of all types */
#pragma once

struct gsm_bts;
struct gsm_bts_trx;

/* First array index to typedef chan_counts_arr. */
enum chan_counts_dim1 {
	CHAN_COUNTS1_ALL = 0,
	CHAN_COUNTS1_STATIC = 1,
	CHAN_COUNTS1_DYNAMIC = 2,
	_CHAN_COUNTS1_NUM
};

/* Second array index to typedef chan_counts_arr. */
enum chan_counts_dim2 {
	/* The maximum possible nr of lchans of this type. Counts all dynamic timeslots as if they are fully available
	 * for this type, regardless of the current pchan mode. (For CHAN_COUNTS1_STATIC, of course no dyn TS are counted
	 * at all.) */
	CHAN_COUNTS2_MAX_TOTAL = 0,
	/* Like MAX_TOTAL, but as soon as dynamic timeslots are switched to a specific pchan kind, current_total shrinks
	 * to count only currently present lchans (used and unused). */
	CHAN_COUNTS2_CURRENT_TOTAL = 1,
	/* Currently used lchans of this type. To get currently free lchans, calculate CURRENT_TOTAL - ALLOCATED. */
	CHAN_COUNTS2_ALLOCATED = 2,
	/* Currently assignable lchans of this type, same as CURRENT_TOTAL - ALLOCATED. */
	CHAN_COUNTS2_FREE = 3,
	_CHAN_COUNTS2_NUM
};

struct chan_counts {
	unsigned int val[_CHAN_COUNTS1_NUM][_CHAN_COUNTS2_NUM][_GSM_LCHAN_MAX];
};

void chan_counts_for_bts(struct chan_counts *bts_counts, const struct gsm_bts *bts);
void chan_counts_for_trx(struct chan_counts *trx_counts, const struct gsm_bts_trx *trx);

static inline void chan_counts_zero(struct chan_counts *counts)
{
	*counts = (struct chan_counts){0};
}

static inline void chan_counts_dim3_add(struct chan_counts *dst,
					enum chan_counts_dim1 dst_dim1, enum chan_counts_dim2 dst_dim2,
					const struct chan_counts *add,
					enum chan_counts_dim1 add_dim1, enum chan_counts_dim2 add_dim2)
{
	int i;
	for (i = 0; i < _GSM_LCHAN_MAX; i++)
		dst->val[dst_dim1][dst_dim2][i] += add->val[add_dim1][add_dim2][i];
}

static inline void chan_counts_dim3_sub(struct chan_counts *dst,
					enum chan_counts_dim1 dst_dim1, enum chan_counts_dim2 dst_dim2,
					const struct chan_counts *sub,
					enum chan_counts_dim1 sub_dim1, enum chan_counts_dim2 sub_dim2)
{
	int i;
	for (i = 0; i < _GSM_LCHAN_MAX; i++)
		dst->val[dst_dim1][dst_dim2][i] -= sub->val[sub_dim1][sub_dim2][i];
}

static inline void chan_counts_dim2_add(struct chan_counts *dst, enum chan_counts_dim1 dst_dim1,
					const struct chan_counts *add, enum chan_counts_dim1 add_dim1)
{
	int i;
	for (i = 0; i < _CHAN_COUNTS2_NUM; i++)
		chan_counts_dim3_add(dst, dst_dim1, i, add, add_dim1, i);
}

static inline void chan_counts_add(struct chan_counts *dst, const struct chan_counts *add)
{
	int i;
	for (i = 0; i < _CHAN_COUNTS1_NUM; i++)
		chan_counts_dim2_add(dst, i, add, i);
}
