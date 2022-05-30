/* API to count total, allocated and free channels of all types */
#pragma once

struct gsm_bts;
struct gsm_bts_trx;
struct gsm_bts_trx_ts;
struct gsm_lchan;

void chan_counts_sig_init();
void chan_counts_ts_update(struct gsm_bts_trx_ts *ts);
void chan_counts_ts_clear(struct gsm_bts_trx_ts *ts);
void chan_counts_trx_update(struct gsm_bts_trx *trx);
void chan_counts_bsc_verify();

/* First array index to chan_counts.val. */
enum chan_counts_dim1 {
	CHAN_COUNTS1_ALL = 0,
	CHAN_COUNTS1_STATIC = 1,
	CHAN_COUNTS1_DYNAMIC = 2,
	_CHAN_COUNTS1_NUM
};

/* Second array index to chan_counts.val. */
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
	/* Signed type, so that chan_counts_diff() can return negative values. */
	int val[_CHAN_COUNTS1_NUM][_CHAN_COUNTS2_NUM][_GSM_LCHAN_MAX];
};

static inline void chan_counts_zero(struct chan_counts *counts)
{
	*counts = (struct chan_counts){0};
}

static inline bool chan_counts_is_zero(const struct chan_counts *counts)
{
	int i1, i2, i3;
	for (i1 = 0; i1 < _CHAN_COUNTS1_NUM; i1++) {
		for (i2 = 0; i2 < _CHAN_COUNTS2_NUM; i2++) {
			for (i3 = 0; i3 < _GSM_LCHAN_MAX; i3++) {
				if (counts->val[i1][i2][i3])
					return false;
			}
		}
	}
	return true;
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

static inline void chan_counts_dim2_sub(struct chan_counts *dst, enum chan_counts_dim1 dst_dim1,
					const struct chan_counts *sub, enum chan_counts_dim1 sub_dim1)
{
	int i;
	for (i = 0; i < _CHAN_COUNTS2_NUM; i++)
		chan_counts_dim3_sub(dst, dst_dim1, i, sub, sub_dim1, i);
}

static inline void chan_counts_add(struct chan_counts *dst, const struct chan_counts *add)
{
	int i;
	for (i = 0; i < _CHAN_COUNTS1_NUM; i++)
		chan_counts_dim2_add(dst, i, add, i);
}

static inline void chan_counts_sub(struct chan_counts *dst, const struct chan_counts *sub)
{
	int i;
	for (i = 0; i < _CHAN_COUNTS1_NUM; i++)
		chan_counts_dim2_sub(dst, i, sub, i);
}
