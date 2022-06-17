/* Measurement Report Processing */

/* (C) 2009 by Harald Welte <laforge@gnumonks.org>
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

#include <errno.h>

#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/meas_rep.h>

int meas_get_field(const struct gsm_meas_rep *rep,
		   enum meas_rep_field field)
{
	switch (field) {
	case MEAS_REP_DL_RXLEV_FULL:
		if (!(rep->flags & MEAS_REP_F_DL_VALID))
			return -EINVAL;
		/* Add BS Power value to rxlev: improve the RXLEV value by the amount of power that the BTS is reducing
		 * transmission. Note that bs_power is coded as dB, a positive value indicating the amount of power reduction
		 * on the downlink; rxlev is coded in dB, where a higher number means stronger signal. */
		return rep->dl.full.rx_lev + rep->bs_power_db;
	case MEAS_REP_DL_RXLEV_SUB:
		if (!(rep->flags & MEAS_REP_F_DL_VALID))
			return -EINVAL;
		/* Apply BS Power as explained above */
		return rep->dl.sub.rx_lev + rep->bs_power_db;
	case MEAS_REP_DL_RXQUAL_FULL:
		if (!(rep->flags & MEAS_REP_F_DL_VALID))
			return -EINVAL;
		return rep->dl.full.rx_qual;
	case MEAS_REP_DL_RXQUAL_SUB:
		if (!(rep->flags & MEAS_REP_F_DL_VALID))
			return -EINVAL;
		return rep->dl.sub.rx_qual;
	case MEAS_REP_UL_RXLEV_FULL:
		return rep->ul.full.rx_lev;
	case MEAS_REP_UL_RXLEV_SUB:
		return rep->ul.sub.rx_lev;
	case MEAS_REP_UL_RXQUAL_FULL:
		return rep->ul.full.rx_qual;
	case MEAS_REP_UL_RXQUAL_SUB:
		return rep->ul.sub.rx_qual;
	}

	return 0;
}


unsigned int calc_initial_idx(unsigned int array_size,
			      unsigned int meas_rep_idx,
			      unsigned int num_values)
{
	int offs, idx;

	/* from which element do we need to start if we're interested
	 * in an average of 'num' elements */
	offs = meas_rep_idx - num_values;

	if (offs < 0)
		idx = array_size + offs;
	else
		idx = offs;

	return idx;
}

static inline enum meas_rep_field choose_meas_rep_field(enum tdma_meas_field field, enum tdma_meas_dir dir,
							enum tdma_meas_set set, const struct gsm_meas_rep *meas_rep)
{
	if (set == TDMA_MEAS_SET_AUTO) {
		bool dtx_in_use;
		dtx_in_use = (meas_rep->flags & ((dir == TDMA_MEAS_DIR_UL) ? MEAS_REP_F_UL_DTX : MEAS_REP_F_DL_DTX));
		set = (dtx_in_use ? TDMA_MEAS_SET_SUB : TDMA_MEAS_SET_FULL);
	}

	osmo_static_assert(TDMA_MEAS_FIELD_RXLEV >= 0 && TDMA_MEAS_FIELD_RXLEV <= 1
			   && TDMA_MEAS_FIELD_RXQUAL >= 0 && TDMA_MEAS_FIELD_RXQUAL <= 1
			   && TDMA_MEAS_DIR_UL >= 0 && TDMA_MEAS_DIR_UL <= 1
			   && TDMA_MEAS_DIR_DL >= 0 && TDMA_MEAS_DIR_DL <= 1
			   && TDMA_MEAS_SET_FULL >= 0 && TDMA_MEAS_SET_FULL <= 1
			   && TDMA_MEAS_SET_SUB >= 0 && TDMA_MEAS_SET_SUB <= 1,
			   choose_meas_rep_field__mux_macro_input_ranges);
#define MUX(FIELD, DIR, SET) ((FIELD) + ((DIR) << 1) + ((SET) << 2))

	switch (MUX(field, dir, set)) {
	case MUX(TDMA_MEAS_FIELD_RXLEV, TDMA_MEAS_DIR_UL, TDMA_MEAS_SET_FULL):
		return MEAS_REP_UL_RXLEV_FULL;
	case MUX(TDMA_MEAS_FIELD_RXLEV, TDMA_MEAS_DIR_UL, TDMA_MEAS_SET_SUB):
		return MEAS_REP_UL_RXLEV_SUB;
	case MUX(TDMA_MEAS_FIELD_RXLEV, TDMA_MEAS_DIR_DL, TDMA_MEAS_SET_FULL):
		return MEAS_REP_DL_RXLEV_FULL;
	case MUX(TDMA_MEAS_FIELD_RXLEV, TDMA_MEAS_DIR_DL, TDMA_MEAS_SET_SUB):
		return MEAS_REP_DL_RXLEV_SUB;
	case MUX(TDMA_MEAS_FIELD_RXQUAL, TDMA_MEAS_DIR_UL, TDMA_MEAS_SET_FULL):
		return MEAS_REP_UL_RXQUAL_FULL;
	case MUX(TDMA_MEAS_FIELD_RXQUAL, TDMA_MEAS_DIR_UL, TDMA_MEAS_SET_SUB):
		return MEAS_REP_UL_RXQUAL_SUB;
	case MUX(TDMA_MEAS_FIELD_RXQUAL, TDMA_MEAS_DIR_DL, TDMA_MEAS_SET_FULL):
		return MEAS_REP_DL_RXQUAL_FULL;
	case MUX(TDMA_MEAS_FIELD_RXQUAL, TDMA_MEAS_DIR_DL, TDMA_MEAS_SET_SUB):
		return MEAS_REP_DL_RXQUAL_SUB;
	default:
		OSMO_ASSERT(false);
	}

#undef MUX
}

/* obtain an average over the last 'num' fields in the meas reps. For 'field', pass either DL_RXLEV or DL_RXQUAL, and
 * by tdma_meas_set, choose between full, subset or automatic choice of set. */
int get_meas_rep_avg(const struct gsm_lchan *lchan,
		     enum tdma_meas_field field, enum tdma_meas_dir dir, enum tdma_meas_set set,
		     unsigned int num)
{
	unsigned int i, idx;
	int avg = 0, valid_num = 0;

	if (num < 1)
		return -EINVAL;

	if (num > lchan->meas_rep_count)
		return -EINVAL;

	idx = calc_initial_idx(ARRAY_SIZE(lchan->meas_rep),
				lchan->meas_rep_idx, num);

	for (i = 0; i < num; i++) {
		int j = (idx+i) % ARRAY_SIZE(lchan->meas_rep);
		enum meas_rep_field use_field;
		int val;

		use_field = choose_meas_rep_field(field, dir, set, &lchan->meas_rep[j]);
		val = meas_get_field(&lchan->meas_rep[j], use_field);

		if (val >= 0) {
			avg += val;
			valid_num++;
		}
	}

	if (valid_num == 0)
		return -EINVAL;

	return avg / valid_num;
}

/* Check if N out of M last values for FIELD are >= bd */
int meas_rep_n_out_of_m_be(const struct gsm_lchan *lchan,
			   enum tdma_meas_field field, enum tdma_meas_dir dir, enum tdma_meas_set set,
			   unsigned int n, unsigned int m, int be)
{
	unsigned int i, idx;
	int count = 0;

	idx = calc_initial_idx(ARRAY_SIZE(lchan->meas_rep),
				lchan->meas_rep_idx, m);

	for (i = 0; i < m; i++) {
		int j = (idx + i) % ARRAY_SIZE(lchan->meas_rep);
		enum meas_rep_field use_field;
		int val;

		use_field = choose_meas_rep_field(field, dir, set, &lchan->meas_rep[j]);
		val = meas_get_field(&lchan->meas_rep[j], use_field);

		if (val >= be) /* implies that val < 0 will not count */
			count++;

		if (count >= n)
			return 1;
	}

	return 0;
}

const struct value_string tdma_meas_set_names[] = {
	{ TDMA_MEAS_SET_FULL, "full" },
	{ TDMA_MEAS_SET_SUB, "subset" },
	{ TDMA_MEAS_SET_AUTO, "auto" },
	{}
};
