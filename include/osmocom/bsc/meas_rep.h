#ifndef _MEAS_REP_H
#define _MEAS_REP_H

#include <stdint.h>

#include <osmocom/gsm/meas_rep.h>

#define MRC_F_PROCESSED	0x0001

/* extracted from a L3 measurement report IE */
struct gsm_meas_rep_cell {
	uint8_t rxlev;
	uint8_t bsic;
	uint8_t neigh_idx;
	uint16_t arfcn;
	unsigned int flags;
};

#define MEAS_REP_F_UL_DTX	0x01
#define MEAS_REP_F_DL_VALID	0x02
#define MEAS_REP_F_BA1		0x04
#define MEAS_REP_F_DL_DTX	0x08
#define MEAS_REP_F_MS_TO	0x10
#define MEAS_REP_F_MS_L1	0x20
#define MEAS_REP_F_FPC		0x40

/* parsed uplink and downlink measurement result */
struct gsm_meas_rep {
	/* back-pointer to the logical channel */
	struct gsm_lchan *lchan;

	/* number of the measurement report */
	uint8_t nr;
	/* flags, see MEAS_REP_F_* */
	unsigned int flags;

	/* uplink and downlink rxlev, rxqual; full and sub */
	struct gsm_meas_rep_unidir ul;
	struct gsm_meas_rep_unidir dl;

	uint8_t bs_power_db;
	/* according to 3GPP TS 48.058 § MS Timing Offset [-63; 192] */
	int16_t ms_timing_offset;
	struct {
		int8_t pwr;	/* MS power in dBm */
		uint8_t ta;	/* MS timing advance */
	} ms_l1;

	/* neighbor measurement reports for up to 6 cells */
	int num_cell;
	struct gsm_meas_rep_cell cell[6];
};

enum tdma_meas_field {
	TDMA_MEAS_FIELD_RXLEV = 0,
	TDMA_MEAS_FIELD_RXQUAL = 1,
};

enum tdma_meas_dir {
	TDMA_MEAS_DIR_UL = 0,
	TDMA_MEAS_DIR_DL = 1,
};

/* (function choose_meas_rep_field() depends on FULL and SUB being 0 and 1, but doesn't care about AUTO's value) */
enum tdma_meas_set {
	TDMA_MEAS_SET_FULL = 0,
	TDMA_MEAS_SET_SUB = 1,
	TDMA_MEAS_SET_AUTO,
};

extern const struct value_string tdma_meas_set_names[];
static inline const char *tdma_meas_set_name(enum tdma_meas_set val)
{ return get_value_string(tdma_meas_set_names, val); }
static inline enum tdma_meas_set tdma_meas_set_from_str(const char *name)
{ return get_string_value(tdma_meas_set_names, name); }

/* obtain an average over the last 'num' fields in the meas reps */
int get_meas_rep_avg(const struct gsm_lchan *lchan,
		     enum tdma_meas_field field, enum tdma_meas_dir dir, enum tdma_meas_set set,
		     unsigned int num);

/* Check if N out of M last values for FIELD are >= bd */
int meas_rep_n_out_of_m_be(const struct gsm_lchan *lchan,
			   enum tdma_meas_field field, enum tdma_meas_dir dir, enum tdma_meas_set set,
			   unsigned int n, unsigned int m, int be);

unsigned int calc_initial_idx(unsigned int array_size,
			      unsigned int meas_rep_idx,
			      unsigned int num_values);

#endif /* _MEAS_REP_H */
