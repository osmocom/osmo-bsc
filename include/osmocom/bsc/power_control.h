#pragma once

#include <stdint.h>
#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/meas_rep.h>

int lchan_ms_pwr_ctrl(struct gsm_lchan *lchan, const struct gsm_meas_rep *mr);

/* MS/BS Power related measurement averaging algo */
enum gsm_power_ctrl_meas_avg_algo {
	GSM_PWR_CTRL_MEAS_AVG_ALGO_NONE			= 0x00,
	GSM_PWR_CTRL_MEAS_AVG_ALGO_UNWEIGHTED		= 0x01,
	GSM_PWR_CTRL_MEAS_AVG_ALGO_WEIGHTED		= 0x02,
	GSM_PWR_CTRL_MEAS_AVG_ALGO_MOD_MEDIAN		= 0x03,
	/* EWMA is an Osmocom specific algo */
	GSM_PWR_CTRL_MEAS_AVG_ALGO_OSMO_EWMA		= 0x04,
};

/* MS/BS Power related measurement parameters */
struct gsm_power_ctrl_meas_params {
	/* Are these measurement paremeters to be taken into account by loop? */
	bool enabled;

	/* Thresholds (see 3GPP TS 45.008, section A.3.2.1) */
	uint8_t lower_thresh; /* lower (decreasing) direction */
	uint8_t upper_thresh; /* upper (increasing) direction */

	/* Threshold Comparators for lower (decreasing) direction */
	uint8_t lower_cmp_p; /* P1 for RxLev, P3 for RxQual */
	uint8_t lower_cmp_n; /* N1 for RxLev, N3 for RxQual */
	/* Threshold Comparators for upper (increasing) direction */
	uint8_t upper_cmp_p; /* P2 for RxLev, P4 for RxQual */
	uint8_t upper_cmp_n; /* N2 for RxLev, N4 for RxQual */

	/* Hreqave and Hreqt (see 3GPP TS 45.008, Annex A) */
	uint8_t h_reqave;
	uint8_t h_reqt;

	/* AVG algorithm and its specific parameters */
	enum gsm_power_ctrl_meas_avg_algo algo;
	union {
		/* Exponentially Weighted Moving Average */
		struct {
			/* Smoothing factor: higher the value - less smoothing */
			uint8_t alpha; /* 1 .. 99 (in %) */
		} ewma;
	};
};

enum gsm_power_ctrl_dir {
	GSM_PWR_CTRL_DIR_UL, /* MS Power Control */
	GSM_PWR_CTRL_DIR_DL, /* BS Power Control */
};

enum gsm_power_ctrl_mode {
	/* Do not send MS/BS Power Control IEs */
	GSM_PWR_CTRL_MODE_NONE = 0,
	/* Send MS/BS Power IE only (with target level) */
	GSM_PWR_CTRL_MODE_STATIC,
	/* Send MS/BS Power [Parameters] IEs (dynamic mode) */
	GSM_PWR_CTRL_MODE_DYN_BTS,
	/* Do not send MS/BS Power IEs and use BSC Power Loop */
	GSM_PWR_CTRL_MODE_DYN_BSC,

};

/* MS/BS Power Control Parameters */
struct gsm_power_ctrl_params {
	/* Power Control direction: Uplink or Downlink */
	enum gsm_power_ctrl_dir dir;
	/* Power Control mode to be used by the BTS */
	enum gsm_power_ctrl_mode mode;

	/* BS Power reduction value / maximum (in dB) */
	uint8_t bs_power_val_db; /* for static mode */
	uint8_t bs_power_max_db; /* for dynamic mode */

	/* Power change step size (dynamic mode only) */
	uint8_t inc_step_size_db; /* increasing direction */
	uint8_t red_step_size_db; /* reducing direction */

	/* Minimum interval between power level changes */
	uint8_t ctrl_interval; /* 1 step is 2 SACCH periods */

	/* Measurement averaging parameters for RxLev & RxQual */
	struct gsm_power_ctrl_meas_params rxqual_meas;
	struct gsm_power_ctrl_meas_params rxlev_meas;
	/* Measurement averaging parameters for C/I: */
	struct gsm_power_ctrl_meas_params ci_fr_meas;
	struct gsm_power_ctrl_meas_params ci_hr_meas;
	struct gsm_power_ctrl_meas_params ci_amr_fr_meas;
	struct gsm_power_ctrl_meas_params ci_amr_hr_meas;
	struct gsm_power_ctrl_meas_params ci_sdcch_meas;
	struct gsm_power_ctrl_meas_params ci_gprs_meas;
};

extern const struct gsm_power_ctrl_params power_ctrl_params_def;
void power_ctrl_params_def_reset(struct gsm_power_ctrl_params *params,
				 enum gsm_power_ctrl_dir dir);
