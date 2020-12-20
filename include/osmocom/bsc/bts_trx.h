#pragma once

#include <stdint.h>
#include <sys/types.h>
#include <stdbool.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/bitvec.h>
#include <osmocom/gsm/tlv.h>

#include <osmocom/abis/e1_input.h>

#include "osmocom/bsc/gsm_data.h"

struct gsm_bts;

#define TRX_NR_TS	8

struct gsm_bts_bb_trx {
	struct gsm_abis_mo mo;
};

/* One TRX in a BTS */
struct gsm_bts_trx {
	/* list header in bts->trx_list */
	struct llist_head list;

	struct gsm_bts *bts;
	/* number of this TRX in the BTS */
	uint8_t nr;
	/* human readable name / description */
	char *description;
	/* how do we talk RSL with this TRX? */
	struct gsm_e1_subslot rsl_e1_link;
	uint8_t rsl_tei;
	struct e1inp_sign_link *rsl_link;

	/* Timeout for initiating the RSL connection. */
	struct osmo_timer_list rsl_connect_timeout;

	/* Some BTS (specifically Ericsson RBS) have a per-TRX OML Link */
	struct e1inp_sign_link *oml_link;

	struct gsm_abis_mo mo;
	struct tlv_parsed nm_attr;
	struct gsm_bts_bb_trx bb_transc;

	uint16_t arfcn;
	int nominal_power;		/* in dBm */
	unsigned int max_power_red;	/* in actual dB */

	union {
		struct {
			struct {
				struct gsm_abis_mo mo;
			} bbsig;
			struct {
				struct gsm_abis_mo mo;
			} pa;
		} bs11;
		struct {
			unsigned int test_state;
			uint8_t test_nr;
			struct rxlev_stats rxlev_stat;
		} ipaccess;
		struct {
			struct osmo_fsm_inst *trx_fi;
			struct {
				struct om2k_mo om2k_mo;
			} trxc;
			struct {
				struct om2k_mo om2k_mo;
			} rx;
			struct {
				struct om2k_mo om2k_mo;
			} tx;
		} rbs2000;
	};
	struct gsm_bts_trx_ts ts[TRX_NR_TS];
};

static inline struct gsm_bts_trx *gsm_bts_bb_trx_get_trx(struct gsm_bts_bb_trx *bb_transc) {
	return (struct gsm_bts_trx *)container_of(bb_transc, struct gsm_bts_trx, bb_transc);
}

struct gsm_bts_trx *gsm_bts_trx_alloc(struct gsm_bts *bts);
char *gsm_trx_name(const struct gsm_bts_trx *trx);

struct gsm_lchan *rsl_lchan_lookup(struct gsm_bts_trx *trx, uint8_t chan_nr,
				   int *rc);

void gsm_trx_lock_rf(struct gsm_bts_trx *trx, bool locked, const char *reason);
bool trx_is_usable(const struct gsm_bts_trx *trx);

void gsm_trx_all_ts_dispatch(struct gsm_bts_trx *trx, uint32_t ts_ev, void *data);
int trx_count_free_ts(struct gsm_bts_trx *trx, enum gsm_phys_chan_config pchan);
bool trx_has_valid_pchan_config(const struct gsm_bts_trx *trx);

int gsm_bts_trx_set_system_infos(struct gsm_bts_trx *trx);
