/* API to define Tnnn timers globally, configure in VTY and use for FSM state changes. */
#pragma once

#include <stdint.h>
#include <osmocom/core/utils.h>

struct osmo_fsm_inst;
struct vty;

enum T_unit {
	T_S = 0,	/*< most T are in seconds, keep 0 as default. */
	T_MS,		/*< milliseconds */
	T_M,		/*< minutes */
	T_CUSTOM,
};

extern const struct value_string T_unit_names[];
static inline const char *T_unit_name(enum T_unit val)
{ return get_value_string(T_unit_names, val); }

/* Define a GSM timer of the form Tnnn, with unit, default value and doc string. */
struct T_def {
	const int T; /*< T1234 number */
	const int default_val; /*< timeout duration (according to unit), default value. */
	const enum T_unit unit;
	const char *desc;
	int val; /*< currently active value, e.g. set by user config. */
};

/* Iterate an array of struct T_def, the last item should be fully zero, i.e. "{}" */
#define for_each_T_def(d, T_defs) \
	for (d = T_defs; d && (d->T || d->default_val || d->desc); d++)

int T_def_get(struct T_def *T_defs, int T, enum T_unit as_unit, int val_if_not_present);
void T_defs_reset(struct T_def *T_defs);
struct T_def *T_def_get_entry(struct T_def *T_defs, int T);

void T_defs_vty_init(struct T_def *T_defs, int cfg_parent_node);
void T_defs_vty_write(struct vty *vty, const char *indent);


struct state_timeout {
	int T;
	bool keep_timer;
};

struct state_timeout *get_state_timeout(uint32_t state, struct state_timeout *timeouts_array);

#define fsm_inst_state_chg_T(fi, state, timeouts_array, T_defs, default_timeout) \
	_fsm_inst_state_chg_T(fi, state, timeouts_array, T_defs, default_timeout, \
			      __FILE__, __LINE__)
int _fsm_inst_state_chg_T(struct osmo_fsm_inst *fi, uint32_t state,
			  struct state_timeout *timeouts_array,
			  struct T_def *T_defs, int default_timeout,
			  const char *file, int line);
