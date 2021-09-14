/* Report the cumulative counter of time for which a flag is true as rate counter. */
#pragma once

#include <stdint.h>

#include <osmocom/core/timer.h>

struct osmo_tdef;
struct rate_ctr;

/*! Configuration for time_cc.
 * Report the cumulative counter of time for which a flag is true as rate counter.
 * For example, for each second that the flag is true, increment a rate counter.
 *
 * The flag to be monitored is reported by time_cc_set_flag().
 *
 * The granularity defines how much time one rate counter increment represents:
 * the default configuration is gran_usec = 1000000, i.e. one rate counter increment represents one second.
 *
 * Reporting as rate counter is configurable by round_threshold_usec and forget_sum_usec, examples:
 *
 * round_threshold_usec:
 * - To get "ceil()" behavior, set round_threshold_usec = 1. This increments the rate counter for each gran_usec period
 *   where the flag was seen true, even if it was true for only a very short fraction of a gran_usec period.
 * - To get "round()" behavior, set round_threshold_usec = half of gran_usec. The rate counter increments when the flag
 *   has been true for 0.5 of a gran_usec (and then again at 1.5 * gran_usec of 'true' flag). round_threshold_usec = 0
 *   is a special value that means to use half of gran_usec.
 * - To get "floor()" behavior, set round_threshold_usec >= gran_usec. The rate counter increments when reaching full
 *   gran_usec periods of the flag being true.
 *
 * forget_sum_usec:
 * This is a tradeoff between the accuracy of the reported rate counter and making sure that the events reported are not
 * irrelevantly long ago.
 * - To keep sub-granularity-period surplus time forever, set forget_sum_usec = 0.
 * - To keep surplus time for up to a minute, set forget_sum_usec = 60000000 (60 seconds).
 * - To get rid of "leftover" time (almost) immediately after the flag goes false, set forget_sum_usec = 1.
 * - If gran_usec is set to one second and forget_sum_usec is set to one minute, the reported rate counter has a
 *   possible inaccuracy of 1/60th, but makes sure that no timings older than a minute affect the current reports.
 *
 * Reporting modes in detail:
 *
 * The rate_ctr increments when the cumulative counter passes round_threshold_usec (default: half of gran_usec).
 *
 *                        sum ^
 *                            |                                          ________
 *                            |                                         /
 *                            |                                        /
 *                            |                                       /
 *                   3*gran --+--------------------------------------+
 *                            |                                     /:
 *                            |                                    / :
 *                            | - - - - - - - - - - - - - - - - - /  :
 *                            |                                  /.  :
 *                            |                                 / .  :
 *                   2*gran --+--------------------------------+  .  :
 *                            |                               /:  .  :
 *                            |                              / :  .  :
 *                            | - - - - - - - - - -_________/  :  .  :
 *                            |                   /         .  :  .  :
 *                            |                  /          .  :  .  :
 *                   1*gran --+-----------------+           .  :  .  :
 *                            |                /:           .  :  .  :
 *                            |               / :           .  :  .  :
 *                            | - - - - - - -/  :           .  :  .  :
 *                            |             /.  :           .  :  .  :
 *                            | ....-------' .  :           .  :  .  :
 *                         0  +------------------------------------------------------------------------> elapsed time
 *                                           .  :           .  :  .  :
 *                               _   _      _______         ____________
 *                   flag:    __| |_| |____| .  :  |_______|.  :  .  :  |__________
 *                            f t f t f    t .  :  f       t.  :  .  :  f
 *   round_threshold_usec       :            .  :           .  :  .  :
 *                 = 1 usec:  0  1           .  :2          .  :3 .  :4  = "ceil()"
 *       = 0 == gran_usec/2:  0              1  :           2  :  3  :   = "round()"
 *             >= gran_usec:  0                 1              2     3   = "floor()"
 *
 */
struct time_cc_cfg {
	/*! Granularity in microseconds: nr of microseconds that one rate_ctr increment represents. A typical value is
	 * gran_usec = 1000000, meaning one rate counter increment represents one second. */
	uint64_t gran_usec;
	/*! Nr of microseconds above a full gran_usec at which to trigger rate_ctr_round. When zero, half a gran_usec. */
	uint64_t round_threshold_usec;
	/*! Forget counted sub-gran time after the flag was false for this long. */
	uint64_t forget_sum_usec;
	/*! Rate counter to report to, or NULL to not use it. */
	struct rate_ctr *rate_ctr;

	/*! Update gran_usec from this T timer value, or zero to not use any T timer. */
	int T_gran;
	/*! Update round_threshold_usec from this T timer value, or zero to not use any T timer. */
	int T_round_threshold;
	/*! Update forget_sum_usec from this T timer value, or zero to not use any T timer. */
	int T_forget_sum;
	/*! Look up T_gran and T_forget_sum in this list of timers, or NULL to not use any T timers. */
	struct osmo_tdef *T_defs;
};

/*! Report the cumulative counter of time for which a flag is true as rate counter.
 * See also time_cc_cfg for details on configuring.
 *
 * Usage:
 *
 *     struct my_obj {
 *             struct time_cc flag_cc;
 *     };
 *
 *     void my_obj_init(struct my_obj *my_obj)
 *     {
 *             time_cc_init(&my_obj->flag_cc);
 *             my_obj->flag_cc.cfg = (struct time_cc_cfg){
 *                             .gran_usec = 1000000,
 *                             .forget_sum_usec = 60000000,
 *                             .rate_ctr = rate_ctr_group_get_ctr(my_ctrg, MY_CTR_IDX),
 *                     };
 *             // optional: set initial flag state, default is 'false':
 *             // time_cc_set_flag(&my_obj->flag_cc, false);
 *     }
 *
 *     void my_obj_event(struct my_obj *my_obj, bool flag)
 *     {
 *             time_cc_set_flag(&my_obj->flag_cc, flag);
 *     }
 *
 *     void my_obj_destruct(struct my_obj *my_obj)
 *     {
 *             time_cc_cleanup(&my_obj->flag_cc);
 *     }
 */
struct time_cc {
	struct time_cc_cfg cfg;

	bool flag_state;

	/** Overall cumulative sum. Does not get reset for the entire lifetime of a time_cc.
	 * (Informational only, not used by the time_cc implementation.) */
	uint64_t total_sum;

	struct osmo_timer_list timer;

	/** CLOCK_MONOTONIC reading in microseconds, at the time when the time_cc instance started counting. */
	uint64_t start_time;
	/** CLOCK_MONOTONIC reading in microseconds, at the time when the time_cc last evaluated the flag state and
	 * possibly added to the cumulated sum. */
	uint64_t last_counted_time;

	/** Internal cumulative counter of time that flag_state was true. It may get reset to zero regularly, depending
	 * on cfg.forget_sum_usec. This is the basis for incrementing cfg.rate_ctr. */
	uint64_t sum;
	/** The amount of time that already reported cfg.rate_ctr increments account for. This may be ahead of or behind
	 * 'sum', depending on cfg.round_threshold_usec. */
	uint64_t reported_sum;
};

void time_cc_init(struct time_cc *tc);
void time_cc_set_flag(struct time_cc *tc, bool flag);
void time_cc_cleanup(struct time_cc *tc);
