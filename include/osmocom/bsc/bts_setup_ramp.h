/* (C) 2022 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 *
 * Author: Alexander Couzens <acouzens@sysmocom.de>
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

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/timer.h>

struct gsm_bts;
struct gsm_network;

enum bts_setup_ramp_state {
	BTS_SETUP_RAMP_INIT,	/*!< initial state */
	BTS_SETUP_RAMP_WAIT,	/*!< BTS has to wait, too many BTS configuring */
	BTS_SETUP_RAMP_READY,	/*!< BTS is allowed to configure */
};

struct bts_setup_ramp {
	enum bts_setup_ramp_state state;
	struct llist_head list;
};

struct bts_setup_ramp_net {
	unsigned count; /*!< max count */
	unsigned step_size; /*!< also the maximum concurrent bts to configure */

	struct llist_head head;
	struct osmo_timer_list timer;
	unsigned int step_interval; /*!< in seconds */
	bool enabled; /*!< enabled by vty */
	bool active; /*!< if currently active */
};

void bts_setup_ramp_init_bts(struct gsm_bts *bts);
void bts_setup_ramp_init_network(struct gsm_network *net);

bool bts_setup_ramp_active(struct gsm_network *net);
bool bts_setup_ramp_wait(struct gsm_bts *bts);
void bts_setup_ramp_remove(struct gsm_bts *bts);
int bts_setup_ramp_unblock_bts(struct gsm_bts *bts);

/* vty related functions */
void bts_setup_ramp_enable(struct gsm_network *net);
void bts_setup_ramp_disable(struct gsm_network *net);
void bts_setup_ramp_set_step_interval(struct gsm_network *net, unsigned int step_interval);
void bts_setup_ramp_set_step_size(struct gsm_network *net, unsigned int step_size);

const char *bts_setup_ramp_get_state_str(struct gsm_bts *bts);
