/* Management functions to allocate/release struct gsm_lchan */
/* (C) 2008 by Harald Welte <laforge@gnumonks.org>
 * (C) 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
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
#ifndef _CHAN_ALLOC_H
#define _CHAN_ALLOC_H

#include "gsm_data.h"

struct gsm_subscriber_connection;

/* Free a logical channel (SDCCH, TCH, ...) */
void lchan_free(struct gsm_lchan *lchan);

struct pchan_load {
	struct load_counter pchan[_GSM_PCHAN_MAX];
};

void bts_chan_load(struct pchan_load *cl, const struct gsm_bts *bts);
void network_chan_load(struct pchan_load *pl, struct gsm_network *net);
void bts_update_t3122_chan_load(struct gsm_bts *bts);

#endif /* _CHAN_ALLOC_H */
