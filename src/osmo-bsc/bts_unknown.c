/* Generic BTS - VTY code tries to allocate this BTS before type is known */

/* (C) 2010 by Daniel Willmann <daniel@totalueberwachung.de>
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


#include <osmocom/bsc/gsm_data.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/bsc/abis_nm.h>

static struct gsm_bts_model model_unknown = {
	.type = GSM_BTS_TYPE_UNKNOWN,
	.name = "unknown",
	.oml_rcvmsg = &abis_nm_rcvmsg,
	.nm_att_tlvdef = {
		.def = {
		},
	},
};

int bts_model_unknown_init(void)
{
	/* NOTE: the buffer is zero-initialized by compiler */
	model_unknown.features = (struct bitvec) {
		.data_len = sizeof(model_unknown._features_data),
		.data = &model_unknown._features_data[0],
	};

	return gsm_bts_model_register(&model_unknown);
}
