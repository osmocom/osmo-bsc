/* sysmocom sysmoBTS specific code */

/* (C) 2010-2012 by Harald Welte <laforge@gnumonks.org>
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

#include <arpa/inet.h>

#include <osmocom/gsm/tlv.h>

#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/signal.h>
#include <osmocom/bsc/abis_nm.h>
#include <osmocom/abis/e1_input.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/talloc.h>
#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/abis_nm.h>
#include <osmocom/bsc/abis_rsl.h>
#include <osmocom/bsc/debug.h>
#include <osmocom/abis/subchan_demux.h>
#include <osmocom/abis/ipaccess.h>
#include <osmocom/core/logging.h>

extern struct gsm_bts_model bts_model_nanobts;

static struct gsm_bts_model model_sysmobts;

int bts_model_sysmobts_init(void)
{
	model_sysmobts = bts_model_nanobts;
	model_sysmobts.name = "sysmobts";
	model_sysmobts.type = GSM_BTS_TYPE_OSMOBTS;

	/* Unlike nanoBTS, sysmoBTS supports SI2bis and SI2ter fine */
	model_sysmobts.force_combined_si = false;

	model_sysmobts.features.data = &model_sysmobts._features_data[0];
	model_sysmobts.features.data_len =
				sizeof(model_sysmobts._features_data);
	memset(model_sysmobts.features.data, 0, model_sysmobts.features.data_len);

        osmo_bts_set_feature(&model_sysmobts.features, BTS_FEAT_GPRS);
	osmo_bts_set_feature(&model_sysmobts.features, BTS_FEAT_EGPRS);
	osmo_bts_set_feature(&model_sysmobts.features, BTS_FEAT_PAGING_COORDINATION);

	return gsm_bts_model_register(&model_sysmobts);
}
