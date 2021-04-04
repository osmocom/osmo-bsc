/* Osmocom OsmoBTS specific code */

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
#include <osmocom/bsc/bts.h>
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

static struct gsm_bts_model model_osmobts;

int bts_model_osmobts_init(void)
{
	model_osmobts = bts_model_nanobts;
	model_osmobts.name = "osmo-bts";
	model_osmobts.type = GSM_BTS_TYPE_OSMOBTS;

	/* Unlike nanoBTS, osmo-bts does support SI2bis and SI2ter fine */
	model_osmobts.force_combined_si = false;

	model_osmobts.features.data = &model_osmobts._features_data[0];
	model_osmobts.features.data_len =
				sizeof(model_osmobts._features_data);
	memset(model_osmobts.features.data, 0, model_osmobts.features.data_len);

	osmo_bts_set_feature(&model_osmobts.features, BTS_FEAT_GPRS);
	osmo_bts_set_feature(&model_osmobts.features, BTS_FEAT_EGPRS);
	osmo_bts_set_feature(&model_osmobts.features, BTS_FEAT_PAGING_COORDINATION);
	osmo_bts_set_feature(&model_osmobts.features, BTS_FEAT_IPV6_NSVC);
	osmo_bts_set_feature(&model_osmobts.features, BTS_FEAT_CCN);

	model_osmobts.nm_att_tlvdef.def[NM_ATT_OSMO_NS_LINK_CFG].type = TLV_TYPE_TL16V;

	return gsm_bts_model_register(&model_osmobts);
}
