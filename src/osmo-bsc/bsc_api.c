/* GSM 08.08 like API for OpenBSC. The bridge from MSC to BSC */

/* (C) 2010-2011 by Holger Hans Peter Freyther
 * (C) 2010-2011 by On-Waves
 * (C) 2009,2017 by Harald Welte <laforge@gnumonks.org>
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

#include <osmocom/bsc/bsc_api.h>
#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/signal.h>
#include <osmocom/bsc/abis_rsl.h>
#include <osmocom/bsc/chan_alloc.h>
#include <osmocom/bsc/handover.h>
#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/gsm_04_08_rr.h>
#include <osmocom/bsc/bsc_subscriber.h>
#include <osmocom/bsc/penalty_timers.h>
#include <osmocom/bsc/osmo_bsc_sigtran.h>
#include <osmocom/bsc/bsc_subscr_conn_fsm.h>
#include <osmocom/bsc/lchan_fsm.h>

#include <osmocom/gsm/protocol/gsm_08_08.h>
#include <osmocom/gsm/gsm48.h>

#include <osmocom/core/talloc.h>

int gsm0808_page(struct gsm_bts *bts, unsigned int page_group, unsigned int mi_len,
		 uint8_t *mi, int chan_type)
{
	return rsl_paging_cmd(bts, page_group, mi_len, mi, chan_type, false);
}

/*! \brief We received a GSM 08.08 CIPHER MODE from the MSC */
int gsm0808_cipher_mode(struct gsm_subscriber_connection *conn, int cipher,
			const uint8_t *key, int len, int include_imeisv)
{
	if (cipher > 0 && key == NULL) {
		LOGP(DRSL, LOGL_ERROR, "%s: Need to have an encryption key.\n",
		     bsc_subscr_name(conn->bsub));
		return -1;
	}

	if (len > MAX_A5_KEY_LEN) {
		LOGP(DRSL, LOGL_ERROR, "%s: The key is too long: %d\n",
		     bsc_subscr_name(conn->bsub), len);
		return -1;
	}

	LOGP(DRSL, LOGL_DEBUG, "(subscr %s) Cipher Mode: cipher=%d key=%s include_imeisv=%d\n",
	     bsc_subscr_name(conn->bsub), cipher, osmo_hexdump_nospc(key, len), include_imeisv);

	conn->lchan->encr.alg_id = RSL_ENC_ALG_A5(cipher);
	if (key) {
		conn->lchan->encr.key_len = len;
		memcpy(conn->lchan->encr.key, key, len);
	}

	return gsm48_send_rr_ciph_mode(conn->lchan, include_imeisv);
}
