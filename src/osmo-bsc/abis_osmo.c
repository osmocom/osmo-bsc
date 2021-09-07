/* Osmocom specific protocols over Abis (IPA) */

/* (C) 2021 sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * Author: Pau Espin Pedrol <pespin@sysmocom.de>
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

#include <errno.h>
#include <osmocom/core/logging.h>

#include <osmocom/core/msgb.h>

#include <osmocom/gsm/protocol/ipaccess.h>
#include <osmocom/gsm/ipa.h>
#include <osmocom/gsm/protocol/gsm_12_21.h>

#include <osmocom/bsc/abis_osmo.h>
#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/bts.h>
#include <osmocom/bsc/pcuif_proto.h>
#include <osmocom/bsc/neighbor_ident.h>

#define OM_HEADROOM_SIZE	128

////////////////////////////////////////
// OSMO ABIS extensions (PCU)
///////////////////////////////////////
#define PCUIF_HDR_SIZE ( sizeof(struct gsm_pcu_if) - sizeof(((struct gsm_pcu_if *)0)->u) )

static struct msgb *abis_osmo_pcu_msgb_alloc(uint8_t msg_type, uint8_t bts_nr, size_t extra_size)
{
	struct msgb *msg;
	struct gsm_pcu_if *pcu_prim;
	msg = msgb_alloc_headroom(OM_HEADROOM_SIZE + sizeof(struct gsm_pcu_if) + extra_size,
				  OM_HEADROOM_SIZE, "IPA/ABIS/OSMO");
	/* Only header is filled, caller is responible for reserving + filling
	 * message type specific contents: */
	msgb_put(msg, PCUIF_HDR_SIZE);
	pcu_prim = (struct gsm_pcu_if *) msgb_data(msg);
	pcu_prim->msg_type = msg_type;
	pcu_prim->bts_nr = bts_nr;
	return msg;
}

/* Send a OML NM Message from BSC to BTS */
static int abis_osmo_pcu_sendmsg(struct gsm_bts *bts, struct msgb *msg)
{
	ipa_prepend_header_ext(msg, IPAC_PROTO_EXT_PCU);
	return abis_osmo_sendmsg(bts, msg);
}

static int abis_osmo_pcu_tx_neigh_addr_cnf(struct gsm_bts *bts, const struct gsm_pcu_if_neigh_addr_req *naddr_req,
				    uint8_t err_code, const struct osmo_cell_global_id_ps *cgi_ps)
{
	struct msgb *msg = abis_osmo_pcu_msgb_alloc(PCU_IF_MSG_CONTAINER, bts->bts_nr, sizeof(struct gsm_pcu_if_neigh_addr_cnf));
	struct gsm_pcu_if *pcu_prim = (struct gsm_pcu_if *) msgb_data(msg);
	struct gsm_pcu_if_neigh_addr_cnf *naddr_cnf = (struct gsm_pcu_if_neigh_addr_cnf *)&pcu_prim->u.container.data[0];

	msgb_put(msg, sizeof(pcu_prim->u.container) + sizeof(struct gsm_pcu_if_neigh_addr_cnf));
	pcu_prim->u.container.msg_type = PCU_IF_MSG_NEIGH_ADDR_CNF;
	osmo_store16be(sizeof(struct gsm_pcu_if_neigh_addr_cnf), &pcu_prim->u.container.length);

	naddr_cnf->orig_req = *naddr_req;
	naddr_cnf->err_code = err_code;
	if (err_code == 0) {
		osmo_store16be(cgi_ps->rai.lac.plmn.mcc, &naddr_cnf->cgi_ps.mcc);
		osmo_store16be(cgi_ps->rai.lac.plmn.mnc, &naddr_cnf->cgi_ps.mnc);
		naddr_cnf->cgi_ps.mnc_3_digits = cgi_ps->rai.lac.plmn.mnc_3_digits;
		osmo_store16be(cgi_ps->rai.lac.lac, &naddr_cnf->cgi_ps.lac);
		naddr_cnf->cgi_ps.rac = cgi_ps->rai.rac;
		osmo_store16be(cgi_ps->cell_identity, &naddr_cnf->cgi_ps.cell_identity);
	}

	return abis_osmo_pcu_sendmsg(bts, msg);
}

static int rcvmsg_pcu_neigh_addr_req(struct gsm_bts *bts, const struct gsm_pcu_if_neigh_addr_req *naddr_req)
{

	struct cell_ab ab;
	uint16_t local_lac, local_ci;
	struct osmo_cell_global_id_ps cgi_ps;
	int rc;

	local_lac = osmo_load16be(&naddr_req->local_lac);
	local_ci = osmo_load16be(&naddr_req->local_ci);
	ab = (struct cell_ab){
		.arfcn = osmo_load16be(&naddr_req->tgt_arfcn),
		.bsic = naddr_req->tgt_bsic,
	};

	LOGP(DNM, LOGL_INFO, "(bts=%d) Rx Neighbor Address Resolution Req (ARFCN=%u,BSIC=%u) from (LAC=%u,CI=%u)\n",
	     bts->nr, ab.arfcn, ab.bsic, local_lac, local_ci);

	if (!cell_ab_valid(&ab)) {
		rc = 2;
		goto do_fail;
	}

	if (neighbor_address_resolution(bts->network, &ab, local_lac, local_ci, &cgi_ps) < 0) {
		rc = 1;
		goto do_fail;
	}
	return abis_osmo_pcu_tx_neigh_addr_cnf(bts, naddr_req, 0, &cgi_ps);

do_fail:
	return abis_osmo_pcu_tx_neigh_addr_cnf(bts, naddr_req, rc, NULL);
}


static int rcvmsg_pcu_container(struct gsm_bts *bts, struct gsm_pcu_if_container *container, size_t container_len)
{
	int rc;
	uint16_t data_length = osmo_load16be(&container->length);

	if (container_len < sizeof(*container) + data_length) {
		LOGP(DNM, LOGL_ERROR, "ABIS_OSMO_PCU CONTAINER message inside (%d) too short\n",
		     container->msg_type);
		return -EINVAL;
	}

	LOGP(DNM, LOGL_INFO, "(bts=%d) Rx ABIS_OSMO_PCU CONTAINER msg type %u\n",
	     bts->nr, container->msg_type);

	switch (container->msg_type) {
	case PCU_IF_MSG_NEIGH_ADDR_REQ:
		if (data_length < sizeof(struct gsm_pcu_if_neigh_addr_req)) {
			LOGP(DNM, LOGL_ERROR, "ABIS_OSMO_PCU CONTAINER ANR_CNF message too short\n");
			return -EINVAL;
		}
		rc = rcvmsg_pcu_neigh_addr_req(bts, (struct gsm_pcu_if_neigh_addr_req *)&container->data);
		break;
	default:
		LOGP(DNM, LOGL_NOTICE, "(bts=%d) Rx ABIS_OSMO_PCU unexpected msg type (%u) inside container!\n",
		     bts->nr, container->msg_type);
		rc = -1;
	}

	return rc;
}

static int rcvmsg_pcu(struct gsm_bts *bts, struct msgb *msg)
{
	struct gsm_pcu_if *pcu_prim;
	int rc;

	if (msgb_l2len(msg) < PCUIF_HDR_SIZE) {
		LOGP(DNM, LOGL_ERROR, "ABIS_OSMO_PCU message too short\n");
		return -EIO;
	}

	pcu_prim = msgb_l2(msg);
	LOGP(DNM, LOGL_INFO, "(bts=%d) Rx ABIS_OSMO_PCU msg type %u\n",
	     pcu_prim->bts_nr, pcu_prim->msg_type);

	switch (pcu_prim->msg_type) {
	case PCU_IF_MSG_CONTAINER:
		if (msgb_l2len(msg) < PCUIF_HDR_SIZE + sizeof(pcu_prim->u.container)) {
			LOGP(DNM, LOGL_ERROR, "ABIS_OSMO_PCU CONTAINER message too short\n");
			rc = -EINVAL;
		} else {
			rc = rcvmsg_pcu_container(bts, &pcu_prim->u.container, msgb_l2len(msg) - PCUIF_HDR_SIZE);
		}
		break;
	default:
		LOGP(DNM, LOGL_NOTICE, "(bts=%d) Rx ABIS_OSMO_PCU unexpected msg type %u!\n",
			 pcu_prim->bts_nr, pcu_prim->msg_type);
		rc = -1;
	}

	return rc;
}

////////////////////////////////////////
// OSMO ABIS extensions (generic code)
///////////////////////////////////////

/* High-Level API */
/* Entry-point where L2 OSMO from BTS enters the NM code */
int abis_osmo_rcvmsg(struct msgb *msg)
{
	int rc;
	struct e1inp_sign_link *link = msg->dst;
	struct gsm_bts *bts = link->trx->bts;
	uint8_t *osmo_type = msgb_l2(msg);
	msg->l2h = osmo_type + 1;

	switch (*osmo_type) {
	case IPAC_PROTO_EXT_PCU:
		rc = rcvmsg_pcu(bts, msg);
		break;
	default:
		LOGP(DNM, LOGL_ERROR, "IPAC_PROTO_EXT 0x%x not supported!\n",
		     *osmo_type);
		rc = -EINVAL;
	}

	msgb_free(msg);
	return rc;
}


/* Send a OML NM Message from BSC to BTS */
int abis_osmo_sendmsg(struct gsm_bts *bts, struct msgb *msg)
{
	msg->dst = bts->osmo_link;

	msg->l2h = msg->data;

	return abis_sendmsg(msg);

}
