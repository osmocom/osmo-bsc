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

int abis_osmo_pcu_tx_anr_req(struct gsm_bts *bts, const struct gsm48_cell_desc *cell_desc_li, unsigned int num_cells)
{
	struct msgb *msg = abis_osmo_pcu_msgb_alloc(PCU_IF_MSG_CONTAINER, bts->bts_nr, sizeof(struct gsm_pcu_if_anr_req));
	struct gsm_pcu_if *pcu_prim = (struct gsm_pcu_if *) msgb_data(msg);
	struct gsm_pcu_if_anr_req *anr_req = (struct gsm_pcu_if_anr_req *)&pcu_prim->u.container.data[0];

	msgb_put(msg, sizeof(pcu_prim->u.container) + sizeof(struct gsm_pcu_if_anr_req));
	pcu_prim->u.container.msg_type = PCU_IF_MSG_ANR_REQ;
	osmo_store16be(sizeof(struct gsm_pcu_if_anr_req), &pcu_prim->u.container.length);

	anr_req->num_cells = num_cells;
	OSMO_ASSERT(num_cells <= ARRAY_SIZE(anr_req->cell_list));
	if (num_cells)
		memcpy(anr_req->cell_list, cell_desc_li, sizeof(*cell_desc_li) * num_cells);

	return abis_osmo_pcu_sendmsg(bts, msg);
}

#define ANR_NEIGH_RXLEV_INVALID 0xff
static int rcvmsg_pcu_anr_cnf(struct gsm_bts *bts, const struct gsm_pcu_if_anr_cnf* anr_cnf)
{
	unsigned int i;
	struct timespec now;
	struct gsm_bts *neigh_bts;
	bool neigh_bts_found;
	struct neighbor *n;

	osmo_clock_gettime(CLOCK_MONOTONIC, &now);
	LOGP(DNM, LOGL_INFO, "(bts=%d) Rx ANR Confirmation (%u cells)\n",
	     bts->nr, anr_cnf->num_cells);

	for (i = 0; i < anr_cnf->num_cells; i++) {
		const struct gsm48_cell_desc *cell_desc = (const struct gsm48_cell_desc *)&anr_cnf->cell_list[i];
		uint16_t arfcn = (cell_desc->arfcn_hi << 8) | cell_desc->arfcn_lo;
		uint8_t bsic = (cell_desc->ncc << 3) | cell_desc->bcc;

		if (anr_cnf->rxlev_list[i] == ANR_NEIGH_RXLEV_INVALID) {
			LOGP(DNM, LOGL_INFO, "(bts=%d) ANR: ARFCN=%u BSIC=%u is NOT a neighbor (not found)\n",
			     bts->nr, arfcn, bsic);
			continue;
		}
		if (anr_cnf->rxlev_list[i] < bts->network->anr.rxlev_threshold) {
			LOGP(DNM, LOGL_INFO,
			    "(bts=%d) ANR: ARFCN=%u BSIC=%u RXLEV=%u (%d dBm) is NOT a neighbor (< rxlev %u)\n",
			     bts->nr, arfcn, bsic, anr_cnf->rxlev_list[i], anr_cnf->rxlev_list[i] - 110,
			     bts->network->anr.rxlev_threshold);
			continue;
		}
		LOGP(DNM, LOGL_INFO, "(bts=%d) ANR: ARFCN=%u BSIC=%u RXLEV=%u (%d dBm) is a neighbor\n",
		     bts->nr, arfcn, bsic, anr_cnf->rxlev_list[i], anr_cnf->rxlev_list[i] - 110);

		/* Find BTS owning ARFCN+BSIC: */
		neigh_bts_found = false;
		llist_for_each_entry(neigh_bts, &bts->network->bts_list, list) {
			if (neigh_bts->c0->arfcn != arfcn || neigh_bts->bsic != bsic)
				continue;
			neigh_bts_found = true;
			break;
		}
		if (!neigh_bts_found) {
			LOGP(DNM, LOGL_NOTICE, "(bts=%d) ANR: ARFCN=%u BSIC=%u RXLEV=%u (%d dBm) matches no BTS configured in BSC!\n",
			     bts->nr, arfcn, bsic, anr_cnf->rxlev_list[i], anr_cnf->rxlev_list[i] - 110);
			continue;
		}

		/* Try to find existing neighbour and update it. */
		neigh_bts_found = false;
		llist_for_each_entry(n, &bts->neighbors, entry) {
			if (n->type != NEIGHBOR_TYPE_BTS_NR)
				continue;
			if (n->bts_nr != neigh_bts->nr)
				continue;
			neigh_bts_found = true;
			n->last_meas_detected = now;
			break;
		}
		/* If the neighbour didn't exist yet, create it and add it to the list */
		if (!neigh_bts_found) {
			LOGP(DNM, LOGL_NOTICE, "(bts=%d) ANR: Added new dynamic neighbor BTS%d\n",
			     bts->nr, neigh_bts->nr);
			n = talloc(bts, struct neighbor);
			*n = (struct neighbor){
				.type = NEIGHBOR_TYPE_BTS_NR,
				.bts_nr = neigh_bts->nr,
				.dynamic = true,
				.last_meas_detected = now,
			};
			llist_add_tail(&n->entry, &bts->neighbors);
			/* TODO: force re-creation of SI? */
		}
	}
	return 0;
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
	case PCU_IF_MSG_ANR_CNF:
		if (data_length < sizeof(struct gsm_pcu_if_anr_cnf)) {
			LOGP(DNM, LOGL_ERROR, "ABIS_OSMO_PCU CONTAINER ANR_CNF message too short\n");
			return -EINVAL;
		}
		rc = rcvmsg_pcu_anr_cnf(bts, (struct gsm_pcu_if_anr_cnf*)&container->data);
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
