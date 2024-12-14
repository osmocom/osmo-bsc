/* GSM Network Management (OML) messages on the A-bis interface
 * 3GPP TS 12.21 version 8.0.0 Release 1999 / ETSI TS 100 623 V8.0.0 */

/* (C) 2008-2018 by Harald Welte <laforge@gnumonks.org>
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


#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <libgen.h>
#include <time.h>
#include <limits.h>
#include <inttypes.h>

#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/debug.h>
#include <osmocom/core/msgb.h>
#include <osmocom/gsm/protocol/gsm_12_21.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/gsm/abis_nm.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <osmocom/bsc/abis_nm.h>
#include <osmocom/bsc/misdn.h>
#include <osmocom/bsc/signal.h>
#include <osmocom/abis/e1_input.h>
#include <osmocom/bsc/chan_alloc.h>
#include <osmocom/bsc/bts.h>
#include <osmocom/bsc/nm_common_fsm.h>
#include <osmocom/gsm/bts_features.h>
#include <osmocom/bsc/ipaccess.h>
#include <osmocom/bsc/bts_ipaccess_nanobts_omlattr.h>

#define OM_ALLOC_SIZE		1024
#define OM_HEADROOM_SIZE	128
#define IPACC_SEGMENT_SIZE	245

/* max number of SW Description IEs we can parse */
#define SW_DESCR_MAX		5

#define LOGPMO(mo, ss, lvl, fmt, args ...) \
	LOGP(ss, lvl, "OC=%s(%02x) INST=(%02x,%02x,%02x): " fmt, \
	     get_value_string(abis_nm_obj_class_names, (mo)->obj_class), \
	     (mo)->obj_class, (mo)->obj_inst.bts_nr, (mo)->obj_inst.trx_nr, \
	     (mo)->obj_inst.ts_nr, ## args)

int abis_nm_tlv_parse(struct tlv_parsed *tp, struct gsm_bts *bts, const uint8_t *buf, int len)
{
	if (!bts->model)
		return -EIO;
	return tlv_parse(tp, &bts->model->nm_att_tlvdef, buf, len, 0, 0);
}

/* Parse OML Primary IP and port from tlv_parsed containing list of Reported Attributes */
int abis_nm_tlv_attr_primary_oml(struct tlv_parsed *tp, struct in_addr *ia, uint16_t *oml_port)
{
	const uint8_t* data;
	if (TLVP_PRES_LEN(tp, NM_ATT_IPACC_PRIM_OML_CFG_LIST, 7)) {
		data = TLVP_VAL(tp, NM_ATT_IPACC_PRIM_OML_CFG_LIST);
		if (NM_ATT_IPACC_PRIM_OML_CFG == *data) {
			ia->s_addr = htonl(osmo_load32be(data+1));
			*oml_port = osmo_load16be(data+5);
			return 0;
		}else {
			LOGP(DNM, LOGL_ERROR,
			     "Get Attributes Response: PRIM_OML_CFG_LIST has unexpected format: %s\n",
			     osmo_hexdump(data, TLVP_LEN(tp, NM_ATT_IPACC_PRIM_OML_CFG_LIST)));
		}
	}
	return -1;
}

/* Parse OML Primary IP and port from tlv_parsed containing list of Reported Attributes */
int abis_nm_tlv_attr_unit_id(struct tlv_parsed *tp, char* unit_id, size_t buf_len)
{
	const uint8_t* data;
	uint16_t len;
	if (TLVP_PRES_LEN(tp, NM_ATT_IPACC_UNIT_ID, 1)) {
		data = TLVP_VAL(tp, NM_ATT_IPACC_UNIT_ID);
		len = TLVP_LEN(tp, NM_ATT_IPACC_UNIT_ID);
		osmo_strlcpy(unit_id, (char*)data, OSMO_MIN(len, buf_len));
		return 0;
	}
	return -1;
}

static int is_in_arr(enum abis_nm_msgtype mt, const enum abis_nm_msgtype *arr, int size)
{
	int i;

	for (i = 0; i < size; i++) {
		if (arr[i] == mt)
			return 1;
	}

	return 0;
}

#if 0
/* is this msgtype the usual ACK/NACK type ? */
static int is_ack_nack(enum abis_nm_msgtype mt)
{
	return !is_in_arr(mt, no_ack_nack, ARRAY_SIZE(no_ack_nack));
}
#endif

/* is this msgtype a report ? */
static int is_report(enum abis_nm_msgtype mt)
{
	return is_in_arr(mt, abis_nm_reports, ARRAY_SIZE(abis_nm_reports));
}

#define MT_ACK(x)	(x+1)
#define MT_NACK(x)	(x+2)

static void fill_om_hdr(struct abis_om_hdr *oh, uint8_t len)
{
	oh->mdisc = ABIS_OM_MDISC_FOM;
	oh->placement = ABIS_OM_PLACEMENT_ONLY;
	oh->sequence = 0;
	oh->length = len;
}

static struct abis_om_fom_hdr *fill_om_fom_hdr(struct abis_om_hdr *oh, uint8_t len,
			    uint8_t msg_type, uint8_t obj_class,
			    uint8_t bts_nr, uint8_t trx_nr, uint8_t ts_nr)
{
	struct abis_om_fom_hdr *foh =
			(struct abis_om_fom_hdr *) oh->data;

	fill_om_hdr(oh, len+sizeof(*foh));
	foh->msg_type = msg_type;
	foh->obj_class = obj_class;
	foh->obj_inst.bts_nr = bts_nr;
	foh->obj_inst.trx_nr = trx_nr;
	foh->obj_inst.ts_nr = ts_nr;
	return foh;
}

static struct msgb *nm_msgb_alloc(void)
{
	return msgb_alloc_headroom(OM_ALLOC_SIZE, OM_HEADROOM_SIZE,
				   "OML");
}

int _abis_nm_sendmsg(struct msgb *msg)
{
	msg->l2h = msg->data;

	if (!msg->dst) {
		LOGP(DNM, LOGL_ERROR, "%s: msg->dst == NULL\n", __func__);
		msgb_free(msg);
		return -EINVAL;
	}

	return abis_sendmsg(msg);
}

/* Send a OML NM Message from BSC to BTS */
static int abis_nm_queue_msg(struct gsm_bts *bts, struct msgb *msg)
{
	msg->dst = bts->oml_link;

	/* queue OML messages */
	if (llist_empty(&bts->abis_queue) && !bts->abis_nm_pend) {
		bts->abis_nm_pend = OBSC_NM_W_ACK_CB(msg);
		return _abis_nm_sendmsg(msg);
	} else {
		msgb_enqueue(&bts->abis_queue, msg);
		return 0;
	}

}

int abis_nm_sendmsg(struct gsm_bts *bts, struct msgb *msg)
{
	OBSC_NM_W_ACK_CB(msg) = 1;
	return abis_nm_queue_msg(bts, msg);
}

static int abis_nm_sendmsg_direct(struct gsm_bts *bts, struct msgb *msg)
{
	OBSC_NM_W_ACK_CB(msg) = 0;
	return abis_nm_queue_msg(bts, msg);
}

static int abis_nm_rcvmsg_sw(struct msgb *mb);

/* Update the administrative state of a given object in our in-memory data
 * structures and send an event to the higher layer */
static int update_admstate(struct gsm_bts *bts, uint8_t obj_class,
			   struct abis_om_obj_inst *obj_inst, uint8_t adm_state)
{
	struct gsm_nm_state *nm_state;
	struct nm_statechg_signal_data nsd;

	memset(&nsd, 0, sizeof(nsd));

	nsd.obj = gsm_objclass2obj(bts, obj_class, obj_inst);
	if (!nsd.obj)
		return -EINVAL;
	nm_state = gsm_objclass2nmstate(bts, obj_class, obj_inst);
	if (!nm_state)
		return -1;

	nsd.bts = bts;
	nsd.obj_class = obj_class;
	nsd.old_state = *nm_state;
	nsd.new_state = *nm_state;
	nsd.obj_inst = obj_inst;

	nsd.new_state.administrative = adm_state;

	/* Update current state before emitting signal: */
	nm_state->administrative = adm_state;

	osmo_signal_dispatch(SS_NM, S_NM_STATECHG, &nsd);
	return 0;
}

static int abis_nm_rx_statechg_rep(struct msgb *mb)
{
	struct abis_om_hdr *oh = msgb_l2(mb);
	struct abis_om_fom_hdr *foh = msgb_l3(mb);
	struct e1inp_sign_link *sign_link = mb->dst;
	struct gsm_bts *bts = sign_link->trx->bts;
	struct tlv_parsed tp;
	struct gsm_nm_state *nm_state;
	struct nm_statechg_signal_data nsd;

	memset(&nsd, 0, sizeof(nsd));

	nsd.obj = gsm_objclass2obj(bts, foh->obj_class, &foh->obj_inst);
	if (!nsd.obj) {
		LOGPFOH(DNM, LOGL_ERROR, foh, "unknown managed object\n");
		return -EINVAL;
	}
	nm_state = gsm_objclass2nmstate(bts, foh->obj_class, &foh->obj_inst);
	if (!nm_state) {
		LOGPFOH(DNM, LOGL_ERROR, foh, "unknown managed object\n");
		return -EINVAL;
	}

	nsd.obj_class = foh->obj_class;
	nsd.old_state = *nm_state;
	nsd.new_state = *nm_state;
	nsd.obj_inst = &foh->obj_inst;
	nsd.bts = bts;

	if (abis_nm_tlv_parse(&tp, bts, foh->data, oh->length - sizeof(*foh)) < 0) {
		LOGPFOH(DNM, LOGL_ERROR, foh, "%s(): tlv_parse failed\n", __func__);
		return -EINVAL;
	}

	DEBUGPFOH(DNM, foh, "STATE CHG: ");
	if (TLVP_PRESENT(&tp, NM_ATT_OPER_STATE)) {
		nsd.new_state.operational = *TLVP_VAL(&tp, NM_ATT_OPER_STATE);
		DEBUGPC(DNM, "OP_STATE=%s ",
			abis_nm_opstate_name(nsd.new_state.operational));
	}
	if (TLVP_PRESENT(&tp, NM_ATT_AVAIL_STATUS)) {
		if (TLVP_LEN(&tp, NM_ATT_AVAIL_STATUS) == 0)
			nsd.new_state.availability = NM_AVSTATE_OK;
		else
			nsd.new_state.availability = *TLVP_VAL(&tp, NM_ATT_AVAIL_STATUS);
		DEBUGPC(DNM, "AVAIL=%s(%02x) ",
			abis_nm_avail_name(nsd.new_state.availability),
			nsd.new_state.availability);
	} else
		nsd.new_state.availability = NM_AVSTATE_OK;
	if (TLVP_PRESENT(&tp, NM_ATT_ADM_STATE)) {
		nsd.new_state.administrative = *TLVP_VAL(&tp, NM_ATT_ADM_STATE);
		DEBUGPC(DNM, "ADM=%2s ",
			get_value_string(abis_nm_adm_state_names,
					 nsd.new_state.administrative));
	}

	if ((nsd.new_state.administrative != 0 && nsd.old_state.administrative == 0) ||
	    nsd.new_state.operational != nsd.old_state.operational ||
	    nsd.new_state.availability != nsd.old_state.availability) {
		DEBUGPC(DNM, "\n");
		/* Update the state of a given object in our in-memory data
 		* structures and send an event to the higher layer */
		*nm_state = nsd.new_state;
		osmo_signal_dispatch(SS_NM, S_NM_STATECHG, &nsd);
	} else {
		DEBUGPC(DNM, "(No State change detected)\n");
	}
	return 0;
}

static inline void log_oml_fail_rep(const struct gsm_bts *bts, const char *type,
				    const char *severity, const uint8_t *p_val,
				    const char *text)
{
	enum abis_nm_pcause_type pcause = p_val[0];
	enum abis_mm_event_causes cause = osmo_load16be(p_val + 1);

	LOGPMO(&bts->mo, DNM, LOGL_ERROR, "Failure Event Report: ");
	if (type)
		LOGPC(DNM, LOGL_ERROR, "Type=%s, ", type);
	if (severity)
		LOGPC(DNM, LOGL_ERROR, "Severity=%s, ", severity);

	LOGPC(DNM, LOGL_ERROR, "Probable cause=%s: ",
	      get_value_string(abis_nm_pcause_type_names, pcause));

	if (pcause == NM_PCAUSE_T_MANUF)
		LOGPC(DNM, LOGL_ERROR, "%s, ",
		      get_value_string(abis_mm_event_cause_names, cause));
	else
		LOGPC(DNM, LOGL_ERROR, "%02X %02X ", p_val[1], p_val[2]);

	if (text) {
		LOGPC(DNM, LOGL_ERROR, "Additional Text=%s. ", text);
	}

	LOGPC(DNM, LOGL_ERROR, "\n");
}

static inline void handle_manufact_report(struct gsm_bts *bts, const uint8_t *p_val, const char *type,
					  const char *severity, const char *text)
{
	enum abis_mm_event_causes cause = osmo_load16be(p_val + 1);

	switch (cause) {
	case OSMO_EVT_PCU_VERS:
		if (text) {
			LOGPMO(&bts->mo, DNM, LOGL_NOTICE, "Reported connected PCU version %s\n", text);
			osmo_strlcpy(bts->pcu_version, text, sizeof(bts->pcu_version));
		} else {
			LOGPMO(&bts->mo, DNM, LOGL_ERROR, "Reported PCU disconnection.\n");
			bts->pcu_version[0] = '\0';
		}
		break;
	default:
		log_oml_fail_rep(bts, type, severity, p_val, text);
	};
}

/* Parse into newly allocated struct abis_nm_fail_evt_rep, caller must free it. */
struct nm_fail_rep_signal_data *abis_nm_fail_evt_rep_parse(struct msgb *mb, struct gsm_bts *bts)
{
	struct abis_om_hdr *oh = msgb_l2(mb);
	struct abis_om_fom_hdr *foh = msgb_l3(mb);
	struct nm_fail_rep_signal_data *sd;
	const uint8_t *p_val = NULL;
	char *p_text = NULL;
	const char *e_type = NULL, *severity = NULL;

	sd = talloc_zero(tall_bsc_ctx, struct nm_fail_rep_signal_data);
	OSMO_ASSERT(sd);

	if (abis_nm_tlv_parse(&sd->tp, bts, foh->data, oh->length - sizeof(*foh)) < 0) {
		LOGPFOH(DNM, LOGL_ERROR, foh, "%s(): tlv_parse failed\n", __func__);
		goto fail;
	}

	if (TLVP_PRESENT(&sd->tp, NM_ATT_ADD_TEXT)) {
		const uint8_t *val = TLVP_VAL(&sd->tp, NM_ATT_ADD_TEXT);
		p_text = talloc_strndup(sd, (const char *) val, TLVP_LEN(&sd->tp, NM_ATT_ADD_TEXT));
	}

	if (TLVP_PRESENT(&sd->tp, NM_ATT_EVENT_TYPE))
		e_type = abis_nm_event_type_name(*TLVP_VAL(&sd->tp, NM_ATT_EVENT_TYPE));

	if (TLVP_PRESENT(&sd->tp, NM_ATT_SEVERITY))
		severity = abis_nm_severity_name(*TLVP_VAL(&sd->tp, NM_ATT_SEVERITY));

	if (TLVP_PRESENT(&sd->tp, NM_ATT_PROB_CAUSE))
		p_val = TLVP_VAL(&sd->tp, NM_ATT_PROB_CAUSE);

	sd->bts = bts;
	sd->msg = mb;
	if (e_type)
		sd->parsed.event_type = e_type;
	else
		sd->parsed.event_type = talloc_strdup(sd, "<none>");
	if (severity)
		sd->parsed.severity = severity;
	else
		sd->parsed.severity = talloc_strdup(sd, "<none>");
	if (p_text)
		sd->parsed.additional_text = p_text;
	else
		sd->parsed.additional_text = talloc_strdup(sd, "<none>");
	sd->parsed.probable_cause = p_val;

	return sd;
fail:
	talloc_free(sd);
	return NULL;
}

static int rx_fail_evt_rep(struct msgb *mb, struct gsm_bts *bts)
{
	struct abis_om_fom_hdr *foh = msgb_l3(mb);
	struct nm_fail_rep_signal_data *sd;
	int rc = 0;
	const uint8_t *p_val;
	const char *e_type, *severity, *p_text;
	struct bts_oml_fail_rep *entry;

	/* Store copy in bts->oml_fail_rep */
	entry = talloc_zero(bts, struct bts_oml_fail_rep);
	OSMO_ASSERT(entry);
	entry->time = time(NULL);
	entry->mb = msgb_copy_c(entry, mb, "OML failure report");
	llist_add(&entry->list, &bts->oml_fail_rep);

	/* Limit list size */
	if (llist_count(&bts->oml_fail_rep) > 50) {
		struct bts_oml_fail_rep *old = llist_last_entry(&bts->oml_fail_rep, struct bts_oml_fail_rep, list);
		llist_del(&old->list);
		talloc_free(old);
	}

	sd = abis_nm_fail_evt_rep_parse(mb, bts);
	if (!sd) {
		LOGPFOH(DNM, LOGL_ERROR, foh, "Failed to parse Failure Event Report\n");
		return -EINVAL;
	}
	e_type = sd->parsed.event_type;
	severity = sd->parsed.severity;
	p_text = sd->parsed.additional_text;
	p_val = sd->parsed.probable_cause;

	if (p_val) {
		switch (p_val[0]) {
		case NM_PCAUSE_T_MANUF:
			handle_manufact_report(bts, p_val, e_type, severity,
					       p_text);
			break;
		default:
			log_oml_fail_rep(bts, e_type, severity, p_val, p_text);
		};
	} else {
		LOGPFOH(DNM, LOGL_ERROR, foh, "Failure Event Report without Probable Cause?!\n");
		rc = -EINVAL;
	}

	osmo_signal_dispatch(SS_NM, S_NM_FAIL_REP, sd);
	talloc_free(sd);
	return rc;
}

static int abis_nm_rcvmsg_report(struct msgb *mb, struct gsm_bts *bts)
{
	struct abis_om_fom_hdr *foh = msgb_l3(mb);
	uint8_t mt = foh->msg_type;

	switch (mt) {
	case NM_MT_STATECHG_EVENT_REP:
		return abis_nm_rx_statechg_rep(mb);
		break;
	case NM_MT_SW_ACTIVATED_REP:
		DEBUGPFOH(DNM, foh, "Software Activated Report\n");
		osmo_signal_dispatch(SS_NM, S_NM_SW_ACTIV_REP, mb);
		break;
	case NM_MT_FAILURE_EVENT_REP:
		rx_fail_evt_rep(mb, bts);
		break;
	case NM_MT_TEST_REP:
		DEBUGPFOH(DNM, foh, "Test Report\n");
		osmo_signal_dispatch(SS_NM, S_NM_TEST_REP, mb);
		break;
	default:
		LOGPFOH(DNM, LOGL_NOTICE, foh, "unknown NM report MT 0x%02x\n", mt);
		break;
	};

	return 0;
}

/* Activate the specified software into the BTS */
static int ipacc_sw_activate(struct gsm_bts *bts, uint8_t obj_class, uint8_t i0, uint8_t i1,
			     uint8_t i2, const struct abis_nm_sw_desc *sw_desc)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();
	uint16_t len = abis_nm_sw_desc_len(sw_desc, true);

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, len, NM_MT_ACTIVATE_SW, obj_class, i0, i1, i2);
	abis_nm_put_sw_desc(msg, sw_desc, true);

	return abis_nm_sendmsg(bts, msg);
}

int abis_nm_select_newest_sw(const struct abis_nm_sw_desc *sw_descr,
			     const size_t size)
{
	int res = 0;
	int i;

	for (i = 1; i < size; ++i) {
		if (memcmp(sw_descr[res].file_version, sw_descr[i].file_version,
			   OSMO_MIN(sw_descr[i].file_version_len,
				    sw_descr[res].file_version_len)) < 0) {
			res = i;
		}
	}

	return res;
}

static inline bool handle_attr(const struct gsm_bts *bts, enum bts_attribute id, uint8_t *val, uint8_t len)
{
	switch (id) {
	case BTS_TYPE_VARIANT:
		LOGPMO(&bts->mo, DNM, LOGL_NOTICE, "Reported variant: %s\n", val);
		break;
	case BTS_SUB_MODEL:
		LOGPMO(&bts->mo, DNM, LOGL_NOTICE, "Reported submodel: %s\n", val);
		break;
	default:
		return false;
	}
	return true;
}

/* Parse Attribute Response Info - return pointer to the actual content */
static inline const uint8_t *parse_attr_resp_info_unreported(const struct abis_om_fom_hdr *foh,
							     const uint8_t *ari, uint16_t ari_len,
							     uint16_t *out_len)
{
	uint8_t num_unreported = ari[0], i;

	DEBUGPFOH(DNM, foh, "Get Attributes Response Info: %u bytes total "
		  "with %u unreported attributes\n", ari_len, num_unreported);

	/* +1 because we have to account for number of unreported attributes, prefixing the list: */
	for (i = 0; i < num_unreported; i++)
		LOGPFOH(DNM, LOGL_ERROR, foh, "Attribute %s is unreported\n",
			get_value_string(abis_nm_att_names, ari[i + 1]));

	/* the data starts right after the list of unreported attributes + space for length of that list */
	if (out_len)
		*out_len = ari_len - (num_unreported + 1);

	return ari + num_unreported + 1; /* we have to account for 1st byte with number of unreported attributes */
}

/* Parse Attribute Response Info content for 3GPP TS 52.021 §9.4.30 Manufacturer Id */
static void parse_osmo_bts_features(struct gsm_bts *bts,
				    const uint8_t *data, uint16_t data_len)
{
	/* log potential BTS feature vector overflow */
	if (data_len > sizeof(bts->_features_data)) {
		LOGPMO(&bts->mo, DNM, LOGL_NOTICE,
		       "Get Attributes Response: feature vector is truncated "
		       "(from %u to %zu bytes)\n", data_len, sizeof(bts->_features_data));
		data_len = sizeof(bts->_features_data);
	}

	/* check that max. expected BTS attribute is above given feature vector length */
	if (data_len > OSMO_BYTES_FOR_BITS(_NUM_BTS_FEAT)) {
		LOGPMO(&bts->mo, DNM, LOGL_NOTICE,
		       "Get Attributes Response: reported unexpectedly long (%u bytes) "
		       "feature vector - most likely it was compiled against newer BSC headers. "
		       "Consider upgrading your BSC to later version.\n", data_len);
	}

	memcpy(bts->_features_data, data, data_len);
	bts->features_known = true;

	/* Log each BTS feature in the reported vector */
	for (unsigned int i = 0; i < data_len * 8; i++) {
		if (!osmo_bts_has_feature(&bts->features, i))
			continue;

		if (i >= _NUM_BTS_FEAT) {
			LOGPMO(&bts->mo, DNM, LOGL_NOTICE,
			       "Get Attributes Response: unknown feature 0x%02x is supported\n", i);
		} else {
			LOGPMO(&bts->mo, DNM, LOGL_NOTICE,
			       "Get Attributes Response: feature '%s' is supported\n",
			       osmo_bts_features_name(i));
		}
	}
}

/* Handle 3GPP TS 52.021 §8.11.3 Get Attribute Response (with nanoBTS specific attribute formatting) */
static int parse_attr_resp_info_attr(struct gsm_bts *bts, const struct gsm_bts_trx *trx, struct abis_om_fom_hdr *foh, struct tlv_parsed *tp)
{
	const uint8_t* data;
	uint16_t len;
	int i;
	int rc;
	uint16_t port;
	struct in_addr ia = {0};
	char unit_id[40];

	switch (bts->type) {
	case GSM_BTS_TYPE_OSMOBTS:
		if (TLVP_PRES_LEN(tp, NM_ATT_MANUF_ID, 2)) {
			parse_osmo_bts_features(bts, TLVP_VAL(tp, NM_ATT_MANUF_ID),
						     TLVP_LEN(tp, NM_ATT_MANUF_ID));
		}
		/* fall-through */
	case GSM_BTS_TYPE_NANOBTS:
		if (TLVP_PRESENT(tp, NM_ATT_IPACC_SUPP_FEATURES)) {
			ipacc_parse_supp_features(bts, foh, TLVP_VAL(tp, NM_ATT_IPACC_SUPP_FEATURES),
							    TLVP_LEN(tp, NM_ATT_IPACC_SUPP_FEATURES));
		}
		break;
	default:
		break;
	}

	/* Parse Attribute Response Info content for 3GPP TS 52.021 §9.4.28 Manufacturer Dependent State */
	/* this attribute does not make sense on BTS level, only on TRX level */
	if (trx && TLVP_PRES_LEN(tp, NM_ATT_MANUF_STATE, 1)) {
		data = TLVP_VAL(tp, NM_ATT_MANUF_STATE);
		LOGPFOH(DNM, LOGL_NOTICE, foh, "Get Attributes Response: nominal power is %u\n", *data);
	}

	/* Parse Attribute Response Info content for 3GPP TS 52.021 §9.4.61 SW Configuration */
	if (TLVP_PRESENT(tp, NM_ATT_SW_CONFIG)) {
		struct abis_nm_sw_desc sw_descr[SW_DESCR_MAX];
		data = TLVP_VAL(tp, NM_ATT_SW_CONFIG);
		len = TLVP_LEN(tp, NM_ATT_SW_CONFIG);
		/* after parsing manufacturer-specific attributes there's list of replies in form of sw-conf structure: */
		rc = abis_nm_get_sw_conf(data, len, &sw_descr[0], ARRAY_SIZE(sw_descr));
		if (rc > 0) {
			for (i = 0; i < rc; i++) {
				if (!handle_attr(bts, str2btsattr((const char *)sw_descr[i].file_id),
						 sw_descr[i].file_version, sw_descr[i].file_version_len)) {
					LOGPFOH(DNM, LOGL_NOTICE, foh, "ARI reported sw[%d/%d]: %s is %s\n",
						i, rc, sw_descr[i].file_id, sw_descr[i].file_version);
				}
			}
		} else {
			LOGPFOH(DNM, LOGL_ERROR, foh, "Failed to parse SW-Config part of "
				"Get Attribute Response Info: %s\n", strerror(-rc));
		}
	}

	if (abis_nm_tlv_attr_primary_oml(tp, &ia, &port) == 0) {
		LOGPFOH(DNM, LOGL_NOTICE, foh,
			"Get Attributes Response: Primary OML IP is %s:%u\n",
			inet_ntoa(ia), port);
	}

	if (abis_nm_tlv_attr_unit_id(tp, unit_id, sizeof(unit_id)) == 0) {
		LOGPFOH(DNM, LOGL_NOTICE, foh, "Get Attributes Response: Unit ID is %s\n", unit_id);
	}

	/* nanoBTS provides Get Attribute Response Info at random position and only the unreported part of it. */
	if (TLVP_PRES_LEN(tp, NM_ATT_GET_ARI, 1)) {
		data = TLVP_VAL(tp, NM_ATT_GET_ARI);
		len = TLVP_LEN(tp, NM_ATT_GET_ARI);
		parse_attr_resp_info_unreported(foh, data, len, NULL);
	}

	return 0;
}

/* Handle 3GPP TS 52.021 §9.4.64 Get Attribute Response Info */
static int parse_attr_resp_info(struct gsm_bts *bts, const struct gsm_bts_trx *trx, struct abis_om_fom_hdr *foh, struct tlv_parsed *tp)
{
	const uint8_t *data;
	uint16_t data_len;

	if (!TLVP_PRES_LEN(tp, NM_ATT_GET_ARI, 1)) {
		LOGPFOH(DNM, LOGL_ERROR, foh, "Get Attr Response without Response Info?!\n");
		return -EINVAL;
	}

	data = parse_attr_resp_info_unreported(foh, TLVP_VAL(tp, NM_ATT_GET_ARI),
					       TLVP_LEN(tp, NM_ATT_GET_ARI),
					       &data_len);

	/* After parsing unreported attribute id list inside Response info,
	   there's a list of reported attribute ids and their values, in a TLV
	   list form. */
	if (abis_nm_tlv_parse(tp, bts, data, data_len) < 0) {
		LOGPFOH(DNM, LOGL_ERROR, foh, "%s(): tlv_parse failed\n", __func__);
		return -EINVAL;
	}

	return parse_attr_resp_info_attr(bts, trx, foh, tp);
}

/* Handle 3GPP TS 52.021 §8.11.3 Get Attribute Response */
static int abis_nm_rx_get_attr_resp(struct msgb *mb)
{
	struct abis_om_hdr *oh = msgb_l2(mb);
	struct abis_om_fom_hdr *foh = msgb_l3(mb);
	struct e1inp_sign_link *sign_link = mb->dst;
	struct gsm_bts *bts = sign_link->trx->bts;
	const struct gsm_bts_trx *trx;
	struct tlv_parsed tp;
	int rc;

	trx = foh->obj_class == NM_OC_BASEB_TRANSC ?
		gsm_bts_trx_num(bts, foh->obj_inst.trx_nr) : NULL;

	DEBUGPFOH(DNM, foh, "Get Attributes Response\n");

	if (abis_nm_tlv_parse(&tp, bts, foh->data, oh->length - sizeof(*foh)) < 0) {
		LOGPFOH(DNM, LOGL_ERROR, foh, "%s(): tlv_parse failed\n", __func__);
		return -EINVAL;
	}

	/* nanoBTS doesn't send Get Attribute Response Info, uses its own format */
	if (bts->type != GSM_BTS_TYPE_NANOBTS)
		rc = parse_attr_resp_info(bts, trx, foh, &tp);
	else
		rc = parse_attr_resp_info_attr(bts, trx, foh, &tp);

	if (gsm_bts_check_cfg(bts) != 0) {
		LOGP(DLINP, LOGL_ERROR, "(bts=%u) BTS config invalid, dropping BTS!\n", bts->nr);
		ipaccess_drop_oml_deferred(bts);
		return -EINVAL;
	}

	osmo_signal_dispatch(SS_NM, S_NM_GET_ATTR_REP, mb);

	return rc;
}

/* 3GPP TS 52.021 §6.2.5 */
static int abis_nm_rx_sw_act_req(struct msgb *mb)
{
	struct abis_om_hdr *oh = msgb_l2(mb);
	struct abis_om_fom_hdr *foh = msgb_l3(mb);
	struct e1inp_sign_link *sign_link = mb->dst;
	struct tlv_parsed tp;
	const uint8_t *sw_config;
	int ret, sw_config_len, len;
	struct abis_nm_sw_desc sw_descr[SW_DESCR_MAX];

	DEBUGPFOH(DNM, foh, "Software Activate Request, ACKing and Activating\n");

	if (oh->length < sizeof(*foh)) {
		LOGPFOH(DNM, LOGL_ERROR, foh, "Software Activate Request with length too small: %u\n", oh->length);
		return -EINVAL;
	}

	ret = abis_nm_sw_act_req_ack(sign_link->trx->bts, foh->obj_class,
				      foh->obj_inst.bts_nr,
				      foh->obj_inst.trx_nr,
				      foh->obj_inst.ts_nr, 0,
				      foh->data, oh->length - sizeof(*foh));
	if (ret != 0) {
		LOGPFOH(DNM, LOGL_ERROR, foh, "Sending SW ActReq ACK failed: %d\n", ret);
		return ret;
	}

	if (abis_nm_tlv_parse(&tp, sign_link->trx->bts, foh->data, oh->length - sizeof(*foh)) < 0) {
		LOGPFOH(DNM, LOGL_ERROR, foh, "%s(): tlv_parse failed\n", __func__);
		return -EINVAL;
	}

	sw_config = TLVP_VAL(&tp, NM_ATT_SW_CONFIG);
	sw_config_len = TLVP_LEN(&tp, NM_ATT_SW_CONFIG);
	if (!TLVP_PRESENT(&tp, NM_ATT_SW_CONFIG)) {
		LOGPFOH(DNM, LOGL_ERROR, foh, "SW config not found! Can't continue.\n");
		return -EINVAL;
	} else {
		DEBUGPFOH(DNM, foh, "Found SW config: %s\n", osmo_hexdump(sw_config, sw_config_len));
	}

	/* Parse up to two sw descriptions from the data */
	len = abis_nm_get_sw_conf(sw_config, sw_config_len, &sw_descr[0],
				  ARRAY_SIZE(sw_descr));
	if (len <= 0) {
		LOGPFOH(DNM, LOGL_ERROR, foh, "Failed to parse SW Config.\n");
		return -EINVAL;
	}

	ret = abis_nm_select_newest_sw(&sw_descr[0], len);
	DEBUGPFOH(DNM, foh, "Selected sw description %d of %d\n", ret, len);

	return ipacc_sw_activate(sign_link->trx->bts, foh->obj_class,
				 foh->obj_inst.bts_nr,
				 foh->obj_inst.trx_nr,
				 foh->obj_inst.ts_nr,
				 &sw_descr[ret]);
}

/* Receive a CHANGE_ADM_STATE_ACK, parse the TLV and update local state */
static int abis_nm_rx_chg_adm_state_ack(struct msgb *mb)
{
	struct abis_om_hdr *oh = msgb_l2(mb);
	struct abis_om_fom_hdr *foh = msgb_l3(mb);
	struct e1inp_sign_link *sign_link = mb->dst;
	struct tlv_parsed tp;
	uint8_t adm_state;

	if (abis_nm_tlv_parse(&tp, sign_link->trx->bts, foh->data, oh->length - sizeof(*foh)) < 0) {
		LOGPFOH(DNM, LOGL_ERROR, foh, "%s(): tlv_parse failed\n", __func__);
		return -EINVAL;
	}

	if (!TLVP_PRESENT(&tp, NM_ATT_ADM_STATE))
		return -EINVAL;

	adm_state = *TLVP_VAL(&tp, NM_ATT_ADM_STATE);

	DEBUGPFOH(DNM, foh, "Rx Change Administrative State ACK %s\n",
		  get_value_string(abis_nm_adm_state_names, adm_state));

	return update_admstate(sign_link->trx->bts, foh->obj_class, &foh->obj_inst, adm_state);
}

static int abis_nm_rx_lmt_event(struct msgb *mb)
{
	struct abis_om_hdr *oh = msgb_l2(mb);
	struct abis_om_fom_hdr *foh = msgb_l3(mb);
	struct e1inp_sign_link *sign_link = mb->dst;
	struct tlv_parsed tp;

	if (abis_nm_tlv_parse(&tp, sign_link->trx->bts, foh->data, oh->length - sizeof(*foh)) < 0) {
		LOGPFOH(DNM, LOGL_ERROR, foh, "%s(): tlv_parse failed\n", __func__);
		return -EINVAL;
	}

	DEBUGPFOH(DNM, foh, "LMT Event ");
	if (TLVP_PRESENT(&tp, NM_ATT_BS11_LMT_LOGON_SESSION) &&
	    TLVP_LEN(&tp, NM_ATT_BS11_LMT_LOGON_SESSION) >= 1) {
		uint8_t onoff = *TLVP_VAL(&tp, NM_ATT_BS11_LMT_LOGON_SESSION);
		DEBUGPC(DNM, "LOG%s ", onoff ? "ON" : "OFF");
	}
	if (TLVP_PRESENT(&tp, NM_ATT_BS11_LMT_USER_ACC_LEV) &&
	    TLVP_LEN(&tp, NM_ATT_BS11_LMT_USER_ACC_LEV) >= 1) {
		uint8_t level = *TLVP_VAL(&tp, NM_ATT_BS11_LMT_USER_ACC_LEV);
		DEBUGPC(DNM, "Level=%u ", level);
	}
	if (TLVP_PRESENT(&tp, NM_ATT_BS11_LMT_USER_NAME) &&
	    TLVP_LEN(&tp, NM_ATT_BS11_LMT_USER_NAME) >= 1) {
		char *name = (char *) TLVP_VAL(&tp, NM_ATT_BS11_LMT_USER_NAME);
		DEBUGPC(DNM, "Username=%s ", name);
	}
	DEBUGPC(DNM, "\n");
	/* FIXME: parse LMT LOGON TIME */
	return 0;
}

/* From a received OML message, determine the matching struct gsm_bts_trx_ts instance.
 * Note that the BTS-TRX-TS numbers received in the FOM header do not correspond
 * to the local bts->nr. Rather, the BTS is identified by the e1inp_sign_link*
 * found in msg->dst which points to OML connection and thus to its 1st TRX, and the
 * TRX and TS is then obtained by the FOM header's TS number. */
struct gsm_bts_trx_ts *abis_nm_get_ts(const struct msgb *oml_msg)
{
	struct abis_om_fom_hdr *foh = msgb_l3(oml_msg);
	struct e1inp_sign_link *sign_link = oml_msg->dst;
	struct gsm_bts_trx *trx = gsm_bts_trx_num(sign_link->trx->bts, foh->obj_inst.trx_nr);
	uint8_t ts_nr = foh->obj_inst.ts_nr;
	if (!trx) {
		LOGPFOH(DNM, LOGL_ERROR, foh, "Channel OPSTART ACK for sign_link without trx\n");
		return NULL;
	}
	if (ts_nr >= ARRAY_SIZE(trx->ts)) {
		LOGPFOH(DNM, LOGL_ERROR, foh, "Channel OPSTART ACK for non-existent TS\n");
		return NULL;
	}
	return &trx->ts[ts_nr];
}

static int abis_nm_rx_opstart_ack(struct msgb *mb)
{
	struct abis_om_fom_hdr *foh = msgb_l3(mb);
	DEBUGPFOH(DNM, foh, "Opstart ACK\n");
	osmo_signal_dispatch(SS_NM, S_NM_OPSTART_ACK, mb);
	return 0;
}

static int abis_nm_rx_opstart_nack(struct msgb *mb)
{
	struct abis_om_fom_hdr *foh = msgb_l3(mb);
	LOGPFOH(DNM, LOGL_ERROR, foh, "Opstart NACK\n");
	osmo_signal_dispatch(SS_NM, S_NM_OPSTART_NACK, mb);
	return 0;
}

static int abis_nm_rx_set_radio_attr_ack(struct msgb *mb)
{
	struct abis_om_fom_hdr *foh = msgb_l3(mb);
	DEBUGPFOH(DNM, foh, "Set Radio Carrier Attributes ACK\n");
	osmo_signal_dispatch(SS_NM, S_NM_SET_RADIO_ATTR_ACK, mb);
	return 0;
}

static int abis_nm_rx_set_channel_attr_ack(struct msgb *mb)
{
	struct abis_om_fom_hdr *foh = msgb_l3(mb);
	DEBUGPFOH(DNM, foh, "Set Channel Attributes ACK\n");
	osmo_signal_dispatch(SS_NM, S_NM_SET_CHAN_ATTR_ACK, mb);
	return 0;
}

static int abis_nm_rx_set_bts_attr_ack(struct msgb *mb)
{
	struct abis_om_fom_hdr *foh = msgb_l3(mb);
	DEBUGPFOH(DNM, foh, "Set BTS Attributes ACK\n");
	osmo_signal_dispatch(SS_NM, S_NM_SET_BTS_ATTR_ACK, mb);
	return 0;
}

bool all_trx_rsl_connected_unlocked(const struct gsm_bts *bts)
{
	const struct gsm_bts_trx *trx;

	if (bts->mo.nm_state.administrative == NM_STATE_LOCKED)
		return false;

	if (bts->gprs.mode != BTS_GPRS_NONE) {
		if (bts->gprs.cell.mo.nm_state.administrative == NM_STATE_LOCKED)
			return false;

		if (bts->site_mgr->gprs.nse.mo.nm_state.administrative == NM_STATE_LOCKED)
			return false;

		if (bts->site_mgr->gprs.nsvc[0].mo.nm_state.administrative == NM_STATE_LOCKED &&
		    bts->site_mgr->gprs.nsvc[1].mo.nm_state.administrative == NM_STATE_LOCKED)
			return false;
	}

	llist_for_each_entry(trx, &bts->trx_list, list) {
		if (!trx->rsl_link_primary)
			return false;

		if (!trx_is_usable(trx))
			return false;
	}

	return true;
}

void abis_nm_queue_send_next(struct gsm_bts *bts)
{
	int wait = 0;
	struct msgb *msg;
	/* the queue is empty */
	while (!llist_empty(&bts->abis_queue)) {
		msg = msgb_dequeue(&bts->abis_queue);
		wait = OBSC_NM_W_ACK_CB(msg);
		_abis_nm_sendmsg(msg);

		if (wait)
			break;
	}

	bts->abis_nm_pend = wait;
}

/* Receive a OML NM Message from BTS */
static int abis_nm_rcvmsg_fom(struct msgb *mb)
{
	struct abis_om_hdr *oh = msgb_l2(mb);
	struct abis_om_fom_hdr *foh = msgb_l3(mb);
	struct e1inp_sign_link *sign_link = mb->dst;
	uint8_t mt = foh->msg_type;
	/* sign_link might get deleted via osmo_signal_dispatch -> save bts */
	struct gsm_bts *bts = sign_link->trx->bts;
	int ret = 0;

	/* check for unsolicited message */
	if (is_report(mt))
		return abis_nm_rcvmsg_report(mb, bts);

	if (is_in_arr(mt, abis_nm_sw_load_msgs, ARRAY_SIZE(abis_nm_sw_load_msgs)))
		return abis_nm_rcvmsg_sw(mb);

	if (is_in_arr(mt, abis_nm_nacks, ARRAY_SIZE(abis_nm_nacks))) {
		struct nm_nack_signal_data nack_data;
		struct tlv_parsed tp;

		if (abis_nm_tlv_parse(&tp, bts, foh->data, oh->length - sizeof(*foh)) < 0) {
			LOGPFOH(DNM, LOGL_ERROR, foh, "%s(): tlv_parse failed\n", __func__);
			return -EINVAL;
		}

		LOGPFOH(DNM, LOGL_NOTICE, foh, "%s NACK ", abis_nm_nack_name(mt));
		if (TLVP_PRESENT(&tp, NM_ATT_NACK_CAUSES))
			LOGPC(DNM, LOGL_NOTICE, "CAUSE=%s\n",
				abis_nm_nack_cause_name(*TLVP_VAL(&tp, NM_ATT_NACK_CAUSES)));
		else
			LOGPC(DNM, LOGL_NOTICE, "\n");

		nack_data.msg = mb;
		nack_data.mt = mt;
		nack_data.bts = bts;
		osmo_signal_dispatch(SS_NM, S_NM_NACK, &nack_data);
		abis_nm_queue_send_next(bts);
		return 0;
	}
#if 0
	/* check if last message is to be acked */
	if (is_ack_nack(nmh->last_msgtype)) {
		if (mt == MT_ACK(nmh->last_msgtype)) {
			DEBUGP(DNM, "received ACK (0x%x)\n", foh->msg_type);
			/* we got our ACK, continue sending the next msg */
		} else if (mt == MT_NACK(nmh->last_msgtype)) {
			/* we got a NACK, signal this to the caller */
			DEBUGP(DNM, "received NACK (0x%x)\n", foh->msg_type);
			/* FIXME: somehow signal this to the caller */
		} else {
			/* really strange things happen */
			return -EINVAL;
		}
	}
#endif

	switch (mt) {
	case NM_MT_CHG_ADM_STATE_ACK:
		ret = abis_nm_rx_chg_adm_state_ack(mb);
		break;
	case NM_MT_SW_ACT_REQ:
		ret = abis_nm_rx_sw_act_req(mb);
		break;
	case NM_MT_BS11_LMT_SESSION:
		ret = abis_nm_rx_lmt_event(mb);
		break;
	case NM_MT_OPSTART_ACK:
		ret = abis_nm_rx_opstart_ack(mb);
		break;
	case NM_MT_OPSTART_NACK:
		ret = abis_nm_rx_opstart_nack(mb);
		break;
	case NM_MT_SET_CHAN_ATTR_ACK:
		abis_nm_rx_set_channel_attr_ack(mb);
		break;
	case NM_MT_SET_RADIO_ATTR_ACK:
		abis_nm_rx_set_radio_attr_ack(mb);
		break;
	case NM_MT_CONN_MDROP_LINK_ACK:
		DEBUGPFOH(DNM, foh, "CONN MDROP LINK ACK\n");
		break;
	case NM_MT_IPACC_RESTART_ACK:
		DEBUGPFOH(DNM, foh, "IPA Restart ACK\n");
		osmo_signal_dispatch(SS_NM, S_NM_IPACC_RESTART_ACK, NULL);
		break;
	case NM_MT_IPACC_RESTART_NACK:
		LOGPFOH(DNM, LOGL_NOTICE, foh, "IPA Restart NACK\n");
		osmo_signal_dispatch(SS_NM, S_NM_IPACC_RESTART_NACK, NULL);
		break;
	case NM_MT_SET_BTS_ATTR_ACK:
		abis_nm_rx_set_bts_attr_ack(mb);
		break;
	case NM_MT_GET_ATTR_RESP:
		ret = abis_nm_rx_get_attr_resp(mb);
		break;
	case NM_MT_ESTABLISH_TEI_ACK:
	case NM_MT_CONN_TERR_SIGN_ACK:
	case NM_MT_DISC_TERR_SIGN_ACK:
	case NM_MT_CONN_TERR_TRAF_ACK:
	case NM_MT_DISC_MDROP_LINK_ACK:
	case NM_MT_STOP_EVENT_REP_ACK:
	case NM_MT_REST_EVENT_REP_ACK:
	case NM_MT_BS11_BEGIN_DB_TX_ACK:
	case NM_MT_BS11_END_DB_TX_ACK:
	case NM_MT_BS11_SET_ATTR_ACK:
		DEBUGPFOH(DNM, foh, "%s\n", get_value_string(abis_nm_msgtype_names, mt));
		break;
	default:
		LOGPFOH(DNM, LOGL_ERROR, foh, "Unhandled message %s\n",
			get_value_string(abis_nm_msgtype_names, mt));
	}

	abis_nm_queue_send_next(bts);
	return ret;
}

static int abis_nm_rx_ipacc(struct msgb *mb);

static int abis_nm_rcvmsg_manuf(struct msgb *mb)
{
	int rc;
	struct e1inp_sign_link *sign_link = mb->dst;
	struct gsm_bts *bts = sign_link->trx->bts;

	switch (bts->type) {
	case GSM_BTS_TYPE_NANOBTS:
	case GSM_BTS_TYPE_OSMOBTS:
		rc = abis_nm_rx_ipacc(mb);
		abis_nm_queue_send_next(bts);
		break;
	default:
		LOGPMO(&bts->mo, DNM, LOGL_ERROR, "don't know how to parse OML for this "
		       "BTS type (%s)\n", btstype2str(bts->type));
		rc = 0;
		break;
	}

	return rc;
}

/* High-Level API */
/* Entry-point where L2 OML from BTS enters the NM code */
int abis_nm_rcvmsg(struct msgb *msg)
{
	struct abis_om_hdr *oh = msgb_l2(msg);
	int rc = 0;

	/* Various consistency checks */
	if (oh->placement != ABIS_OM_PLACEMENT_ONLY) {
		LOGP(DNM, LOGL_ERROR, "ABIS OML placement 0x%x not supported\n",
			oh->placement);
		if (oh->placement != ABIS_OM_PLACEMENT_FIRST) {
			rc = -EINVAL;
			goto err;
		}
	}
	if (oh->sequence != 0) {
		LOGP(DNM, LOGL_ERROR, "ABIS OML sequence 0x%x != 0x00\n",
			oh->sequence);
		rc = -EINVAL;
		goto err;
	}
#if 0
	unsigned int l2_len = msg->tail - (uint8_t *)msgb_l2(msg);
	unsigned int hlen = sizeof(*oh) + sizeof(struct abis_om_fom_hdr);
	if (oh->length + hlen > l2_len) {
		LOGP(DNM, LOGL_ERROR, "ABIS OML truncated message (%u > %u)\n",
			oh->length + sizeof(*oh), l2_len);
		return -EINVAL;
	}
	if (oh->length + hlen < l2_len)
		LOGP(DNM, LOGL_ERROR, "ABIS OML message with extra trailer?!? (oh->len=%d, sizeof_oh=%d l2_len=%d\n", oh->length, sizeof(*oh), l2_len);
#endif
	msg->l3h = (unsigned char *)oh + sizeof(*oh);

	switch (oh->mdisc) {
	case ABIS_OM_MDISC_FOM:
		rc = abis_nm_rcvmsg_fom(msg);
		break;
	case ABIS_OM_MDISC_MANUF:
		rc = abis_nm_rcvmsg_manuf(msg);
		break;
	case ABIS_OM_MDISC_MMI:
	case ABIS_OM_MDISC_TRAU:
		LOGP(DNM, LOGL_ERROR, "unimplemented ABIS OML message discriminator 0x%x\n",
			oh->mdisc);
		break;
	default:
		LOGP(DNM, LOGL_ERROR, "unknown ABIS OML message discriminator 0x%x\n",
			oh->mdisc);
		rc = -EINVAL;
		break;
	}
err:
	msgb_free(msg);
	return rc;
}

#if 0
/* initialized all resources */
struct abis_nm_h *abis_nm_init(struct abis_nm_cfg *cfg)
{
	struct abis_nm_h *nmh;

	nmh = malloc(sizeof(*nmh));
	if (!nmh)
		return NULL;

	nmh->cfg = cfg;

	return nmh;
}

/* free all resources */
void abis_nm_fini(struct abis_nm_h *nmh)
{
	free(nmh);
}
#endif

/* Here we are trying to define a high-level API that can be used by
 * the actual BSC implementation.  However, the architecture is currently
 * still under design.  Ideally the calls to this API would be synchronous,
 * while the underlying stack behind the APi runs in a traditional select
 * based state machine.
 */

/* 6.2 Software Load: */
enum sw_state {
	SW_STATE_NONE,
	SW_STATE_WAIT_INITACK,
	SW_STATE_WAIT_SEGACK,
	SW_STATE_WAIT_ENDACK,
	SW_STATE_WAIT_ACTACK,
	SW_STATE_ERROR,
};

struct abis_nm_sw {
	struct gsm_bts *bts;
	int trx_nr;
	gsm_cbfn *cbfn;
	void *cb_data;
	int forced;

	/* this will become part of the SW LOAD INITIATE */
	uint8_t obj_class;
	uint8_t obj_instance[3];

	uint8_t file_id[255];
	uint8_t file_id_len;

	uint8_t file_version[255];
	uint8_t file_version_len;

	uint8_t window_size;
	uint8_t seg_in_window;

	int fd;
	FILE *stream;
	enum sw_state state;
	int last_seg;
};

static struct abis_nm_sw g_sw;

static void sw_add_file_id_and_ver(struct abis_nm_sw *sw, struct msgb *msg)
{
	if (sw->bts->type == GSM_BTS_TYPE_NANOBTS) {
		msgb_v_put(msg, NM_ATT_SW_DESCR);
		msgb_tl16v_put(msg, NM_ATT_FILE_ID, sw->file_id_len, sw->file_id);
		msgb_tl16v_put(msg, NM_ATT_FILE_VERSION, sw->file_version_len,
			       sw->file_version);
	} else if (sw->bts->type == GSM_BTS_TYPE_BS11) {
		msgb_tlv_put(msg, NM_ATT_FILE_ID, sw->file_id_len, sw->file_id);
		msgb_tlv_put(msg, NM_ATT_FILE_VERSION, sw->file_version_len,
			     sw->file_version);
	} else {
		LOGPMO(&sw->bts->mo, DNM, LOGL_ERROR, "Please implement this for the BTS.\n");
	}
}

/* 6.2.1 / 8.3.1: Load Data Initiate */
static int sw_load_init(struct abis_nm_sw *sw)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();
	uint8_t len = 3*2 + sw->file_id_len + sw->file_version_len;

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, len, NM_MT_LOAD_INIT, sw->obj_class,
			sw->obj_instance[0], sw->obj_instance[1],
			sw->obj_instance[2]);

	sw_add_file_id_and_ver(sw, msg);
	msgb_tv_put(msg, NM_ATT_WINDOW_SIZE, sw->window_size);

	return abis_nm_sendmsg(sw->bts, msg);
}

static int is_last_line(FILE *stream)
{
	char next_seg_buf[256];
	long pos;

	/* check if we're sending the last line */
	pos = ftell(stream);

	/* Did ftell fail? Then we are at the end for sure */
	if (pos < 0)
		return 1;

	if (!fgets(next_seg_buf, sizeof(next_seg_buf)-2, stream)) {
		int rc = fseek(stream, pos, SEEK_SET);
		if (rc < 0)
			return rc;
		return 1;
	}

	fseek(stream, pos, SEEK_SET);
	return 0;
}

/* 6.2.2 / 8.3.2 Load Data Segment */
static int sw_load_segment(struct abis_nm_sw *sw)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();
	char seg_buf[256];
	char *line_buf = seg_buf+2;
	unsigned char *tlv;
	int len;

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);

	switch (sw->bts->type) {
	case GSM_BTS_TYPE_BS11:
		if (fgets(line_buf, sizeof(seg_buf)-2, sw->stream) == NULL) {
			perror("fgets reading segment");
			return -EINVAL;
		}
		seg_buf[0] = 0x00;

		/* check if we're sending the last line */
		sw->last_seg = is_last_line(sw->stream);
		if (sw->last_seg)
			seg_buf[1] = 0;
		else
			seg_buf[1] = 1 + sw->seg_in_window++;

		len = strlen(line_buf) + 2;
		tlv = msgb_put(msg, TLV_GROSS_LEN(len));
		tlv_put(tlv, NM_ATT_BS11_FILE_DATA, len, (uint8_t *)seg_buf);
		/* BS11 wants CR + LF in excess of the TLV length !?! */
		tlv[1] -= 2;

		/* we only now know the exact length for the OM hdr */
		len = strlen(line_buf)+2;
		break;
	case GSM_BTS_TYPE_NANOBTS: {
		osmo_static_assert(sizeof(seg_buf) >= IPACC_SEGMENT_SIZE, buffer_big_enough);
		len = read(sw->fd, &seg_buf, IPACC_SEGMENT_SIZE);
		if (len < 0) {
			perror("read failed");
			return -EINVAL;
		}

		if (len != IPACC_SEGMENT_SIZE)
			sw->last_seg = 1;

		++sw->seg_in_window;
		msgb_tl16v_put(msg, NM_ATT_IPACC_FILE_DATA, len, (const uint8_t *) seg_buf);
		len += 3;
		break;
	}
	default:
		LOGPMO(&sw->bts->mo, DNM, LOGL_ERROR, "sw_load_segment needs implementation for the BTS.\n");
		/* FIXME: Other BTS types */
		return -1;
	}

	fill_om_fom_hdr(oh, len, NM_MT_LOAD_SEG, sw->obj_class,
			sw->obj_instance[0], sw->obj_instance[1],
			sw->obj_instance[2]);

	return abis_nm_sendmsg_direct(sw->bts, msg);
}

/* 6.2.4 / 8.3.4 Load Data End */
static int sw_load_end(struct abis_nm_sw *sw)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();
	uint8_t len = 2*2 + sw->file_id_len + sw->file_version_len;

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, len, NM_MT_LOAD_END, sw->obj_class,
			sw->obj_instance[0], sw->obj_instance[1],
			sw->obj_instance[2]);

	sw_add_file_id_and_ver(sw, msg);
	return abis_nm_sendmsg(sw->bts, msg);
}

/* Activate the specified software into the BTS */
static int sw_activate(struct abis_nm_sw *sw)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();
	uint8_t len = 2*2 + sw->file_id_len + sw->file_version_len;

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, len, NM_MT_ACTIVATE_SW, sw->obj_class,
			sw->obj_instance[0], sw->obj_instance[1],
			sw->obj_instance[2]);

	/* FIXME: this is BS11 specific format */
	msgb_tlv_put(msg, NM_ATT_FILE_ID, sw->file_id_len, sw->file_id);
	msgb_tlv_put(msg, NM_ATT_FILE_VERSION, sw->file_version_len,
		     sw->file_version);

	return abis_nm_sendmsg(sw->bts, msg);
}

static int parse_sdp_header(struct abis_nm_sw *sw)
{
	const struct gsm_abis_mo *mo = &sw->bts->mo;
	struct sdp_firmware firmware_header;
	int rc;
	struct stat stat;

	rc = read(sw->fd, &firmware_header, sizeof(firmware_header));
	if (rc != sizeof(firmware_header)) {
		LOGPMO(mo, DNM, LOGL_ERROR, "Could not read SDP file header.\n");
		return -1;
	}

	if (strncmp(firmware_header.magic, " SDP", 4) != 0) {
		LOGPMO(mo, DNM, LOGL_ERROR, "The magic number is wrong.\n");
		return -1;
	}

	if (firmware_header.more_magic[0] != 0x10 ||
	    firmware_header.more_magic[1] != 0x02) {
		LOGPMO(mo, DNM, LOGL_ERROR, "The more magic number is wrong.\n");
		return -1;
	}

	if (firmware_header.more_more_magic != 0x0000) {
		LOGPMO(mo, DNM, LOGL_ERROR, "The more more magic number is wrong.\n");
		return -1;
	}

	if (fstat(sw->fd, &stat) == -1) {
		LOGPMO(mo, DNM, LOGL_ERROR, "Could not stat the file.\n");
		return -1;
	}

	if (ntohl(firmware_header.file_length) != stat.st_size) {
		LOGPMO(mo, DNM, LOGL_ERROR, "The filesizes do not match.\n");
		return -1;
	}

	/* go back to the start as we checked the whole filesize.. */
	lseek(sw->fd, 0l, SEEK_SET);
	LOGPMO(mo, DNM, LOGL_NOTICE, "The ipaccess SDP header is not fully understood. "
	       "There might be checksums in the file that are not verified and incomplete "
	       "firmware might be flashed.  There is absolutely no WARRANTY that "
	       "flashing will work.\n");
	return 0;
}

static int sw_open_file(struct abis_nm_sw *sw, const char *fname)
{
	char file_id[12+1];
	char file_version[80+1];
	int rc;

	sw->fd = open(fname, O_RDONLY);
	if (sw->fd < 0)
		return sw->fd;

	switch (sw->bts->type) {
	case GSM_BTS_TYPE_BS11:
		sw->stream = fdopen(sw->fd, "r");
		if (!sw->stream) {
			perror("fdopen");
			return -1;
		}
		/* read first line and parse file ID and VERSION */
		rc = fscanf(sw->stream, "@(#)%12s:%80s\r\n",
			    file_id, file_version);
		if (rc != 2) {
			perror("parsing header line of software file");
			return -1;
		}
		strcpy((char *)sw->file_id, file_id);
		sw->file_id_len = strlen(file_id);
		strcpy((char *)sw->file_version, file_version);
		sw->file_version_len = strlen(file_version);
		/* rewind to start of file */
		rewind(sw->stream);
		break;
	case GSM_BTS_TYPE_NANOBTS:
		/* TODO: extract that from the filename or content */
		rc = parse_sdp_header(sw);
		if (rc < 0) {
			fprintf(stderr, "Could not parse the ipaccess SDP header\n");
			return -1;
		}

		strcpy((char *)sw->file_id, "id");
		sw->file_id_len = 3;
		strcpy((char *)sw->file_version, "version");
		sw->file_version_len = 8;
		break;
	default:
		/* We don't know how to treat them yet */
		close(sw->fd);
		return -EINVAL;
	}

	return 0;
}

static void sw_close_file(struct abis_nm_sw *sw)
{
	switch (sw->bts->type) {
	case GSM_BTS_TYPE_BS11:
		fclose(sw->stream);
		break;
	default:
		close(sw->fd);
		break;
	}
}

/* Fill the window */
static int sw_fill_window(struct abis_nm_sw *sw)
{
	int rc;

	while (sw->seg_in_window < sw->window_size) {
		rc = sw_load_segment(sw);
		if (rc < 0)
			return rc;
		if (sw->last_seg)
			break;
	}
	return 0;
}

/* callback function from abis_nm_rcvmsg() handler */
static int abis_nm_rcvmsg_sw(struct msgb *mb)
{
	struct abis_om_fom_hdr *foh = msgb_l3(mb);
	struct e1inp_sign_link *sign_link = mb->dst;
	int rc = -1;
	struct abis_nm_sw *sw = &g_sw;
	enum sw_state old_state = sw->state;

	//DEBUGP(DNM, "state %u, NM MT 0x%02x\n", sw->state, foh->msg_type);

	switch (sw->state) {
	case SW_STATE_WAIT_INITACK:
		switch (foh->msg_type) {
		case NM_MT_LOAD_INIT_ACK:
			/* fill window with segments */
			if (sw->cbfn)
				sw->cbfn(GSM_HOOK_NM_SWLOAD,
					 NM_MT_LOAD_INIT_ACK, mb,
					 sw->cb_data, NULL);
			rc = sw_fill_window(sw);
			sw->state = SW_STATE_WAIT_SEGACK;
			abis_nm_queue_send_next(sign_link->trx->bts);
			break;
		case NM_MT_LOAD_INIT_NACK:
			if (sw->forced) {
				DEBUGPFOH(DNM, foh, "FORCED: Ignoring Software Load Init NACK\n");
				if (sw->cbfn)
					sw->cbfn(GSM_HOOK_NM_SWLOAD,
						 NM_MT_LOAD_INIT_ACK, mb,
						 sw->cb_data, NULL);
				rc = sw_fill_window(sw);
				sw->state = SW_STATE_WAIT_SEGACK;
			} else {
				LOGPFOH(DNM, LOGL_NOTICE, foh, "Software Load Init NACK\n");
				/* FIXME: cause */
				if (sw->cbfn)
					sw->cbfn(GSM_HOOK_NM_SWLOAD,
						 NM_MT_LOAD_INIT_NACK, mb,
						 sw->cb_data, NULL);
				sw->state = SW_STATE_ERROR;
			}
			abis_nm_queue_send_next(sign_link->trx->bts);
			break;
		}
		break;
	case SW_STATE_WAIT_SEGACK:
		switch (foh->msg_type) {
		case NM_MT_LOAD_SEG_ACK:
			if (sw->cbfn)
				sw->cbfn(GSM_HOOK_NM_SWLOAD,
					 NM_MT_LOAD_SEG_ACK, mb,
					 sw->cb_data, NULL);
			sw->seg_in_window = 0;
			if (!sw->last_seg) {
				/* fill window with more segments */
				rc = sw_fill_window(sw);
				sw->state = SW_STATE_WAIT_SEGACK;
			} else {
				/* end the transfer */
				sw->state = SW_STATE_WAIT_ENDACK;
				rc = sw_load_end(sw);
			}
			abis_nm_queue_send_next(sign_link->trx->bts);
			break;
		case NM_MT_LOAD_ABORT:
			if (sw->cbfn)
				sw->cbfn(GSM_HOOK_NM_SWLOAD,
					 NM_MT_LOAD_ABORT, mb,
					 sw->cb_data, NULL);
			break;
		}
		break;
	case SW_STATE_WAIT_ENDACK:
		switch (foh->msg_type) {
		case NM_MT_LOAD_END_ACK:
			sw_close_file(sw);
			DEBUGPFOH(DNM, foh, "Software Load End\n");
			sw->state = SW_STATE_NONE;
			if (sw->cbfn)
				sw->cbfn(GSM_HOOK_NM_SWLOAD,
					 NM_MT_LOAD_END_ACK, mb,
					 sw->cb_data, NULL);
			rc = 0;
			abis_nm_queue_send_next(sign_link->trx->bts);
			break;
		case NM_MT_LOAD_END_NACK:
			if (sw->forced) {
				DEBUGPFOH(DNM, foh, "FORCED: Ignoring Software Load End NACK\n");
				sw->state = SW_STATE_NONE;
				if (sw->cbfn)
					sw->cbfn(GSM_HOOK_NM_SWLOAD,
						 NM_MT_LOAD_END_ACK, mb,
						 sw->cb_data, NULL);
			} else {
				LOGPFOH(DNM, LOGL_NOTICE, foh, "Software Load End NACK\n");
				/* FIXME: cause */
				sw->state = SW_STATE_ERROR;
				if (sw->cbfn)
					sw->cbfn(GSM_HOOK_NM_SWLOAD,
						 NM_MT_LOAD_END_NACK, mb,
						 sw->cb_data, NULL);
			}
			abis_nm_queue_send_next(sign_link->trx->bts);
			break;
		}
		break;
	case SW_STATE_WAIT_ACTACK:
		switch (foh->msg_type) {
		case NM_MT_ACTIVATE_SW_ACK:
			/* we're done */
			LOGPFOH(DNM, LOGL_INFO, foh, "Activate Software DONE!\n");
			sw->state = SW_STATE_NONE;
			rc = 0;
			if (sw->cbfn)
				sw->cbfn(GSM_HOOK_NM_SWLOAD,
					 NM_MT_ACTIVATE_SW_ACK, mb,
					 sw->cb_data, NULL);
			abis_nm_queue_send_next(sign_link->trx->bts);
			break;
		case NM_MT_ACTIVATE_SW_NACK:
			LOGPFOH(DNM, LOGL_ERROR, foh, "Activate Software NACK\n");
			/* FIXME: cause */
			sw->state = SW_STATE_ERROR;
			if (sw->cbfn)
				sw->cbfn(GSM_HOOK_NM_SWLOAD,
					 NM_MT_ACTIVATE_SW_NACK, mb,
					 sw->cb_data, NULL);
			abis_nm_queue_send_next(sign_link->trx->bts);
			break;
		}
		break;
	case SW_STATE_NONE:
		switch (foh->msg_type) {
		case NM_MT_ACTIVATE_SW_ACK:
			rc = 0;
			break;
		}
		break;
	case SW_STATE_ERROR:
		break;
	}

	if (rc)
		LOGPFOH(DNM, LOGL_ERROR, foh, "unexpected NM MT 0x%02x in state %u -> %u\n",
			foh->msg_type, old_state, sw->state);

	return rc;
}

/* Load the specified software into the BTS */
int abis_nm_software_load(struct gsm_bts *bts, int trx_nr, const char *fname,
			  uint8_t win_size, int forced,
			  gsm_cbfn *cbfn, void *cb_data)
{
	struct abis_nm_sw *sw = &g_sw;
	int rc;

	LOGPMO(&bts->mo, DNM, LOGL_DEBUG, "Software Load (file \"%s\")\n", fname);

	if (sw->state != SW_STATE_NONE)
		return -EBUSY;

	sw->bts = bts;
	sw->trx_nr = trx_nr;

	switch (bts->type) {
	case GSM_BTS_TYPE_BS11:
		sw->obj_class = NM_OC_SITE_MANAGER;
		sw->obj_instance[0] = 0xff;
		sw->obj_instance[1] = 0xff;
		sw->obj_instance[2] = 0xff;
		break;
	case GSM_BTS_TYPE_NANOBTS:
		sw->obj_class = NM_OC_BASEB_TRANSC;
		sw->obj_instance[0] = sw->bts->bts_nr;
		sw->obj_instance[1] = sw->trx_nr;
		sw->obj_instance[2] = 0xff;
		break;
	case GSM_BTS_TYPE_UNKNOWN:
	default:
		LOGPMO(&bts->mo, DNM, LOGL_ERROR, "Software Load not properly implemented.\n");
		return -1;
		break;
	}
	sw->window_size = win_size;
	sw->state = SW_STATE_WAIT_INITACK;
	sw->cbfn = cbfn;
	sw->cb_data = cb_data;
	sw->forced = forced;

	rc = sw_open_file(sw, fname);
	if (rc < 0) {
		sw->state = SW_STATE_NONE;
		return rc;
	}

	return sw_load_init(sw);
}

int abis_nm_software_load_status(struct gsm_bts *bts)
{
	struct abis_nm_sw *sw = &g_sw;
	struct stat st;
	int rc, percent;

	rc = fstat(sw->fd, &st);
	if (rc < 0) {
		perror("ERROR during stat");
		return rc;
	}

	if (sw->stream)
		percent = (ftell(sw->stream) * 100) / st.st_size;
	else
		percent = (lseek(sw->fd, 0, SEEK_CUR) * 100) / st.st_size;
	return percent;
}

/* Activate the specified software into the BTS */
int abis_nm_software_activate(struct gsm_bts *bts, const char *fname,
			      gsm_cbfn *cbfn, void *cb_data)
{
	struct abis_nm_sw *sw = &g_sw;
	int rc;

	LOGPMO(&bts->mo, DNM, LOGL_DEBUG, "Activating Software (file \"%s\")\n", fname);

	if (sw->state != SW_STATE_NONE)
		return -EBUSY;

	sw->bts = bts;
	sw->obj_class = NM_OC_SITE_MANAGER;
	sw->obj_instance[0] = 0xff;
	sw->obj_instance[1] = 0xff;
	sw->obj_instance[2] = 0xff;
	sw->state = SW_STATE_WAIT_ACTACK;
	sw->cbfn = cbfn;
	sw->cb_data = cb_data;

	/* Open the file in order to fill some sw struct members */
	rc = sw_open_file(sw, fname);
	if (rc < 0) {
		sw->state = SW_STATE_NONE;
		return rc;
	}
	sw_close_file(sw);

	return sw_activate(sw);
}

static void fill_nm_channel(struct abis_nm_channel *ch, uint8_t bts_port,
		       uint8_t ts_nr, uint8_t subslot_nr)
{
	ch->attrib = NM_ATT_ABIS_CHANNEL;
	ch->bts_port = bts_port;
	ch->timeslot = ts_nr;
	ch->subslot = subslot_nr;
}

int abis_nm_establish_tei(struct gsm_bts *bts, uint8_t trx_nr,
			  uint8_t e1_port, uint8_t e1_timeslot, uint8_t e1_subslot,
			  uint8_t tei)
{
	struct abis_om_hdr *oh;
	struct abis_nm_channel *ch;
	uint8_t len = sizeof(*ch) + 2;
	struct msgb *msg = nm_msgb_alloc();

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, len, NM_MT_ESTABLISH_TEI, NM_OC_RADIO_CARRIER,
			bts->bts_nr, trx_nr, 0xff);

	msgb_tv_put(msg, NM_ATT_TEI, tei);

	ch = (struct abis_nm_channel *) msgb_put(msg, sizeof(*ch));
	fill_nm_channel(ch, e1_port, e1_timeslot, e1_subslot);

	return abis_nm_sendmsg(bts, msg);
}

/* connect signalling of one (BTS,TRX) to a particular timeslot on the E1 */
int abis_nm_conn_terr_sign(struct gsm_bts_trx *trx,
			   uint8_t e1_port, uint8_t e1_timeslot, uint8_t e1_subslot)
{
	struct gsm_bts *bts = trx->bts;
	struct abis_om_hdr *oh;
	struct abis_nm_channel *ch;
	struct msgb *msg = nm_msgb_alloc();

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, sizeof(*ch), NM_MT_CONN_TERR_SIGN,
			NM_OC_RADIO_CARRIER, bts->bts_nr, trx->nr, 0xff);

	ch = (struct abis_nm_channel *) msgb_put(msg, sizeof(*ch));
	fill_nm_channel(ch, e1_port, e1_timeslot, e1_subslot);

	return abis_nm_sendmsg(bts, msg);
}

#if 0
int abis_nm_disc_terr_sign(struct abis_nm_h *h, struct abis_om_obj_inst *inst,
			   struct abis_nm_abis_channel *chan)
{
}
#endif

int abis_nm_conn_terr_traf(struct gsm_bts_trx_ts *ts,
			   uint8_t e1_port, uint8_t e1_timeslot,
			   uint8_t e1_subslot)
{
	struct gsm_bts *bts = ts->trx->bts;
	struct abis_om_hdr *oh;
	struct abis_nm_channel *ch;
	struct msgb *msg = nm_msgb_alloc();

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, sizeof(*ch), NM_MT_CONN_TERR_TRAF,
			NM_OC_CHANNEL, bts->bts_nr, ts->trx->nr, ts->nr);

	ch = (struct abis_nm_channel *) msgb_put(msg, sizeof(*ch));
	fill_nm_channel(ch, e1_port, e1_timeslot, e1_subslot);

	LOGPMO(&ts->mo, DNM, LOGL_DEBUG, "CONNECT TERR TRAF E1=(%u,%u,%u)\n",
	       e1_port, e1_timeslot, e1_subslot);

	return abis_nm_sendmsg(bts, msg);
}

#if 0
int abis_nm_disc_terr_traf(struct abis_nm_h *h, struct abis_om_obj_inst *inst,
			   struct abis_nm_abis_channel *chan,
			   uint8_t subchan)
{
}
#endif

/* 3GPP TS 52.021 § 8.11.1 */
int abis_nm_get_attr(struct gsm_bts *bts, uint8_t obj_class, uint8_t bts_nr, uint8_t trx_nr, uint8_t ts_nr,
		     const uint8_t *attr, uint8_t attr_len)
{
	const struct abis_om_fom_hdr *foh;
	struct abis_om_hdr *oh;
	struct msgb *msg;

	if (bts->type != GSM_BTS_TYPE_OSMOBTS && bts->type != GSM_BTS_TYPE_NANOBTS) {
		LOGPMO(&bts->mo, DNM, LOGL_NOTICE, "Getting attributes from BTS "
		       "type %s is not supported.\n", btstype2str(bts->type));
		return -EINVAL;
	}

	msg = nm_msgb_alloc();
	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	foh = fill_om_fom_hdr(oh, TL16V_GROSS_LEN(attr_len), NM_MT_GET_ATTR,
			      obj_class, bts_nr, trx_nr, ts_nr);
	msgb_tl16v_put(msg, NM_ATT_LIST_REQ_ATTR, attr_len, attr);

	DEBUGPFOH(DNM, foh, "Tx Get Attributes (Request)\n");

	return abis_nm_sendmsg(bts, msg);
}

/* Chapter 8.6.1 */
int abis_nm_set_bts_attr(struct gsm_bts *bts, uint8_t *attr, int attr_len)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();
	uint8_t *cur;

	LOGPMO(&bts->mo, DNM, LOGL_DEBUG, "Set BTS Attr\n");

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, attr_len, NM_MT_SET_BTS_ATTR, NM_OC_BTS, bts->bts_nr, 0xff, 0xff);
	cur = msgb_put(msg, attr_len);
	memcpy(cur, attr, attr_len);

	return abis_nm_sendmsg(bts, msg);
}

/* Chapter 8.6.2 */
int abis_nm_set_radio_attr(struct gsm_bts_trx *trx, uint8_t *attr, int attr_len)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();
	uint8_t *cur;

	LOG_TRX(trx, DNM, LOGL_DEBUG, "Set TRX Attr\n");

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, attr_len, NM_MT_SET_RADIO_ATTR, NM_OC_RADIO_CARRIER,
			trx->bts->bts_nr, trx->nr, 0xff);
	cur = msgb_put(msg, attr_len);
	memcpy(cur, attr, attr_len);

	return abis_nm_sendmsg(trx->bts, msg);
}

int abis_nm_update_max_power_red(struct gsm_bts_trx *trx)
{
	uint8_t attr[] = { NM_ATT_RF_MAXPOWR_R, trx->max_power_red / 2 };
	return abis_nm_set_radio_attr(trx, attr, ARRAY_SIZE(attr));
}

static int verify_chan_comb(struct gsm_bts_trx_ts *ts, uint8_t chan_comb,
			const char **reason)
{
	int i;

	*reason = "Reason unknown";

	/* As it turns out, the BS-11 has some very peculiar restrictions
	 * on the channel combinations it allows */
	switch (ts->trx->bts->type) {
	case GSM_BTS_TYPE_BS11:
		switch (chan_comb) {
		case NM_CHANC_TCHHalf:
		case NM_CHANC_TCHHalf2:
		case NM_CHANC_OSMO_DYN:
			/* not supported */
			*reason = "TCH/H is not supported.";
			return -EINVAL;
		case NM_CHANC_SDCCH:
			/* only one SDCCH/8 per TRX */
			for (i = 0; i < TRX_NR_TS; i++) {
				if (i == ts->nr)
					continue;
				if (ts->trx->ts[i].nm_chan_comb ==
				    NM_CHANC_SDCCH) {
					*reason = "Only one SDCCH/8 per TRX allowed.";
					return -EINVAL;
				}
			}
			/* not allowed for TS0 of BCCH-TRX */
			if (ts->trx == ts->trx->bts->c0 &&
			    ts->nr == 0) {
				*reason = "SDCCH/8 must not be on C0/TS0.";
				return -EINVAL;
			}

			/* not on the same TRX that has a BCCH+SDCCH4
			 * combination */
			if (ts->trx != ts->trx->bts->c0 &&
			    (ts->trx->ts[0].nm_chan_comb == NM_CHANC_BCCHComb ||
			     ts->trx->ts[0].nm_chan_comb == NM_CHANC_SDCCH_CBCH)) {
				*reason = "SDCCH/8 and BCCH must be on the same TRX.";
				return -EINVAL;
			}
			break;
		case NM_CHANC_mainBCCH:
		case NM_CHANC_BCCHComb:
			/* allowed only for TS0 of C0 */
			if (ts->trx != ts->trx->bts->c0 || ts->nr != 0) {
				*reason = "Main BCCH must be on TS0.";
				return -EINVAL;
			}
			break;
		case NM_CHANC_BCCH:
			/* allowed only for TS 2/4/6 of C0 */
			if (ts->trx != ts->trx->bts->c0) {
				*reason = "BCCH must be on C0.";
				return -EINVAL;
			}
			if (ts->nr != 2 && ts->nr != 4 && ts->nr != 6) {
				*reason = "BCCH must be on TS 2/4/6.";
				return -EINVAL;
			}
			break;
		case NM_CHANC_SDCCH_CBCH: /* this is not like 08.58, but in fact
			 * FCCH+SCH+BCCH+CCCH+SDCCH/4+SACCH/C4+CBCH */
			/* FIXME: only one CBCH allowed per cell */
			break;
		}
		break;
	case GSM_BTS_TYPE_NANOBTS:
		switch (ts->nr) {
		case 0:
			if (ts->trx->nr == 0) {
				/* only on TRX0 */
				switch (chan_comb) {
				case NM_CHANC_BCCH:
				case NM_CHANC_BCCH_CBCH:
				case NM_CHANC_mainBCCH:
				case NM_CHANC_BCCHComb:
					return 0;
					break;
				default:
					*reason = "TS0 of TRX0 must carry a BCCH.";
					return -EINVAL;
				}
			} else {
				switch (chan_comb) {
				case NM_CHANC_TCHFull:
				case NM_CHANC_TCHHalf:
				case NM_CHANC_IPAC_TCHFull_TCHHalf:
					return 0;
				default:
					*reason = "TS0 must carry a TCH/F or TCH/H.";
					return -EINVAL;
				}
			}
			break;
		case 1:
			if (ts->trx->nr == 0) {
				switch (chan_comb) {
				case NM_CHANC_SDCCH_CBCH:
					if (ts->trx->ts[0].nm_chan_comb ==
					    NM_CHANC_mainBCCH)
						return 0;
					*reason = "TS0 must be the main BCCH for CBCH.";
					return -EINVAL;
				case NM_CHANC_SDCCH:
				case NM_CHANC_TCHFull:
				case NM_CHANC_TCHHalf:
				case NM_CHANC_IPAC_TCHFull_TCHHalf:
				case NM_CHANC_IPAC_TCHFull_PDCH:
				case NM_CHANC_OSMO_DYN:
					return 0;
				default:
					*reason = "TS1 must carry a CBCH, SDCCH or TCH.";
					return -EINVAL;
				}
			} else {
				switch (chan_comb) {
				case NM_CHANC_SDCCH:
				case NM_CHANC_TCHFull:
				case NM_CHANC_TCHHalf:
				case NM_CHANC_IPAC_TCHFull_TCHHalf:
					return 0;
				default:
					*reason = "TS1 must carry a SDCCH or TCH.";
					return -EINVAL;
				}
			}
			break;
		case 2:
		case 3:
		case 4:
		case 5:
		case 6:
		case 7:
			switch (chan_comb) {
			case NM_CHANC_TCHFull:
			case NM_CHANC_TCHHalf:
			case NM_CHANC_IPAC_TCHFull_TCHHalf:
				return 0;
			case NM_CHANC_IPAC_PDCH:
			case NM_CHANC_IPAC_TCHFull_PDCH:
			case NM_CHANC_OSMO_DYN:
				if (ts->trx->nr == 0)
					return 0;
				else {
					*reason = "PDCH must be on TRX0.";
					return -EINVAL;
				}
			}
			break;
		}
		*reason = "Unknown combination";
		return -EINVAL;
	case GSM_BTS_TYPE_OSMOBTS:
		/* no known restrictions */
		return 0;
	default:
		/* unknown BTS type */
		return 0;
	}
	return 0;
}

/* Chapter 8.6.3 */
int abis_nm_set_channel_attr(struct gsm_bts_trx_ts *ts, uint8_t chan_comb)
{
	struct gsm_bts *bts = ts->trx->bts;
	struct abis_om_hdr *oh;
	struct abis_om_fom_hdr *foh;
	uint8_t zero = 0x00;
	struct msgb *msg = nm_msgb_alloc();
	const char *reason = NULL;

	/* NOTE: message length will be set later, see down below */
	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	foh = fill_om_fom_hdr(oh, 0, NM_MT_SET_CHAN_ATTR, NM_OC_CHANNEL, bts->bts_nr,
			      ts->trx->nr, ts->nr);

	DEBUGPFOH(DNM, foh, "Set Chan Attr\n");
	if (verify_chan_comb(ts, chan_comb, &reason) < 0) {
		LOGPFOH(DNM, LOGL_ERROR, foh, "Invalid Channel Combination %d on %s. Reason: %s\n",
			chan_comb, gsm_ts_name(ts), reason);
		msgb_free(msg);
		return -EINVAL;
	}
	ts->nm_chan_comb = chan_comb;

	msgb_tv_put(msg, NM_ATT_CHAN_COMB, chan_comb);
	if (ts->hopping.enabled) {
		unsigned int i, n;
		uint16_t *u16 = NULL;
		uint8_t *u8 = NULL;

		msgb_tv_put(msg, NM_ATT_HSN, ts->hopping.hsn);
		msgb_tv_put(msg, NM_ATT_MAIO, ts->hopping.maio);

		msgb_put_u8(msg, NM_ATT_ARFCN_LIST);

		/* 3GPP TS 12.21 defines this IE as TL16V */
		if (bts->type != GSM_BTS_TYPE_BS11)
			u16 = (uint16_t *) msgb_put(msg, 2);
		else /* ... but BS-11 wants TLV instead */
			u8 = (uint8_t *) msgb_put(msg, 1);

		/* build the ARFCN list from pre-computed bitmap */
		for (i = 0, n = 0; i < ts->hopping.arfcns.data_len*8; i++) {
			if (bitvec_get_bit_pos(&ts->hopping.arfcns, i)) {
				msgb_put_u16(msg, i);
				n += 1;
			}
		}

		/* BS-11 cannot handle more than 255 ARFCNs, because L is 8 bit.
		 * This is unlikely to happen, but better check than sorry... */
		if (bts->type == GSM_BTS_TYPE_BS11 && n > 0xff) {
			LOGPFOH(DNM, LOGL_ERROR, foh, "Cannot handle %u (more than 255) "
				"hopping channels\n", n);
			msgb_free(msg);
			return -EINVAL;
		}

		/* 3GPP TS 12.21 defines L as length of the V part (in octets) */
		if (bts->type != GSM_BTS_TYPE_BS11)
			*u16 = htons(n * sizeof(*u16));
		else /* ... BS-11 wants the number of channels instead */
			*u8 = n;
	}
	msgb_tv_put(msg, NM_ATT_TSC, gsm_ts_tsc(ts));	/* training sequence */
	if (bts->type == GSM_BTS_TYPE_BS11)
		msgb_tlv_put(msg, 0x59, 1, &zero);

	msg->l2h = (uint8_t *) oh;
	msg->l3h = (uint8_t *) foh;
	oh->length = msgb_l3len(msg);

	DEBUGPFOH(DNM, foh, "%s(): sending %s\n", __func__, msgb_hexdump(msg));
	return abis_nm_sendmsg(bts, msg);
}

int abis_nm_sw_act_req_ack(struct gsm_bts *bts, uint8_t obj_class, uint8_t i1,
			   uint8_t i2, uint8_t i3, int nack,
			   const uint8_t *attr, unsigned int attr_len)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();
	uint8_t msgtype = NM_MT_SW_ACT_REQ_ACK;
	uint8_t len = attr_len;

	if (nack) {
		len += 2;
		msgtype = NM_MT_SW_ACT_REQ_NACK;
	}

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, len, msgtype, obj_class, i1, i2, i3);

	if (attr != NULL && attr_len > 0)
		memcpy(msgb_put(msg, attr_len), attr, attr_len);
	if (nack)
		msgb_tv_put(msg, NM_ATT_NACK_CAUSES, NM_NACK_OBJCLASS_NOTSUPP);

	return abis_nm_sendmsg_direct(bts, msg);
}

int abis_nm_raw_msg(struct gsm_bts *bts, int len, uint8_t *rawmsg)
{
	struct msgb *msg = nm_msgb_alloc();
	struct abis_om_hdr *oh;
	uint8_t *data;

	oh = (struct abis_om_hdr *) msgb_put(msg, sizeof(*oh));
	fill_om_hdr(oh, len);
	data = msgb_put(msg, len);
	memcpy(data, rawmsg, len);

	return abis_nm_sendmsg(bts, msg);
}

/* Siemens specific commands */
static int __simple_cmd(struct gsm_bts *bts, uint8_t msg_type)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, 0, msg_type, NM_OC_SITE_MANAGER,
			0xff, 0xff, 0xff);

	return abis_nm_sendmsg(bts, msg);
}

/* Chapter 8.9.2 */
int abis_nm_opstart(struct gsm_bts *bts, uint8_t obj_class, uint8_t i0, uint8_t i1, uint8_t i2)
{
	struct abis_om_hdr *oh;
	struct abis_om_fom_hdr *foh;
	struct msgb *msg = nm_msgb_alloc();

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	foh = fill_om_fom_hdr(oh, 0, NM_MT_OPSTART, obj_class, i0, i1, i2);

	DEBUGPFOH(DNM, foh, "Sending OPSTART\n");

	return abis_nm_sendmsg(bts, msg);
}

/* Chapter 8.8.5 */
int abis_nm_chg_adm_state(struct gsm_bts *bts, uint8_t obj_class, uint8_t i0,
			  uint8_t i1, uint8_t i2, enum abis_nm_adm_state adm_state)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, 2, NM_MT_CHG_ADM_STATE, obj_class, i0, i1, i2);
	msgb_tv_put(msg, NM_ATT_ADM_STATE, adm_state);

	return abis_nm_sendmsg(bts, msg);
}

int abis_nm_conn_mdrop_link(struct gsm_bts *bts, uint8_t e1_port0, uint8_t ts0,
			    uint8_t e1_port1, uint8_t ts1)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();
	uint8_t *attr;

	DEBUGP(DNM, "CONNECT MDROP LINK E1=(%u,%u) -> E1=(%u, %u)\n",
		e1_port0, ts0, e1_port1, ts1);

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, 6, NM_MT_CONN_MDROP_LINK,
			NM_OC_SITE_MANAGER, 0x00, 0x00, 0x00);

	attr = msgb_put(msg, 3);
	attr[0] = NM_ATT_MDROP_LINK;
	attr[1] = e1_port0;
	attr[2] = ts0;

	attr = msgb_put(msg, 3);
	attr[0] = NM_ATT_MDROP_NEXT;
	attr[1] = e1_port1;
	attr[2] = ts1;

	return abis_nm_sendmsg(bts, msg);
}

/* Chapter 8.7.1 */
int abis_nm_perform_test(struct gsm_bts *bts, uint8_t obj_class,
			 uint8_t bts_nr, uint8_t trx_nr, uint8_t ts_nr,
			 uint8_t test_nr, uint8_t auton_report, struct msgb *msg)
{
	struct abis_om_hdr *oh;

	DEBUGP(DNM, "PERFORM TEST %s\n", abis_nm_test_name(test_nr));

	if (!msg) {
		msg = nm_msgb_alloc();
		if (!msg)
			return -ENOMEM;
	}

	msgb_tv_push(msg, NM_ATT_AUTON_REPORT, auton_report);
	msgb_tv_push(msg, NM_ATT_TEST_NO, test_nr);
	msg->l3h = msg->data;
	oh = (struct abis_om_hdr *) msgb_push(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, msgb_l3len(msg), NM_MT_PERF_TEST,
			obj_class, bts_nr, trx_nr, ts_nr);

	return abis_nm_sendmsg(bts, msg);
}

int abis_nm_event_reports(struct gsm_bts *bts, int on)
{
	if (on == 0)
		return __simple_cmd(bts, NM_MT_STOP_EVENT_REP);
	else
		return __simple_cmd(bts, NM_MT_REST_EVENT_REP);
}

/* Siemens (or BS-11) specific commands */

int abis_nm_bs11_bsc_disconnect(struct gsm_bts *bts, int reconnect)
{
	if (reconnect == 0)
		return __simple_cmd(bts, NM_MT_BS11_DISCONNECT);
	else
		return __simple_cmd(bts, NM_MT_BS11_RECONNECT);
}

int abis_nm_bs11_restart(struct gsm_bts *bts)
{
	return __simple_cmd(bts, NM_MT_BS11_RESTART);
}


struct bs11_date_time {
	uint16_t	year;
	uint8_t	month;
	uint8_t	day;
	uint8_t	hour;
	uint8_t	min;
	uint8_t	sec;
} __attribute__((packed));


void get_bs11_date_time(struct bs11_date_time *aet)
{
	time_t t;
	struct tm *tm;

	t = time(NULL);
	tm = localtime(&t);
	aet->sec = tm->tm_sec;
	aet->min = tm->tm_min;
	aet->hour = tm->tm_hour;
	aet->day = tm->tm_mday;
	aet->month = tm->tm_mon;
	aet->year = htons(1900 + tm->tm_year);
}

int abis_nm_bs11_reset_resource(struct gsm_bts *bts)
{
	return __simple_cmd(bts, NM_MT_BS11_RESET_RESOURCE);
}

int abis_nm_bs11_db_transmission(struct gsm_bts *bts, int begin)
{
	if (begin)
		return __simple_cmd(bts, NM_MT_BS11_BEGIN_DB_TX);
	else
		return __simple_cmd(bts, NM_MT_BS11_END_DB_TX);
}

int abis_nm_bs11_create_object(struct gsm_bts *bts,
				enum abis_bs11_objtype type, uint8_t idx,
				uint8_t attr_len, const uint8_t *attr)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();
	uint8_t *cur;

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, attr_len, NM_MT_BS11_CREATE_OBJ,
			NM_OC_BS11, type, 0, idx);
	cur = msgb_put(msg, attr_len);
	memcpy(cur, attr, attr_len);

	return abis_nm_sendmsg(bts, msg);
}

int abis_nm_bs11_delete_object(struct gsm_bts *bts,
				enum abis_bs11_objtype type, uint8_t idx)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, 0, NM_MT_BS11_DELETE_OBJ,
			NM_OC_BS11, type, 0, idx);

	return abis_nm_sendmsg(bts, msg);
}

int abis_nm_bs11_create_envaBTSE(struct gsm_bts *bts, uint8_t idx)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();
	uint8_t zero = 0x00;

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, 3, NM_MT_BS11_CREATE_OBJ,
			NM_OC_BS11_ENVABTSE, 0, idx, 0xff);
	msgb_tlv_put(msg, 0x99, 1, &zero);

	return abis_nm_sendmsg(bts, msg);
}

int abis_nm_bs11_create_bport(struct gsm_bts *bts, uint8_t idx)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, 0, NM_MT_BS11_CREATE_OBJ, NM_OC_BS11_BPORT,
			idx, 0xff, 0xff);

	return abis_nm_sendmsg(bts, msg);
}

int abis_nm_bs11_delete_bport(struct gsm_bts *bts, uint8_t idx)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, 0, NM_MT_BS11_DELETE_OBJ, NM_OC_BS11_BPORT,
			idx, 0xff, 0xff);

	return abis_nm_sendmsg(bts, msg);
}

static const uint8_t sm_attr[] = { NM_ATT_TEI, NM_ATT_ABIS_CHANNEL };
int abis_nm_bs11_get_oml_tei_ts(struct gsm_bts *bts)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, 2+sizeof(sm_attr), NM_MT_GET_ATTR, NM_OC_SITE_MANAGER,
			0xff, 0xff, 0xff);
	msgb_tlv_put(msg, NM_ATT_LIST_REQ_ATTR, sizeof(sm_attr), sm_attr);

	return abis_nm_sendmsg(bts, msg);
}

/* like abis_nm_conn_terr_traf + set_tei */
int abis_nm_bs11_conn_oml_tei(struct gsm_bts *bts, uint8_t e1_port,
			  uint8_t e1_timeslot, uint8_t e1_subslot,
			  uint8_t tei)
{
	struct abis_om_hdr *oh;
	struct abis_nm_channel *ch;
	struct msgb *msg = nm_msgb_alloc();

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, sizeof(*ch)+2, NM_MT_BS11_SET_ATTR,
			NM_OC_SITE_MANAGER, 0xff, 0xff, 0xff);

	ch = (struct abis_nm_channel *) msgb_put(msg, sizeof(*ch));
	fill_nm_channel(ch, e1_port, e1_timeslot, e1_subslot);
	msgb_tv_put(msg, NM_ATT_TEI, tei);

	return abis_nm_sendmsg(bts, msg);
}

int abis_nm_bs11_set_trx_power(struct gsm_bts_trx *trx, uint8_t level)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, 3, NM_MT_BS11_SET_ATTR,
			NM_OC_BS11, BS11_OBJ_PA, 0x00, trx->nr);
	msgb_tlv_put(msg, NM_ATT_BS11_TXPWR, 1, &level);

	return abis_nm_sendmsg(trx->bts, msg);
}

int abis_nm_bs11_get_trx_power(struct gsm_bts_trx *trx)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();
	uint8_t attr = NM_ATT_BS11_TXPWR;

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, 2+sizeof(attr), NM_MT_GET_ATTR,
			NM_OC_BS11, BS11_OBJ_PA, 0x00, trx->nr);
	msgb_tlv_put(msg, NM_ATT_LIST_REQ_ATTR, sizeof(attr), &attr);

	return abis_nm_sendmsg(trx->bts, msg);
}

int abis_nm_bs11_get_pll_mode(struct gsm_bts *bts)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();
	uint8_t attr[] = { NM_ATT_BS11_PLL_MODE };

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, 2+sizeof(attr), NM_MT_GET_ATTR,
			NM_OC_BS11, BS11_OBJ_LI, 0x00, 0x00);
	msgb_tlv_put(msg, NM_ATT_LIST_REQ_ATTR, sizeof(attr), attr);

	return abis_nm_sendmsg(bts, msg);
}

int abis_nm_bs11_get_cclk(struct gsm_bts *bts)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();
	uint8_t attr[] = { NM_ATT_BS11_CCLK_ACCURACY,
			    NM_ATT_BS11_CCLK_TYPE };

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, 2+sizeof(attr), NM_MT_GET_ATTR,
			NM_OC_BS11, BS11_OBJ_CCLK, 0x00, 0x00);
	msgb_tlv_put(msg, NM_ATT_LIST_REQ_ATTR, sizeof(attr), attr);

	return abis_nm_sendmsg(bts, msg);

}

//static const uint8_t bs11_logon_c7[] = { 0x07, 0xd9, 0x01, 0x11, 0x0d, 0x10, 0x20 };

int abis_nm_bs11_factory_logon(struct gsm_bts *bts, int on)
{
	return abis_nm_bs11_logon(bts, 0x02, "FACTORY", on);
}

int abis_nm_bs11_infield_logon(struct gsm_bts *bts, int on)
{
	return abis_nm_bs11_logon(bts, 0x03, "FIELD  ", on);
}

int abis_nm_bs11_logon(struct gsm_bts *bts, uint8_t level, const char *name, int on)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();
	struct bs11_date_time bdt;

	get_bs11_date_time(&bdt);

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	if (on) {
		uint8_t len = 3*2 + sizeof(bdt)
				+ 1 + strlen(name);
		fill_om_fom_hdr(oh, len, NM_MT_BS11_LMT_LOGON,
				NM_OC_BS11_BTSE, 0xff, 0xff, 0xff);
		msgb_tlv_put(msg, NM_ATT_BS11_LMT_LOGIN_TIME,
			     sizeof(bdt), (uint8_t *) &bdt);
		msgb_tlv_put(msg, NM_ATT_BS11_LMT_USER_ACC_LEV,
			     1, &level);
		msgb_tlv_put(msg, NM_ATT_BS11_LMT_USER_NAME,
			     strlen(name), (uint8_t *)name);
	} else {
		fill_om_fom_hdr(oh, 0, NM_MT_BS11_LMT_LOGOFF,
				NM_OC_BS11_BTSE, 0xff, 0xff, 0xff);
	}

	return abis_nm_sendmsg(bts, msg);
}

int abis_nm_bs11_set_trx1_pw(struct gsm_bts *bts, const char *password)
{
	struct abis_om_hdr *oh;
	struct msgb *msg;

	if (strlen(password) != 10)
		return -EINVAL;

 	msg = nm_msgb_alloc();
	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, 2+strlen(password), NM_MT_BS11_SET_ATTR,
			NM_OC_BS11, BS11_OBJ_TRX1, 0x00, 0x00);
	msgb_tlv_put(msg, NM_ATT_BS11_PASSWORD, 10, (const uint8_t *)password);

	return abis_nm_sendmsg(bts, msg);
}

/* change the BS-11 PLL Mode to either locked (E1 derived) or standalone */
int abis_nm_bs11_set_pll_locked(struct gsm_bts *bts, int locked)
{
	struct abis_om_hdr *oh;
	struct msgb *msg;
	uint8_t tlv_value;

	msg = nm_msgb_alloc();
	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, 3, NM_MT_BS11_SET_ATTR, NM_OC_BS11,
			BS11_OBJ_LI, 0x00, 0x00);

	if (locked)
		tlv_value = BS11_LI_PLL_LOCKED;
	else
		tlv_value = BS11_LI_PLL_STANDALONE;

	msgb_tlv_put(msg, NM_ATT_BS11_PLL_MODE, 1, &tlv_value);

	return abis_nm_sendmsg(bts, msg);
}

/* Set the calibration value of the PLL (work value/set value)
 * It depends on the login which one is changed */
int abis_nm_bs11_set_pll(struct gsm_bts *bts, int value)
{
	struct abis_om_hdr *oh;
	struct msgb *msg;
	uint8_t tlv_value[2];

	msg = nm_msgb_alloc();
	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, 3, NM_MT_BS11_SET_ATTR, NM_OC_BS11,
			BS11_OBJ_TRX1, 0x00, 0x00);

	tlv_value[0] = value>>8;
	tlv_value[1] = value&0xff;

	msgb_tlv_put(msg, NM_ATT_BS11_PLL, 2, tlv_value);

	return abis_nm_sendmsg(bts, msg);
}

int abis_nm_bs11_get_state(struct gsm_bts *bts)
{
	return __simple_cmd(bts, NM_MT_BS11_GET_STATE);
}

/* BS11 SWL */

void *tall_fle_ctx = NULL;

struct abis_nm_bs11_sw {
	struct gsm_bts *bts;
	char swl_fname[PATH_MAX];
	uint8_t win_size;
	int forced;
	struct llist_head file_list;
	gsm_cbfn *user_cb;	/* specified by the user */
};
static struct abis_nm_bs11_sw _g_bs11_sw, *g_bs11_sw = &_g_bs11_sw;

struct file_list_entry {
	struct llist_head list;
	char fname[PATH_MAX];
};

struct file_list_entry *fl_dequeue(struct llist_head *queue)
{
	struct llist_head *lh;

	if (llist_empty(queue))
		return NULL;

	lh = queue->next;
	llist_del(lh);

	return llist_entry(lh, struct file_list_entry, list);
}

static int bs11_read_swl_file(struct abis_nm_bs11_sw *bs11_sw)
{
	struct file_list_entry *fle;
	char linebuf[255];
	FILE *swl;
	int rc = 0;

	swl = fopen(bs11_sw->swl_fname, "r");
	if (!swl)
		return -ENODEV;

	/* zero the stale file list, if any */
	while ((fle = fl_dequeue(&bs11_sw->file_list)))
		talloc_free(fle);

	while (fgets(linebuf, sizeof(linebuf), swl)) {
		char file_id[12+1];
		char file_version[80+1];
		struct file_list_entry *fle;
		static char dir[PATH_MAX];

		if (strlen(linebuf) < 4)
			continue;

		rc = sscanf(linebuf+4, "%12s:%80s\r\n", file_id, file_version);
		if (rc < 0) {
			perror("ERR parsing SWL file");
			rc = -EINVAL;
			goto out;
		}
		if (rc < 2)
			continue;

		fle = talloc_zero(tall_fle_ctx, struct file_list_entry);
		if (!fle) {
			rc = -ENOMEM;
			goto out;
		}

		/* construct new filename */
		osmo_strlcpy(dir, bs11_sw->swl_fname, sizeof(dir));
		strncat(fle->fname, dirname(dir), sizeof(fle->fname) - 1);
		strcat(fle->fname, "/");
		strncat(fle->fname, file_id, sizeof(fle->fname) - 1 -strlen(fle->fname));

		llist_add_tail(&fle->list, &bs11_sw->file_list);
	}

out:
	fclose(swl);
	return rc;
}

/* bs11 swload specific callback, passed to abis_nm core swload */
static int bs11_swload_cbfn(unsigned int hook, unsigned int event,
			    struct msgb *msg, void *data, void *param)
{
	struct abis_nm_bs11_sw *bs11_sw = data;
	struct file_list_entry *fle;
	int rc = 0;

	switch (event) {
	case NM_MT_LOAD_END_ACK:
		fle = fl_dequeue(&bs11_sw->file_list);
		if (fle) {
			/* start download the next file of our file list */
			rc = abis_nm_software_load(bs11_sw->bts, 0xff, fle->fname,
						   bs11_sw->win_size,
						   bs11_sw->forced,
						   &bs11_swload_cbfn, bs11_sw);
			talloc_free(fle);
		} else {
			/* activate the SWL */
			rc = abis_nm_software_activate(bs11_sw->bts,
							bs11_sw->swl_fname,
							bs11_swload_cbfn,
							bs11_sw);
		}
		break;
	case NM_MT_LOAD_SEG_ACK:
	case NM_MT_LOAD_END_NACK:
	case NM_MT_LOAD_INIT_ACK:
	case NM_MT_LOAD_INIT_NACK:
	case NM_MT_ACTIVATE_SW_NACK:
	case NM_MT_ACTIVATE_SW_ACK:
	default:
		/* fallthrough to the user callback */
		if (bs11_sw->user_cb)
			rc = bs11_sw->user_cb(hook, event, msg, NULL, NULL);
		break;
	}

	return rc;
}

/* Siemens provides a SWL file that is a mere listing of all the other
 * files that are part of a software release.  We need to upload first
 * the list file, and then each file that is listed in the list file */
int abis_nm_bs11_load_swl(struct gsm_bts *bts, const char *fname,
			  uint8_t win_size, int forced, gsm_cbfn *cbfn)
{
	struct abis_nm_bs11_sw *bs11_sw = g_bs11_sw;
	struct file_list_entry *fle;
	int rc = 0;

	INIT_LLIST_HEAD(&bs11_sw->file_list);
	bs11_sw->bts = bts;
	bs11_sw->win_size = win_size;
	bs11_sw->user_cb = cbfn;
	bs11_sw->forced = forced;

	osmo_strlcpy(bs11_sw->swl_fname, fname, sizeof(bs11_sw->swl_fname));
	rc = bs11_read_swl_file(bs11_sw);
	if (rc < 0)
		return rc;

	/* dequeue next item in file list */
	fle = fl_dequeue(&bs11_sw->file_list);
	if (!fle)
		return -EINVAL;

	/* start download the next file of our file list */
	rc = abis_nm_software_load(bts, 0xff, fle->fname, win_size, forced,
				   bs11_swload_cbfn, bs11_sw);
	talloc_free(fle);
	return rc;
}

#if 0
static uint8_t req_attr_btse[] = {
	NM_ATT_ADM_STATE, NM_ATT_BS11_LMT_LOGON_SESSION,
	NM_ATT_BS11_LMT_LOGIN_TIME, NM_ATT_BS11_LMT_USER_ACC_LEV,
	NM_ATT_BS11_LMT_USER_NAME,

	0xaf, NM_ATT_BS11_RX_OFFSET, NM_ATT_BS11_VENDOR_NAME,

	NM_ATT_BS11_SW_LOAD_INTENDED, NM_ATT_BS11_SW_LOAD_SAFETY,

	NM_ATT_BS11_SW_LOAD_STORED };

static uint8_t req_attr_btsm[] = {
	NM_ATT_ABIS_CHANNEL, NM_ATT_TEI, NM_ATT_BS11_ABIS_EXT_TIME,
	NM_ATT_ADM_STATE, NM_ATT_AVAIL_STATUS, 0xce, NM_ATT_FILE_ID,
	NM_ATT_FILE_VERSION, NM_ATT_OPER_STATE, 0xe8, NM_ATT_BS11_ALL_TEST_CATG,
	NM_ATT_SW_DESCR, NM_ATT_GET_ARI };
#endif

static uint8_t req_attr[] = {
	NM_ATT_ADM_STATE, NM_ATT_AVAIL_STATUS, 0xa8, NM_ATT_OPER_STATE,
	0xd5, 0xa1, NM_ATT_BS11_ESN_FW_CODE_NO, NM_ATT_BS11_ESN_HW_CODE_NO,
	0x42, NM_ATT_BS11_ESN_PCB_SERIAL, NM_ATT_BS11_PLL };

int abis_nm_bs11_get_serno(struct gsm_bts *bts)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	/* SiemensHW CCTRL object */
	fill_om_fom_hdr(oh, 2+sizeof(req_attr), NM_MT_GET_ATTR, NM_OC_BS11,
			0x03, 0x00, 0x00);
	msgb_tlv_put(msg, NM_ATT_LIST_REQ_ATTR, sizeof(req_attr), req_attr);

	return abis_nm_sendmsg(bts, msg);
}

int abis_nm_bs11_set_ext_time(struct gsm_bts *bts)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();
	struct bs11_date_time aet;

	get_bs11_date_time(&aet);
	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	/* SiemensHW CCTRL object */
	fill_om_fom_hdr(oh, 2+sizeof(aet), NM_MT_BS11_SET_ATTR, NM_OC_SITE_MANAGER,
			0xff, 0xff, 0xff);
	msgb_tlv_put(msg, NM_ATT_BS11_ABIS_EXT_TIME, sizeof(aet), (uint8_t *) &aet);

	return abis_nm_sendmsg(bts, msg);
}

int abis_nm_bs11_get_bport_line_cfg(struct gsm_bts *bts, uint8_t bport)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();
	uint8_t attr = NM_ATT_BS11_LINE_CFG;

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, 2+sizeof(attr), NM_MT_GET_ATTR,
			NM_OC_BS11_BPORT, bport, 0xff, 0x02);
	msgb_tlv_put(msg, NM_ATT_LIST_REQ_ATTR, sizeof(attr), &attr);

	return abis_nm_sendmsg(bts, msg);
}

int abis_nm_bs11_set_bport_line_cfg(struct gsm_bts *bts, uint8_t bport, enum abis_bs11_line_cfg line_cfg)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();
	struct bs11_date_time aet;

	get_bs11_date_time(&aet);
	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, 2, NM_MT_BS11_SET_ATTR, NM_OC_BS11_BPORT,
			bport, 0xff, 0x02);
	msgb_tv_put(msg, NM_ATT_BS11_LINE_CFG, line_cfg);

	return abis_nm_sendmsg(bts, msg);
}

static int abis_nm_rx_ipacc(struct msgb *msg)
{
	struct in_addr addr;
	struct abis_om_hdr *oh = msgb_l2(msg);
	struct abis_om_fom_hdr *foh;
	uint8_t idstrlen = oh->data[0];
	struct tlv_parsed tp;
	struct ipacc_ack_signal_data signal;
	struct e1inp_sign_link *sign_link = msg->dst;
	struct gsm_bts *bts = sign_link->trx->bts;
	struct gsm_bts_trx *trx;

	foh = (struct abis_om_fom_hdr *) (oh->data + 1 + idstrlen);

	if (strncmp((char *)&oh->data[1], abis_nm_ipa_magic, idstrlen)) {
		LOGPFOH(DNM, LOGL_ERROR, foh, "id string is not com.ipaccess !?!\n");
		return -EINVAL;
	}

	if (abis_nm_tlv_parse(&tp, bts, foh->data, oh->length - sizeof(*foh)) < 0) {
		LOGPFOH(DNM, LOGL_ERROR, foh, "%s(): tlv_parse failed\n", __func__);
		return -EINVAL;
	}

	/* The message might be received over the main OML link, so we cannot
	 * just use sign_link->trx. Resolve it by number from the FOM header. */
	trx = gsm_bts_trx_num(bts, foh->obj_inst.trx_nr);

	DEBUGPFOH(DNM, foh, "Rx IPACCESS(0x%02x): %s\n", foh->msg_type,
		  osmo_hexdump(foh->data, oh->length - sizeof(*foh)));

	switch (foh->msg_type) {
	case NM_MT_IPACC_RSL_CONNECT_ACK:
		DEBUGPFOH(DNM, foh, "RSL CONNECT ACK ");
		if (TLVP_PRESENT(&tp, NM_ATT_IPACC_DST_IP)) {
			memcpy(&addr,
				TLVP_VAL(&tp, NM_ATT_IPACC_DST_IP), sizeof(addr));

			DEBUGPC(DNM, "IP=%s ", inet_ntoa(addr));
		}
		if (TLVP_PRESENT(&tp, NM_ATT_IPACC_DST_IP_PORT))
			DEBUGPC(DNM, "PORT=%" SCNu16 " ", osmo_load16be(TLVP_VAL(&tp, NM_ATT_IPACC_DST_IP_PORT)));
		if (TLVP_PRESENT(&tp, NM_ATT_IPACC_STREAM_ID))
			DEBUGPC(DNM, "STREAM=0x%02x ",
					*TLVP_VAL(&tp, NM_ATT_IPACC_STREAM_ID));
		DEBUGPC(DNM, "\n");
		if (!trx)
			goto obj_inst_error;
		osmo_timer_del(&trx->rsl_connect_timeout);
		break;
	case NM_MT_IPACC_RSL_CONNECT_NACK:
		LOGPFOH(DNM, LOGL_ERROR, foh, "RSL CONNECT NACK ");
		if (TLVP_PRESENT(&tp, NM_ATT_NACK_CAUSES))
			LOGPC(DNM, LOGL_ERROR, " CAUSE=%s\n",
				abis_nm_nack_cause_name(*TLVP_VAL(&tp, NM_ATT_NACK_CAUSES)));
		else
			LOGPC(DNM, LOGL_ERROR, "\n");
		if (!trx)
			goto obj_inst_error;
		osmo_timer_del(&trx->rsl_connect_timeout);
		break;
	case NM_MT_IPACC_SET_NVATTR_ACK:
		DEBUGPFOH(DNM, foh, "SET NVATTR ACK\n");
		/* FIXME: decode and show the actual attributes */
		break;
	case NM_MT_IPACC_SET_NVATTR_NACK:
		LOGPFOH(DNM, LOGL_ERROR, foh, "SET NVATTR NACK ");
		if (TLVP_PRESENT(&tp, NM_ATT_NACK_CAUSES))
			LOGPC(DNM, LOGL_ERROR, " CAUSE=%s\n",
				abis_nm_nack_cause_name(*TLVP_VAL(&tp, NM_ATT_NACK_CAUSES)));
		else
			LOGPC(DNM, LOGL_ERROR, "\n");
		break;
	case NM_MT_IPACC_GET_NVATTR_ACK:
		DEBUGPFOH(DNM, foh, "GET NVATTR ACK\n");
		/* FIXME: decode and show the actual attributes */
		break;
	case NM_MT_IPACC_GET_NVATTR_NACK:
		LOGPFOH(DNM, LOGL_ERROR, foh, "GET NVATTR NACK ");
		if (TLVP_PRESENT(&tp, NM_ATT_NACK_CAUSES))
			LOGPC(DNM, LOGL_ERROR, " CAUSE=%s\n",
				abis_nm_nack_cause_name(*TLVP_VAL(&tp, NM_ATT_NACK_CAUSES)));
		else
			LOGPC(DNM, LOGL_ERROR, "\n");
		break;
	case NM_MT_IPACC_SET_ATTR_ACK:
		DEBUGPFOH(DNM, foh, "SET ATTR ACK\n");
		break;
	case NM_MT_IPACC_SET_ATTR_NACK:
		LOGPFOH(DNM, LOGL_ERROR, foh, "SET ATTR NACK ");
		if (TLVP_PRESENT(&tp, NM_ATT_NACK_CAUSES))
			LOGPC(DNM, LOGL_ERROR, " CAUSE=%s\n",
				abis_nm_nack_cause_name(*TLVP_VAL(&tp, NM_ATT_NACK_CAUSES)));
		else
			LOGPC(DNM, LOGL_ERROR, "\n");
		break;
	default:
		LOGPFOH(DNM, LOGL_ERROR, foh, "Unknown message\n");
		break;
	}

	/* signal handling */
	switch  (foh->msg_type) {
	case NM_MT_IPACC_RSL_CONNECT_NACK:
	case NM_MT_IPACC_SET_NVATTR_NACK:
	case NM_MT_IPACC_GET_NVATTR_NACK:
		signal.bts = bts;
		signal.foh = foh;
		osmo_signal_dispatch(SS_NM, S_NM_IPACC_NACK, &signal);
		break;
	case NM_MT_IPACC_RSL_CONNECT_ACK:
	case NM_MT_IPACC_SET_NVATTR_ACK:
	case NM_MT_IPACC_SET_ATTR_ACK:
		signal.bts = bts;
		signal.foh = foh;
		osmo_signal_dispatch(SS_NM, S_NM_IPACC_ACK, &signal);
		break;
	default:
		break;
	}

	return 0;

obj_inst_error:
	LOGPFOH(DNM, LOGL_ERROR, foh, "Unknown object instance\n");
	return -EINVAL;
}

/* send an ip-access manufacturer specific message */
int abis_nm_ipaccess_msg(struct gsm_bts *bts, uint8_t msg_type,
			 uint8_t obj_class, uint8_t bts_nr,
			 uint8_t trx_nr, uint8_t ts_nr,
			 uint8_t *attr, int attr_len)
{
	struct msgb *msg = nm_msgb_alloc();
	struct abis_om_hdr *oh;
	struct abis_om_fom_hdr *foh;
	uint8_t *data;

	/* construct the 12.21 OM header, observe the erroneous length */
	oh = (struct abis_om_hdr *) msgb_put(msg, sizeof(*oh));
	fill_om_hdr(oh, sizeof(*foh) + attr_len);
	oh->mdisc = ABIS_OM_MDISC_MANUF;

	/* add the ip.access magic */
	msgb_lv_put(msg, sizeof(abis_nm_ipa_magic),
		    (const uint8_t *) abis_nm_ipa_magic);

	/* fill the 12.21 FOM header */
	foh = (struct abis_om_fom_hdr *) msgb_put(msg, sizeof(*foh));
	foh->msg_type = msg_type;
	foh->obj_class = obj_class;
	foh->obj_inst.bts_nr = bts_nr;
	foh->obj_inst.trx_nr = trx_nr;
	foh->obj_inst.ts_nr = ts_nr;

	if (attr && attr_len) {
		data = msgb_put(msg, attr_len);
		memcpy(data, attr, attr_len);
	}

	return abis_nm_sendmsg(bts, msg);
}

/* set some attributes in NVRAM */
int abis_nm_ipaccess_set_nvattr(struct gsm_bts_trx *trx, uint8_t *attr,
				int attr_len)
{
	return abis_nm_ipaccess_msg(trx->bts, NM_MT_IPACC_SET_NVATTR,
				    NM_OC_BASEB_TRANSC, 0, trx->nr, 0xff, attr,
				    attr_len);
}

static void rsl_connect_timeout(void *data)
{
	struct gsm_bts_trx *trx = data;
	struct ipacc_ack_signal_data signal;

	LOG_TRX(trx, DRSL, LOGL_NOTICE, "RSL connection request timed out\n");

	/* Fake an RSL CONNECT NACK message from the BTS. */
	struct abis_om_fom_hdr foh = {
		.msg_type = NM_MT_IPACC_RSL_CONNECT_NACK,
		.obj_class = NM_OC_BASEB_TRANSC,
		.obj_inst = {
			.bts_nr = trx->bts->bts_nr,
			.trx_nr = trx->nr,
			.ts_nr = 0xff,
		},
	};
	signal.foh = &foh;
	signal.bts = trx->bts;
	osmo_signal_dispatch(SS_NM, S_NM_IPACC_NACK, &signal);
}

int abis_nm_ipaccess_rsl_connect(struct gsm_bts_trx *trx,
				 uint32_t ip, uint16_t port, uint8_t stream)
{
	struct msgb *attr;
	struct in_addr ia;
	int error;

	osmo_timer_setup(&trx->rsl_connect_timeout, rsl_connect_timeout, trx);

	attr = msgb_alloc(32, "RSL-connect-attr");
	msgb_tv_put(attr, NM_ATT_IPACC_STREAM_ID, stream);
	msgb_tv16_put(attr, NM_ATT_IPACC_DST_IP_PORT, port);

	/* if ip == 0, we use the default IP */
	if (ip != 0) {
		ia.s_addr = htonl(ip);
		msgb_tv_fixed_put(attr, NM_ATT_IPACC_DST_IP, 4, (void*)&ia.s_addr);
	} else {
		ia = (struct in_addr){};
	}

	LOG_TRX(trx, DNM, LOGL_INFO, "IPA RSL CONNECT IP=%s PORT=%u STREAM=0x%02x\n",
		inet_ntoa(ia), port, stream);

	error = abis_nm_ipaccess_msg(trx->bts, NM_MT_IPACC_RSL_CONNECT,
				     NM_OC_BASEB_TRANSC, trx->bts->bts_nr,
				     trx->nr, 0xff, attr->data, attr->len);
	msgb_free(attr);
	if (error == 0)
		osmo_timer_schedule(&trx->rsl_connect_timeout, 60, 0);

	return error;
}

/* restart / reboot an ip.access nanoBTS */
int abis_nm_ipaccess_restart(struct gsm_bts_trx *trx)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, 0, NM_MT_IPACC_RESTART, NM_OC_BASEB_TRANSC,
			trx->bts->bts_nr, trx->nr, 0xff);

	return abis_nm_sendmsg_direct(trx->bts, msg);
}

int abis_nm_ipaccess_set_attr(struct gsm_bts *bts, uint8_t obj_class,
				uint8_t bts_nr, uint8_t trx_nr, uint8_t ts_nr,
				uint8_t *attr, uint8_t attr_len)
{
	return abis_nm_ipaccess_msg(bts, NM_MT_IPACC_SET_ATTR,
				    obj_class, bts_nr, trx_nr, ts_nr,
				     attr, attr_len);
}

void abis_nm_ipaccess_cgi(uint8_t *buf, struct gsm_bts *bts)
{
	struct gsm48_ra_id *_buf = (struct gsm48_ra_id*)buf;
	uint16_t ci = htons(bts->cell_identity);
	/* we simply reuse the GSM48 function and write the Cell ID over the position where the RAC
	 * starts */
	gsm48_ra_id_by_bts(_buf, bts);
	memcpy(&_buf->rac, &ci, sizeof(ci));
}

static const struct value_string ipacc_testres_names[] = {
	{ NM_IPACC_TESTRES_SUCCESS,	"SUCCESS" },
	{ NM_IPACC_TESTRES_TIMEOUT,	"TIMEOUT" },
	{ NM_IPACC_TESTRES_NO_CHANS,	"NO CHANNELS" },
	{ NM_IPACC_TESTRES_PARTIAL,	"PARTIAL" },
	{ NM_IPACC_TESTRES_STOPPED,	"STOPPED" },
	{ 0,				NULL }
};

const char *ipacc_testres_name(uint8_t res)
{
	return get_value_string(ipacc_testres_names, res);
}

void ipac_parse_cgi(struct osmo_cell_global_id *cid, const uint8_t *buf)
{
	osmo_plmn_from_bcd(buf, &cid->lai.plmn);
	cid->lai.lac = ntohs(*((uint16_t *)&buf[3]));
	cid->cell_identity = ntohs(*((uint16_t *)&buf[5]));
}

/* parse BCCH information IEI from wire format to struct ipac_bcch_info */
int ipac_parse_bcch_info(struct ipac_bcch_info *binf, uint8_t *buf)
{
	uint8_t *cur = buf;
	uint16_t len __attribute__((unused));

	memset(binf, 0, sizeof(*binf));

	if (cur[0] != NM_IPAC_EIE_BCCH_INFO)
		return -EINVAL;
	cur++;

	len = ntohs(*(uint16_t *)cur);
	cur += 2;

	binf->info_type = ntohs(*(uint16_t *)cur);
	cur += 2;

	if (binf->info_type & IPAC_BINF_FREQ_ERR_QUAL)
		binf->freq_qual = *cur >> 2;

	binf->arfcn = (*cur++ & 3) << 8;
	binf->arfcn |= *cur++;

	if (binf->info_type & IPAC_BINF_RXLEV)
		binf->rx_lev = *cur & 0x3f;
	cur++;

	if (binf->info_type & IPAC_BINF_RXQUAL)
		binf->rx_qual = *cur & 0x7;
	cur++;

	if (binf->info_type & IPAC_BINF_FREQ_ERR_QUAL)
		binf->freq_err = ntohs(*(uint16_t *)cur);
	cur += 2;

	if (binf->info_type & IPAC_BINF_FRAME_OFFSET)
		binf->frame_offset = ntohs(*(uint16_t *)cur);
	cur += 2;

	if (binf->info_type & IPAC_BINF_FRAME_NR_OFFSET)
		binf->frame_nr_offset = ntohl(*(uint32_t *)cur);
	cur += 4;

#if 0
	/* Somehow this is not set correctly */
	if (binf->info_type & IPAC_BINF_BSIC)
#endif
		binf->bsic = *cur & 0x3f;
	cur++;

	ipac_parse_cgi(&binf->cgi, cur);
	cur += 7;

	if (binf->info_type & IPAC_BINF_NEIGH_BA_SI2) {
		memcpy(binf->ba_list_si2, cur, sizeof(binf->ba_list_si2));
		cur += sizeof(binf->ba_list_si2);
	}

	if (binf->info_type & IPAC_BINF_NEIGH_BA_SI2bis) {
		memcpy(binf->ba_list_si2bis, cur,
			sizeof(binf->ba_list_si2bis));
		cur += sizeof(binf->ba_list_si2bis);
	}

	if (binf->info_type & IPAC_BINF_NEIGH_BA_SI2ter) {
		memcpy(binf->ba_list_si2ter, cur,
			sizeof(binf->ba_list_si2ter));
		cur += sizeof(binf->ba_list_si2ter);
	}

	return 0;
}

void abis_nm_clear_queue(struct gsm_bts *bts)
{
	struct msgb *msg;

	while (!llist_empty(&bts->abis_queue)) {
		msg = msgb_dequeue(&bts->abis_queue);
		msgb_free(msg);
	}

	bts->abis_nm_pend = 0;
}
