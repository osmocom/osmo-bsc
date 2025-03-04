/* Nokia XXXsite family specific code */

/* (C) 2011 by Dieter Spaar <spaar@mirider.augusta.de>
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

/*
  TODO: Attention: There are some static variables used for states during
  configuration. Those variables have to be moved to a BTS specific context,
  otherwise there will most certainly be problems if more than one Nokia BTS
  is used.
*/

#include <time.h>

#include <osmocom/gsm/tlv.h>

#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/abis_nm.h>
#include <osmocom/abis/e1_input.h>
#include <osmocom/bsc/signal.h>
#include <osmocom/bsc/timeslot_fsm.h>
#include <osmocom/bsc/system_information.h>
#include <osmocom/bsc/bts.h>

#include <osmocom/core/timer.h>

#include <osmocom/abis/lapd.h>

enum reset_timer_state {
	RESET_T_NONE = 0,
	RESET_T_STOP_LAPD = 1,		/* first timer expiration: stop LAPD SAP */
	RESET_T_RESTART_LAPD = 2,	/* second timer expiration: restart LAPD SAP */
};

/* TODO: put in a separate file ? */

extern int abis_nm_sendmsg(struct gsm_bts *bts, struct msgb *msg);

static void nokia_abis_nm_queue_send_next(struct gsm_bts *bts);
static void reset_timer_cb(void *_bts);
static int abis_nm_reset(struct gsm_bts *bts, uint16_t ref);
static int dump_elements(uint8_t * data, int len) __attribute__((unused));

static void bootstrap_om_bts(struct gsm_bts *bts)
{
	LOG_BTS(bts, DNM, LOGL_NOTICE, "bootstrapping OML\n");

	if (!bts->nokia.skip_reset) {
		if (!bts->nokia.did_reset)
			abis_nm_reset(bts, 1);
	} else
		bts->nokia.did_reset = 1;

	gsm_bts_all_ts_dispatch(bts, TS_EV_OML_READY, NULL);
}

static void bootstrap_om_trx(struct gsm_bts_trx *trx)
{
	LOG_TRX(trx, DNM, LOGL_NOTICE, "bootstrapping OML\n");

	gsm_trx_all_ts_dispatch(trx, TS_EV_OML_READY, NULL);
}

static int shutdown_om(struct gsm_bts *bts)
{
	gsm_bts_stats_reset(bts);
	/* TODO !? */
	return 0;
}

#define SAPI_OML    62
#define SAPI_RSL    0

/*

  Tell LAPD to start start the SAP (send SABM requests) for all signalling
  timeslots in this line

  Attention: this has to be adapted for mISDN
*/

static void start_sabm_in_line(struct e1inp_line *line, int start, int sapi)
{
	struct e1inp_sign_link *link;
	int i;

	for (i = 0; i < ARRAY_SIZE(line->ts); i++) {
		struct e1inp_ts *ts = &line->ts[i];

		if (ts->type != E1INP_TS_TYPE_SIGN)
			continue;

		llist_for_each_entry(link, &ts->sign.sign_links, list) {
			if (sapi != -1 && link->sapi != sapi)
				continue;

#if 0				/* debugging */
			printf("sap start/stop (%d): %d tei=%d sapi=%d\n",
			       start, i + 1, link->tei, link->sapi);
#endif

			if (start) {
				ts->lapd->profile.t200_sec = 1;
				ts->lapd->profile.t200_usec = 0;
				lapd_sap_start(ts->lapd, link->tei,
					       link->sapi);
			} else
				lapd_sap_stop(ts->lapd, link->tei,
					      link->sapi);
		}
	}
}

/* Callback function to be called every time we receive a signal from INPUT */
static int gbl_sig_cb(unsigned int subsys, unsigned int signal,
		      void *handler_data, void *signal_data)
{
	struct gsm_bts *bts;

	if (subsys != SS_L_GLOBAL)
		return 0;

	switch (signal) {
	case S_GLOBAL_BTS_CLOSE_OM:
		bts = signal_data;
		if (bts->type == GSM_BTS_TYPE_NOKIA_SITE)
			shutdown_om(signal_data);
		break;
	}

	return 0;
}

/* Callback function to be called every time we receive a signal from INPUT */
static int inp_sig_cb(unsigned int subsys, unsigned int signal,
		      void *handler_data, void *signal_data)
{
	struct input_signal_data *isd = signal_data;

	if (subsys != SS_L_INPUT)
		return 0;

	switch (signal) {
	case S_L_INP_LINE_INIT:
		start_sabm_in_line(isd->line, 1, SAPI_OML);	/* start only OML */
		break;
	case S_L_INP_TEI_DN:
		break;
	case S_L_INP_TEI_UP:
		switch (isd->link_type) {
		case E1INP_SIGN_OML:
			if (isd->trx->bts->type != GSM_BTS_TYPE_NOKIA_SITE)
				break;

			if (isd->tei == isd->trx->bts->oml_tei)
				bootstrap_om_bts(isd->trx->bts);
			else
				bootstrap_om_trx(isd->trx);
			break;
		default:
			break;
		}
		break;
	case S_L_INP_TEI_UNKNOWN:
		/* We are receiving LAPD frames with one TEI that we do not
		 * seem to know, likely that we (the BSC) stopped working
		 * and lost our local states. However, the BTS is already
		 * configured, we try to take over the RSL links. */
		start_sabm_in_line(isd->line, 1, SAPI_RSL);
		break;
	}

	return 0;
}

static void nm_statechg_evt(unsigned int signal,
			    struct nm_statechg_signal_data *nsd)
{
	if (nsd->bts->type != GSM_BTS_TYPE_NOKIA_SITE)
		return;
}

static int nm_sig_cb(unsigned int subsys, unsigned int signal,
		     void *handler_data, void *signal_data)
{
	if (subsys != SS_NM)
		return 0;

	switch (signal) {
	case S_NM_STATECHG:
		nm_statechg_evt(signal, signal_data);
		break;
	default:
		break;
	}

	return 0;
}

/* TODO: put in a separate file ? */

static const struct value_string nokia_msgt_name[] = {
	{ 0x7F, "NOKIA_BTS_RSSI_VSWR_COUNTERS_REQ" },
	{ 0x80, "NOKIA_BTS_CONF_DATA" },
	{ 0x81, "NOKIA_BTS_ACK" },
	{ 0x82, "NOKIA_BTS_OMU_STARTED" },
	{ 0x83, "NOKIA_BTS_START_DOWNLOAD_REQ" },
	{ 0x84, "NOKIA_BTS_MF_REQ" },
	{ 0x85, "NOKIA_BTS_AF_REQ" },
	{ 0x86, "NOKIA_BTS_RESET_REQ" },
	{ 0x87, "NOKIA_reserved" },
	{ 0x88, "NOKIA_BTS_CONF_REQ" },
	{ 0x89, "NOKIA_BTS_TEST_REQ" },
	{ 0x8A, "NOKIA_BTS_TEST_REPORT" },
	{ 0x8B, "NOKIA_reserved" },
	{ 0x8C, "NOKIA_reserved" },
	{ 0x8D, "NOKIA_reserved" },
	{ 0x8E, "NOKIA_BTS_CONF_COMPL" },
	{ 0x8F, "NOKIA_reserved" },
	{ 0x90, "NOKIA_BTS_STM_TEST_REQ" },
	{ 0x91, "NOKIA_BTS_STM_TEST_REPORT" },
	{ 0x92, "NOKIA_BTS_TRANSMISSION_COMMAND" },
	{ 0x93, "NOKIA_BTS_TRANSMISSION_ANSWER" },
	{ 0x94, "NOKIA_BTS_HW_DB_UPLOAD_REQ" },
	{ 0x95, "NOKIA_BTS_START_HW_DB_DOWNLOAD_REQ" },
	{ 0x96, "NOKIA_BTS_HW_DB_SAVE_REQ" },
	{ 0x97, "NOKIA_BTS_FLASH_ERASURE_REQ" },
	{ 0x98, "NOKIA_BTS_HW_DB_DOWNLOAD_REQ" },
	{ 0x99, "NOKIA_BTS_PWR_SUPPLY_CONTROL" },
	{ 0x9A, "NOKIA_BTS_ATTRIBUTE_REQ" },
	{ 0x9B, "NOKIA_BTS_ATTRIBUTE_REPORT" },
	{ 0x9C, "NOKIA_BTS_HW_REQ" },
	{ 0x9D, "NOKIA_BTS_HW_REPORT" },
	{ 0x9E, "NOKIA_BTS_RTE_TEST_REQ" },
	{ 0x9F, "NOKIA_BTS_RTE_TEST_REPORT" },
	{ 0xA0, "NOKIA_BTS_HW_DB_VERIFICATION_REQ" },
	{ 0xA1, "NOKIA_BTS_CLOCK_REQ" },
	{ 0xA2, "NOKIA_AC_CIRCUIT_REQ_NACK" },
	{ 0xA3, "NOKIA_AC_INTERRUPTED" },
	{ 0xA4, "NOKIA_BTS_NEW_TRE_INFO" },
	{ 0xA5, "NOKIA_AC_BSC_CIRCUITS_ALLOCATED" },
	{ 0xA6, "NOKIA_BTS_TRE_POLL_LIST" },
	{ 0xA7, "NOKIA_AC_CIRCUIT_REQ" },
	{ 0xA8, "NOKIA_BTS_BLOCK_CTRL_REQ" },
	{ 0xA9, "NOKIA_BTS_GSM_TIME_REQ" },
	{ 0xAA, "NOKIA_BTS_GSM_TIME" },
	{ 0xAB, "NOKIA_BTS_OUTPUT_CONTROL" },
	{ 0xAC, "NOKIA_BTS_STATE_CHANGED" },
	{ 0xAD, "NOKIA_BTS_SW_SAVE_REQ" },
	{ 0xAE, "NOKIA_BTS_ALARM" },
	{ 0xAF, "NOKIA_BTS_CHA_ADM_STATE" },
	{ 0xB0, "NOKIA_AC_POOL_SIZE_REPORT" },
	{ 0xB1, "NOKIA_AC_POOL_SIZE_INQUIRY" },
	{ 0xB2, "NOKIA_BTS_COMMISS_TEST_COMPLETED" },
	{ 0xB3, "NOKIA_BTS_COMMISS_TEST_REQ" },
	{ 0xB4, "NOKIA_BTS_TRANSP_BTS_TO_BSC" },
	{ 0xB5, "NOKIA_BTS_TRANSP_BSC_TO_BTS" },
	{ 0xB6, "NOKIA_BTS_LCS_COMMAND" },
	{ 0xB7, "NOKIA_BTS_LCS_ANSWER" },
	{ 0xB8, "NOKIA_BTS_LMU_FN_OFFSET_COMMAND" },
	{ 0xB9, "NOKIA_BTS_LMU_FN_OFFSET_ANSWER" },
	{ 0xBA, "NOKIA_BTS_LAPD_CTR_REP" },
	{ 0xBB, "NOKIA_BTS_TRX_CONFIGURATION_UPDATE" },
	{ 0xBC, "NOKIA_BTS_DYNAMIC_LOAD_INFO" },
	{ 0xBD, "NOKIA_BTS_CONF_DATA_BS2" },
	{ 0xBE, "NOKIA_BTS_REGISTRY_REQ" },
	{ 0xBF, "NOKIA_BTS_SFS_UPLOAD_REQ" },
	{ 0xC0, "NOKIA_BTS_DELAY_MEAS_REQ" },
	{ 0xC1, "NOKIA_BTS_DELAY_MEAS_ACK" },
	{ 0xC2, "NOKIA_BTS_PABIS_MEAS_REQ" },
	{ 0xC3, "NOKIA_BTS_PABIS_MEAS_ACK" },
	{ 0xC4, "NOKIA_BSC_RESET_INFO" },
	{ 0xC5, "NOKIA_BSC_RESET_COMPL" },
	{ 0xC6, "NOKIA_BSC_RESET_COMPL_ANSWER" },
	{ 0xC7, "NOKIA_BTS_RSSI_VSWR_COUNTERS" },
	{ 0, NULL }
};

static const char *get_msg_type_name_string(uint8_t msg_type)
{
	return get_value_string(nokia_msgt_name, msg_type);
}

static const struct value_string nokia_element_name[] = {
	{ 0x01, "Ny1" },
	{ 0x02, "T3105_F" },
	{ 0x03, "Interference band limits" },
	{ 0x04, "Interference report timer in secs" },
	{ 0x05, "Channel configuration per TS" },
	{ 0x06, "BSIC" },
	{ 0x07, "RACH report timer in secs" },
	{ 0x08, "Hardware database status" },
	{ 0x09, "BTS RX level" },
	{ 0x0A, "ARFN" },
	{ 0x0B, "STM antenna attenuation" },
	{ 0x0C, "Cell allocation bitmap" },
	{ 0x0D, "Radio definition per TS" },
	{ 0x0E, "Frame number" },
	{ 0x0F, "Antenna diversity" },
	{ 0x10, "T3105_D" },
	{ 0x11, "File format" },
	{ 0x12, "Last File" },
	{ 0x13, "BTS type" },
	{ 0x14, "Erasure mode" },
	{ 0x15, "Hopping mode" },
	{ 0x16, "Floating TRX" },
	{ 0x17, "Power supplies" },
	{ 0x18, "Reset type" },
	{ 0x19, "Averaging period" },
	{ 0x1A, "RBER2" },
	{ 0x1B, "LAC" },
	{ 0x1C, "CI" },
	{ 0x1D, "Failure parameters" },
	{ 0x1E, "(RF max power reduction)" },
	{ 0x1F, "Measured RX_SENS" },
	{ 0x20, "Extended cell radius" },
	{ 0x21, "reserved" },
	{ 0x22, "Success-Failure" },
	{ 0x23, "Ack-Nack" },
	{ 0x24, "OMU test results" },
	{ 0x25, "File identity" },
	{ 0x26, "Generation and version code" },
	{ 0x27, "SW description" },
	{ 0x28, "BCCH LEV" },
	{ 0x29, "Test type" },
	{ 0x2A, "Subscriber number" },
	{ 0x2B, "reserved" },
	{ 0x2C, "HSN" },
	{ 0x2D, "reserved" },
	{ 0x2E, "MS RXLEV" },
	{ 0x2F, "MS TXLEV" },
	{ 0x30, "RXQUAL" },
	{ 0x31, "RX SENS" },
	{ 0x32, "Alarm block" },
	{ 0x33, "Neighbouring BCCH levels" },
	{ 0x34, "STM report type" },
	{ 0x35, "MA" },
	{ 0x36, "MAIO" },
	{ 0x37, "H_FLAG" },
	{ 0x38, "TCH_ARFN" },
	{ 0x39, "Clock output" },
	{ 0x3A, "Transmitted power" },
	{ 0x3B, "Clock sync" },
	{ 0x3C, "TMS protocol discriminator" },
	{ 0x3D, "TMS protocol data" },
	{ 0x3E, "FER" },
	{ 0x3F, "SWR result" },
	{ 0x40, "Object identity" },
	{ 0x41, "STM RX Antenna Test" },
	{ 0x42, "reserved" },
	{ 0x43, "reserved" },
	{ 0x44, "Object current state" },
	{ 0x45, "reserved" },
	{ 0x46, "FU channel configuration" },
	{ 0x47, "reserved" },
	{ 0x48, "ARFN of a CU" },
	{ 0x49, "FU radio definition" },
	{ 0x4A, "reserved" },
	{ 0x4B, "Severity" },
	{ 0x4C, "Diversity selection" },
	{ 0x4D, "RX antenna test" },
	{ 0x4E, "RX antenna supervision period" },
	{ 0x4F, "RX antenna state" },
	{ 0x50, "Sector configuration" },
	{ 0x51, "Additional info" },
	{ 0x52, "SWR parameters" },
	{ 0x53, "HW inquiry mode" },
	{ 0x54, "reserved" },
	{ 0x55, "Availability status" },
	{ 0x56, "reserved" },
	{ 0x57, "EAC inputs" },
	{ 0x58, "EAC outputs" },
	{ 0x59, "reserved" },
	{ 0x5A, "Position" },
	{ 0x5B, "HW unit identity" },
	{ 0x5C, "RF test signal attenuation" },
	{ 0x5D, "Operational state" },
	{ 0x5E, "Logical object identity" },
	{ 0x5F, "reserved" },
	{ 0x60, "BS_TXPWR_OM" },
	{ 0x61, "Loop_Duration" },
	{ 0x62, "LNA_Path_Selection" },
	{ 0x63, "Serial number" },
	{ 0x64, "HW version" },
	{ 0x65, "Obj. identity and obj. state" },
	{ 0x66, "reserved" },
	{ 0x67, "EAC input definition" },
	{ 0x68, "EAC id and text" },
	{ 0x69, "HW unit status" },
	{ 0x6A, "SW release version" },
	{ 0x6B, "FW version" },
	{ 0x6C, "Bit_Error_Ratio" },
	{ 0x6D, "RXLEV_with_Attenuation" },
	{ 0x6E, "RXLEV_without_Attenuation" },
	{ 0x6F, "reserved" },
	{ 0x70, "CU_Results" },
	{ 0x71, "reserved" },
	{ 0x72, "LNA_Path_Results" },
	{ 0x73, "RTE Results" },
	{ 0x74, "Real Time" },
	{ 0x75, "RX diversity selection" },
	{ 0x76, "EAC input config" },
	{ 0x77, "Feature support" },
	{ 0x78, "File version" },
	{ 0x79, "Outputs" },
	{ 0x7A, "FU parameters" },
	{ 0x7B, "Diagnostic info" },
	{ 0x7C, "FU BSIC" },
	{ 0x7D, "TRX Configuration" },
	{ 0x7E, "Download status" },
	{ 0x7F, "RX difference limit" },
	{ 0x80, "TRX HW capability" },
	{ 0x81, "Common HW config" },
	{ 0x82, "Autoconfiguration pool size" },
	{ 0x83, "TRE diagnostic info" },
	{ 0x84, "TRE object identity" },
	{ 0x85, "New TRE Info" },
	{ 0x86, "Acknowledgement period" },
	{ 0x87, "Synchronization mode" },
	{ 0x88, "reserved" },
	{ 0x89, "Block Control Data" },
	{ 0x8A, "SW load mode" },
	{ 0x8B, "Recommended recovery action" },
	{ 0x8C, "BSC BCF id" },
	{ 0x8D, "Q1 baud rate" },
	{ 0x8E, "Allocation status" },
	{ 0x8F, "Functional entity number" },
	{ 0x90, "Transmission delay" },
	{ 0x91, "Loop Duration ms" },
	{ 0x92, "Logical channel" },
	{ 0x93, "Q1 address" },
	{ 0x94, "Alarm detail" },
	{ 0x95, "Cabinet type" },
	{ 0x96, "HW unit existence" },
	{ 0x97, "RF power parameters" },
	{ 0x98, "Message scenario" },
	{ 0x99, "HW unit max amount" },
	{ 0x9A, "Master TRX" },
	{ 0x9B, "Transparent data" },
	{ 0x9C, "BSC topology info" },
	{ 0x9D, "Air i/f modulation" },
	{ 0x9E, "LCS Q1 command data" },
	{ 0x9F, "Frame number offset" },
	{ 0xA0, "Abis TSL" },
	{ 0xA1, "Dynamic pool info" },
	{ 0xA2, "LCS LLP data" },
	{ 0xA3, "LCS Q1 answer data" },
	{ 0xA4, "DFCA FU Radio Definition" },
	{ 0xA5, "Antenna hopping" },
	{ 0xA6, "Field record sequence number" },
	{ 0xA7, "Timeslot offslot" },
	{ 0xA8, "EPCR capability" },
	{ 0xA9, "Connectsite optional element" },
	{ 0xAA, "TSC" },
	{ 0xAB, "Special TX Power Setting" },
	{ 0xAC, "Optional sync settings" },
	{ 0xAD, "STIRC Option Setting" },
	{ 0xAE, "Rx Difference Samples Count" },
	{ 0xAF, "BTS Object Mapping" },
	{ 0xB0, "Abis Mapping" },
	{ 0xB1, "LAPDm T200 Values" },
	{ 0xB2, "DTRX info" },
	{ 0xB3, "Link and Counters" },
	{ 0xB4, "TRS and BTS licensing" },
	{ 0xB5, "TRX DDU association" },
	{ 0xB6, "Power control reason" },
	{ 0xB7, "CSDAP" },
	{ 0xB8, "BS2 parameters" },
	{ 0xB9, "BSC parameters" },
	{ 0xBA, "BTS parameters" },
	{ 0xBB, "TRX parameters" },
	{ 0xBC, "HO parameters" },
	{ 0xBD, "POC parameters" },
	{ 0xBE, "ADJC parameters" },
	{ 0xBF, "ADJC object" },
	{ 0xC0, "UADJC parameters" },
	{ 0xC1, "UADJC object" },
	{ 0xC2, "BTS PCM id" },
	{ 0xC3, "Segment Object id" },
	{ 0xC4, "Cell load parameters" },
	{ 0xC5, "Dynamic cell load info" },
	{ 0xC6, "BSC Release information" },
	{ 0xC7, "Complete data" },
	{ 0xC8, "OMUSIG PCM info" },
	{ 0xC9, "Line type" },
	{ 0xCA, "Concurrent OMUSIGs priorities" },
	{ 0xCB, "OMUSIG Priority" },
	{ 0xCC, "OSC support" },
	{ 0xCD, "CSDAP id" },
	{ 0xCE, "CSDAP parameters" },
	{ 0xCF, "Local Switching Counters" },
	{ 0xD0, "TX queue handling parameters" },
	{ 0xD1, "Valid History Records" },
	{ 0xD2, "Measurement Operation Status" },
	{ 0xD3, "Abis Delay Counters" },
	{ 0xD4, "Abis Measurement channel" },
	{ 0xD5, "Packet Abis BCF group configuration" },
	{ 0xD6, "Traffic to DSCP mapping" },
	{ 0xD7, "UL Shaping parameters" },
	{ 0xD8, "Traffic scheduling" },
	{ 0xD9, "Random Fill Bits usage" },
	{ 0xDA, "Packet Abis BCF group id" },
	{ 0xDB, "UDP" },
	{ 0xDC, "Backhaul utilization monitor parameters" },
	{ 0xDD, "Packet loss monitor parameters" },
	{ 0xDE, "Congestion control" },
	{ 0xDF, "Congestion reaction hysteresis parameters" },
	{ 0xE0, "Multiplexing parameters" },
	{ 0xE1, "IP addresses" },
	{ 0xE2, "TRX feature capability" },
	{ 0xE3, "Packet Abis If configuration" },
	{ 0xE4, "BTS IPv4 address C/U-plane" },
	{ 0xE5, "IPv4 address" },
	{ 0xE6, "Subnet mask" },
	{ 0xE7, "BSC IPv4 address C-plane" },
	{ 0xE8, "BSC IPv4 address CS U-plane" },
	{ 0xE9, "BSC IPv4 address PS U-plane" },
	{ 0xEA, "MC-PPP class map" },
	{ 0xEB, "SCTP parameters" },
	{ 0xEC, "Packet Abis mapping" },
	{ 0xED, "Sig ID" },
	{ 0xEE, "Packet Abis mapping" },
	{ 0xEF, "Measurement Request Type" },
	{ 0xF0, "Peer BTS info" },
	{ 0xF1, "Packet Abis Counters" },
	{ 0xF2, "Waiting time for BSC restarting" },
	{ 0xF3, "Peer BCF ID" },
	{ 0xF4, "TRX starting mode" },
	{ 0xF5, "GSM-R configuration" },
	{ 0xF6, "DSCP to VLAN priority mapping" },
	{ 0xF7, "TRX Assosiation" },
	{ 0xF8, "Power Finetuning" },
	{ 0xF9, "Abis Delay Measurement UDP port" },
	{ 0xFA, "Abis If parameters" },
	{ 0xFB, "PDV" },
	{ 0xFC, "Horizon BTS parameters" },
	{ 0xFD, "reserved" },
	{ 0xFE, "Radio Module SW" },
	{ 0, NULL }
};

static const char *get_element_name_string(uint16_t element)
{
	return get_value_string(nokia_element_name, element);
}

static const struct value_string nokia_bts_types[] = {
	{ 0x0a, 	"MetroSite GSM 900" },
	{ 0x0b,		"MetroSite GSM 1800" },
	{ 0x0c,		"MetroSite GSM 1900 (PCS)" },
	{ 0x0d,		"MetroSite GSM 900 & 1800" },
	{ 0x0e,		"InSite GSM 900" },
	{ 0x0f,		"InSite GSM 1800" },
	{ 0x10,		"InSite GSM 1900" },
	{ 0x11,		"UltraSite GSM 900" },
	{ 0x12,		"UltraSite GSM 1800" },
	{ 0x13,		"UltraSite GSM/US-TDMA 1900" },
	{ 0x14,		"UltraSite GSM 900 & 1800" },
	{ 0x16,		"UltraSite GSM/US-TDMA 850" },
	{ 0x18,		"MetroSite GSM/US-TDMA 850" },
	{ 0x19,		"UltraSite GSM 800/1900" },
	{ 0, 		NULL }
};

static const char *get_bts_type_string(uint8_t type)
{
	return get_value_string(nokia_bts_types, type);
}

static const struct value_string nokia_severity[] = {
	{ 0,	"indeterminate" },
	{ 1,	"critical" },
	{ 2,	"major" },
	{ 3,	"minor" },
	{ 4,	"warning" },
	{ 0,	NULL }
};

static const char *get_severity_string(uint8_t severity)
{
	return get_value_string(nokia_severity, severity);
}

static const struct value_string nokia_reset_type[] = {
	{ 0,	"OMU reset" },			/* BTS is still able to carry traffic */
	{ 1,	"Site reset" },
	{ 2,	"Reserved" },
	{ 3,	"Autoconfiguration site reset" },
	{ 4,	"MetroSite VTGA reset" },
	{ 5,	"Total reset" },		/* Complete reset of Packet Abis BTS and Conversion Function reset */
	{ 0,	NULL }
};

static const char *get_reset_type_string(uint8_t reset_type)
{
	return get_value_string(nokia_reset_type, reset_type);
}

static const struct value_string nokia_object_identity[] = {
	{ 0x01,		"BCF" },		/* Base Control Function */
	{ 0x02,		"OMU" },		/* Operation and Maintenance Unit */
	{ 0x04,		"TRX" },		/* Transceiver (FU + CU) */
	{ 0x05,		"BTS" },		/* Base Transceiver Station (1..248) */
	{ 0x07,		"FU" },			/* Frame Unit */
	{ 0x08,		"CU" },			/* Carrier Unit */
	{ 0x10,		"TRE" },		/* Transmission Equipment (0..15) */
	{ 0x11,		"TRU" },		/* Transmission Unit */
	{ 0x13,		"RTSL" },		/* Radio Timeslot of a FU (0..7) */
	{ 0x14,		"DMR" },		/* Digital Microwave Radio Link */
	{ 0x15,		"CF" },			/* Conversion Function */
	{ 0x64,		"RTC" },		/* Remote Tune Combiner */
	{ 0,	NULL }
};

static const char *get_object_identity_string(uint16_t object_identity)
{
	return get_value_string(nokia_object_identity, object_identity);
}

static const struct value_string nokia_object_state[] = {
	{ 0x0,		"Enabled" },
	{ 0x1,		"Disabled" },
	{ 0x2,		"Locked" },
	{ 0x3,		"Unlocked" },
	{ 0x4,		"Shutdown" },		/* reserved for BTS MMI use */
	{ 0x5,		"Powersave" },		/* reserved for BTS MMI use */
	{ 0,	NULL }
};

static const char *get_object_state_string(uint8_t object_state)
{
	return get_value_string(nokia_object_state, object_state);
}

/* TODO: put in a separate file ? */

/* some message IDs */

#define NOKIA_MSG_CONF_DATA             128
#define NOKIA_MSG_ACK                   129
#define NOKIA_MSG_OMU_STARTED           130
#define NOKIA_MSG_START_DOWNLOAD_REQ    131
#define NOKIA_MSG_MF_REQ                132
#define NOKIA_MSG_RESET_REQ             134
#define NOKIA_MSG_CONF_REQ              136
#define NOKIA_MSG_CONF_COMPLETE         142
#define NOKIA_MSG_BLOCK_CTRL_REQ        168
#define NOKIA_MSG_STATE_CHANGED         172
#define NOKIA_MSG_ALARM                 174
#define NOKIA_MSG_CHA_ADM_STATE         175

/* some element IDs */

#define NOKIA_EI_BTS_TYPE       0x13
#define NOKIA_EI_ACK            0x23
#define NOKIA_EI_ADD_INFO       0x51
#define NOKIA_EI_SEVERITY       0x4B
#define NOKIA_EI_ALARM_DETAIL   0x94
#define NOKIA_EI_RESET_TYPE     0x18
#define NOKIA_EI_OBJ_ID         0x40
#define NOKIA_EI_OBJ_STATE      0x44
#define NOKIA_EI_OBJ_ID_STATE   0x65

#define OM_ALLOC_SIZE       1024
#define OM_HEADROOM_SIZE    128

static uint8_t fu_config_template[] = {
	0x7F, 0x7A, 0x39,
	/* ID = 0x7A (FU parameters) ## constructed ## */
	/* length = 57 */
	/* [3] */

	0x5F, 0x40, 0x04,
	/* ID = 0x40 (Object identity) */
	/* length = 4 */
	/* [6] */
	0x00, 0x07, 0x01, 0xFF,

	0x41, 0x02,
	/* ID = 0x01 (Ny1) */
	/* length = 2 */
	/* [12] */
	0x00, 0x05,

	0x42, 0x02,
	/* ID = 0x02 (T3105_F) */
	/* length = 2 */
	/* [16] */
	0x00, 0x28, /* FIXME: use net->T3105 */

	0x50, 0x02,
	/* ID = 0x10 (T3105_D) */
	/* length = 2 */
	/* [20] */
	0x00, 0x28, /* FIXME: use net->T3105 */

	0x43, 0x05,
	/* ID = 0x03 (Interference band limits) */
	/* length = 5 */
	/* [24] */
	0x0F, 0x1B, 0x27, 0x33, 0x3F,

	0x44, 0x02,
	/* ID = 0x04 (Interference report timer in secs) */
	/* length = 2 */
	/* [31] */
	0x00, 0x10,

	0x47, 0x01,
	/* ID = 0x07 (RACH report timer in secs) */
	/* length = 1 */
	/* [35] */
	0x1E,

	0x4C, 0x10,
	/* ID = 0x0C (Cell allocation bitmap) ####### */
	/* length = 16 */
	/* [38] */
	0x8F, 0xB1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

	0x59, 0x01,
	/* ID = 0x19 (Averaging period) */
	/* length = 1 */
	/* [56] */
	0x01,

	0x5E, 0x01,
	/* ID = 0x1E ((RF max power reduction)) */
	/* length = 1 */
	/* [59] */
	0x00,

	0x7F, 0x46, 0x11,
	/* ID = 0x46 (FU channel configuration) ## constructed ## */
	/* length = 17 */
	/* [63] */

	0x5F, 0x40, 0x04,
	/* ID = 0x40 (Object identity) */
	/* length = 4 */
	/* [66] */
	0x00, 0x07, 0x01, 0xFF,

	0x45, 0x08,
	/* ID = 0x05 (Channel configuration per TS) */
	/* length = 8 */
	/* [72] */
	0x01, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09,

	0x7F, 0x65, 0x0B,
	/* ID = 0x65 (Obj. identity and obj. state) ## constructed ## */
	/* length = 11 */
	/* [83] */

	0x5F, 0x40, 0x04,
	/* ID = 0x40 (Object identity) */
	/* length = 4 */
	/* [86] */
	0x00, 0x04, 0x01, 0xFF,

	0x5F, 0x44, 0x01,
	/* ID = 0x44 (Object current state) */
	/* length = 1 */
	/* [93] */
	0x02,

	0x7F, 0x7C, 0x0A,
	/* ID = 0x7C (FU BSIC) ## constructed ## */
	/* length = 10 */
	/* [97] */

	0x5F, 0x40, 0x04,
	/* ID = 0x40 (Object identity) */
	/* length = 4 */
	/* [100] */
	0x00, 0x07, 0x01, 0xFF,

	0x46, 0x01,
	/* ID = 0x06 (BSIC) */
	/* length = 1 */
	/* [106] */
	0x00,

	0x7F, 0x48, 0x0B,
	/* ID = 0x48 (ARFN of a CU) ## constructed ## */
	/* length = 11 */
	/* [110] */

	0x5F, 0x40, 0x04,
	/* ID = 0x40 (Object identity) */
	/* length = 4 */
	/* [113] */
	0x00, 0x08, 0x01, 0xFF,

	0x4A, 0x02,
	/* ID = 0x0A (ARFN) ####### */
	/* length = 2 */
	/* [119] */
	0x03, 0x62,

	0x7F, 0x49, 0x59,
	/* ID = 0x49 (FU radio definition) ## constructed ## */
	/* length = 89 */
	/* [124] */

	0x5F, 0x40, 0x04,
	/* ID = 0x40 (Object identity) */
	/* length = 4 */
	/* [127] */
	0x00, 0x07, 0x01, 0xFF,

	0x4D, 0x50,
	/* ID = 0x0D (Radio definition per TS) ####### */
	/* length = 80 */
	/* [133] */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* MA */
	0x03, 0x62,		/* HSN, MAIO or ARFCN if no hopping */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x03, 0x62,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x03, 0x62,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x03, 0x62,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x03, 0x62,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x03, 0x62,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x03, 0x62,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x03, 0x62,
};

/* TODO: put in a separate file ? */

/*
  build the configuration for each TRX
*/

static int make_fu_config(struct gsm_bts_trx *trx, uint8_t id,
			  uint8_t * fu_config, int *hopping)
{
	int i;

	*hopping = 0;

	memcpy(fu_config, fu_config_template, sizeof(fu_config_template));

	/* set ID */

	fu_config[6 + 2] = id;
	fu_config[66 + 2] = id;
	fu_config[86 + 2] = id;
	fu_config[100 + 2] = id;
	fu_config[113 + 2] = id;
	fu_config[127 + 2] = id;

	/* set ARFCN */

	uint16_t arfcn = trx->arfcn;

	fu_config[119] = arfcn >> 8;
	fu_config[119 + 1] = arfcn & 0xFF;

	for (i = 0; i < ARRAY_SIZE(trx->ts); i++) {
		struct gsm_bts_trx_ts *ts = &trx->ts[i];

		if (ts->hopping.enabled) {
			/* reverse order */
			int j;
			for (j = 0; j < ts->hopping.ma_len; j++)
				fu_config[133 + (i * 10) + (7 - j)] =
				    ts->hopping.ma_data[j];
			fu_config[133 + 8 + (i * 10)] = ts->hopping.hsn;
			fu_config[133 + 8 + 1 + (i * 10)] = ts->hopping.maio;
			*hopping = 1;
		} else {
			fu_config[133 + 8 + (i * 10)] = arfcn >> 8;
			fu_config[133 + 8 + 1 + (i * 10)] = arfcn & 0xFF;
		}
	}

	/* set BSIC */

	/*
	   Attention: all TRX except the first one seem to get the TSC
	   from the CHANNEL ACTIVATION command (in CHANNEL IDENTIFICATION,
	   GSM 04.08 CHANNEL DESCRIPTION).
	   There was a bug in rsl_chan_activate_lchan() setting this parameter.
	 */

	uint8_t bsic = trx->bts->bsic;

	fu_config[106] = bsic;

	/* set CA */

	if (generate_cell_chan_list(&fu_config[38], trx->bts) != 0) {
		LOG_TRX(trx, DNM, LOGL_ERROR, "generate_cell_chan_list failed\n");
		return 0;
	}

	/* set channel configuration */

	for (i = 0; i < ARRAY_SIZE(trx->ts); i++) {
		struct gsm_bts_trx_ts *ts = &trx->ts[i];
		uint8_t chan_config;

		/*
		   0 = FCCH + SCH + BCCH + CCCH
		   1 = FCCH + SCH + BCCH + CCCH + SDCCH/4 + SACCH/4
		   2 = BCCH + CCCH (This combination is not used in any BTS)
		   3 = FCCH + SCH + BCCH + CCCH + SDCCH/4 with SDCCH2 used as CBCH
		   4 = SDCCH/8 + SACCH/8
		   5 = SDCCH/8 with SDCCH2 used as CBCH
		   6 = TCH/F + FACCH/F + SACCH/F
		   7 = E-RACH (Talk family)
		   9 = Dual rate (capability for TCH/F and TCH/H)
		   10 = reserved for BTS internal use
		   11 = PBCCH + PCCCH + PDTCH + PACCH + PTCCH (can be used in GPRS release 2).
		   0xFF = spare TS
		 */

		switch (ts->pchan_from_config) {
		case GSM_PCHAN_NONE:
			chan_config = 0xFF;
			break;
		case GSM_PCHAN_CCCH:
			chan_config = 0;
			break;
		case GSM_PCHAN_CCCH_SDCCH4:
			chan_config = 1;
			break;
		case GSM_PCHAN_CCCH_SDCCH4_CBCH:
			chan_config = 3;
			break;
		case GSM_PCHAN_TCH_F:
			chan_config = 6;	/* 9 should work too */
			break;
		case GSM_PCHAN_TCH_H:
			chan_config = 9;
			break;
		case GSM_PCHAN_SDCCH8_SACCH8C:
			chan_config = 4;
			break;
		case GSM_PCHAN_SDCCH8_SACCH8C_CBCH:
			chan_config = 5;
			break;
		case GSM_PCHAN_PDCH:
			chan_config = 11;
			break;
		default:
			LOG_TRX(trx, DNM, LOGL_ERROR, "unsupported channel config %s for timeslot %d\n",
				gsm_pchan_name(ts->pchan_from_config), i);
			return 0;
		}

		fu_config[72 + i] = chan_config;
	}
	return sizeof(fu_config_template);
}

/* TODO: put in a separate file ? */

static uint8_t bts_config_1[] = {
	0x4E, 0x02,
	/* ID = 0x0E (Frame number) */
	/* length = 2 */
	/* [2] */
	0xFF, 0xFF,

	0x5F, 0x4E, 0x02,
	/* ID = 0x4E (RX antenna supervision period) */
	/* length = 2 */
	/* [7] */
	0xFF, 0xFF,

	0x5F, 0x50, 0x02,
	/* ID = 0x50 (Sector configuration) */
	/* length = 2 */
	/* [12] */
	0x01, 0x01,
};

static uint8_t bts_config_2[] = {
	0x55, 0x02,
	/* ID = 0x15 (Hopping mode) */
	/* length = 2 */
	/* [2] */
	0x01, 0x00,

	0x5F, 0x75, 0x02,
	/* ID = 0x75 (RX diversity selection) */
	/* length = 2 */
	/* [7] */
	0x01, 0x01,
};

static uint8_t bts_config_3[] = {
	0x5F, 0x20, 0x02,
	/* ID = 0x20 (Extended cell radius) */
	/* length = 2 */
	/* [3] */
	0x01, 0x00,
};

static uint8_t bts_config_4[] = {
	0x5F, 0x74, 0x09,
	/* ID = 0x74 (Real Time) */
	/* length = 9 */
	/* [3] year-high, year-low, month, day, hour, minute, second, msec-high, msec-low */
	0x07, 0xDB, 0x06, 0x02, 0x0B, 0x20, 0x0C, 0x00,
	0x00,

	0x5F, 0x76, 0x03,
	/* ID = 0x76 (EAC input config) */
	/* length = 3 */
	/* [15] */
	0x01, 0x01, 0x00,

	0x5F, 0x76, 0x03,
	/* ID = 0x76 (EAC input config) */
	/* length = 3 */
	/* [21] */
	0x02, 0x01, 0x00,

	0x5F, 0x76, 0x03,
	/* ID = 0x76 (EAC input config) */
	/* length = 3 */
	/* [27] */
	0x03, 0x01, 0x00,

	0x5F, 0x76, 0x03,
	/* ID = 0x76 (EAC input config) */
	/* length = 3 */
	/* [33] */
	0x04, 0x01, 0x00,

	0x5F, 0x76, 0x03,
	/* ID = 0x76 (EAC input config) */
	/* length = 3 */
	/* [39] */
	0x05, 0x01, 0x00,

	0x5F, 0x76, 0x03,
	/* ID = 0x76 (EAC input config) */
	/* length = 3 */
	/* [45] */
	0x06, 0x01, 0x00,

	0x5F, 0x76, 0x03,
	/* ID = 0x76 (EAC input config) */
	/* length = 3 */
	/* [51] */
	0x07, 0x01, 0x00,

	0x5F, 0x76, 0x03,
	/* ID = 0x76 (EAC input config) */
	/* length = 3 */
	/* [57] */
	0x08, 0x01, 0x00,

	0x5F, 0x76, 0x03,
	/* ID = 0x76 (EAC input config) */
	/* length = 3 */
	/* [63] */
	0x09, 0x01, 0x00,

	0x5F, 0x76, 0x03,
	/* ID = 0x76 (EAC input config) */
	/* length = 3 */
	/* [69] */
	0x0A, 0x01, 0x00,
};

static uint8_t bts_config_insite[] = {
	0x4E, 0x02,
	/* ID = 0x0E (Frame number) */
	/* length = 2 */
	/* [2] */
	0xFF, 0xFF,

	0x5F, 0x4E, 0x02,
	/* ID = 0x4E (RX antenna supervision period) */
	/* length = 2 */
	/* [7] */
	0xFF, 0xFF,

	0x5F, 0x50, 0x02,
	/* ID = 0x50 (Sector configuration) */
	/* length = 2 */
	/* [12] */
	0x01, 0x01,

	0x55, 0x02,
	/* ID = 0x15 (Hopping mode) */
	/* length = 2 */
	/* [16] */
	0x01, 0x00,

	0x5F, 0x20, 0x02,
	/* ID = 0x20 (Extended cell radius) */
	/* length = 2 */
	/* [21] */
	0x01, 0x00,

	0x5F, 0x74, 0x09,
	/* ID = 0x74 (Real Time) */
	/* length = 9 */
	/* [26] */
	0x07, 0xDB, 0x07, 0x0A, 0x0F, 0x09, 0x0B, 0x00,
	0x00,
};

void set_real_time(uint8_t * real_time)
{
	time_t t;
	struct tm *tm;

	t = time(NULL);
	tm = localtime(&t);

	/* year-high, year-low, month, day, hour, minute, second, msec-high, msec-low */

	real_time[0] = (1900 + tm->tm_year) >> 8;
	real_time[1] = (1900 + tm->tm_year) & 0xFF;
	real_time[2] = tm->tm_mon + 1;
	real_time[3] = tm->tm_mday;
	real_time[4] = tm->tm_hour;
	real_time[5] = tm->tm_min;
	real_time[6] = tm->tm_sec;
	real_time[7] = 0;
	real_time[8] = 0;
}

/* TODO: put in a separate file ? */

/*
  build the configuration data
*/

static int make_bts_config(struct gsm_bts *bts, uint8_t bts_type, int n_trx, uint8_t * fu_config,
			   int need_hopping, int hopping_type)
{
	/* is it an InSite BTS ? */
	if (bts_type == 0x0E || bts_type == 0x0F || bts_type == 0x10) {	/* TODO */
		if (n_trx != 1) {
			LOG_BTS(bts, DNM, LOGL_ERROR, "InSite has only one TRX\n");
			return 0;
		}
		if (need_hopping != 0) {
			LOG_BTS(bts, DNM, LOGL_ERROR, "InSite does not support hopping\n");
			return 0;
		}
		memcpy(fu_config, bts_config_insite, sizeof(bts_config_insite));
		set_real_time(&fu_config[26]);
		return sizeof(bts_config_insite);
	}

	int len = 0;
	int i;

	memcpy(fu_config + len, bts_config_1, sizeof(bts_config_1));

	/* set sector configuration */
	fu_config[len + 12 - 1] = 1 + n_trx;	/* len */
	for (i = 0; i < n_trx; i++)
		fu_config[len + 12 + 1 + i] = ((i + 1) & 0xFF);

	len += (sizeof(bts_config_1) + (n_trx - 1));

	memcpy(fu_config + len, bts_config_2, sizeof(bts_config_2));
	/* set hopping mode */
	if (need_hopping) {
		switch (hopping_type) {
		/* 0: no hopping, 1: Baseband hopping, 2: RF hopping */
		case 0:
			LOG_BTS(bts, DNM, LOGL_INFO, "Baseband hopping selected!\n");
			fu_config[len + 2 + 1] = 1;
			break;
		case 1:
			LOG_BTS(bts, DNM, LOGL_INFO, "Synthesizer (RF) hopping selected!\n");
			fu_config[len + 2 + 1] = 2;
			break;
		default:
			LOG_BTS(bts, DNM, LOGL_INFO, "No hopping is selected!\n");
			fu_config[len + 2 + 1] = 0;
			break;
		}
	}
	len += sizeof(bts_config_2);

	/* set extended cell radius for each TRX */
	for (i = 0; i < n_trx; i++) {
		memcpy(fu_config + len, bts_config_3, sizeof(bts_config_3));
		fu_config[len + 3] = ((i + 1) & 0xFF);
		len += sizeof(bts_config_3);
	}

	memcpy(fu_config + len, bts_config_4, sizeof(bts_config_4));
	set_real_time(&fu_config[len + 3]);
	len += sizeof(bts_config_4);

	return len;
}

/* TODO: put in a separate file ? */

static struct msgb *nm_msgb_alloc(void)
{
	return msgb_alloc_headroom(OM_ALLOC_SIZE, OM_HEADROOM_SIZE, "OML");
}

/* TODO: put in a separate file ? */

struct abis_om_nokia_hdr {
	uint8_t msg_type;
	uint8_t spare;
	uint16_t reference;
	uint8_t data[0];
} __attribute__ ((packed));

#define ABIS_OM_NOKIA_HDR_SIZE (sizeof(struct abis_om_hdr) + sizeof(struct abis_om_nokia_hdr))

static int abis_nm_send(struct gsm_bts *bts, uint8_t msg_type, uint16_t ref,
			uint8_t * data, int len_data)
{
	struct abis_om_hdr *oh;
	struct abis_om_nokia_hdr *noh;
	struct msgb *msg = nm_msgb_alloc();

	oh = (struct abis_om_hdr *)msgb_put(msg,
					    ABIS_OM_NOKIA_HDR_SIZE + len_data);

	oh->mdisc = ABIS_OM_MDISC_FOM;
	oh->placement = ABIS_OM_PLACEMENT_ONLY;
	oh->sequence = 0;
	oh->length = sizeof(struct abis_om_nokia_hdr) + len_data;

	noh = (struct abis_om_nokia_hdr *)oh->data;

	noh->msg_type = msg_type;
	noh->spare = 0;
	noh->reference = htons(ref);
	memcpy(noh->data, data, len_data);

	LOG_BTS(bts, DNM, LOGL_DEBUG, "Sending %s\n", get_msg_type_name_string(msg_type));

	return abis_nm_sendmsg(bts, msg);
}

/* TODO: put in a separate file ? */

static uint8_t download_req[] = {
	0x5F, 0x25, 0x0B,
	/* ID = 0x25 (File identity) */
	/* length = 11 */
	/* [3] */
	0x2A, 0x2A, 0x2A, 0x2A, 0x2A, 0x2A, 0x2A, 0x2A,
	0x2A, 0x2A, 0x2A,

	0x5F, 0x78, 0x03,
	/* ID = 0x78 (File version) */
	/* length = 3 */
	/* [17] */
	0x2A, 0x2A, 0x2A,

	0x5F, 0x81, 0x0A, 0x01,
	/* ID = 0x8A (SW load mode) */
	/* length = 1 */
	/* [24] */
	0x01,

	0x5F, 0x81, 0x06, 0x01,
	/* ID = 0x86 (Acknowledgement period) */
	/* length = 1 */
	/* [29] */
	0x01,
};

static int abis_nm_download_req(struct gsm_bts *bts, uint16_t ref)
{
	uint8_t *data = download_req;
	int len_data = sizeof(download_req);

	return abis_nm_send(bts, NOKIA_MSG_START_DOWNLOAD_REQ, ref, data,
			    len_data);
}

/* TODO: put in a separate file ? */

static uint8_t ack[] = {
	0x5F, 0x23, 0x01,
	/* ID = 0x23 (Ack-Nack) */
	/* length = 1 */
	/* [3] */
	0x01,
};

static int abis_nm_ack(struct gsm_bts *bts, uint16_t ref)
{
	uint8_t *data = ack;
	int len_data = sizeof(ack);

	return abis_nm_send(bts, NOKIA_MSG_ACK, ref, data, len_data);
}

/* TODO: put in a separate file ? */

static uint8_t reset[] = {
	0x5F, 0x40, 0x04,
	/* ID = 0x40 (Object identity) */
	/* length = 4 */
	/* [3] */
	0x00, 0x01, 0xFF, 0xFF,
};

static int abis_nm_reset(struct gsm_bts *bts, uint16_t ref)
{
	uint8_t *data = reset;
	int len_data = sizeof(reset);
	LOG_BTS(bts, DLINP, LOGL_INFO, "Nokia BTS reset timer: %d\n", bts->nokia.bts_reset_timer_cnf);
	return abis_nm_send(bts, NOKIA_MSG_RESET_REQ, ref, data, len_data);
}

static uint8_t trx_unlock[] = {
	0x7F, 0x65, 0x0B,
	/* ID = 0x65 (Obj. identity and obj. state) ## constructed ## */
	/* length = 11 */
	/* [83] */

	0x5F, 0x40, 0x04,
	/* ID = 0x40 (Object identity) */
	/* length = 4 */
	/* [86] */
	0x00, 0x04, 0x01, 0xFF,

	0x5F, 0x44, 0x01,
	/* ID = 0x44 (Object current state) */
	/* length = 1 */
	/* [93] */
	0x03,
};

static int abis_nm_cha_adm_trx_unlock(struct gsm_bts *bts, uint8_t trx_id, uint16_t ref)
{
	/* BTS_CHA_ADM_STATE */
	/* object_identity = TRX; object_state = locked/unlocked */
	uint8_t *data = trx_unlock;
	data[8] = trx_id;
	int len_data = sizeof(trx_unlock);
	LOG_BTS(bts, DNM, LOGL_INFO, "TRX=%d Admin state change: UNLOCKED\n", trx_id);
	dump_elements(data, len_data);
	return abis_nm_send(bts, NOKIA_MSG_CHA_ADM_STATE, ref, data, len_data);
}

static uint8_t trx_reset[] = {
	0x5F, 0x40, 0x04,
	/* ID = 0x40 (Object identity) */
	/* length = 4 */
	/* [3] */
	0x00, 0x04, 0x01, 0xFF,
};

static int abis_nm_trx_reset(struct gsm_bts *bts, uint8_t trx_id, uint16_t ref)
{
	uint8_t *data = trx_reset;
	data[5] = trx_id;
	int len_data = sizeof(trx_reset);
	LOG_BTS(bts, DNM, LOGL_INFO, "TRX=%d Reset!\n", trx_id);
	dump_elements(data, len_data);
	return abis_nm_send(bts, NOKIA_MSG_RESET_REQ, ref, data, len_data);
}

/* TODO: put in a separate file ? */

static int abis_nm_send_multi_segments(struct gsm_bts *bts, uint8_t msg_type,
				       uint16_t ref, uint8_t * data, int len)
{
	int len_remain, len_to_send, max_send;
	int seq = 0;
	int ret;

	len_remain = len;

	while (len_remain) {
		struct abis_om_hdr *oh;
		struct abis_om_nokia_hdr *noh;
		struct msgb *msg = nm_msgb_alloc();

		if (seq == 0)
			max_send = 256 - sizeof(struct abis_om_nokia_hdr);
		else
			max_send = 256;

		if (len_remain > max_send) {
			len_to_send = max_send;

			if (seq == 0) {
				/* first segment */
				oh = (struct abis_om_hdr *)msgb_put(msg,
								    ABIS_OM_NOKIA_HDR_SIZE
								    +
								    len_to_send);

				oh->mdisc = ABIS_OM_MDISC_FOM;
				oh->placement = ABIS_OM_PLACEMENT_FIRST;	/* first segment of multi-segment message */
				oh->sequence = seq;
				oh->length = 0;	/* 256 bytes */

				noh = (struct abis_om_nokia_hdr *)oh->data;

				noh->msg_type = msg_type;
				noh->spare = 0;
				noh->reference = htons(ref);
				memcpy(noh->data, data, len_to_send);
			} else {
				/* segment in between */
				oh = (struct abis_om_hdr *)msgb_put(msg,
								    sizeof
								    (struct
								     abis_om_hdr)
								    +
								    len_to_send);

				oh->mdisc = ABIS_OM_MDISC_FOM;
				oh->placement = ABIS_OM_PLACEMENT_MIDDLE;	/* segment of multi-segment message */
				oh->sequence = seq;
				oh->length = 0;	/* 256 bytes */

				memcpy(oh->data, data, len_to_send);
			}
		} else {

			len_to_send = len_remain;

			/* check if message fits in a single segment */

			if (seq == 0)
				return abis_nm_send(bts, msg_type, ref, data,
						    len_to_send);

			/* last segment */

			oh = (struct abis_om_hdr *)msgb_put(msg,
							    sizeof(struct
								   abis_om_hdr)
							    + len_to_send);

			oh->mdisc = ABIS_OM_MDISC_FOM;
			oh->placement = ABIS_OM_PLACEMENT_LAST;	/* last segment of multi-segment message */
			oh->sequence = seq;
			oh->length = len_to_send;

			memcpy(oh->data, data, len_to_send);
		}

		LOG_BTS(bts, DNM, LOGL_DEBUG, "Sending multi-segment %d\n", seq);

		ret = abis_nm_sendmsg(bts, msg);
		if (ret < 0)
			return ret;

		nokia_abis_nm_queue_send_next(bts);

		/* next segment */
		len_remain -= len_to_send;
		data += len_to_send;
		seq++;
	}

	return 0;
}

/* TODO: put in a separate file ? */

static int abis_nm_send_config(struct gsm_bts *bts, uint8_t bts_type)
{
	struct gsm_bts_trx *trx;
	uint8_t config[2048];	/* TODO: might be too small if lots of TRX are used */
	int len = 0;
	int idx = 0;
	int ret;
	int hopping = 0;
	int need_hopping = 0;
	int hopping_type = 0;

	hopping_type = bts->nokia.hopping_mode;

	memset(config, 0, sizeof(config));

	llist_for_each_entry(trx, &bts->trx_list, list) {
#if 0				/* debugging */
		printf("TRX\n");
		printf("  arfcn: %d\n", trx->arfcn);
		printf("  bsic: %d\n", trx->bts->bsic);
		uint8_t ca[20];
		memset(ca, 0xFF, sizeof(ca));
		ret = generate_cell_chan_list(ca, trx->bts);
		printf("  ca (%d): %s\n", ret, osmo_hexdump(ca, sizeof(ca)));
		int i;
		for (i = 0; i < ARRAY_SIZE(trx->ts); i++) {
			struct gsm_bts_trx_ts *ts = &trx->ts[i];

			printf("  pchan %d: %d\n", i, ts->pchan);
		}
#endif
		ret = make_fu_config(trx, idx + 1, config + len, &hopping);
		need_hopping |= hopping;
		len += ret;

		idx++;
	}

	ret = make_bts_config(bts, bts_type, idx, config + len, need_hopping, hopping_type);
	len += ret;

#if 0				/* debugging */
	dump_elements(config, len);
#endif

	return abis_nm_send_multi_segments(bts, NOKIA_MSG_CONF_DATA, 1, config,
					   len);
}

#define GET_NEXT_BYTE if(idx >= len) return 0; \
                        ub = data[idx++];

static int find_element(uint8_t * data, int len, uint16_t id, uint8_t * value,
			int max_value)
{
	uint8_t ub;
	int idx = 0;
	int found = 0;
	int constructed __attribute__((unused));
	uint16_t id_value;

	for (;;) {

		GET_NEXT_BYTE;

		/* encoding bit, constructed means that other elements are contained */
		constructed = ((ub & 0x20) ? 1 : 0);

		if ((ub & 0x1F) == 0x1F) {
			/* fixed pattern, ID follows */
			GET_NEXT_BYTE;	/* ID */
			id_value = ub & 0x7F;
			if (ub & 0x80) {
				/* extension bit */
				GET_NEXT_BYTE;	/* ID low part */
				id_value = (id_value << 7) | (ub & 0x7F);
			}
			if (id_value == id)
				found = 1;
		} else {
			id_value = (ub & 0x3F);
			if (id_value == id)
				found = 1;
		}

		GET_NEXT_BYTE;	/* length */

		if (found) {
			/* get data */
			uint8_t n = ub;
			uint8_t i;
			for (i = 0; i < n; i++) {
				GET_NEXT_BYTE;
				if (max_value <= 0)
					return -1;	/* buffer too small */
				*value = ub;
				value++;
				max_value--;
			}
			return n;	/* length */
		} else {
			/* skip data */
			uint8_t n = ub;
			uint8_t i;
			for (i = 0; i < n; i++) {
				GET_NEXT_BYTE;
			}
		}
	}
	return 0;		/* not found */
}

static int dump_elements(uint8_t * data, int len)
{
	uint8_t ub;
	int idx = 0;
	int constructed;
	uint16_t id_value;
	static char indent[100] = "";	/* TODO: move static to BTS context */

	for (;;) {

		GET_NEXT_BYTE;

		/* encoding bit, constructed means that other elements are contained */
		constructed = ((ub & 0x20) ? 1 : 0);

		if ((ub & 0x1F) == 0x1F) {
			/* fixed pattern, ID follows */
			GET_NEXT_BYTE;	/* ID */
			id_value = ub & 0x7F;
			if (ub & 0x80) {
				/* extension bit */
				GET_NEXT_BYTE;	/* ID low part */
				id_value = (id_value << 7) | (ub & 0x7F);
			}

		} else {
			id_value = (ub & 0x3F);
		}

		GET_NEXT_BYTE;	/* length */

		printf("%s--ID = 0x%02X (%s) %s\n", indent, id_value,
		       get_element_name_string(id_value),
		       constructed ? "** constructed **" : "");
		printf("%s  length = %d\n", indent, ub);
		printf("%s  %s\n", indent, osmo_hexdump(data + idx, ub));

		if (constructed) {
			int indent_len = strlen(indent);
			strcat(indent, "   ");

			dump_elements(data + idx, ub);

			indent[indent_len] = 0;
		}
		/* skip data */
		uint8_t n = ub;
		uint8_t i;
		for (i = 0; i < n; i++) {
			GET_NEXT_BYTE;
		}
	}
	return 0;
}

static void mo_ok(struct gsm_abis_mo *mo)
{
	mo->nm_state.operational    = NM_OPSTATE_ENABLED;
	mo->nm_state.administrative = NM_STATE_UNLOCKED;
	mo->nm_state.availability   = NM_AVSTATE_OK;
}

static void nokia_abis_nm_fake_1221_ok(struct gsm_bts *bts)
{
	/*
	 * The Nokia BTS don't follow the 12.21 model and we don't have OM objects
	 * for the various elements. However some of the BSC code depends on seeing
	 * those object "up & running", so when the Nokia init is done, we fake
	 * a "good" state
	 */
	struct gsm_bts_trx *trx;

	mo_ok(&bts->mo);
	mo_ok(&bts->site_mgr->mo);

	llist_for_each_entry(trx, &bts->trx_list, list) {
		int i;

		mo_ok(&trx->mo);
		mo_ok(&trx->bb_transc.mo);

		for (i = 0; i < ARRAY_SIZE(trx->ts); i++) {
			struct gsm_bts_trx_ts *ts = &trx->ts[i];
			mo_ok(&ts->mo);
		}
	}
}

/* TODO: put in a separate file ? */

/* taken from abis_nm.c */

static void nokia_abis_nm_queue_send_next(struct gsm_bts *bts)
{
	int wait = 0;
	struct msgb *msg;
	/* the queue is empty */
	while (!llist_empty(&bts->abis_queue)) {
		msg = msgb_dequeue(&bts->abis_queue);
		wait = OBSC_NM_W_ACK_CB(msg);
		abis_sendmsg(msg);

		if (wait)
			break;
	}

	bts->abis_nm_pend = wait;
}

/* TODO: put in a separate file ? */

/* timer for restarting OML after BTS reset */

static void reset_timer_cb(void *_bts)
{
	struct gsm_bts *bts = _bts;
	struct gsm_e1_subslot *e1_link = &bts->oml_e1_link;
	struct e1inp_line *line;

	/* OML link */
	line = e1inp_line_find(e1_link->e1_nr);
	if (!line) {
		LOG_BTS(bts, DLINP, LOGL_ERROR, "BTS OML link referring to non-existing E1 line %u\n",
			e1_link->e1_nr);
		return;
	}

	switch (bts->nokia.wait_reset) {
	case RESET_T_NONE:				/* shouldn't happen */
		break;
	case RESET_T_STOP_LAPD:
		start_sabm_in_line(line, 0, -1);	/* stop all first */
		bts->nokia.wait_reset = RESET_T_RESTART_LAPD;
		osmo_timer_schedule(&bts->nokia.reset_timer, bts->nokia.bts_reset_timer_cnf, 0);
		break;
	case RESET_T_RESTART_LAPD:
		bts->nokia.wait_reset = 0;
		start_sabm_in_line(line, 0, -1);	/* stop all first */
		start_sabm_in_line(line, 1, SAPI_OML);	/* start only OML */
		break;
	}
}

/* TODO: put in a separate file ? */

/*
  This is how the configuration is done:
  - start OML link
  - reset BTS
  - receive ACK, wait some time and restart OML link
  - receive OMU STARTED message, send START DOWNLOAD REQ
  - receive CNF REQ message, send CONF DATA
  - receive ACK, start RSL link(s)
  ACK some other messages received from the BTS.

  Probably its also possible to configure the BTS without a reset, this
  has not been tested yet.
*/

#define FIND_ELEM(data, data_len, ei, var, len) (find_element(data, data_len, ei, var, len) == len)
static int abis_nm_rcvmsg_fom(struct msgb *mb)
{
	struct e1inp_sign_link *sign_link = (struct e1inp_sign_link *)mb->dst;
	struct gsm_bts *bts = sign_link->trx->bts;
	struct abis_om_hdr *oh = msgb_l2(mb);
	struct abis_om_nokia_hdr *noh = msgb_l3(mb);
	uint8_t mt = noh->msg_type;
	int ret = 0;
	uint16_t ref = ntohs(noh->reference);
	uint8_t info[256];
	uint8_t ack = 0xFF;
	uint8_t severity = 0xFF;
	uint8_t reset_type = 0xFF;
	uint8_t object_identity[4] = {0};
	uint8_t object_state = 0xFF;
	uint8_t object_id_state[11] = {0};
	int severity_len = 0;
	int ei_add_info_len = 0;
	int ei_alarm_detail_len = 0;
	int len_data;


	if (bts->nokia.wait_reset) {
		LOG_BTS(bts, DNM, LOGL_INFO, "Ignoring message while waiting for reset: %s\n", msgb_hexdump(mb));
		return ret;
	}

	if (oh->length < sizeof(struct abis_om_nokia_hdr)) {
		LOG_BTS(bts, DNM, LOGL_ERROR, "Message too short: %s\n", msgb_hexdump(mb));
		return -EINVAL;
	}

	len_data = oh->length - sizeof(struct abis_om_nokia_hdr);
	LOG_BTS(bts, DNM, LOGL_INFO, "Rx (0x%02X) %s\n", mt, get_msg_type_name_string(mt));
#if 0				/* debugging */
	dump_elements(noh->data, len_data);
#endif

	switch (mt) {
	case NOKIA_MSG_OMU_STARTED:
		if (FIND_ELEM(noh->data, len_data, NOKIA_EI_BTS_TYPE, &bts->nokia.bts_type, sizeof(bts->nokia.bts_type))) {
			LOG_BTS(bts, DNM, LOGL_INFO, "Rx BTS type = %d (%s)\n",
				bts->nokia.bts_type,
				get_bts_type_string(bts->nokia.bts_type));
		} else {
			LOG_BTS(bts, DNM, LOGL_ERROR, "BTS type not found in NOKIA_MSG_OMU_STARTED\n");
		}
		if (FIND_ELEM(noh->data, len_data, NOKIA_EI_RESET_TYPE, &reset_type, sizeof(reset_type))) {
			LOG_BTS(bts, DNM, LOGL_INFO, "Rx BTS reset type = '%s'\n",
				get_reset_type_string(reset_type));
		} else {
			LOG_BTS(bts, DNM, LOGL_ERROR, "BTS reset type not found in NOKIA_MSG_OMU_STARTED\n");
		}
		/* send START_DOWNLOAD_REQ */
		abis_nm_download_req(bts, ref);
		break;
	case NOKIA_MSG_MF_REQ:
		break;
	case NOKIA_MSG_CONF_REQ:
		/* send ACK */
		abis_nm_ack(bts, ref);
		nokia_abis_nm_queue_send_next(bts);
		/* send CONF_DATA */
		abis_nm_send_config(bts, bts->nokia.bts_type);
		bts->nokia.configured = 1;
		break;
	case NOKIA_MSG_ACK:
		if (FIND_ELEM(noh->data, len_data, NOKIA_EI_ACK, &ack, sizeof(ack))) {
			LOG_BTS(bts, DNM, LOGL_INFO, "Rx ACK = %u\n", ack);
			if (ack != 1) {
				LOG_BTS(bts, DNM, LOGL_ERROR, "Rx No ACK (%u): don't know how to proceed\n", ack);
				/* TODO: properly handle failures (NACK) */
			}
		} else
			LOG_BTS(bts, DNM, LOGL_ERROR, "Rx MSG_ACK but no EI_ACK found: %s\n", msgb_hexdump(mb));

		/* TODO: the assumption for the following is that no NACK was received */

		/* ACK for reset message ? */
		if (!bts->nokia.did_reset) {
			bts->nokia.did_reset = 1;

			/*
			   TODO: For the InSite processing the received data is
			   blocked in the driver during reset.
			   Otherwise the LAPD module might assert because the InSite
			   sends garbage on the E1 line during reset.
			   This is done by looking at "wait_reset" in the driver
			   (function handle_ts1_read()) and ignoring the received data.
			   It seems to be necessary for the MetroSite too.
			 */

			/* we cannot delete / stop the OML LAPD SAP right here, as we are in
			 * the middle of processing an LAPD I frame and are subsequently returning
			 * back to the LAPD I frame processing code that assumes the SAP is still
			 * active. So we first schedule the timer at 0ms in the future, where we
			 * kill all LAPD SAP and re-arm the timer for the reset duration, after which
			 * we re-create them */
			bts->nokia.wait_reset = RESET_T_STOP_LAPD;
			osmo_timer_setup(&bts->nokia.reset_timer, reset_timer_cb, bts);
			osmo_timer_schedule(&bts->nokia.reset_timer, 0, 0);
		}
		break;
	case NOKIA_MSG_STATE_CHANGED:
		/* send ACK */
		abis_nm_ack(bts, ref);
		if (!FIND_ELEM(noh->data, len_data, NOKIA_EI_OBJ_ID_STATE, object_id_state, sizeof(object_id_state))) {
			LOG_BTS(bts, DNM, LOGL_NOTICE, "Missing NOKIA_EI_OBJ_ID_STATE\n");
			return -EINVAL;
		}
		LOG_BTS(bts, DNM, LOGL_NOTICE, "State changed: %s=%d, %s\n",
			get_object_identity_string(object_id_state[4]),
			object_id_state[5],
			get_object_state_string(object_id_state[10]));
		break;
	case NOKIA_MSG_CONF_COMPLETE:
		/* send ACK */
		abis_nm_ack(bts, ref);
		if (bts->nokia.configured != 0) {
			struct gsm_bts_trx *trx;
			uint8_t bcch_trx_nr;
			/* we first need to unlock and reset the TRX that runs BCCH */
			llist_for_each_entry(trx, &bts->trx_list, list) {
				if (trx->ts[0].pchan_from_config == GSM_PCHAN_CCCH ||
				    trx->ts[0].pchan_from_config == GSM_PCHAN_CCCH_SDCCH4 ||
				    trx->ts[0].pchan_from_config == GSM_PCHAN_CCCH_SDCCH4_CBCH) {
					/* saving the number of TRX that has BCCH on it */
					bcch_trx_nr = trx->nr;
					/* unlock TRX */
					abis_nm_cha_adm_trx_unlock(bts, trx->nr+1, ref);
					/* reset TRX */
					abis_nm_trx_reset(bts, trx->nr+1, ref);
				}
			}
			/* now unlocking all other TRXs */
			llist_for_each_entry(trx, &bts->trx_list, list) {
				if (trx->nr != bcch_trx_nr) {
					/* unlock TRX */
					abis_nm_cha_adm_trx_unlock(bts, trx->nr+1, ref);
				}
			}
			/* start TRX  (RSL link) */
			struct gsm_e1_subslot *e1_link = &sign_link->trx->rsl_e1_link;
			struct e1inp_line *line;
			bts->nokia.configured = 0;
			/* RSL Link */
			line = e1inp_line_find(e1_link->e1_nr);
			if (!line) {
				LOG_BTS(bts, DLINP, LOGL_ERROR, "RSL link referring to "
					"non-existing E1 line %u\n", e1_link->e1_nr);
				return -ENOMEM;
			}
			/* start TRX */
			start_sabm_in_line(line, 1, SAPI_RSL);  /* start only RSL */
		}
		/* fake 12.21 OM */
		nokia_abis_nm_fake_1221_ok(bts);
		break;
	case NOKIA_MSG_BLOCK_CTRL_REQ:	/* BTS uses this scenario to block an object in BSC */
		/* TODO: implement block function */
		/* send ACK */
		abis_nm_ack(bts, ref);
		break;
	case NOKIA_MSG_ALARM:
		if (!FIND_ELEM(noh->data, len_data, NOKIA_EI_OBJ_ID, object_identity, sizeof(object_identity)) ||
		    !FIND_ELEM(noh->data, len_data, NOKIA_EI_OBJ_STATE, &object_state, sizeof(object_state))) {
			if (!FIND_ELEM(noh->data, len_data, NOKIA_EI_OBJ_ID_STATE, object_id_state, sizeof(object_id_state))) {
				LOG_BTS(bts, DNM, LOGL_NOTICE, "Missing NOKIA_EI_OBJ_ID & NOKIA_EI_OBJ_STATE or NOKIA_EI_OBJ_ID_STATE\n");
				return -EINVAL;
			}
			object_identity[1] = object_id_state[4];
			object_identity[2] = object_id_state[5];
			object_state = object_id_state[10];
		}
		severity_len = find_element(noh->data, len_data, NOKIA_EI_SEVERITY, &severity, sizeof(severity));
		/* Either Additional info or Alarm detail may be included at a time */
		ei_add_info_len = find_element(noh->data, len_data, NOKIA_EI_ADD_INFO, info, sizeof(info));
		if (ei_add_info_len > 0) {
			info[ei_add_info_len] = 0;
			if (severity_len > 0) {
				LOG_BTS(bts, DNM, LOGL_NOTICE, "Rx ALARM (%s=%d(%s)) Severity %s (%d) : %s\n",
					get_object_identity_string(object_identity[1]),
					object_identity[2],
					get_object_state_string(object_state),
					get_severity_string(severity),
					severity,
					info);
			} else {
				LOG_BTS(bts, DNM, LOGL_NOTICE, "Rx ALARM (%s=%d(%s)) : %s\n",
					get_object_identity_string(object_identity[1]),
					object_identity[2],
					get_object_state_string(object_state),
					info);
			}
		}
		/* nothing found, try details */
		ei_alarm_detail_len = find_element(noh->data, len_data, NOKIA_EI_ALARM_DETAIL, info, sizeof(info));
		if (ei_alarm_detail_len > 0) {
			uint16_t code;
			info[ei_alarm_detail_len] = 0;
			code = (info[0] << 8) + info[1];
			if (severity_len > 0) {
				LOG_BTS(bts, DNM, LOGL_NOTICE, "Rx ALARM (%s=%d(%s)) Severity %s (%d), code 0x%X : %s\n",
					get_object_identity_string(object_identity[1]),
					object_identity[2],
					get_object_state_string(object_state),
					get_severity_string(severity),
					severity,
					code,
					info + 2);
			} else {
				LOG_BTS(bts, DNM, LOGL_NOTICE, "Rx ALARM (%s=%d(%s)) : %s\n",
					get_object_identity_string(object_identity[1]),
					object_identity[2],
					get_object_state_string(object_state),
					info + 2);
			}
		}
		if (ei_add_info_len == 0 && ei_alarm_detail_len == 0) {
			LOG_BTS(bts, DNM, LOGL_NOTICE, "Rx ALARM (%s=%d(%s))\n",
				get_object_identity_string(object_identity[1]),
				object_identity[2],
				get_object_state_string(object_state));
		}
		/* send ACK */
		abis_nm_ack(bts, ref);
		break;
	}
	nokia_abis_nm_queue_send_next(bts);
	return ret;
}

/* TODO: put in a separate file ? */

int abis_nokia_rcvmsg(struct msgb *msg)
{
	struct e1inp_sign_link *sign_link = (struct e1inp_sign_link *)msg->dst;
	struct gsm_bts *bts = sign_link->trx->bts;
	struct abis_om_hdr *oh = msgb_l2(msg);
	int rc = 0;

	/* Various consistency checks */
	if (oh->placement != ABIS_OM_PLACEMENT_ONLY) {
		LOG_BTS(bts, DNM, LOGL_ERROR, "Rx ABIS OML placement 0x%x not supported\n", oh->placement);
		if (oh->placement != ABIS_OM_PLACEMENT_FIRST)
			return -EINVAL;
	}
	if (oh->sequence != 0) {
		LOG_BTS(bts, DNM, LOGL_ERROR, "Rx ABIS OML sequence 0x%x != 0x00\n", oh->sequence);
		return -EINVAL;
	}
	msg->l3h = (unsigned char *)oh + sizeof(*oh);

	switch (oh->mdisc) {
	case ABIS_OM_MDISC_FOM:
		LOG_BTS(bts, DNM, LOGL_INFO, "Rx ABIS_OM_MDISC_FOM\n");
		rc = abis_nm_rcvmsg_fom(msg);
		break;
	case ABIS_OM_MDISC_MANUF:
		LOG_BTS(bts, DNM, LOGL_INFO, "Rx ABIS_OM_MDISC_MANUF: ignoring\n");
		break;
	case ABIS_OM_MDISC_MMI:
	case ABIS_OM_MDISC_TRAU:
		LOG_BTS(bts, DNM, LOGL_ERROR, "Rx unimplemented ABIS OML message discriminator 0x%x\n", oh->mdisc);
		break;
	default:
		LOG_BTS(bts, DNM, LOGL_ERROR, "Rx unknown ABIS OML message discriminator 0x%x\n", oh->mdisc);
		return -EINVAL;
	}

	msgb_free(msg);
	return rc;
}

static int bts_model_nokia_site_start(struct gsm_network *net);

static void bts_model_nokia_site_e1line_bind_ops(struct e1inp_line *line)
{
	e1inp_line_bind_ops(line, &bts_isdn_e1inp_line_ops);
}

static struct gsm_bts_model model_nokia_site = {
	.type = GSM_BTS_TYPE_NOKIA_SITE,
	.name = "nokia_site",
	.start = bts_model_nokia_site_start,
	.oml_rcvmsg = &abis_nokia_rcvmsg,
	.e1line_bind_ops = &bts_model_nokia_site_e1line_bind_ops,
};

static struct gsm_network *my_net;

static int bts_model_nokia_site_start(struct gsm_network *net)
{
	osmo_signal_register_handler(SS_L_INPUT, inp_sig_cb, NULL);
	osmo_signal_register_handler(SS_L_GLOBAL, gbl_sig_cb, NULL);
	osmo_signal_register_handler(SS_NM, nm_sig_cb, NULL);

	my_net = net;

	return 0;
}

int bts_model_nokia_site_init(void)
{
	model_nokia_site.features.data = &model_nokia_site._features_data[0];
	model_nokia_site.features.data_len = sizeof(model_nokia_site._features_data);

	osmo_bts_set_feature(&model_nokia_site.features, BTS_FEAT_HOPPING);
	osmo_bts_set_feature(&model_nokia_site.features, BTS_FEAT_HSCSD);
	osmo_bts_set_feature(&model_nokia_site.features, BTS_FEAT_MULTI_TSC);

	return gsm_bts_model_register(&model_nokia_site);
}
