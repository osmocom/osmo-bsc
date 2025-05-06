/* Convert measurement report feed into JSON feed printed to stdout.
 * Each measurement report is printed as a separae JSON root entry.
 * All measurement reports are separated by a new line.
 */

/* (C) 2015 by Alexander Chemeris <Alexander.Chemeris@fairwaves.co>
 * With parts of code adopted from different places in OpenBSC.
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
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include <netinet/in.h>

#include <getopt.h>

#include <osmocom/core/socket.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/select.h>
#include <osmocom/core/application.h>

#include <osmocom/gsm/gsm_utils.h>

#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/meas_feed.h>

/* binding IP */
static char *bind_ip;

static void print_meas_rep_uni_json(struct gsm_meas_rep_unidir *mru)
{
	printf("\"RXL-FULL\":%d, \"RXL-SUB\":%d, ",
		rxlev2dbm(mru->full.rx_lev),
		rxlev2dbm(mru->sub.rx_lev));
	printf("\"RXQ-FULL\":%d, \"RXQ-SUB\":%d",
		mru->full.rx_qual, mru->sub.rx_qual);
}

static void print_meas_rep_json(struct gsm_meas_rep *mr)
{
	int i;

	printf("\"NR\":%d", mr->nr);

	if (mr->flags & MEAS_REP_F_DL_DTX)
		printf(", \"DTXd\":true");

	printf(", \"UL_MEAS\":{");
	print_meas_rep_uni_json(&mr->ul);
	printf("}");
	printf(", \"BS_POWER\":%d", mr->bs_power_db / 2);
	if (mr->flags & MEAS_REP_F_MS_TO)
		printf(", \"MS_TO\":%d", mr->ms_timing_offset);

	if (mr->flags & MEAS_REP_F_MS_L1) {
		printf(", \"L1_MS_PWR\":%d", mr->ms_l1.pwr);
		printf(", \"L1_FPC\":%s",
			mr->flags & MEAS_REP_F_FPC ? "true" : "false");
		printf(", \"L1_TA\":%u", mr->ms_l1.ta);
	}

	if (mr->flags & MEAS_REP_F_UL_DTX)
		printf(", \"DTXu\":true");
	if (mr->flags & MEAS_REP_F_BA1)
		printf(", \"BA1\":true");
	if (mr->flags & MEAS_REP_F_DL_VALID) {
		printf(", \"DL_MEAS\":{");
		print_meas_rep_uni_json(&mr->dl);
		printf("}");
	}

	if (mr->num_cell == 7)
		return;
	printf(", \"NUM_NEIGH\":%u, \"NEIGH\":[", mr->num_cell);
	for (i = 0; i < mr->num_cell; i++) {
		struct gsm_meas_rep_cell *mrc = &mr->cell[i];
		if (i!=0) printf(", ");
		printf("{\"IDX\":%u, \"ARFCN\":%u, \"BSIC\":%u, \"POWER\":%d}",
			mrc->neigh_idx, mrc->arfcn, mrc->bsic, rxlev2dbm(mrc->rxlev));
	}
	printf("]");
}

static void print_chan_info_json(struct meas_feed_meas *mfm)
{
	printf("\"lchan_type\":\"%s\", \"pchan_type\":\"%s\", "
		   "\"bts_nr\":%d, \"trx_nr\":%d, \"ts_nr\":%d, \"ss_nr\":%d",
	gsm_chan_t_name(mfm->lchan_type), gsm_pchan_name(mfm->pchan_type),
	mfm->bts_nr, mfm->trx_nr, mfm->ts_nr, mfm->ss_nr);
}

static void print_meas_feed_json(struct meas_feed_meas *mfm)
{
	time_t now = time(NULL);

	printf("{");
	printf("\"time\":%ld, \"imsi\":\"%s\", \"name\":\"%s\", \"scenario\":\"%s\", ",
		now, mfm->imsi, mfm->name, mfm->scenario);

	switch (mfm->hdr.version) {
	case 1:
		printf("\"chan_info\":{");
		print_chan_info_json(mfm);
		printf("}, ");
		/* no break, fall to version 0 */
	case 0:
		printf("\"meas_rep\":{");
		print_meas_rep_json(&mfm->mr);
		printf("}");
		break;
	}

	printf("}\n");

}

static int handle_meas(struct msgb *msg)
{
	struct meas_feed_meas *mfm = (struct meas_feed_meas *) msgb_data(msg);

	print_meas_feed_json(mfm);

	return 0;
}

static int handle_msg(struct msgb *msg)
{
	struct meas_feed_hdr *mfh = (struct meas_feed_hdr *) msgb_data(msg);

	if (mfh->version != MEAS_FEED_VERSION)
		return -EINVAL;

	switch (mfh->msg_type) {
	case MEAS_FEED_MEAS:
		handle_meas(msg);
		break;
	default:
		break;
	}
	return 0;
}

static int udp_fd_cb(struct osmo_fd *ofd, unsigned int what)
{
	int rc;

	if (what & OSMO_FD_READ) {
		struct msgb *msg = msgb_alloc(1024, "UDP Rx");

		rc = read(ofd->fd, msgb_data(msg), msgb_tailroom(msg));
		if (rc < 0)
			return rc;
		msgb_put(msg, rc);
		handle_msg(msg);
		msgb_free(msg);
	}

	return 0;
}

static void print_help(void)
{
	printf(" -h --help. This help text.\n");
	printf(" -b --bind-ip. The IP to bind to.\n");
}

static void print_usage(void)
{
	printf("Usage: meas_json [options]\n");
}

static void handle_options(int argc, char **argv)
{
	int options_mask = 0;

	/* disable explicit missing arguments error output from getopt_long */
	opterr = 0;

	while (1) {
		int option_index = 0, c;
		static struct option long_options[] = {
			{"help", 0, 0, 'h'},
			{"bind-ip", 0, 0, 'b'},
			{0, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "hb:",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			print_usage();
			print_help();
			exit(0);
		case 'b':
			bind_ip = optarg;
			break;
		case '?':
			if (optopt) {
				printf("ERROR: missing mandatory argument "
				       "for `%s' option\n", argv[optind-1]);
			} else {
				printf("ERROR: unknown option `%s'\n",
					argv[optind-1]);
			}
			print_usage();
			print_help();
			exit(EXIT_FAILURE);
			break;
		default:
			/* ignore */
			break;
		}
	}
	if (argc > optind) {
		fprintf(stderr, "Unsupported positional arguments on command line\n");
		exit(2);
	}
}

/* default categories */
static struct log_info_cat default_categories[] = {
};

static const struct log_info meas_json_log_info = {
	.cat = default_categories,
	.num_cat = ARRAY_SIZE(default_categories),
};

int main(int argc, char **argv)
{

	void *tall_ctx = talloc_named_const(NULL, 0, "meas_json");
	osmo_init_logging2(tall_ctx, &meas_json_log_info);

	handle_options(argc, argv);

	int rc;
	struct osmo_fd udp_ofd;

	udp_ofd.cb = udp_fd_cb;
	rc =  osmo_sock_init_ofd(&udp_ofd, AF_INET, SOCK_DGRAM, IPPROTO_UDP, bind_ip, 8888, OSMO_SOCK_F_BIND);
	if (rc < 0)
		exit(1);

	while (1) {
		osmo_select_main(0);
	};

	exit(0);
}
