/* UDP-Feed of measurement reports */

#include <unistd.h>

#include <sys/socket.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/osmo_io.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>

#include <osmocom/vty/command.h>
#include <osmocom/vty/vty.h>

#include <osmocom/bsc/meas_rep.h>
#include <osmocom/bsc/signal.h>
#include <osmocom/bsc/bsc_subscriber.h>
#include <osmocom/bsc/meas_feed.h>
#include <osmocom/bsc/vty.h>
#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/bts.h>
#include <osmocom/bsc/lchan.h>

struct meas_feed_state {
	struct osmo_io_fd *io_fd;
	char scenario[31+1];
	char *dst_host;
	uint16_t dst_port;
	size_t txqueue_max;
};

static struct meas_feed_state g_mfs = { .txqueue_max = MEAS_FEED_TXQUEUE_MAX_LEN_DEFAULT };

static int process_meas_rep(struct gsm_meas_rep *mr)
{
	struct msgb *msg;
	struct meas_feed_meas *mfm;
	struct bsc_subscr *bsub;

	OSMO_ASSERT(g_mfs.io_fd != NULL);

	/* ignore measurements as long as we don't know who it is */
	if (!mr->lchan) {
		LOGP(DMEAS, LOGL_DEBUG, "meas_feed: no lchan, not sending report\n");
		return 0;
	}
	if (!mr->lchan->conn) {
		LOGP(DMEAS, LOGL_DEBUG, "meas_feed: lchan without conn, not sending report\n");
		return 0;
	}

	bsub = mr->lchan->conn->bsub;

	msg = msgb_alloc(sizeof(struct meas_feed_meas), "meas_feed_msg");
	if (!msg)
		return 0;

	/* fill in the header */
	mfm = (struct meas_feed_meas *) msgb_put(msg, sizeof(*mfm));
	mfm->hdr.msg_type = MEAS_FEED_MEAS;
	mfm->hdr.version = MEAS_FEED_VERSION;

	/* fill in MEAS_FEED_MEAS specific header */
	if (bsub)
		osmo_strlcpy(mfm->imsi, bsub->imsi, sizeof(mfm->imsi));
	/* This used to be a human readable meaningful name set in the old osmo-nitb's subscriber
	 * database. Now we're several layers away from that (and possibly don't even have a name in
	 * osmo-hlr either), hence this is a legacy item now that we should leave empty ... *but*:
	 * here in the BSC we often don't know the subscriber's full identity information. For example,
	 * we might only know the TMSI, and hence would pass an empty IMSI above. So after all, feed
	 * bsc_subscr_name(), which possibly will feed the IMSI again, but in case only the TMSI is known
	 * would add that to the information set as "TMSI:0x12345678". */
	osmo_strlcpy(mfm->name, bsc_subscr_name(bsub), sizeof(mfm->name));
	osmo_strlcpy(mfm->scenario, g_mfs.scenario, sizeof(mfm->scenario));

	/* copy the entire measurement report */
	memcpy(&mfm->mr, mr, sizeof(mfm->mr));

	/* copy channel information */
	/* we assume that the measurement report always belong to some timeslot */
	mfm->lchan_type = (uint8_t)mr->lchan->type;
	mfm->pchan_type = (uint8_t)mr->lchan->ts->pchan_is;
	mfm->bts_nr = mr->lchan->ts->trx->bts->nr;
	mfm->trx_nr = mr->lchan->ts->trx->nr;
	mfm->ts_nr = mr->lchan->ts->nr;
	mfm->ss_nr = mr->lchan->nr;

	/* and send it to the socket */
	if (osmo_iofd_write_msgb(g_mfs.io_fd, msg)) {
		LOGP(DMEAS, LOGL_ERROR, "meas_feed %s: sending measurement report failed\n",
		     gsm_lchan_name(mr->lchan));
		msgb_free(msg);
	} else
		LOGP(DMEAS, LOGL_DEBUG, "meas_feed %s: sent measurement report\n",
		     gsm_lchan_name(mr->lchan));

	return 0;
}

static int meas_feed_sig_cb(unsigned int subsys, unsigned int signal,
			    void *handler_data, void *signal_data)
{
	struct lchan_signal_data *sdata = signal_data;

	if (subsys != SS_LCHAN)
		return 0;

	if (signal == S_LCHAN_MEAS_REP)
		process_meas_rep(sdata->mr);

	return 0;
}

static void meas_feed_close(void)
{
	if (g_mfs.io_fd == NULL)
		return;
	osmo_signal_unregister_handler(SS_LCHAN, meas_feed_sig_cb, NULL);
	osmo_iofd_close(g_mfs.io_fd);
	osmo_iofd_free(g_mfs.io_fd);
	g_mfs.io_fd = NULL;
}

static void meas_feed_noop_cb(struct osmo_io_fd *iofd, int res, struct msgb *msg)
{
}

int meas_feed_cfg_set(const char *dst_host, uint16_t dst_port)
{
	int rc;
	/* osmo_io code throws an error if 'write_cb' is NULL, so we set a no-op */
	struct osmo_io_ops meas_feed_oio = {
		.read_cb = NULL,
		.write_cb = meas_feed_noop_cb,
		.segmentation_cb = NULL
	};
	/* Already initialized */
	if (g_mfs.io_fd != NULL) {
		/* No change needed, do nothing */
		if (!strcmp(dst_host, g_mfs.dst_host) && dst_port == g_mfs.dst_port)
			return 0;
		meas_feed_close();
	}

	rc = osmo_sock_init(AF_UNSPEC, SOCK_DGRAM, IPPROTO_UDP, dst_host, dst_port, OSMO_SOCK_F_CONNECT);
	if (rc < 0) {
		osmo_signal_unregister_handler(SS_LCHAN, meas_feed_sig_cb, NULL);
		return rc;
	}
	g_mfs.io_fd = osmo_iofd_setup(NULL, rc, "meas_iofd", OSMO_IO_FD_MODE_READ_WRITE, &meas_feed_oio, NULL);
	if (!g_mfs.io_fd)
		return -1;
	osmo_iofd_set_txqueue_max_length(g_mfs.io_fd, g_mfs.txqueue_max);
	if ((rc = osmo_iofd_register(g_mfs.io_fd, rc)))
		return rc;

	osmo_talloc_replace_string(NULL, &g_mfs.dst_host, dst_host);
	g_mfs.dst_port = dst_port;
	osmo_signal_register_handler(SS_LCHAN, meas_feed_sig_cb, NULL);
	LOGP(DMEAS, LOGL_DEBUG, "meas_feed: started %s\n",
	     osmo_sock_get_name2(osmo_iofd_get_fd(g_mfs.io_fd)));
	return 0;
}

void meas_feed_cfg_get(char **host, uint16_t *port)
{
	*port = g_mfs.dst_port;
	*host = g_mfs.dst_host;
}

void meas_feed_txqueue_max_length_set(unsigned int max_length)
{
	g_mfs.txqueue_max = max_length;
	if (g_mfs.io_fd)
		osmo_iofd_set_txqueue_max_length(g_mfs.io_fd, max_length);
}

unsigned int meas_feed_txqueue_max_length_get(void)
{
	return g_mfs.txqueue_max;
}

void meas_feed_scenario_set(const char *name)
{
	osmo_strlcpy(g_mfs.scenario, name, sizeof(g_mfs.scenario));
}

const char *meas_feed_scenario_get(void)
{
	return g_mfs.scenario;
}
