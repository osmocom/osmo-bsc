/* UDP-Feed of measurement reports */

#include <unistd.h>

#include <sys/socket.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/write_queue.h>
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

struct meas_feed_state {
	struct osmo_wqueue wqueue;
	char scenario[31+1];
	char *dst_host;
	uint16_t dst_port;
};

static struct meas_feed_state g_mfs = {};

static int process_meas_rep(struct gsm_meas_rep *mr)
{
	struct msgb *msg;
	struct meas_feed_meas *mfm;
	struct bsc_subscr *bsub;

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

	msg = msgb_alloc(sizeof(struct meas_feed_meas), "Meas. Feed");
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
	if (osmo_wqueue_enqueue(&g_mfs.wqueue, msg) != 0) {
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

static int feed_write_cb(struct osmo_fd *ofd, struct msgb *msg)
{
	return write(ofd->fd, msgb_data(msg), msgb_length(msg));
}

static int feed_read_cb(struct osmo_fd *ofd)
{
	int rc;
	char buf[256];

	rc = read(ofd->fd, buf, sizeof(buf));
	osmo_fd_read_disable(ofd);

	return rc;
}

int meas_feed_cfg_set(const char *dst_host, uint16_t dst_port)
{
	int rc;
	int already_initialized = 0;

	if (g_mfs.wqueue.bfd.fd)
		already_initialized = 1;


	if (already_initialized &&
	    !strcmp(dst_host, g_mfs.dst_host) &&
	    dst_port == g_mfs.dst_port)
		return 0;

	if (!already_initialized) {
		osmo_wqueue_init(&g_mfs.wqueue, 10);
		g_mfs.wqueue.write_cb = feed_write_cb;
		g_mfs.wqueue.read_cb = feed_read_cb;
		osmo_signal_register_handler(SS_LCHAN, meas_feed_sig_cb, NULL);
		LOGP(DMEAS, LOGL_DEBUG, "meas_feed: registered signal callback\n");
	}

	if (already_initialized) {
		osmo_wqueue_clear(&g_mfs.wqueue);
		osmo_fd_unregister(&g_mfs.wqueue.bfd);
		close(g_mfs.wqueue.bfd.fd);
		/* don't set to zero, as that would mean 'not yet initialized' */
		g_mfs.wqueue.bfd.fd = -1;
	}
	rc = osmo_sock_init_ofd(&g_mfs.wqueue.bfd, AF_UNSPEC, SOCK_DGRAM,
				IPPROTO_UDP, dst_host, dst_port,
				OSMO_SOCK_F_CONNECT);
	if (rc < 0)
		return rc;

	osmo_fd_read_disable(&g_mfs.wqueue.bfd);

	if (g_mfs.dst_host)
		talloc_free(g_mfs.dst_host);
	g_mfs.dst_host = talloc_strdup(NULL, dst_host);
	g_mfs.dst_port = dst_port;

	return 0;
}

void meas_feed_cfg_get(char **host, uint16_t *port)
{
	*port = g_mfs.dst_port;
	*host = g_mfs.dst_host;
}

void meas_feed_scenario_set(const char *name)
{
	osmo_strlcpy(g_mfs.scenario, name, sizeof(g_mfs.scenario));
}

const char *meas_feed_scenario_get(void)
{
	return g_mfs.scenario;
}
