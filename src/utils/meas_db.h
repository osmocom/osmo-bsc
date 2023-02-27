#ifndef OPENBSC_MEAS_DB_H
#define OPENBSC_MEAS_DB_H

struct meas_db_state;

struct meas_db_state *meas_db_open(void *ctx, const char *fname);
void meas_db_close(struct meas_db_state *st);

int meas_db_begin(struct meas_db_state *st);
int meas_db_commit(struct meas_db_state *st);

int meas_db_insert(struct meas_db_state *st, unsigned long timestamp,
		   const struct meas_feed_meas *mfm);

#endif
