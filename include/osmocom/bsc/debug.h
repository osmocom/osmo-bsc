#pragma once

#include <stdio.h>
#include <osmocom/core/linuxlist.h>

#define DEBUG
#include <osmocom/core/logging.h>

/* Debug Areas of the code */
enum {
	DRLL,
	DMM,
	DRR,
	DRSL,
	DNM,
	DPAG,
	DMEAS,
	DMSC,
	DHO,
	DHODEC,
	DREF,
	DCTRL,
	DFILTER,
	DPCU,
	DLCLS,
	DCHAN,
	DTS,
	DAS,
	DCBS,
	DLCS,
	Debug_LastEntry,
};

#define LOG_BTS(bts, subsys, level, fmt, args...) \
	LOGP(subsys, level, "(bts=%d) " fmt, (bts)->nr, ## args)

#define LOG_TRX(trx, subsys, level, fmt, args...) \
	LOGP(subsys, level, "(bts=%d,trx=%d) " fmt, (trx)->bts->nr, (trx)->nr, ## args)
