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
	DNAT,
	DCTRL,
	DFILTER,
	DPCU,
	DLCLS,
	Debug_LastEntry,
};
