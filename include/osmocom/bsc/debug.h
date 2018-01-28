#pragma once

#include <stdio.h>
#include <osmocom/core/linuxlist.h>

#define DEBUG
#include <osmocom/core/logging.h>

/* Debug Areas of the code */
enum {
	DRLL,
	DCC,
	DMM,
	DRR,
	DRSL,
	DNM,
	DPAG,
	DMEAS,
	DMSC,
	DMGCP,
	DHO,
	DHODEC,
	DREF,
	DNAT,
	DCTRL,
	DFILTER,
	DPCU,
	Debug_LastEntry,
};
