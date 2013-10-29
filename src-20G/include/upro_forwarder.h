#ifndef UPRO_FORWARDER_H
#define UPRO_FORWARDER_H

#include "psio.h"

typedef struct upro_forwarder_s {
	struct ps_handle handle;
	uint64_t total_packets;
	uint64_t total_bytes;
	struct timeval startime;
	struct timeval endtime;
	struct timeval subtime;
} __attribute__((aligned(64))) upro_forwarder_t;

#endif
