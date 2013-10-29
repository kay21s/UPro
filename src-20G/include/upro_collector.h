#ifndef UPRO_COLLECTOR_H
#define UPRO_COLLECTOR_H

#include "psio.h"

#define MAX_COLLECTOR_NUM 12

typedef struct upro_collector_s {
	struct ps_handle handle;
	uint64_t total_packets;
	uint64_t total_bytes;
	struct timeval startime;
	struct timeval endtime;
	struct timeval subtime;
} __attribute__((aligned(64))) upro_collector_t;

#endif
