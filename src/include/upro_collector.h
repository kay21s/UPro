#ifndef UPRO_COLLECTOR_H
#define UPRO_COLLECTOR_H

#include "upro_batch.h"

typedef struct upro_collector_context_s {
	upro_batch_t *batch;
	int core_id;
} upro_collector_context_t;

int upro_collector_main(upro_collector_context_t *context);

#endif
