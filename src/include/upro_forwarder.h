#ifndef UPRO_FORWARDER_H
#define UPRO_FORWARDER_H

#include "upro_batch.h"

typedef struct upro_forwarder_context_s {
	upro_batch_t *batch;
	int core_id;
} upro_forwarder_context_t;

int upro_forwarder_main(upro_forwarder_context_t *context);

#endif
