
#ifndef UPRO_CONTEXT_H
#define UPRO_CONTEXT_H

#include "upro_batch.h"

typedef struct upro_forwarder_context_s {
	upro_batch_t *batch;
	int ifindex;
	int core_id;
	int queue_id;
	int initialized;
	int id;
} upro_forwarder_context_t;

typedef struct upro_collector_context_s {
	upro_batch_t *batch;
	int ifindex;
	int core_id;
	int queue_id;
	int initialized;
	int id;
} upro_collector_context_t;

typedef struct upro_gpu_worker_context_s {
	upro_batch_t *cpu_batch_set;
	int core_id; /* which core should gpu worker run */
	/* Add more info passing to GPU worker here ... */
} upro_gpu_worker_context_t;

void *upro_gpu_worker_main(upro_gpu_worker_context_t *context);
void *upro_collector_main(upro_collector_context_t *context);
void *upro_forwarder_main(upro_forwarder_context_t *context);

#endif
