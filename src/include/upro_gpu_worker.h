#ifndef UPRO_GPU_WORKER_H
#define UPRO_GPU_WORKER_H

#include "upro_batch.h"
#include "../../libgpucrypto/crypto_context.h"

typedef struct upro_gpu_worker_s {
	upro_batch_buf_t **bufs[3]; /* Three buf sets */
	int cur_buf_id;

	crypto_context_t cry_ctx;
	int total_bytes;
} upro_gpu_worker_t;

typedef struct upro_gpu_worker_context_s {
	upro_batch_t *cpu_batch_set;
	int core_id; /* which core should gpu worker run */
	/* Add more info passing to GPU worker here ... */
} upro_gpu_worker_context_t;

void *upro_gpu_worker_main(void *context);

#endif
