#ifndef UPRO_GPU_WORKER_H
#define UPRO_GPU_WORKER_H

#include "upro_batch.h"

typedef struct upro_gpu_worker_s {
	upro_batch_buf_t **bufs[3]; /* Three buf sets */
	int cur_buf_id;
	int total_bytes;
} upro_gpu_worker_t;

#endif
