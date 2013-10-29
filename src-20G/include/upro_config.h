#ifndef UPRO_CONFIG_H
#define UPRO_CONFIG_H

#include "psio.h"

# define MAX_WORKER_NUM 12

typedef struct upro_config_s {
	unsigned int cpu_worker_num;
	unsigned int if0_worker_num;
	unsigned int if1_worker_num;
	unsigned int gpu_worker_num;

	unsigned int iterations;
	unsigned int log_sample_num;

	unsigned int eiu_hdr_len;

	unsigned int gpu;
	unsigned long batch_buf_max_size;
	unsigned long batch_job_max_num;

	unsigned int *core_ids;

	// Most important argument for realtime scheduling algorithm
	unsigned int I; // 40ms, 30ms ...
	unsigned int type;

	int io_batch_num;

	int ifindex_0;
	int ifindex_1;

	char interface_0[5];
	char interface_1[5];
} upro_config_t;

#endif
