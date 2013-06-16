#ifndef UPRO_CONFIG_H
#define UPRO_CONFIG_H

#include "psio.h"

typedef struct upro_config_s {
	unsigned int cpu_worker_num;
	unsigned int gpu_worker_num;
	unsigned int worker_num; // cpu_worker_num + gpu_worker_num
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
	int client_ifindex;
	int server_ifindex;

	char client_interface[5];
	char server_interface[5];

	struct ps_device client_device;
	struct ps_device server_device;
} upro_config_t;

#endif
