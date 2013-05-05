#ifndef UPRO_CONFIG_H
#define UPRO_CONFIG_H

typedef struct upro_config_s {
	unsigned int cpu_worker_num;
	unsigned int gpu_worker_num;
	unsigned int worker_num; // cpu_worker_num + gpu_worker_num
	unsigned int iterations;
	unsigned int log_sample_num;

	unsigned int gpu;
	unsigned int batch_buf_max_size;
	unsigned int batch_job_max_num;

	unsigned int *core_ids;

	// Most important argument for realtime scheduling algorithm
	unsigned int I; // 40ms, 30ms ...
	unsigned int type;

	/* we currently not use these */
	unsigned int aes_key_size;
	unsigned int aes_iv_size;
	unsigned int hmac_key_size;

	int client_ifindex;
	int server_ifindex;

	char client_interface[5];
	char server_interface[5];
} upro_config_t;

#endif
