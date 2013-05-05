#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>

#include "upro_collector.h"
#include "upro_forwarder.h"
#include "upro_transworker.h"
#include "upro_gpu_worker.h"
#include "upro_config.h"
#include "upro_memory.h"
#include "upro_macros.h"
#include "upro_job.h"
#include "upro_batch.h"
#include "psio.h"

upro_batch_t *batch_set;
upro_config_t *config;

int upro_init_config()
{
	int i;

	config = (upro_config_t *)upro_mem_calloc(sizeof(upro_config_t));

	config->gpu = 0; // if this need batch processing by GPU

	config->cpu_worker_num = 1;
	config->gpu_worker_num = 1;
	config->worker_num = config->cpu_worker_num + config->gpu_worker_num + 1;

	// length = strlen("219.219.216.106");
	// config->server_ip = (char *)malloc(length);
	// memcpy(config->server_ip, "219.219.216.106", length);

	config->core_ids = (unsigned int *)upro_mem_malloc(config->worker_num * sizeof(unsigned int));
	for (i = 0; i < config->worker_num; i ++) {
		/* currently, we use this sequence */
		config->core_ids[i] = i;
	}

	config->iterations = 5;
	config->log_sample_num = 100;
	config->I = 40; // ms
	/* we take 40ms as parameter, for 10Gbps bandwidth,
	   40ms * 10Gbps = 400 * 10^3 bits ~= (<) 50 KB = 40 * 1.25 * 10^3.
	   Take 64 bytes minimum packet size, at most 782 jobs each batch,
	   we allocate 1000 jobs at most.
	   */
	config->batch_buf_max_size = config->I * 1.25 * 1000; // byte
	config->batch_job_max_num = 1000;

	config->aes_key_size = 16; // 128/8 byte
	config->aes_iv_size = 16; // 128/8 byte
	config->hmac_key_size = 64; // for sha1, byte

	memcpy(config->client_interface, "xge0", sizeof("xge0"));
	memcpy(config->server_interface, "xge1", sizeof("xge1"));

	config->client_ifindex = -1;
	config->server_ifindex = -1;
	/*

	config = {
		1, // cpu_worker_num
		0, // gpu_worker_num
		1, // total worker
		128, // epoll_max_events

		"219.219.216.11", // server_ip
		80, // server_port
		"127.0.0.1", // listen_ip
		80, // listen_port

		4096, // conn_buffer_size
	};
	*/
	return 0;
}

/* Init config->client_ifindex, and config->server_ifindex */
int upro_init_ioengine()
{
	int i, ifindex = -1;
	int num_devices_attached = 0;
	int devices_attached[PS_MAX_DEVICES];
	struct ps_device devices[PS_MAX_DEVICES];

	int num_devices = ps_list_devices(devices);
	if (num_devices == -1) {
		perror("ps_list_devices");
		exit(1);
	}

	/* client side interface */
	for (i = 0; i < num_devices; i ++) {
		if (strcmp(config->client_interface, devices[i].name) != 0)
			continue;

		ifindex = devices[i].ifindex;
		// memcpy(config->client_device, devices[i], sizeof(struct ps_device));

		break;
	}

	if (ifindex == -1) {
		printf("Interface %s does not exist!\n", config->client_interface);
		exit(4);
	}

	for (i = 0; i < num_devices_attached; i ++) {
		if (devices_attached[i] == ifindex) {
			printf("device has been attached\n");
			exit(0);
		}
	}

	devices_attached[num_devices_attached] = ifindex;
	config->client_ifindex = ifindex;
	num_devices_attached ++;

	/* server side interface */
	for (i = 0; i < num_devices; i ++) {
		if (strcmp(config->server_interface, devices[i].name) != 0)
			continue;

		ifindex = devices[i].ifindex;
		// memcpy(config->server_device, devices[i], sizeof(struct ps_device));
		break;
	}

	if (ifindex == -1) {
		printf("Interface %s does not exist!\n", config->server_interface);
		exit(4);
	}

	for (i = 0; i < num_devices_attached; i ++) {
		if (devices_attached[i] == ifindex) {
			printf("device has been attached\n");
			exit(0);
		}
	}

	devices_attached[num_devices_attached] = ifindex;
	config->server_ifindex = ifindex;
	num_devices_attached ++;

	return 0;
}

void upro_init_thread_keys()
{
	pthread_key_create(&worker_batch_struct, NULL);
}

int upro_init_batch_set()
{
	batch_set = (upro_batch_t *)upro_mem_malloc(config->cpu_worker_num * sizeof(upro_batch_t));
	return 0;
}

int upro_launch_transworker()
{
	unsigned int thread_id;
	pthread_t tid;
	pthread_attr_t attr;
	upro_transworker_context_t *context;

	/* pass a memory block to each worker */
	context = (upro_transworker_context_t *)upro_mem_malloc(sizeof(upro_transworker_context_t)); 
	thread_id = config->cpu_worker_num + config->gpu_worker_num;
	context->core_id = config->core_ids[thread_id];

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if (pthread_create(&tid, &attr, (void *)upro_transworker_main, (void *)context) != 0) {
		printf("pthread_create error!!\n");
		return -1;
	}

	return 0;
}

int upro_launch_forwarders()
{
	unsigned int i;
	pthread_t tid;
	pthread_attr_t attr;
	upro_forwarder_context_t *context;

	for (i = 0; i < config->cpu_worker_num; i ++) {
		/* pass a memory block to each worker */
		context = (upro_forwarder_context_t *)upro_mem_malloc(sizeof(upro_forwarder_context_t));
		context->batch = &(batch_set[i]);
		context->core_id = config->core_ids[i];

		pthread_attr_init(&attr);
		pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
		if (pthread_create(&tid, &attr, (void *)upro_forwarder_main, (void *)context) != 0) {
			printf("pthread_create error!!\n");
			return -1;
		}
	}
	return 0;
}

int upro_launch_collectors()
{
	unsigned int i;
	pthread_t tid;
	pthread_attr_t attr;
	upro_collector_context_t *context;

	for (i = 0; i < config->cpu_worker_num; i ++) {
		/* pass a memory block to each worker */
		context = (upro_collector_context_t *)upro_mem_malloc(sizeof(upro_collector_context_t));
		context->batch = &(batch_set[i]);
		context->core_id = config->core_ids[i];

		pthread_attr_init(&attr);
		pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
		if (pthread_create(&tid, &attr, (void *)upro_collector_main, (void *)context) != 0) {
			printf("pthread_create error!!\n");
			return -1;
		}
	}
	return 0;
}

int upro_launch_gpu_workers()
{
	pthread_t tid;
	pthread_attr_t attr;
	int thread_id;
	unsigned int i;
	upro_gpu_worker_context_t * context;

	assert(config->gpu_worker_num == 1);
	for (i = 0; i < config->gpu_worker_num; i ++) {
		/* We take gpu worker thread */
		thread_id = config->cpu_worker_num + i; /* We take gpu worker thread */

		/* pass a memory block to each worker */
		context = (upro_gpu_worker_context_t *)upro_mem_malloc(sizeof(upro_gpu_worker_context_t));
		context->cpu_batch_set = batch_set;
		context->core_id = config->core_ids[thread_id];

		pthread_attr_init(&attr);
		pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
		if (pthread_create(&tid, &attr, (void *)upro_gpu_worker_main, (void *)context) != 0) {
			printf("pthread_create error!!\n");
			return -1;
		}
	}
	return 0;
}

int main()
{
	upro_init_config();
	upro_init_batch_set();
	upro_init_thread_keys();

	/* Launch workers first*/
	upro_launch_collectors();
	upro_launch_forwarders();
	upro_launch_transworker();
	upro_launch_gpu_workers();

	return 0;
}
