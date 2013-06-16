#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>
#include <time.h>

#include <signal.h>
#include <sys/wait.h>
#include <sys/time.h>

#include "upro_context.h"
#include "upro_collector.h"
#include "upro_transworker.h"
#include "upro_config.h"
#include "upro_memory.h"
#include "upro_macros.h"
#include "upro_job.h"
#include "upro_batch.h"
#include "psio.h"

upro_batch_t *batch_set;
upro_config_t *config;
pthread_mutex_t mutex_worker_init = PTHREAD_MUTEX_INITIALIZER;

extern upro_collector_t collectors[MAX_COLLECTOR_NUM];

void collector_handle_signal(int signal)
{
	int i;
	struct timeval subtime;
	uint64_t total_rx_packets = 0, total_rx_bytes = 0;;
	upro_collector_t *cc;
	double speed_handle = 0;
	double speed_actual = 0;

	for (i = 0; i < config->cpu_worker_num; i ++) {
		cc = &(collectors[i]);

		gettimeofday(&(cc->endtime), NULL);
		timersub(&(cc->endtime), &(cc->startime), &(cc->subtime));
	}

	for (i = 0; i < config->cpu_worker_num; i ++) {
		cc = &(collectors[i]);
		subtime = cc->subtime;

		total_rx_packets = (cc->handle).rx_packets[config->server_ifindex];
		total_rx_bytes = (cc->handle).rx_bytes[config->server_ifindex];
		speed_handle += (double)(total_rx_bytes * 8) / (double) ((subtime.tv_sec * 1000000 + subtime.tv_usec) * 1000),

		printf("----------\n");
		printf("In handle: %ld packets received, elapse time : %lds, Send Speed : %lf Mpps, %5.2f Gbps, Aveage Len. = %ld\n", 
				total_rx_packets, subtime.tv_sec, 
				(double)(total_rx_packets) / (double) (subtime.tv_sec * 1000000 + subtime.tv_usec),
				(double)(total_rx_bytes * 8) / (double) ((subtime.tv_sec * 1000000 + subtime.tv_usec) * 1000),
				total_rx_bytes / total_rx_packets);

		total_rx_packets = cc->total_packets;
		total_rx_bytes = cc->total_bytes;
		speed_actual += (double)(total_rx_bytes * 8) / (double) ((subtime.tv_sec * 1000000 + subtime.tv_usec) * 1000),
		printf("Actual: %ld packets received, elapse time : %lds, Send Speed : %lf Mpps, %5.2f Gbps, Aveage Len. = %ld\n", 
				total_rx_packets, subtime.tv_sec, 
				(double)(total_rx_packets) / (double) (subtime.tv_sec * 1000000 + subtime.tv_usec),
				(double)(total_rx_bytes * 8) / (double) ((subtime.tv_sec * 1000000 + subtime.tv_usec) * 1000),
				total_rx_bytes / total_rx_packets);
	}

	printf("<<< IOEngine handle speed %lf, actual processing speed %lf >>>\n", speed_handle, speed_actual);

	exit(0);
}

int upro_init_config()
{
	config = (upro_config_t *)upro_mem_calloc(sizeof(upro_config_t));

	config->gpu = 0; // if this need batch processing by GPU
	config->cpu_worker_num = 4; // Note: This should equal to the setting in IOEngine
	config->gpu_worker_num = 1;
	config->worker_num = config->cpu_worker_num + config->gpu_worker_num + 1;

	config->iterations = 20;
	config->log_sample_num = 100;
	//config->I = 20; // ms
	config->I = 30; // ms
	/* we take 50ms as parameter, for 10Gbps bandwidth,
	   50ms * 10Gbps = 0.05 * 10^10 bits ~= (<) 62.5 MB.
	   Take 64 bytes minimum packet size, at most 1 million jobs each batch,
	   we allocate 1000 jobs at most.
	   */
	/* 10Gbps * 20ms = 200Mb = 25MB, 4 worker, each with 6.25MB */
	config->batch_buf_max_size = 6.25 * 10e6; // byte
	config->batch_job_max_num = 10e5;

	config->eiu_hdr_len = 42; // eth+ip+udp header max size

	memcpy(config->client_interface, "xge0", sizeof("xge0"));
	memcpy(config->server_interface, "xge1", sizeof("xge1"));

	config->io_batch_num = 128;
	config->client_ifindex = -1;
	config->server_ifindex = -1;

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
		memcpy(&(config->client_device), &(devices[i]), sizeof(struct ps_device));
		break;
	}
	assert (ifindex != -1);

	for (i = 0; i < num_devices_attached; i ++) {
		assert(devices_attached[i] != ifindex);
	}
	devices_attached[num_devices_attached] = ifindex;
	config->client_ifindex = ifindex;
	num_devices_attached ++;


	/* server side interface */
	for (i = 0; i < num_devices; i ++) {
		if (strcmp(config->server_interface, devices[i].name) != 0)
			continue;
		ifindex = devices[i].ifindex;
		memcpy(&(config->server_device), &(devices[i]), sizeof(struct ps_device));
		break;
	}
	assert (ifindex != -1);

	for (i = 0; i < num_devices_attached; i ++) {
		assert(devices_attached[i] != ifindex);
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
	pthread_t tid;
	pthread_attr_t attr;
	upro_transworker_context_t *context;

	/* pass a memory block to each worker */
	context = (upro_transworker_context_t *)upro_mem_malloc(sizeof(upro_transworker_context_t)); 
	context->core_id = config->cpu_worker_num * 2 + 1;

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

	/* core id = 1, 3, 5, 7, ... */
	for (i = 0; i < config->cpu_worker_num; i ++) {
		/* pass a memory block to each worker */
		context = (upro_forwarder_context_t *)upro_mem_malloc(sizeof(upro_forwarder_context_t));

		context->queue_id = i;
		context->batch = &(batch_set[i]);
		context->core_id = i + config->cpu_worker_num;
		//context->core_id = i * 2 + 12; // 12,14,16, on the other die

		pthread_attr_init(&attr);
		pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
		if (pthread_create(&tid, &attr, (void *)upro_forwarder_main, (void *)context) != 0) {
			printf("pthread_create error!!\n");
			return -1;
		}
	}
	return 0;
}

int upro_launch_collectors(upro_collector_context_t **collector_context_set)
{
	unsigned int i;
	pthread_t tid;
	pthread_attr_t attr;
	upro_collector_context_t *context;

	/* core id = 0, 2, 4, 6, ... */
	for (i = 0; i < config->cpu_worker_num; i ++) {
		/* pass a memory block to each worker */
		context = (upro_collector_context_t *)upro_mem_malloc(sizeof(upro_collector_context_t));
		collector_context_set[i] = context;

		context->queue_id = i;
		context->batch = &(batch_set[i]);
		//context->core_id = i * 2; // 0, 2, 4...
		context->core_id = i; // FIXME: why? 0, 1, 2...

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
	unsigned int i;
	upro_gpu_worker_context_t * context;

	assert(config->gpu_worker_num == 1);
	for (i = 0; i < config->gpu_worker_num; i ++) {
		/* pass a memory block to each worker */
		context = (upro_gpu_worker_context_t *)upro_mem_malloc(sizeof(upro_gpu_worker_context_t));
		context->cpu_batch_set = batch_set;
		//FIXME:context->core_id = config->cpu_worker_num * 2;
		context->core_id = 10;

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
	upro_init_ioengine();

	upro_collector_context_t **collector_context_set;
	collector_context_set = malloc(config->cpu_worker_num * sizeof(void *));

	//signal(SIGINT, collector_handle_signal);

	/* Launch workers first*/
	upro_launch_collectors(collector_context_set);

	upro_launch_forwarders();
	//upro_launch_transworker();

	/* Synchronization, Wait for CPU workers */
	int i, ready;
	upro_collector_context_t *collector_context;
	while (1) {
		ready = 0;

		pthread_mutex_lock(&mutex_worker_init);
		for (i = 0; i < config->cpu_worker_num; i ++) {
			collector_context = collector_context_set[i];
			if (collector_context->initialized)
				ready ++;
		}
		pthread_mutex_unlock(&mutex_worker_init);

		if (ready == config->cpu_worker_num) break;
		usleep(5000);
	}
	printf("--------------------------------------\n");
	upro_launch_gpu_workers();

	while(1) sleep(60);
	return 0;
}
