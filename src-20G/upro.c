#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>

#include <signal.h>
#include <sys/wait.h>
#include <sys/time.h>

#include "upro_context.h"
#include "upro_collector.h"
#include "upro_forwarder.h"
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

extern upro_collector_t collectors[MAX_WORKER_NUM];
extern upro_forwarder_t forwarders[MAX_WORKER_NUM];

int upro_init_config()
{
	config = (upro_config_t *)upro_mem_calloc(sizeof(upro_config_t));

	config->gpu = 0; // if this need batch processing by GPU
	/* if1_worker_num + if2_worker_num = cpu_worker_num */
	config->cpu_worker_num = 4; // Note: This should equal to the setting in IOEngine
	config->if0_worker_num = 2; // collector-forwarder pairs on interface 1
	config->if1_worker_num = 2;
	assert(config->if0_worker_num + config->if1_worker_num == config->cpu_worker_num);
	config->gpu_worker_num = 1;

	config->I = 20; // ms
	//config->I = 44; // ms
	/* we take 50ms as parameter, for 10Gbps bandwidth,
	   50ms * 10Gbps = 0.05 * 10^10 bits ~= (<) 62.5 MB.
	   Take 64 bytes minimum packet size, at most 1 million jobs each batch,
	   we allocate 1000 jobs at most.
	   */
	/* 10Gbps * 20ms = 200Mb = 25MB, 4 worker, each with 6.25MB */
	config->batch_buf_max_size = 10 * 10e6; // byte
	config->batch_job_max_num = 10e5;

	config->eiu_hdr_len = 42; // eth+ip+udp header max size

	memcpy(config->interface_0, "xge0", sizeof("xge0"));
	memcpy(config->interface_1, "xge1", sizeof("xge1"));

	config->io_batch_num = 128;
	config->ifindex_0 = -1;
	config->ifindex_1 = -1;

	config->iterations = 20;
	config->log_sample_num = 100;
	return 0;
}

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

		total_rx_packets = (cc->handle).rx_packets[config->ifindex_0] + (cc->handle).rx_packets[config->ifindex_1];
		total_rx_bytes = (cc->handle).rx_bytes[config->ifindex_0] + (cc->handle).rx_bytes[config->ifindex_1];
		speed_handle += (double)(total_rx_bytes * 8) / (double) ((subtime.tv_sec * 1000000 + subtime.tv_usec) * 1000);

		printf("----------\n");
		if (total_rx_packets != 0) {
			printf("In handle: %ld packets received, elapse time : %lds, RX Speed : %lf Mpps, %5.2f Gbps, Aveage Len. = %ld\n", 
				total_rx_packets, subtime.tv_sec, 
				(double)(total_rx_packets) / (double) (subtime.tv_sec * 1000000 + subtime.tv_usec),
				(double)(total_rx_bytes * 8) / (double) ((subtime.tv_sec * 1000000 + subtime.tv_usec) * 1000),
				total_rx_bytes / total_rx_packets);
		}

		total_rx_packets = cc->total_packets;
		total_rx_bytes = cc->total_bytes;
		speed_actual += (double)(total_rx_bytes * 8) / (double) ((subtime.tv_sec * 1000000 + subtime.tv_usec) * 1000);
		if (total_rx_packets != 0) {
			printf("Actual: %ld packets received, elapse time : %lds, RX Speed : %lf Mpps, %5.2f Gbps, Aveage Len. = %ld\n", 
				total_rx_packets, subtime.tv_sec, 
				(double)(total_rx_packets) / (double) (subtime.tv_sec * 1000000 + subtime.tv_usec),
				(double)(total_rx_bytes * 8) / (double) ((subtime.tv_sec * 1000000 + subtime.tv_usec) * 1000),
				total_rx_bytes / total_rx_packets);
		}
	}

	printf("----------\n");
	printf("<<< IOEngine handle speed %lf, actual processing speed %lf >>>\n", speed_handle, speed_actual);

	exit(0);
}

void forwarder_handle_signal(int signal)
{
	int i;
	struct timeval subtime;
	uint64_t total_tx_packets = 0, total_tx_bytes = 0;;
	upro_forwarder_t *cc;
	double speed_handle = 0;
	double speed_actual = 0;

	for (i = 0; i < config->cpu_worker_num; i ++) {
		cc = &(forwarders[i]);

		gettimeofday(&(cc->endtime), NULL);
		timersub(&(cc->endtime), &(cc->startime), &(cc->subtime));
	}

	for (i = 0; i < config->cpu_worker_num; i ++) {
		cc = &(forwarders[i]);
		subtime = cc->subtime;

		total_tx_packets = (cc->handle).tx_packets[config->ifindex_0] + (cc->handle).tx_packets[config->ifindex_1];
		total_tx_bytes = (cc->handle).tx_bytes[config->ifindex_0] + (cc->handle).tx_bytes[config->ifindex_1];
		speed_handle += (double)(total_tx_bytes * 8) / (double) ((subtime.tv_sec * 1000000 + subtime.tv_usec) * 1000);

		printf("----------\n");
		if (total_tx_packets != 0) {
			printf("In handle: %ld packets Sent, elapse time : %lds, Send Speed : %lf Mpps, %5.2f Gbps, Aveage Len. = %ld\n", 
				total_tx_packets, subtime.tv_sec, 
				(double)(total_tx_packets) / (double) (subtime.tv_sec * 1000000 + subtime.tv_usec),
				(double)(total_tx_bytes * 8) / (double) ((subtime.tv_sec * 1000000 + subtime.tv_usec) * 1000),
				total_tx_bytes / total_tx_packets);
		}

		total_tx_packets = cc->total_packets;
		total_tx_bytes = cc->total_bytes;
		speed_actual += (double)(total_tx_bytes * 8) / (double) ((subtime.tv_sec * 1000000 + subtime.tv_usec) * 1000);
		if (total_tx_packets != 0) {
			printf("Actual: %ld packets Sent, elapse time : %lds, Send Speed : %lf Mpps, %5.2f Gbps, Aveage Len. = %ld\n", 
				total_tx_packets, subtime.tv_sec, 
				(double)(total_tx_packets) / (double) (subtime.tv_sec * 1000000 + subtime.tv_usec),
				(double)(total_tx_bytes * 8) / (double) ((subtime.tv_sec * 1000000 + subtime.tv_usec) * 1000),
				total_tx_bytes / total_tx_packets);
		}
	}

	printf("----------\n");
	printf("<<< IOEngine handle speed %lf, actual processing speed %lf >>>\n", speed_handle, speed_actual);

	exit(0);
}

/* Init config->ifindex_0, and config->ifindex_1 */
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
		if (strcmp(config->interface_0, devices[i].name) != 0)
			continue;
		ifindex = devices[i].ifindex;
		break;
	}
	assert(ifindex != -1);

	for (i = 0; i < num_devices_attached; i ++) {
		assert(devices_attached[i] != ifindex);
	}
	devices_attached[num_devices_attached] = ifindex;
	config->ifindex_0 = ifindex;
	num_devices_attached ++;


	/* server side interface */
	for (i = 0; i < num_devices; i ++) {
		if (strcmp(config->interface_1, devices[i].name) != 0)
			continue;
		ifindex = devices[i].ifindex;
		break;
	}
	assert(ifindex != -1);

	for (i = 0; i < num_devices_attached; i ++) {
		assert(devices_attached[i] != ifindex);
	}
	devices_attached[num_devices_attached] = ifindex;
	config->ifindex_1 = ifindex;
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

#if 0
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
#endif

int upro_launch_forwarders()
{
	unsigned int i;
	pthread_t tid;
	pthread_attr_t attr;
	upro_forwarder_context_t *context;

	for (i = 0; i < config->if0_worker_num; i ++) {
		/* pass a memory block to each worker */
		context = (upro_forwarder_context_t *)upro_mem_malloc(sizeof(upro_forwarder_context_t));

		context->queue_id = i;
		context->batch = &(batch_set[i]);
		context->ifindex = config->ifindex_0;
		context->id = i;

#if defined(AFFINITY_1)
		context->core_id = i + config->cpu_worker_num;
#elif defined(AFFINITY_2)
		context->core_id = i * 2 + 1;
#elif defined(AFFINITY_3)
		context->core_id = i * 2;
#elif defined(AFFINITY_4)
		int start = config->cpu_worker_num % 2 == 0 ? config->cpu_worker_num+1 : config->cpu_worker_num+2;
		context->core_id = i + start;
#endif

		pthread_attr_init(&attr);
		pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
		if (pthread_create(&tid, &attr, (void *)upro_forwarder_main, (void *)context) != 0) {
			assert(0);
		}
	}

#if 1
	/* if1_worker_num = cpu_worker_num - if0_worker_num */
	for (i = config->if0_worker_num; i < config->cpu_worker_num; i ++) {
		/* pass a memory block to each worker */
		context = (upro_forwarder_context_t *)upro_mem_malloc(sizeof(upro_forwarder_context_t));

		context->queue_id = i - config->if0_worker_num;
		context->batch = &(batch_set[i]);
		context->ifindex = config->ifindex_1;
		context->id = i;

#if defined(AFFINITY_1)
		context->core_id = i + config->cpu_worker_num;
#elif defined(AFFINITY_2)
		context->core_id = i * 2 + 1;
#elif defined(AFFINITY_3)
		context->core_id = i * 2;
#elif defined(AFFINITY_4)
		int start = config->cpu_worker_num % 2 == 0 ? config->cpu_worker_num+1 : config->cpu_worker_num+2;
		context->core_id = i + start;
#endif

		pthread_attr_init(&attr);
		pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
		if (pthread_create(&tid, &attr, (void *)upro_forwarder_main, (void *)context) != 0) {
			assert(0);
		}
	}
	return 0;
#endif
}

void dump(upro_collector_context_t *context)
{
	int ret;
	int queue_id = context->queue_id;

	upro_collector_t *cc = &(collectors[context->id]); 
	assert(ps_init_handle(&(cc->handle)) == 0);

	struct ps_queue queue;
	queue.ifindex = context->ifindex;
	queue.qidx = queue_id;
	printf("[Collector %d] is attaching if:queue %d:%d ...\n", context->id, queue.ifindex, queue.qidx);
	assert(ps_attach_rx_device(&(cc->handle), &queue) == 0);

	struct ps_chunk chunk;
	assert(ps_alloc_chunk(&(cc->handle), &chunk) == 0);
	chunk.recv_blocking = 1;

	gettimeofday(&(cc->startime), NULL);
	
	for (;;) {
		chunk.cnt = config->io_batch_num;

		ret = ps_recv_chunk(&(cc->handle), &chunk);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			assert(0);
		}

		cc->total_packets += ret;
		cc->total_bytes += ret * 1370;
		continue;
	}
}

int upro_launch_collectors(upro_collector_context_t **collector_context_set)
{
	unsigned int i;
	pthread_t tid;
	pthread_attr_t attr;
	upro_collector_context_t *context;

	for (i = 0; i < config->if0_worker_num; i ++) {
		/* pass a memory block to each worker */
		context = (upro_collector_context_t *)upro_mem_malloc(sizeof(upro_collector_context_t));
		collector_context_set[i] = context;

		context->queue_id = i;
		context->batch = &(batch_set[i]);
		context->ifindex = config->ifindex_0;
		context->id = i;

#if defined(AFFINITY_1)
		context->core_id = i;
#elif defined(AFFINITY_2)
		context->core_id = i * 2;
#elif defined(AFFINITY_3)
		context->core_id = i * 2 + 1;
#elif defined(AFFINITY_4)
		int start = 1;
		context->core_id = i + start;
#endif

		pthread_attr_init(&attr);
		pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
		if (pthread_create(&tid, &attr, (void *)upro_collector_main, (void *)context) != 0) {
		//if (pthread_create(&tid, &attr, (void *)dump, (void *)context) != 0) {
			assert(0);
		}
	}

#if 1
	for (i = config->if0_worker_num; i < config->cpu_worker_num; i ++) {
		/* pass a memory block to each worker */
		context = (upro_collector_context_t *)upro_mem_malloc(sizeof(upro_collector_context_t));
		collector_context_set[i] = context;

		context->queue_id = i - config->if0_worker_num;
		context->batch = &(batch_set[i]);
		context->ifindex = config->ifindex_1;
		context->id = i;

#if defined(AFFINITY_1)
		context->core_id = i;
#elif defined(AFFINITY_2)
		context->core_id = i * 2;
#elif defined(AFFINITY_3)
		context->core_id = i * 2 + 1;
#elif defined(AFFINITY_4)
		int start = 1;
		context->core_id = i + start;
#endif

		pthread_attr_init(&attr);
		pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
		if (pthread_create(&tid, &attr, (void *)upro_collector_main, (void *)context) != 0) {
		//if (pthread_create(&tid, &attr, (void *)dump, (void *)context) != 0) {
			assert(0);
		}
	}
#endif
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

#if defined(AFFINITY_4)
		context->core_id = 0;
#else
		context->core_id = 10;
#endif

		pthread_attr_init(&attr);
		pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
		if (pthread_create(&tid, &attr, (void *)upro_gpu_worker_main, (void *)context) != 0) {
			printf("pthread_create error!!\n");
			return -1;
		}
	}
	return 0;
}

int upro_parse_option(int argc, char*argv[])
{
	int opt;
	while((opt = getopt(argc, argv, "n:i:")) != -1) {
		switch(opt) {
		case 'i':
			config->I = atoi(optarg);
			printf("[ARG] Time interval is set to %d ms\n", config->I);
			break;
		case 'n':
			config->cpu_worker_num = atoi(optarg);
			assert(config->cpu_worker_num % 2 == 0);
			config->if0_worker_num = config->if1_worker_num = config->cpu_worker_num / 2;
			printf("[ARG] %d workers in total, with each interface %d worker\n", config->cpu_worker_num, config->if0_worker_num);
			break;
		}
	}

	return 0;
}

int main(int argc, char*argv[])
{
	int i, ready;
	upro_collector_context_t *collector_context;

	upro_init_config();
	upro_parse_option(argc, argv);
	upro_init_batch_set();
	upro_init_thread_keys();
	upro_init_ioengine();

	upro_collector_context_t **collector_context_set;
	collector_context_set = malloc(config->cpu_worker_num * sizeof(void *));

#if defined(COLLECTOR_PERFORMANCE_TEST)
	signal(SIGINT, collector_handle_signal);
#endif
	//signal(SIGINT, forwarder_handle_signal);

	/* Launch workers first*/
	upro_launch_collectors(collector_context_set);

#if !defined(COLLECTOR_PERFORMANCE_TEST)
	upro_launch_forwarders();

	/* Synchronization, Wait for CPU workers */
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
#endif

	while(1) sleep(60);
	return 0;
}
