#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <string.h>
#include <sched.h>
#include <assert.h>
#include <signal.h>

#include "upro_gpu_worker.h"
#include "upro_context.h"
#include "upro_config.h"
#include "upro_memory.h"
#include "upro_macros.h"
#include "upro_job.h"
#include "upro_batch.h"
#include "upro_log.h"
#include "upro_timer.h"

#include "crypto_size.h"
#include "libgpucrypto.h"
#include <cuda_runtime.h>

extern upro_config_t *config;
extern pthread_mutex_t mutex_worker_init;

uint64_t total_packets = 0, total_bytes = 0;
upro_timer_t counter;

void handle_signal(int signal)
{
	upro_timer_stop(&counter);
	double subtime = upro_timer_get_total_time(&counter);
	total_bytes = total_packets * 1370; // FIXME

	printf("--------------------------------------------------\n");
	printf("%ld packets transmitted, elapse time : %lf ms, Send Speed : %lf Mpps, %5.2f Gbps\n\n", 
			total_packets, subtime,
			(double)(total_packets) / (double)(subtime * 1000),
			(double)(total_bytes*8) / (double)(subtime * 1000000));

	exit(0);
}

int upro_gpu_get_available_buf_id(upro_batch_t *batch)
{
	int id;

	assert(batch->available_buf_id[0] != -1);

#if defined(USE_LOCK)
	pthread_mutex_lock(&(batch->mutex_available_buf_id));
	id = batch->available_buf_id[0];
	batch->available_buf_id[0] = batch->available_buf_id[1];
	batch->available_buf_id[1] = -1; 
	pthread_mutex_unlock(&(batch->mutex_available_buf_id));
#else
	pthread_mutex_lock(&(batch->mutex_available_buf_id));
	id = batch->available_buf_id[0];
	batch->available_buf_id[0] = batch->available_buf_id[1];
	batch->available_buf_id[1] = -1; 
	pthread_mutex_unlock(&(batch->mutex_available_buf_id));
#endif
	return id;
}

/* Get the buffer of each CPU worker at each time interval I */
void upro_gpu_get_batch(upro_gpu_worker_t *g, upro_batch_t *batch_set)
{
	int i, available_buf_id;
	upro_batch_t *batch;

	/* We calculate the next batch we will get,
	 * it  == batch->gpu_buf_id, so in some sense
	 * this is for debugging */
	g->cur_buf_id = (g->cur_buf_id + 1) % 3;

	//printf("--- [GPU Worker] > get batch %d\n", g->cur_buf_id);

	/* Tell the CPU worker we are taking the batch */
	for (i = 0; i < config->cpu_worker_num; i ++) {
		batch = &(batch_set[i]);

		assert(batch->gpu_buf_id == -1);

		available_buf_id = upro_gpu_get_available_buf_id(batch);

		batch->gpu_buf_id = batch->collector_buf_id;
		assert(batch->gpu_buf_id == g->cur_buf_id);

		/* Let the collector know the new available buffer transparently */
#if defined(USE_LOCK)
		pthread_mutex_lock(&(batch->mutex_batch_launch));
		batch->collector_buf_id = available_buf_id;
		pthread_mutex_unlock(&(batch->mutex_batch_launch));
#else
		batch->collector_buf_id = available_buf_id;
#endif

		/* For statistic */
		g->total_bytes += g->bufs[g->cur_buf_id][i]->buf_length;
	}
	return ;
}

/* Tell the CPU forwarder that this batch has been completed */
void upro_gpu_give_to_forwarder(upro_gpu_worker_t *g, upro_batch_t *batch_set)
{
	int i;
	upro_batch_t *batch;

	for (i = 0; i < config->cpu_worker_num; i ++) {
		batch = &(batch_set[i]);
		batch->gpu_buf_id = -1;

		/* Wait for the forwarder to complete last batch forwarding */
		while (batch->forwarder_buf_id != -1) ;

		/* Give the buf to forwarder */
#if defined(USE_LOCK)
		pthread_mutex_lock(&(batch->mutex_forwarder_buf_id));
		batch->forwarder_buf_id = g->cur_buf_id;
		pthread_mutex_unlock(&(batch->mutex_forwarder_buf_id));
#else
		batch->forwarder_buf_id = g->cur_buf_id;
#endif
	}

	return ;
}

int upro_gpu_worker_init(upro_gpu_worker_t *g, upro_gpu_worker_context_t *context)
{
	int i, j;
	upro_batch_t *batch_set = context->cpu_batch_set;

	/* Set affinity of this gpu worker */
	unsigned long mask = 1 << context->core_id;
	if (sched_setaffinity(0, sizeof(unsigned long), (cpu_set_t *)&mask) < 0) {
		upro_err("Err set affinity in GPU worker\n");
		assert(0);
	}

	/* set schedule policy */
	struct sched_param param;
	param.sched_priority = 99;
	pthread_setschedparam(pthread_self(), SCHED_FIFO, &param);

	/* set signal processing function */
	signal(SIGINT, handle_signal);

	/* Init GPU buf set pointers */
	for (i = 0; i < 3; i ++) {
		g->bufs[i] = (upro_batch_buf_t **)malloc(config->cpu_worker_num * sizeof(upro_batch_buf_t *));
	}

	for (i = 0; i < 3; i ++) {
		for (j = 0; j < config->cpu_worker_num; j ++) {
			g->bufs[i][j] = &(batch_set[j].buf[i]);
		}
	}

	/* After waiting for I, we first take buffer set A (buf_id = 0), which has been filled with
	 * jobs by CPU workers.
	 * For Initialization in function upro_gpu_get_batch, it is to be +1%3, so the initilization
	 * value can be 2 or -1, to get batch 0.
	 */
	g->cur_buf_id = 2; 

	return 0;
}

#define MAX_GPU_STREAM 16

/* created thread, all this calls are in the thread context */
void *upro_gpu_worker_main(upro_gpu_worker_context_t *context)
{
	upro_timer_t t, loopcounter;
	upro_log_t log;
	int i, id = 0, start = 0;
	double elapsed_time;
	upro_batch_buf_t *buf;

	assert(config->cpu_worker_num <= 16);
	cudaStream_t stream[MAX_GPU_STREAM];
	for (i = 0; i < MAX_GPU_STREAM; i ++) {
		cudaStreamCreate(&stream[i]);
	}

	/* Init timers */
	upro_timer_init(&t); // For separate events
	upro_timer_init(&counter); // For the whole program
	upro_timer_init(&loopcounter); // For each loop
	upro_log_init(&log);

	/* Initialize GPU worker, we wait for that all CPU workers have been initialized
	 * then we can init GPU worker with the batches of CPU worker */
	upro_gpu_worker_t g;
	upro_gpu_worker_init(&g, context);

	printf("GPU Worker is working on core %d ...\n", context->core_id);

	/* Timers for each kernel launch */
	upro_timer_restart(&loopcounter);
	
	for (;;) {
	//for (i = 0; i < 10; i ++) {
		upro_log_loop_marker(&log);

		//////////////////////////////////////////
		/* This is a CPU/GPU synchronization point */
		do {
			elapsed_time = upro_timer_get_elapsed_time(&loopcounter);
			if (elapsed_time - config->I > 0.1) { // surpassed the time point more than 1 ms
				upro_log_msg(&log, "\n%s %lf\n", "--- [GPU Worker] Time point lost! : ", elapsed_time);
				// assert(0);
			}
		} while ((double)(config->I) - elapsed_time > 0.1);

		upro_log_msg(&log, "%s %lf\n", "--- [GPU Worker] Time point arrived : ", elapsed_time);
		//////////////////////////////////////////

		upro_timer_restart(&loopcounter);

		/* Get Input Buffer from CPU Workers */
		upro_gpu_get_batch(&g, context->cpu_batch_set);

		upro_timer_restart(&t);

		for (id = 0; id < config->cpu_worker_num; id ++) {
			buf = g.bufs[g.cur_buf_id][id];

			if (buf->job_num == 0) {
				continue;
			} else {
				printf("%d,", buf->job_num);
				if (upro_unlikely(start == 0))	{
					upro_timer_restart(&counter);
					start = 1;
				}
			}

			// FOR DEBUG 
			/*
			{
				int j;
				for (j = 0; j < buf->job_num; j ++) {
					assert(((uint16_t *)(buf->length_pos))[j] == 1328);
					assert(((uint32_t *)(buf->pkt_offset_pos))[j] == 1344 * j);
					uint64_t a = *(uint32_t *) ((uint8_t *)buf->input_buf + 1344 * j);
					assert(a == 0x01006080);
				}
				
			}
			*/


			/* Statistic */
			total_packets += buf->job_num;

#if defined(TRANSFER_SEPERATE)
			cudaMemcpyAsync(buf->input_buf_d, buf->input_buf, buf->buf_length, cudaMemcpyHostToDevice, stream[id]);
			cudaMemcpyAsync(buf->aes_key_pos_d, buf->aes_key_pos, AES_KEY_SIZE * buf->job_num, cudaMemcpyHostToDevice, stream[id]);
			cudaMemcpyAsync(buf->aes_iv_pos_d, buf->aes_iv_pos, AES_IV_SIZE * buf->job_num, cudaMemcpyHostToDevice, stream[id]);
			cudaMemcpyAsync(buf->pkt_offset_pos_d, buf->pkt_offset_pos, PKT_OFFSET_SIZE * buf->job_num, cudaMemcpyHostToDevice, stream[id]);
			cudaMemcpyAsync(buf->length_pos_d, buf->length_pos, PKT_LENGTH_SIZE * buf->job_num, cudaMemcpyHostToDevice, stream[id]);
			cudaMemcpyAsync(buf->hmac_key_pos_d, buf->hmac_key_pos, HMAC_KEY_SIZE * buf->job_num, cudaMemcpyHostToDevice, stream[id]);
#else
			cudaMemcpyAsync(buf->input_buf_d, buf->input_buf, alloc_size, cudaMemcpyHostToDevice, stream[id]);
#endif

			co_aes_sha1_gpu (
				buf->input_buf_d,
				buf->input_buf_d, // output_buf = input_buf, we do not allocate output now
				buf->aes_key_pos_d,
				buf->aes_iv_pos_d,
				buf->hmac_key_pos_d,
				buf->pkt_offset_pos_d,
				buf->length_pos_d,
				buf->job_num,
				NULL,
				256, // the library requires to initialize the T-box
				stream[id]);

			cudaMemcpyAsync(buf->input_buf, buf->input_buf_d, buf->buf_length, cudaMemcpyDeviceToHost, stream[id]);
		}

		cudaDeviceSynchronize();

		upro_timer_stop(&t);
		upro_log_msg(&log, "\n%s %lf ms\n", "--- [GPU Worker] Execution Time :", upro_timer_get_total_time(&t));
		
		/* Tell the forwarders that this batch has been processed */
		upro_gpu_give_to_forwarder(&g, context->cpu_batch_set);
	}

	upro_timer_stop(&counter);
	printf("End of execution, now the program costs : %f ms\n", upro_timer_get_total_time(&counter));
	// printf("Processing speed is %.2f Mbps\n", (bytes * 8) / (1e3 * upro_timer_get_total_time(&counter)));
	// upro_log_print(&log);

	return 0;
}
