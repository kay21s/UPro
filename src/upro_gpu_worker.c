#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <string.h>
#include <sched.h>

#include "upro_gpu_worker.h"
#include "upro_config.h"
#include "upro_memory.h"
#include "upro_macros.h"
#include "upro_job.h"
#include "upro_batch.h"
#include "upro_log.h"
#include "upro_timer.h"
#include "crypto_context.h"

extern upro_config_t *config;
extern pthread_mutex_t mutex_worker_init;

/* Get the buffer of each CPU worker at each time interval I */
void upro_gpu_get_batch(upro_gpu_worker_t *g, upro_batch_t *batch_set)
{
	int i;
	static int init = 0;
	upro_batch_t *batch;

	/* We calculate the next batch we will get,
	 * it  == batch->gpu_buf_id, so in some sense
	 * this is for debugging */
	g->cur_buf_id = (g->cur_buf_id + 1) % 3;

	/* Tell the CPU worker we are taking the batch */
	for (i = 0; i < config->cpu_worker_num; i ++) {
		batch = &(batch_set[i]);

		if (batch->buf_has_been_taken == -1) {

			assert(batch->gpu_buf_id == -1);
			assert(batch->available_buf_id != -1);

			batch->gpu_buf_id = batch->collector_buf_id;
			assert(batch->gpu_buf_id == g->cur_buf_id);

			/* Make a global notice on the batch struct that 
			 * the buf has been taken, and let the collector
			 * know the new available buffer transparently */
			pthread_mutex_lock(&(batch->mutex_collector_buf_id));
			batch->collector_buf_id = batch->available_buf_id;
			pthread_mutex_unlock(&(batch->mutex_collector_buf_id));

			/* For debugging */
			pthread_mutex_lock(&(batch->mutex_available_buf_id));
			if (batch->available_buf_id == 1 && init == 0) {
				/* For the first round, make buf 2 into the cycle */
				init = 1;
				batch->available_buf_id = 2;
			} else {
				batch->available_buf_id = -1;
			}
			pthread_mutex_unlock(&(batch->mutex_available_buf_id));
			
		} else {
			upro_err("error in upro_gpu_take_buf\n");
			exit(0);
		}

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

	for (i = 0; i < config->cpu_forwarder_num; i ++) {
		batch = &(batch_set[i]);

		if (batch->forwarder_buf_id == -1) {
			/* just for debug */
			batch->gpu_buf_id = -1;

			/* Give the buf to forwarder */
			pthread_mutex_lock(&(batch->mutex_forwarder_buf_id));
			batch->forwarder_buf_id = g->cur_buf_id;
			pthread_mutex_unlock(&(batch->mutex_forwarder_buf_id));
		} else {
			upro_err("error in upro_gpu_take_buf\n");
			exit(0);
		}
	}

	return ;
}

int upro_gpu_worker_init(upro_gpu_worker_t *g, upro_gpu_worker_context_t *context)
{
	int i, ready;
	upro_batch_t *batch_set = context->cpu_batch_set;
	upro_collector_context_t *collector_context_set = context->collector_context_set;
	int core_id = context->core_id;

	/* Set affinity of this gpu worker */
	mask = 1 << core_id;
	if (sched_setaffinity(0, sizeof(unsigned long), (cpu_set_t *)&mask) < 0) {
		upro_err("Err set affinity in GPU worker\n");
		exit(0);
	}

	/* Synchronization, Wait for CPU workers */
	while (1) {
		ready = 0;

		pthread_mutex_lock(&mutex_worker_init);
		for (i = 0; i < config->cpu_worker_num + config->cpu_forwarder_num; i ++) {
			if (collector_context_set[i].initialized)
				ready ++;
		}
		pthread_mutex_unlock(&mutex_worker_init);

		if (ready == config->cpu_worker_num) break;
		usleep(5000);
	}

	/* Init GPU buf set pointers */
	for (i = 0; i < 3; i ++) {
		g->bufs[i] = (upro_batch_buf_t **)malloc(config->cpu_worker_num * sizeof(upro_batch_buf_t **));
	}

	for (i = 0; i < 3; i ++) {
		for (j = 0; j < config->cpu_worker_num; j ++) {
			g->bufs[i][j] = &(batch_set[i].buf[j]);
		}
	}

	/* After waiting for I, we first take buffer set A (buf_id = 0), which has been filled with
	 * jobs by CPU workers.
	 * For Initialization in function upro_gpu_get_batch, it is to be +1%3, so the initilization
	 * value can be 2 or -1, to get batch 0.
	 */
	 g->cur_buf_id = 2; 

	
	/* Initialize variables in libgpucrypto */
	/* There is a one-to-one mapping from CPU Worker's UPRO_BATCH_T
	 * to GPU Worker's CUDA_STREAM_T
	 * The pinned memory buffers are in $batch$, while their corresponding
	 * device buffers are in $stream$
	 */
	uint32_t input_size = config->batch_buf_max_size +
		config->batch_job_max_num * AES_KEY_SIZE +
		config->batch_job_max_num * AES_IV_SIZE +
		config->batch_job_max_num * PKT_OFFSET_SIZE + // input buffer
		config->batch_job_max_num * PKT_LENGTH_SIZE +
		config->batch_job_max_num * HMAC_KEY_SIZE;
	uint32_t output_size = config->batch_buf_max_size;

	crypto_context_init(&(g->cry_ctx), input_size, output_size, config->cpu_worker_num);

	/* Tell the dispatcher that GPU worker is ready too */
	pthread_mutex_lock(&mutex_worker_init);
	sched_set[config->cpu_worker_num].initialized = 1;
	pthread_mutex_unlock(&mutex_worker_init);

	return 0;
}

/* created thread, all this calls are in the thread context */
void *upro_gpu_worker_main(void *context)
{
	upro_timer_t t, counter, loopcounter;
	upro_log_t log;
	int i, first, ready;
	unsigned long mask = 0;
	double elapsed_time;
	int cuda_stream_id;
	upro_batch_buf_t *buf;

	/* Init timers */
	upro_timer_init(&t);
	upro_timer_init(&counter);
	upro_timer_init(&loopcounter);
	upro_log_init(&log);

	/* Initialize GPU worker, we wait for that all CPU workers have been initialized
	 * then we can init GPU worker with the batches of CPU worker */
	upro_gpu_worker_t g;
	upro_gpu_worker_init(&g, (upro_gpu_worker_context_t *)context);

	/* Timers for each kernel launch */
	upro_timer_restart(&loopcounter);
	
	for (i = 0; i < config->iterations; i ++) {
		upro_log_loop_marker(&log);

		/* Counter for the whole loop, from the second loop */
		if (i == 2)	upro_timer_restart(&counter);

		// Wait for 'I', synchronization point
		//////////////////////////////////////////
		/* This is a CPU/GPU synchronization point, as all commands in the
		 * in-order queue before the preceding cl*Unmap() are now finished.
		 * We can accurately sample the per-loop timer here.
		 */
		first = 1;
		do {
			elapsed_time = upro_timer_get_elapsed_time(&loopcounter);
			if (first) {
				upro_log_msg(&log, "\n%s %d\n", "<<<<<<<<Elapsed Time : ", elapsed_time);
				first = 0;
			}

			if (elapsed_time - config->I > 1) { // surpassed the time point more than 1 ms
				upro_log_msg(&log, "\n%s %d\n", ">>>>>>>>Time point lost!!!! : ", elapsed_time);
				break;
			}
		} while (abs(elapsed_time - config->I) > 1);

		upro_log_msg(&log, "%s %d\n", ">>>>>>>>Time point arrived : ", elapsed_time);
		upro_timer_restart(&loopcounter);

		upro_timer_restart(&t);
		/* Get Input Buffer from CPU Workers */
		//////////////////////////////////////////
		upro_gpu_get_batch(&g, batch_set);
		upro_timer_stop(&t);
		upro_log_msg(&log, "\n%s\n", "---------------------------", 0);
		upro_log_timer(&log, "%s %f ms\n", "Get Input Time",
			upro_timer_get_total_time(&t), 10, 1);


		//Enqueue a kernel run call.
		//////////////////////////////////////////
		upro_timer_restart(&t);

		/* We launch each cpu worker batch as a stream*/
		for (cuda_stream_id = 0; cuda_stream_id < config->cpu_worker_num; cuda_stream_id ++) {
			buf = g.collector_cur_buf[cuda_stream_id];

			crypto_context_aes_sha1_encrypt (
				&(g.cry_ctx),
				buf->input_buf,
				buf->input_buf, // output_buf = input_buf, we do not allocate output now
				0, // in_pos
				buf->aes_key_pos,
				buf->aes_iv_pos,
				buf->hmac_key_pos,
				buf->pkt_offset_pos,
				buf->length_pos,
				buf->buf_size, // input buffer size
				buf->buf_length, // output buffer size
				buf->job_num,
				cuda_stream_id,
				128);

			/* Wait for transfer completion */
			crypto_context_sync(&(g.cry_ctx), cuda_stream_id, buf->input_buf, 1, 1);
		}

		upro_timer_stop(&t);
		upro_log_timer(&log, "%s %f ms\n", "Execution Time",
			upro_timer_get_total_time(&t), 10, 1);
		
		/* Tell the forwarders that this batch has been processed */
		//////////////////////////////////////////
		upro_gpu_give_to_forwarder(&g, batch_set);

		upro_log_msg(&log, "%s %dth iteration\n", "This is", i);
		//if (i > 1)	timeLog->Msg( "%s %f ms\n", "Time after is", counter.GetElapsedTime());
	}

	upro_timer_stop(&counter);
	printf("End of execution, now the program costs : %f ms\n", upro_timer_get_total_time(&counter));
	// FIXME:printf("Processing speed is %.2f Mbps\n", (bytes * 8) / (1e3 * upro_timer_get_total_time(&counter)));

	return 0;
}
