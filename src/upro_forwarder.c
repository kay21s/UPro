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
#include <linux/ip.h>

#include "upro_context.h"
#include "upro_config.h"
#include "upro_memory.h"
#include "upro_macros.h"
#include "upro_job.h"
#include "upro_batch.h"
#include "psio.h"

extern pthread_key_t worker_batch_struct;
extern upro_config_t *config;
extern pthread_mutex_t mutex_worker_init;

int upro_forwarder_init(upro_forwarder_context_t *context, struct ps_chunk *chunk, struct ps_handle *handle)
{
	upro_batch_t *batch = context->batch;
	unsigned long mask = 1 << context->core_id;

	/* set schedule affinity */
	if (sched_setaffinity(0, sizeof(unsigned long), (cpu_set_t *)&mask) < 0) {
		upro_err("Err set affinity in forwarder\n");
		assert(0);
	}

	/* set schedule policy */
	struct sched_param param;
	param.sched_priority = 99;
	pthread_setschedparam(pthread_self(), SCHED_FIFO, &param);

	batch->forwarder_buf_id = -1;
	
	/* Initialize ioengine */
	assert(ps_init_handle(handle) == 0);
	assert(ps_alloc_chunk(handle, chunk) == 0);
	chunk->recv_blocking = 1;
	chunk->queue.ifindex = config->server_ifindex;
	//chunk->queue.ifindex = config->client_ifindex;
	//chunk->queue.qidx = queue_id;

	pthread_setspecific(worker_batch_struct, (void *)batch);
	__builtin_prefetch(batch);
	__builtin_prefetch(&worker_batch_struct);

	pthread_mutex_lock(&mutex_worker_init);
	context->initialized = 1;
	pthread_mutex_unlock(&mutex_worker_init);

	return 0;
}

/* This function trigger write event of all the jobs in this batch */
int upro_forwarder_forwarding(int queue_id, struct ps_chunk *chunk, struct ps_handle *handle)
{
	int i, this_cnt, total_cnt;
	upro_job_t *this_job;
	upro_batch_t *batch = pthread_getspecific(worker_batch_struct);
	upro_batch_buf_t *buf = &(batch->buf[batch->forwarder_buf_id]);

	// printf("<<< [Forwarder %d] > gets %d packets to forward\n", queue_id, buf->job_num);
	if (buf->job_num == 0)	return -1;

	chunk->queue.qidx = queue_id;
	total_cnt = buf->job_num;

	while (total_cnt > 0) {
		this_cnt = total_cnt > PS_MAX_CHUNK_SIZE ? PS_MAX_CHUNK_SIZE : total_cnt;
		total_cnt -= this_cnt;

		for (i = 0; i < this_cnt; i ++) {
			this_job = &(buf->job_list[i]);

			chunk->info[i].offset = i * PS_MAX_PACKET_SIZE;
			chunk->info[i].len = this_job->pkt_length + this_job->hdr_length;
			//printf("%d ", this_job->pkt_length);

			/* Modify the ip header length, we assume it is ipv4 */
			struct iphdr *iph = (struct iphdr *)(this_job->pkt_ptr);
			iph->tot_len = this_job->pkt_length + this_job->hdr_length - 14;
			/* 14 is the ether header length, tot_len = IP + UDP + RTP */

			memcpy_aligned(chunk->buf + chunk->info[i].offset,
					this_job->hdr_ptr,
					this_job->hdr_length);
			memcpy_aligned(chunk->buf + chunk->info[i].offset + this_job->hdr_length,
					this_job->pkt_ptr,
					this_job->pkt_length);
		}

		chunk->cnt = this_cnt;
		assert(ps_send_chunk(handle, chunk) > 0);
	}

	//printf("<<< [Forwarder %d] finished forwarding %d\n", queue_id, batch->forwarder_buf_id);

	return 0;
}
inline int upro_forwarder_refresh_buffer(upro_batch_buf_t *buf)
{
	/* refresh collector_buf  */
	buf->job_num = 0;
	buf->buf_length = 0;
	buf->hdr_length = 0;

	return 0;
}

int upro_forwarder_give_available_buffer(int queue_id)
{
	upro_batch_t *batch = pthread_getspecific(worker_batch_struct);
	upro_batch_buf_t *buf = &(batch->buf[batch->forwarder_buf_id]);
	
	/* Make the buffer looks like new */
	upro_forwarder_refresh_buffer(buf);

	/* tell the collector that the buffer is available */
#if defined(USE_LOCK)
	pthread_mutex_lock(&(batch->mutex_available_buf_id));
	if (batch->available_buf_id[0] == -1) {
		batch->available_buf_id[0] = batch->forwarder_buf_id;
	} else if (batch->available_buf_id[1] == -1) {
		batch->available_buf_id[1] = batch->forwarder_buf_id;
	} else {
		printf("Three buffers available\n");
		assert(0);
	}
	pthread_mutex_unlock(&(batch->mutex_available_buf_id));

	//printf("<<< [Forwarder %d] < give available buffer %d\n", queue_id, batch->forwarder_buf_id);

	pthread_mutex_lock(&(batch->mutex_forwarder_buf_id));
	batch->forwarder_buf_id = -1;
	pthread_mutex_unlock(&(batch->mutex_forwarder_buf_id));
#else
	pthread_mutex_lock(&(batch->mutex_available_buf_id));
	if (batch->available_buf_id[0] == -1) {
		batch->available_buf_id[0] = batch->forwarder_buf_id;
	} else if (batch->available_buf_id[1] == -1) {
		batch->available_buf_id[1] = batch->forwarder_buf_id;
	} else {
		printf("Three buffers available\n");
		assert(0);
	}
	pthread_mutex_unlock(&(batch->mutex_available_buf_id));

	batch->forwarder_buf_id = -1;
#endif

	return 0;
}

int upro_forwarder_get_buffer()
{
	upro_batch_t *batch = pthread_getspecific(worker_batch_struct);

	/* wait for the gpu worker to give me the buffer ~~ */
	while(batch->forwarder_buf_id == -1) {
		//;
		usleep(1);
	}

	return 0;
}

void *upro_forwarder_main(upro_forwarder_context_t *context)
{
	//int queue_id = (context->core_id - 1) >> 1;
	int queue_id = context->queue_id;
	/* static variables */
	struct ps_chunk chunk;
	struct ps_handle handle;

	upro_forwarder_init(context, &chunk, &handle);
	printf("Forwarder on core %d is sending via queue %d ...\n", context->core_id, queue_id);

	while(1) {
		upro_forwarder_get_buffer();
		upro_forwarder_forwarding(queue_id, &chunk, &handle);
		upro_forwarder_give_available_buffer(queue_id);
	}

	exit(0);
}
