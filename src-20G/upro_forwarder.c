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
#include "upro_forwarder.h"
#include "upro_config.h"
#include "upro_memory.h"
#include "upro_macros.h"
#include "upro_job.h"
#include "upro_batch.h"

#include "psio.h"
#include "memcpy.h"

extern pthread_key_t worker_batch_struct;
extern upro_config_t *config;
extern pthread_mutex_t mutex_worker_init;

upro_forwarder_t forwarders[MAX_WORKER_NUM];

int upro_forwarder_init(upro_forwarder_context_t *context)
{
	int i;
	upro_batch_t *batch = context->batch;

	for (i = 0; i < config->cpu_worker_num; i ++) {
		forwarders[i].total_packets = 0;
		forwarders[i].total_bytes = 0;
	}

#if defined(CPU_AFFINITY)
	/* set schedule affinity */
	unsigned long mask = 1 << context->core_id;
	if (sched_setaffinity(0, sizeof(unsigned long), (cpu_set_t *)&mask) < 0) {
		assert(0);
	}

	/* set schedule policy */
	struct sched_param param;
	param.sched_priority = 99;
	pthread_setschedparam(pthread_self(), SCHED_FIFO, &param);
#endif

	batch->forwarder_buf_id = -1;
	
	pthread_setspecific(worker_batch_struct, (void *)batch);
	__builtin_prefetch(batch);
	__builtin_prefetch(&worker_batch_struct);

	pthread_mutex_lock(&mutex_worker_init);
	context->initialized = 1;
	pthread_mutex_unlock(&mutex_worker_init);

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
	batch->forwarder_buf_id = -1;
#else
	if (batch->available_buf_id[0] == -1) {
		batch->available_buf_id[0] = batch->forwarder_buf_id;
	} else if (batch->available_buf_id[1] == -1) {
		batch->available_buf_id[1] = batch->forwarder_buf_id;
	} else {
		printf("Three buffers available\n");
		assert(0);
	}

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

/* This function trigger write event of all the jobs in this batch */
int upro_forwarder_forwarding(int queue_id, int ifindex, int forwarder_id)
{
	int i, this_cnt, total_cnt, ret = config->io_batch_num;
	upro_job_t *this_job;
	upro_batch_t *batch = pthread_getspecific(worker_batch_struct);
	upro_batch_buf_t *buf = &(batch->buf[batch->forwarder_buf_id]);

	/* Initialize ioengine */
	upro_forwarder_t *cc = &(forwarders[forwarder_id]);
	assert(ps_init_handle(&(cc->handle)) == 0);

	struct ps_chunk chunk;
	assert(ps_alloc_chunk(&(cc->handle), &chunk) == 0);

	chunk.recv_blocking = 1;
	chunk.queue.ifindex = ifindex;
	chunk.queue.qidx = queue_id;
	chunk.cnt = config->io_batch_num;

	gettimeofday(&(cc->startime), NULL);

#if 1
	for (;;) {
		/* Get buffer first */
		upro_forwarder_get_buffer();
		
#if defined(NOT_FORWARD)
		upro_forwarder_give_available_buffer(queue_id);
		continue;
#endif

		batch = pthread_getspecific(worker_batch_struct);
		buf = &(batch->buf[batch->forwarder_buf_id]);

		// printf("<<< [Forwarder %d] > gets %d packets to forward\n", queue_id, buf->job_num);
		if (buf->job_num == 0) {
			upro_forwarder_give_available_buffer(queue_id);
			continue;
		}

		total_cnt = buf->job_num;

		while (total_cnt > 0) {
			this_cnt = total_cnt > 128 ? 128 : total_cnt;

			/*
			this_job = &(buf->job_list[0]);
			struct iphdr *iph = (struct iphdr *)((uint8_t *)(this_job->hdr_ptr) + 14);
			iph->tot_len = this_job->payload_length + this_job->hdr_length - 14;
			*/

			for (i = 0; i < this_cnt; i ++) {
#if 1
				this_job = &(buf->job_list[i]);
				struct iphdr *iph = (struct iphdr *)((uint8_t *)(this_job->hdr_ptr) + 14);
				iph->tot_len = this_job->payload_length + this_job->hdr_length - 14;

				/* Modify the ip header length, we assume it is ipv4 */
				/* 14 is the ether header length, tot_len = IP + UDP + RTP */
				memcpy_aligned(chunk.buf + chunk.info[i].offset,
						this_job->hdr_ptr,
						this_job->hdr_length);
				memcpy_aligned(chunk.buf + chunk.info[i].offset + this_job->hdr_length,
						this_job->payload_ptr,
						this_job->payload_length);

				chunk.info[i].offset = i * PS_MAX_PACKET_SIZE;
				chunk.info[i].len = this_job->payload_length + this_job->hdr_length;
#endif
			}

			chunk.cnt = this_cnt;
			ret = ps_send_chunk(&(cc->handle), &chunk);
			assert(ret >= 0);

			cc->total_packets += ret;
			cc->total_bytes += ret * 1370;

			total_cnt -= ret;
		}

		/* Give available buffer */
		upro_forwarder_give_available_buffer(queue_id);
	}
#else
	for (;;) {
		/* Get buffer first */
		upro_forwarder_get_buffer();
		
#if defined(NOT_FORWARD)
		upro_forwarder_give_available_buffer(queue_id);
		continue;
#endif

		batch = pthread_getspecific(worker_batch_struct);
		buf = &(batch->buf[batch->forwarder_buf_id]);

		// printf("<<< [Forwarder %d] > gets %d packets to forward\n", queue_id, buf->job_num);
		if (buf->job_num == 0) {
			upro_forwarder_give_available_buffer(queue_id);
			continue;
		}

		total_cnt = buf->job_num;

		while (total_cnt > 0) {
			chunk.cnt = total_cnt > config->io_batch_num ? config->io_batch_num : total_cnt;
			this_cnt = ret; /* not all packets in last batch are forwarded, we do
			not to copy chunk.cnt packets again, since there are still chunk.cnt - ret packets left*/

			/*
			this_job = &(buf->job_list[0]);
			struct iphdr *iph = (struct iphdr *)((uint8_t *)(this_job->hdr_ptr) + 14);
			iph->tot_len = this_job->payload_length + this_job->hdr_length - 14;
			*/

			for (i = 0; i < this_cnt; i ++) {
#if 1
				this_job = &(buf->job_list[i]);
				struct iphdr *iph = (struct iphdr *)((uint8_t *)(this_job->hdr_ptr) + 14);
				iph->tot_len = this_job->payload_length + this_job->hdr_length - 14;

				/* Modify the ip header length, we assume it is ipv4 */
				/* 14 is the ether header length, tot_len = IP + UDP + RTP */
				memcpy_aligned(chunk.buf + chunk.info[i].offset,
						this_job->hdr_ptr,
						this_job->hdr_length);
				memcpy_aligned(chunk.buf + chunk.info[i].offset + this_job->hdr_length,
						this_job->payload_ptr,
						this_job->payload_length);

				chunk.info[i].offset = i * PS_MAX_PACKET_SIZE;
				chunk.info[i].len = this_job->payload_length + this_job->hdr_length;
#endif
			}

			ret = ps_send_chunk(&(cc->handle), &chunk);
			assert(ret >= 0);

			total_cnt -= ret;
		}

		cc->total_packets += buf->job_num;
		cc->total_bytes += buf->job_num * 1370;

		/* Give available buffer */
		upro_forwarder_give_available_buffer(queue_id);
	}
#endif

	return 0;
}

void *upro_forwarder_main(upro_forwarder_context_t *context)
{
	printf("Forwarder on core %d is sending via ifindex:queue %d:%d ...\n", context->core_id, context->ifindex, context->queue_id);
	upro_forwarder_init(context);
	upro_forwarder_forwarding(context->queue_id, context->ifindex, context->id);

	exit(0);
}
