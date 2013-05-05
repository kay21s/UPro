#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <string.h>
#include <sched.h>

#include "upro_forwarder.h"
#include "upro_config.h"
#include "upro_memory.h"
#include "upro_macros.h"
#include "upro_job.h"
#include "upro_batch.h"
#include "psio.h"

int upro_forwarder_init(upro_forwarder_context_t *context)
{
	upro_batch_t *batch = context->batch;
	unsigned long mask = 1 << context->core_id;

	if (sched_setaffinity(0, sizeof(unsigned long), (cpu_set_t *)&mask) < 0) {
		upro_err("Err set affinity in forwarder\n");
		exit(0);
	}

	pthread_setspecific(worker_batch_struct, (void *)batch);
	__builtin_prefetch(batch);
	__builtin_prefetch(&worker_batch_struct);

	pthread_mutex_lock(&mutex_worker_init);
	context->initialized = 1;
	pthread_mutex_unlock(&mutex_worker_init);

	return 0;
}

/* This function trigger write event of all the jobs in this batch */
int upro_forwarder_forwarding(int queue_id)
{
	/* static variables */
	static struct ps_chunk chunk;
	static struct ps_handle handle;
	static int chunk_init = 0;

	char *base;
	hammer_job_t *this_job;
	upro_batch_t *batch = upro_sched_get_batch_struct(); 
	upro_batch_buf_t *buf = &(batch->buf[batch->forwarder_buf_id]);

	/* Only run on the first time */
	if (chunk_init == 0) {
		assert(ps_init_handle(&handle) == 0);
		assert(ps_alloc_chunk(&handle, &chunk) == 0);

		chunk.recv_blocking = 1;
		chunk.queue.ifindex = config->client_ifindex;
		chunk.queue.qidx = queue_id;

		chunk_init = 1;
	}

	/* get the base pointer for offset calculation */
	base = (buf->job_list[0])->pkt_ptr;

	for (i = 0; i < buf->job_num; i ++) {
		this_job = &(buf->job_list[i]);

		// TODO: chunk.info[i].offset = this_job->pkt_ptr - base;
		chunk.info[i].offset = i * PS_MAX_PACKET_SIZE;
		chunk.info[i].len = this_job->pkt_length;

		/* Modify the ip header length, we assume it is ipv4 */
		struct iphdr *iph = (struct iphdr *)this_job->pkt_ptr;
		iph->tot_len = this_job->pkt_length;

		memcpy_aligned(chunk.buf + chunk.info[i].offset,
						this_job->pkt_ptr,
						this_job->pkt_length);
	}

	assert(ps_send_chunk(&handle, chunk) > 0);

	return 0;
}

int upro_forwarder_refresh_buffer()
{
	upro_batch_t *batch = upro_sched_get_batch_struct(); 

	/* refresh collector_buf  */
	batch->collector_buf->job_num = 0;
	batch->collector_buf->buf_length = 0;
	assert(batch->collector_buf->job_list == NULL);

	return 0;
}

int upro_forwarder_give_available_buffer()
{
	upro_batch_t *batch = upro_sched_get_batch_struct(); 
	
	// debug
	assert(batch->available_buf_id == -1);

	/* Make the buffer looks like new */
	upro_forwarder_refresh_buffer();

	/* tell the collector that the buffer is available */
	pthread_mutex_lock(&(batch->mutex_available_buf_id));
	batch->available_buf_id = batch->forwarder_buf_id;
	pthread_mutex_unlock(&(batch->mutex_available_buf_id));

	pthread_mutex_lock(&(batch->mutex_forwarder_buf_id));
	batch->forwarder_buf_id = -1;
	pthread_mutex_unlock(&(batch->mutex_forwarder_buf_id));

	return 0;
}

int upro_forwarder_get_buffer()
{
	upro_batch_t *batch = upro_sched_get_batch_struct(); 

	/* wait for the gpu worker to give me the buffer ~~ */
	while(batch->forwarder_buf_id == -1)
		;
	
	return 0;
}

void upro_forwarder_main(upro_forwarder_context_t *context)
{
	upro_forwarder_init(context);

	while(1) {
		upro_forwarder_get_buffer();

		upro_forwarder_forwarding();

		upro_forwarder_give_available_buffer();
	}
}
