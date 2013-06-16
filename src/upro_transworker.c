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

#include "upro_transworker.h"
#include "upro_config.h"
#include "upro_memory.h"
#include "upro_macros.h"
#include "upro_batch.h"
#include "psio.h"

extern upro_config_t *config;
extern pthread_mutex_t mutex_worker_init;

int upro_transworker_init(upro_transworker_context_t *context)
{
	unsigned long mask = 1 << context->core_id;

	if (sched_setaffinity(0, sizeof(unsigned long), (cpu_set_t *)&mask) < 0) {
		upro_err("Err set affinity in transworker\n");
		exit(0);
	}

	pthread_mutex_lock(&mutex_worker_init);
	context->initialized = 1;
	pthread_mutex_unlock(&mutex_worker_init);

	return 0;
}

void upro_transworker_main(upro_transworker_context_t *context)
{
	struct ps_handle handle;
	struct ps_chunk chunk;
	struct ps_queue queue;
	int ret, i;

	upro_transworker_init(context);

	/* handle and queue init */
	assert(ps_init_handle(&handle) == 0);
	
	/* attach all the queue in the client side */
	for (i = 0; i < config->client_device.num_rx_queues; i ++) {
		queue.ifindex = config->client_ifindex;
		queue.qidx = i;
		assert(ps_attach_rx_device(&handle, &queue) == 0);
	}

	assert(ps_alloc_chunk(&handle, &chunk) == 0);
	chunk.recv_blocking = 1;

	printf("Transworker is working ...\n");

	/* receive and forward */
	for (;;) {
		chunk.cnt = 16;
		chunk.queue.ifindex = config->client_ifindex;

		ret = ps_recv_chunk(&handle, &chunk);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			if (!chunk.recv_blocking && errno == EWOULDBLOCK)
				break;
			assert(0);
		}

		chunk.cnt = ret;
		chunk.queue.ifindex = config->server_ifindex;

		ret = ps_send_chunk(&handle, &chunk);
		assert(ret >= 0);
	}

	return;
}
