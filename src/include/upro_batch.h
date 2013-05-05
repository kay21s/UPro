#ifndef upro_BATCH_H
#define upro_BATCH_H

#include <pthread.h>
#include "upro_job.h"

typedef struct upro_batch_buf_s
{
	/* keys, pkt_offsets, and ivs, are all stored in the input buffer */
	void *input_buf;
	// void *output_buf;

	unsigned int aes_key_pos;
	unsigned int aes_iv_pos;
	unsigned int pkt_offset_pos;
	unsigned int length_pos; //length of RTP packet payload
	unsigned int hmac_key_pos;
	
	// Job for forwarding
	upro_job_t *job_list;
	int job_num;

	int buf_size;
	int buf_length;

} upro_batch_buf_t;


/* Each CPU worker holds such a data structure */
typedef struct upro_batch_s
{
	upro_batch_buf_t buf[3];

	/* Current buffer CPU worker is using */
	upro_batch_buf_t *collector_buf;

	unsigned int collector_buf_id;
	unsigned int forwarder_buf_id;
	unsigned int available_buf_id;
	unsigned int gpu_buf_id;

	/* GPU worker notify CPU worker 
	 * buf_has_been_taken tell CPU worker which buf has just been taken,
	 * processed_buf_id tell CPU worker which buf has been processed.
	 * they all should be -1, if there are no events.
	 * GPU write it (0/1), and CPU clears it to -1 to claim its own action.
	 */
	pthread_mutex_t mutex_forwarder_buf_id; 
	pthread_mutex_t mutex_collector_buf_id; 
	pthread_mutex_t mutex_available_buf_id; 
} upro_batch_t;

extern pthread_key_t worker_batch_struct;

#endif
