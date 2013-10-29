#ifndef UPRO_BATCH_H
#define UPRO_BATCH_H

#include <pthread.h>
#include "upro_job.h"

typedef struct upro_batch_buf_s
{
	/* keys, pkt_offsets, and ivs, are all stored in the input buffer */
	void *input_buf;
	void *aes_key_pos;
	void *aes_iv_pos;
	void *pkt_offset_pos;
	void *length_pos; //length of RTP packet payload
	void *hmac_key_pos;
	
	void *input_buf_d;
	// void *output_buf_d;
	void *aes_key_pos_d;
	void *aes_iv_pos_d;
	void *pkt_offset_pos_d;
	void *length_pos_d; //length of RTP packet payload
	void *hmac_key_pos_d;

	// Job for forwarding
	upro_job_t *job_list;
	int job_num;

	int buf_size;
	int buf_length;

	void *hdr_buf;
	int hdr_length;
} upro_batch_buf_t;


/* Each CPU worker holds such a data structure */
typedef struct upro_batch_s
{
	upro_batch_buf_t buf[3];

	volatile int collector_buf_id;
	volatile int forwarder_buf_id;
	volatile int available_buf_id[2];
	int gpu_buf_id;

	/* GPU worker notify CPU worker 
	 * buf_has_been_taken tell CPU worker which buf has just been taken,
	 * processed_buf_id tell CPU worker which buf has been processed.
	 * they all should be -1, if there are no events.
	 * GPU write it (0/1), and CPU clears it to -1 to claim its own action.
	 */
	pthread_mutex_t mutex_forwarder_buf_id; 
	pthread_mutex_t mutex_available_buf_id; 
	pthread_mutex_t mutex_batch_launch; 
} upro_batch_t;

extern pthread_key_t worker_batch_struct;

#endif
