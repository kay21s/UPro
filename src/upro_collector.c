#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>

#include "upro_collector.h"
#include "upro_config.h"
#include "upro_memory.h"
#include "upro_macros.h"
#include "upro_job.h"
#include "upro_batch.h"
#include "crypto_size.h"
#include "psio.h"

//pthread_key_t worker_batch_struct;
extern upro_config_t *config;

int upro_collector_batch_init()
{
	int res;
	uint32_t alloc_size = config->batch_buf_max_size +
		config->batch_job_max_num * AES_KEY_SIZE +
		config->batch_job_max_num * AES_IV_SIZE +
		config->batch_job_max_num * PKT_OFFSET_SIZE + // input buffer
		config->batch_job_max_num * PKT_LENGTH_SIZE +
		config->batch_job_max_num * HMAC_KEY_SIZE;

	upro_batch_t *batch = upro_sched_get_batch_struct();
	
	for (i = 0; i < 3; i ++) {
		// batch->buf[i].output_buf = cuda_pinned_mem_alloc(config->batch_buf_max_size);
		batch->buf[i].input_buf = cuda_pinned_mem_alloc(alloc_size);

		batch->buf[i].aes_key_pos = config->batch_buf_max_size;
		batch->buf[i].aes_iv_pos = batch->buf[i].aes_key_pos + config->batch_job_max_num * AES_KEY_SIZE;
		batch->buf[i].pkt_offset_pos = batch->buf[i].aes_iv_pos + config->batch_job_max_num * AES_IV_SIZE;
		batch->buf[i].length_pos = batch->buf[i].pkt_offset_pos + config->batch_job_max_num * PKT_OFFSET_SIZE;
		batch->buf[i].hmac_key_pos = batch->buf[i].length_pos + config->batch_job_max_num * PKT_LENGTH_SIZE;

		batch->buf[i].job_list = upro_mem_malloc(config->batch_job_max_num * sizeof(upro_job_t));
		batch->buf[i].buf_size = config->batch_buf_max_size;
		batch->buf[i].buf_length = 0;
		batch->buf[i].job_num = 0;
	}

	batch->collector_buf = &(batch->buf[0]);
	batch->collector_buf_id = 0;
	batch->forwarder_buf_id = -1;
	batch->available_buf_id = 1;
	/* buf 2 is available in the first time, so we take some special measures */
	
	res = pthread_mutex_init(&(batch->mutex_forwarder_buf_id), NULL);
	if (res != 0) {
		perror("Mutex initialization failed");
		exit(EXIT_FAILURE);
	}

	res = pthread_mutex_init(&(batch->mutex_collector_buf_id), NULL);
	if (res != 0) {
		perror("Mutex initialization failed");
		exit(EXIT_FAILURE);
	}

	return 0;
}

int upro_collector_init(upro_collector_context_t *context)
{
	upro_batch_t *batch = context->batch;
	unsigned long mask = 1 << context->core_id;

	upro_collector_batch_init();

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

uint64_t swap64(uint64_t v)
{
	return	((v & 0x00000000000000ffU) << 56) |
			((v & 0x000000000000ff00U) << 48) |
			((v & 0x0000000000ff0000U) << 24) |
			((v & 0x00000000ff000000U) << 8)  |
			((v & 0x000000ff00000000U) >> 8)  |
			((v & 0x0000ff0000000000U) >> 24) |
			((v & 0x00ff000000000000U) >> 48) |
			((v & 0xff00000000000000U) >> 56);
}

/* The optional MKI fields after the SRTP payload is ignored, we only append SHA-1 tag */
int upro_collector_job_add(char *pkt_ptr, int pkt_len, char *payload_ptr, int payload_len)
{
	upro_batch_t *batch = upro_sched_get_batch_struct();
	int pad_len, job_num = batch->collector_buf->job_num;
	upro_job_t *new_job = &(batch->collector_buf->job_list[job_num]);
	upro_batch_buf_t *buf;
	void *base;

	/* Calculating the information for output buffer */
	new_job->pkt_ptr = batch->collector_buf->input_buf + batch->collector_buf->buf_length;
	new_job->payload_ptr = new->pkt_ptr + (pkt_len - payload_len);

	new_job->pkt_length = pkt_len + SHA1_OUTPUT_SIZE;
	new_job->payload_length = payload_len + SHA1_OUTPUT_SIZE;

	/* Pad SHA-1
	 * 1) data must be padded to 512 bits (64 bytes)
	 * 2) Padding always begins with one-bit 1 first (1 bytes)
	 * 3) Then zero or more bits "0" are padded to bring the length of 
	 *    the message up to 64 bits fewer than a multiple of 512.
	 * 4) Appending Length (8 bytes). 64 bits are appended to the end of the padded 
	 *    message to indicate the length of the original message in bytes
	 *    4.1) the length of the message is stored in big-endian format
	 *    4.2) Break the 64-bit length into 2 words (32 bits each).
	 *         The low-order word is appended first and followed by the high-order word.
	 *--------------------------------------------------------
	 *    data   |100000000000000000000000000000000Length|
	 *--------------------------------------------------------
	 */
	pad_len = (payload_len + 63 + 9) & (~0x3F);
	*(uint8_t *)(new_job->payload_ptr + payload_len) = 1 << 7;
	uint64_t len64 = swap64((uint64_t)payload_len);
	*(uint64_t *)(new_job->payload_ptr + pad_len- 8) = len64;

	/* The above 4 lines add padding for SHA-1 for GPU calculation,
	 * but in fact, these paddings are not real packet data, and will not be forwarded,
	 * however, there should be a authentication tag, i.e. SHA-1 result, be appended
	 * under the RTP packet, Is the previous padded length enough for it ?
	 * It is a bit tricky and we reserve it as follows :
	 */

	 /* just now it is 64-byte aligned, SHA1_OUTPUT_SIZE = 20 bytes
	 * so there needs another 12 bytes for 16-alignment
	 * pad_len = (pad_len+ SHA1_OUTPUT_SIZE + 16) & (~0x0F);
	 * FIXME: is this padding needed? I have forgotten.
	 *
	 * In RFC 3711, page 6 : MKI(optional) and authentication tag are the only fields
	 * defined by SRTP that are not in RTP. Only 8-bit alignment is assumed.
	 */

	if (pad_len - payload_len < SHA1_OUTPUT_SIZE) {
		pad_len = payload_len + SHA1_OUTPUT_SIZE;
	}

	/* Update batch parameters */
	batch->collector_buf->job_num ++;
	batch->collector_buf->buf_length += pad_len;

	if (batch->collector_buf->buf_length >= batch->collector_buf->buf_size ||
			batch->collector_buf->job_num >= config->batch_job_max_num) {
		upro_err("error in batch job add\n");
		exit(0);
	}

	/* Add the job to the batch job list */
	upro_list_add(&(new_job->_head), batch->job_list);

	buf = batch->collector_buf;
	/* Add aes_key to the input buffer */
	base = buf->input_buf + buf->aes_key_pos;
	memcpy((uint8_t *)base + AES_KEY_SIZE * job_num, c->aes_key, AES_KEY_SIZE);
	/* iv */
	base = buf->input_buf + buf->aes_iv_pos;
	memcpy((uint8_t *)base + AES_IV_SIZE * job_num, c->iv, AES_IV_SIZE);
	/* pkt_offset */
	base = buf->input_buf + buf->pkt_offset_pos;
	((uint32_t *)base)[job_num] = batch->collector_buf->buf_length + (pkt_len - payload_len);
	/* payload length */
	base = buf->input_buf + buf->length_pos;
	((uint16_t *)base)[job_num] = payload_len;
	/* hmac key */
	base = buf->input_buf + buf->hmac_key_pos;
	memcpy((uint8_t *)base + HMAC_KEY_SIZE * job_num, c->hmac_key, HMAC_KEY_SIZE);

	return 0;
}

char *get_payload(char *ptr, int *len, int *payload_len, int *udp, uint16_t *sport, uint16_t *dport)
{
	struct ethhdr *ethh;
	struct iphdr *iph;
	struct ip6_hdr *ip6h;
	struct udphdr *udph;
	struct tcphdr *tcph;
	uint8_t proto_in_ip = 0;
	char *payload;

	ethh = (struct ethhdr *)buf;

	/* Skip the ethernet header */
	ptr = (char *)(ethh + 1);
	*len = *len - sizeof(struct ethhdr);
	
	/* IP layer */
	switch (ntohs(ethh->h_proto)) {
	case ETH_P_IP:
		iph = (struct iphdr *)(ethh + 1);
		proto_in_ip = iph->protocol;
		udph = (struct udphdr *)((uint32_t *)iph + iph->ihl);
		tcph = (struct tcphdr *)((uint32_t *)iph + iph->ihl);
		break;
	case ETH_P_IPV6:
		ip6h = (struct ip6_hdr *)(ethh + 1);
		proto_in_ip = ip6h->ip6_nxt;
		udph = (struct udphdr *)((uint8_t *)ip6h + ip6h->ip6_plen);
		tcph = (struct tcphdr *)((uint8_t *)ip6h + ip6h->ip6_plen);
		break;
	default:
		printf("protocol %04hx  ", ntohs(ethh->h_proto));
		goto done;
	}

	/* Transport layer */
	switch (proto_in_ip) {
	case IPPROTO_TCP:
		payload = (char *)tcph + tcph->doff * 4;
		*payload_len = len - (payload - ptr);
		break;
	case IPPROTO_UDP:
		payload = (char *)udph + 8;
		*payload_len = ntohs(udph->len);
		*udp = 1;
		*sport = udph->source;
		*dport = udph->dest;
		break;
	default:
		printf("protocol %d ", proto_in_ip);
		break;
	}
done:
	return payload;
}

int established(uint16_t sport, uint16_t dport)
{
	return 1;
}

int forward_packet(char *ptr, int len)
{
	return 1;
}

/* if is filtered, */
void rtp_filter(char *ptr, int len, int udp, uint16_t sport, uint16_t dport)
{
	if (udp) {
		if (established(sport, dport)) {
			return 0;
		}
	} else {
		forward_packet(ptr, len);
		return 1;
	}
}

int process_packet(char *ptr, int len)
{
	int payload_len, ret, available;
	uint16_t sport, dport, udp = 0;
	char *payload_ptr;
	upro_batch_t *batch = upro_sched_get_batch_struct();

	/* Get the payload pointer and the length,
	 * and get rid of the ethernet header */
	payload_ptr = get_payload(ptr, &len, &payload_len, &udp, &sport, &dport);

	// if it is not rtp packets to be encrypted, it is forwarded directly
	ret = rtp_filter(ptr, len, udp, sport, dport);
	if (ret)
		return ret;

	/* Lock, we do not permit GPU worker to enter */
	///////////////////////////////////////////////////////////
	pthread_mutex_lock(&(batch->mutex_batch_launch));

	batch->collector_buf = batch->buf[batch->collector_buf_id];
	
	available = batch->collector_buf->buf_size - batch->collector_buf->buf_length;
	if (available < len) {
		upro_err("small available buffer!\n");
		exit(0);
	}

	memcpy(batch->collector_buf->input_buf + batch->collector_buf->buf_length, ptr, len);

	/* Batch this job */
	upro_collector_job_add(ptr, len, payload_ptr, payload_len);

	/* Unlock, Now gpu worker has completed this read, GPU can launch this batch */
	///////////////////////////////////////////////////////////
	pthread_mutex_unlock(&(batch->mutex_batch_launch));

	return 0;
}

int upro_collector_read(int queue_id)
{
	int ret;
	struct ps_chunk chunk;
	struct ps_handle handle;

	assert(ps_init_handle(&handle) == 0);
	assert(ps_alloc_chunk(&handle, &chunk) == 0);

	chunk.recv_blocking = 1;
	chunk.queue.ifindex = config->server_ifindex;
	chunk.queue.qidx = queue_id;

	for (;;) {
		chunk.cnt = config->io_batch_num;
		ret = ps_recv_queue(&handle, &chunk);

		if (ret < 0) {
			if (errno == EINTR)
				continue;

			if (!chunk.recv_blocking && errno == EWOULDBLOCK)
				break;

			exit(0);
		}

		for (i = 0; i < chunk.cnt; i ++) {
			process_packet(chunk.buf + chunk.info[i].offset, chunk.info[i].len);
		}
	}
}

void upro_collector_main(upro_collector_context_t *context)
{
	upro_collector_init(context);
	upro_collector_read(context->core_id);
}
