#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>
#include <errno.h>
#include <stdint.h>

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <sys/time.h>

#include "upro_context.h"
#include "upro_collector.h"
#include "upro_config.h"
#include "upro_memory.h"
#include "upro_macros.h"
#include "upro_job.h"
#include "upro_batch.h"

#include "crypto_size.h"
#include "crypto_mem.h"
#include "psio.h"

pthread_key_t worker_batch_struct;
pthread_key_t collector;

extern upro_config_t *config;
extern pthread_mutex_t mutex_worker_init;

upro_collector_t collectors[MAX_WORKER_NUM];

int upro_collector_batch_init()
{
	int i;

	upro_batch_t *batch = pthread_getspecific(worker_batch_struct);
#if defined(TRANSFER_SEPERATE)
	unsigned char *device_input_buf;
	unsigned char *device_aes_key_pos;
	unsigned char *device_aes_iv_pos;
	unsigned char *device_pkt_offset_pos;
	unsigned char *device_length_pos;
	unsigned char *device_hmac_key_pos;

	cudaMalloc((void **)&(device_input_buf), config->batch_buf_max_size);
	cudaMalloc((void **)&(device_aes_key_pos), config->batch_job_max_num * AES_KEY_SIZE);
	cudaMalloc((void **)&(device_aes_iv_pos), config->batch_job_max_num * AES_IV_SIZE);
	cudaMalloc((void **)&(device_pkt_offset_pos), config->batch_job_max_num * PKT_OFFSET_SIZE);
	cudaMalloc((void **)&(device_length_pos), config->batch_job_max_num * PKT_LENGTH_SIZE);
	cudaMalloc((void **)&(device_hmac_key_pos), config->batch_job_max_num * HMAC_KEY_SIZE);

#else
	assert(0);
	uint32_t alloc_size = config->batch_buf_max_size +
		config->batch_job_max_num * config->eiu_hdr_len +
		config->batch_job_max_num * AES_KEY_SIZE +
		config->batch_job_max_num * AES_IV_SIZE +
		config->batch_job_max_num * PKT_OFFSET_SIZE + // input buffer
		config->batch_job_max_num * PKT_LENGTH_SIZE +
		config->batch_job_max_num * HMAC_KEY_SIZE;

	//printf("CUDA pinned memmory is to be allocated %d bytes\n", alloc_size);
	unsigned char *device_input_buf;
	cudaMalloc((void **)&(device_input_buf), alloc_size);
#endif

	for (i = 0; i < 3; i ++) {
#if defined(TRANSFER_SEPERATE)
		// 0x00 -- cudaHostAllocDefault, 0x04 -- cudaHostAllocWriteCombined
		cudaHostAlloc((void **)&(batch->buf[i].input_buf), config->batch_buf_max_size, 0x00);
		cudaHostAlloc((void **)&(batch->buf[i].aes_key_pos), config->batch_job_max_num * AES_KEY_SIZE, 0x04);
		cudaHostAlloc((void **)&(batch->buf[i].aes_iv_pos), config->batch_job_max_num * AES_IV_SIZE, 0x04);
		cudaHostAlloc((void **)&(batch->buf[i].pkt_offset_pos), config->batch_job_max_num * PKT_OFFSET_SIZE, 0x04);
		cudaHostAlloc((void **)&(batch->buf[i].length_pos), config->batch_job_max_num * PKT_LENGTH_SIZE, 0x04);
		cudaHostAlloc((void **)&(batch->buf[i].hmac_key_pos), config->batch_job_max_num * HMAC_KEY_SIZE, 0x04);
		/*
		batch->buf[i].input_buf = malloc(config->batch_buf_max_size);
		batch->buf[i].aes_key_pos = malloc(config->batch_job_max_num * AES_KEY_SIZE);
		batch->buf[i].aes_iv_pos = malloc(config->batch_job_max_num * AES_IV_SIZE);
		batch->buf[i].pkt_offset_pos = malloc(config->batch_job_max_num * PKT_OFFSET_SIZE);
		batch->buf[i].length_pos = malloc(config->batch_job_max_num * PKT_LENGTH_SIZE);
		batch->buf[i].hmac_key_pos = malloc(config->batch_job_max_num * HMAC_KEY_SIZE);
		*/

		batch->buf[i].hdr_buf = malloc(config->batch_job_max_num * config->eiu_hdr_len);

		*(int *)(batch->buf[i].input_buf) = 0;
		*(int *)(batch->buf[i].aes_key_pos) = 0;
		*(int *)(batch->buf[i].aes_iv_pos) = 0;
		*(int *)(batch->buf[i].length_pos) = 0;
		*(int *)(batch->buf[i].hmac_key_pos) = 0;

		batch->buf[i].input_buf_d = device_input_buf;
		batch->buf[i].aes_key_pos_d = device_aes_key_pos;
		batch->buf[i].aes_iv_pos_d = device_aes_iv_pos;
		batch->buf[i].pkt_offset_pos_d = device_pkt_offset_pos;
		batch->buf[i].length_pos_d = device_length_pos;
		batch->buf[i].hmac_key_pos_d = device_hmac_key_pos;
		
#else
		//cudaHostAlloc((void **)&(batch->buf[i].input_buf), alloc_size, cudaHostAllocDefault);
		batch->buf[i].input_buf = malloc(alloc_size);
		batch->buf[i].aes_key_pos = batch->buf[i].input_buf + config->batch_buf_max_size;
		batch->buf[i].aes_iv_pos = batch->buf[i].aes_key_pos + config->batch_job_max_num * AES_KEY_SIZE;
		batch->buf[i].pkt_offset_pos = batch->buf[i].aes_iv_pos + config->batch_job_max_num * AES_IV_SIZE;
		batch->buf[i].length_pos = batch->buf[i].pkt_offset_pos + config->batch_job_max_num * PKT_OFFSET_SIZE;
		batch->buf[i].hmac_key_pos = batch->buf[i].length_pos + config->batch_job_max_num * PKT_LENGTH_SIZE;

		batch->buf[i].input_buf_d = device_input_buf;

#endif
		batch->buf[i].job_list = upro_mem_malloc(config->batch_job_max_num * sizeof(upro_job_t));
		batch->buf[i].buf_size = config->batch_buf_max_size;
		batch->buf[i].buf_length = 0;
		batch->buf[i].job_num = 0;
	}

	batch->forwarder_buf_id = -1;
	batch->gpu_buf_id = -1;
	/* The collecotor buffer currently using is #0 */
	batch->collector_buf_id = 0;
	/* At first the available buf is #1 and #2 */
	batch->available_buf_id[0] = 1;
	batch->available_buf_id[1] = 2;
	
	assert(pthread_mutex_init(&(batch->mutex_forwarder_buf_id), NULL) == 0);
	assert(pthread_mutex_init(&(batch->mutex_available_buf_id), NULL) == 0);
	assert(pthread_mutex_init(&(batch->mutex_batch_launch), NULL) == 0);

	return 0;
}

int upro_collector_init(upro_collector_context_t *context)
{
	int i;

	upro_batch_t *batch = context->batch;
	pthread_setspecific(worker_batch_struct, (void *)batch);
	__builtin_prefetch(batch);
	__builtin_prefetch(&worker_batch_struct); 

	for (i = 0; i < config->cpu_worker_num; i ++) {
		collectors[i].total_packets = 0;
		collectors[i].total_bytes = 0;
	}
	
	/* Init collector batch */
	upro_collector_batch_init();

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

	pthread_mutex_lock(&mutex_worker_init);
	context->initialized = 1;
	pthread_mutex_unlock(&mutex_worker_init);

	return 0;
}

inline int upro_collector_get_attributes(char *aes_key[16], char *aes_iv[], char *hmac_key[])
{
	return 0;
}

inline uint64_t swap64(uint64_t v)
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
	static char aes_key[AES_KEY_SIZE], aes_iv[AES_IV_SIZE], hmac_key[HMAC_KEY_SIZE];
	upro_batch_t *batch = pthread_getspecific(worker_batch_struct);
	upro_batch_buf_t *buf = &(batch->buf[batch->collector_buf_id]);
	int pad_len, job_num = buf->job_num, hdr_len = pkt_len - payload_len;
	upro_job_t *new_job = &(buf->job_list[job_num]);

	/* Copy the TCP/IP packet into batch buffer */
	memcpy(buf->input_buf + buf->buf_length, payload_ptr, payload_len);
	memcpy(buf->hdr_buf + buf->hdr_length, pkt_ptr, hdr_len);

	/* Calculating the information for output buffer */
	new_job->payload_ptr = buf->input_buf + buf->buf_length;
	new_job->payload_length = ((payload_len + 3) & (~0x03)) + HMAC_TAG_SIZE; /* 4 bytes aligned + TAG, for forwarding */
	new_job->hdr_ptr = buf->hdr_buf + buf->hdr_length;
	new_job->hdr_length = hdr_len;

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
	pad_len = (payload_len + 8 + 1 + 63) & (~0x3F);
	*(uint8_t *)((buf->input_buf + buf->buf_length) + pad_len - 9) = 1 << 7;
	uint64_t len64 = swap64((uint64_t)payload_len);
	*(uint64_t *)((buf->input_buf + buf->buf_length) + pad_len - 8) = len64;

	/* The above 4 lines add padding for SHA-1 for GPU calculation,
	 * but in fact, these paddings are not real packet data, and will not be forwarded,
	 * however, there should be a authentication tag, i.e. SHA-1 result, be appended
	 * under the RTP packet, Is the previous padded length enough for it ?
	 * It is a bit tricky and we reserve it as follows :
	 */

	/* just now it is 64-byte aligned, HMAC_TAG_SIZE = 20 bytes
	 * so there needs another 12 bytes for 16-alignment
	 * pad_len = (pad_len+ SHA1_OUTPUT_SIZE + 16) & (~0x0F);
	 *
	 * In RFC 3711, page 6 : MKI(optional) and authentication tag are the only fields
	 * defined by SRTP that are not in RTP. Only 8-bit alignment is assumed.
	 */
	if (pad_len - payload_len < HMAC_TAG_SIZE) {
		pad_len = payload_len + HMAC_TAG_SIZE;
	}

	/* FIXME different alignment, 16 64? */
	/* pad the pad_len to be 64 bytes aligned for the next packet */
	if ((pad_len & 0x03F) != 0)
		pad_len = ((pad_len >> 6) + 1) << 6;

	assert(buf->buf_size - buf->buf_length > pad_len);
	//if (buf->buf_size - buf->buf_length > pad_len)
	//	return 0;

	/* Add the job */
	upro_collector_get_attributes((char **)&aes_key,(char **)&aes_iv, (char **)&hmac_key);

	memcpy((uint8_t *)(buf->aes_key_pos) + AES_KEY_SIZE * job_num, aes_key, AES_KEY_SIZE);
	memcpy((uint8_t *)(buf->aes_iv_pos) + AES_IV_SIZE * job_num, aes_iv, AES_IV_SIZE);
	((uint32_t *)(buf->pkt_offset_pos))[job_num] = buf->buf_length;
	((uint16_t *)(buf->length_pos))[job_num] = payload_len;
	memcpy((uint8_t *)(buf->hmac_key_pos) + HMAC_KEY_SIZE * job_num, hmac_key, HMAC_KEY_SIZE);

	/* Update batch parameters */
	buf->job_num ++;
	buf->buf_length += pad_len;
	buf->hdr_length += hdr_len;

	assert (buf->buf_length < buf->buf_size && buf->job_num < config->batch_job_max_num);

	return 0;
}

char *get_payload(char *ptr, int len, int *payload_len, int *udp, uint16_t *sport, uint16_t *dport)
{
	struct ethhdr *ethh;
	struct iphdr *iph;
	struct ip6_hdr *ip6h;
	struct udphdr *udph;
	struct tcphdr *tcph;
	uint8_t proto_in_ip = 0;
	char *payload_ptr;

	ethh = (struct ethhdr *)ptr;

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
		payload_ptr = (char *)tcph + tcph->doff * 4;
		*payload_len = len - (payload_ptr - ptr);
		break;
	case IPPROTO_UDP:
		payload_ptr = (char *)udph + 8;
		//FIXME: since the packet sent is not right, so this line is not correct
		//*payload_len = ntohs(udph->len); 
		*payload_len = len - (payload_ptr - ptr);
		*udp = 1;
		*sport = udph->source;
		*dport = udph->dest;
		break;
	default:
		printf("protocol %d ", proto_in_ip);
		break;
	}
done:
	return payload_ptr;
}

inline int established(uint16_t sport, uint16_t dport)
{
	return 1;
}

inline int forward_packet(char *ptr, int len)
{
	return 1;
}

/* if is filtered, */
inline int rtp_filter(int udp, uint16_t sport, uint16_t dport)
{
	if (udp) {
		if (established(sport, dport)) {
			return 0;
		}
	}
	return 1;
}

int process_packet(char *ptr, int len)
{
	int payload_len, ret, udp = 0;
	uint16_t sport, dport;
	char *payload_ptr;
	upro_batch_t *batch = pthread_getspecific(worker_batch_struct);

	/* Get the payload pointer and the length,
	 * and get rid of the ethernet header */
	payload_ptr = get_payload(ptr, len, &payload_len, &udp, &sport, &dport);

	/* if it is not rtp packets to be encrypted, it is forwarded directly */
	ret = rtp_filter(udp, sport, dport);
	if (ret) {
		forward_packet(ptr, len);
		assert(0);
		//printf("1");
		return 0;
	}

	assert(len == 1370);
	/* eth_hdr + ip_hdr + udp_hdr = 42 in general */
	assert(payload_len == len - 42);
	//printf("payload_len = %d, len = %d\n", payload_len, len);

	/* Lock, we do not permit GPU worker to enter */
	///////////////////////////////////////////////////////////
	pthread_mutex_lock(&(batch->mutex_batch_launch));
	/* Add this job into batch */
	upro_collector_job_add(ptr, len, payload_ptr, payload_len);
	pthread_mutex_unlock(&(batch->mutex_batch_launch));

	return 0;
}

int upro_collector_read(int queue_id)
{
	int ret, i;

	upro_collector_t *cc = &(collectors[queue_id]); 
	assert(ps_init_handle(&(cc->handle)) == 0);

	struct ps_queue queue;
	queue.ifindex = config->server_ifindex;
	queue.qidx = queue_id;
	assert(ps_attach_rx_device(&(cc->handle), &queue) == 0);
	printf("[Collector %d] is attaching if:queue %d:%d ...\n", queue_id, queue.ifindex, queue.qidx);

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
			if (!chunk.recv_blocking && errno == EWOULDBLOCK) {
				upro_err("!!! [Collector %d] : recv nothing\n", queue_id);
				assert(0);
			}
			assert(0);
		}

		assert(ret <= 128);

		cc->total_packets += ret;
		cc->total_bytes += ret * 1370;

#if defined(NOT_COLLECT)
		continue;
#endif

		for (i = 0; i < ret; i ++) {
			//assert(chunk.info[i].len == 1370);
			
			if (chunk.info[i].len == 1370) {
				process_packet(chunk.buf + chunk.info[i].offset, chunk.info[i].len);
			} else {
				upro_err("%d ", chunk.info[i].len);
				//assert(0);
			}
		}
	}
	return 0;
}

void *upro_collector_main(upro_collector_context_t *context)
{
	int queue_id = context->queue_id;
	printf("Collector on core %d, receiving queue %d ...\n", context->core_id, queue_id);
	upro_collector_init(context);
	upro_collector_read(queue_id);

	exit(0);
}
