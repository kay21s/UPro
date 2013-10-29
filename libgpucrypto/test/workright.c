#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <cuda_runtime.h>

#include "crypto_size.h"
#include "libgpucrypto.h"

//4096 8192 16384 32768 65536
//10G from 10ms->50ms : 9124, 18248, 27372, 36496, 45620
//#define NUM_FLOWS 9124
//#define NUM_FLOWS 8000
//#define NUM_FLOWS 16384
#define THREADS_PER_BLK 256
#define MEMORY_ALIGNMENT  4096
#define ALIGN_UP(x,size) ( ((size_t)x+(size-1))&(~(size-1)) )
#define MAX_GPU_STREAM 16

//#define KERNEL_TEST 1

int main(int argc, char*argv[])
{
	FILE *fp;
	uint16_t i, fsize, pad_size, stream_id;
	char * rtp_pkt;
	uint8_t default_aes_keys[AES_KEY_SIZE], default_ivs[AES_IV_SIZE], default_hmac_keys[HMAC_KEY_SIZE];

	struct  timespec start, end;
#if defined(KERNEL_TEST)
	struct  timespec kernel_start, kernel_end;
#endif


	cudaEvent_t startE, stopE;
    cudaEventCreate(&startE);
    cudaEventCreate(&stopE);


	uint32_t NUM_FLOWS, STREAM_NUM;
	if (argc > 2) {
		NUM_FLOWS = atoi(argv[1]);
		STREAM_NUM = atoi(argv[2]);
	} else {
		NUM_FLOWS = 8192;
		STREAM_NUM = 1;
	}
	//printf ("Num of flows is %d, stream num is %d\n", NUM_FLOWS, STREAM_NUM);

	cudaStream_t stream[STREAM_NUM];
	for (i = 0; i < STREAM_NUM; i ++) {
		cudaStreamCreate(&stream[i]);
	}

	uint8_t * host_in,*device_in[STREAM_NUM];
	uint8_t * host_aes_keys,* device_aes_keys[STREAM_NUM];
	uint8_t * host_ivs,* device_ivs[STREAM_NUM];
	uint8_t * host_hmac_keys,*device_hmac_keys[STREAM_NUM];
	uint32_t * host_pkt_offset,*device_pkt_offset[STREAM_NUM];
	uint16_t * host_actual_length,*device_actual_length[STREAM_NUM];
       
	double diff;
	uint8_t a = 123;

	fp = fopen("rtp.pkt", "rb");
	fseek(fp, 0, SEEK_END);
	// NOTE: fsize should be 1356 bytes
	//fsize = ftell(fp);
	fsize = 1328;
	fseek(fp, 0, SEEK_SET);

	rtp_pkt = (char *)calloc(fsize, sizeof(char));
	fread(rtp_pkt, fsize, sizeof(char), fp);

	pad_size = (fsize + 63 + 9) & (~0x03F);

	//printf("the original package is %d bytes,now we pad it to %d bytes\n", fsize, pad_size);

	for (i = 0; i < AES_KEY_SIZE; i ++)
		default_aes_keys[i] = a;
	for (i = 0; i < AES_IV_SIZE; i ++)
		default_ivs[i] = a;
	for (i = 0; i < HMAC_KEY_SIZE; i ++)
		default_hmac_keys[i] = a;

	//printf("duplicate it %d times, takes %d bytes\n",NUM_FLOWS,pad_size*NUM_FLOWS);
	cudaHostAlloc((void **)&host_in, pad_size * NUM_FLOWS * sizeof(uint8_t), cudaHostAllocDefault);
	cudaHostAlloc((void **)&host_aes_keys, NUM_FLOWS * AES_KEY_SIZE, cudaHostAllocWriteCombined);
	cudaHostAlloc((void **)&host_ivs, NUM_FLOWS * AES_IV_SIZE, cudaHostAllocWriteCombined);
	cudaHostAlloc((void **)&host_hmac_keys, NUM_FLOWS * HMAC_KEY_SIZE, cudaHostAllocWriteCombined);
	cudaHostAlloc((void **)&host_pkt_offset, NUM_FLOWS * PKT_OFFSET_SIZE, cudaHostAllocWriteCombined);
	cudaHostAlloc((void **)&host_actual_length, NUM_FLOWS * PKT_LENGTH_SIZE, cudaHostAllocWriteCombined);

	for (i = 0; i < NUM_FLOWS; i ++){
		memcpy(host_in + i * pad_size, rtp_pkt, fsize * sizeof(uint8_t));
		memcpy((uint8_t *)host_aes_keys + i * AES_KEY_SIZE, default_aes_keys, AES_KEY_SIZE);
		memcpy((uint8_t *)host_ivs + i * AES_IV_SIZE, default_ivs, AES_IV_SIZE);
		memcpy((uint8_t *)host_hmac_keys + i * HMAC_KEY_SIZE, default_hmac_keys, HMAC_KEY_SIZE);
		host_pkt_offset[i] = i * pad_size;
		host_actual_length[i] = fsize;
	}

	for (i = 0; i < STREAM_NUM; i ++) {
		cudaMalloc((void **)&(device_in[i]), pad_size * NUM_FLOWS * sizeof(uint8_t));
		cudaMalloc((void **)&(device_aes_keys[i]), NUM_FLOWS * AES_KEY_SIZE);
		cudaMalloc((void **)&(device_ivs[i]), NUM_FLOWS * AES_IV_SIZE);
		cudaMalloc((void **)&(device_hmac_keys[i]), NUM_FLOWS * HMAC_KEY_SIZE);
		cudaMalloc((void **)&(device_pkt_offset[i]), NUM_FLOWS * PKT_OFFSET_SIZE);
		cudaMalloc((void **)&(device_actual_length[i]), NUM_FLOWS * PKT_LENGTH_SIZE);
	}

	/* warm up */
	for (stream_id = 0; stream_id < STREAM_NUM; stream_id ++) {
		cudaMemcpyAsync(device_in[stream_id], host_in, pad_size * NUM_FLOWS * sizeof(uint8_t), cudaMemcpyHostToDevice, stream[stream_id]);
		cudaMemcpyAsync(device_aes_keys[stream_id], host_aes_keys, NUM_FLOWS * AES_KEY_SIZE, cudaMemcpyHostToDevice, stream[stream_id]);
		cudaMemcpyAsync(device_ivs[stream_id], host_ivs, NUM_FLOWS * AES_IV_SIZE, cudaMemcpyHostToDevice, stream[stream_id]);
		cudaMemcpyAsync(device_hmac_keys[stream_id], host_hmac_keys, NUM_FLOWS * HMAC_KEY_SIZE, cudaMemcpyHostToDevice, stream[stream_id]);
		cudaMemcpyAsync(device_pkt_offset[stream_id], host_pkt_offset, NUM_FLOWS * PKT_OFFSET_SIZE, cudaMemcpyHostToDevice, stream[stream_id]);
		cudaMemcpyAsync(device_actual_length[stream_id], host_actual_length, NUM_FLOWS * PKT_LENGTH_SIZE, cudaMemcpyHostToDevice, stream[stream_id]);

		co_aes_sha1_gpu(
					device_in[stream_id],
					device_in[stream_id],
					device_aes_keys[stream_id],
					device_ivs[stream_id],
					device_hmac_keys[stream_id],
					device_pkt_offset[stream_id],
					device_actual_length[stream_id],
					NUM_FLOWS,
					NULL,
					THREADS_PER_BLK,
					stream[stream_id]);

		cudaDeviceSynchronize();
	}

	/* Real test */
	for (i = 0; i < 1; i ++) {
		clock_gettime(CLOCK_MONOTONIC, &start);
		cudaEventRecord(startE, 0);

		for (stream_id = 0; stream_id < STREAM_NUM; stream_id ++) {

			cudaMemcpyAsync(device_in[stream_id], host_in, pad_size * NUM_FLOWS * sizeof(uint8_t), cudaMemcpyHostToDevice, stream[stream_id]);
			cudaMemcpyAsync(device_aes_keys[stream_id], host_aes_keys, NUM_FLOWS * AES_KEY_SIZE, cudaMemcpyHostToDevice, stream[stream_id]);
			cudaMemcpyAsync(device_ivs[stream_id], host_ivs, NUM_FLOWS * AES_IV_SIZE, cudaMemcpyHostToDevice, stream[stream_id]);
			cudaMemcpyAsync(device_hmac_keys[stream_id], host_hmac_keys, NUM_FLOWS * HMAC_KEY_SIZE, cudaMemcpyHostToDevice, stream[stream_id]);
			cudaMemcpyAsync(device_pkt_offset[stream_id], host_pkt_offset, NUM_FLOWS * PKT_OFFSET_SIZE, cudaMemcpyHostToDevice, stream[stream_id]);
			cudaMemcpyAsync(device_actual_length[stream_id], host_actual_length, NUM_FLOWS * PKT_LENGTH_SIZE, cudaMemcpyHostToDevice, stream[stream_id]);

#if defined(KERNEL_TEST)
			cudaDeviceSynchronize();
			clock_gettime(CLOCK_MONOTONIC, &kernel_start);
			//gettimeofday(&kernel_start, NULL);
#endif
			co_aes_sha1_gpu(
					device_in[stream_id],
					device_in[stream_id],
					device_aes_keys[stream_id],
					device_ivs[stream_id],
					device_hmac_keys[stream_id],
					device_pkt_offset[stream_id],
					device_actual_length[stream_id],
					NUM_FLOWS,
					NULL,
					THREADS_PER_BLK,
					stream[stream_id]);
#if defined(KERNEL_TEST)
			cudaDeviceSynchronize();
			clock_gettime(CLOCK_MONOTONIC, &kernel_end);
			//gettimeofday(&kernel_end, NULL);
#endif
			cudaMemcpyAsync(host_in, device_in[stream_id], pad_size * NUM_FLOWS * sizeof(uint8_t), cudaMemcpyDeviceToHost, stream[stream_id]);
		}

		cudaDeviceSynchronize();
		clock_gettime(CLOCK_MONOTONIC, &end);

		cudaEventRecord(stopE, 0);
		cudaEventSynchronize(stopE);
		float time;
		cudaEventElapsedTime(&time, startE, stopE);
		//printf("event speed is ------- %f Gbps\n", (fsize * 8 * NUM_FLOWS * STREAM_NUM * 1e-6)/time);

#if defined(KERNEL_TEST)
		diff = 1000000 * (kernel_end.tv_sec-kernel_start.tv_sec)+ (kernel_end.tv_nsec-kernel_start.tv_nsec)/1000;
		printf("Only Kernel, the difference is %lf ms, speed is %lf Mbps\n", (double)diff/1000, (double)((fsize * 8) * NUM_FLOWS * STREAM_NUM) / diff);
#else
		diff = 1000000 * (end.tv_sec-start.tv_sec)+ (end.tv_nsec-start.tv_nsec)/1000;
		printf("%lf\n", (double)diff/1000);
		//printf("%lfms,%lf Mbps\n", (double)diff/1000, (double)((fsize * 8) * NUM_FLOWS * STREAM_NUM) / diff);
#endif
	}

	return 0;
}
