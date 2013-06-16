#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
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
#define TRAN_NONE 1

int main(int argc, char*argv[])
{
	FILE *fp;
	uint16_t i, fsize, pad_size;
	char * rtp_pkt;
	uint8_t * host_in,*device_in, *host_out;
	uint8_t * host_aes_keys,* device_aes_keys;
	uint8_t * host_ivs,* device_ivs;
	uint8_t * host_hmac_keys,*device_hmac_keys;
	uint32_t * host_pkt_offset,*device_pkt_offset;
	uint16_t * host_actual_length,*device_actual_length;
	uint8_t * host_checkbits,*device_checkbits;
	uint8_t default_aes_keys[AES_KEY_SIZE], default_ivs[AES_IV_SIZE], default_hmac_keys[HMAC_KEY_SIZE];

	struct  timeval start, start1;
	struct  timeval end, end1;
	struct timeval start2, end2;
	struct timeval start3, end3;


	cudaEvent_t startE, stopE;
    cudaEventCreate(&startE);
    cudaEventCreate(&stopE);


	uint32_t NUM_FLOWS;
	if (argc > 1) {
		NUM_FLOWS = atoi(argv[1]);
	} else {
		NUM_FLOWS = 4096;
	}
       
	unsigned  long diff;
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

	printf("the original package is %d bytes,now we pad it to %d bytes\n", fsize, pad_size);

	for (i = 0; i < AES_KEY_SIZE; i ++)
		default_aes_keys[i] = a;
	for (i = 0; i < AES_IV_SIZE; i ++)
		default_ivs[i] = a;
	for (i = 0; i < HMAC_KEY_SIZE; i ++)
		default_hmac_keys[i] = a;

	printf("duplicate it %d times, takes %d bytes\n",NUM_FLOWS,pad_size*NUM_FLOWS);
#if defined(TRAN_NONE)
	host_in = (uint8_t *)calloc(pad_size * NUM_FLOWS, sizeof(uint8_t));
	host_aes_keys = (uint8_t *)calloc(NUM_FLOWS, AES_KEY_SIZE);
	host_ivs = (uint8_t *)calloc(NUM_FLOWS, AES_IV_SIZE);
	host_hmac_keys = (uint8_t *)calloc(NUM_FLOWS,HMAC_KEY_SIZE);
	host_pkt_offset = (uint32_t *)calloc(NUM_FLOWS, PKT_OFFSET_SIZE);
	host_actual_length = (uint16_t *)calloc(NUM_FLOWS, PKT_LENGTH_SIZE);
	host_checkbits = (uint8_t *)calloc(NUM_FLOWS, sizeof(uint8_t));

	cudaMalloc((void **)&device_in, pad_size * NUM_FLOWS * sizeof(uint8_t));
	cudaMalloc((void **)&device_aes_keys, NUM_FLOWS * AES_KEY_SIZE);
	cudaMalloc((void **)&device_ivs, NUM_FLOWS * AES_IV_SIZE);
	cudaMalloc((void **)&device_hmac_keys, NUM_FLOWS * HMAC_KEY_SIZE);
	cudaMalloc((void **)&device_pkt_offset, NUM_FLOWS * PKT_OFFSET_SIZE);
	cudaMalloc((void **)&device_actual_length, NUM_FLOWS * PKT_LENGTH_SIZE);
	cudaMalloc((void **)&device_checkbits, NUM_FLOWS * sizeof(uint8_t));

#elif defined(TRAN_PINNED)
	cudaHostAlloc((void **)&host_out, pad_size * NUM_FLOWS * sizeof(uint8_t), cudaHostAllocDefault);

	cudaHostAlloc((void **)&host_in, pad_size * NUM_FLOWS * sizeof(uint8_t), cudaHostAllocWriteCombined);
	cudaHostAlloc((void **)&host_aes_keys, NUM_FLOWS * AES_KEY_SIZE, cudaHostAllocWriteCombined);
	cudaHostAlloc((void **)&host_ivs, NUM_FLOWS * AES_IV_SIZE, cudaHostAllocWriteCombined);
	cudaHostAlloc((void **)&host_hmac_keys, NUM_FLOWS * HMAC_KEY_SIZE, cudaHostAllocWriteCombined);
	cudaHostAlloc((void **)&host_pkt_offset, NUM_FLOWS * PKT_OFFSET_SIZE, cudaHostAllocWriteCombined);
	cudaHostAlloc((void **)&host_actual_length, NUM_FLOWS * PKT_LENGTH_SIZE, cudaHostAllocWriteCombined);
	cudaHostAlloc((void **)&host_checkbits, NUM_FLOWS * sizeof(uint8_t), cudaHostAllocWriteCombined);

	cudaMalloc((void **)&device_in, pad_size * NUM_FLOWS * sizeof(uint8_t));
	cudaMalloc((void **)&device_aes_keys, NUM_FLOWS * AES_KEY_SIZE);
	cudaMalloc((void **)&device_ivs, NUM_FLOWS * AES_IV_SIZE);
	cudaMalloc((void **)&device_hmac_keys, NUM_FLOWS * HMAC_KEY_SIZE);
	cudaMalloc((void **)&device_pkt_offset, NUM_FLOWS * PKT_OFFSET_SIZE);
	cudaMalloc((void **)&device_actual_length, NUM_FLOWS * PKT_LENGTH_SIZE);
	cudaMalloc((void **)&device_checkbits, NUM_FLOWS * sizeof(uint8_t));

#endif

	// initialize device memory
	// just for performance
	cudaMemcpy(device_in, host_in, pad_size * NUM_FLOWS * sizeof(uint8_t), cudaMemcpyHostToDevice);
	cudaMemcpy(device_aes_keys, host_aes_keys, NUM_FLOWS * AES_KEY_SIZE, cudaMemcpyHostToDevice);
	cudaMemcpy(device_ivs, host_ivs, NUM_FLOWS * AES_IV_SIZE, cudaMemcpyHostToDevice);
	cudaMemcpy(device_hmac_keys, host_hmac_keys, NUM_FLOWS * HMAC_KEY_SIZE, cudaMemcpyHostToDevice);
	cudaMemcpy(device_pkt_offset, host_pkt_offset, NUM_FLOWS * PKT_OFFSET_SIZE, cudaMemcpyHostToDevice);
	cudaMemcpy(device_actual_length, host_actual_length, NUM_FLOWS * PKT_LENGTH_SIZE, cudaMemcpyHostToDevice);
	cudaMemcpy(device_checkbits, host_checkbits, NUM_FLOWS * sizeof(uint8_t), cudaMemcpyHostToDevice);

	// write the buffer
	for (i = 0; i < NUM_FLOWS; i ++){
		memcpy(host_in + i * pad_size, rtp_pkt, fsize * sizeof(uint8_t));
		memcpy((uint8_t *)host_aes_keys + i * AES_KEY_SIZE, default_aes_keys, AES_KEY_SIZE);
		memcpy((uint8_t *)host_ivs + i * AES_IV_SIZE, default_ivs, AES_IV_SIZE);
		memcpy((uint8_t *)host_hmac_keys + i * HMAC_KEY_SIZE, default_hmac_keys, HMAC_KEY_SIZE);
		host_pkt_offset[i] = i * pad_size;
		host_actual_length[i] = fsize;
		host_checkbits[i] = 0;
	}


/*
	cudaMemcpyAsync(device_in, host_in, pad_size * NUM_FLOWS * sizeof(uint8_t), cudaMemcpyHostToDevice, 0);
	cudaMemcpyAsync(device_aes_keys, host_aes_keys, NUM_FLOWS * AES_KEY_SIZE, cudaMemcpyHostToDevice, 0);
	cudaMemcpyAsync(device_ivs, host_ivs, NUM_FLOWS * AES_IV_SIZE, cudaMemcpyHostToDevice, 0);
	cudaMemcpyAsync(device_hmac_keys, host_hmac_keys, NUM_FLOWS * HMAC_KEY_SIZE, cudaMemcpyHostToDevice, 0);
	cudaMemcpyAsync(device_pkt_offset, host_pkt_offset, NUM_FLOWS * PKT_OFFSET_SIZE, cudaMemcpyHostToDevice, 0);
	cudaMemcpyAsync(device_actual_length, host_actual_length, NUM_FLOWS * PKT_LENGTH_SIZE, cudaMemcpyHostToDevice, 0);
	cudaMemcpyAsync(device_checkbits, host_checkbits, NUM_FLOWS * sizeof(uint8_t), cudaMemcpyHostToDevice, 0);


	co_aes_sha1_gpu(
		device_in,
		device_in,
		device_aes_keys,
		device_ivs,
		device_hmac_keys,
		device_pkt_offset,
		device_actual_length,
		NUM_FLOWS,
		device_checkbits,
		THREADS_PER_BLK,
		0);
*/


	for (i = 0; i < 10; i ++) {
		gettimeofday(&start,NULL);
		cudaEventRecord(startE, 0);


		gettimeofday(&start1,NULL);
		cudaMemcpyAsync(device_in, host_in, pad_size * NUM_FLOWS * sizeof(uint8_t), cudaMemcpyHostToDevice, 0);
		cudaMemcpyAsync(device_aes_keys, host_aes_keys, NUM_FLOWS * AES_KEY_SIZE, cudaMemcpyHostToDevice, 0);
		cudaMemcpyAsync(device_ivs, host_ivs, NUM_FLOWS * AES_IV_SIZE, cudaMemcpyHostToDevice, 0);
		cudaMemcpyAsync(device_hmac_keys, host_hmac_keys, NUM_FLOWS * HMAC_KEY_SIZE, cudaMemcpyHostToDevice, 0);
		cudaMemcpyAsync(device_pkt_offset, host_pkt_offset, NUM_FLOWS * PKT_OFFSET_SIZE, cudaMemcpyHostToDevice, 0);
		cudaMemcpyAsync(device_actual_length, host_actual_length, NUM_FLOWS * PKT_LENGTH_SIZE, cudaMemcpyHostToDevice, 0);
		cudaMemcpyAsync(device_checkbits, host_checkbits, NUM_FLOWS * sizeof(uint8_t), cudaMemcpyHostToDevice, 0);


		//cudaDeviceSynchronize();
		//gettimeofday(&end1,NULL);
		//gettimeofday(&start2,NULL);

#if 1
		co_aes_sha1_gpu(
				device_in,
				device_in,
				device_aes_keys,
				device_ivs,
				device_hmac_keys,
				device_pkt_offset,
				device_actual_length,
				NUM_FLOWS,
				device_checkbits,
				THREADS_PER_BLK,
				0);
#else
		launch_aes_gpu(
				device_in,
				device_in,
				device_aes_keys,
				device_ivs,
				device_pkt_offset,
				device_actual_length,
				NUM_FLOWS,
				device_checkbits,
				THREADS_PER_BLK,
				0);
		/*
		   launch_sha1_gpu(
		   device_in,
		   device_hmac_keys,
		   device_pkt_offset,
		   device_actual_length,
		   NUM_FLOWS,
		   device_checkbits,
		   THREADS_PER_BLK,
		   0);
		 */
#endif

		//	cudaDeviceSynchronize();
		//	gettimeofday(&end2,NULL);
		//	gettimeofday(&start3,NULL);


		//cudaMemcpyAsync(host_out, device_in, pad_size * NUM_FLOWS * sizeof(uint8_t), cudaMemcpyDeviceToHost, 0);
		//cudaMemcpyAsync(host_checkbits, device_checkbits, NUM_FLOWS * sizeof(uint8_t), cudaMemcpyDeviceToHost, 0);	
		cudaMemcpy(host_in, device_in, pad_size * NUM_FLOWS * sizeof(uint8_t), cudaMemcpyDeviceToHost);



		cudaDeviceSynchronize();
		//	gettimeofday(&end3,NULL);
		gettimeofday(&end,NULL);

		cudaEventRecord(stopE, 0);
		cudaEventSynchronize(stopE);
		float time;
		cudaEventElapsedTime(&time, startE, stopE);
		printf("event speed is ------- %f Gbps\n", (fsize *8 * NUM_FLOWS * 1e-6)/time);
		diff = 1000000 * (end.tv_sec-start.tv_sec)+ end.tv_usec-start.tv_usec;
		printf("Plus memcpy, thedifference is %lf ms, speed is %ld Mbps\n", (double)diff/1000, ((fsize * 8) * NUM_FLOWS) / diff);
		/*
		   diff = 1000000 * (end1.tv_sec-start1.tv_sec)+ end1.tv_usec-start1.tv_usec;
		   printf("Transfer host -> device, \tlatency is %lf ms, speed is %ld Mbps\n", (double)diff/1000, ((fsize * 8) * NUM_FLOWS) / diff);
		   diff = 1000000 * (end2.tv_sec-start2.tv_sec)+ end2.tv_usec-start2.tv_usec;
		   printf("Kernel Execution, \t\tlatency is %lf ms, speed is %ld Mbps\n", (double)diff/1000, ((fsize * 8) * NUM_FLOWS) / diff);
		   diff = 1000000 * (end3.tv_sec-start3.tv_sec)+ end3.tv_usec-start3.tv_usec;
		   printf("Transfer device -> host, \tlatency is %lf ms, speed is %ld Mbps\n", (double)diff/1000, ((fsize * 8) * NUM_FLOWS) / diff);
		   cudaDeviceReset();

		 */
	}

	// assert(host_checkbits[0] == 1);
	//for (i = 0; i < NUM_FLOWS; i ++)
	//	printf("%d",host_checkbits[i]);
	
	return 0;
}
