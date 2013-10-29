#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>


#define NUM_FLOWS 4096 
#define THREADS_PER_BLK 128
#define MEMORY_ALIGNMENT  4096
#define BLOCK_SIZE 16
#define HMAC_KEY_SIZE 20
#define HMAC_TAG_SIZE 10
#define ALIGN_UP(x,size) ( ((size_t)x+(size-1))&(~(size-1)) )
#define TRAN_NONE 1

void sha1_hash(uint8_t *message, uint32_t len, uint32_t *hash);
extern void sha1_compress(uint32_t *state, uint32_t *block);

unsigned char test_key_128[16] =      {	0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
unsigned char test_init_counter[16] = {	0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff};
unsigned char test_init_vector[16] =  {	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};


uint64_t swap64(uint64_t v)
{
	return  ((v & 0x00000000000000ffU) << 56) |
		((v & 0x000000000000ff00U) << 48) |
		((v & 0x0000000000ff0000U) << 24) |
		((v & 0x00000000ff000000U) << 8)  |
		((v & 0x000000ff00000000U) >> 8)  |
		((v & 0x0000ff0000000000U) >> 24) |
		((v & 0x00ff000000000000U) >> 48) |
		((v & 0xff00000000000000U) >> 56);
}



int main()
{
	FILE *fp;
	uint16_t i, j, fsize, pad_size, sha1_size;
	char * rtp_pkt;
	uint8_t * host_in, *host_out, *in;
	uint8_t default_hmac_keys[HMAC_KEY_SIZE];
	uint32_t hash[5];

	struct  timeval start, end;
	struct  timeval start_aes, end_aes;
	struct  timeval start_sha, end_sha;
       
	unsigned  long diff;
	uint8_t a = 123;

	fp = fopen("rtp.pkt", "rb");
	fseek(fp, 0, SEEK_END);
	fsize = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	rtp_pkt = (char *)calloc(fsize, sizeof(char));
	fread(rtp_pkt, fsize, sizeof(char), fp);

	pad_size = (fsize + 8 + 1 + 63) & (~0x3F);
	sha1_size = (fsize + 63) & (~0x3F);
	const uint64_t len64 = swap64((uint64_t)fsize);


	printf("the original package is %d bytes,now we pad it to %d bytes\n", fsize, pad_size);

	for (i = 0; i < HMAC_KEY_SIZE; i ++)
		default_hmac_keys[i] = a;

	printf("duplicate it %d times, takes %d bytes\n",NUM_FLOWS,pad_size*NUM_FLOWS);
	host_in = (uint8_t *)calloc(pad_size * NUM_FLOWS, sizeof(uint8_t));
	host_out = (uint8_t *)calloc(pad_size * NUM_FLOWS, sizeof(uint8_t));

	uint8_t *testCounter = (uint8_t *)malloc(16);
	for (i = 0; i < BLOCK_SIZE; i ++)
		testCounter[i] = test_init_counter[i];

	// write the buffer
	for (i = 0; i < NUM_FLOWS; i ++){
		in = host_in + i * pad_size;
		memcpy(in, rtp_pkt, fsize * sizeof(uint8_t));

		*(uint8_t *)(in + pad_size - 9) = 1 << 7;
		*(uint64_t *)(in + pad_size - 8) = len64;
	}

	gettimeofday(&start,NULL);

	gettimeofday(&start_aes,NULL);

	for (i = 0; i < NUM_FLOWS; i ++)
	{
		//i = 0;

		in = host_in + i * pad_size;
		uint8_t cc = in[0] & 0x0F; /* Get the number of CSRC identifiers */
		uint16_t header_len = 12 + 4 * cc; /* Get the total header length */
		in = in + header_len; /* Get to the payload */
		int numBlocks, len = fsize - header_len;

		
		if (fsize & 0x0f == 0)
			numBlocks = fsize >> 4;
		else
			numBlocks = (fsize >> 4) + 1;

		//printf("header_len = %d, in = %p, numBlocks = %d\n", header_len, in, numBlocks);

		intel_AES_encdec128_CTR(in, in, test_key_128, numBlocks, testCounter);

		if (fsize & 0x0f != 0) {
			in = in + fsize;
			for (j = 0; j < numBlocks * 16 - fsize; j ++) {
				in[j] = 0;
			}
		}

	}

	gettimeofday(&end_aes,NULL);

	gettimeofday(&start_sha,NULL);
	in = host_in;

	unsigned long ji, mm = NUM_FLOWS * sha1_size / 64;
	printf("mm = %ld\n", mm);
	for (ji = 0; ji < mm ; ji++)
		sha1_compress(hash, (uint32_t *)in);

#if 0
	const unsigned long N = 10000000;
	unsigned long ji;
	uint32_t state[5];
	uint32_t block[16];
	for (ji = 0; ji < N; ji++)
		sha1_compress(hash, in);
#endif
#if 0
	for (i = 0; i < NUM_FLOWS; i ++)
	{
		/* Sha1 comeon */
		in = host_in + i * pad_size;
		sha1_hash(in, sha1_size, hash);
		memcpy(in + sha1_size, hash, HMAC_TAG_SIZE);
	}
#endif
	gettimeofday(&end_sha,NULL);

	gettimeofday(&end,NULL);


	diff = 1000000 * (end.tv_sec-start.tv_sec)+ end.tv_usec-start.tv_usec;
	printf("Speed is %ld Mbps\n", ((fsize * 8) * NUM_FLOWS) / diff);
	diff = 1000000 * (end_aes.tv_sec-start_aes.tv_sec)+ end_aes.tv_usec-start_aes.tv_usec;
	printf("AES Speed is %ld Mbps\n", (((fsize - 12) * 8) * NUM_FLOWS) / diff);
	diff = 1000000 * (end_sha.tv_sec-start_sha.tv_sec)+ end_sha.tv_usec-start_sha.tv_usec;
	printf("SHA1 Speed is %ld Mbps\n", ((sha1_size * 8) * NUM_FLOWS) / diff);
	//printf("SHA1 Speed is %ld Mbps\n", (N * 64 * 8) / diff);


//////////////////////////////////////
/*
	uint32_t state[5];
	uint32_t block[16];
	const unsigned long N = 10000000;

	gettimeofday(&start_sha,NULL);
	for (i = 0; i < N; i++)
		sha1_compress(state, block);
	gettimeofday(&end_sha,NULL);
	diff = 1000000 * (end_sha.tv_sec-start_sha.tv_sec)+ end_sha.tv_usec-start_sha.tv_usec;
	printf("SHA1 Speed is %ld Mbps\n", (N * 64 * 8) / diff);
*/
	return 0;
}

void sha1_hash(uint8_t *message, uint32_t len, uint32_t *hash)
{
	int i;

	hash[0] = 0x67452301;
	hash[1] = 0xEFCDAB89;
	hash[2] = 0x98BADCFE;
	hash[3] = 0x10325476;
	hash[4] = 0xC3D2E1F0;
	
	for (i = 0; i + 64 <= len; i += 64)
		sha1_compress(hash, (uint32_t*)(message + i));
	
	
	assert(len - i == 0);
	return;
}
