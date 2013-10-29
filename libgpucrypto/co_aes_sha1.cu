#include <stdint.h>
#include <stdio.h>
#include <assert.h>

#include "aes_core.h"
#include "sha1.h"
#include "crypto_size.h"

/* AES counter mode + HMAC SHA-1, 
   the encryption of each block in AES counter mode is not parallelized in this implementation */
__global__ void aes_ctr_sha1_kernel(
			uint8_t	*input_buf,
			uint8_t *output_buf,
			const uint8_t *aes_keys,
			uint8_t *ivs,
			const uint8_t *hmac_keys,
			const uint32_t *pkt_offset,
			const uint16_t *length,
			const unsigned int num_flows,
			uint8_t *checkbits)
{
	int idx = blockIdx.x * blockDim.x + threadIdx.x;
	uint16_t len;

/**************************************************************************
  AES Encryption is started first
 ***************************************************************************/
#if 1
	__shared__ uint32_t shared_Te0[256];
	__shared__ uint32_t shared_Te1[256];
	__shared__ uint32_t shared_Te2[256];
	__shared__ uint32_t shared_Te3[256];
	__shared__ uint32_t shared_Rcon[10];

	/* Private counter 128 bits */
	uint32_t keystream[4];

	/* initialize T boxes */
	for (unsigned i = 0; i * blockDim.x < 256 ; i ++) {
		unsigned index = threadIdx.x + i * blockDim.x;
		if (index >= 256)
			break;
		shared_Te0[index] = Te0_ConstMem[index];
		shared_Te1[index] = Te1_ConstMem[index];
		shared_Te2[index] = Te2_ConstMem[index];
		shared_Te3[index] = Te3_ConstMem[index];
	}

	for(unsigned i = 0; i * blockDim.x < 10; i ++){
		int index = threadIdx.x + blockDim.x * i;
		if(index < 10){
			shared_Rcon[index] = rcon[index];
		}
	}

	/* ----debug-----*/
	if (idx >= num_flows) {
		//printf("idx = %d, num_flows = %d, exit.\n", idx, num_flows);
		return;
	}

	/* make sure T boxes have been initialized. */
	__syncthreads();

	/* Encrypt using counter mode, this is the actual length of the packet */
	/* pkt_offset[idx + 1] - pkt_offset[idx] is used for "length[idx] + padding for HMAC + HMAC sha-1 tag" */
	len = length[idx];

	/* Skip RTP header to Locate the data to be encrypted */
	uint8_t *in = pkt_offset[idx] + input_buf;
	uint8_t cc = in[0] & 0x0F; /* Get the number of CSRC identifiers */
	if (cc != 0) {
		//printf("%d,%d,%d,%d\n", in[0], in[1], in[2], in[3]);
		return;
	}
	uint16_t header_len = 12 + 4 * cc; /* Get the total header length */

	/* Jump to the parts need encryption */
	in = in + header_len; /* Get to the payload */

	uint8_t *out = pkt_offset[idx] + output_buf;
	out	= out + header_len; /* Get to the payload */
	len	-= header_len; /* data length that needs encryption */
	
	assert(out == in);

	/* ----debug----- */
	if (len <= 0) {
		printf("idx = %d, len <= 0, exit.\n", idx);
		return;
	}

	const uint8_t *key = idx * 16 + aes_keys;
	uint64_t *iv = (uint64_t *) (idx * AES_BLOCK_SIZE + ivs);
	// printf("idx %d is writing : %d header_len : %d len\n", idx, header_len, len);
	while (len >= AES_BLOCK_SIZE) {

		/* for the ith block, its input is ((iv + i) mod 2^128)*/
		iv[0] ++;
		if (iv[0] == 0)
			iv[1] ++;

		/* Get the keystream here */
		AES_128_encrypt((uint8_t *)iv, (uint8_t *)keystream, key,
				shared_Te0, shared_Te1, shared_Te2, shared_Te3, shared_Rcon);

		*((uint32_t*)out)       = *((uint32_t*)in)       ^ *((uint32_t*)keystream);
		*(((uint32_t*)out) + 1) = *(((uint32_t*)in) + 1) ^ *(((uint32_t*)keystream) + 1);
		*(((uint32_t*)out) + 2) = *(((uint32_t*)in) + 2) ^ *(((uint32_t*)keystream) + 2);
		*(((uint32_t*)out) + 3) = *(((uint32_t*)in) + 3) ^ *(((uint32_t*)keystream) + 3);

		//if (idx == 0)
		//	printf("in = %p, out = %p, output_buf = %p, offset = %d\n", in, out, output_buf, out - output_buf);

		len -= AES_BLOCK_SIZE;
		in  += AES_BLOCK_SIZE;
		out += AES_BLOCK_SIZE;

		//if (idx == 0)
		//	printf("len = %d,  %d\n", len, AES_BLOCK_SIZE);
	}

	if (len) {
		//if (idx == 0)
		//	printf("len = %d\n");
		/* for the ith block, its input is ((iv + i) mod 2^128)*/
		iv[0] ++;
		if (iv[0] == 0)
			iv[1] ++;

		AES_128_encrypt((uint8_t *)iv, (uint8_t *)keystream, key,
				shared_Te0, shared_Te1, shared_Te2, shared_Te3, shared_Rcon);

		for(unsigned n = 0; n < len; ++n)
			out[n] = in[n] ^ ((uint8_t *)keystream)[n];
	}

	__syncthreads();
#endif
/**************************************************************************
  AES Encryption completed, Now we start SHA-1 Calculation
 ***************************************************************************/
#if 0
	uint32_t w_register[16];

	uint32_t *w = w_register;
	hash_digest_t h;
	uint32_t offset = pkt_offset[idx];
	len = length[idx];

	//uint16_t sha1_pad_len = (len + 8 + 1 + 63) & (~0x3F);
	//sha1_pad_len -= 64;
	uint16_t sha1_output_pos = (len + 3) & ~0x03;
	uint32_t *sha1_out = (uint32_t *)(input_buf + offset + sha1_output_pos);

	for (unsigned i = 0; i < 16; i++)
		w[i] = 0x36363636;

	/* In SRTP, HMAC_KEY_SIZE is 160 bits = 20 bytes */
	xorpads(w, (uint32_t *)(hmac_keys + HMAC_KEY_SIZE * idx));

	h.h1 = 0x67452301;
	h.h2 = 0xEFCDAB89;
	h.h3 = 0x98BADCFE;
	h.h4 = 0x10325476;
	h.h5 = 0xC3D2E1F0;

	//SHA1 compute on ipad
	computeSHA1Block((char*)w, w, 0, 64, h);

	//SHA1 compute on message
	unsigned num_iter = (len + 8 + 1 + 63) >> 6; // the same as divide 64
	for (unsigned i = 0; i < num_iter; i ++)
		computeSHA1Block((char *)(input_buf + offset), w, i * 64, len, h);

	/* In SRTP, sha1_out has only 80 bits output 32+32+16 = 80 */
	*(sha1_out)   = swap(h.h1);
	*(sha1_out+1) = swap(h.h2);
	uint32_t temp = swap(h.h3);
	*(uint16_t *)(sha1_out+2)  = ((uint16_t *)&temp)[0];

	h.h1 = 0x67452301;
	h.h2 = 0xEFCDAB89;
	h.h3 = 0x98BADCFE;
	h.h4 = 0x10325476;
	h.h5 = 0xC3D2E1F0;

	for (unsigned i = 0; i < 16; i++)
		w[i] = 0x5c5c5c5c;

	xorpads(w, (uint32_t*)(hmac_keys + 20 * idx));

	//SHA 1 compute on opads
	computeSHA1Block((char*)w, w, 0, 64, h);

	//SHA 1 compute on (hash of ipad|m)
	//HMAC_TAG_SIZE  = 10
	computeSHA1Block((char*)sha1_out, w, 0, 10, h);

	*(sha1_out)   = swap(h.h1);
	*(sha1_out+1) = swap(h.h2);
	temp = swap(h.h3);
	*(uint16_t *)(sha1_out+2)  = ((uint16_t *)&temp)[0];

	__syncthreads();
#endif
	// Now we set the checkbits
	//*(checkbits + idx) = 1;
	return;
}

extern "C" void co_aes_sha1_gpu(
			uint8_t		*in,
			uint8_t		*out,
			uint8_t		*aes_keys,
			uint8_t		*ivs,
			uint8_t		*hmac_keys,
			uint32_t	*pkt_offset,
			uint16_t	*actual_length,
			unsigned int num_flows,
			uint8_t		*checkbits,
			unsigned	threads_per_blk,
			cudaStream_t stream)
{
	int num_blks = (num_flows + threads_per_blk - 1) / threads_per_blk;

	//printf("stream=%d, threads_per_blk =%d, num_blks = %d\n", stream, threads_per_blk, num_blks);
	if (stream == 0) {
		aes_ctr_sha1_kernel<<<num_blks, threads_per_blk>>>(
		       in, out, aes_keys, ivs, hmac_keys, pkt_offset, actual_length, num_flows, checkbits);
	} else  {
		aes_ctr_sha1_kernel<<<num_blks, threads_per_blk, 0, stream>>>(
		       in, out, aes_keys, ivs, hmac_keys, pkt_offset, actual_length, num_flows, checkbits);
	}
}

