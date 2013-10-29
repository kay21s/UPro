/* 
 * Copyright (c) 2010, Intel Corporation
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 * 
 *     * Redistributions of source code must retain the above copyright notice, 
 *       this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright notice, 
 *       this list of conditions and the following disclaimer in the documentation 
 *       and/or other materials provided with the distribution.
 *     * Neither the name of Intel Corporation nor the names of its contributors 
 *       may be used to endorse or promote products derived from this software 
 *       without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND 
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. 
 * IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, 
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF 
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE 
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF 
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
*/

#include <stdlib.h>
#include <stdio.h>
#include <malloc.h>
#include <memory.h>
#ifdef __linux__
#include <alloca.h>
#ifndef _alloca
#define _alloca alloca
#endif
#endif

#include "iaesni.h"

// The following test vectors, keys, IV, and counter values are defined in the
// 'NIST Special Publication 800-38A' (Appendix F) and can be found at the following URL:

char NIST_SP800_38A_Pub[] =			   "http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf";

unsigned char test_plain_text[64] =   {	0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
										0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
										0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,
										0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10};

unsigned char test_key_128[16] =      {	0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};

unsigned char test_key_192[24] =	  {	0x8e,0x73,0xb0,0xf7,0xda,0x0e,0x64,0x52,0xc8,0x10,0xf3,0x2b,0x80,0x90,0x79,0xe5,0x62,0xf8,0xea,0xd2,0x52,0x2c,0x6b,0x7b};

unsigned char test_key_256[32] =      {	0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4};

unsigned char test_init_counter[16] = {	0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff};

unsigned char test_init_vector[16] =  {	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};


unsigned char test_cipher_128_cbc[64]={ 0x76,0x49,0xab,0xac,0x81,0x19,0xb2,0x46,0xce,0xe9,0x8e,0x9b,0x12,0xe9,0x19,0x7d,
										0x50,0x86,0xcb,0x9b,0x50,0x72,0x19,0xee,0x95,0xdb,0x11,0x3a,0x91,0x76,0x78,0xb2,
										0x73,0xbe,0xd6,0xb8,0xe3,0xc1,0x74,0x3b,0x71,0x16,0xe6,0x9e,0x22,0x22,0x95,0x16,
										0x3f,0xf1,0xca,0xa1,0x68,0x1f,0xac,0x09,0x12,0x0e,0xca,0x30,0x75,0x86,0xe1,0xa7};

unsigned char test_cipher_192_cbc[64]={ 0x4f,0x02,0x1d,0xb2,0x43,0xbc,0x63,0x3d,0x71,0x78,0x18,0x3a,0x9f,0xa0,0x71,0xe8,
										0xb4,0xd9,0xad,0xa9,0xad,0x7d,0xed,0xf4,0xe5,0xe7,0x38,0x76,0x3f,0x69,0x14,0x5a,
										0x57,0x1b,0x24,0x20,0x12,0xfb,0x7a,0xe0,0x7f,0xa9,0xba,0xac,0x3d,0xf1,0x02,0xe0,
										0x08,0xb0,0xe2,0x79,0x88,0x59,0x88,0x81,0xd9,0x20,0xa9,0xe6,0x4f,0x56,0x15,0xcd};

unsigned char test_cipher_256_cbc[64]={ 0xf5,0x8c,0x4c,0x04,0xd6,0xe5,0xf1,0xba,0x77,0x9e,0xab,0xfb,0x5f,0x7b,0xfb,0xd6,
										0x9c,0xfc,0x4e,0x96,0x7e,0xdb,0x80,0x8d,0x67,0x9f,0x77,0x7b,0xc6,0x70,0x2c,0x7d,
										0x39,0xf2,0x33,0x69,0xa9,0xd9,0xba,0xcf,0xa5,0x30,0xe2,0x63,0x04,0x23,0x14,0x61,
										0xb2,0xeb,0x05,0xe2,0xc3,0x9b,0xe9,0xfc,0xda,0x6c,0x19,0x07,0x8c,0x6a,0x9d,0x1b};

unsigned char test_cipher_128_ctr[64]={ 0x87,0x4d,0x61,0x91,0xb6,0x20,0xe3,0x26,0x1b,0xef,0x68,0x64,0x99,0x0d,0xb6,0xce,
										0x98,0x06,0xf6,0x6b,0x79,0x70,0xfd,0xff,0x86,0x17,0x18,0x7b,0xb9,0xff,0xfd,0xff,
										0x5a,0xe4,0xdf,0x3e,0xdb,0xd5,0xd3,0x5e,0x5b,0x4f,0x09,0x02,0x0d,0xb0,0x3e,0xab,
										0x1e,0x03,0x1d,0xda,0x2f,0xbe,0x03,0xd1,0x79,0x21,0x70,0xa0,0xf3,0x00,0x9c,0xee};

unsigned char test_cipher_192_ctr[64]={ 0x1a,0xbc,0x93,0x24,0x17,0x52,0x1c,0xa2,0x4f,0x2b,0x04,0x59,0xfe,0x7e,0x6e,0x0b,
										0x09,0x03,0x39,0xec,0x0a,0xa6,0xfa,0xef,0xd5,0xcc,0xc2,0xc6,0xf4,0xce,0x8e,0x94,
										0x1e,0x36,0xb2,0x6b,0xd1,0xeb,0xc6,0x70,0xd1,0xbd,0x1d,0x66,0x56,0x20,0xab,0xf7,
										0x4f,0x78,0xa7,0xf6,0xd2,0x98,0x09,0x58,0x5a,0x97,0xda,0xec,0x58,0xc6,0xb0,0x50};

unsigned char test_cipher_256_ctr[64]={ 0x60,0x1e,0xc3,0x13,0x77,0x57,0x89,0xa5,0xb7,0xa7,0xf5,0x04,0xbb,0xf3,0xd2,0x28,
										0xf4,0x43,0xe3,0xca,0x4d,0x62,0xb5,0x9a,0xca,0x84,0xe9,0x90,0xca,0xca,0xf5,0xc5,
										0x2b,0x09,0x30,0xda,0xa2,0x3d,0xe9,0x4c,0xe8,0x70,0x17,0xba,0x2d,0x84,0x98,0x8d,
										0xdf,0xc9,0xc5,0x8d,0xb6,0x7a,0xad,0xa6,0x13,0xc2,0xdd,0x08,0x45,0x79,0x41,0xa6};

#define TEST_PASS (0)
#define TEST_FAIL_ENC (1)
#define TEST_FAIL_DEC (2)
#define BLOCK_SIZE (16) //in bytes
#define NUM_TEST_BLOCKS (4)

int test128_CBC(unsigned long numBlocks)
{
	unsigned int buffer_size = numBlocks * BLOCK_SIZE;
	unsigned int i;
	UCHAR *testVector = (UCHAR*)_alloca(buffer_size);
	UCHAR *testResult = (UCHAR*)_alloca(buffer_size);
	UCHAR local_test_iv[BLOCK_SIZE];
	unsigned int half_size;

	// Init the test vector and the test result
	for (i=0;i<buffer_size;i++)
	{
		testVector[i] = test_plain_text[i];
		testResult[i] = 0xee;
	}

	// Init the Initialization Vector
	memcpy(local_test_iv,test_init_vector,BLOCK_SIZE);

	intel_AES_enc128_CBC(testVector, testResult, test_key_128, numBlocks, local_test_iv);

	// check the encrypted buffer against the known cipher text
	for (i=0;i<buffer_size;i++)
	{
		if (testResult[i] != test_cipher_128_cbc[i])
		{
			printf("%d",i);
			return TEST_FAIL_DEC;
		}
	}

	//test chaining as well
	memcpy(local_test_iv,test_init_vector,BLOCK_SIZE);
	half_size = numBlocks/2;
	intel_AES_dec128_CBC(testResult,testVector,test_key_128,half_size,local_test_iv);
	intel_AES_dec128_CBC(testResult+BLOCK_SIZE*(half_size),testVector+BLOCK_SIZE*(half_size),test_key_128,numBlocks - half_size,local_test_iv);

	for (i=0;i<buffer_size;i++)
	{
		if (testVector[i] != test_plain_text[i])
		{
			printf("%d",i);
			return TEST_FAIL_DEC;
		}
	}

	return TEST_PASS;
}

int test192_CBC(unsigned long numBlocks)
{
	unsigned int buffer_size = numBlocks*BLOCK_SIZE;
	unsigned int i;
	UCHAR *testVector = (UCHAR*)_alloca(buffer_size);
	UCHAR *testResult = (UCHAR*)_alloca(buffer_size);
	UCHAR local_test_iv[BLOCK_SIZE];
	unsigned int half_size;

	for (i=0;i<buffer_size;i++)
	{
		testVector[i] = test_plain_text[i];
		testResult[i] = 0xee;
	}

	memcpy(local_test_iv,test_init_vector,BLOCK_SIZE);

	intel_AES_enc192_CBC(testVector, testResult, test_key_192, numBlocks, local_test_iv);

	// check the encrypted buffer against the known cipher text
	for (i=0;i<buffer_size;i++)
	{
		if (testResult[i] != test_cipher_192_cbc[i])
		{
			printf("%d",i);
			return TEST_FAIL_DEC;
		}
	}

	//test chaining as well
	memcpy(local_test_iv,test_init_vector,BLOCK_SIZE);
	half_size = numBlocks/2;
	intel_AES_dec192_CBC(testResult,testVector,test_key_192,half_size,local_test_iv);
	intel_AES_dec192_CBC(testResult+BLOCK_SIZE*(half_size),testVector+BLOCK_SIZE*(half_size),test_key_192,numBlocks - half_size,local_test_iv);

	for (i=0;i<buffer_size;i++)
	{
		if (testVector[i] != test_plain_text[i])
		{
			printf("%d",i);
			return TEST_FAIL_DEC;
		}
	}

	return TEST_PASS;

}

int test256_CBC(unsigned long numBlocks)
{
	unsigned int buffer_size = numBlocks*BLOCK_SIZE;
	unsigned int i;
	UCHAR *testVector = (UCHAR*)_alloca(buffer_size);
	UCHAR *testResult = (UCHAR*)_alloca(buffer_size);
	UCHAR local_test_iv[BLOCK_SIZE];
	unsigned int half_size;

	for (i=0;i<buffer_size;i++)
	{
		testVector[i] = test_plain_text[i];
		testResult[i] = 0xee;
	}

	memcpy(local_test_iv,test_init_vector,BLOCK_SIZE);

	intel_AES_enc256_CBC(testVector, testResult, test_key_256, numBlocks, local_test_iv);

	// check the encrypted buffer against the known cipher text
	for (i=0;i<buffer_size;i++)
	{
		if (testResult[i] != test_cipher_256_cbc[i])
		{
			printf("%d",i);
			return TEST_FAIL_DEC;
		}
	}

	//test chaining as well
	memcpy(local_test_iv,test_init_vector,BLOCK_SIZE);
	half_size = numBlocks/2;
	intel_AES_dec256_CBC(testResult,testVector,test_key_256,half_size,local_test_iv);
	intel_AES_dec256_CBC(testResult+BLOCK_SIZE*(half_size),testVector+BLOCK_SIZE*(half_size),test_key_256,numBlocks - half_size,local_test_iv);

	for (i=0;i<buffer_size;i++)
	{
		if (testVector[i] != test_plain_text[i])
		{
			printf("%d",i);
			return TEST_FAIL_DEC;
		}
	}

	return TEST_PASS;
}

int test128_CTR(unsigned long numBlocks)
{
	unsigned int buffer_size = numBlocks*BLOCK_SIZE;
	unsigned int i;
	UCHAR *testVector = (UCHAR*)_alloca(buffer_size);
	UCHAR *testResult = (UCHAR*)_alloca(buffer_size);
	UCHAR *testCounter = (UCHAR*)_alloca(BLOCK_SIZE);

	for (i=0; i < BLOCK_SIZE; i++)
		testCounter[i] = test_init_counter[i];

	for (i=0;i<buffer_size;i++)
	{
		testVector[i] = test_plain_text[i];
		testResult[i] = 0xee;
	}

	intel_AES_encdec128_CTR(testVector, testResult, test_key_128, numBlocks, testCounter);

	for (i=0;i<buffer_size;i++)
	{

		if (testResult[i] != test_cipher_128_ctr[i])
		{
			printf("\nEncryption Failed: intel_aes_encdec128_CTR numBlocks = %ld, bytes differ at %d\n",numBlocks, i);

			return TEST_FAIL_ENC;
		}
		testVector[i] = 0xdd;
	}

	for (i=0; i < BLOCK_SIZE; i++)
		testCounter[i] = test_init_counter[i];

	intel_AES_encdec128_CTR(testResult, testVector, test_key_128, numBlocks, testCounter);

	for (i=0;i<buffer_size;i++)
	{
		if (testVector[i] != test_plain_text[i])
			return TEST_FAIL_DEC;
	}

	return TEST_PASS;

}

int test192_CTR(unsigned long numBlocks)
{
	unsigned int buffer_size = numBlocks*BLOCK_SIZE;
	unsigned int i;
	UCHAR *testVector = (UCHAR*)_alloca(buffer_size);
	UCHAR *testResult = (UCHAR*)_alloca(buffer_size);
	UCHAR *testCounter = (UCHAR*)_alloca(BLOCK_SIZE);

	for (i=0; i < BLOCK_SIZE; i++)
		testCounter[i] = test_init_counter[i];

	for (i=0;i<buffer_size;i++)
	{
		testVector[i] = test_plain_text[i];
		testResult[i] = 0xee;
	}

	intel_AES_encdec192_CTR(testVector, testResult, test_key_192, numBlocks, testCounter);

	for (i=0;i<buffer_size;i++)
	{
		if (testResult[i] != test_cipher_192_ctr[i])
			return TEST_FAIL_ENC;

		testVector[i] = 0xdd;
	}

	for (i=0; i < BLOCK_SIZE; i++)
	testCounter[i] = test_init_counter[i];

	intel_AES_encdec192_CTR(testResult, testVector, test_key_192, numBlocks, testCounter);

	for (i=0;i<buffer_size;i++)
	{
		if (testVector[i] != test_plain_text[i])
			return TEST_FAIL_DEC;
	}

	return TEST_PASS;

}

int test256_CTR(unsigned long numBlocks)
{
	unsigned int buffer_size = numBlocks * BLOCK_SIZE;
	unsigned int i;
	UCHAR *testVector = (UCHAR*)_alloca(buffer_size);
	UCHAR *testResult = (UCHAR*)_alloca(buffer_size);
	UCHAR *testCounter = (UCHAR*)_alloca(BLOCK_SIZE);

	for (i=0; i < BLOCK_SIZE; i++)
		testCounter[i] = test_init_counter[i];

	for (i=0;i<buffer_size;i++)
	{
		testVector[i] = test_plain_text[i];
		testResult[i] = 0xee;
	}

	intel_AES_encdec256_CTR(testVector, testResult, test_key_256, numBlocks, testCounter);

	for (i=0;i<buffer_size;i++)
	{
		if (testResult[i] != test_cipher_256_ctr[i])
			return TEST_FAIL_ENC;

		testVector[i] = 0xdd;
	}

	for (i=0; i < BLOCK_SIZE; i++)
	testCounter[i] = test_init_counter[i];

	intel_AES_encdec256_CTR(testResult, testVector, test_key_256, numBlocks, testCounter);

	for (i=0;i<buffer_size;i++)
	{
		if (testVector[i] != test_plain_text[i])
			return TEST_FAIL_DEC;
	}

	return TEST_PASS;
}

int  main(void)
{
	int i = 0;
	printf("\nIntel(R) AES-NI Sample Library validation application\n\n");

	// verify that AESNI support exists on the platform
	if (check_for_aes_instructions() == 0)
	{
		printf("Intel AES New Instructions NOT detected on this platform - validation app will now terminate.\n");
		return 1;
	}
	else
		printf("Intel AES New Instructions detected\n\n");

	printf("The Test Vectors used to validate implementation correctness for\n");  
	printf("the following block ciphers 'AES[128|192|256][CBC|CTR]' are defined in the\n");
	printf("'NIST Special Publication 800-38A' (Appendix F) and can be found here:\n");
	printf("%s\n\n\n", NIST_SP800_38A_Pub);

	// AES-CBC test
	printf("Testing AES-CBC Mode\n\n");
	for (i=1;i <= NUM_TEST_BLOCKS;i++)
	{
		printf("%d block(s):  AES-128-CBC: %s",i,(test128_CBC(i) != TEST_PASS) ? "FAIL" : "PASS");
		printf(", AES-192-CBC: %s",(test192_CBC(i) != TEST_PASS) ? "FAIL" : "PASS");
		printf(", AES-256-CBC: %s\n",(test256_CBC(i) != TEST_PASS) ? "FAIL" : "PASS");
		printf("\n");
	}

	// AES-CTR test
	printf("\n\nTesting AES-CTR Mode\n\n");
	for (i=1; i <= NUM_TEST_BLOCKS; i++)
	{
		printf("%d block(s):  AES-128-CTR: %s",i,(test128_CTR(i) != TEST_PASS) ? "FAIL" : "PASS");
		printf(", AES-192-CTR: %s",(test192_CTR(i) != TEST_PASS) ? "FAIL" : "PASS");
		printf(", AES-256-CTR: %s\n",(test256_CTR(i) != TEST_PASS) ? "FAIL" : "PASS");
		printf("\n");
	}

	return 0;
}
