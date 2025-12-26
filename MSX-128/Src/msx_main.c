/******************************************************************************
* 
*
* THIS CODE IS FURNISHED TO YOU "AS IS" WITHOUT WARRANTY OF ANY KIND.
*
*****************************************************************************/

#include "main.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "define.h"

#define NUM 10

void msx_measure()
{
	uint8_t p_i8[BLOCK_BYTE];
#ifdef IO
	uint8_t p_o8[BLOCK_BYTE] = {0};
	uint8_t c_o8[BLOCK_BYTE] = {0};
#endif
	uint8_t	 sk[SK_BYTE];
	uint32_t rk[RK_NUM_F*2*ROUND];
	int		 loop, i;

	volatile uint32_t	k_cycs[NUM] = {0};
	volatile uint32_t	e_cycs[NUM] = {0};
	volatile uint32_t	d_cycs[NUM] = {0};
	volatile uint32_t	cyc_min;

	srand(20240123);
	for (loop = 0; loop < NUM; loop++)
	{
		for(i = 0; i < SK_BYTE; i++)
		{
			sk[i] = rand();
		}

		// Key schedule
		DWT->CYCCNT = 0;
		key_sche(sk, rk);
		k_cycs[loop] = DWT->CYCCNT;

		// Encryption
		DWT->CYCCNT = 0;
#ifdef IO
		msx_enc(c_o8, p_i8, rk);
#else
		msx_enc(p_i8, rk);
#endif
		e_cycs[loop] = DWT->CYCCNT;

		// Decryption
		DWT->CYCCNT = 0;
#ifdef IO
		msx_dec(p_o8, c_o8, rk);
#else
		msx_dec(p_i8, rk);
#endif
		d_cycs[loop] = DWT->CYCCNT;
	}

	cyc_min = k_cycs[0];
	for (loop = 1; loop < NUM; loop++)
	{
		if (cyc_min > k_cycs[loop])
		{
			cyc_min = k_cycs[loop];
		}
	}
	printf("key_sche : %lu cycle\n", cyc_min);

	cyc_min = e_cycs[0];
	for (loop = 1; loop < NUM; loop++)
	{
		if (cyc_min > e_cycs[loop])
		{
			cyc_min = e_cycs[loop];
		}
	}
	printf("%s : %lu cycle\n", "msx_enc", cyc_min);

	cyc_min = d_cycs[0];
	for (loop = 1; loop < NUM; loop++)
	{
		if (cyc_min > d_cycs[loop])
		{
			cyc_min = d_cycs[loop];
		}
	}
	printf("%s : %lu cycle\n", "msx_dec", cyc_min);

}

int msx_test(void)
{
	uint8_t	p_i8[BLOCK_BYTE] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
	uint8_t c_i8[BLOCK_BYTE], d_i8[BLOCK_BYTE];
#if SK_BIT == 128
	uint8_t sk[SK_BYTE] = {0xfe, 0x5a, 0x9e, 0x88, 0xbe, 0x34, 0xea, 0xa3, 0x38, 0xd5, 0xcf, 0x8a, 0x07, 0x1f, 0xf6, 0xa3};
	uint8_t exp[BLOCK_BYTE] = {0xde, 0x99, 0x96, 0x56, 0x04, 0x7f, 0x27, 0x14, 0x79, 0x80, 0x42, 0x65, 0xdb, 0x99, 0x69, 0xbe};
#else
	uint8_t sk[SK_BYTE] = {0x3a, 0x59, 0x14, 0x5f, 0x61, 0xef, 0xbc, 0x16, 0xdb, 0x9c, 0x49, 0x16, 0xee, 0xf8, 0x51, 0xec,
						   0x52, 0xef, 0x74, 0x10, 0x23, 0x5f, 0xb3, 0x5b, 0x34, 0x83, 0xe5, 0x3b, 0xa2, 0xdc, 0xde, 0xdd};
	uint8_t exp[BLOCK_BYTE] = {0x95, 0x31, 0x7a, 0xa7, 0xc7, 0x3a, 0xc7, 0x3d, 0xcc, 0x3e, 0x0a, 0x88, 0x6d, 0xc1, 0x02, 0x67};
#endif
	uint32_t rk[RK_NUM_F*2*ROUND];

	printf("\nMSX TEST");

#ifdef IO
	key_sche(sk, rk);
	msx_enc(c_i8, p_i8, rk);
#else
	key_sche(sk, rk);
	memcpy(c_i8, p_i8, BLOCK_BYTE);
	msx_enc(c_i8, rk);
#endif
	if(memcmp(c_i8, exp, BLOCK_BYTE) != 0)
	{
		uint32_t i;
		printf("ROUND %d msx_enc() ERROR. Not expected CT\n", ROUND);
		printf("EXP : ");
		for(i = 0; i < BLOCK_BYTE; i++) printf("%02x",exp[i]);
		printf("\nACT : ");
		for(i = 0; i < BLOCK_BYTE; i++) printf("%02x",c_i8[i]);
		printf("\n");
		return -1;
	}

#ifdef IO
	msx_dec(d_i8, c_i8, rk);
#else
	memcpy(d_i8, c_i8, BLOCK_BYTE);
	msx_dec(d_i8, rk);
#endif
	if(memcmp(d_i8, p_i8, BLOCK_BYTE) != 0)
	{
		uint32_t i;
		printf("ROUND %d msx_enc()/msx_dec() ERROR.\n", ROUND);
		printf("Dec : ");
		for(i = 0; i < BLOCK_BYTE; i++) printf("%02x",d_i8[i]);
		printf("\n");
		return -1;
	}

	printf(" OK.\n");
	return 0;
}

// Main
int msx_main(void)
{
#if LOOP == 0
	printf("Full Unroll imp.\n");
#else
	printf("Loop %d imp.\n", LOOP);
#endif

#ifdef IO
	printf("PT/CT is sparated argment.\n");
#else
	printf("PT/CT is one argment.\n");
#endif

	printf("key length = %d\n", SK_BIT);

	if( msx_test() != 0)
	{
		return -1;
	}

	msx_measure();

	return 0;
}
