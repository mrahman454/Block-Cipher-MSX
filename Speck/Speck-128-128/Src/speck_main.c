/******************************************************************************
* 
*
* THIS CODE IS FURNISHED TO YOU "AS IS" WITHOUT WARRANTY OF ANY KIND.
*
*****************************************************************************/
/*
 * Test Vector
 * https://nsacyber.github.io/simon-speck/implementations/ImplementationGuide1.1.pdf
 */

#include "stdio.h"
#include "stdlib.h"
#include "memory.h"
#include "define.h"

#include "stm32f4xx.h"

int speck_test()
{
#ifdef WORD_IN
	u64 K[2] ={0x0706050403020100, 0x0f0e0d0c0b0a0908};
	u64	pt[2] = {0x7469206564616d20, 0x6c61766975716520};
	u64 ct[2];
	u64 exp[2] = {0x7860fedf5c570d18, 0xa65d985179783265};
#else
	u8 K[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
	u8 pt[16] = {0x20, 0x6d, 0x61, 0x64, 0x65, 0x20, 0x69, 0x74, 0x20, 0x65, 0x71, 0x75, 0x69, 0x76, 0x61, 0x6c};
	u8 ct[16] = {0x20, 0x6d, 0x61, 0x64, 0x65, 0x20, 0x69, 0x74, 0x20, 0x65, 0x71, 0x75, 0x69, 0x76, 0x61, 0x6c};
	u8 exp[16] = {0x18, 0x0d, 0x57, 0x5c, 0xdf, 0xfe, 0x60, 0x78, 0x65, 0x32, 0x78, 0x79, 0x51, 0x98, 0x5d, 0xa6};
	int i;
#endif
	u64 rk[ROUNDS];

	ExpandKey(K, rk);
	memcpy(ct, pt, 16);
#ifdef WORD_IN
	Encrypt(ct+1, ct, rk);
#else
	Encrypt(ct, rk);
#endif

	printf("PT = ");
#ifdef WORD_IN
	printf("%08llx%08llx", pt[0], pt[1]);
#else
	for(i = 0; i < 8; i++)
	{
		printf("%02x", pt[i]);
	}
#endif
	printf("\nCT = ");
#ifdef WORD_IN
	printf("%08llx%08llx", ct[0], ct[1]);
#else
	for(i = 0; i < 8; i++)
	{
		printf("%02x", ct[i]);
	}
#endif
	printf("\n");
	if(memcmp(ct, exp, 16) != 0)
	{
		printf("Not expected CT.\n");
		return -1;
	}

#ifdef WORD_IN
	Decrypt(ct+1, ct, rk);
#else
	Decrypt(ct, rk);
#endif

	if(memcmp(ct, pt, 16) != 0)
	{
		printf("DEC error.\n");
		return -1;
	}

	printf("TEST OK.\n\n");
	return 0;
}

void speck_measure()
{
#ifdef WORD_IN
	u64	pi[2];
	u64	ct[2];
	u64	K[2];
#else
    u8 pi[16];
    u8 ct[16];
    u8 K[16];
#endif
    u64		rk[ROUNDS];
	int		loop, i;

	volatile uint32_t	e_cycs[10] = {0};
	volatile uint32_t	d_cycs[10] = {0};
	volatile uint32_t	k_cycs[10] = {0};
	volatile uint32_t	cyc_min;

	srand(20230215);

	memcpy(ct, pi, 8);
	for (loop = 0; loop < 10; loop++)
	{
#ifdef WORD_IN
	  	for (i = 0; i < 2; i++)		pi[i] = ((u64)rand()<<32)|rand();
	  	for (i = 0; i < 2; i++)		K[i] = ((u64)rand()<<32)|rand();
#else
	  	for (i = 0; i < 16; i++)	pi[i] = (u8)rand();
	  	for (i = 0; i < 16; i++)	K[i] = (u8)rand();
#endif
	  	DWT->CYCCNT = 0;
		ExpandKey(K, rk);
		k_cycs[loop] = DWT->CYCCNT;

		DWT->CYCCNT = 0;
#ifdef WORD_IN
		Encrypt(ct+1, ct, rk);
#else
		Encrypt(ct, rk);
#endif
		e_cycs[loop] = DWT->CYCCNT;

		DWT->CYCCNT = 0;
#ifdef WORD_IN
		Decrypt(ct+1, ct, rk);
#else
		Decrypt(ct, rk);
#endif
		d_cycs[loop] = DWT->CYCCNT;
	}

	cyc_min = k_cycs[0];
	for (loop = 1; loop < 10; loop++)
	{
		if (cyc_min > k_cycs[loop])
		{
			cyc_min = k_cycs[loop];
		}
	}
	printf("Key Schedule()\t%lu cycles.\n", cyc_min);

	cyc_min = e_cycs[0];
	for (loop = 1; loop < 10; loop++)
	{
		if (cyc_min > e_cycs[loop])
		{
			cyc_min = e_cycs[loop];
		}
	}
	printf("Encrypt()\t\t%lu cycles.\n", cyc_min);

	cyc_min = d_cycs[0];
	for (loop = 1; loop < 10; loop++)
	{
		if (cyc_min > d_cycs[loop])
		{
			cyc_min = d_cycs[loop];
		}
	}
	printf("Decrypt()\t\t%lu cycles.\n", cyc_min);

	return;
}

int speck_main()
{
#ifdef WORD_IN
	printf("WORD IN\n");
#else
	printf("BYTE IN\n");
#endif

#if LOOP != 0
	printf("Round func is %dR/loop imp.\n", LOOP);
#elif LOOP == 0
	printf("Round func is unroll imp.\n");
#endif

	if (speck_test() == -1)
		return -1;

	speck_measure();

	return 0;
}
