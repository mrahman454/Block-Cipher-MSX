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
	u64 K[4] ={0x0706050403020100, 0x0f0e0d0c0b0a0908, 0x1716151413121110, 0x1f1e1d1c1b1a1918};
	u64	pt[2] = {0x202e72656e6f6f70, 0x65736f6874206e49};
	u64 ct[2];
	u64 exp[2] = {0x4eeeb48d9c188f43, 0x4109010405c0f53e};
#else
	u8 K[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
				0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
	u8 pt[16] = {0x70,0x6f,0x6f,0x6e,0x65,0x72,0x2e,0x20,0x49,0x6e,0x20,0x74,0x68,0x6f,0x73,0x65};
	u8 ct[16];
	u8 exp[16] = {0x43, 0x8f, 0x18, 0x9c, 0x8d, 0xb4, 0xee, 0x4e, 0x3e, 0xf5, 0xc0, 0x05, 0x04, 0x01, 0x09, 0x41};
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
	for(i = 0; i < 16; i++)
	{
		printf("%02x", pt[i]);
	}
#endif
	printf("\nCT = ");
#ifdef WORD_IN
	printf("%08llx%08llx", ct[0], ct[1]);
#else
	for(i = 0; i < 16; i++)
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
	u64	K[4];
#else
    u8 pi[16];
    u8 ct[16];
    u8 K[32];
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
	  	for (i = 0; i < 4; i++)		K[i] = ((u64)rand()<<32)|rand();
#else
	  	for (i = 0; i < 16; i++)	pi[i] = (u8)rand();
	  	for (i = 0; i < 32; i++)	K[i] = (u8)rand();
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
