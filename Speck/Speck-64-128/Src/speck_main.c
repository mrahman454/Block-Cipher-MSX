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

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "define.h"

#include "stm32f4xx.h"

int speck_test(void)
{
#ifdef WORD_IN
	u32 pt[2] = { 0x7475432d, 0x3b726574 };
	u32 ct[2] = { 0 };
	u32 K[4] = { 0x03020100, 0x0b0a0908, 0x13121110, 0x1b1a1918 };
	u32 exp[2] = {0x454e028b, 0x8c6fa548};
#else
	u8 pt[8] = {0x2d, 0x43, 0x75, 0x74, 0x74, 0x65, 0x72, 0x3b};
	u8 ct[8] ={0};
	u8 K[16] = { 0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b, 0x10, 0x11, 0x12, 0x13, 0x18, 0x19, 0x1a, 0x1b };
	u8 exp[8] = {0x8b, 0x02, 0x4e, 0x45, 0x48, 0xa5, 0x6f, 0x8c};
	u32 i;
#endif
	u32 rk[ROUNDS];

	ExpandKey(K, rk);
	memcpy(ct, pt, 8);
#ifdef WORD_IN
	Encrypt(ct+1, ct, rk);
#else
	Encrypt(ct, rk);
#endif

	printf("PT = ");
#ifdef WORD_IN
	printf("%04x%04x", pt[0], pt[1]);
#else
	for(i = 0; i < 8; i++)
	{
		printf("%02x", pt[i]);
	}
#endif
	printf("\nCT = ");
#ifdef WORD_IN
	printf("%04x%04x", ct[0], ct[1]);
#else
	for(i = 0; i < 8; i++)
	{
		printf("%02x", ct[i]);
	}
#endif
	printf("\n");
   	if(memcmp(ct, exp, 8) != 0)
   	{
   		printf("Not expected CT.\n");
   		return -1;
   	}

#ifdef WORD_IN
   	Decrypt(ct+1, ct, rk);
#else
   	Decrypt(ct, rk);
#endif

   	if(memcmp(ct, pt, 8) != 0)
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
	u32	pi[2];
	u32	ct[2];
	u32	K[4];
#else
    u8 pi[8];
    u8 ct[8];
    u8 K[16];
#endif
    u32		rk[ROUNDS];
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
	  	for (i = 0; i < 2; i++)		pi[i] = (u32)rand();
	  	for (i = 0; i < 4; i++)		K[i] = (u32)rand();
#else
	  	for (i = 0; i < 8; i++)		pi[i] = (u8)rand();
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

// Main
int speck_main(void)
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

	if(speck_test() != 0)
	{
		return -1;
	}

	speck_measure();

	return 0;
}
