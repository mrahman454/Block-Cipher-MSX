/******************************************************************************
* 
*
* THIS CODE IS FURNISHED TO YOU "AS IS" WITHOUT WARRANTY OF ANY KIND.
*
*****************************************************************************/

#include <stdio.h>
#include "define.h"

//#define PRINT

#include "update_st.h"
#include "f_func.h"

#define ROUND_PROC(fin, num, c, dst)	{dst ^= func_f(fin, rk+(num), c);}

// Encryption
#ifdef IO
// c     : Ciphertext (output)
// p     : Plaintext  (input)
// rk    : Round key  (input)
void msx_enc(uint8_t c[BLOCK_BYTE], uint8_t const p[BLOCK_BYTE], uint32_t rk[RK_NUM_F*2*ROUND])
#else
// p     : Plaintext  (input)/Ciphertext (output)
// rk    : Round key  (input)
void msx_enc(uint8_t p[BLOCK_BYTE], uint32_t rk[RK_NUM_F*2*ROUND])
#endif
{
	uint32_t	p32[BLOCK_BYTE/4];

#ifdef PRINT
	printf("msx_enc\n");
#endif

	p32[0] = (p[3] << 24) | (p[2] << 16) | (p[1] << 8) | p[0];
	p32[1] = (p[7] << 24) | (p[6] << 16) | (p[5] << 8) | p[4];
	p32[2] = (p[11] << 24) | (p[10] << 16) | (p[9] << 8) | p[8];
	p32[3] = (p[15] << 24) | (p[14] << 16) | (p[13] << 8) | p[12];

#ifdef PRINT
//	printf("pl : %04lx %04lx pr : %04lx %04lx\n", pl_in[1], pl_in[0], pr_in[1], pr_in[0]);
#endif

#if LOOP != 0
	for(uint32_t i = 0; ; i++)
	{
		ROUND_PROC(p32[1], (i*12), i, p32[0]);		// ROUND R
		ROUND_PROC(p32[3], (i*12)+6, i, p32[2]);	// ROUND L
#if LOOP >= 2
		i++;
		ROUND_PROC(p32[0], (i*12), i, p32[3]);		// ROUND R
		ROUND_PROC(p32[2], (i*12)+6, i, p32[1]);	// ROUND L
#endif
		if(i == (ROUND-1)) break;

#if LOOP >= 4
		i++;
		ROUND_PROC(p32[3], (i*12), i, p32[2]);		// ROUND R
		ROUND_PROC(p32[1], (i*12)+6, i, p32[0]);	// ROUND L

		i++;
		ROUND_PROC(p32[2], (i*12), i, p32[1]);		// ROUND R
		ROUND_PROC(p32[0], (i*12)+6, i, p32[3]);	// ROUND L
#endif
#if LOOP == 8
		i++;
		ROUND_PROC(p32[1], (i*12), i, p32[0]);		// ROUND R
		ROUND_PROC(p32[3], (i*12)+6, i, p32[2]);	// ROUND L

		i++;
		ROUND_PROC(p32[0], (i*12), i, p32[3]);		// ROUND R
		ROUND_PROC(p32[2], (i*12)+6, i, p32[1]);	// ROUND L

		i++;
		ROUND_PROC(p32[3], (i*12), i, p32[2]);		// ROUND R
		ROUND_PROC(p32[1], (i*12)+6, i, p32[0]);	// ROUND L

		i++;
		ROUND_PROC(p32[2], (i*12), i, p32[1]);		// ROUND R
		ROUND_PROC(p32[0], (i*12)+6, i, p32[3]);	// ROUND L
#endif
#if LOOP == 1
		uint32_t tmp = p32[3];
		p32[3] = p32[2];
		p32[2] = p32[1];
		p32[1] = p32[0];
		p32[0] = tmp;
#elif LOOP == 2
		uint32_t tmp = p32[0];
		p32[0] = p32[2];
		p32[2] = tmp;
		tmp = p32[1];
		p32[1] = p32[3];
		p32[3] = tmp;
#endif
	}

#else
	ROUND_PROC(p32[1], 0, CON, p32[0]);					// ROUND 1 R
	ROUND_PROC(p32[3], 6, CON, p32[2]);					// ROUND 1 L

	ROUND_PROC(p32[0], 12, (CON+0x10000), p32[3]);		// ROUND 2 R
	ROUND_PROC(p32[2], 18, (CON+0x10000), p32[1]);		// ROUND 2 L

	ROUND_PROC(p32[3], 24, (CON+0x20000), p32[2]);		// ROUND 3 R
	ROUND_PROC(p32[1], 30, (CON+0x20000), p32[0]);		// ROUND 3 L

	ROUND_PROC(p32[2], 36, (CON+0x30000), p32[1]);		// ROUND 4 R
	ROUND_PROC(p32[0], 42, (CON+0x30000), p32[3]);		// ROUND 4 L

	ROUND_PROC(p32[1], 48, (CON+0x40000), p32[0]);		// ROUND 5 R
	ROUND_PROC(p32[3], 54, (CON+0x40000), p32[2]);		// ROUND 5 L

	ROUND_PROC(p32[0], 60, (CON+0x50000), p32[3]);		// ROUND 6 R
	ROUND_PROC(p32[2], 66, (CON+0x50000), p32[1]);		// ROUND 6 L

	ROUND_PROC(p32[3], 72, (CON+0x60000), p32[2]);		// ROUND 7 R
	ROUND_PROC(p32[1], 78, (CON+0x60000), p32[0]);		// ROUND 7 L

	ROUND_PROC(p32[2], 84, (CON+0x70000), p32[1]);		// ROUND 8 R
	ROUND_PROC(p32[0], 90, (CON+0x70000), p32[3]);		// ROUND 8 L

	ROUND_PROC(p32[1], 96, (CON+0x80000), p32[0]);		// ROUND 9 R
	ROUND_PROC(p32[3], 102, (CON+0x80000), p32[2]);		// ROUND 9 L

	ROUND_PROC(p32[0], 108, (CON+0x90000), p32[3]);		// ROUND10 R
	ROUND_PROC(p32[2], 114, (CON+0x90000), p32[1]);		// ROUND10 L

	ROUND_PROC(p32[3], 120, (CON+0xa0000), p32[2]);		// ROUND11 R
	ROUND_PROC(p32[1], 126, (CON+0xa0000), p32[0]);		// ROUND11 L

	ROUND_PROC(p32[2], 132, (CON+0xb0000), p32[1]);		// ROUND12 R
	ROUND_PROC(p32[0], 138, (CON+0xb0000), p32[3]);		// ROUND12 L

	ROUND_PROC(p32[1], 144, (CON+0xc0000), p32[0]);		// ROUND13 R
	ROUND_PROC(p32[3], 150, (CON+0xc0000), p32[2]);		// ROUND13 L

	ROUND_PROC(p32[0], 156, (CON+0xd0000), p32[3]);		// ROUND14 R
	ROUND_PROC(p32[2], 162, (CON+0xd0000), p32[1]);		// ROUND14 L

	ROUND_PROC(p32[3], 168, (CON+0xe0000), p32[2]);		// ROUND15 R
	ROUND_PROC(p32[1], 174, (CON+0xe0000), p32[0]);		// ROUND15 L

	ROUND_PROC(p32[2], 180, (CON+0xf0000), p32[1]);		// ROUND16 R
	ROUND_PROC(p32[0], 186, (CON+0xf0000), p32[3]);		// ROUND16 L

	ROUND_PROC(p32[1], 192, (CON+0x100000), p32[0]);	// ROUND17 R
	ROUND_PROC(p32[3], 198, (CON+0x100000), p32[2]);	// ROUND17 L

	ROUND_PROC(p32[0], 204, (CON+0x110000), p32[3]);	// ROUND18 R
	ROUND_PROC(p32[2], 210, (CON+0x110000), p32[1]);	// ROUND18 L
#endif // LOOP

#ifdef IO
	c[0] = p16[6] & 0xff;
	c[1] = p16[6] >> 8;
	c[2] = p16[7] & 0xff;
	c[3] = p16[7] >> 8;
	c[4] = p16[0] & 0xff;
	c[5] = p16[0] >> 8;
	c[6] = p16[1] & 0xff;
	c[7] = p16[1] >> 8;
	c[8] = p16[2] & 0xff;
	c[9] = p16[2] >> 8;
	c[10] = p16[3] & 0xff;
	c[11] = p16[3] >> 8;
	c[12] = p16[4] & 0xff;
	c[13] = p16[4] >> 8;
	c[14] = p16[5] & 0xff;
	c[15] = p16[5] >> 8;
#else
#if LOOP == 1
	p[0] = p32[0] & 0xff;
	p[1] = (p32[0] >> 8) & 0x000000ff;
	p[2] = (p32[0] >> 16) & 0x000000ff;
	p[3] = (p32[0] >> 24) & 0x000000ff;
	p[4] = p32[1] & 0xff;
	p[5] = (p32[1] >> 8) & 0x000000ff;
	p[6] = (p32[1] >> 16) & 0x000000ff;
	p[7] = (p32[1] >> 24) & 0x000000ff;
	p[8] = p32[2] & 0xff;
	p[9] = (p32[2] >> 8) & 0x000000ff;
	p[10] = (p32[2] >> 16) & 0x000000ff;
	p[11] = (p32[2] >> 24) & 0x000000ff;
	p[12] = p32[3] & 0xff;
	p[13] = (p32[3] >> 8) & 0x000000ff;
	p[14] = (p32[3] >> 16) & 0x000000ff;
	p[15] = (p32[3] >> 24) & 0x000000ff;
#elif (LOOP == 2) || (LOOP == 0)
	p[0] = p32[3] & 0xff;
	p[1] = (p32[3] >> 8) & 0x000000ff;
	p[2] = (p32[3] >> 16) & 0x000000ff;
	p[3] = (p32[3] >> 24) & 0x000000ff;
	p[4] = p32[0] & 0xff;
	p[5] = (p32[0] >> 8) & 0x000000ff;
	p[6] = (p32[0] >> 16) & 0x000000ff;
	p[7] = (p32[0] >> 24) & 0x000000ff;
	p[8] = p32[1] & 0xff;
	p[9] = (p32[1] >> 8) & 0x000000ff;
	p[10] = (p32[1] >> 16) & 0x000000ff;
	p[11] = (p32[1] >> 24) & 0x000000ff;
	p[12] = p32[2] & 0xff;
	p[13] = (p32[2] >> 8) & 0x000000ff;
	p[14] = (p32[2] >> 16) & 0x000000ff;
	p[15] = (p32[2] >> 24) & 0x000000ff;
#elif (LOOP == 4) || (LOOP == 8)
	p[0] = p32[3] & 0xff;
	p[1] = (p32[3] >> 8) & 0x000000ff;
	p[2] = (p32[3] >> 16) & 0x000000ff;
	p[3] = (p32[3] >> 24) & 0x000000ff;
	p[4] = p32[0] & 0xff;
	p[5] = (p32[0] >> 8) & 0x000000ff;
	p[6] = (p32[0] >> 16) & 0x000000ff;
	p[7] = (p32[0] >> 24) & 0x000000ff;
	p[8] = p32[1] & 0xff;
	p[9] = (p32[1] >> 8) & 0x000000ff;
	p[10] = (p32[1] >> 16) & 0x000000ff;
	p[11] = (p32[1] >> 24) & 0x000000ff;
	p[12] = p32[2] & 0xff;
	p[13] = (p32[2] >> 8) & 0x000000ff;
	p[14] = (p32[2] >> 16) & 0x000000ff;
	p[15] = (p32[2] >> 24) & 0x000000ff;
#endif

#endif
}

// Decryption
#ifdef IO
// p     : Plaintext  (output)
// c     : Ciphertext (input)
// rk    : Round key  (input)
void msx_dec(uint8_t p[BLOCK_BYTE], uint8_t const c[BLOCK_BYTE], uint32_t rk[RK_NUM_F*2*ROUND])
#else
// c     : Ciphertext (input)/Plaintext  (output)
// rk    : Round key  (input)
void msx_dec(uint8_t c[BLOCK_BYTE], uint32_t rk[RK_NUM_F*2*ROUND])
#endif
{
	uint32_t	c32[BLOCK_BYTE/4];

#ifdef PRINT
	printf("msx_dec\n");
#endif

	c32[0] = (c[3] << 24) | (c[2] << 16) | (c[1] << 8) | c[0];
	c32[1] = (c[7] << 24) | (c[6] << 16) | (c[5] << 8) | c[4];
	c32[2] = (c[11] << 24) | (c[10] << 16) | (c[9] << 8) | c[8];
	c32[3] = (c[15] << 24) | (c[14] << 16) | (c[13] << 8) | c[12];

#if LOOP != 0
	for(int32_t i = ROUND-1; ; i--)
	{
		ROUND_PROC(c32[1], (i*12), i, c32[0]);		// ROUND R
		ROUND_PROC(c32[3], (i*12)+6, i, c32[2]);	// ROUND L
#if LOOP >= 2
		i--;
		ROUND_PROC(c32[2], (i*12), i, c32[1]);		// ROUND R
		ROUND_PROC(c32[0], (i*12)+6, i, c32[3]);	// ROUND L
#endif
		if(i == 0) break;

#if LOOP >= 4
		i--;
		ROUND_PROC(c32[3], (i*12), i, c32[2]);		// ROUND R
		ROUND_PROC(c32[1], (i*12)+6, i, c32[0]);	// ROUND L

		i--;
		ROUND_PROC(c32[0], (i*12), i, c32[3]);		// ROUND R
		ROUND_PROC(c32[2], (i*12)+6, i, c32[1]);	// ROUND L
#endif
#if LOOP == 8
		i--;
		ROUND_PROC(c32[1], (i*12), i, c32[0]);		// ROUND R
		ROUND_PROC(c32[3], (i*12)+6, i, c32[2]);	// ROUND L

		i--;
		ROUND_PROC(c32[2], (i*12), i, c32[1]);		// ROUND R
		ROUND_PROC(c32[0], (i*12)+6, i, c32[3]);	// ROUND L

		i--;
		ROUND_PROC(c32[3], (i*12), i, c32[2]);		// ROUND R
		ROUND_PROC(c32[1], (i*12)+6, i, c32[0]);	// ROUND L

		i--;
		ROUND_PROC(c32[0], (i*12), i, c32[3]);		// ROUND R
		ROUND_PROC(c32[2], (i*12)+6, i, c32[1]);	// ROUND L
#endif
#if LOOP == 1
		uint32_t tmp = c32[0];
		c32[0] = c32[1];
		c32[1] = c32[2];
		c32[2] = c32[3];
		c32[3] = tmp;
#elif LOOP == 2
		uint32_t tmp = c32[0];
		c32[0] = c32[2];
		c32[2] = tmp;
		tmp = c32[1];
		c32[1] = c32[3];
		c32[3] = tmp;
#endif
	}

#else
	ROUND_PROC(c32[1], 204, (CON+0x110000), c32[0]);	// ROUND18 R
	ROUND_PROC(c32[3], 210, (CON+0x110000), c32[2]);	// ROUND18 L

	ROUND_PROC(c32[2], 192, (CON+0x100000), c32[1]);	// ROUND17 R
	ROUND_PROC(c32[0], 198, (CON+0x100000), c32[3]);	// ROUND17 L

	ROUND_PROC(c32[3], 180, (CON+0xf0000), c32[2]);		// ROUND16 R
	ROUND_PROC(c32[1], 186, (CON+0xf0000), c32[0]);		// ROUND16 L

	ROUND_PROC(c32[0], 168, (CON+0xe0000), c32[3]);		// ROUND15 R
	ROUND_PROC(c32[2], 174, (CON+0xe0000), c32[1]);		// ROUND15 L

	ROUND_PROC(c32[1], 156, (CON+0xd0000), c32[0]);		// ROUND14 R
	ROUND_PROC(c32[3], 162, (CON+0xd0000), c32[2]);		// ROUND14 L

	ROUND_PROC(c32[2], 144, (CON+0xc0000), c32[1]);		// ROUND13 R
	ROUND_PROC(c32[0], 150, (CON+0xc0000), c32[3]);		// ROUND13 L

	ROUND_PROC(c32[3], 132, (CON+0xb0000), c32[2]);		// ROUND12 R
	ROUND_PROC(c32[1], 138, (CON+0xb0000), c32[0]);		// ROUND12 L

	ROUND_PROC(c32[0], 120, (CON+0xa0000), c32[3]);		// ROUND11 R
	ROUND_PROC(c32[2], 126, (CON+0xa0000), c32[1]);		// ROUND11 L

	ROUND_PROC(c32[1], 108, (CON+0x90000), c32[0]);		// ROUND10 R
	ROUND_PROC(c32[3], 114, (CON+0x90000), c32[2]);		// ROUND10 L

	ROUND_PROC(c32[2], 96, (CON+0x80000), c32[1]);		// ROUND 9 R
	ROUND_PROC(c32[0], 102, (CON+0x80000), c32[3]);		// ROUND 9 L

	ROUND_PROC(c32[3], 84, (CON+0x70000), c32[2]);		// ROUND 8 R
	ROUND_PROC(c32[1], 90, (CON+0x70000), c32[0]);		// ROUND 8 L

	ROUND_PROC(c32[0], 72, (CON+0x60000), c32[3]);		// ROUND 7 R
	ROUND_PROC(c32[2], 78, (CON+0x60000), c32[1]);		// ROUND 7 L

	ROUND_PROC(c32[1], 60, (CON+0x50000), c32[0]);		// ROUND 6 R
	ROUND_PROC(c32[3], 66, (CON+0x50000), c32[2]);		// ROUND 6 L

	ROUND_PROC(c32[2], 48, (CON+0x40000), c32[1]);		// ROUND 5 R
	ROUND_PROC(c32[0], 54, (CON+0x40000), c32[3]);		// ROUND 5 L

	ROUND_PROC(c32[3], 36, (CON+0x30000), c32[2]);		// ROUND 4 R
	ROUND_PROC(c32[1], 42, (CON+0x30000), c32[0]);		// ROUND 4 L

	ROUND_PROC(c32[0], 24, (CON+0x20000), c32[3]);		// ROUND 3 R
	ROUND_PROC(c32[2], 30, (CON+0x20000), c32[1]);		// ROUND 3 L

	ROUND_PROC(c32[1], 12, (CON+0x10000), c32[0]);		// ROUND 2 R
	ROUND_PROC(c32[3], 18, (CON+0x10000), c32[2]);		// ROUND 2 L

	ROUND_PROC(c32[2], 0, CON, c32[1]);					// ROUND 1 R
	ROUND_PROC(c32[0], 6, CON, c32[3]);					// ROUND 1 L
#endif

#ifdef IO
	p[0] = c32[0] & 0xff;
	p[1] = c32[0] >> 8;
	p[2] = c32[1] & 0xff;
	p[3] = c32[1] >> 8;
	p[4] = c32[2] & 0xff;
	p[5] = c32[2] >> 8;
	p[6] = c32[3] & 0xff;
	p[7] = c32[3] >> 8;
	p[8] = c32[4] & 0xff;
	p[9] = c32[4] >> 8;
	p[10] = c32[5] & 0xff;
	p[11] = c32[5] >> 8;
	p[12] = c32[6] & 0xff;
	p[13] = c32[6] >> 8;
	p[14] = c32[7] & 0xff;
	p[15] = c32[7] >> 8;
#else
#if LOOP == 1
	c[0] = c32[0] & 0xff;
	c[1] = (c32[0] >> 8) & 0x000000ff;
	c[2] = (c32[0] >> 16) & 0x000000ff;
	c[3] = (c32[0] >> 24) & 0x000000ff;
	c[4] = c32[1] & 0xff;
	c[5] = (c32[1] >> 8) & 0x000000ff;
	c[6] = (c32[1] >> 16) & 0x000000ff;
	c[7] = (c32[1] >> 24) & 0x000000ff;
	c[8] = c32[2] & 0xff;
	c[9] = (c32[2] >> 8) & 0x000000ff;
	c[10] = (c32[2] >> 16) & 0x000000ff;
	c[11] = (c32[2] >> 24) & 0x000000ff;
	c[12] = c32[3] & 0xff;
	c[13] = (c32[3] >> 8) & 0x000000ff;
	c[14] = (c32[3] >> 16) & 0x000000ff;
	c[15] = (c32[3] >> 24) & 0x000000ff;
#elif (LOOP == 2) || (LOOP == 0)
	c[0] = c32[1] & 0xff;
	c[1] = (c32[1] >> 8) & 0x000000ff;
	c[2] = (c32[1] >> 16) & 0x000000ff;
	c[3] = (c32[1] >> 24) & 0x000000ff;
	c[4] = c32[2] & 0xff;
	c[5] = (c32[2] >> 8) & 0x000000ff;
	c[6] = (c32[2] >> 16) & 0x000000ff;
	c[7] = (c32[2] >> 24) & 0x000000ff;
	c[8] = c32[3] & 0xff;
	c[9] = (c32[3] >> 8) & 0x000000ff;
	c[10] = (c32[3] >> 16) & 0x000000ff;
	c[11] = (c32[3] >> 24) & 0x000000ff;
	c[12] = c32[0] & 0xff;
	c[13] = (c32[0] >> 8) & 0x000000ff;
	c[14] = (c32[0] >> 16) & 0x000000ff;
	c[15] = (c32[0] >> 24) & 0x000000ff;
#elif (LOOP == 4) || (LOOP == 8)
	c[0] = c32[1] & 0xff;
	c[1] = (c32[1] >> 8) & 0x000000ff;
	c[2] = (c32[1] >> 16) & 0x000000ff;
	c[3] = (c32[1] >> 24) & 0x000000ff;
	c[4] = c32[2] & 0xff;
	c[5] = (c32[2] >> 8) & 0x000000ff;
	c[6] = (c32[2] >> 16) & 0x000000ff;
	c[7] = (c32[2] >> 24) & 0x000000ff;
	c[8] = c32[3] & 0xff;
	c[9] = (c32[3] >> 8) & 0x000000ff;
	c[10] = (c32[3] >> 16) & 0x000000ff;
	c[11] = (c32[3] >> 24) & 0x000000ff;
	c[12] = c32[0] & 0xff;
	c[13] = (c32[0] >> 8) & 0x000000ff;
	c[14] = (c32[0] >> 16) & 0x000000ff;
	c[15] = (c32[0] >> 24) & 0x000000ff;
#endif
#endif
}

#define C1	732050807
#define C2	568877293
#define C3	527446341
#define C4	505872366
#define C5	942805254
#define C6	634010619
#define C7	1296924710
#define C8	3826869025
#define C9	515107230
#define C10	1130980195
#define C11	2149511253
#define C12	539907735
#define C13	244569516
#define C14	920961429
#define C15	2743527186
#define C16	2947265473
#define C17	645454543
#define C18	3960268375
#define C19	2795036687
#define C20	563113322
#define C21	2690074390
#define C22	722202776
#define C23	833026909
#define C24	2035301852

#define SET_RK(i)\
{\
	rk[i] = st[0];\
	rk[i+1] = st[1];\
	rk[i+2] = st[2];\
	rk[i+3] = st[3];\
	rk[i+4] = st[4];\
	rk[i+5] = st[5];\
	rk[i+6] = st[6];\
	rk[i+7] = st[7];\
	rk[i+8] = st[8];\
	rk[i+9] = st[9];\
	rk[i+10] = st[10];\
	rk[i+11] = st[11];\
	rk[i+12] = st[12];\
	rk[i+13] = st[13];\
	rk[i+14] = st[14];\
	rk[i+15] = st[15];\
	rk[i+16] = st[16];\
	rk[i+17] = st[17];\
	rk[i+18] = st[18];\
	rk[i+19] = st[19];\
	rk[i+20] = st[20];\
	rk[i+21] = st[21];\
	rk[i+22] = st[22];\
	rk[i+23] = st[23];\
}

// Key Schedule
// sk : Secret Key (input)
// rk : Round key  (output)
void key_sche(uint8_t sk[SK_BYTE], uint32_t rk[RK_NUM_F*2*ROUND])
{
	uint32_t sk_int[SK_WORD];
	uint32_t st[S_NUM];
	sk_int[0] = (sk[0*4+3] << 24) | (sk[0*4+2] << 16) | (sk[0*4+1] << 8) | sk[0*4];
	sk_int[1] = (sk[1*4+3] << 24) | (sk[1*4+2] << 16) | (sk[1*4+1] << 8) | sk[1*4];
	sk_int[2] = (sk[2*4+3] << 24) | (sk[2*4+2] << 16) | (sk[2*4+1] << 8) | sk[2*4];
	sk_int[3] = (sk[3*4+3] << 24) | (sk[3*4+2] << 16) | (sk[3*4+1] << 8) | sk[3*4];
#if SK_BIT == 256
	sk_int[4] = (sk[4*4+3] << 24) | (sk[4*4+2] << 16) | (sk[4*4+1] << 8) | sk[4*4];
	sk_int[5] = (sk[5*4+3] << 24) | (sk[5*4+2] << 16) | (sk[5*4+1] << 8) | sk[5*4];
	sk_int[6] = (sk[6*4+3] << 24) | (sk[6*4+2] << 16) | (sk[6*4+1] << 8) | sk[6*4];
	sk_int[7] = (sk[7*4+3] << 24) | (sk[7*4+2] << 16) | (sk[7*4+1] << 8) | sk[7*4];
#endif

#if SK_BIT == 128
	st[0] = (sk_int[2] + sk_int[3] + sk_int[0]) ^ C1;
	st[1] = sk_int[1] ^ C2;
	st[2] = sk_int[0] ^ C3;
	st[3] = sk_int[3] ^ C4;
	st[4] = sk_int[0] ^ C5;
	st[5] = sk_int[2] ^ C6;
	st[6] = sk_int[3] ^ C7;
	st[7] = sk_int[2] ^ C8;
	st[8] = sk_int[1] ^ C9;
	st[9] = sk_int[0] ^ C10;
	st[10] = sk_int[1] ^ C11;
	st[11] = sk_int[3] ^ C12;
	st[12] = sk_int[0] ^ C13;
	st[13] = sk_int[3] ^ C14;
	st[14] = sk_int[2] ^ C15;
	st[15] = sk_int[1] ^ C16;
	st[16] = sk_int[2] ^ C17;
	st[17] = sk_int[0] ^ C18;
	st[18] = sk_int[1] ^ C19;
	st[19] = sk_int[0] ^ C20;
	st[20] = sk_int[3] ^ C21;
	st[21] = sk_int[2] ^ C22;
	st[22] = sk_int[3] ^ C23;
	st[23] = sk_int[1] ^ C24;
#elif SK_BIT == 256
	st[0] = (sk_int[2] + sk_int[1] + sk_int[5] + sk_int[4]) ^ C1;
	st[1] = (sk_int[3] + sk_int[7] + sk_int[6] + sk_int[0]) ^ C2;
	st[2] = sk_int[0] ^ C3;
	st[3] = sk_int[6] ^ C4;
	st[4] = sk_int[7] ^ C5;
	st[5] = sk_int[4] ^ C6;
	st[6] = sk_int[2] ^ C7;
	st[7] = sk_int[3] ^ C8;
	st[8] = sk_int[1] ^ C9;
	st[9] = sk_int[6] ^ C10;
	st[10] = sk_int[7] ^ C11;
	st[11] = sk_int[5] ^ C12;
	st[12] = sk_int[0] ^ C13;
	st[13] = sk_int[1] ^ C14;
	st[14] = sk_int[2] ^ C15;
	st[15] = sk_int[4] ^ C16;
	st[16] = sk_int[5] ^ C17;
	st[17] = sk_int[6] ^ C18;
	st[18] = sk_int[0] ^ C19;
	st[19] = sk_int[1] ^ C20;
	st[20] = sk_int[3] ^ C21;
	st[21] = sk_int[4] ^ C22;
	st[22] = sk_int[5] ^ C23;
	st[23] = sk_int[7] ^ C24;
#endif

#if LOOP != 0

	uint32_t idx[10] = {0,1,3,6,9,12,14,17,20,23};

	for(uint32_t i = 0; ; i++)
	{
		SET_RK(i*S_NUM);

#ifdef PRINT
		printf("RK%2ld :", (2*i)+1);
		for(int32_t j = 0; j < 12; j++) printf(" %08lx", st[j]);
		printf("\nRK%2ld :", (2*i)+2);
		for(int32_t j = 12; j < 24; j++) printf(" %08lx", st[j]);
		printf("\n");
#endif

		if(i >= (ROUND/2)-1) break;

		update_st(st, idx);
#if (LOOP >= 2)
		i++;
		SET_RK(i*S_NUM);
		update_st(st, idx);
#endif
#if LOOP >= 4
		i++;
		SET_RK(i*S_NUM);
		update_st(st, idx);

		i++;
		SET_RK(i*S_NUM);
		update_st(st, idx);
#endif
#if LOOP >= 8
		i++;
		SET_RK(i*S_NUM);
		update_st(st, idx);

		i++;
		SET_RK(i*S_NUM);
		update_st(st, idx);

		i++;
		SET_RK(i*S_NUM);
		update_st(st, idx);

		i++;
		SET_RK(i*S_NUM);
		update_st(st, idx);
#endif
	}
#else
	SET_RK(0);
	update_st(0, 1, 3, 6, 9, 12, 14, 17, 20, 23);
	SET_RK(24);
	update_st(1, (1+1), (3+1), (6+1), (9+1), (12+1), (14+1), (17+1), (20+1), 0);
	SET_RK(48);
	update_st(2, (1+2), (3+2), (6+2), (9+2), (12+2), (14+2), (17+2), (20+2), 1);
	SET_RK(72);
	update_st(3, (1+3), (3+3), (6+3), (9+3), (12+3), (14+3), (17+3), (20+3), 2);
	SET_RK(96);
	update_st(4, (1+4), (3+4), (6+4), (9+4), (12+4), (14+4), (17+4), 0, 3);
	SET_RK(120);
	update_st(5, (1+5), (3+5), (6+5), (9+5), (12+5), (14+5), (17+5), 1, 4);
	SET_RK(144);
	update_st(6, (1+6), (3+6), (6+6), (9+6), (12+6), (14+6), (17+6), 2, 5);
	SET_RK(168);
	update_st(7, (1+7), (3+7), (6+7), (9+7), (12+7), (14+7), 0, 3, 6);
	SET_RK(192);
#endif
}
