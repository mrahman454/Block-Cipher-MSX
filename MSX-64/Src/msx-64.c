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

#define ROUND_PROC(fin, num, c, dst)	{dst ^= func_f(fin, rk+num, c);}

#define SWAP(x, y){\
	uint32_t tmp = x;\
	x = y;\
	y = tmp;\
}

// Encryption
#ifdef IO
// c     : Ciphertext (output)
// p     : Plaintext  (input)
// rk    : Round key  (input)
void msx_enc(uint8_t c[BLOCK_BYTE], uint8_t const p[BLOCK_BYTE], uint32_t rk[RK_NUM_F*ROUND])
#else
// p     : Plaintext  (input)/Ciphertext (output)
// rk    : Round key  (input)
void msx_enc(uint8_t p[BLOCK_BYTE], uint32_t rk[RK_NUM_F*ROUND])
#endif
{
	uint32_t	pl_in, pr_in;
#if LOOP != 0
	uint32_t	i;
#endif

#ifdef PRINT
	printf("msx_enc %d\n", ROUND);
#endif

	// 64-bit input -> 32-bit*2 data
	pr_in = (p[3] << 24) | (p[2] << 16) | (p[1] << 8) | p[0];
	pl_in = (p[7] << 24) | (p[6] << 16) | (p[5] << 8) | p[4];

#ifdef PRINT
	printf("pl : %08lx pr : %08lx\n", pl_in, pr_in);
#endif

#if LOOP != 0
	for(i = 0; ; i++)
	{
		ROUND_PROC(pl_in, (i*RK_NUM_F), (i), pr_in);
#if LOOP >= 2
		i++;
		ROUND_PROC(pr_in, (i*RK_NUM_F), (i), pl_in);
#endif
		if(i == (ROUND-1)) break;
#if LOOP >= 4
		i++;
		ROUND_PROC(pl_in, (i*RK_NUM_F), (i), pr_in);
		i++;
		ROUND_PROC(pr_in, (i*RK_NUM_F), (i), pl_in);
#endif
#if LOOP >= 6
		i++;
		ROUND_PROC(pl_in, (i*RK_NUM_F), (i), pr_in);
		i++;
		ROUND_PROC(pr_in, (i*RK_NUM_F), (i), pl_in);
#endif
#if LOOP == 1
		SWAP(pl_in, pr_in);
#endif
	} // loop i

#elif LOOP == 0
	ROUND_PROC(pl_in, 0, CON, pr_in);							// ROUND 1
	ROUND_PROC(pr_in, RK_NUM_F, (CON+0x10000), pl_in);			// ROUND 2
	ROUND_PROC(pl_in, (RK_NUM_F*2), (CON+0x20000), pr_in);		// ROUND 3
	ROUND_PROC(pr_in, (RK_NUM_F*3), (CON+0x30000), pl_in);		// ROUND 4
	ROUND_PROC(pl_in, (RK_NUM_F*4), (CON+0x40000), pr_in);		// ROUND 5
	ROUND_PROC(pr_in, (RK_NUM_F*5), (CON+0x50000), pl_in);		// ROUND 6
	ROUND_PROC(pl_in, (RK_NUM_F*6), (CON+0x60000), pr_in);		// ROUND 7
	ROUND_PROC(pr_in, (RK_NUM_F*7), (CON+0x70000), pl_in);		// ROUND 8
	ROUND_PROC(pl_in, (RK_NUM_F*8), (CON+0x80000), pr_in);		// ROUND 9
	ROUND_PROC(pr_in, (RK_NUM_F*9), (CON+0x90000), pl_in);		// ROUND 10
	ROUND_PROC(pl_in, (RK_NUM_F*10), (CON+0xa0000), pr_in);		// ROUND 11
	ROUND_PROC(pr_in, (RK_NUM_F*11), (CON+0xb0000), pl_in);		// ROUND 12
	ROUND_PROC(pl_in, (RK_NUM_F*12), (CON+0xc0000), pr_in);		// ROUND 13
	ROUND_PROC(pr_in, (RK_NUM_F*13), (CON+0xd0000), pl_in);		// ROUND 14
#endif

	EOUT[0] = P0 & 0x000000ff;
	EOUT[1] = (P0 >>  8) & 0x000000ff;
	EOUT[2] = (P0 >> 16) & 0x000000ff;
	EOUT[3] = (P0 >> 24);
	EOUT[4] = P1 & 0x000000ff;
	EOUT[5] = (P1 >>  8) & 0x000000ff;
	EOUT[6] = (P1 >> 16) & 0x000000ff;
	EOUT[7] = (P1 >> 24);
}

// Decryption
#ifdef IO
// p     : Plaintext  (output)
// c     : Ciphertext (input)
// rk    : Round key  (input)
void msx_dec(uint8_t p[BLOCK_BYTE], uint8_t const c[BLOCK_BYTE], uint32_t rk[RK_NUM_F*ROUND])
#else
// c     : Ciphertext (input)/Plaintext  (output)
// rk    : Round key  (input)
void msx_dec(uint8_t c[BLOCK_BYTE], uint32_t rk[RK_NUM_F*ROUND])
#endif
{
#ifdef PRINT
	printf("msx_dec %d\n", ROUND);
#endif

	// 64-bit input -> 32-bit*2 data
	uint32_t D0 = (c[3] << 24) | (c[2] << 16) | (c[1] << 8) | c[0];
	uint32_t D1 = (c[7] << 24) | (c[6] << 16) | (c[5] << 8) | c[4];
#ifdef PRINT
	printf("cl : %08lx cr : %08lx\n", cl_in, cr_in);
#endif

#if LOOP != 0
	for(int32_t i = ROUND-1; ; i--)
	{
		ROUND_PROC(D1, (i*RK_NUM_F), (i), D0);
#if LOOP >= 2
		i--;
		ROUND_PROC(D0, (i*RK_NUM_F), (i), D1);
#endif
		if(i == 0) break;
#if LOOP >= 4
		i--;
		ROUND_PROC(D1, (i*RK_NUM_F), (i), D0);
		i--;
		ROUND_PROC(D0, (i*RK_NUM_F), (i), D1);
#endif
#if LOOP >= 6
		i--;
		ROUND_PROC(D1, (i*RK_NUM_F), (i), D0);
		i--;
		ROUND_PROC(D0, (i*RK_NUM_F), (i), D1);
#endif
#if LOOP == 1
		SWAP(D0, D1);
#endif
	} // loop i

#elif LOOP == 0
	ROUND_PROC(D1, (RK_NUM_F*13), (CON+0xd0000), D0);		// ROUND 14
	ROUND_PROC(D0, (RK_NUM_F*12), (CON+0xc0000), D1);		// ROUND 13
	ROUND_PROC(D1, (RK_NUM_F*11), (CON+0xb0000), D0);		// ROUND 12
	ROUND_PROC(D0, (RK_NUM_F*10), (CON+0xa0000), D1);		// ROUND 11
	ROUND_PROC(D1, (RK_NUM_F*9), (CON+0x90000), D0);		// ROUND 10
	ROUND_PROC(D0, (RK_NUM_F*8), (CON+0x80000), D1);		// ROUND 9
	ROUND_PROC(D1, (RK_NUM_F*7), (CON+0x70000), D0);		// ROUND 8
	ROUND_PROC(D0, (RK_NUM_F*6), (CON+0x60000), D1);		// ROUND 7
	ROUND_PROC(D1, (RK_NUM_F*5), (CON+0x50000), D0);		// ROUND 6
	ROUND_PROC(D0, (RK_NUM_F*4), (CON+0x40000), D1);		// ROUND 5
	ROUND_PROC(D1, (RK_NUM_F*3), (CON+0x30000), D0);		// ROUND 4
	ROUND_PROC(D0, (RK_NUM_F*2), (CON+0x20000), D1);		// ROUND 3
	ROUND_PROC(D1, RK_NUM_F, (CON+0x10000), D0);			// ROUND 2
	ROUND_PROC(D0, 0, CON, D1);								// ROUND 1
#endif

	DOUT[0] = cr_in & 0x000000ff;
	DOUT[1] = (cr_in >> 8) & 0x000000ff;
	DOUT[2] = (cr_in >> 16) & 0x000000ff;
	DOUT[3] = (cr_in >> 24);
	DOUT[4] = cl_in & 0x000000ff;
	DOUT[5] = (cl_in >> 8) & 0x000000ff;
	DOUT[6] = (cl_in >> 16) & 0x000000ff;
	DOUT[7] = (cl_in >> 24);
}

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

// Key Schedule
// sk : Secret Key (input)
// rk : Round key  (output)
void key_sche(uint8_t sk[SK_BYTE], uint32_t rk[RK_NUM_F*ROUND])
{
	uint32_t sk_int[SK_WORD];
	uint32_t st[S_NUM];

#ifdef PRINT
	printf("SK[15-0] :");
	for(int32_t j = 15; j >= 0; j--)
		printf(" %02x", sk[j]);
	printf("\n");
#endif

#if 0
	for(uint32_t i = 0; i < SK_WORD; i++)
	{
		sk_int[i] = (sk[i*4+3] << 24) | (sk[i*4+2] << 16) | (sk[i*4+1] << 8) | sk[i*4];
	}
#else
	sk_int[0] = (sk[3] << 24) | (sk[2] << 16) | (sk[1] << 8) | sk[0];
	sk_int[1] = (sk[7] << 24) | (sk[6] << 16) | (sk[5] << 8) | sk[4];
	sk_int[2] = (sk[11] << 24) | (sk[10] << 16) | (sk[9] << 8) | sk[8];
	sk_int[3] = (sk[15] << 24) | (sk[14] << 16) | (sk[13] << 8) | sk[12];
#endif

	st[0] = (sk_int[1] + sk_int[0] + sk_int[3]) ^ C1;
	st[1] = sk_int[2] ^ C2;
	st[2] = sk_int[0] ^ C3;
	st[3] = sk_int[3] ^ C4;
	st[4] = sk_int[0] ^ C5;
	st[5] = sk_int[1] ^ C6;

	st[6] = sk_int[3] ^ C7;
	st[7] = sk_int[0] ^ C8;
	st[8] = sk_int[2] ^ C9;
	st[9] = sk_int[1] ^ C10;
	st[10] = sk_int[2] ^ C11;
	st[11] = sk_int[3] ^ C12;

#if LOOP != 0
	uint32_t idx[6] = {0, 1, 3, 5, 7, 10};

	for(uint32_t i = 0; ; i++)
	{
		SET_RK(i*S_NUM);
#if LOOP != 6
		if(i == (ROUND/2)-1) break;
#endif
		update_st(st, idx);
#if LOOP >= 2
		i++;
		SET_RK(i*S_NUM);
		update_st(st, idx);
#endif
#if LOOP >= 4
		i++;
		SET_RK(i*S_NUM);
		update_st(st, idx);
#endif
#if LOOP == 6
		if(i == (ROUND/2)-1) break;

		i++;
		SET_RK(i*S_NUM);
		update_st(st, idx);
#endif
	}
#else // LOOP = 0(unroll)
	SET_RK(0);
	update_st(0, 1, 3, 5, 7, 10);
	SET_RK(12);
	update_st(1, 2, 4, 6, 8, 11);
	SET_RK(24);
	update_st(2, 3, 5, 7, 9, 0);
	SET_RK(36);
	update_st(3, 4, 6, 8, 10, 1);
	SET_RK(48);
	update_st(4, 5, 7, 9, 11, 2);
	SET_RK(60);
	update_st(5, 6, 8, 10, 0, 3);
	SET_RK(72);
#endif
}
