/******************************************************************************
*
*
* THIS CODE IS FURNISHED TO YOU "AS IS" WITHOUT WARRANTY OF ANY KIND.
*
*****************************************************************************/

#define func_p(y){\
	uint32_t x = y;\
	y ^= ROL32(x, 13);\
	y ^= ROL32(x, 21);\
}

// F function
// x : 32-bit input
// rk : Round Key
// c : 32-bit constant value
// return : 32-bit output
F_PREFIX uint32_t func_f(uint32_t const x, const uint32_t rk[RK_NUM_F], const uint32_t c)
{
	uint32_t	x0, x1, w0, w1, y;

	x0 = x & 0x0000ffff;	// Low 16bit of input
	x1 = x >> 16;			// High 16bit of input

	w0 = (x0 + rk[0]) * (x1 + rk[1]);
	w0 += rk[2];
	w1 = (x0 + rk[3]) * (x1 + rk[4]);
	w1 += rk[5];

#if LOOP != 0
	w1 ^= ((c << 16) + CON);
#else
	w1 ^= c;
#endif

	y = (w0 >> 16) | (w1 & 0xffff0000);

	func_p(y);

#ifdef PRINT
	printf("  Fi : %08lx RK[%08lx %08lx %08lx %08lx %08lx %08lx] Fo : %08lx\n",
	x, rk[0], rk[1], rk[2], rk[3], rk[4], rk[5], y);
#endif

	return y;
}
