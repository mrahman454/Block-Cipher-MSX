/******************************************************************************
* 
*
* THIS CODE IS FURNISHED TO YOU "AS IS" WITHOUT WARRANTY OF ANY KIND.
*
*****************************************************************************/

#ifndef INC_DEFINE_H_
#define INC_DEFINE_H_

//#define IO
#ifdef IO
#define EOUT	c
#define DOUT	p
#else
#define EOUT	p
#define DOUT	c
#endif

#define LOOP	0		// Enc/Dec imp. 1,2,4,6:round/loop 0：unroll

#if LOOP == 1
#define P0 pr_in
#define P1 pl_in
#define D0 cr_in
#define D1 cl_in
#else
#define P0 pl_in
#define P1 pr_in
#define D0 cl_in
#define D1 cr_in
#endif

#define CON 0xa1cd0000

#define RK_NUM_F	6
#define ROUND		14

#define SK_BIT	128
#define SK_BYTE	(SK_BIT/8)
#define SK_WORD	(SK_BIT/32)

#define BLOCK_BIT	64
#define BLOCK_BYTE	(BLOCK_BIT/8)

#define S_NUM	12

#define ROL32(x,r) (((x)<<(r))|((x)>>(32-(r))))

#ifdef IO
void msx_enc(uint8_t c[BLOCK_BYTE], uint8_t const p[BLOCK_BYTE], uint32_t rk[6*ROUND]);
void msx_dec(uint8_t p[BLOCK_BYTE], uint8_t const c[BLOCK_BYTE], uint32_t rk[6*ROUND]);
void key_sche(uint8_t sk[SK_BYTE], uint32_t rk[6*ROUND]);
#else
void msx_enc(uint8_t p[BLOCK_BYTE], uint32_t rk[6*ROUND]);
void msx_dec(uint8_t c[BLOCK_BYTE], uint32_t rk[6*ROUND]);
void key_sche(uint8_t sk[SK_BYTE], uint32_t rk[6*ROUND]);
#endif


/* define forceinline macro */
#ifdef _MSC_VER
#define forceinline __forceinline
#elif defined(__GNUC__)
#define forceinline inline __attribute__((__always_inline__))
#elif defined(__CLANG__)
#if __has_attribute(__always_inline__)
#define forceinline inline __attribute__((__always_inline__))
#else
#define forceinline inline
#endif
#else
#define forceinline inline
#endif

#define ALIGN_ARM_BOUNDRY 8
#define ALIGNED __attribute__ ((aligned(ALIGN_ARM_BOUNDRY)))

#define F_INLINE

#ifdef F_INLINE
#define F_PREFIX	forceinline
#else
#define F_PREFIX	__attribute__((__noinline__))
#endif

#endif /* INC_DEFINE_H_ */
