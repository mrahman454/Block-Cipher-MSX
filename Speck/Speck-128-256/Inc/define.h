#ifndef DEFINE_H_
#define DEFINE_H_

typedef unsigned char		u8;
typedef unsigned long long	u64;

#define LOOP	1	// 0:FULL unroll  1,3,9:Round/loop

#define ROUNDS	34

//#define WORD_IN

#ifdef WORD_IN
int Encrypt(u64 *u,u64 *v,u64 rk[]);
int Decrypt(u64 *u,u64 *v,u64 rk[]);
int ExpandKey(u64 K[],u64 key[]);
#else
int Encrypt(u8 *u, u64 rk[]);
int Decrypt(u8 *u, u64 rk[]);
int ExpandKey(u8 K[],u64 key[]);
#endif

#endif /* DEFINE_H_ */
