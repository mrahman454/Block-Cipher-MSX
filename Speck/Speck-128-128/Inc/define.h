#ifndef DEFINE_H_
#define DEFINE_H_

typedef unsigned char u8;
typedef unsigned long long u64;

#define LOOP	8	// 0:FULL unroll  1,8:Round/loop

#define ROUNDS 32

//#define WORD_IN

#ifdef WORD_IN
int Encrypt(u64 *u,u64 *v,u64 key[]);
int Decrypt(u64 *u,u64 *v,u64 key[]);
int ExpandKey(u64 K[],u64 key[]);
#else
int Encrypt(u8 *u,u64 key[]);
int Decrypt(u8 *u, u64 key[]);
int ExpandKey(u8 K[],u64 key[]);
#endif

#endif /* DEFINE_H_ */
