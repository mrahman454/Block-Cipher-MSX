#ifndef INC_DEFINE_H_
#define INC_DEFINE_H_

typedef unsigned char u8;
typedef unsigned int u32;

#define LOOP 9	// 0:FULL unroll  1,3,9:Round/loop

#define ROUNDS 27

//#define WORD_IN

#ifdef WORD_IN
int Encrypt(u32 *u,u32 *v,u32 key[]);
int Decrypt(u32 *u,u32 *v,u32 key[]);
int ExpandKey(u32 K[],u32 key[]);
#else
int Encrypt(u8 *u,u32 key[]);
int Decrypt(u8 *u, u32 key[]);
int ExpandKey(u8 K[],u32 key[]);
#endif

#endif /* INC_DEFINE_H_ */
