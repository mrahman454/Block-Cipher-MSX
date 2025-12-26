/*
 *
 * https://github.com/nsacyber/simon-speck-supercop/blob/master/crypto_stream/speck128128ctr/ref/stream.c
 *
 */
#include "define.h"

/*
int crypto_stream_speck128256ctr_ref(
  unsigned char *out, 
  unsigned long long outlen, 
  const unsigned char *n, 
  const unsigned char *k
)
{
  u64 i,nonce[2],K[4],key[34],x,y,t;
  unsigned char *block=malloc(16);   

  if (!outlen) {free(block); return 0;}

  nonce[0]=((u64*)n)[0];
  nonce[1]=((u64*)n)[1];

  for(i=0;i<4;i++) K[i]=((u64 *)k)[i];

  ExpandKey(K,key);

  t=0;
  while(outlen>=16){
    x=nonce[1]; y=nonce[0]; nonce[0]++;
    Encrypt(&x,&y,key);                          
    ((u64 *)out)[1+t]=x; 
    ((u64 *)out)[0+t]=y; 
    t+=2;                                      
    outlen-=16;                                  
  }

  if (outlen>0){
    x=nonce[1]; y=nonce[0];
    Encrypt(&x,&y,key);
    ((u64 *)block)[1]=x; ((u64 *)block)[0]=y;
    for(i=0;i<outlen;i++) out[i+8*t]=block[i];
  }

  free(block);

  return 0;
}



int crypto_stream_speck128256ctr_ref_xor(
  unsigned char *out, 
  const unsigned char *in, 
  unsigned long long inlen, 
  const unsigned char *n, 
  const unsigned char *k)
{
  u64 i,nonce[2],K[4],key[34],x,y,t;
  unsigned char *block=malloc(16);  
 
  if (!inlen) {free(block); return 0;}

  nonce[0]=((u64*)n)[0];
  nonce[1]=((u64*)n)[1];

  for(i=0;i<4;i++) K[i]=((u64 *)k)[i];

  ExpandKey(K,key);

  t=0;
  while(inlen>=16){
    x=nonce[1]; y=nonce[0]; nonce[0]++;
    Encrypt(&x,&y,key);                          
    ((u64 *)out)[1+t]=x^((u64 *)in)[1+t]; 
    ((u64 *)out)[0+t]=y^((u64 *)in)[0+t]; 
    t+=2;                                      
    inlen-=16;                                  
  }
  if (inlen>0){
    x=nonce[1]; y=nonce[0];
    Encrypt(&x,&y,key);
    ((u64 *)block)[1]=x; ((u64 *)block)[0]=y;
    for(i=0;i<inlen;i++) out[i+8*t]=block[i]^in[i+8*t];
  }

  free(block);

  return 0;
}
*/

#define ROR64(x,r) (((x)>>(r))|((x)<<(64-(r))))
#define ROL64(x,r) (((x)<<(r))|((x)>>(64-(r))))
#define R(x,y,k) (x=ROR64(x,8), x+=y, x^=k, y=ROL64(y,3), y^=x)
#define RI(x,y,k) (y^=x, y=ROR64(y,3), x^=k, x-=y, x=ROL64(x,8))

#define U8ToU64(d8, d64) {\
  u64 z;\
  d64 = *(d8);\
  z = *(d8+1);  d64 |= (z << 8);\
  z = *(d8+2);  d64 |= (z << 16);\
  z = *(d8+3);  d64 |= (z << 24);\
  z = *(d8+4);  d64 |= (z << 32);\
  z = *(d8+5);  d64 |= (z << 40);\
  z = *(d8+6);  d64 |= (z << 48);\
  z = *(d8+7);  d64 |= (z << 56);\
}

#define U64ToU8(d64, d8) {\
  *(d8) = d64 & 0xff;\
  *(d8+1) = (d64 >> 8) & 0xff;\
  *(d8+2) = (d64 >> 16) & 0xff;\
  *(d8+3) = (d64 >> 24) & 0xff;\
  *(d8+4) = (d64 >> 32) & 0xff;\
  *(d8+5) = (d64 >> 40) & 0xff;\
  *(d8+6) = (d64 >> 48) & 0xff;\
  *(d8+7) = (d64 >> 56) & 0xff;\
}

#ifdef WORD_IN
int Encrypt(u64 *u,u64 *v,u64 key[])
#else
int Encrypt(u8 *u, u64 key[])
#endif
{
  u64 x,y;
#ifdef WORD_IN
  x=*u, y=*v;
#else
  U8ToU64(u, y);
  U8ToU64(u+8, x);
#endif

#if LOOP == 1
  for(int i=0;i<ROUNDS;i++)
  {
	R(x,y,key[i]);
  }
#elif LOOP == 9
  for(int i=0; ;i+=9)
  {
	R(x,y,key[i]);
	R(x,y,key[i+1]);
	R(x,y,key[i+2]);
	R(x,y,key[i+3]);
	R(x,y,key[i+4]);
	R(x,y,key[i+5]);
	R(x,y,key[i+6]);
	if(i == 27) break;
	R(x,y,key[i+7]);
	R(x,y,key[i+8]);
  }

#elif LOOP == 0
	R(x,y,key[0]);
	R(x,y,key[1]);
	R(x,y,key[2]);
	R(x,y,key[3]);
	R(x,y,key[4]);
	R(x,y,key[5]);
	R(x,y,key[6]);
	R(x,y,key[7]);
	R(x,y,key[8]);
	R(x,y,key[9]);
	R(x,y,key[10]);
	R(x,y,key[11]);
	R(x,y,key[12]);
	R(x,y,key[13]);
	R(x,y,key[14]);
	R(x,y,key[15]);
	R(x,y,key[16]);
	R(x,y,key[17]);
	R(x,y,key[18]);
	R(x,y,key[19]);
	R(x,y,key[20]);
	R(x,y,key[21]);
	R(x,y,key[22]);
	R(x,y,key[23]);
	R(x,y,key[24]);
	R(x,y,key[25]);
	R(x,y,key[26]);
	R(x,y,key[27]);
	R(x,y,key[28]);
	R(x,y,key[29]);
	R(x,y,key[30]);
	R(x,y,key[31]);
	R(x,y,key[32]);
	R(x,y,key[33]);
#endif

#ifdef WORD_IN
  *u=x; *v=y;
#else
  U64ToU8(y, u);
  U64ToU8(x, u+8);
#endif

  return 0;
}

#ifdef WORD_IN
int Decrypt(u64 *u,u64 *v,u64 key[])
#else
int Decrypt(u8 *u, u64 key[])
#endif
{
  u64 x,y;
#ifdef WORD_IN
  x=*u,y=*v;
#else
  U8ToU64(u, y);
  U8ToU64(u+8, x);
#endif

#if LOOP == 1
  for(int i=(ROUNDS-1);i>=0;i--)
	RI(x,y,key[i]);

#elif LOOP == 9
  for(int i=(ROUNDS-1); ;i-=9)
  {
	RI(x,y,key[i]);
	RI(x,y,key[i-1]);
	RI(x,y,key[i-2]);
	RI(x,y,key[i-3]);
	RI(x,y,key[i-4]);
	RI(x,y,key[i-5]);
	RI(x,y,key[i-6]);
	if(i == 6) break;
	RI(x,y,key[i-7]);
	RI(x,y,key[i-8]);
  }

#elif LOOP == 0
	RI(x,y,key[33]);
	RI(x,y,key[32]);
	RI(x,y,key[31]);
	RI(x,y,key[30]);
	RI(x,y,key[29]);
	RI(x,y,key[28]);
	RI(x,y,key[27]);
	RI(x,y,key[26]);
	RI(x,y,key[25]);
	RI(x,y,key[24]);
	RI(x,y,key[23]);
	RI(x,y,key[22]);
	RI(x,y,key[21]);
	RI(x,y,key[20]);
	RI(x,y,key[19]);
	RI(x,y,key[18]);
	RI(x,y,key[17]);
	RI(x,y,key[16]);
	RI(x,y,key[15]);
	RI(x,y,key[14]);
	RI(x,y,key[13]);
	RI(x,y,key[12]);
	RI(x,y,key[11]);
	RI(x,y,key[10]);
	RI(x,y,key[9]);
	RI(x,y,key[8]);
	RI(x,y,key[7]);
	RI(x,y,key[6]);
	RI(x,y,key[5]);
	RI(x,y,key[4]);
	RI(x,y,key[3]);
	RI(x,y,key[2]);
	RI(x,y,key[1]);
	RI(x,y,key[0]);
#endif

#ifdef WORD_IN
  *u=x; *v=y;
#else
  U64ToU8(y, u);
  U64ToU8(x, u+8);
#endif

  return 0;
}

#ifdef WORD_IN
int ExpandKey(u64 K[],u64 key[])
#else
int ExpandKey(u8 K[],u64 key[])
#endif
{
  u64 D, C, B ,A;

#ifdef WORD_IN
  D=K[3],C=K[2],B=K[1],A=K[0];
#else
  U8ToU64(K, A);
  U8ToU64(K+8, B);
  U8ToU64(K+16, C);
  U8ToU64(K+24, D);
#endif

#if LOOP == 1
  for(int i=0;i<33;i+=3){
    key[i]=A; R(B,A,i);
    key[i+1]=A; R(C,A,i+1);
    key[i+2]=A; R(D,A,i+2);
  }
  key[33]=A;

#elif LOOP == 9
  for(int i=0; ;i+=9)
  {
	key[i]=A; R(B,A,i);
	key[i+1]=A; R(C,A,i+1);
	key[i+2]=A; R(D,A,i+2);
	key[i+3]=A; R(B,A,i+3);
	key[i+4]=A; R(C,A,i+4);
	key[i+5]=A; R(D,A,i+5);
	key[i+6]=A; R(B,A,i+6);
	if(i == 27) break;
	key[i+7]=A; R(C,A,i+7);
	key[i+8]=A; R(D,A,i+8);
  }

#elif LOOP == 0
  key[0]=A; R(B,A,0);
  key[1]=A; R(C,A,1);
  key[2]=A; R(D,A,2);
  key[3]=A; R(B,A,3);
  key[4]=A; R(C,A,4);
  key[5]=A; R(D,A,5);
  key[6]=A; R(B,A,6);
  key[7]=A; R(C,A,7);
  key[8]=A; R(D,A,8);
  key[9]=A; R(B,A,9);
  key[10]=A; R(C,A,10);
  key[11]=A; R(D,A,11);
  key[12]=A; R(B,A,12);
  key[13]=A; R(C,A,13);
  key[14]=A; R(D,A,14);
  key[15]=A; R(B,A,15);
  key[16]=A; R(C,A,16);
  key[17]=A; R(D,A,17);
  key[18]=A; R(B,A,18);
  key[19]=A; R(C,A,19);
  key[20]=A; R(D,A,20);
  key[21]=A; R(B,A,21);
  key[22]=A; R(C,A,22);
  key[23]=A; R(D,A,23);
  key[24]=A; R(B,A,24);
  key[25]=A; R(C,A,25);
  key[26]=A; R(D,A,26);
  key[27]=A; R(B,A,27);
  key[28]=A; R(C,A,28);
  key[29]=A; R(D,A,29);
  key[30]=A; R(B,A,30);
  key[31]=A; R(C,A,31);
  key[32]=A; R(D,A,32);
  key[33]=A;
#endif

  return 1;
}
