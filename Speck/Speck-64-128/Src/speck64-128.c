/*
 *
 * https://github.com/nsacyber/simon-speck-supercop/blob/master/crypto_stream/speck64128ctr/ref/stream.c
 *
 */
#include "define.h"

/*
int crypto_stream_speck64128ctr_ref(
  unsigned char *out, 
  unsigned long long outlen, 
  const unsigned char *n, 
  const unsigned char *k
)
{
  u32 i,nonce[2],K[4],key[27],x,y,t;
  unsigned char *block=malloc(8);   

  if (!outlen) {free(block); return 0;}

  nonce[0]=((u32*)n)[0];
  nonce[1]=((u32*)n)[1];

  for(i=0;i<4;i++) K[i]=((u32 *)k)[i];

  ExpandKey(K,key);

  t=0;
  while(outlen>=8){
    x=nonce[1]; y=nonce[0]; nonce[0]++;
    Encrypt(&x,&y,key);                          
    ((u32 *)out)[1+t]=x; 
    ((u32 *)out)[0+t]=y; 
    t+=2;                                      
    outlen-=8;                                  
  }

  if (outlen>0){
    x=nonce[1]; y=nonce[0];
    Encrypt(&x,&y,key);
    ((u32 *)block)[1]=x; ((u32 *)block)[0]=y;
    for(i=0;i<outlen;i++) out[i+4*t]=block[i];
  }

  free(block);

  return 0;
}



int crypto_stream_speck64128ctr_ref_xor(
  unsigned char *out, 
  const unsigned char *in, 
  unsigned long long inlen, 
  const unsigned char *n, 
  const unsigned char *k)
{
  u32 i,nonce[2],K[4],key[27],x,y,t;
  unsigned char *block=malloc(8);  
 
  if (!inlen) {free(block); return 0;}

  nonce[0]=((u32*)n)[0];
  nonce[1]=((u32*)n)[1];

  for(i=0;i<4;i++) K[i]=((u32 *)k)[i];

  ExpandKey(K,key);

  t=0;
  while(inlen>=8){
    x=nonce[1]; y=nonce[0]; nonce[0]++;
    Encrypt(&x,&y,key);                          
    ((u32 *)out)[1+t]=x^((u32 *)in)[1+t]; 
    ((u32 *)out)[0+t]=y^((u32 *)in)[0+t]; 
    t+=2;                                      
    inlen-=8;                                  
  }
  if (inlen>0){
    x=nonce[1]; y=nonce[0];
    Encrypt(&x,&y,key);
    ((u32 *)block)[1]=x; ((u32 *)block)[0]=y;
    for(i=0;i<inlen;i++) out[i+4*t]=block[i]^in[i+4*t];
  }

  free(block);

  return 0;
}
*/
#define ROR32(x,r) (((x)>>(r))|((x)<<(32-(r))))
#define ROL32(x,r) (((x)<<(r))|((x)>>(32-(r))))
#define R(x,y,k) (x=ROR32(x,8), x+=y, x^=k, y=ROL32(y,3), y^=x)
#define RI(x,y,k) (y^=x, y=ROR32(y,3), x^=k, x-=y, x=ROL32(x,8))

#define U8ToU32(d8, d32) {\
  u32 z;\
  d32 = *(d8);\
  z = *(d8+1);  d32 |= (z << 8);\
  z = *(d8+2);  d32 |= (z << 16);\
  z = *(d8+3);  d32 |= (z << 24);\
}

#define U32ToU8(d32, d8) {\
  *(d8) = d32 & 0xff;\
  *(d8+1) = (d32 >> 8) & 0xff;\
  *(d8+2) = (d32 >> 16) & 0xff;\
  *(d8+3) = (d32 >> 24) & 0xff;\
}

#ifdef WORD_IN
int Encrypt(u32 *u,u32 *v,u32 key[])
#else
int Encrypt(u8 *u, u32 key[])
#endif
{
  u32 x, y;
#ifdef WORD_IN
  x=*u,y=*v;
#else
  U8ToU32(u, y);
  U8ToU32(u+4, x);
#endif

#if LOOP == 1
  for(u32 i=0;i<ROUNDS;i++)
  {
    R(x,y,key[i]);
  }
#elif LOOP == 3
  for(u32 i=0;i<ROUNDS;i+=3)
  {
    R(x,y,key[i]);
    R(x,y,key[i+1]);
    R(x,y,key[i+2]);
  }
#elif LOOP == 9
	for(int i = 0; i < ROUNDS; i+=9)
	{
		R(x, y, key[i]);
		R(x, y, key[i+1]);
		R(x, y, key[i+2]);
		R(x, y, key[i+3]);
		R(x, y, key[i+4]);
		R(x, y, key[i+5]);
		R(x, y, key[i+6]);
		R(x, y, key[i+7]);
		R(x, y, key[i+8]);
	}
#elif LOOP == 0
	R(x, y, key[0]);
	R(x, y, key[1]);
	R(x, y, key[2]);
	R(x, y, key[3]);
	R(x, y, key[4]);
	R(x, y, key[5]);
	R(x, y, key[6]);
	R(x, y, key[7]);
	R(x, y, key[8]);
	R(x, y, key[9]);
	R(x, y, key[10]);
	R(x, y, key[11]);
	R(x, y, key[12]);
	R(x, y, key[13]);
	R(x, y, key[14]);
	R(x, y, key[15]);
	R(x, y, key[16]);
	R(x, y, key[17]);
	R(x, y, key[18]);
	R(x, y, key[19]);
	R(x, y, key[20]);
	R(x, y, key[21]);
	R(x, y, key[22]);
	R(x, y, key[23]);
	R(x, y, key[24]);
	R(x, y, key[25]);
	R(x, y, key[26]);
#endif

#ifdef WORD_IN
  *u=x; *v=y;
#else
  U32ToU8(y, u);
  U32ToU8(x, u+4);
#endif

  return 0;
}

#ifdef WORD_IN
int Decrypt(u32 *u,u32 *v,u32 key[])
#else
int Decrypt(u8 *u, u32 key[])
#endif
{
  u32 x, y;
#ifdef WORD_IN
  x=*u,y=*v;
#else
  U8ToU32(u, y);
  U8ToU32(u+4, x);
#endif

#if LOOP == 1
  for(int i=ROUNDS-1;i>=0;i--)
  {
	  RI(x,y,key[i]);
  }
#elif LOOP == 3
  for(int i=ROUNDS-1;i>=0;i-=3)
  {
	  RI(x,y,key[i]);
	  RI(x,y,key[i-1]);
	  RI(x,y,key[i-2]);
  }
#elif LOOP == 9
  for(int i=ROUNDS-1; i>=0; i-=9)
  {
	RI(x,y,key[i]);
	RI(x,y,key[i-1]);
	RI(x,y,key[i-2]);
	RI(x,y,key[i-3]);
	RI(x,y,key[i-4]);
	RI(x,y,key[i-5]);
	RI(x,y,key[i-6]);
	RI(x,y,key[i-7]);
	RI(x,y,key[i-8]);
  }
#else
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
  U32ToU8(y, u);
  U32ToU8(x, u+4);
#endif

  return 0;
}

#ifdef WORD_IN
int ExpandKey(u32 K[],u32 key[])
#else
int ExpandKey(u8 K[],u32 key[])
#endif
{
  u32 A, B, C, D;
#ifdef WORD_IN
  D=K[3],C=K[2],B=K[1],A=K[0];
#else
  U8ToU32(K, A);
  U8ToU32(K+4, B);
  U8ToU32(K+8, C);
  U8ToU32(K+12, D);
#endif

#if LOOP == 1 || LOOP == 3
  for(u32 i=0;i<27;i+=3){
    key[i]=A; R(B,A,i);
    key[i+1]=A; R(C,A,i+1);
    key[i+2]=A; R(D,A,i+2);
  }
#elif LOOP == 9
  for(u32 i=0; ; i+=9){
    key[i]=A;   R(B,A,i);
    key[i+1]=A; R(C,A,i+1);
    key[i+2]=A; R(D,A,i+2);
    key[i+3]=A; R(B,A,i+3);
    key[i+4]=A; R(C,A,i+4);
    key[i+5]=A; R(D,A,i+5);
    key[i+6]=A; R(B,A,i+6);
    key[i+7]=A; R(C,A,i+7);
    key[i+8]=A;
    if(i == 18) break;
    R(D,A,i+8);
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
  key[26]=A;
#endif

  return 1;
}
