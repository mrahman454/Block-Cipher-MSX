/******************************************************************************
*
*
* THIS CODE IS FURNISHED TO YOU "AS IS" WITHOUT WARRANTY OF ANY KIND.
*
*****************************************************************************/

#include "main.h"
#include <stdio.h>
#include <string.h>
#include "aes.h"

void aes_main(void)
{
  int i;
  uint32_t rkeys[480];
  unsigned char key0[32];
  unsigned char ctext0[16*8], ptext0[16*8];

 // 2B7E1516 28AED2A6 ABF71588 09CF4F3C
  key0[3] = 0x16;
  key0[2] = 0x15;
  key0[1] = 0x7E;
  key0[0] = 0x2B;
  key0[7] = 0xA6;
  key0[6] = 0xD2;
  key0[5] = 0xAE;
  key0[4] = 0x28;
  key0[11] = 0x88;
  key0[10] = 0x15;
  key0[9] = 0xF7;
  key0[8] = 0xAB;
  key0[15] = 0x3C;
  key0[14] = 0x4F;
  key0[13] = 0xCF;
  key0[12] = 0x09;

  //6BC1BEE2 2E409F96 E93D7E11 7393172A
  //AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51
  ptext0[3] = 0xE2;
  ptext0[2] = 0xBE;
  ptext0[1] = 0xC1;
  ptext0[0] = 0x6B;
  ptext0[7] = 0x96;
  ptext0[6] = 0x9F;
  ptext0[5] = 0x40;
  ptext0[4] = 0x2E;
  ptext0[11] = 0x11;
  ptext0[10] = 0x7E;
  ptext0[9] = 0x3D;
  ptext0[8] = 0xE9;
  ptext0[15] = 0x2A;
  ptext0[14] = 0x17;
  ptext0[13] = 0x93;
  ptext0[12] = 0x73;

  printf("key0 =");
  for(i = 0; i < 16; i++) printf(" %02x", key0[i]);
  printf("\n");
  printf("ptext0 =");
  for(i = 0; i < 16; i++) printf(" %02x", ptext0[i]);
  printf("\n\n");

  /* Fully-fixsliced encryption functions */
  DWT->CYCCNT = 0;
  aes128_keyschedule_lut(rkeys, key0);
  printf("AES128 KeySchedule LUT\t%5ld cycles/keys.\n", DWT->CYCCNT);
  DWT->CYCCNT = 0;
  aes128_encrypt(ctext0, rkeys, ptext0);
  printf("AES128 Encrypt\t\t\t%5ld cycles/8blocks.\n", DWT->CYCCNT);

  DWT->CYCCNT = 0;
  aes256_keyschedule_lut(rkeys, key0);
  printf("AES256 KeySchedule LUT\t%5ld cycles/keys.\n", DWT->CYCCNT);
  DWT->CYCCNT = 0;
  aes256_encrypt(ctext0, rkeys, ptext0);
  printf("AES256 Encrypt\t\t\t%5ld cycles/8blocks.\n", DWT->CYCCNT);

  printf("\nctext0 =");
  for(i = 0; i < 16; i++) printf(" %02x", ctext0[i]);
  printf("\n");

}
