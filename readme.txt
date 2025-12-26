# Overview

A reference implementation of Multiply-Shift-XOR (MSX) block cipher suitable for microcontrollers (e.g. ARM or AVR). 
Implementations of Speck and AES block ciphers are also included for comparison. 

1.MSX

 MSX
 +- MSX-64 ... 64bit block MSX cipher
  ||
  |+- Src
  ||  msx_main.c
  ||  msx-64.c
  ||  f_func.h
  ||  update_st.h
  ||
  |+- Inc ... header files
  |   define.h
  |   main.h
  |   stm32f4xx_hal_conf.h
  |   stm32f4xx_it.h
  |
 +- MSX-128 ... 128bit block MSX cipher
  
# How to use

Call the msx_main() defined in msx_main.c from main().
You will need to create main() routine separately.
This msx_main.c was created for STM32CubeIDE, so if you want to run it in a different environment,
you may need to modify msx_measure(), which performs performance measurement. 
Those defined in main.h and DWT->CYCCNT variable are specific to the environment.

msx_main.c is the main body of the MSX encryption.
The implementation of the encryption function msx_enc() and the decryption function msx_dec() is determined by IO and LOOP defined in define.h.
If IO is defined, the plaintext and ciphertext are specified separately as arguments to msx_enc()/msx_dec(). 
If the definition is removed, the input data is overwritten by the output data.
LOOP switches the loop implementation of msx_enc()/msx_dec().
You will need to specify one of the values listed in the comments in the header file.

The same applies to MSX-128.
If you want to change the master key length, modify the value of SK_BIT in define.h.

2.Speck

C implementation of Speck cipher. 

 Speck
 +- Speck-64-128  ...  Speck with 64bit block 128bit key
 +- Speck-128-128 ... Speck with 128bit block 128bit key
 +- Speck-128-256 ... Speck with 128bit block 256bit key

The file structure and usage are basically the same as MSX.
The original Speck source code used 32-bit or 64-bit variables for plain text, cipher text, and master key types. They are modified to use general byte sequence arguments.
These can be switched by the presence or absence of the WORD_IN definition in define.h.
As with MSX, the LOOP definition can be used to switch between the Encrypt and Decrypt loop implementations.

3.AES

Highly optimized implementation of AES for microcontrollers, using "fixslicing" technique. 

 AES
 +- barrel_shiftrows  ... barrel shift implementation AES
 +- fixslicing        ... fixslicing implementation AES

The usage is mostly the same as MSX/Speck. 
