#ifndef _KEYGENBLOWFISH_H
#define _KEYGENBLOWFISH_H

#include "keygen_random.h"

#include <stdlib.h>

const int MAXKEYBYTES = 56; /* 448-bit maximum key; additional bits ignored. */
const int N = 16;

typedef struct CipherKeyStruct
{
    unsigned long S[4][256];
    unsigned long P[18];
} CipherKey;

unsigned long F(CipherKey* bc, unsigned long x);
void encipher(CipherKey* c, unsigned long* xl, unsigned long* xr);
void decipher(CipherKey* c, unsigned long* xl, unsigned long* xr);
void initialize(CipherKey* c, const char* keybytes, int keylength, unsigned long seed);
CipherKey* CreateCipherKey(const char* keybytes, int length);
void ReleaseCipherKey(CipherKey* key);
void Encipher(CipherKey* key, char* buffer, int length);
void Decipher(CipherKey* key, char* buffer, int length);

#endif
