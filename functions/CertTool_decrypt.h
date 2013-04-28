#ifndef _CT_DECRYPT_H
#define _CT_DECRYPT_H

#include "CertTool_global.h"

extern unsigned long CT_a;

unsigned long CT_mult(long p, long q);
unsigned long CT_NextRandomRange(long range);
unsigned char* CT_GetCryptBytes(unsigned int seed, unsigned int size);
unsigned char* CT_Decrypt(unsigned char** data, unsigned char** rand, unsigned int size);
void CT_DecryptCerts();

#endif
