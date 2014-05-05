#ifndef _MSC_CHECKSUM_H
#define _MSC_CHECKSUM_H

#include "Misc_global.h"
#include "Misc_projectid.h"

unsigned int MakeChecksumV3(unsigned int sym);
unsigned int MakeChecksumV8(unsigned int sym, unsigned int salt);
void MSC_cbGetSalt();
void MSC_RetrieveSaltValue();
void MSC_SALT_cbOpenMutexA2();
void MSC_SALT_cbVirtualProtect();
void MSC_SALT_cbOpenMutexA();
void MSC_SALT_cbEntry();
DWORD WINAPI MSC_GetSalt(void* lpvoid);
unsigned long MSC_CHK_mult(long p, long q);
unsigned long MSC_CHK_NextRandomRange(long range);
unsigned char* MSC_CHK_GetCryptBytes(unsigned int seed, unsigned int size);
unsigned char* MSC_CHK_Decrypt(unsigned char** data, unsigned char** rand, unsigned int size);
bool MSC_CHK_DecryptCerts(unsigned int* seed, unsigned char* raw_data, unsigned int raw_size);
void MSC_CHK_cbGetOtherSeed();
void MSC_CHK_cbOtherSeeds();
void MSC_CHK_cbReturnSeed1();
void MSC_CHK_cbSeed1();
void MSC_CHK_cbCertificateFunction();
void MSC_CHK_cbVirtualProtect();
void MSC_CHK_cbOpenMutexA();
void MSC_CHK_cbEntry();
DWORD WINAPI MSC_FindChecksum(void* lpvoid);

#endif
