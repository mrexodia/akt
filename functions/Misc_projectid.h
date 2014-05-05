#ifndef _MSC_PROJECTID_H
#define _MSC_PROJECTID_H

#include "Misc_global.h"

unsigned int MSC_FindCertificateFunctionOld(BYTE* d, unsigned int size);
unsigned int MSC_FindCertificateFunctionNew(BYTE* d, unsigned int size);
unsigned int MSC_FindCertificateMarkers(BYTE* d, unsigned int size);
unsigned int MSC_FindCertificateMarkers2(BYTE* d, unsigned int size);
unsigned long MSC_mult(long p, long q);
unsigned long MSC_NextRandomRange(long range);
unsigned char* MSC_GetCryptBytes(unsigned int seed, unsigned int size);
unsigned char* MSC_Decrypt(unsigned char** data, unsigned char** rand, unsigned int size);
char* MSC_DecryptCerts(unsigned int* seed, unsigned char* raw_data, unsigned int raw_size);
void MSC_cbGetOtherSeed();
void MSC_cbOtherSeeds();
void MSC_cbReturnSeed1();
void MSC_cbSeed1();
void MSC_cbCertificateFunction();
void MSC_PRJ_cbVirtualProtect();
void MSC_PRJ_cbOpenMutexA();
void MSC_PRJ_cbEntry();
DWORD WINAPI MSC_GetProjectID(void* lpvoid);

#endif
