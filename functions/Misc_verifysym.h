#ifndef _MSC_VERIFYSYM_H
#define _MSC_VERIFYSYM_H

#include "Misc_global.h"

#define max_bufsize 65535

unsigned int MSC_FindMagicPattern(BYTE* d, unsigned int size, unsigned int* ebp_sub);
void MSC_cbMagicValue();
void MSC_VR_cbVirtualProtect();
void MSC_VR_cbOpenMutexA();
void MSC_VR_cbEntry();
DWORD WINAPI MSC_VR_GetMagic(void* lpvoid);
unsigned int MSC_VR_GenerateNumber_core(int push_value, int* in_value);
unsigned int MSC_VR_GenerateNumberDword(int* in_value);
void MSC_VR_TEA_Decrypt(unsigned int* k, unsigned char* data, unsigned int length, int flag);
void MSC_VR_TEA_Decrypt_Nrounds(unsigned int *k, unsigned int *data, unsigned int rounds);
int MSC_VR_brute(unsigned int _magic1, unsigned int _magic2, unsigned int _sym, unsigned int _md5_ecdsa, unsigned char* data, unsigned int data_size);
void MSC_VR_StepProgressBar(int total_keys);
DWORD WINAPI MSC_VR_BruteThread(LPVOID arg);

#endif
