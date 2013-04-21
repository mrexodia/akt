#ifndef _CT_DEBUGGER
#define _CT_DEBUGGER

#include "CertTool_global.h"
#include "CertTool_parser.h"

void CT_cbGetSalt();
void CT_RetrieveSaltValue();
void CT_cbEndBigLoop();
void CT_cbTeaDecrypt();
void CT_cbMagicJump();
void CT_cbMagicValue();
UINT CT_DetermineRegisterFromByte(unsigned char byte);
void CT_SortArray(unsigned int* a, int size);
void CT_cbGetOtherSeed();
void CT_cbOtherSeeds();
void CT_cbReturnSeed1();
void CT_cbSeed1();
void CT_cbCertificateFunction();
void CT_cbVirtualProtect();
void CT_cbOpenMutexA();
void CT_cbEntry();
DWORD WINAPI CT_FindCertificates(void* lpvoid);

#endif
