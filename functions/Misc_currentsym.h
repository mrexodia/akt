#ifndef _MSC_CURRENTSYM_H
#define _MSC_CURRENTSYM_H

#include "Misc_global.h"

unsigned int FindMagicPattern(BYTE* d, unsigned int size);
void MSC_cbGetACP();
void MSC_cbSymGet();
void MSC_cbVirtualProtect();
void MSC_cbOpenMutexA();
void MSC_cbEntry();
DWORD WINAPI MSC_CurSymDebugThread(void* lpvoid);

#endif
