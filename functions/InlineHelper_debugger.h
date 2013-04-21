#ifndef _IH_DEBUGGER_H
#define _IH_DEBUGGER_H

#include "InlineHelper_global.h"
#include "InlineHelper_codegen.h"

BYTE IH_FindCrcStart(BYTE* data);
unsigned int IH_FindFreeSpace(BYTE* d, unsigned int size);
void IH_GetFreeSpaceAddr(void);
void IH_GetImportTableAddresses();
void IH_cbOutputDebugStringA();
void IH_cbVirtualProtect();
void IH_cbOpenMutexA();
void IH_cbEntryPoint();
void IH_cbDllEntryPoint();
DWORD WINAPI IH_DebugThread(LPVOID lpStartAddress);

#endif
