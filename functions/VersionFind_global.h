#ifndef _VF_GLOBAL_H
#define _VF_GLOBAL_H

#include "_global.h"

extern HWND VF_shared;
extern bool VF_fdFileIsDll;
extern LPPROCESS_INFORMATION VF_fdProcessInfo;
extern char VF_szFileName[256];
extern char VF_version[20];

extern unsigned int VF_version_decrypt_call_dest;
extern unsigned int VF_version_decrypt_call;
extern unsigned int VF_version_decrypt_neweip;
extern unsigned int VF_version_decrypt_buffer;

extern unsigned int VF_extra_options_reg;
extern unsigned int VF_extra_options;

extern bool VF_minimal;
extern long VF_fdImageBase;
extern long VF_fdEntryPoint;
extern long VF_fdEntrySectionNumber;
extern long VF_fdEntrySectionOffset;
extern long VF_fdEntrySectionSize;
extern unsigned int VF_raw_options;
extern unsigned int VF_raw_options_reg;

unsigned int VF_FindUsbPattern(BYTE* d, unsigned int size);
unsigned int VF_FindAnd20Pattern(BYTE* d, unsigned int size);
unsigned int VF_FindAnd40000Pattern(BYTE* d, unsigned int size);
bool VF_IsMinimalProtection(ULONG_PTR va);
void VF_FatalError(const char* msg);
unsigned int VF_FindarmVersion(BYTE* d, unsigned int size);
unsigned int VF_FindPushAddr(BYTE* d, unsigned int size, unsigned int addr);

#endif
