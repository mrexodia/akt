#ifndef _VF_GLOBAL_H
#define _VF_GLOBAL_H

#include "_global.h"


/**********************************************************************
 *						Prototypes
 *********************************************************************/
unsigned int VF_FindUsbPattern(BYTE* d, unsigned int size);
unsigned int VF_FindAnd20Pattern(BYTE* d, unsigned int size);
unsigned int VF_Find40000Pattern(BYTE* d, unsigned int size);
unsigned int VF_FindShrPattern(BYTE* d, unsigned int size);
bool VF_IsMinimalProtection(char* szFileName, ULONG_PTR va, long parSectionNumber);
void VF_FatalError(const char* szMessage, cbErrorMessage ErrorMessageCallback);
unsigned int VF_FindarmVersion(BYTE* d, unsigned int size);
unsigned int VF_FindPushAddr(BYTE* d, unsigned int size, unsigned int addr);

#endif
