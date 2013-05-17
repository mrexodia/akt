#ifndef _IH_DECRYPT_H
#define _IH_DECRYPT_H

#include "InlineHelper_global.h"


/**********************************************************************
 *						Prototypes
 *********************************************************************/
void IHD_FatalError(const char* msg);
unsigned int IHD_FindJump(BYTE* d, unsigned int size, char* reg);
void IHD_cbOEP();
void IHD_cbJumpOEP();
void IHD_cbGuardPage();
void IHD_cbEntry();
DWORD WINAPI IHD_DebugThread(LPVOID lpStartAddress);
void IHD_Debugger(char* szFileName, cbErrorMessage ErrorMessageCallback);

#endif
