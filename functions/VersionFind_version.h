#ifndef _VF_VERSION_H
#define _VF_VERSION_H

#include "VersionFind_global.h"


/**********************************************************************
 *						Prototypes
 *********************************************************************/
void VF_cbVerGetVersion();
void VF_cbVerOnDecryptVersion();
void VF_cbVerReturnDecryptCall();
void VF_cbVerDecryptCall();
void VF_cbVerVirtualProtect();
void VF_cbVerOpenMutexA();
void VF_cbVerEntry();
void VF_Version(char* szFileName, char* szVersion, ErrMessageCallback ErrorMessageCallback);

#endif
