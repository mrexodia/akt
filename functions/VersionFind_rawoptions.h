#ifndef _VF_RAWOPTIONS_H
#define _VF_RAWOPTIONS_H

#include "VersionFind_global.h"


/**********************************************************************
 *						Prototypes
 *********************************************************************/
void VF_cbRetrieveRawOptions();
void VF_cbMutexReturn();
void VF_cbOpOpenMutexA();
void VF_cbOpGetCommandLine();
void VF_cbOpEntry();
bool VF_RawOptions(char* szFileName, unsigned int* raw_options, bool* bIsMinimal, cbErrorMessage ErrorMessageCallback);

#endif
