#ifndef _VF_EXTRAOPTIONS_H
#define _VF_EXTRAOPTIONS_H

#include "VersionFind_global.h"


/**********************************************************************
 *						Prototypes
 *********************************************************************/
void VF_cbExtraDwordRetrieve();
void VF_cbExtraDw();
void VF_cbExtraVirtualProtect();
void VF_cbExtraOpenMutexA();
void VF_cbEntry();
void VF_ExtraOptions(char* szFileName, unsigned int* extra_options, ErrMessageCallback errorCallback);

#endif
