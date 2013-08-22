#ifndef _IH_CODEGEN_H
#define _IH_CODEGEN_H

#include "InlineHelper_global.h"
#include "..\template.h"

/**********************************************************************
 *						Prototypes
 *********************************************************************/
void IH_GenerateAsmCode(const char* szFileName, char* codeText, bool fileIsDll, IH_InlineHelperData_t TargetData);

#endif
