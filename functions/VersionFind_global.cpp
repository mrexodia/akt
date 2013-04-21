#ifndef _VF_GLOBAL_H
#define _VF_GLOBAL_H

#include "_global.h"

//Version number
HWND VF_shared;
bool VF_fdFileIsDll = false;
LPPROCESS_INFORMATION VF_fdProcessInfo = NULL;
char VF_szFileName[256]="";
char VF_version[20]="";

unsigned int VF_version_decrypt_call_dest=0;
unsigned int VF_version_decrypt_call=0;
unsigned int VF_version_decrypt_neweip=0;
unsigned int VF_version_decrypt_buffer=0;

//Extra Options
unsigned int VF_extra_options_reg=0;
unsigned int VF_extra_options=0;

//Raw Options
bool VF_minimal=false;
long VF_fdImageBase=0;
long VF_fdEntryPoint=0;
long VF_fdEntrySectionNumber=0;
long VF_fdEntrySectionOffset=0;
long VF_fdEntrySectionSize=0;
unsigned int VF_raw_options=0;
unsigned int VF_raw_options_reg=0;



#endif
