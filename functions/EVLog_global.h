#ifndef _EV_GLOBAL_H
#define _EV_GLOBAL_H

#include "_global.h"

//Debugger
extern HWND EV_shared;
extern HWND EV_list_hwnd;
extern bool EV_fdFileIsDll;
extern LPPROCESS_INFORMATION EV_fdProcessInfo;
extern long EV_fdImageBase;
extern long EV_fdEntryPoint;
extern long EV_fdEntrySectionNumber;
extern long EV_fdEntrySectionSize;
extern long EV_fdEntrySectionOffset;
extern DWORD EV_bytes_read;
extern char EV_szFileName[256];
extern char EV_log_message[256];
extern char EV_guard_text[256];
extern DWORD EV_oldprotect;
extern ULONG_PTR EV_va;
extern bool EV_bpvp_set;

//Dialog
extern char EV_program_dir[256];

#endif
