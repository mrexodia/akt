#include "EVLog_global.h"

//Debugger
HWND EV_shared;
HWND EV_list_hwnd;
bool EV_fdFileIsDll = false;
LPPROCESS_INFORMATION EV_fdProcessInfo = NULL;
long EV_fdImageBase = NULL;
long EV_fdEntryPoint = NULL;
long EV_fdEntrySectionNumber = NULL;
long EV_fdEntrySectionSize = NULL;
long EV_fdEntrySectionOffset = NULL;
DWORD EV_bytes_read=0;
char EV_szFileName[256]="";
char EV_log_message[256]="";
char EV_guard_text[256]="Break!";
DWORD EV_oldprotect=0;
ULONG_PTR EV_va;
bool EV_bpvp_set=false;

//Dialog
char EV_program_dir[256]="";
