#ifndef _EV_DEBUGGER_H
#define _EV_DEBUGGER_H

#include "EVLog_global.h"

void RemoveListDuplicates(HWND hwndDlg, UINT id);
unsigned int EV_FindSetEnvPattern(BYTE* d, unsigned int size, bool skip_first);
unsigned int EV_FindSetEnvPatternOld(BYTE* d, unsigned int size, bool skip_first);
unsigned int EV_FindSetEnvPatternOldOld(BYTE* d, unsigned int size, bool skip_first);
void EV_FatalError(const char* msg);
void EV_BreakDebugger();
void EV_cbEndLog();
void EV_log_var_valW(const wchar_t* varname, const wchar_t* varvalue);
void EV_log_var_valA(const char* varname, const char* varvalue);
void EV_cbSetEnvW();
void EV_cbSetEnvA();
void EV_cbVirtualProtect();
void EV_cbOpenMutexA();
void EV_cbEntry();
DWORD WINAPI EV_DebugThread(LPVOID lpStartAddress);

#endif
