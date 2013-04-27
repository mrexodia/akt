#ifndef _IH_GLOBAL_H
#define _IH_GLOBAL_H

#include "_global.h"

extern long IH_fdImageBase;
extern long IH_fdEntryPoint;
extern long IH_fdEntrySectionNumber;
extern long IH_fdEntrySectionSize;
extern long IH_fdEntrySectionOffset;

extern char IH_program_dir[256];
extern char IH_current_dir[256];
extern char IH_szFileName[256];
extern char IH_code_text[2048];
extern char IH_debugProgramDir[256];
extern char IH_security_addr_register[4];

//extern int IH_outputdebugcount;
extern int IH_outputdebugcount_total;
extern int IH_crc_base;

extern unsigned int IH_addr_VirtualProtect;
extern unsigned int IH_addr_OutputDebugStringA;
extern unsigned int IH_addr_WriteProcessMemory;
extern unsigned int IH_empty_entry;
extern unsigned int IH_crc_original_vals[5];
extern unsigned int IH_OEP;

extern bool IH_fdFileIsDll;

extern HWND IH_shared;
extern LPPROCESS_INFORMATION IH_fdProcessInfo;

extern HINSTANCE PLUGIN_INST;
typedef char*(*PLUGINFO)(void);
typedef void(*PLUGFUNC)(HINSTANCE hInst, HWND hwndDlg, const char* register_vp, const char* progdir, unsigned int imagebase);
extern PLUGINFO PluginInfo;
extern PLUGFUNC PluginFunction;
extern char IH_plugin_ini_file[256];

extern HBRUSH hb;
extern RECT rc;

extern HWND IHD_shared;
extern bool IHD_fdFileIsDll;
extern LPPROCESS_INFORMATION IHD_fdProcessInfo;
extern long IHD_fdImageBase;
extern ULONG_PTR IHD_va;
extern long IHD_fdLoadedBase;
extern long IHD_fdEntryPoint;
extern long IHD_fdSizeOfImage;
extern long IHD_fdEntrySectionNumber;
extern long IHD_fdEntrySectionSize;
extern long IHD_fdEntrySectionOffset;
extern long IHD_fdEntrySectionRawOffset;
extern long IHD_fdEntrySectionRawSize;
extern DWORD IHD_bytes_read;
extern char IHD_szFileName[256];
extern char IHD_log_message[256];
extern char IHD_reg;

extern unsigned int IHD_newentry;
extern unsigned int IHD_freespace;
extern BYTE* IHD_decryptSectionData;
extern unsigned int IHD_epsection_raw_offset;
extern bool IH_arma960;
extern unsigned int IH_arma960_add;

unsigned int IH_FindCallPattern(BYTE* d, unsigned int size);
unsigned int IH_FindEB6APattern(BYTE* d, unsigned int size);
unsigned int IH_Find960Pattern(BYTE* d, unsigned int size);

#endif
