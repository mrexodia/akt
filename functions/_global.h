#ifndef _GLOBAL_H
#define _GLOBAL_H

#define _WIN32_WINNT 0x0501
#define WINVER 0x0501
#define _WIN32_IE 0x0500

//file browse
#define WM_BROWSE WM_USER

#include <string>
#include <vector>
#include <windows.h>
#include <commctrl.h>

#include "..\resource.h"
#include "..\TitanEngine\TitanEngine.h"
#include "..\BeaEngine/BeaEngine.h"
#include "..\exception/akt_exception.h"

#include "keygen\keygen_main.h"

/**********************************************************************
 *						Standard Callbacks
 *********************************************************************/
typedef void (*cbErrorMessage)(char*, char*);
typedef void (*cbGenericTwoArg)(void*, void*);
typedef void (*cbStd)();

extern char sg_szAKTDirectory[256];
extern char sg_szPluginIniFilePath[256];

extern HINSTANCE hInst;
extern bool log_version;
extern char program_dir[256];

UINT DetermineRegisterFromText(char* reg_text);
unsigned int FindDwordInMemory(BYTE* dump_addr, unsigned dword_to_find, unsigned int filesize);
void LeftClick();
void PasteFromClipboard(char* d, int maxlen);
void CopyToClipboard(const char* text);
char* FormatTextHex(const char* text);
void SetLevelList(HWND hwndDlg);
void NoFocus();
bool IsHexChar(char c);
void FormatHex(char* string);
int StringToByteArray(const char* s, unsigned char* d, int d_len);
int ByteArrayToString(unsigned char* s, char* d, int s_len, int d_len);
char* EncodeShortV3(unsigned char* keybytes, int keylength, bool level10);
int DecodeShortV3(const char* serial, bool level10, unsigned char* dest, int dest_len);
unsigned int FindBAADF00DPattern(BYTE* d, unsigned int size);
unsigned int FindSalt1Pattern(BYTE* d, unsigned int size);
unsigned int FindSalt2Pattern(BYTE* d, unsigned int size);
bool IsArmadilloProtected(ULONG_PTR va);
unsigned int Find960Pattern(BYTE* d, unsigned int size);
unsigned int FindEB6APattern(BYTE* d, unsigned int size);
unsigned int FindCallPattern(BYTE* d, unsigned int size);
bool FixIsDebuggerPresent(HANDLE hProcess, bool hide);
void* malloc2(size_t size);
void free2(void *address);
void UpdateHorizontalScrollLen(HWND list, const char* string);
const char* wpmerror();
const char* rpmerror();
bool BrowseFileOpen(HWND owner, const char* filter, const char* defext, char* filename, int filename_size, const char* init_dir);

/**
Structures
*/
typedef struct _NTPEB
{
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN Spare;
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    VOID* LoaderData;
    VOID* ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PVOID FastPebLock;
    void* FastPebLockRoutine;
    void* FastPebUnlockRoutine;
    ULONG EnvironmentUpdateCount;
    PVOID* KernelCallbackTable;
    PVOID EventLogSection;
    PVOID EventLog;
    void* FreeList;
    ULONG TlsExpansionCounter;
    PVOID TlsBitmap;
    ULONG TlsBitmapBits[0x2];
    PVOID ReadOnlySharedMemoryBase;
    PVOID ReadOnlySharedMemoryHeap;
    PVOID* ReadOnlyStaticServerData;
    PVOID AnsiCodePageData;
    PVOID OemCodePageData;
    PVOID UnicodeCaseTableData;
    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;
    BYTE  Spare2[0x4];
    LARGE_INTEGER CriticalSectionTimeout;
    ULONG HeapSegmentReserve;
    ULONG HeapSegmentCommit;
    ULONG HeapDeCommitTotalFreeThreshold;
    ULONG HeapDeCommitFreeBlockThreshold;
    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    PVOID* *ProcessHeaps;
    PVOID diSharedHandleTable;
    PVOID ProcessStarterHelper;
    PVOID GdiDCAttributeList;
    PVOID  LoaderLock;
    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    ULONG OSBuildNumber;
    ULONG OSPlatformId;
    ULONG ImageSubSystem;
    ULONG ImageSubSystemMajorVersion;
    ULONG ImageSubSystemMinorVersion;
    ULONG  GdiHandleBuffer[0x22];
    ULONG PostProcessInitRoutine;
    ULONG TlsExpansionBitmap;
    BYTE TlsExpansionBitmapBits[0x80];
    ULONG SessionId;
} NTPEB, *PNTPEB;


#endif
