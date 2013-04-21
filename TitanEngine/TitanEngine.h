#ifndef TITANENGINE
#define TITANENGINE

#if _MSC_VER > 1000
#pragma once
#endif

#include <windows.h>

#pragma pack(push, 1)

/* Engine.Libs:
#define TitanEngineLinkLibs
#define TitanEngineSubFolderSDK // Comment out this line to have SDK in default folder!

#ifdef TitanEngineLinkLibs
	#ifdef TitanEngineSubFolderSDK
		#if defined(_WIN64)
			#pragma comment(lib, "sdk\\TitanEngine_x64.lib")
		#else
			#pragma comment(lib, "sdk\\TitanEngine_x86.lib")
		#endif
	#else
		#if defined(_WIN64)
			#pragma comment(lib, "TitanEngine_x64.lib")
		#else
			#pragma comment(lib, "TitanEngine_x86.lib")
		#endif
	#endif
#endif*/

// Global.Constant.Structure.Declaration:
// Engine.External:
#define UE_ACCESS_READ 0
#define UE_ACCESS_WRITE 1
#define UE_ACCESS_ALL 2

#define UE_HIDE_BASIC 1

#define UE_PLUGIN_CALL_REASON_PREDEBUG 1
#define UE_PLUGIN_CALL_REASON_EXCEPTION 2
#define UE_PLUGIN_CALL_REASON_POSTDEBUG 3

#define TEE_HOOK_NRM_JUMP 1
#define TEE_HOOK_NRM_CALL 3
#define TEE_HOOK_IAT 5

#define UE_ENGINE_ALOW_MODULE_LOADING 1
#define UE_ENGINE_AUTOFIX_FORWARDERS 2
#define UE_ENGINE_PASS_ALL_EXCEPTIONS 3
#define UE_ENGINE_NO_CONSOLE_WINDOW 4
#define UE_ENGINE_BACKUP_FOR_CRITICAL_FUNCTIONS 5
#define UE_ENGINE_CALL_PLUGIN_CALLBACK 6
#define UE_ENGINE_RESET_CUSTOM_HANDLER 7
#define UE_ENGINE_CALL_PLUGIN_DEBUG_CALLBACK 8

#define UE_OPTION_REMOVEALL 1
#define UE_OPTION_DISABLEALL 2
#define UE_OPTION_REMOVEALLDISABLED 3
#define UE_OPTION_REMOVEALLENABLED 4

#define UE_STATIC_DECRYPTOR_XOR 1
#define UE_STATIC_DECRYPTOR_SUB 2
#define UE_STATIC_DECRYPTOR_ADD 3

#define UE_STATIC_DECRYPTOR_FOREWARD 1
#define UE_STATIC_DECRYPTOR_BACKWARD 2

#define UE_STATIC_KEY_SIZE_1 1
#define UE_STATIC_KEY_SIZE_2 2
#define UE_STATIC_KEY_SIZE_4 4
#define UE_STATIC_KEY_SIZE_8 8

#define UE_STATIC_APLIB 1
#define UE_STATIC_APLIB_DEPACK 2
#define UE_STATIC_LZMA 3

#define UE_STATIC_HASH_MD5 1
#define UE_STATIC_HASH_SHA1 2
#define UE_STATIC_HASH_CRC32 3

#define UE_RESOURCE_LANGUAGE_ANY -1

#define UE_PE_OFFSET 0
#define UE_IMAGEBASE 1
#define UE_OEP 2
#define UE_SIZEOFIMAGE 3
#define UE_SIZEOFHEADERS 4
#define UE_SIZEOFOPTIONALHEADER 5
#define UE_SECTIONALIGNMENT 6
#define UE_IMPORTTABLEADDRESS 7
#define UE_IMPORTTABLESIZE 8
#define UE_RESOURCETABLEADDRESS 9
#define UE_RESOURCETABLESIZE 10
#define UE_EXPORTTABLEADDRESS 11
#define UE_EXPORTTABLESIZE 12
#define UE_TLSTABLEADDRESS 13
#define UE_TLSTABLESIZE 14
#define UE_RELOCATIONTABLEADDRESS 15
#define UE_RELOCATIONTABLESIZE 16
#define UE_TIMEDATESTAMP 17
#define UE_SECTIONNUMBER 18
#define UE_CHECKSUM 19
#define UE_SUBSYSTEM 20
#define UE_CHARACTERISTICS 21
#define UE_NUMBEROFRVAANDSIZES 22
#define UE_SECTIONNAME 23
#define UE_SECTIONVIRTUALOFFSET 24
#define UE_SECTIONVIRTUALSIZE 25
#define UE_SECTIONRAWOFFSET 26
#define UE_SECTIONRAWSIZE 27
#define UE_SECTIONFLAGS 28

#define UE_CH_BREAKPOINT 1
#define UE_CH_SINGLESTEP 2
#define UE_CH_ACCESSVIOLATION 3
#define UE_CH_ILLEGALINSTRUCTION 4
#define UE_CH_NONCONTINUABLEEXCEPTION 5
#define UE_CH_ARRAYBOUNDSEXCEPTION 6
#define UE_CH_FLOATDENORMALOPERAND 7
#define UE_CH_FLOATDEVIDEBYZERO 8
#define UE_CH_INTEGERDEVIDEBYZERO 9
#define UE_CH_INTEGEROVERFLOW 10
#define UE_CH_PRIVILEGEDINSTRUCTION 11
#define UE_CH_PAGEGUARD 12
#define UE_CH_EVERYTHINGELSE 13
#define UE_CH_CREATETHREAD 14
#define UE_CH_EXITTHREAD 15
#define UE_CH_CREATEPROCESS 16
#define UE_CH_EXITPROCESS 17
#define UE_CH_LOADDLL 18
#define UE_CH_UNLOADDLL 19
#define UE_CH_OUTPUTDEBUGSTRING 20
#define UE_CH_AFTEREXCEPTIONPROCESSING 21
#define UE_CH_ALLEVENTS 22

#define UE_OPTION_HANDLER_RETURN_HANDLECOUNT 1
#define UE_OPTION_HANDLER_RETURN_ACCESS 2
#define UE_OPTION_HANDLER_RETURN_FLAGS 3
#define UE_OPTION_HANDLER_RETURN_TYPENAME 4

#define UE_BREAKPOINT_INT3 1
#define UE_BREAKPOINT_LONG_INT3 2
#define UE_BREAKPOINT_UD2 3

#define UE_BPXREMOVED 0
#define UE_BPXACTIVE 1
#define UE_BPXINACTIVE 2

#define UE_BREAKPOINT 0
#define UE_SINGLESHOOT 1
#define UE_HARDWARE 2
#define UE_MEMORY 3
#define UE_MEMORY_READ 4
#define UE_MEMORY_WRITE 5
#define UE_BREAKPOINT_TYPE_INT3 0x10000000
#define UE_BREAKPOINT_TYPE_LONG_INT3 0x20000000
#define UE_BREAKPOINT_TYPE_UD2 0x30000000

#define UE_HARDWARE_EXECUTE 4
#define UE_HARDWARE_WRITE 5
#define UE_HARDWARE_READWRITE 6

#define UE_HARDWARE_SIZE_1 7
#define UE_HARDWARE_SIZE_2 8
#define UE_HARDWARE_SIZE_4 9

#define UE_ON_LIB_LOAD 1
#define UE_ON_LIB_UNLOAD 2
#define UE_ON_LIB_ALL 3

#define UE_APISTART 0
#define UE_APIEND 1

#define UE_PLATFORM_x86 1
#define UE_PLATFORM_x64 2
#define UE_PLATFORM_ALL 3

#define UE_FUNCTION_STDCALL 1
#define UE_FUNCTION_CCALL 2
#define UE_FUNCTION_FASTCALL 3
#define UE_FUNCTION_STDCALL_RET 4
#define UE_FUNCTION_CCALL_RET 5
#define UE_FUNCTION_FASTCALL_RET 6
#define UE_FUNCTION_STDCALL_CALL 7
#define UE_FUNCTION_CCALL_CALL 8
#define UE_FUNCTION_FASTCALL_CALL 9
#define UE_PARAMETER_BYTE 0
#define UE_PARAMETER_WORD 1
#define UE_PARAMETER_DWORD 2
#define UE_PARAMETER_QWORD 3
#define UE_PARAMETER_PTR_BYTE 4
#define UE_PARAMETER_PTR_WORD 5
#define UE_PARAMETER_PTR_DWORD 6
#define UE_PARAMETER_PTR_QWORD 7
#define UE_PARAMETER_STRING 8
#define UE_PARAMETER_UNICODE 9

#define UE_CMP_NOCONDITION 0
#define UE_CMP_EQUAL 1
#define UE_CMP_NOTEQUAL 2
#define UE_CMP_GREATER 3
#define UE_CMP_GREATEROREQUAL 4
#define UE_CMP_LOWER 5
#define UE_CMP_LOWEROREQUAL 6
#define UE_CMP_REG_EQUAL 7
#define UE_CMP_REG_NOTEQUAL 8
#define UE_CMP_REG_GREATER 9
#define UE_CMP_REG_GREATEROREQUAL 10
#define UE_CMP_REG_LOWER 11
#define UE_CMP_REG_LOWEROREQUAL 12
#define UE_CMP_ALWAYSFALSE 13

#define UE_EAX 1
#define UE_EBX 2
#define UE_ECX 3
#define UE_EDX 4
#define UE_EDI 5
#define UE_ESI 6
#define UE_EBP 7
#define UE_ESP 8
#define UE_EIP 9
#define UE_EFLAGS 10
#define UE_DR0 11
#define UE_DR1 12
#define UE_DR2 13
#define UE_DR3 14
#define UE_DR6 15
#define UE_DR7 16
#define UE_RAX 17
#define UE_RBX 18
#define UE_RCX 19
#define UE_RDX 20
#define UE_RDI 21
#define UE_RSI 22
#define UE_RBP 23
#define UE_RSP 24
#define UE_RIP 25
#define UE_RFLAGS 26
#define UE_R8 27
#define UE_R9 28
#define UE_R10 29
#define UE_R11 30
#define UE_R12 31
#define UE_R13 32
#define UE_R14 33
#define UE_R15 34
#define UE_CIP 35
#define UE_CSP 36
#define UE_SEG_GS 37
#define UE_SEG_FS 38
#define UE_SEG_ES 39
#define UE_SEG_DS 40
#define UE_SEG_CS 41
#define UE_SEG_SS 42

typedef struct
{
    DWORD PE32Offset;
    DWORD ImageBase;
    DWORD OriginalEntryPoint;
    DWORD NtSizeOfImage;
    DWORD NtSizeOfHeaders;
    WORD SizeOfOptionalHeaders;
    DWORD FileAlignment;
    DWORD SectionAligment;
    DWORD ImportTableAddress;
    DWORD ImportTableSize;
    DWORD ResourceTableAddress;
    DWORD ResourceTableSize;
    DWORD ExportTableAddress;
    DWORD ExportTableSize;
    DWORD TLSTableAddress;
    DWORD TLSTableSize;
    DWORD RelocationTableAddress;
    DWORD RelocationTableSize;
    DWORD TimeDateStamp;
    WORD SectionNumber;
    DWORD CheckSum;
    WORD SubSystem;
    WORD Characteristics;
    DWORD NumberOfRvaAndSizes;
} PE32Struct, *PPE32Struct;

typedef struct
{
    DWORD PE64Offset;
    DWORD64 ImageBase;
    DWORD OriginalEntryPoint;
    DWORD NtSizeOfImage;
    DWORD NtSizeOfHeaders;
    WORD SizeOfOptionalHeaders;
    DWORD FileAlignment;
    DWORD SectionAligment;
    DWORD ImportTableAddress;
    DWORD ImportTableSize;
    DWORD ResourceTableAddress;
    DWORD ResourceTableSize;
    DWORD ExportTableAddress;
    DWORD ExportTableSize;
    DWORD TLSTableAddress;
    DWORD TLSTableSize;
    DWORD RelocationTableAddress;
    DWORD RelocationTableSize;
    DWORD TimeDateStamp;
    WORD SectionNumber;
    DWORD CheckSum;
    WORD SubSystem;
    WORD Characteristics;
    DWORD NumberOfRvaAndSizes;
} PE64Struct, *PPE64Struct;

typedef struct
{
    bool NewDll;
    int NumberOfImports;
    ULONG_PTR ImageBase;
    ULONG_PTR BaseImportThunk;
    ULONG_PTR ImportThunk;
    char* APIName;
    char* DLLName;
} ImportEnumData, *PImportEnumData;

typedef struct
{
    HANDLE hThread;
    DWORD dwThreadId;
    void* ThreadStartAddress;
    void* ThreadLocalBase;
} THREAD_ITEM_DATA, *PTHREAD_ITEM_DATA;

typedef struct
{
    HANDLE hFile;
    void* BaseOfDll;
    HANDLE hFileMapping;
    void* hFileMappingView;
    char szLibraryPath[MAX_PATH];
    char szLibraryName[MAX_PATH];
} LIBRARY_ITEM_DATA, *PLIBRARY_ITEM_DATA;

typedef struct
{
    HANDLE hFile;
    void* BaseOfDll;
    HANDLE hFileMapping;
    void* hFileMappingView;
    wchar_t szLibraryPath[MAX_PATH];
    wchar_t szLibraryName[MAX_PATH];
} LIBRARY_ITEM_DATAW, *PLIBRARY_ITEM_DATAW;

typedef struct
{
    HANDLE hProcess;
    DWORD dwProcessId;
    HANDLE hThread;
    DWORD dwThreadId;
    HANDLE hFile;
    void* BaseOfImage;
    void* ThreadStartAddress;
    void* ThreadLocalBase;
} PROCESS_ITEM_DATA, *PPROCESS_ITEM_DATA;

typedef struct
{
    ULONG ProcessId;
    HANDLE hHandle;
} HandlerArray, *PHandlerArray;

typedef struct
{
    char PluginName[64];
    DWORD PluginMajorVersion;
    DWORD PluginMinorVersion;
    HMODULE PluginBaseAddress;
    void* TitanDebuggingCallBack;
    void* TitanRegisterPlugin;
    void* TitanReleasePlugin;
    void* TitanResetPlugin;
    bool PluginDisabled;
} PluginInformation, *PPluginInformation;

#define TEE_MAXIMUM_HOOK_SIZE 14
#define TEE_MAXIMUM_HOOK_RELOCS 7
#if defined(_WIN64)
#define TEE_MAXIMUM_HOOK_INSERT_SIZE 14
#else
#define TEE_MAXIMUM_HOOK_INSERT_SIZE 5
#endif

typedef struct HOOK_ENTRY
{
    bool IATHook;
    BYTE HookType;
    DWORD HookSize;
    void* HookAddress;
    void* RedirectionAddress;
    BYTE HookBytes[TEE_MAXIMUM_HOOK_SIZE];
    BYTE OriginalBytes[TEE_MAXIMUM_HOOK_SIZE];
    void* IATHookModuleBase;
    DWORD IATHookNameHash;
    bool HookIsEnabled;
    bool HookIsRemote;
    void* PatchedEntry;
    DWORD RelocationInfo[TEE_MAXIMUM_HOOK_RELOCS];
    int RelocationCount;
} HOOK_ENTRY, *PHOOK_ENTRY;

#define UE_DEPTH_SURFACE 0
#define UE_DEPTH_DEEP 1

#define UE_UNPACKER_CONDITION_SEARCH_FROM_EP 1

#define UE_UNPACKER_CONDITION_LOADLIBRARY 1
#define UE_UNPACKER_CONDITION_GETPROCADDRESS 2
#define UE_UNPACKER_CONDITION_ENTRYPOINTBREAK 3
#define UE_UNPACKER_CONDITION_RELOCSNAPSHOT1 4
#define UE_UNPACKER_CONDITION_RELOCSNAPSHOT2 5

#define UE_FIELD_OK 0
#define UE_FIELD_BROKEN_NON_FIXABLE 1
#define UE_FIELD_BROKEN_NON_CRITICAL 2
#define UE_FIELD_BROKEN_FIXABLE_FOR_STATIC_USE 3
#define UE_FIELD_BROKEN_BUT_CAN_BE_EMULATED 4
#define UE_FILED_FIXABLE_NON_CRITICAL 5
#define UE_FILED_FIXABLE_CRITICAL 6
#define UE_FIELD_NOT_PRESET 7
#define UE_FIELD_NOT_PRESET_WARNING 8

#define UE_RESULT_FILE_OK 10
#define UE_RESULT_FILE_INVALID_BUT_FIXABLE 11
#define UE_RESULT_FILE_INVALID_AND_NON_FIXABLE 12
#define UE_RESULT_FILE_INVALID_FORMAT 13

typedef struct
{
    BYTE OveralEvaluation;
    bool EvaluationTerminatedByException;
    bool FileIs64Bit;
    bool FileIsDLL;
    bool FileIsConsole;
    bool MissingDependencies;
    bool MissingDeclaredAPIs;
    BYTE SignatureMZ;
    BYTE SignaturePE;
    BYTE EntryPoint;
    BYTE ImageBase;
    BYTE SizeOfImage;
    BYTE FileAlignment;
    BYTE SectionAlignment;
    BYTE ExportTable;
    BYTE RelocationTable;
    BYTE ImportTable;
    BYTE ImportTableSection;
    BYTE ImportTableData;
    BYTE IATTable;
    BYTE TLSTable;
    BYTE LoadConfigTable;
    BYTE BoundImportTable;
    BYTE COMHeaderTable;
    BYTE ResourceTable;
    BYTE ResourceData;
    BYTE SectionTable;
} FILE_STATUS_INFO, *PFILE_STATUS_INFO;

typedef struct
{
    BYTE OveralEvaluation;
    bool FixingTerminatedByException;
    bool FileFixPerformed;
    bool StrippedRelocation;
    bool DontFixRelocations;
    DWORD OriginalRelocationTableAddress;
    DWORD OriginalRelocationTableSize;
    bool StrippedExports;
    bool DontFixExports;
    DWORD OriginalExportTableAddress;
    DWORD OriginalExportTableSize;
    bool StrippedResources;
    bool DontFixResources;
    DWORD OriginalResourceTableAddress;
    DWORD OriginalResourceTableSize;
    bool StrippedTLS;
    bool DontFixTLS;
    DWORD OriginalTLSTableAddress;
    DWORD OriginalTLSTableSize;
    bool StrippedLoadConfig;
    bool DontFixLoadConfig;
    DWORD OriginalLoadConfigTableAddress;
    DWORD OriginalLoadConfigTableSize;
    bool StrippedBoundImports;
    bool DontFixBoundImports;
    DWORD OriginalBoundImportTableAddress;
    DWORD OriginalBoundImportTableSize;
    bool StrippedIAT;
    bool DontFixIAT;
    DWORD OriginalImportAddressTableAddress;
    DWORD OriginalImportAddressTableSize;
    bool StrippedCOM;
    bool DontFixCOM;
    DWORD OriginalCOMTableAddress;
    DWORD OriginalCOMTableSize;
} FILE_FIX_INFO, *PFILE_FIX_INFO;

#if !defined (_WIN64)
#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/
#endif

// Global.Function.Declaration:
// TitanEngine.Dumper.functions:
    bool DumpProcess(HANDLE hProcess, LPVOID ImageBase, char* szDumpFileName, ULONG_PTR EntryPoint);
    bool DumpProcessW(HANDLE hProcess, LPVOID ImageBase, wchar_t* szDumpFileName, ULONG_PTR EntryPoint);
    bool DumpProcessEx(DWORD ProcessId, LPVOID ImageBase, char* szDumpFileName, ULONG_PTR EntryPoint);
    bool DumpProcessExW(DWORD ProcessId, LPVOID ImageBase, wchar_t* szDumpFileName, ULONG_PTR EntryPoint);
    bool DumpMemory(HANDLE hProcess, LPVOID MemoryStart, ULONG_PTR MemorySize, char* szDumpFileName);
    bool DumpMemoryW(HANDLE hProcess, LPVOID MemoryStart, ULONG_PTR MemorySize, wchar_t* szDumpFileName);
    bool DumpMemoryEx(DWORD ProcessId, LPVOID MemoryStart, ULONG_PTR MemorySize, char* szDumpFileName);
    bool DumpMemoryExW(DWORD ProcessId, LPVOID MemoryStart, ULONG_PTR MemorySize, wchar_t* szDumpFileName);
    bool DumpRegions(HANDLE hProcess, char* szDumpFolder, bool DumpAboveImageBaseOnly);
    bool DumpRegionsW(HANDLE hProcess, wchar_t* szDumpFolder, bool DumpAboveImageBaseOnly);
    bool DumpRegionsEx(DWORD ProcessId, char* szDumpFolder, bool DumpAboveImageBaseOnly);
    bool DumpRegionsExW(DWORD ProcessId, wchar_t* szDumpFolder, bool DumpAboveImageBaseOnly);
    bool DumpModule(HANDLE hProcess, LPVOID ModuleBase, char* szDumpFileName);
    bool DumpModuleW(HANDLE hProcess, LPVOID ModuleBase, wchar_t* szDumpFileName);
    bool DumpModuleEx(DWORD ProcessId, LPVOID ModuleBase, char* szDumpFileName);
    bool DumpModuleExW(DWORD ProcessId, LPVOID ModuleBase, wchar_t* szDumpFileName);
    bool PastePEHeader(HANDLE hProcess, LPVOID ImageBase, char* szDebuggedFileName);
    bool PastePEHeaderW(HANDLE hProcess, LPVOID ImageBase, wchar_t* szDebuggedFileName);
    bool ExtractSection(char* szFileName, char* szDumpFileName, DWORD SectionNumber);
    bool ExtractSectionW(wchar_t* szFileName, wchar_t* szDumpFileName, DWORD SectionNumber);
    bool ResortFileSections(char* szFileName);
    bool ResortFileSectionsW(wchar_t* szFileName);
    bool FindOverlay(char* szFileName, LPDWORD OverlayStart, LPDWORD OverlaySize);
    bool FindOverlayW(wchar_t* szFileName, LPDWORD OverlayStart, LPDWORD OverlaySize);
    bool ExtractOverlay(char* szFileName, char* szExtactedFileName);
    bool ExtractOverlayW(wchar_t* szFileName, wchar_t* szExtactedFileName);
    bool AddOverlay(char* szFileName, char* szOverlayFileName);
    bool AddOverlayW(wchar_t* szFileName, wchar_t* szOverlayFileName);
    bool CopyOverlay(char* szInFileName, char* szOutFileName);
    bool CopyOverlayW(wchar_t* szInFileName, wchar_t* szOutFileName);
    bool RemoveOverlay(char* szFileName);
    bool RemoveOverlayW(wchar_t* szFileName);
    bool MakeAllSectionsRWE(char* szFileName);
    bool MakeAllSectionsRWEW(wchar_t* szFileName);
    long AddNewSectionEx(char* szFileName, char* szSectionName, DWORD SectionSize, DWORD SectionAttributes, LPVOID SectionContent, DWORD ContentSize);
    long AddNewSectionExW(wchar_t* szFileName, char* szSectionName, DWORD SectionSize, DWORD SectionAttributes, LPVOID SectionContent, DWORD ContentSize);
    long AddNewSection(char* szFileName, char* szSectionName, DWORD SectionSize);
    long AddNewSectionW(wchar_t* szFileName, char* szSectionName, DWORD SectionSize);
    bool ResizeLastSection(char* szFileName, DWORD NumberOfExpandBytes, bool AlignResizeData);
    bool ResizeLastSectionW(wchar_t* szFileName, DWORD NumberOfExpandBytes, bool AlignResizeData);
    void SetSharedOverlay(char* szFileName);
    void SetSharedOverlayW(wchar_t* szFileName);
    char* GetSharedOverlay();
    wchar_t* GetSharedOverlayW();
    bool DeleteLastSection(char* szFileName);
    bool DeleteLastSectionW(wchar_t* szFileName);
    bool DeleteLastSectionEx(char* szFileName, DWORD NumberOfSections);
    bool DeleteLastSectionExW(wchar_t* szFileName, DWORD NumberOfSections);
    long long GetPE32DataFromMappedFile(ULONG_PTR FileMapVA, DWORD WhichSection, DWORD WhichData);
    long long GetPE32Data(char* szFileName, DWORD WhichSection, DWORD WhichData);
    long long GetPE32DataW(wchar_t* szFileName, DWORD WhichSection, DWORD WhichData);
    bool GetPE32DataFromMappedFileEx(ULONG_PTR FileMapVA, LPVOID DataStorage);
    bool GetPE32DataEx(char* szFileName, LPVOID DataStorage);
    bool GetPE32DataExW(wchar_t* szFileName, LPVOID DataStorage);
    bool SetPE32DataForMappedFile(ULONG_PTR FileMapVA, DWORD WhichSection, DWORD WhichData, ULONG_PTR NewDataValue);
    bool SetPE32Data(char* szFileName, DWORD WhichSection, DWORD WhichData, ULONG_PTR NewDataValue);
    bool SetPE32DataW(wchar_t* szFileName, DWORD WhichSection, DWORD WhichData, ULONG_PTR NewDataValue);
    bool SetPE32DataForMappedFileEx(ULONG_PTR FileMapVA, LPVOID DataStorage);
    bool SetPE32DataEx(char* szFileName, LPVOID DataStorage);
    long GetPE32SectionNumberFromVA(ULONG_PTR FileMapVA, ULONG_PTR AddressToConvert);
    long long ConvertVAtoFileOffset(ULONG_PTR FileMapVA, ULONG_PTR AddressToConvert, bool ReturnType);
    long long ConvertVAtoFileOffsetEx(ULONG_PTR FileMapVA, DWORD FileSize, ULONG_PTR ImageBase, ULONG_PTR AddressToConvert, bool AddressIsRVA, bool ReturnType);
    long long ConvertFileOffsetToVA(ULONG_PTR FileMapVA, ULONG_PTR AddressToConvert, bool ReturnType);
    long long ConvertFileOffsetToVAEx(ULONG_PTR FileMapVA, DWORD FileSize, ULONG_PTR ImageBase, ULONG_PTR AddressToConvert, bool ReturnType);
// TitanEngine.Realigner.functions:
    bool FixHeaderCheckSum(char* szFileName);
    bool FixHeaderCheckSumW(wchar_t* szFileName);
    long RealignPE(ULONG_PTR FileMapVA, DWORD FileSize, DWORD RealingMode);
    long RealignPEEx(char* szFileName, DWORD RealingFileSize, DWORD ForcedFileAlignment);
    long RealignPEExW(wchar_t* szFileName, DWORD RealingFileSize, DWORD ForcedFileAlignment);
    bool WipeSection(char* szFileName, int WipeSectionNumber, bool RemovePhysically);
    bool WipeSectionW(wchar_t* szFileName, int WipeSectionNumber, bool RemovePhysically);
    bool IsPE32FileValidEx(char* szFileName, DWORD CheckDepth, LPVOID FileStatusInfo);
    bool IsPE32FileValidExW(wchar_t* szFileName, DWORD CheckDepth, LPVOID FileStatusInfo);
    bool FixBrokenPE32FileEx(char* szFileName, LPVOID FileStatusInfo, LPVOID FileFixInfo);
    bool FixBrokenPE32FileExW(wchar_t* szFileName, LPVOID FileStatusInfo, LPVOID FileFixInfo);
    bool IsFileDLL(char* szFileName, ULONG_PTR FileMapVA);
    bool IsFileDLLW(wchar_t* szFileName, ULONG_PTR FileMapVA);
// TitanEngine.Hider.functions:
    void* GetPEBLocation(HANDLE hProcess);
    bool HideDebugger(HANDLE hProcess, DWORD PatchAPILevel);
    bool UnHideDebugger(HANDLE hProcess, DWORD PatchAPILevel);
// TitanEngine.Relocater.functions:
    void RelocaterCleanup();
    void RelocaterInit(DWORD MemorySize, ULONG_PTR OldImageBase, ULONG_PTR NewImageBase);
    void RelocaterAddNewRelocation(HANDLE hProcess, ULONG_PTR RelocateAddress, DWORD RelocateState);
    long RelocaterEstimatedSize();
    bool RelocaterExportRelocation(ULONG_PTR StorePlace, DWORD StorePlaceRVA, ULONG_PTR FileMapVA);
    bool RelocaterExportRelocationEx(char* szFileName, char* szSectionName);
    bool RelocaterExportRelocationExW(wchar_t* szFileName, char* szSectionName);
    bool RelocaterGrabRelocationTable(HANDLE hProcess, ULONG_PTR MemoryStart, DWORD MemorySize);
    bool RelocaterGrabRelocationTableEx(HANDLE hProcess, ULONG_PTR MemoryStart, ULONG_PTR MemorySize, DWORD NtSizeOfImage);
    bool RelocaterMakeSnapshot(HANDLE hProcess, char* szSaveFileName, LPVOID MemoryStart, ULONG_PTR MemorySize);
    bool RelocaterMakeSnapshotW(HANDLE hProcess, wchar_t* szSaveFileName, LPVOID MemoryStart, ULONG_PTR MemorySize);
    bool RelocaterCompareTwoSnapshots(HANDLE hProcess, ULONG_PTR LoadedImageBase, ULONG_PTR NtSizeOfImage, char* szDumpFile1, char* szDumpFile2, ULONG_PTR MemStart);
    bool RelocaterCompareTwoSnapshotsW(HANDLE hProcess, ULONG_PTR LoadedImageBase, ULONG_PTR NtSizeOfImage, wchar_t* szDumpFile1, wchar_t* szDumpFile2, ULONG_PTR MemStart);
    bool RelocaterChangeFileBase(char* szFileName, ULONG_PTR NewImageBase);
    bool RelocaterChangeFileBaseW(wchar_t* szFileName, ULONG_PTR NewImageBase);
    bool RelocaterRelocateMemoryBlock(ULONG_PTR FileMapVA, ULONG_PTR MemoryLocation, void* RelocateMemory, DWORD RelocateMemorySize, ULONG_PTR CurrentLoadedBase, ULONG_PTR RelocateBase);
    bool RelocaterWipeRelocationTable(char* szFileName);
    bool RelocaterWipeRelocationTableW(wchar_t* szFileName);
// TitanEngine.Resourcer.functions:
    long long ResourcerLoadFileForResourceUse(char* szFileName);
    long long ResourcerLoadFileForResourceUseW(wchar_t* szFileName);
    bool ResourcerFreeLoadedFile(LPVOID LoadedFileBase);
    bool ResourcerExtractResourceFromFileEx(ULONG_PTR FileMapVA, char* szResourceType, char* szResourceName, char* szExtractedFileName);
    bool ResourcerExtractResourceFromFile(char* szFileName, char* szResourceType, char* szResourceName, char* szExtractedFileName);
    bool ResourcerExtractResourceFromFileW(wchar_t* szFileName, char* szResourceType, char* szResourceName, char* szExtractedFileName);
    bool ResourcerFindResource(char* szFileName, char* szResourceType, DWORD ResourceType, char* szResourceName, DWORD ResourceName, DWORD ResourceLanguage, PULONG_PTR pResourceData, LPDWORD pResourceSize);
    bool ResourcerFindResourceW(wchar_t* szFileName, wchar_t* szResourceType, DWORD ResourceType, wchar_t* szResourceName, DWORD ResourceName, DWORD ResourceLanguage, PULONG_PTR pResourceData, LPDWORD pResourceSize);
    bool ResourcerFindResourceEx(ULONG_PTR FileMapVA, DWORD FileSize, wchar_t* szResourceType, DWORD ResourceType, wchar_t* szResourceName, DWORD ResourceName, DWORD ResourceLanguage, PULONG_PTR pResourceData, LPDWORD pResourceSize);
    void ResourcerEnumerateResource(char* szFileName, void* CallBack);
    void ResourcerEnumerateResourceW(wchar_t* szFileName, void* CallBack);
    void ResourcerEnumerateResourceEx(ULONG_PTR FileMapVA, DWORD FileSize, void* CallBack);
// TitanEngine.Threader.functions:
    bool ThreaderImportRunningThreadData(DWORD ProcessId);
    void* ThreaderGetThreadInfo(HANDLE hThread, DWORD ThreadId);
    void ThreaderEnumThreadInfo(void* EnumCallBack);
    bool ThreaderPauseThread(HANDLE hThread);
    bool ThreaderResumeThread(HANDLE hThread);
    bool ThreaderTerminateThread(HANDLE hThread, DWORD ThreadExitCode);
    bool ThreaderPauseAllThreads(bool LeaveMainRunning);
    bool ThreaderResumeAllThreads(bool LeaveMainPaused);
    bool ThreaderPauseProcess();
    bool ThreaderResumeProcess();
    long long ThreaderCreateRemoteThread(ULONG_PTR ThreadStartAddress, bool AutoCloseTheHandle, LPVOID ThreadPassParameter, LPDWORD ThreadId);
    bool ThreaderInjectAndExecuteCode(LPVOID InjectCode, DWORD StartDelta, DWORD InjectSize);
    long long ThreaderCreateRemoteThreadEx(HANDLE hProcess, ULONG_PTR ThreadStartAddress, bool AutoCloseTheHandle, LPVOID ThreadPassParameter, LPDWORD ThreadId);
    bool ThreaderInjectAndExecuteCodeEx(HANDLE hProcess, LPVOID InjectCode, DWORD StartDelta, DWORD InjectSize);
    void ThreaderSetCallBackForNextExitThreadEvent(LPVOID exitThreadCallBack);
    bool ThreaderIsThreadStillRunning(HANDLE hThread);
    bool ThreaderIsThreadActive(HANDLE hThread);
    bool ThreaderIsAnyThreadActive();
    bool ThreaderExecuteOnlyInjectedThreads();
    long long ThreaderGetOpenHandleForThread(DWORD ThreadId);
    void* ThreaderGetThreadData();
    bool ThreaderIsExceptionInMainThread();
// TitanEngine.Debugger.functions:
    void* StaticDisassembleEx(ULONG_PTR DisassmStart, LPVOID DisassmAddress);
    void* StaticDisassemble(LPVOID DisassmAddress);
    void* DisassembleEx(HANDLE hProcess, LPVOID DisassmAddress);
    void* Disassemble(LPVOID DisassmAddress);
    long StaticLengthDisassemble(LPVOID DisassmAddress);
    long LengthDisassembleEx(HANDLE hProcess, LPVOID DisassmAddress);
    long LengthDisassemble(LPVOID DisassmAddress);
    void* InitDebug(char* szFileName, char* szCommandLine, char* szCurrentFolder);
    void* InitDebugW(wchar_t* szFileName, wchar_t* szCommandLine, wchar_t* szCurrentFolder);
    void* InitDebugEx(char* szFileName, char* szCommandLine, char* szCurrentFolder, LPVOID EntryCallBack);
    void* InitDebugExW(wchar_t* szFileName, wchar_t* szCommandLine, wchar_t* szCurrentFolder, LPVOID EntryCallBack);
    void* InitDLLDebug(char* szFileName, bool ReserveModuleBase, char* szCommandLine, char* szCurrentFolder, LPVOID EntryCallBack);
    void* InitDLLDebugW(wchar_t* szFileName, bool ReserveModuleBase, wchar_t* szCommandLine, wchar_t* szCurrentFolder, LPVOID EntryCallBack);
    bool StopDebug();
    void SetBPXOptions(long DefaultBreakPointType);
    bool IsBPXEnabled(ULONG_PTR bpxAddress);
    bool EnableBPX(ULONG_PTR bpxAddress);
    bool DisableBPX(ULONG_PTR bpxAddress);
    bool SetBPX(ULONG_PTR bpxAddress, DWORD bpxType, LPVOID bpxCallBack);
    bool SetBPXEx(ULONG_PTR bpxAddress, DWORD bpxType, DWORD NumberOfExecution, DWORD CmpRegister, DWORD CmpCondition, ULONG_PTR CmpValue, LPVOID bpxCallBack, LPVOID bpxCompareCallBack, LPVOID bpxRemoveCallBack);
    bool DeleteBPX(ULONG_PTR bpxAddress);
    bool SafeDeleteBPX(ULONG_PTR bpxAddress);
    bool SetAPIBreakPoint(char* szDLLName, char* szAPIName, DWORD bpxType, DWORD bpxPlace, LPVOID bpxCallBack);
    bool DeleteAPIBreakPoint(char* szDLLName, char* szAPIName, DWORD bpxPlace);
    bool SafeDeleteAPIBreakPoint(char* szDLLName, char* szAPIName, DWORD bpxPlace);
    bool SetMemoryBPX(ULONG_PTR MemoryStart, DWORD SizeOfMemory, LPVOID bpxCallBack);
    bool SetMemoryBPXEx(ULONG_PTR MemoryStart, DWORD SizeOfMemory, DWORD BreakPointType, bool RestoreOnHit, LPVOID bpxCallBack);
    bool RemoveMemoryBPX(ULONG_PTR MemoryStart, DWORD SizeOfMemory);
    bool GetContextFPUDataEx(HANDLE hActiveThread, void* FPUSaveArea);
    long long GetContextDataEx(HANDLE hActiveThread, DWORD IndexOfRegister);
    long long GetContextData(DWORD IndexOfRegister);
    bool SetContextFPUDataEx(HANDLE hActiveThread, void* FPUSaveArea);
    bool SetContextDataEx(HANDLE hActiveThread, DWORD IndexOfRegister, ULONG_PTR NewRegisterValue);
    bool SetContextData(DWORD IndexOfRegister, ULONG_PTR NewRegisterValue);
    void ClearExceptionNumber();
    long CurrentExceptionNumber();
    bool MatchPatternEx(HANDLE hProcess, void* MemoryToCheck, int SizeOfMemoryToCheck, void* PatternToMatch, int SizeOfPatternToMatch, PBYTE WildCard);
    bool MatchPattern(void* MemoryToCheck, int SizeOfMemoryToCheck, void* PatternToMatch, int SizeOfPatternToMatch, PBYTE WildCard);
    long long FindEx(HANDLE hProcess, LPVOID MemoryStart, DWORD MemorySize, LPVOID SearchPattern, DWORD PatternSize, LPBYTE WildCard);
    long long Find(LPVOID MemoryStart, DWORD MemorySize, LPVOID SearchPattern, DWORD PatternSize, LPBYTE WildCard);
    bool FillEx(HANDLE hProcess, LPVOID MemoryStart, DWORD MemorySize, PBYTE FillByte);
    bool Fill(LPVOID MemoryStart, DWORD MemorySize, PBYTE FillByte);
    bool PatchEx(HANDLE hProcess, LPVOID MemoryStart, DWORD MemorySize, LPVOID ReplacePattern, DWORD ReplaceSize, bool AppendNOP, bool PrependNOP);
    bool Patch(LPVOID MemoryStart, DWORD MemorySize, LPVOID ReplacePattern, DWORD ReplaceSize, bool AppendNOP, bool PrependNOP);
    bool ReplaceEx(HANDLE hProcess, LPVOID MemoryStart, DWORD MemorySize, LPVOID SearchPattern, DWORD PatternSize, DWORD NumberOfRepetitions, LPVOID ReplacePattern, DWORD ReplaceSize, PBYTE WildCard);
    bool Replace(LPVOID MemoryStart, DWORD MemorySize, LPVOID SearchPattern, DWORD PatternSize, DWORD NumberOfRepetitions, LPVOID ReplacePattern, DWORD ReplaceSize, PBYTE WildCard);
    void* GetDebugData();
    void* GetTerminationData();
    long GetExitCode();
    long long GetDebuggedDLLBaseAddress();
    long long GetDebuggedFileBaseAddress();
    bool GetRemoteString(HANDLE hProcess, LPVOID StringAddress, LPVOID StringStorage, int MaximumStringSize);
    long long GetFunctionParameter(HANDLE hProcess, DWORD FunctionType, DWORD ParameterNumber, DWORD ParameterType);
    long long GetJumpDestinationEx(HANDLE hProcess, ULONG_PTR InstructionAddress, bool JustJumps);
    long long GetJumpDestination(HANDLE hProcess, ULONG_PTR InstructionAddress);
    bool IsJumpGoingToExecuteEx(HANDLE hProcess, HANDLE hThread, ULONG_PTR InstructionAddress, ULONG_PTR RegFlags);
    bool IsJumpGoingToExecute();
    void SetCustomHandler(DWORD ExceptionId, LPVOID CallBack);
    void ForceClose();
    void StepInto(LPVOID traceCallBack);
    void StepOver(LPVOID traceCallBack);
    void SingleStep(DWORD StepCount, LPVOID StepCallBack);
    bool GetUnusedHardwareBreakPointRegister(LPDWORD RegisterIndex);
    bool SetHardwareBreakPointEx(HANDLE hActiveThread, ULONG_PTR bpxAddress, DWORD IndexOfRegister, DWORD bpxType, DWORD bpxSize, LPVOID bpxCallBack, LPDWORD IndexOfSelectedRegister);
    bool SetHardwareBreakPoint(ULONG_PTR bpxAddress, DWORD IndexOfRegister, DWORD bpxType, DWORD bpxSize, LPVOID bpxCallBack);
    bool DeleteHardwareBreakPoint(DWORD IndexOfRegister);
    bool RemoveAllBreakPoints(DWORD RemoveOption);
    void* GetProcessInformation();
    void* GetStartupInformation();
    void DebugLoop();
    void SetDebugLoopTimeOut(DWORD TimeOut);
    void SetNextDbgContinueStatus(DWORD SetDbgCode);
    bool AttachDebugger(DWORD ProcessId, bool KillOnExit, LPVOID DebugInfo, LPVOID CallBack);
    bool DetachDebugger(DWORD ProcessId);
    bool DetachDebuggerEx(DWORD ProcessId);
    void DebugLoopEx(DWORD TimeOut);
    void AutoDebugEx(char* szFileName, bool ReserveModuleBase, char* szCommandLine, char* szCurrentFolder, DWORD TimeOut, LPVOID EntryCallBack);
    void AutoDebugExW(wchar_t* szFileName, bool ReserveModuleBase, wchar_t* szCommandLine, wchar_t* szCurrentFolder, DWORD TimeOut, LPVOID EntryCallBack);
    bool IsFileBeingDebugged();
    void SetErrorModel(bool DisplayErrorMessages);
// TitanEngine.FindOEP.functions:
    void FindOEPInit();
    bool FindOEPGenerically(char* szFileName, LPVOID TraceInitCallBack, LPVOID CallBack);
    bool FindOEPGenericallyW(wchar_t* szFileName, LPVOID TraceInitCallBack, LPVOID CallBack);
// TitanEngine.Importer.functions:
    void ImporterCleanup();
    void ImporterSetImageBase(ULONG_PTR ImageBase);
    void ImporterSetUnknownDelta(ULONG_PTR DeltaAddress);
    long long ImporterGetCurrentDelta();
    void ImporterInit(DWORD MemorySize, ULONG_PTR ImageBase);
    void ImporterAddNewDll(char* szDLLName, ULONG_PTR FirstThunk);
    void ImporterAddNewAPI(char* szAPIName, ULONG_PTR ThunkValue);
    void ImporterAddNewOrdinalAPI(ULONG_PTR OrdinalNumber, ULONG_PTR ThunkValue);
    long ImporterGetAddedDllCount();
    long ImporterGetAddedAPICount();
    void* ImporterGetLastAddedDLLName();
    void ImporterMoveIAT();
    bool ImporterExportIAT(ULONG_PTR StorePlace, ULONG_PTR FileMapVA);
    long ImporterEstimatedSize();
    bool ImporterExportIATEx(char* szExportFileName, char* szSectionName);
    bool ImporterExportIATExW(wchar_t* szExportFileName, char* szSectionName);
    long long ImporterFindAPIWriteLocation(char* szAPIName);
    long long ImporterFindOrdinalAPIWriteLocation(ULONG_PTR OrdinalNumber);
    long long ImporterFindAPIByWriteLocation(ULONG_PTR APIWriteLocation);
    long long ImporterFindDLLByWriteLocation(ULONG_PTR APIWriteLocation);
    void* ImporterGetDLLName(ULONG_PTR APIAddress);
    void* ImporterGetAPIName(ULONG_PTR APIAddress);
    long long ImporterGetAPIOrdinalNumber(ULONG_PTR APIAddress);
    void* ImporterGetAPINameEx(ULONG_PTR APIAddress, ULONG_PTR DLLBasesList);
    long long ImporterGetRemoteAPIAddress(HANDLE hProcess, ULONG_PTR APIAddress);
    long long ImporterGetRemoteAPIAddressEx(char* szDLLName, char* szAPIName);
    long long ImporterGetLocalAPIAddress(HANDLE hProcess, ULONG_PTR APIAddress);
    void* ImporterGetDLLNameFromDebugee(HANDLE hProcess, ULONG_PTR APIAddress);
    void* ImporterGetAPINameFromDebugee(HANDLE hProcess, ULONG_PTR APIAddress);
    long long ImporterGetAPIOrdinalNumberFromDebugee(HANDLE hProcess, ULONG_PTR APIAddress);
    long ImporterGetDLLIndexEx(ULONG_PTR APIAddress, ULONG_PTR DLLBasesList);
    long ImporterGetDLLIndex(HANDLE hProcess, ULONG_PTR APIAddress, ULONG_PTR DLLBasesList);
    long long ImporterGetRemoteDLLBase(HANDLE hProcess, HMODULE LocalModuleBase);
    bool ImporterRelocateWriteLocation(ULONG_PTR AddValue);
    bool ImporterIsForwardedAPI(HANDLE hProcess, ULONG_PTR APIAddress);
    void* ImporterGetForwardedAPIName(HANDLE hProcess, ULONG_PTR APIAddress);
    void* ImporterGetForwardedDLLName(HANDLE hProcess, ULONG_PTR APIAddress);
    long ImporterGetForwardedDLLIndex(HANDLE hProcess, ULONG_PTR APIAddress, ULONG_PTR DLLBasesList);
    long long ImporterGetForwardedAPIOrdinalNumber(HANDLE hProcess, ULONG_PTR APIAddress);
    long long ImporterGetNearestAPIAddress(HANDLE hProcess, ULONG_PTR APIAddress);
    void* ImporterGetNearestAPIName(HANDLE hProcess, ULONG_PTR APIAddress);
    bool ImporterCopyOriginalIAT(char* szOriginalFile, char* szDumpFile);
    bool ImporterCopyOriginalIATW(wchar_t* szOriginalFile, wchar_t* szDumpFile);
    bool ImporterLoadImportTable(char* szFileName);
    bool ImporterLoadImportTableW(wchar_t* szFileName);
    bool ImporterMoveOriginalIAT(char* szOriginalFile, char* szDumpFile, char* szSectionName);
    bool ImporterMoveOriginalIATW(wchar_t* szOriginalFile, wchar_t* szDumpFile, char* szSectionName);
    void ImporterAutoSearchIAT(HANDLE hProcess, char* szFileName, ULONG_PTR ImageBase, ULONG_PTR SearchStart, DWORD SearchSize, LPVOID pIATStart, LPVOID pIATSize);
    void ImporterAutoSearchIATW(HANDLE hProcess, wchar_t* szFileName, ULONG_PTR ImageBase, ULONG_PTR SearchStart, DWORD SearchSize, LPVOID pIATStart, LPVOID pIATSize);
    void ImporterAutoSearchIATEx(HANDLE hProcess, ULONG_PTR ImageBase, ULONG_PTR SearchStart, DWORD SearchSize, LPVOID pIATStart, LPVOID pIATSize);
    void ImporterEnumAddedData(LPVOID EnumCallBack);
    long ImporterAutoFixIATEx(HANDLE hProcess, char* szDumpedFile, char* szSectionName, bool DumpRunningProcess, bool RealignFile, ULONG_PTR EntryPointAddress, ULONG_PTR ImageBase, ULONG_PTR SearchStart, DWORD SearchSize, DWORD SearchStep, bool TryAutoFix, bool FixEliminations, LPVOID UnknownPointerFixCallback);
    long ImporterAutoFixIATExW(HANDLE hProcess, wchar_t* szDumpedFile, char* szSectionName, bool DumpRunningProcess, bool RealignFile, ULONG_PTR EntryPointAddress, ULONG_PTR ImageBase, ULONG_PTR SearchStart, DWORD SearchSize, DWORD SearchStep, bool TryAutoFix, bool FixEliminations, LPVOID UnknownPointerFixCallback);
    long ImporterAutoFixIAT(HANDLE hProcess, char* szDumpedFile, ULONG_PTR ImageBase, ULONG_PTR SearchStart, DWORD SearchSize, DWORD SearchStep);
    long ImporterAutoFixIATW(HANDLE hProcess, wchar_t* szDumpedFile, ULONG_PTR ImageBase, ULONG_PTR SearchStart, DWORD SearchSize, DWORD SearchStep);
// Global.Engine.Hook.functions:
    bool HooksSafeTransitionEx(LPVOID HookAddressArray, int NumberOfHooks, bool TransitionStart);
    bool HooksSafeTransition(LPVOID HookAddress, bool TransitionStart);
    bool HooksIsAddressRedirected(LPVOID HookAddress);
    void* HooksGetTrampolineAddress(LPVOID HookAddress);
    void* HooksGetHookEntryDetails(LPVOID HookAddress);
    bool HooksInsertNewRedirection(LPVOID HookAddress, LPVOID RedirectTo, int HookType);
    bool HooksInsertNewIATRedirectionEx(ULONG_PTR FileMapVA, ULONG_PTR LoadedModuleBase, char* szHookFunction, LPVOID RedirectTo);
    bool HooksInsertNewIATRedirection(char* szModuleName, char* szHookFunction, LPVOID RedirectTo);
    bool HooksRemoveRedirection(LPVOID HookAddress, bool RemoveAll);
    bool HooksRemoveRedirectionsForModule(HMODULE ModuleBase);
    bool HooksRemoveIATRedirection(char* szModuleName, char* szHookFunction, bool RemoveAll);
    bool HooksDisableRedirection(LPVOID HookAddress, bool DisableAll);
    bool HooksDisableRedirectionsForModule(HMODULE ModuleBase);
    bool HooksDisableIATRedirection(char* szModuleName, char* szHookFunction, bool DisableAll);
    bool HooksEnableRedirection(LPVOID HookAddress, bool EnableAll);
    bool HooksEnableRedirectionsForModule(HMODULE ModuleBase);
    bool HooksEnableIATRedirection(char* szModuleName, char* szHookFunction, bool EnableAll);
    void HooksScanModuleMemory(HMODULE ModuleBase, LPVOID CallBack);
    void HooksScanEntireProcessMemory(LPVOID CallBack);
    void HooksScanEntireProcessMemoryEx();
// TitanEngine.Tracer.functions:
    void TracerInit();
    long long TracerLevel1(HANDLE hProcess, ULONG_PTR AddressToTrace);
    long long HashTracerLevel1(HANDLE hProcess, ULONG_PTR AddressToTrace, DWORD InputNumberOfInstructions);
    long TracerDetectRedirection(HANDLE hProcess, ULONG_PTR AddressToTrace);
    long long TracerFixKnownRedirection(HANDLE hProcess, ULONG_PTR AddressToTrace, DWORD RedirectionId);
    long TracerFixRedirectionViaImpRecPlugin(HANDLE hProcess, char* szPluginName, ULONG_PTR AddressToTrace);
// TitanEngine.Exporter.functions:
    void ExporterCleanup();
    void ExporterSetImageBase(ULONG_PTR ImageBase);
    void ExporterInit(DWORD MemorySize, ULONG_PTR ImageBase, DWORD ExportOrdinalBase, char* szExportModuleName);
    bool ExporterAddNewExport(char* szExportName, DWORD ExportRelativeAddress);
    bool ExporterAddNewOrdinalExport(DWORD OrdinalNumber, DWORD ExportRelativeAddress);
    long ExporterGetAddedExportCount();
    long ExporterEstimatedSize();
    bool ExporterBuildExportTable(ULONG_PTR StorePlace, ULONG_PTR FileMapVA);
    bool ExporterBuildExportTableEx(char* szExportFileName, char* szSectionName);
    bool ExporterBuildExportTableExW(wchar_t* szExportFileName, char* szSectionName);
    bool ExporterLoadExportTable(char* szFileName);
    bool ExporterLoadExportTableW(wchar_t* szFileName);
// TitanEngine.Librarian.functions:
    bool LibrarianSetBreakPoint(char* szLibraryName, DWORD bpxType, bool SingleShoot, LPVOID bpxCallBack);
    bool LibrarianRemoveBreakPoint(char* szLibraryName, DWORD bpxType);
    void* LibrarianGetLibraryInfo(char* szLibraryName);
    void* LibrarianGetLibraryInfoW(wchar_t* szLibraryName);
    void* LibrarianGetLibraryInfoEx(void* BaseOfDll);
    void* LibrarianGetLibraryInfoExW(void* BaseOfDll);
    void LibrarianEnumLibraryInfo(void* EnumCallBack);
    void LibrarianEnumLibraryInfoW(void* EnumCallBack);
// TitanEngine.Process.functions:
    long GetActiveProcessId(char* szImageName);
    long GetActiveProcessIdW(wchar_t* szImageName);
    void EnumProcessesWithLibrary(char* szLibraryName, void* EnumFunction);
// TitanEngine.TLSFixer.functions:
    bool TLSBreakOnCallBack(LPVOID ArrayOfCallBacks, DWORD NumberOfCallBacks, LPVOID bpxCallBack);
    bool TLSGrabCallBackData(char* szFileName, LPVOID ArrayOfCallBacks, LPDWORD NumberOfCallBacks);
    bool TLSGrabCallBackDataW(wchar_t* szFileName, LPVOID ArrayOfCallBacks, LPDWORD NumberOfCallBacks);
    bool TLSBreakOnCallBackEx(char* szFileName, LPVOID bpxCallBack);
    bool TLSBreakOnCallBackExW(wchar_t* szFileName, LPVOID bpxCallBack);
    bool TLSRemoveCallback(char* szFileName);
    bool TLSRemoveCallbackW(wchar_t* szFileName);
    bool TLSRemoveTable(char* szFileName);
    bool TLSRemoveTableW(wchar_t* szFileName);
    bool TLSBackupData(char* szFileName);
    bool TLSBackupDataW(wchar_t* szFileName);
    bool TLSRestoreData();
    bool TLSBuildNewTable(ULONG_PTR FileMapVA, ULONG_PTR StorePlace, ULONG_PTR StorePlaceRVA, LPVOID ArrayOfCallBacks, DWORD NumberOfCallBacks);
    bool TLSBuildNewTableEx(char* szFileName, char* szSectionName, LPVOID ArrayOfCallBacks, DWORD NumberOfCallBacks);
    bool TLSBuildNewTableExW(wchar_t* szFileName, char* szSectionName, LPVOID ArrayOfCallBacks, DWORD NumberOfCallBacks);
// TitanEngine.TranslateName.functions:
    void* TranslateNativeName(char* szNativeName);
    void* TranslateNativeNameW(wchar_t* szNativeName);
// TitanEngine.Handler.functions:
    long HandlerGetActiveHandleCount(DWORD ProcessId);
    bool HandlerIsHandleOpen(DWORD ProcessId, HANDLE hHandle);
    void* HandlerGetHandleName(HANDLE hProcess, DWORD ProcessId, HANDLE hHandle, bool TranslateName);
    void* HandlerGetHandleNameW(HANDLE hProcess, DWORD ProcessId, HANDLE hHandle, bool TranslateName);
    long HandlerEnumerateOpenHandles(DWORD ProcessId, LPVOID HandleBuffer, DWORD MaxHandleCount);
    long long HandlerGetHandleDetails(HANDLE hProcess, DWORD ProcessId, HANDLE hHandle, DWORD InformationReturn);
    bool HandlerCloseRemoteHandle(HANDLE hProcess, HANDLE hHandle);
    long HandlerEnumerateLockHandles(char* szFileOrFolderName, bool NameIsFolder, bool NameIsTranslated, LPVOID HandleDataBuffer, DWORD MaxHandleCount);
    long HandlerEnumerateLockHandlesW(wchar_t* szFileOrFolderName, bool NameIsFolder, bool NameIsTranslated, LPVOID HandleDataBuffer, DWORD MaxHandleCount);
    bool HandlerCloseAllLockHandles(char* szFileOrFolderName, bool NameIsFolder, bool NameIsTranslated);
    bool HandlerCloseAllLockHandlesW(wchar_t* szFileOrFolderName, bool NameIsFolder, bool NameIsTranslated);
    bool HandlerIsFileLocked(char* szFileOrFolderName, bool NameIsFolder, bool NameIsTranslated);
    bool HandlerIsFileLockedW(wchar_t* szFileOrFolderName, bool NameIsFolder, bool NameIsTranslated);
// TitanEngine.Handler[Mutex].functions:
    long HandlerEnumerateOpenMutexes(HANDLE hProcess, DWORD ProcessId, LPVOID HandleBuffer, DWORD MaxHandleCount);
    long long HandlerGetOpenMutexHandle(HANDLE hProcess, DWORD ProcessId, char* szMutexString);
    long long HandlerGetOpenMutexHandleW(HANDLE hProcess, DWORD ProcessId, wchar_t* szMutexString);
    long HandlerGetProcessIdWhichCreatedMutex(char* szMutexString);
    long HandlerGetProcessIdWhichCreatedMutexW(wchar_t* szMutexString);
// TitanEngine.Injector.functions:
    bool RemoteLoadLibrary(HANDLE hProcess, char* szLibraryFile, bool WaitForThreadExit);
    bool RemoteLoadLibraryW(HANDLE hProcess, wchar_t* szLibraryFile, bool WaitForThreadExit);
    bool RemoteFreeLibrary(HANDLE hProcess, HMODULE hModule, char* szLibraryFile, bool WaitForThreadExit);
    bool RemoteFreeLibraryW(HANDLE hProcess, HMODULE hModule, wchar_t* szLibraryFile, bool WaitForThreadExit);
    bool RemoteExitProcess(HANDLE hProcess, DWORD ExitCode);
// TitanEngine.StaticUnpacker.functions:
    bool StaticFileLoad(char* szFileName, DWORD DesiredAccess, bool SimulateLoad, LPHANDLE FileHandle, LPDWORD LoadedSize, LPHANDLE FileMap, PULONG_PTR FileMapVA);
    bool StaticFileLoadW(wchar_t* szFileName, DWORD DesiredAccess, bool SimulateLoad, LPHANDLE FileHandle, LPDWORD LoadedSize, LPHANDLE FileMap, PULONG_PTR FileMapVA);
    bool StaticFileUnload(char* szFileName, bool CommitChanges, HANDLE FileHandle, DWORD LoadedSize, HANDLE FileMap, ULONG_PTR FileMapVA);
    bool StaticFileUnloadW(wchar_t* szFileName, bool CommitChanges, HANDLE FileHandle, DWORD LoadedSize, HANDLE FileMap, ULONG_PTR FileMapVA);
    bool StaticFileOpen(char* szFileName, DWORD DesiredAccess, LPHANDLE FileHandle, LPDWORD FileSizeLow, LPDWORD FileSizeHigh);
    bool StaticFileOpenW(wchar_t* szFileName, DWORD DesiredAccess, LPHANDLE FileHandle, LPDWORD FileSizeLow, LPDWORD FileSizeHigh);
    bool StaticFileGetContent(HANDLE FileHandle, DWORD FilePositionLow, LPDWORD FilePositionHigh, void* Buffer, DWORD Size);
    void StaticFileClose(HANDLE FileHandle);
    void StaticMemoryDecrypt(LPVOID MemoryStart, DWORD MemorySize, DWORD DecryptionType, DWORD DecryptionKeySize, ULONG_PTR DecryptionKey);
    void StaticMemoryDecryptEx(LPVOID MemoryStart, DWORD MemorySize, DWORD DecryptionKeySize, void* DecryptionCallBack);
    void StaticMemoryDecryptSpecial(LPVOID MemoryStart, DWORD MemorySize, DWORD DecryptionKeySize, DWORD SpecDecryptionType, void* DecryptionCallBack);
    void StaticSectionDecrypt(ULONG_PTR FileMapVA, DWORD SectionNumber, bool SimulateLoad, DWORD DecryptionType, DWORD DecryptionKeySize, ULONG_PTR DecryptionKey);
    bool StaticMemoryDecompress(void* Source, DWORD SourceSize, void* Destination, DWORD DestinationSize, int Algorithm);
    bool StaticRawMemoryCopy(HANDLE hFile, ULONG_PTR FileMapVA, ULONG_PTR VitualAddressToCopy, DWORD Size, bool AddressIsRVA, char* szDumpFileName);
    bool StaticRawMemoryCopyW(HANDLE hFile, ULONG_PTR FileMapVA, ULONG_PTR VitualAddressToCopy, DWORD Size, bool AddressIsRVA, wchar_t* szDumpFileName);
    bool StaticRawMemoryCopyEx(HANDLE hFile, DWORD RawAddressToCopy, DWORD Size, char* szDumpFileName);
    bool StaticRawMemoryCopyExW(HANDLE hFile, DWORD RawAddressToCopy, DWORD Size, wchar_t* szDumpFileName);
    bool StaticRawMemoryCopyEx64(HANDLE hFile, DWORD64 RawAddressToCopy, DWORD64 Size, char* szDumpFileName);
    bool StaticRawMemoryCopyEx64W(HANDLE hFile, DWORD64 RawAddressToCopy, DWORD64 Size, wchar_t* szDumpFileName);
    bool StaticHashMemory(void* MemoryToHash, DWORD SizeOfMemory, void* HashDigest, bool OutputString, int Algorithm);
    bool StaticHashFileW(wchar_t* szFileName, char* HashDigest, bool OutputString, int Algorithm);
    bool StaticHashFile(char* szFileName, char* HashDigest, bool OutputString, int Algorithm);
// TitanEngine.Engine.functions:
    void EngineUnpackerInitialize(char* szFileName, char* szUnpackedFileName, bool DoLogData, bool DoRealignFile, bool DoMoveOverlay, void* EntryCallBack);
    void EngineUnpackerInitializeW(wchar_t* szFileName, wchar_t* szUnpackedFileName, bool DoLogData, bool DoRealignFile, bool DoMoveOverlay, void* EntryCallBack);
    bool EngineUnpackerSetBreakCondition(void* SearchStart, DWORD SearchSize, void* SearchPattern, DWORD PatternSize, DWORD PatternDelta, ULONG_PTR BreakType, bool SingleBreak, DWORD Parameter1, DWORD Parameter2);
    void EngineUnpackerSetEntryPointAddress(ULONG_PTR UnpackedEntryPointAddress);
    void EngineUnpackerFinalizeUnpacking();
// TitanEngine.Engine.functions:
    void SetEngineVariable(DWORD VariableId, bool VariableSet);
    bool EngineCreateMissingDependencies(char* szFileName, char* szOutputFolder, bool LogCreatedFiles);
    bool EngineCreateMissingDependenciesW(wchar_t* szFileName, wchar_t* szOutputFolder, bool LogCreatedFiles);
    bool EngineFakeMissingDependencies(HANDLE hProcess);
    bool EngineDeleteCreatedDependencies();
    bool EngineCreateUnpackerWindow(char* WindowUnpackerTitle, char* WindowUnpackerLongTitle, char* WindowUnpackerName, char* WindowUnpackerAuthor, void* StartUnpackingCallBack);
    void EngineAddUnpackerWindowLogMessage(char* szLogMessage);
// Global.Engine.Extension.Functions:
    bool ExtensionManagerIsPluginLoaded(char* szPluginName);
    bool ExtensionManagerIsPluginEnabled(char* szPluginName);
    bool ExtensionManagerDisableAllPlugins();
    bool ExtensionManagerDisablePlugin(char* szPluginName);
    bool ExtensionManagerEnableAllPlugins();
    bool ExtensionManagerEnablePlugin(char* szPluginName);
    bool ExtensionManagerUnloadAllPlugins();
    bool ExtensionManagerUnloadPlugin(char* szPluginName);
    void* ExtensionManagerGetPluginInfo(char* szPluginName);

#if !defined (_WIN64)
#ifdef __cplusplus
}
#endif /*__cplusplus*/
#endif

#pragma pack(pop)

#endif /*TITANENGINE*/
