#include "InlineHelper_decrypt.h"

//TODO: Implement this
/*
-get crc vals
-decrypt
-clear adata
-old entry is free space
-original entry is new entry
-set ep to free space
*/

/**********************************************************************
 *						Module Variables
 *********************************************************************/
static char* g_szFileName=0;
static cbErrorMessage g_ErrorMessageCallback=0;

static bool g_fdFileIsDll=false;

static LPPROCESS_INFORMATION g_fdProcessInfo=0;
//static unsigned int g_epsection_raw_offset=0;

static long g_fdImageBase=0;
static ULONG_PTR IHD_va;
static long g_fdEntryPoint=0;
static long g_fdEntrySectionNumber=0;
static long g_fdEntrySectionSize=0;
static long g_fdEntrySectionOffset=0;
static long g_fdEntrySectionRawOffset=0;
static long g_fdEntrySectionRawSize=0;

static char g_reg=0;


/**********************************************************************
 *						Functions
 *********************************************************************/
void IHD_FatalError(const char* msg) //TODO: never used
{
    g_ErrorMessageCallback((char*)msg, (char*)"Error!");
    ExitProcess(1);
}

unsigned int IHD_FindJump(BYTE* d, unsigned int size, char* reg)
{
    for(unsigned int i=0; i<size; i++) //61FFE?
        if(d[i]==0x61 and d[i+1]==0xFF and(d[i+2]>>4)==0x0E)
        {
            *reg=d[i+2]^0xE0;
            return i+1;
        }
    return 0;
}

void IHD_cbOEP()
{
    unsigned int eip=GetContextData(UE_EIP);
    DeleteBPX(eip);
    int real_ep_section=GetPE32SectionNumberFromVA(IHD_va, eip);
    unsigned int IHD_epsection_raw_offset=GetPE32DataFromMappedFile(IHD_va, real_ep_section, UE_SECTIONRAWOFFSET);
    unsigned int epsection_offset=GetPE32DataFromMappedFile(IHD_va, real_ep_section, UE_SECTIONVIRTUALOFFSET);
    unsigned int epsection_raw_size=GetPE32DataFromMappedFile(IHD_va, real_ep_section, UE_SECTIONRAWSIZE);
    BYTE* new_data=(BYTE*)malloc2(epsection_raw_size);
    ReadProcessMemory(g_fdProcessInfo->hProcess, (void*)(epsection_offset+g_fdImageBase), new_data, epsection_raw_size, 0);
    char newfile[256]="";
    strcpy(newfile, g_szFileName);
    newfile[strlen(newfile)-4]=0;
    strcat(newfile, "_.exe");
    CopyFileA(g_szFileName, newfile, FALSE);
    HANDLE hFile=CreateFileA(newfile, GENERIC_ALL, 0, 0, OPEN_EXISTING, 0, 0);
    if(hFile==INVALID_HANDLE_VALUE)
    {
        MessageBoxA(0, "Could not open file!", "Fail..", MB_ICONERROR);
        StopDebug();
    }
    OVERLAPPED ovl= {0};
    ovl.Offset=IHD_epsection_raw_offset;
    WriteFile(hFile, new_data, epsection_raw_size, 0, &ovl);
    CloseHandle(hFile);
    free2(new_data);
    char msg[256]="";
    sprintf(msg, "New file written to %s.\n\nShould I set a new EP and clear out the old .adata section?", newfile);
    if(MessageBoxA(0, msg, "Question", MB_ICONQUESTION|MB_YESNO)==IDYES)
    {
        SetPE32Data(newfile, 0, UE_OEP, eip-g_fdImageBase);
        hFile=CreateFileA(newfile, GENERIC_ALL, 0, 0, OPEN_EXISTING, 0, 0);
        if(hFile==INVALID_HANDLE_VALUE)
        {
            MessageBoxA(0, "Could not open file!", "Fail..", MB_ICONERROR);
            StopDebug();
        }
        BYTE* empty_mem=(BYTE*)malloc2(g_fdEntrySectionRawSize);
        memset(empty_mem, 0, g_fdEntrySectionRawSize);
        memset(&ovl, 0, sizeof(OVERLAPPED));
        ovl.Offset=g_fdEntrySectionRawOffset;
        WriteFile(hFile, empty_mem, g_fdEntrySectionRawSize, 0, &ovl);
        free2(empty_mem);
        CloseHandle(hFile);
    }
    MessageBoxA(0, "All done!", "Done", MB_ICONINFORMATION);
    StopDebug();
}

void IHD_cbJumpOEP()
{
    DeleteBPX(GetContextData(UE_EIP));
    unsigned int final_reg=0;
    switch(g_reg)
    {
    case 0:
        final_reg=UE_EAX;
        break;
    case 1:
        final_reg=UE_ECX;
        break;
    case 2:
        final_reg=UE_EDX;
        break;
    case 3:
        final_reg=UE_EBX;
        break;
    case 4:
        final_reg=UE_ESP;
        break;
    case 5:
        final_reg=UE_EBP;
        break;
    case 6:
        final_reg=UE_ESI;
        break;
    case 7:
        final_reg=UE_EDI;
        break;
    }
    SetBPX(GetContextData(final_reg), UE_BREAKPOINT, (void*)IHD_cbOEP);
}

void IHD_cbGuardPage()
{
    unsigned int eip=GetContextData(UE_EIP);
    unsigned int size_read=(g_fdEntrySectionOffset+g_fdEntrySectionSize+g_fdImageBase)-eip;
    BYTE* data=(BYTE*)malloc2(size_read);
    ReadProcessMemory(g_fdProcessInfo->hProcess, (void*)eip, data, size_read, 0);
    unsigned int bp_addr=IHD_FindJump(data, size_read, &g_reg);
    if(!bp_addr)
    {
        g_ErrorMessageCallback((char*)"Could not find:\n\npushad\njmp [register]\n\nPlease contact Mr. eXoDia.", (char*)"Error!");
        StopDebug();
    }
    free2(data);
    SetHardwareBreakPoint(eip+bp_addr, UE_DR0, UE_HARDWARE_EXECUTE, 1, (void*)IHD_cbJumpOEP);
}

void IHD_cbEntry()
{
    FixIsDebuggerPresent(g_fdProcessInfo->hProcess, true);
    g_fdImageBase=GetDebuggedFileBaseAddress();
    BYTE entry_byte=0;
    ReadProcessMemory(g_fdProcessInfo->hProcess, (void*)(g_fdEntryPoint+g_fdImageBase), &entry_byte, 1, 0);
    if(entry_byte!=0x60)
    {
        g_ErrorMessageCallback((char*)"The entry section is not encrypted...", (char*)"Error!");
        StopDebug();
    }
    int total_sections=GetPE32Data(g_szFileName, 0, UE_SECTIONNUMBER);
    for(int i=0; i<total_sections; i++)
        if(i!=g_fdEntrySectionNumber)
            SetMemoryBPXEx((GetPE32Data(g_szFileName, i, UE_SECTIONVIRTUALOFFSET)+g_fdImageBase), 0x1000, UE_MEMORY_WRITE, false, (void*)IHD_cbGuardPage);
}

DWORD WINAPI IHD_DebugThread(LPVOID lpStartAddress) //TODO: never used
{
    FILE_STATUS_INFO inFileStatus= {0};

    g_fdFileIsDll=false;
    g_fdImageBase=0;
    g_fdEntryPoint=0;
    g_fdProcessInfo=0;
    DWORD bytes_read=0;

    IsPE32FileValidEx(g_szFileName, UE_DEPTH_SURFACE, &inFileStatus);
    if(inFileStatus.FileIs64Bit)
    {
        g_ErrorMessageCallback((char*)"64-bit files are not (yet) supported!", (char*)"Error!");
        return 0;
    }
    HANDLE hFile, fileMap;
    g_fdEntryPoint=(long)GetPE32Data(g_szFileName, 0, UE_OEP);
    //fdSizeOfImage=(long)GetPE32Data(g_szFileName, 0, UE_SIZEOFIMAGE);
    StaticFileLoad(g_szFileName, UE_ACCESS_READ, false, &hFile, &bytes_read, &fileMap, &IHD_va);
    g_fdEntrySectionNumber=GetPE32SectionNumberFromVA(IHD_va, g_fdEntryPoint+GetPE32Data(g_szFileName, 0, UE_IMAGEBASE));
    CloseHandle(hFile);
    CloseHandle(fileMap);
    g_fdEntrySectionSize= (long)GetPE32Data(g_szFileName, g_fdEntrySectionNumber, UE_SECTIONVIRTUALSIZE);
    g_fdEntrySectionRawOffset=GetPE32Data(g_szFileName, g_fdEntrySectionNumber, UE_SECTIONRAWOFFSET);
    g_fdEntrySectionRawSize=GetPE32Data(g_szFileName, g_fdEntrySectionNumber, UE_SECTIONRAWSIZE);
    g_fdEntrySectionOffset=(long)GetPE32Data(g_szFileName, g_fdEntrySectionNumber, UE_SECTIONVIRTUALOFFSET);
    g_fdFileIsDll=inFileStatus.FileIsDLL;
    if(!g_fdFileIsDll)
    {
        g_fdProcessInfo=(LPPROCESS_INFORMATION)InitDebugEx(g_szFileName, 0, 0, (void*)IHD_cbEntry);
    }
    else
    {
        g_fdProcessInfo=(LPPROCESS_INFORMATION)InitDLLDebug(g_szFileName, false, 0, 0, (void*)IHD_cbEntry);
    }
    if(g_fdProcessInfo)
    {
        DebugLoop();
        return 0;
    }
    else
    {
        g_ErrorMessageCallback((char*)"Something went wrong during initialization...", (char*)"Error!");
        return 0;
    }
    return 1;
}


void IHD_Debugger(char* szFileName, cbErrorMessage ErrorMessageCallback)
{
    g_ErrorMessageCallback=ErrorMessageCallback;
    g_szFileName=szFileName;

    CreateThread(0, 0, IHD_DebugThread, 0, 0, 0);
}


