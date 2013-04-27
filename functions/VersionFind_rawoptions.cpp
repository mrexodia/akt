#include "VersionFind_rawoptions.h"

/**********************************************************************
 *						Module Variables
 *********************************************************************/
// Debugging Variables
static bool g_fdFileIsDll = false;
static LPPROCESS_INFORMATION g_fdProcessInfo;

// Internal Use Variables
static long g_fdEntrySectionOffset=0;
static long g_fdEntrySectionSize=0;
static unsigned int g_raw_options_reg=0;
static ErrMessageCallback g_ErrorMessageCallback = NULL;

// Output Pointers
static unsigned int* gPtrRawOptions=0;


/**********************************************************************
 *						Functions
 *********************************************************************/
void VF_cbRetrieveRawOptions()
{
    DeleteBPX(GetContextData(UE_EIP));
    *gPtrRawOptions=GetContextData(g_raw_options_reg);
    StopDebug();
}


void VF_cbMutexReturn()
{
    unsigned int eip=GetContextData(UE_EIP);
    DeleteBPX(eip);
    BYTE* eip_data=(BYTE*)malloc(100);
    ReadProcessMemory(g_fdProcessInfo->hProcess, (void*)eip, eip_data, 100, 0);
    int and20=VF_FindAnd20Pattern(eip_data, 100);
    if(!and20)
        VF_FatalError("Could not find 'and [reg],20'", g_ErrorMessageCallback);
    unsigned int andreg=eip_data[and20+1]&0x0F;
    g_raw_options_reg=0xFFFFFFFF;
    switch(andreg)
    {
    case 0:
        g_raw_options_reg=UE_EAX;
        break;
    case 1:
        g_raw_options_reg=UE_ECX;
        break;
    case 2:
        g_raw_options_reg=UE_EDX;
        break;
    case 3:
        g_raw_options_reg=UE_EBX;
        break;
    case 5:
        g_raw_options_reg=UE_EBP;
        break;
    case 6:
        g_raw_options_reg=UE_ESI;
        break;
    case 7:
        g_raw_options_reg=UE_EDI;
        break;
    }
    if(g_raw_options_reg==0xFFFFFFFF)
        VF_FatalError("Could not determine raw options register", g_ErrorMessageCallback);
    SetBPX((and20+eip), UE_BREAKPOINT, (void*)VF_cbRetrieveRawOptions);
}


void VF_cbOpOpenMutexA()
{
    long esp_addr=0;
    unsigned int return_addr=0;
    DeleteAPIBreakPoint((char*)"kernel32.dll", (char*)"OpenMutexA", UE_APISTART);
    esp_addr=(long)GetContextData(UE_ESP);
    ReadProcessMemory(g_fdProcessInfo->hProcess, (const void*)esp_addr, &return_addr, 4, 0);
    SetBPX(return_addr, UE_BREAKPOINT, (void*)VF_cbMutexReturn);
}


void VF_cbOpGetCommandLine()
{
    DeleteAPIBreakPoint((char*)"kernel32.dll", (char*)"GetCommandLineA", UE_APISTART);
    DeleteAPIBreakPoint((char*)"kernel32.dll", (char*)"GetCommandLineW", UE_APISTART);
    BYTE* data=(BYTE*)malloc(g_fdEntrySectionSize);
    ReadProcessMemory(g_fdProcessInfo->hProcess, (void*)g_fdEntrySectionOffset, data, g_fdEntrySectionSize, 0);
    int and40000=VF_FindAnd40000Pattern(data, g_fdEntrySectionSize);
    if(!and40000)
        VF_FatalError("Could not find 'and [reg],40000'", g_ErrorMessageCallback);
    unsigned int andreg=data[and40000+1]&0x0F;
    g_raw_options_reg=0xFFFFFFFF;
    switch(andreg)
    {
    case 0:
        g_raw_options_reg=UE_EAX;
        break;
    case 1:
        g_raw_options_reg=UE_ECX;
        break;
    case 2:
        g_raw_options_reg=UE_EDX;
        break;
    case 3:
        g_raw_options_reg=UE_EBX;
        break;
    case 5:
        g_raw_options_reg=UE_EBP;
        break;
    case 6:
        g_raw_options_reg=UE_ESI;
        break;
    case 7:
        g_raw_options_reg=UE_EDI;
        break;
    }
    if(g_raw_options_reg==0xFFFFFFFF)
        VF_FatalError("Could not determine raw options register", g_ErrorMessageCallback);
    SetBPX((and40000+g_fdEntrySectionOffset), UE_BREAKPOINT, (void*)VF_cbRetrieveRawOptions);
}


void VF_cbOpEntry()
{
    if(!g_fdFileIsDll)
        SetAPIBreakPoint((char*)"kernel32.dll", (char*)"OpenMutexA", UE_BREAKPOINT, UE_APISTART, (void*)VF_cbOpOpenMutexA);
    else
    {
        SetAPIBreakPoint((char*)"kernel32.dll", (char*)"GetCommandLineA", UE_BREAKPOINT, UE_APISTART, (void*)VF_cbOpGetCommandLine);
        SetAPIBreakPoint((char*)"kernel32.dll", (char*)"GetCommandLineW", UE_BREAKPOINT, UE_APISTART, (void*)VF_cbOpGetCommandLine);
    }
}


bool VF_RawOptions(char* szFileName, unsigned int* raw_options, bool* bIsMinimal, ErrMessageCallback ErrorMessageCallback)
{
    long fdImageBase=NULL;
    long fdEntryPoint=NULL;
    long fdEntrySectionNumber=0;
    FILE_STATUS_INFO inFileStatus = {0};

    gPtrRawOptions = raw_options;
    g_fdFileIsDll = false;
    g_fdProcessInfo = NULL;
    g_ErrorMessageCallback = ErrorMessageCallback;

    if(IsPE32FileValidEx(szFileName, UE_DEPTH_SURFACE, &inFileStatus))
    {
        if(inFileStatus.FileIs64Bit)
        {
            ErrorMessageCallback((char*)"64-bit files are not (yet) supported!", (char*)"Error!");
            return 0;
        }
        HANDLE hFile, fileMap;
        ULONG_PTR va;
        DWORD bytes_read;
        fdImageBase = (long)GetPE32Data(szFileName, NULL, UE_IMAGEBASE);
        fdEntryPoint = (long)GetPE32Data(szFileName, NULL, UE_OEP);
        StaticFileLoad(szFileName, UE_ACCESS_READ, false, &hFile, &bytes_read, &fileMap, &va);
        if(!IsArmadilloProtected(va))
        {
            ErrorMessageCallback((char*)"Not armadillo protected...", (char*)"Error!");
        }
        else
        {
            fdEntrySectionNumber = GetPE32SectionNumberFromVA(va, fdEntryPoint+fdImageBase);
            g_fdEntrySectionOffset = (long)GetPE32Data(szFileName, fdEntrySectionNumber, UE_SECTIONVIRTUALOFFSET)+fdImageBase;
            g_fdEntrySectionSize = (long)GetPE32Data(szFileName, fdEntrySectionNumber, UE_SECTIONVIRTUALSIZE);
            StaticFileClose(hFile);
            *bIsMinimal=VF_IsMinimalProtection(szFileName, va, fdEntrySectionNumber);
            g_fdFileIsDll = inFileStatus.FileIsDLL;
            if(!g_fdFileIsDll)
            {
                g_fdProcessInfo = (LPPROCESS_INFORMATION)InitDebugEx(szFileName, NULL, NULL, (void*)VF_cbOpEntry);
            }
            else
            {
                g_fdProcessInfo = (LPPROCESS_INFORMATION)InitDLLDebug(szFileName, false, NULL, NULL, (void*)VF_cbOpEntry);
            }
            if(g_fdProcessInfo)
            {
                DebugLoop();
                return true;
            }
            else
            {
                ErrorMessageCallback((char*)"Something went wrong during initialization...", (char*)"Error!");
            }
        }
    }
    else
    {
        ErrorMessageCallback((char*)"This is not a valid PE file...", (char*)"Error!");
    }
    return false;
}
