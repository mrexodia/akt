#include "VersionFind_version.h"

/**********************************************************************
 *						Module Variables
 *********************************************************************/
// Debugging Variables
static bool g_fdFileIsDll = false;
static LPPROCESS_INFORMATION g_fdProcessInfo;

// Output Pointers
static char* g_szVersion;

// Internal Use Variables
static unsigned int g_version_decrypt_buffer = 0;
static unsigned int g_version_decrypt_call = 0;
static unsigned int g_version_decrypt_call_dest = 0;
static unsigned int g_version_decrypt_neweip = 0;
static ErrMessageCallback g_ErrorMessageCallback = NULL;


/**********************************************************************
 *						Functions
 *********************************************************************/
void VF_cbVerGetVersion()
{
    DeleteBPX(GetContextData(UE_EIP));
    ReadProcessMemory(g_fdProcessInfo->hProcess, (void*)g_version_decrypt_buffer, g_szVersion, 10, 0);
    StopDebug();
}


void VF_cbVerOnDecryptVersion()
{
    DeleteBPX(GetContextData(UE_EIP));
    unsigned int esp=GetContextData(UE_ESP);
    ReadProcessMemory(g_fdProcessInfo->hProcess, (void*)(esp+4), &g_version_decrypt_buffer, 4, 0);
    SetBPX((g_version_decrypt_call+5), UE_BREAKPOINT, (void*)VF_cbVerGetVersion);
}


void VF_cbVerReturnDecryptCall()
{
    DeleteBPX(GetContextData(UE_EIP));
    SetBPX(g_version_decrypt_call, UE_BREAKPOINT, (void*)VF_cbVerOnDecryptVersion);
    SetContextData(UE_EIP, g_version_decrypt_neweip);
}


void VF_cbVerDecryptCall()
{
    DeleteBPX(GetContextData(UE_EIP));
    unsigned int esp=GetContextData(UE_ESP);
    unsigned int retn=0;
    ReadProcessMemory(g_fdProcessInfo->hProcess, (void*)esp, &retn, 4, 0);
    SetBPX(retn, UE_BREAKPOINT, (void*)VF_cbVerReturnDecryptCall);
}


void VF_cbVerVirtualProtect()
{
    DeleteAPIBreakPoint((char*)"kernel32.dll", (char*)"VirtualProtect", UE_APISTART);
    MEMORY_BASIC_INFORMATION mbi= {0};
    unsigned int sec_addr=0;
    unsigned int sec_size=0;
    unsigned int esp_addr=0;
    BYTE* sec_data=0;
    esp_addr=(long)GetContextData(UE_ESP);
    ReadProcessMemory(g_fdProcessInfo->hProcess, (const void*)((esp_addr)+4), &sec_addr, 4, 0);
    sec_addr-=0x1000;
    VirtualQueryEx(g_fdProcessInfo->hProcess, (void*)sec_addr, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
    sec_size=mbi.RegionSize;
    sec_data=(BYTE*)malloc(sec_size);
    ReadProcessMemory(g_fdProcessInfo->hProcess, (const void*)sec_addr, sec_data, sec_size, 0);
    unsigned int armversion_addr=VF_FindarmVersion(sec_data, sec_size);
    if(!armversion_addr)
        VF_FatalError("Could not find '<armVersion'", g_ErrorMessageCallback);
    armversion_addr+=sec_addr;
    unsigned int push_addr=VF_FindPushAddr(sec_data, sec_size, armversion_addr);
    if(!push_addr)
        VF_FatalError("Could not find reference to '<armVersion'", g_ErrorMessageCallback);
    int call_decrypt=push_addr;
    while(sec_data[call_decrypt]!=0xE8)
        call_decrypt--;
    unsigned int call_dw=0;
    memcpy(&call_dw, (sec_data+call_decrypt+1), 4);
    unsigned int call_dest=(call_decrypt+sec_addr)+call_dw+5;
    unsigned int push100=0;
    for(int i=call_decrypt; i>0; i--)
    {
        if(sec_data[i]==0x68 and sec_data[i+1]==0x00 and sec_data[i+2]==0x01 and sec_data[i+3]==0x00 and sec_data[i+4]==0x00)
        {
            push100=i;
            break;
        }
    }
    if(!push100)
        VF_FatalError("Could not find 'push 100'", g_ErrorMessageCallback);
    //push_addr+=sec_addr; //TODO: remove this
    call_decrypt+=sec_addr;
    push100+=sec_addr;
    g_version_decrypt_call=call_decrypt;
    g_version_decrypt_call_dest=call_dest;
    g_version_decrypt_neweip=push100;
    SetBPX(g_version_decrypt_call_dest, UE_BREAKPOINT, (void*)VF_cbVerDecryptCall);
    free(sec_data);
}


void VF_cbVerOpenMutexA()
{
    char mutex_name[20]="";
    long mutex_addr=0;
    long esp_addr=0;
    unsigned int return_addr=0;
    DeleteAPIBreakPoint((char*)"kernel32.dll", (char*)"OpenMutexA", UE_APISTART);
    esp_addr=(long)GetContextData(UE_ESP);
    ReadProcessMemory(g_fdProcessInfo->hProcess, (const void*)esp_addr, &return_addr, 4, 0);
    ReadProcessMemory(g_fdProcessInfo->hProcess, (const void*)(esp_addr+12), &mutex_addr, 4, 0);
    ReadProcessMemory(g_fdProcessInfo->hProcess, (const void*)mutex_addr, &mutex_name, 20, 0);
    CreateMutexA(0, FALSE, mutex_name);
    if(GetLastError()==ERROR_SUCCESS)
        SetAPIBreakPoint((char*)"kernel32.dll", (char*)"VirtualProtect", UE_BREAKPOINT, UE_APISTART, (void*)VF_cbVerVirtualProtect);
    else
    {
        char log_message[256]="";
        sprintf(log_message, "[Fail] Failed to create mutex %s", mutex_name);
        VF_FatalError(log_message, g_ErrorMessageCallback);
    }
}


void VF_cbVerEntry()
{
    if(!g_fdFileIsDll)
        SetAPIBreakPoint((char*)"kernel32.dll", (char*)"OpenMutexA", UE_BREAKPOINT, UE_APISTART, (void*)VF_cbVerOpenMutexA);
    else
        SetAPIBreakPoint((char*)"kernel32.dll", (char*)"VirtualProtect", UE_BREAKPOINT, UE_APISTART, (void*)VF_cbVerVirtualProtect);
}


void VF_Version(char* szFileName, char* szVersion, ErrMessageCallback ErrorMessageCallback)
{
    FILE_STATUS_INFO inFileStatus = {0};

    g_szVersion = szVersion;
    g_fdFileIsDll = false;
    g_fdProcessInfo = NULL;
    g_ErrorMessageCallback = ErrorMessageCallback;

    if(IsPE32FileValidEx(szFileName, UE_DEPTH_SURFACE, &inFileStatus))
    {
        if(inFileStatus.FileIs64Bit)
        {
            ErrorMessageCallback((char*)"64-bit files are not (yet) supported!", (char*)"Error!");
            return;
        }
        HANDLE hFile, fileMap;
        ULONG_PTR va;
        DWORD bytes_read=0;
        StaticFileLoad(szFileName, UE_ACCESS_READ, false, &hFile, &bytes_read, &fileMap, &va);
        if(!IsArmadilloProtected(va))
        {
            ErrorMessageCallback((char*)"Not armadillo protected...", (char*)"Error!");
            return;
        }
        StaticFileClose(hFile);
        g_fdFileIsDll = inFileStatus.FileIsDLL;
        if(!g_fdFileIsDll)
        {
            g_fdProcessInfo = (LPPROCESS_INFORMATION)InitDebugEx(szFileName, NULL, NULL, (void*)VF_cbVerEntry);
        }
        else
        {
            g_fdProcessInfo = (LPPROCESS_INFORMATION)InitDLLDebug(szFileName, false, NULL, NULL, (void*)VF_cbVerEntry);
        }
        if(g_fdProcessInfo)
        {
            DebugLoop();
        }
        else
        {
            ErrorMessageCallback((char*)"Something went wrong during initialization...", (char*)"Error!");
        }
    }
    else
    {
        ErrorMessageCallback((char*)"This is not a valid PE file...", (char*)"Error!");
    }
}
