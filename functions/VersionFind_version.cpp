#include "VersionFind_version.h"

/**********************************************************************
 *						Module Variables
 *********************************************************************/
// Debugging Variables
static bool g_fdFileIsDll=false;
static LPPROCESS_INFORMATION g_fdProcessInfo;

// Output Pointers
static char* g_szVersion;

// Internal Use Variables
static unsigned int g_version_decrypt_buffer=0;
static unsigned int g_version_decrypt_call=0;
static unsigned int g_version_decrypt_call_dest=0;
static unsigned int g_version_decrypt_neweip=0;
static cbErrorMessage g_ErrorMessageCallback=0;


/**********************************************************************
 *						Functions
 *********************************************************************/
static void cbGetVersion()
{
    DeleteBPX(GetContextData(UE_EIP));
    if(!ReadProcessMemory(g_fdProcessInfo->hProcess, (void*)g_version_decrypt_buffer, g_szVersion, 10, 0))
    {
        VF_FatalError(rpmerror(), g_ErrorMessageCallback);
        return;
    }
    StopDebug();
}


static void cbOnDecryptVersion()
{
    DeleteBPX(GetContextData(UE_EIP));
    unsigned int esp=GetContextData(UE_ESP);
    if(!ReadProcessMemory(g_fdProcessInfo->hProcess, (void*)(esp+4), &g_version_decrypt_buffer, 4, 0))
    {
        VF_FatalError(rpmerror(), g_ErrorMessageCallback);
        return;
    }
    SetBPX((g_version_decrypt_call+5), UE_BREAKPOINT, (void*)cbGetVersion);
}


static void cbReturnDecryptCall()
{
    DeleteBPX(GetContextData(UE_EIP));
    SetBPX(g_version_decrypt_call, UE_BREAKPOINT, (void*)cbOnDecryptVersion);
    SetContextData(UE_EIP, g_version_decrypt_neweip);
}


static void cbDecryptCall()
{
    DeleteBPX(GetContextData(UE_EIP));
    unsigned int esp=GetContextData(UE_ESP);
    unsigned int retn=0;
    if(!ReadProcessMemory(g_fdProcessInfo->hProcess, (void*)esp, &retn, 4, 0))
    {
        VF_FatalError(rpmerror(), g_ErrorMessageCallback);
        return;
    }
    SetBPX(retn, UE_BREAKPOINT, (void*)cbReturnDecryptCall);
}


static void cbVirtualProtect()
{
    MEMORY_BASIC_INFORMATION mbi= {0};
    unsigned int sec_addr=0;
    unsigned int sec_size=0;
    unsigned int esp_addr=0;
    BYTE* sec_data=0;
    esp_addr=(long)GetContextData(UE_ESP);
    if(!ReadProcessMemory(g_fdProcessInfo->hProcess, (const void*)((esp_addr)+4), &sec_addr, 4, 0))
    {
        VF_FatalError(rpmerror(), g_ErrorMessageCallback);
        return;
    }
    sec_addr-=0x1000;
    VirtualQueryEx(g_fdProcessInfo->hProcess, (void*)sec_addr, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
    sec_size=mbi.RegionSize;
    sec_data=(BYTE*)malloc2(sec_size);
    if(!ReadProcessMemory(g_fdProcessInfo->hProcess, (const void*)sec_addr, sec_data, sec_size, 0))
    {
        free2(sec_data);
        VF_FatalError(rpmerror(), g_ErrorMessageCallback);
        return;
    }
    if(*(unsigned short*)sec_data != 0x5A4D) //not a PE file
    {
        free2(sec_data);
        return;
    }
    DeleteAPIBreakPoint((char*)"kernel32.dll", (char*)"VirtualProtect", UE_APISTART);

    unsigned int armversion_addr=VF_FindarmVersion(sec_data, sec_size);
    if(!armversion_addr)
    {
        free2(sec_data);
        VF_FatalError("Could not find '<armVersion'", g_ErrorMessageCallback);
        return;
    }
    armversion_addr+=sec_addr;
    unsigned int push_addr=VF_FindPushAddr(sec_data, sec_size, armversion_addr);
    if(!push_addr)
    {
        free2(sec_data);
        VF_FatalError("Could not find reference to '<armVersion'", g_ErrorMessageCallback);
        return;
    }
    int call_decrypt=push_addr;
    while(sec_data[call_decrypt]!=0xE8) //TODO: fix this!!
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
    {
        VF_FatalError("Could not find 'push 100'", g_ErrorMessageCallback);
        return;
    }
    //push_addr+=sec_addr; //TODO: remove this
    call_decrypt+=sec_addr;
    push100+=sec_addr;
    g_version_decrypt_call=call_decrypt;
    g_version_decrypt_call_dest=call_dest;
    g_version_decrypt_neweip=push100;
    SetBPX(g_version_decrypt_call_dest, UE_BREAKPOINT, (void*)cbDecryptCall);
    free2(sec_data);
}


static void cbOpenMutexA()
{
    char mutex_name[20]="";
    long mutex_addr=0;
    long esp_addr=0;
    unsigned int return_addr=0;
    DeleteAPIBreakPoint((char*)"kernel32.dll", (char*)"OpenMutexA", UE_APISTART);
    esp_addr=(long)GetContextData(UE_ESP);
    if(!ReadProcessMemory(g_fdProcessInfo->hProcess, (const void*)esp_addr, &return_addr, 4, 0))
    {
        VF_FatalError(rpmerror(), g_ErrorMessageCallback);
        return;
    }
    if(!ReadProcessMemory(g_fdProcessInfo->hProcess, (const void*)(esp_addr+12), &mutex_addr, 4, 0))
    {
        VF_FatalError(rpmerror(), g_ErrorMessageCallback);
        return;
    }
    if(!ReadProcessMemory(g_fdProcessInfo->hProcess, (const void*)mutex_addr, &mutex_name, 20, 0))
    {
        VF_FatalError(rpmerror(), g_ErrorMessageCallback);
        return;
    }
    CreateMutexA(0, FALSE, mutex_name);
    if(GetLastError()==ERROR_SUCCESS)
        SetAPIBreakPoint((char*)"kernel32.dll", (char*)"VirtualProtect", UE_BREAKPOINT, UE_APISTART, (void*)cbVirtualProtect);
    else
    {
        char log_message[256]="";
        sprintf(log_message, "[Fail] Failed to create mutex %s", mutex_name);
        VF_FatalError(log_message, g_ErrorMessageCallback);
    }
}


static void cbEntry()
{
    FixIsDebuggerPresent(g_fdProcessInfo->hProcess, true);
    if(!g_fdFileIsDll)
        SetAPIBreakPoint((char*)"kernel32.dll", (char*)"OpenMutexA", UE_BREAKPOINT, UE_APISTART, (void*)cbOpenMutexA);
    else
        SetAPIBreakPoint((char*)"kernel32.dll", (char*)"VirtualProtect", UE_BREAKPOINT, UE_APISTART, (void*)cbVirtualProtect);
}


void VF_Version(char* szFileName, char* szVersion, cbErrorMessage ErrorMessageCallback)
{
    FILE_STATUS_INFO inFileStatus= {0};

    g_szVersion=szVersion;
    g_fdFileIsDll=false;
    g_fdProcessInfo=0;
    g_ErrorMessageCallback=ErrorMessageCallback;

    IsPE32FileValidEx(szFileName, UE_DEPTH_SURFACE, &inFileStatus);
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
    g_fdFileIsDll=inFileStatus.FileIsDLL;
    if(!g_fdFileIsDll)
        g_fdProcessInfo=(LPPROCESS_INFORMATION)InitDebugEx(szFileName, 0, 0, (void*)cbEntry);
    else
        g_fdProcessInfo=(LPPROCESS_INFORMATION)InitDLLDebug(szFileName, false, 0, 0, (void*)cbEntry);
    if(g_fdProcessInfo)
        DebugLoop();
    else
        ErrorMessageCallback((char*)"Something went wrong during initialization...", (char*)"Error!");
}
