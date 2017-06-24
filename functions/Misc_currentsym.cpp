#include "Misc_currentsym.h"

unsigned int FindMagicPattern(BYTE* d, unsigned int size)
{
    for(unsigned int i = 0; i < size; i++) //8813000089
        if(d[i] == 0x88 && d[i + 1] == 0x13 && d[i + 2] == 0x00 && d[i + 3] == 0x00 && d[i + 4] == 0x89)
        {
            return i + 7;
        }
    return 0;
}

void MSC_cbGetACP()
{
    char text[11] = "";
    sprintf(text, "%.8X", MSC_current_sym);
    SetDlgItemTextA(MSC_shared, IDC_EDT_CURRENTSYM, text);
    StopDebug();
}

void MSC_cbSymGet()
{
    if(!MSC_getversion_set)
    {
        SetAPIBreakPoint((char*)"kernel32.dll", (char*)"GetACP", UE_BREAKPOINT, UE_APISTART, (void*)MSC_cbGetACP);
        MSC_getversion_set = true;
    }
    unsigned char ebp_sub_sym = 0;
    ReadProcessMemory(MSC_fdProcessInfo->hProcess, (void*)(GetContextData(UE_EIP) + 2), &ebp_sub_sym, 1, 0);
    ReadProcessMemory(MSC_fdProcessInfo->hProcess, (void*)(GetContextData(UE_EBP) + ebp_sub_sym), &MSC_current_sym, 4, 0);
}

void MSC_cbVirtualProtect()
{
    long esp_addr = GetContextData(UE_ESP);
    unsigned int security_code_base = 0, security_code_size = 0;
    ReadProcessMemory(MSC_fdProcessInfo->hProcess, (void*)(esp_addr + 4), &security_code_base, 4, 0);
    ReadProcessMemory(MSC_fdProcessInfo->hProcess, (void*)(esp_addr + 8), &security_code_size, 4, 0);
    BYTE* header_code = (BYTE*)malloc2(0x1000);
    ReadProcessMemory(MSC_fdProcessInfo->hProcess, (void*)(security_code_base - 0x1000), header_code, 0x1000, 0);
    if(*(unsigned short*)header_code != 0x5A4D) //not a PE file
    {
        free2(header_code);
        return;
    }
    free2(header_code);
    DeleteAPIBreakPoint((char*)"kernel32.dll", (char*)"VirtualProtect", UE_APISTART);
    BYTE* security_code = (BYTE*)malloc2(security_code_size);
    ReadProcessMemory(MSC_fdProcessInfo->hProcess, (void*)security_code_base, security_code, security_code_size, 0);

    MSC_magic_addr = FindMagicPattern(security_code, security_code_size);
    if(!MSC_magic_addr)
    {
        MSC_FatalError("Failed to locate pattern...");
        return;
    }
    SetBPX(MSC_magic_addr + security_code_base, UE_BREAKPOINT, (void*)MSC_cbSymGet);
    free2(security_code);
}

void MSC_cbOpenMutexA()
{
    char mutex_name[20] = "";
    long mutex_addr = 0;
    long esp_addr = 0;
    unsigned int return_addr = 0;
    DeleteAPIBreakPoint((char*)"kernel32.dll", (char*)"OpenMutexA", UE_APISTART);
    esp_addr = (long)GetContextData(UE_ESP);
    ReadProcessMemory(MSC_fdProcessInfo->hProcess, (const void*)esp_addr, &return_addr, 4, 0);
    ReadProcessMemory(MSC_fdProcessInfo->hProcess, (const void*)(esp_addr + 12), &mutex_addr, 4, 0);
    ReadProcessMemory(MSC_fdProcessInfo->hProcess, (const void*)mutex_addr, &mutex_name, 20, 0);
    CreateMutexA(0, FALSE, mutex_name);
    if(GetLastError() == ERROR_SUCCESS)
        SetAPIBreakPoint((char*)"kernel32.dll", (char*)"VirtualProtect", UE_BREAKPOINT, UE_APISTART, (void*)MSC_cbVirtualProtect);
    else
    {
        char log_message[256] = "";
        sprintf(log_message, "[Fail] Failed to create mutex %s", mutex_name);
        MSC_FatalError(log_message);
    }
}

void MSC_cbEntry()
{
    FixIsDebuggerPresent(MSC_fdProcessInfo->hProcess, true);
    if(!MSC_fdFileIsDll)
        SetAPIBreakPoint((char*)"kernel32.dll", (char*)"OpenMutexA", UE_BREAKPOINT, UE_APISTART, (void*)MSC_cbOpenMutexA);
    else
        SetAPIBreakPoint((char*)"kernel32.dll", (char*)"VirtualProtect", UE_BREAKPOINT, UE_APISTART, (void*)MSC_cbVirtualProtect);
}

DWORD WINAPI MSC_CurSymDebugThread(void* lpvoid)
{
    MSC_isdebugging = true;
    HWND btn = GetDlgItem(MSC_shared, IDC_BTN_GETCURSYM);
    EnableWindow(btn, 0);
    MSC_getversion_set = false;
    MSC_current_sym = 0;
    MSC_fdFileIsDll = false;
    MSC_fdProcessInfo = 0;
    FILE_STATUS_INFO inFileStatus = {0};
    IsPE32FileValidEx(MSC_szFileName, UE_DEPTH_SURFACE, &inFileStatus);
    if(inFileStatus.FileIs64Bit)
    {
        MessageBoxA(MSC_shared, "64-bit files are not (yet) supported!", "Error!", MB_ICONERROR);
        return 0;
    }
    HANDLE hFile, fileMap;
    ULONG_PTR va;
    DWORD bytes_read = 0;
    StaticFileLoad(MSC_szFileName, UE_ACCESS_READ, false, &hFile, &bytes_read, &fileMap, &va);
    if(!IsArmadilloProtected(va))
    {
        EnableWindow(btn, 1);
        MSC_isdebugging = false;
        MessageBoxA(MSC_shared, "Not armadillo protected...", "Error!", MB_ICONERROR);
        return 0;
    }
    StaticFileClose(hFile);
    MSC_fdFileIsDll = inFileStatus.FileIsDLL;
    if(!MSC_fdFileIsDll)
    {
        MSC_fdProcessInfo = (LPPROCESS_INFORMATION)InitDebugEx(MSC_szFileName, 0, 0, (void*)MSC_cbEntry);
    }
    else
    {
        MSC_fdProcessInfo = (LPPROCESS_INFORMATION)InitDLLDebug(MSC_szFileName, false, 0, 0, (void*)MSC_cbEntry);
    }
    if(MSC_fdProcessInfo)
    {
        DebugLoop();
    }
    else
    {
        MessageBoxA(MSC_shared, "Something went wrong during initialization...", "Error!", MB_ICONERROR);
    }
    EnableWindow(btn, 1);
    MSC_isdebugging = false;
    return 0;
}
