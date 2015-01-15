#include "EVLog_debugger.h"

bool EV_bpvp_set = false;
bool EV_fdFileIsDll = false;
LPPROCESS_INFORMATION EV_fdProcessInfo = 0;
char EV_guard_text[256] = "Break!";
ULONG_PTR EV_va;

void RemoveListDuplicates(HWND hwndDlg, UINT id)
{
    int total_unique = 0;
    char** unique_list;
    HWND lst = GetDlgItem(hwndDlg, id);
    int total_list = SendMessageA(lst, LB_GETCOUNT, 0, 0);
    unique_list = (char**)malloc2(total_list * 4);
    memset(unique_list, 0, total_list * 4);

    //Filter duplicates
    for(int i = 0; i < total_list; i++)
    {
        if(!total_unique) //First entry
        {
            int textlen = SendMessageA(lst, LB_GETTEXTLEN, 0, 0);
            unique_list[total_unique] = (char*)malloc2(textlen + 1);
            memset(unique_list[total_unique], 0, textlen + 1);
            SendMessageA(lst, LB_GETTEXT, i, (LPARAM)unique_list[total_unique]);
            total_unique++;
        }
        else //Other entries
        {
            char list_text[256] = "";
            SendMessageA(lst, LB_GETTEXT, i, (LPARAM)list_text);
            bool isnotinlist = true;
            for(int i = 0; i < total_unique; i++) //Search for a string in the unique list
            {
                if(!strcmp(unique_list[i], list_text))
                    isnotinlist = false;
            }
            if(isnotinlist) //Add a new item to the unique list
            {
                int textlen = strlen(list_text);
                unique_list[total_unique] = (char*)malloc2(textlen + 1);
                memset(unique_list[total_unique], 0, textlen + 1);
                strcpy(unique_list[total_unique], list_text);
                total_unique++;
            }
        }
    }

    //Add all unique items to list
    SendMessageA(lst, LB_RESETCONTENT, 0, 0);
    for(int i = 0; i < total_unique; i++)
    {
        SendMessageA(lst, LB_ADDSTRING, 0, (LPARAM)unique_list[i]);
        free2(unique_list[i]);
    }
    free2(unique_list);
}

unsigned int EV_FindSetEnvPattern(BYTE* d, unsigned int size, bool skip_first)
{
    bool skip = skip_first;
    for(unsigned int i = 0; i < size; i++) //55 8B EC 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 83 EC 20 A1 ?? ?? ?? ?? 33 C5 50 8D 45 F4 64 A3 00 00 00 00 89 4D D8 6A FF 8B 4D
    {
        if(d[i] == 0x55 and d[i + 1] == 0x8B and d[i + 2] == 0xEC and d[i + 3] == 0x6A and d[i + 4] == 0xFF and d[i + 5] == 0x68)
            if(d[i + 10] == 0x64 and d[i + 11] == 0xA1 and d[i + 12] == 0 and d[i + 13] == 0 and d[i + 14] == 0 and d[i + 15] == 0)
                if(d[i + 16] == 0x50 and d[i + 17] == 0x83 and d[i + 18] == 0xEC and d[i + 19] == 0x20 and d[i + 20] == 0xA1)
                    if(d[i + 25] == 0x33 and d[i + 26] == 0xC5 and d[i + 27] == 0x50 and d[i + 28] == 0x8D and d[i + 29] == 0x45 and d[i + 30] == 0xF4)
                        if(d[i + 31] == 0x64 and d[i + 32] == 0xA3 and d[i + 33] == 0 and d[i + 34] == 0 and d[i + 35] == 0 and d[i + 36] == 0)
                            if(d[i + 37] == 0x89 and d[i + 38] == 0x4D and d[i + 39] == 0xD8 and d[i + 40] == 0x6A and d[i + 41] == 0xFF and d[i + 42] == 0x8B and d[i + 43] == 0x4D)
                                if(d[i + 44] == 0xD8 and d[i + 45] == 0x83 and d[i + 46] == 0xC1 and d[i + 47] == 4 and d[i + 48] == 0xE8)
                                {
                                    if(!skip)
                                        return i;
                                    else
                                        skip = false;
                                }
    }
    return 0;
}

unsigned int EV_FindSetEnvPatternOld(BYTE* d, unsigned int size, bool skip_first)
{
    bool skip = skip_first;
    for(unsigned int i = 0; i < size; i++) //55 8B EC 83 EC 1C 89 4D E8 6A FF 8B 4D E8 83 C1 04 E8
    {
        if(d[i] == 0x55 and d[i + 1] == 0x8B and d[i + 2] == 0xEC and d[i + 3] == 0x83 and d[i + 4] == 0xEC)
            if(d[i + 5] == 0x1C and d[i + 6] == 0x89 and d[i + 7] == 0x4D and d[i + 8] == 0xE8 and d[i + 9] == 0x6A and d[i + 10] == 0xFF)
                if(d[i + 11] == 0x8B and d[i + 12] == 0x4D and d[i + 13] == 0xE8 and d[i + 14] == 0x83 and d[i + 15] == 0xC1 and d[i + 16] == 0x04 and d[i + 17] == 0xE8)
                {
                    if(!skip)
                        return i;
                    else
                        skip = false;
                }
    }
    return 0;
}

unsigned int EV_FindSetEnvPatternOldOld(BYTE* d, unsigned int size, bool skip_first)
{
    bool skip = skip_first;
    for(unsigned int i = 0; i < size; i++) //55 8B EC 83 EC 14 89 4D F0 8B 4D F0 E8
    {
        if(d[i] == 0x55 and d[i + 1] == 0x8B and d[i + 2] == 0xEC and d[i + 3] == 0x83 and d[i + 4] == 0xEC)
            if(d[i + 5] == 0x14 and d[i + 6] == 0x89 and d[i + 7] == 0x4D and d[i + 8] == 0xF0 and d[i + 9] == 0x8B and d[i + 10] == 0x4D)
                if(d[i + 11] == 0xF0 and d[i + 12] == 0xE8)
                {
                    if(!skip)
                        return i;
                    else
                        skip = false;
                }
    }
    return 0;
}

//55 8B EC 83 EC 14 89 4D F0 8B 4D F0 E8

void EV_FatalError(const char* msg)
{
    MessageBoxA(EV_shared, msg, "Fatal Error!", MB_ICONERROR);
    ExitProcess(1);
}

void EV_BreakDebugger() //TODO: never used
{
    DWORD EV_oldprotect = 0;
    VirtualProtect(EV_guard_text, 256, PAGE_READWRITE | PAGE_GUARD, &EV_oldprotect);
    EV_guard_text[0] = 0;
}

void EV_cbEndLog()
{
    unsigned int esp_addr = (long)GetContextData(UE_ESP) + 4;
    unsigned int return_eip = 0;
    ReadProcessMemory(EV_fdProcessInfo->hProcess, (const void*)esp_addr, &return_eip, 4, 0);
    if(GetPE32SectionNumberFromVA(EV_va, return_eip) != -1)
    {
        StopDebug();
    }
}

void EV_log_var_valW(const wchar_t* varname, const wchar_t* varvalue)
{
    wchar_t final_string[512] = L"";
    if(varvalue[0] and varname[0])
        swprintf(final_string, L"%s=%s", varname, varvalue);
    //swprintf(final_string, L"SetEnvW: %s=%s", varname, varvalue);
    else if(varvalue[0] == 0 and varname[0] and varname[1])
    {
        //swprintf(final_string, L"SetEnvW: %s=(null)", varname);
        swprintf(final_string, L"%s=(null)", varname);
    }
    else
        return;
    SendMessageW(EV_list_hwnd, LB_ADDSTRING, 0, (LPARAM)final_string);
    int cSelect = (int)SendMessageA(EV_list_hwnd, LB_GETCOUNT, 0, 0) - 1;
    SendMessageW(EV_list_hwnd, LB_SETCURSEL, (WPARAM)cSelect, 0);
}

void EV_log_var_valA(const char* varname, const char* varvalue)
{
    char final_string[512] = "";
    if(varvalue[0] and varname[0])
        //sprintf(final_string, "SetEnvA: %s=%s", varname, varvalue);
        sprintf(final_string, "%s=%s", varname, varvalue);
    else if(varvalue[0] == 0 and varname[0] and varname[1])
    {
        //sprintf(final_string, "SetEnvA: %s=(null)", varname);
        sprintf(final_string, "%s=(null)", varname);
    }
    else
        return;
    SendMessageA(EV_list_hwnd, LB_ADDSTRING, 0, (LPARAM)final_string);
    int cSelect = (int)SendMessageA(EV_list_hwnd, LB_GETCOUNT, 0, 0) - 1;
    SendMessageA(EV_list_hwnd, LB_SETCURSEL, (WPARAM)cSelect, 0);
}

void EV_cbSetEnvW()
{
    if(!EV_bpvp_set) //Set VirtualProtect breakpoint
    {
        SetAPIBreakPoint((char*)"kernel32.dll", (char*)"VirtualProtect", UE_BREAKPOINT, UE_APISTART, (void*)EV_cbEndLog);
        EV_bpvp_set = true;
    }
    wchar_t env_name[256] = L"", env_valu[256] = L"";
    long text_addr = 0;
    long esp_addr = (long)GetContextData(UE_ESP);
    text_addr = 0;
    ReadProcessMemory(EV_fdProcessInfo->hProcess, (const void*)(esp_addr + 4), &text_addr, 4, 0);
    if(text_addr)
        ReadProcessMemory(EV_fdProcessInfo->hProcess, (const void*)text_addr, &env_name, 512, 0);
    text_addr = 0;
    ReadProcessMemory(EV_fdProcessInfo->hProcess, (const void*)(esp_addr + 8), &text_addr, 4, 0);
    if(text_addr)
        ReadProcessMemory(EV_fdProcessInfo->hProcess, (const void*)text_addr, &env_valu, 512, 0);
    EV_log_var_valW(env_name, env_valu);
}

void EV_cbSetEnvA()
{
    if(!EV_bpvp_set) //Set VirtualProtect breakpoint
    {
        SetAPIBreakPoint((char*)"kernel32.dll", (char*)"VirtualProtect", UE_BREAKPOINT, UE_APISTART, (void*)EV_cbEndLog);
        EV_bpvp_set = true;
    }
    char env_name[256] = "", env_valu[256] = "";
    long text_addr = 0;
    long esp_addr = (long)GetContextData(UE_ESP);
    text_addr = 0;
    ReadProcessMemory(EV_fdProcessInfo->hProcess, (const void*)(esp_addr + 4), &text_addr, 4, 0);
    if(text_addr)
        ReadProcessMemory(EV_fdProcessInfo->hProcess, (const void*)text_addr, &env_name, 256, 0);
    text_addr = 0;
    ReadProcessMemory(EV_fdProcessInfo->hProcess, (const void*)(esp_addr + 8), &text_addr, 4, 0);
    if(text_addr)
        ReadProcessMemory(EV_fdProcessInfo->hProcess, (const void*)text_addr, &env_valu, 256, 0);
    EV_log_var_valA(env_name, env_valu);
}

void EV_cbVirtualProtect()
{
    unsigned int sec_addr = 0;
    unsigned int sec_size = 0;
    unsigned int esp_addr = 0;
    BYTE* sec_data = 0;
    esp_addr = (long)GetContextData(UE_ESP);

    ReadProcessMemory(EV_fdProcessInfo->hProcess, (const void*)((esp_addr) + 4), &sec_addr, 4, 0);
    ReadProcessMemory(EV_fdProcessInfo->hProcess, (const void*)((esp_addr) + 8), &sec_size, 4, 0);
    BYTE* header_code = (BYTE*)malloc2(0x1000);
    ReadProcessMemory(EV_fdProcessInfo->hProcess, (void*)(sec_addr - 0x1000), header_code, 0x1000, 0);
    if(*(unsigned short*)header_code != 0x5A4D) //not a PE file
    {
        free2(header_code);
        return;
    }
    free2(header_code);
    DeleteAPIBreakPoint((char*)"kernel32.dll", (char*)"VirtualProtect", UE_APISTART);
    sec_data = (BYTE*)malloc2(sec_size);
    ReadProcessMemory(EV_fdProcessInfo->hProcess, (const void*)sec_addr, sec_data, sec_size, 0);
    unsigned int SetEnvA = 0, SetEnvW = 0;
    SetEnvW = EV_FindSetEnvPattern(sec_data, sec_size, false) + sec_addr;
    if(!(SetEnvW - sec_addr))
    {
        SetEnvW = EV_FindSetEnvPatternOld(sec_data, sec_size, false) + sec_addr;
        if(!(SetEnvW - sec_addr))
        {
            SetEnvW = EV_FindSetEnvPatternOldOld(sec_data, sec_size, false) + sec_addr;
            if(!(SetEnvW - sec_addr))
                EV_FatalError("Could not locate the SetEnvW function, please contact Mr. eXoDia...");
        }
    }
    //SetHardwareBreakPoint(SetEnvW, UE_DR1, UE_HARDWARE_EXECUTE, UE_HARDWARE_SIZE_1, (void*)EV_cbSetEnvW);
    SetBPX(SetEnvW, UE_BREAKPOINT, (void*)EV_cbSetEnvW);
    SetEnvA = EV_FindSetEnvPattern(sec_data, sec_size, true) + sec_addr;
    if(!(SetEnvA - sec_addr))
    {
        SetEnvA = EV_FindSetEnvPatternOld(sec_data, sec_size, true) + sec_addr;
        if(!(SetEnvA - sec_addr))
        {
            SetEnvA = EV_FindSetEnvPatternOldOld(sec_data, sec_size, true) + sec_addr;
            if(!(SetEnvA - sec_addr))
                EV_FatalError("Could not locate the SetEnvA function, please contact Mr. eXoDia...");
        }
    }
    //SetHardwareBreakPoint(SetEnvA, UE_DR0, UE_HARDWARE_EXECUTE, UE_HARDWARE_SIZE_1, (void*)EV_cbSetEnvA);
    SetBPX(SetEnvW, UE_BREAKPOINT, (void*)EV_cbSetEnvA);
}

void EV_cbOpenMutexA()
{
    char mutex_name[20] = "";
    long mutex_addr = 0;
    long esp_addr = 0;
    DeleteAPIBreakPoint((char*)"kernel32.dll", (char*)"OpenMutexA", UE_APISTART);
    esp_addr = (long)GetContextData(UE_ESP) + 12;
    ReadProcessMemory(EV_fdProcessInfo->hProcess, (const void*)esp_addr, &mutex_addr, 4, 0);
    ReadProcessMemory(EV_fdProcessInfo->hProcess, (const void*)mutex_addr, &mutex_name, 20, 0);
    CreateMutexA(0, FALSE, mutex_name);
    if(GetLastError() == ERROR_SUCCESS)
    {
        SetAPIBreakPoint((char*)"kernel32.dll", (char*)"VirtualProtect", UE_BREAKPOINT, UE_APISTART, (void*)EV_cbVirtualProtect);
    }
    else
    {
        char EV_log_message[256] = "";
        sprintf(EV_log_message, "[Fail] Failed to create mutex %s", mutex_name);
        EV_FatalError(EV_log_message);
    }
}

void EV_cbEntry()
{
    FixIsDebuggerPresent(EV_fdProcessInfo->hProcess, true);
    if(!EV_fdFileIsDll)
        SetAPIBreakPoint((char*)"kernel32.dll", (char*)"OpenMutexA", UE_BREAKPOINT, UE_APISTART, (void*)EV_cbOpenMutexA);
    else
        SetAPIBreakPoint((char*)"kernel32.dll", (char*)"VirtualProtect", UE_BREAKPOINT, UE_APISTART, (void*)EV_cbVirtualProtect);
}

DWORD WINAPI EV_DebugThread(LPVOID lpStartAddress)
{
    EV_fdFileIsDll = false;
    EV_fdProcessInfo = 0;
    EV_bpvp_set = false;
    DWORD EV_bytes_read = 0;
    FILE_STATUS_INFO inFileStatus = {0};
    IsPE32FileValidEx(EV_szFileName, UE_DEPTH_SURFACE, &inFileStatus);
    HANDLE hFile, fileMap;
    //EV_fdEntryPoint=(long)GetPE32Data(EV_szFileName, 0, UE_OEP);
    StaticFileLoad(EV_szFileName, UE_ACCESS_READ, false, &hFile, &EV_bytes_read, &fileMap, &EV_va);
    StaticFileClose(hFile);
    EV_fdFileIsDll = inFileStatus.FileIsDLL;
    if(!EV_fdFileIsDll)
    {
        EV_fdProcessInfo = (LPPROCESS_INFORMATION)InitDebugEx(EV_szFileName, 0, 0, (void*)EV_cbEntry);
    }
    else
    {
        EV_fdProcessInfo = (LPPROCESS_INFORMATION)InitDLLDebug(EV_szFileName, false, 0, 0, (void*)EV_cbEntry);
    }
    if(EV_fdProcessInfo)
    {
        DebugLoop();
        RemoveListDuplicates(EV_shared, IDC_LIST);
        return 0;
    }
    else
    {
        MessageBoxA(EV_shared, "Something went wrong during initialization...", "Error!", MB_ICONERROR);
        return 0;
    }
    return 1;
}
