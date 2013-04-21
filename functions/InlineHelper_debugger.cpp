#include "InlineHelper_global.h"

BYTE IH_FindCrcStart(BYTE* data) //Find the start of the CRC array
{
    for(unsigned int i=0; i<1024; i++)
    {
        if(data[i]==0x33) ///Pattern : 33 ?? ?? 33 ?? ?? 33 ?? ?? (with some extras)
        {
            if(data[i+3]==0x33)
            {
                if(data[i+5]==0x33)
                {
                    return data[i+7];
                }
                else if(data[i+6]==0x33)
                {
                    return data[i+8];
                }
                else if(data[i+9]==0x33)
                {
                    return data[i+11];
                }
                else
                {
                    return data[i+5];
                }
            }
        }
    }
    for(unsigned int i=0; i<1024; i++)
    {
        if(data[i]==0x33) ///Pattern : 33 ?? ?? ?? ?? ?? 33 ?? ?? ?? ?? ?? 33 ?? ??
        {
            if(data[i+6]==0x33)
            {
                if(data[i+12]==0x33)
                {
                    return data[i+14];
                }
            }
        }
    }
    return 0;
}

unsigned int IH_FindFreeSpace(BYTE* d, unsigned int size)
{
    for(unsigned int i=0; i<size; i++) //0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
        if(d[i]==0x00 and d[i+1]==0x00 and d[i+2]==0x00 and d[i+3]==0x00 and d[i+4]==0x00 and d[i+5]==0x00 and d[i+6]==0x00 and d[i+7]==0x00 and d[i+8]==0x00 and d[i+9]==0x00 and d[i+10]==0x00 and d[i+11]==0x00 and d[i+12]==0x00 and d[i+13]==0x00 and d[i+14]==0x00 and d[i+15]==0x00 and d[i+16]==0x00 and d[i+17]==0x00 and d[i+18]==0x00 and d[i+19]==0x00 and d[i+20]==0x00 and d[i+21]==0x00 and d[i+22]==0x00 and d[i+23]==0x00 and d[i+24]==0x00 and d[i+25]==0x00 and d[i+26]==0x00 and d[i+27]==0x00 and d[i+28]==0x00 and d[i+29]==0x00 and d[i+30]==0x00 and d[i+31]==0x00 and d[i+32]==0x00 and d[i+33]==0x00 and d[i+34]==0x00 and d[i+35]==0x00 and d[i+36]==0x00 and d[i+37]==0x00 and d[i+38]==0x00 and d[i+39]==0x00 and d[i+40]==0x00 and d[i+41]==0x00 and d[i+42]==0x00 and d[i+43]==0x00 and d[i+44]==0x00 and d[i+45]==0x00 and d[i+46]==0x00 and d[i+47]==0x00 and d[i+48]==0x00 and d[i+49]==0x00)
            return i;
    return 0;
}

void IH_GetFreeSpaceAddr(void) //Retrieve address for free space
{
    BYTE* dump_addr=(BYTE*)VirtualAlloc(VirtualAlloc(0, IH_fdEntrySectionSize, MEM_RESERVE, PAGE_EXECUTE_READWRITE), IH_fdEntrySectionSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    ReadProcessMemory(IH_fdProcessInfo->hProcess, (void*)(IH_fdEntrySectionOffset+IH_fdImageBase), dump_addr, IH_fdEntrySectionSize, &IH_bytes_read);
    unsigned int free_addr=IH_FindFreeSpace(dump_addr, (unsigned int)IH_fdEntrySectionSize)+IH_fdEntrySectionOffset+IH_fdImageBase+5;
    char result_temp[10]="";
    sprintf(result_temp, "%08X", free_addr);
    SetDlgItemTextA(IH_shared, IDC_EDT_FREESPACE, result_temp);
    VirtualFree(dump_addr, IH_fdEntrySectionSize, MEM_DECOMMIT);
}

void IH_GetImportTableAddresses() //Retrieve basic import data
{
    HINSTANCE kernel32; //Handle to kernel32
    DeleteFile("loaded_binary.mem");
    DumpProcess(IH_fdProcessInfo->hProcess, (void*)IH_fdImageBase, (char*)"loaded_binary.mem", IH_fdEntryPoint);
    kernel32=GetModuleHandleA("kernel32");
    IH_addr_VirtualProtect=(unsigned int)GetProcAddress(kernel32, "VirtualProtect");
    IH_addr_OutputDebugStringA=(unsigned int)GetProcAddress(kernel32, "OutputDebugStringA");
    IH_addr_GetEnvironmentVariableA=(unsigned int)GetProcAddress(kernel32, "GetEnvironmentVariableA");
    IH_addr_SetEnvironmentVariableA=(unsigned int)GetProcAddress(kernel32, "SetEnvironmentVariableA");
    IH_addr_LoadLibraryA=(unsigned int)GetProcAddress(kernel32, "LoadLibraryA");
    IH_addr_GetProcAddress=(unsigned int)GetProcAddress(kernel32, "GetProcAddress");
    IH_addr_WriteProcessMemory=(unsigned int)GetProcAddress(kernel32, "WriteProcessMemory");

    HANDLE hFile=CreateFileA("loaded_binary.mem", GENERIC_ALL, 0, 0, OPEN_EXISTING, 0, 0);
    DWORD high=0,filesize=GetFileSize(hFile, &high);
    BYTE* dump_addr=(BYTE*)VirtualAlloc(VirtualAlloc(0, filesize+0x1000, MEM_RESERVE, PAGE_EXECUTE_READWRITE), filesize+0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    ReadFile(hFile, dump_addr, filesize, &high, 0);
    unsigned int result_addr=0;
    char result_txt[10]="";

    result_addr=FindDwordInMemory(dump_addr, IH_addr_VirtualProtect, filesize);
    if(result_addr)
        IH_addr_VirtualProtect=(unsigned int)(result_addr+IH_fdImageBase);
    else
        IH_addr_VirtualProtect=0;
    sprintf(result_txt, "%08X", IH_addr_VirtualProtect);
    SetDlgItemTextA(IH_shared, IDC_EDT_VP, result_txt);

    result_addr=FindDwordInMemory(dump_addr, IH_addr_OutputDebugStringA, filesize);
    if(result_addr)
        IH_addr_OutputDebugStringA=(unsigned int)(result_addr+IH_fdImageBase);
    else
        IH_addr_OutputDebugStringA=0;
    sprintf(result_txt, "%08X", IH_addr_OutputDebugStringA);
    SetDlgItemTextA(IH_shared, IDC_EDT_ODSA, result_txt);

    result_addr=FindDwordInMemory(dump_addr, IH_addr_GetEnvironmentVariableA, filesize);
    if(result_addr)
        IH_addr_GetEnvironmentVariableA=(unsigned int)(result_addr+IH_fdImageBase);
    else
        IH_addr_GetEnvironmentVariableA=0;
    sprintf(result_txt, "%08X", IH_addr_GetEnvironmentVariableA);
    SetDlgItemTextA(IH_shared, IDC_EDT_GEVA, result_txt);

    result_addr=FindDwordInMemory(dump_addr, IH_addr_SetEnvironmentVariableA, filesize);
    if(result_addr)
        IH_addr_SetEnvironmentVariableA=(unsigned int)(result_addr+IH_fdImageBase);
    else
        IH_addr_SetEnvironmentVariableA=0;
    sprintf(result_txt, "%08X", IH_addr_SetEnvironmentVariableA);
    SetDlgItemTextA(IH_shared, IDC_EDT_SEVA, result_txt);

    result_addr=FindDwordInMemory(dump_addr, IH_addr_LoadLibraryA, filesize);
    if(result_addr)
        IH_addr_LoadLibraryA=(unsigned int)(result_addr+IH_fdImageBase);
    else
        IH_addr_LoadLibraryA=0;
    sprintf(result_txt, "%08X", IH_addr_LoadLibraryA);
    SetDlgItemTextA(IH_shared, IDC_EDT_LLA, result_txt);

    result_addr=FindDwordInMemory(dump_addr, IH_addr_GetProcAddress, filesize);
    if(result_addr)
        IH_addr_GetProcAddress=(unsigned int)(result_addr+IH_fdImageBase);
    else
        IH_addr_GetProcAddress=0;
    sprintf(result_txt, "%08X", IH_addr_GetProcAddress);
    SetDlgItemTextA(IH_shared, IDC_EDT_GPA, result_txt);

    result_addr=FindDwordInMemory(dump_addr, IH_addr_WriteProcessMemory, filesize);
    if(result_addr)
        IH_addr_WriteProcessMemory=(unsigned int)(result_addr+IH_fdImageBase);
    else
        IH_addr_WriteProcessMemory=0;
    sprintf(result_txt, "%08X", IH_addr_WriteProcessMemory);
    SetDlgItemTextA(IH_shared, IDC_EDT_WPM, result_txt);

    ///Free the memory and close the handle
    VirtualFree(dump_addr, filesize+0x1000, MEM_DECOMMIT);
    CloseHandle(hFile);
}

void IH_cbOutputDebugStringA() //Callback for OutputDebugStringA
{
    ///Increase the total counter.
    IH_outputdebugcount_total++;

    ///Check if we landed on the correct place.
    char debug_string[256]="";
    unsigned int esp_addr=(long)GetContextData(UE_ESP), string_addr;
    ReadProcessMemory(IH_fdProcessInfo->hProcess, (void*)(esp_addr+4), &string_addr, 4, &IH_bytes_read);
    ReadProcessMemory(IH_fdProcessInfo->hProcess, (void*)string_addr, &debug_string, 255, &IH_bytes_read);
    if(debug_string[16]=='%' and debug_string[17]=='s')
        IH_outputdebugcount++;

    ///The second call to OutputDebugString("%s%s%s%s%s%s%s%s%s%...s%s%s%s%s%s%s"); is the call we need.
    if(IH_outputdebugcount==2)
    {
        IH_outputdebugcount=0;
        ///Declare some variables.
        unsigned int ebp_addr=GetContextData(UE_EBP),esp_addr=GetContextData(UE_ESP),bp_addr=0;
        BYTE search_bytes[1024]= {0xFF};

        ///Read the executable code to obtain the CRC base
        ReadProcessMemory(IH_fdProcessInfo->hProcess, (void*)esp_addr, &bp_addr, 4, &IH_bytes_read); ///Get the return address.
        ReadProcessMemory(IH_fdProcessInfo->hProcess, (void*)bp_addr, search_bytes, 1024, &IH_bytes_read); ///Read the actual disassembly.
        IH_crc_base=0x100-IH_FindCrcStart(search_bytes); ///Use a pattern to find the CRC base and NEG this base.

        unsigned int crc_check_call=IH_FindEB6APattern(search_bytes, 1024);
        bool arma960=false;
        unsigned int push_addr=0;
        if(crc_check_call) //Old versions will not have special stuff
        {
            unsigned int final_call=IH_FindCallPattern(search_bytes+crc_check_call, 1024-crc_check_call);
            if(final_call)
            {
                final_call+=crc_check_call;
                push_addr=IH_Find960Pattern(search_bytes+crc_check_call, 1024-crc_check_call);
                if(push_addr and push_addr<final_call)
                    arma960=true;
                push_addr+=crc_check_call+2;
            }
        }
        if(!IH_crc_base)
        {
            MessageBoxA(IH_shared, "There was an error! please contact me, I can fix it", "Error!", MB_ICONERROR);
            //TerminateProcess(IH_fdProcessInfo->hProcess, 0);
            //DetachDebugger(IH_fdProcessInfo->dwProcessId);
            StopDebug();
            return;
        }

        ///Read the CRC values from the variable stack.
        ReadProcessMemory(IH_fdProcessInfo->hProcess, (void*)(ebp_addr-IH_crc_base), &IH_crc_original_vals[0], 4, &IH_bytes_read);
        if(!arma960)
        {
            ReadProcessMemory(IH_fdProcessInfo->hProcess, (void*)(ebp_addr-IH_crc_base-8), &IH_crc_original_vals[1], 4, &IH_bytes_read);
            ReadProcessMemory(IH_fdProcessInfo->hProcess, (void*)(ebp_addr-IH_crc_base-12), &IH_crc_original_vals[2], 4, &IH_bytes_read);
            ReadProcessMemory(IH_fdProcessInfo->hProcess, (void*)(ebp_addr-IH_crc_base-16), &IH_crc_original_vals[3], 4, &IH_bytes_read);
            ReadProcessMemory(IH_fdProcessInfo->hProcess, (void*)(ebp_addr-IH_crc_base-20), &IH_crc_original_vals[4], 4, &IH_bytes_read);
        }
        else
        {
            unsigned int crc_read_addr=0;
            memcpy(&crc_read_addr, search_bytes+push_addr, 4);
            ReadProcessMemory(IH_fdProcessInfo->hProcess, (void*)crc_read_addr, &IH_crc_original_vals[1], 16, 0);
        }
        IH_arma960=arma960;
        IH_arma960_add=push_addr;


        char crc_temp[10]="";
        sprintf(crc_temp, "%02X", IH_crc_base);
        SetDlgItemTextA(IH_shared, IDC_EDT_CRCBASE, crc_temp);
        sprintf(crc_temp, "%08X", IH_crc_original_vals[0]);
        SetDlgItemTextA(IH_shared, IDC_EDT_CRC1, crc_temp);
        sprintf(crc_temp, "%08X", IH_crc_original_vals[1]);
        SetDlgItemTextA(IH_shared, IDC_EDT_CRC2, crc_temp);
        sprintf(crc_temp, "%08X", IH_crc_original_vals[2]);
        SetDlgItemTextA(IH_shared, IDC_EDT_CRC3, crc_temp);
        sprintf(crc_temp, "%08X", IH_crc_original_vals[3]);
        SetDlgItemTextA(IH_shared, IDC_EDT_CRC4, crc_temp);
        sprintf(crc_temp, "%08X", IH_crc_original_vals[4]);
        SetDlgItemTextA(IH_shared, IDC_EDT_CRC5, crc_temp);
        SetDlgItemInt(IH_shared, IDC_EDT_COUNTER, IH_outputdebugcount_total, TRUE);

        ///Generate code
        IH_GenerateAsmCode();
        SendDlgItemMessageA(IH_shared, IDC_EDT_OEP, EM_SETREADONLY, 0, 0); //Enable change of OEP...

        ///Termintate the process and detach the debugger.
        //TerminateProcess(IH_fdProcessInfo->hProcess, 0);
        //DetachDebugger(IH_fdProcessInfo->dwProcessId);
        StopDebug();
    }
}

void IH_cbVirtualProtect() //Callback for VirtualProtect
{
    DeleteAPIBreakPoint((char*)"kernel32.dll", (char*)"VirtualProtect", UE_APISTART);
    SetAPIBreakPoint((char*)"kernel32.dll", (char*)"OutputDebugStringA", UE_BREAKPOINT, UE_APISTART, (void*)IH_cbOutputDebugStringA);

    long security_addr=0,esp_addr=0,code_size=0;
    esp_addr=(long)GetContextData(UE_ESP);
    ReadProcessMemory(IH_fdProcessInfo->hProcess, (const void*)(esp_addr+4), &security_addr, 4, &IH_bytes_read);
    ReadProcessMemory(IH_fdProcessInfo->hProcess, (const void*)(esp_addr+8), &code_size, 4, &IH_bytes_read);

    DumpMemory(IH_fdProcessInfo->hProcess, (void*)security_addr, code_size, (char*)"security_code.mem");

    if(GetContextData(UE_EAX)==security_addr)
        strcpy(IH_security_addr_register, "EAX");

    else if(GetContextData(UE_ECX)==security_addr)
        strcpy(IH_security_addr_register, "ECX");

    else if(GetContextData(UE_EDX)==security_addr)
        strcpy(IH_security_addr_register, "EDX");

    else if(GetContextData(UE_EBX)==security_addr)
        strcpy(IH_security_addr_register, "EBX");

    else if(GetContextData(UE_ESI)==security_addr)
        strcpy(IH_security_addr_register, "ESI");

    else if(GetContextData(UE_EDI)==security_addr)
        strcpy(IH_security_addr_register, "EDI");

    else
    {
        MessageBoxA(IH_shared, "There was an error recovering the correct register.\n\nThe program will quit now!", "Error!", MB_ICONERROR);
        ExitProcess(1);
    }
}

void IH_cbOpenMutexA() //Callback for OpenMutexA
{
    char mutex_name[20]="";
    long mutex_addr=0;
    long esp_addr=0;
    DWORD bytes_read=0;
    DeleteAPIBreakPoint((char*)"kernel32.dll", (char*)"OpenMutexA", UE_APISTART);
    esp_addr=(long)GetContextData(UE_ESP)+12;
    ReadProcessMemory(IH_fdProcessInfo->hProcess, (const void*)esp_addr, &mutex_addr, 4, &bytes_read);
    ReadProcessMemory(IH_fdProcessInfo->hProcess, (const void*)mutex_addr, &mutex_name, 20, &bytes_read);
    CreateMutexA(0, FALSE, mutex_name);
    if(GetLastError()==ERROR_SUCCESS)
    {
        SetAPIBreakPoint((char*)"kernel32.dll", (char*)"VirtualProtect", UE_BREAKPOINT, UE_APISTART, (void*)IH_cbVirtualProtect);
    }
    else
    {
        char log_message[50]="";
        wsprintfA(log_message, "Failed to create mutex %s", mutex_name);
        MessageBoxA(IH_shared, log_message, "Error!", MB_ICONERROR);
    }
}

void IH_cbEntryPoint() //Entry callback
{
    HideDebugger(IH_fdProcessInfo->hProcess, UE_HIDE_BASIC);
    IH_GetImportTableAddresses();
    IH_GetFreeSpaceAddr();
    char entry_temp[10]="";
    sprintf(entry_temp, "%08X", (unsigned int)(IH_fdImageBase+IH_fdEntryPoint));
    SetDlgItemTextA(IH_shared, IDC_EDT_OEP, entry_temp);
    SetAPIBreakPoint((char*)"kernel32.dll", (char*)"OpenMutexA", UE_BREAKPOINT, UE_APISTART, (void*)IH_cbOpenMutexA);
}

void IH_cbDllEntryPoint() //DLL Entry callback
{
    HideDebugger(IH_fdProcessInfo->hProcess, UE_HIDE_BASIC);
    IH_GetImportTableAddresses();
    IH_GetFreeSpaceAddr();
    char entry_temp[10]="";
    sprintf(entry_temp, "%08X", (unsigned int)(IH_fdImageBase+IH_fdEntryPoint));
    SetDlgItemTextA(IH_shared, IDC_EDT_OEP, entry_temp);
    SetAPIBreakPoint((char*)"kernel32.dll", (char*)"VirtualProtect", UE_BREAKPOINT, UE_APISTART, (void*)IH_cbVirtualProtect);
}

DWORD WINAPI IH_DebugThread(LPVOID lpStartAddress) //Thread for debugging
{
    EnableWindow(GetDlgItem(IH_shared, IDC_BTN_INLINE), FALSE);
    EnableWindow(GetDlgItem(IH_shared, IDC_BTN_COPY), FALSE);
    SendDlgItemMessageA(IH_shared, IDC_EDT_OEP, EM_SETREADONLY, 0, 0); //Enable change of OEP...
    DragAcceptFiles(IH_shared, FALSE);
    IH_fdFileIsDll = false;
    IH_fdImageBase = NULL;
    IH_fdEntryPoint = NULL;
    IH_fdProcessInfo = NULL;
    IH_outputdebugcount=0;
    IH_outputdebugcount_total=0;
    IH_bytes_read=0;
    IH_crc_original_vals[0]=0;
    IH_crc_original_vals[1]=0;
    IH_crc_original_vals[2]=0;
    IH_crc_original_vals[3]=0;
    IH_crc_original_vals[4]=0;

    FILE_STATUS_INFO inFileStatus = {0};
    if(IsPE32FileValidEx(IH_szFileName, UE_DEPTH_DEEP, &inFileStatus))
    {
        if(inFileStatus.FileIs64Bit)
        {
            MessageBoxA(IH_shared, "64-bit files are not (yet) supported!", "Error!", MB_ICONERROR);
            return 0;
        }
        HANDLE hFile, fileMap;
        ULONG_PTR va;

        IH_fdImageBase = (long)GetPE32Data(IH_szFileName, NULL, UE_IMAGEBASE);
        IH_fdEntryPoint = (long)GetPE32Data(IH_szFileName, NULL, UE_OEP);
        //fdSizeOfImage = (long)GetPE32Data(szFileName, NULL, UE_SIZEOFIMAGE);
        StaticFileLoad(IH_szFileName, UE_ACCESS_READ, false, &hFile, &IH_bytes_read, &fileMap, &va);
        IH_fdEntrySectionNumber = GetPE32SectionNumberFromVA(va, IH_fdEntryPoint+IH_fdImageBase);
        StaticFileClose(hFile);
        IH_fdEntrySectionSize= (long)GetPE32Data(IH_szFileName, IH_fdEntrySectionNumber, UE_SECTIONVIRTUALSIZE);
        IH_fdEntrySectionOffset = (long)GetPE32Data(IH_szFileName, IH_fdEntrySectionNumber, UE_SECTIONVIRTUALOFFSET);

        IH_fdFileIsDll = inFileStatus.FileIsDLL;
        if(!IH_fdFileIsDll)
        {
            IH_fdProcessInfo = (LPPROCESS_INFORMATION)InitDebugEx(IH_szFileName, NULL, NULL, (void*)IH_cbEntryPoint);
        }
        else
        {
            IH_fdProcessInfo = (LPPROCESS_INFORMATION)InitDLLDebug(IH_szFileName, false, NULL, NULL, (void*)IH_cbDllEntryPoint);
        }

        if(IH_fdProcessInfo)
        {
            DebugLoop();
            EnableWindow(GetDlgItem(IH_shared, IDC_BTN_INLINE), TRUE);
            EnableWindow(GetDlgItem(IH_shared, IDC_BTN_COPY), TRUE);
            DragAcceptFiles(IH_shared, TRUE);
            return 0;
        }
        else
        {
            MessageBoxA(IH_shared, "Something went wrong during initialization...", "Error!", MB_ICONERROR);
            EnableWindow(GetDlgItem(IH_shared, IDC_BTN_INLINE), TRUE);
            EnableWindow(GetDlgItem(IH_shared, IDC_BTN_COPY), TRUE);
            DragAcceptFiles(IH_shared, TRUE);
            return 0;
        }
    }
    else
    {
        MessageBoxA(IH_shared, "This is not a valid PE file...", "Error!", MB_ICONERROR);
    }
    EnableWindow(GetDlgItem(IH_shared, IDC_BTN_INLINE), TRUE);
    EnableWindow(GetDlgItem(IH_shared, IDC_BTN_COPY), TRUE);
    DragAcceptFiles(IH_shared, TRUE);
    return 1;
}
