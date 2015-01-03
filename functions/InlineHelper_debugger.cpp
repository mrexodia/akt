#include "InlineHelper_debugger.h"

/**********************************************************************
 *						Module Variables
 *********************************************************************/
static char* g_szFileName=0;
static IH_InlineHelperData_t* g_PtrTargetData=0;
static cbStd g_EndingCallback;
static cbErrorMessage g_ErrorMessageCallback=0;

static bool g_bFileIsDll;
static LPPROCESS_INFORMATION IH_fdProcessInfo; 		// Process information structure

static long g_fdImageBase=0; 					// Process image base
static long g_fdEntryPoint=0; 					// Process entry
static long g_fdEntrySectionNumber=0; 			// Entry section number
static long g_fdEntrySectionSize=0; 			// Entry section size
static long g_fdEntrySectionOffset=0; 			// Entry section offset

static int g_OutputDebugStringATotalCount=0; 		// Total count of hits on OutputDebugStringA
static int g_OutputDebugStringAMinorCount=0; 		// Counter for correct hits on OutputDebugStringA


/**********************************************************************
 *						Functions
 *********************************************************************/
BYTE IH_FindCrcStart(BYTE* data) //Find the start of the CRC array
{
    for(unsigned int i=0,xorCount=0; i<1024; i+=StaticLengthDisassemble(&data[i]))
    {
        /*
        039BAD0A     8B52 38                        MOV EDX,DWORD PTR DS:[EDX+0x38]
        039BAD0D     3351 24                        XOR EDX,DWORD PTR DS:[ECX+0x24]
        039BAD10     3350 7C                        XOR EDX,DWORD PTR DS:[EAX+0x7C]                                                                                  ; ntdll_1a.77AB96BA
        039BAD13     3355 EC                        XOR EDX,DWORD PTR SS:[EBP-0x14] <- we are looking for this
        039BAD16     3355 E4                        XOR EDX,DWORD PTR SS:[EBP-0x1C]
        039BAD19     8995 04F8FFFF                  MOV DWORD PTR SS:[EBP-0x7FC],EDX
        */
        if(!_strnicmp((const char*)StaticDisassemble(&data[i]), "XOR", 3)) //we found a xor
            xorCount++;
        else
            xorCount=0;
        if(xorCount==3)
            return data[i+2]; //return 0x1C
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
    BYTE* dump_addr;
    unsigned int free_addr;

    dump_addr=(BYTE*)VirtualAlloc(VirtualAlloc(0, g_fdEntrySectionSize, MEM_RESERVE, PAGE_EXECUTE_READWRITE), g_fdEntrySectionSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    ReadProcessMemory(IH_fdProcessInfo->hProcess, (void*)(g_fdEntrySectionOffset+g_fdImageBase), dump_addr, g_fdEntrySectionSize, 0);
    free_addr=IH_FindFreeSpace(dump_addr, (unsigned int)g_fdEntrySectionSize)+g_fdEntrySectionOffset+g_fdImageBase+5;

    g_PtrTargetData->EmptyEntry=free_addr;

    VirtualFree(dump_addr, g_fdEntrySectionSize, MEM_DECOMMIT);
}

void IH_GetImportTableAddresses() //Retrieve basic import data
{
    HINSTANCE kernel32; 						// Handle to kernel32
    unsigned int VirtualProtect_Addr; 			// VirtualProtect Address
    unsigned int OutputDebugStringA_Addr; 		// OutputDebugStringA Address
    unsigned int WriteProcessMemory_Addr; 		// WriteProcessMemory Address
    unsigned int GetEnvironmentVariableA_Addr; 	// GetEnvironmentVariableA Address
    unsigned int SetEnvironmentVariableA_Addr; 	// SetEnvironmentVariableA Address
    unsigned int LoadLibraryA_Addr; 			// LoadLibraryA Address
    unsigned int GetProcAddress_Addr; 			// GetProcAddress address

    DeleteFile("loaded_binary.mem");
    DumpProcess(IH_fdProcessInfo->hProcess, (void*)g_fdImageBase, (char*)"loaded_binary.mem", g_fdEntryPoint);
    kernel32=GetModuleHandleA("kernel32");

    VirtualProtect_Addr=ImporterGetRemoteAPIAddress(IH_fdProcessInfo->hProcess, (unsigned int)GetProcAddress(kernel32, "VirtualProtect"));
    OutputDebugStringA_Addr=ImporterGetRemoteAPIAddress(IH_fdProcessInfo->hProcess, (unsigned int)GetProcAddress(kernel32, "OutputDebugStringA"));
    GetEnvironmentVariableA_Addr=ImporterGetRemoteAPIAddress(IH_fdProcessInfo->hProcess, (unsigned int)GetProcAddress(kernel32, "GetEnvironmentVariableA"));
    SetEnvironmentVariableA_Addr=ImporterGetRemoteAPIAddress(IH_fdProcessInfo->hProcess, (unsigned int)GetProcAddress(kernel32, "SetEnvironmentVariableA"));
    LoadLibraryA_Addr=ImporterGetRemoteAPIAddress(IH_fdProcessInfo->hProcess, (unsigned int)GetProcAddress(kernel32, "LoadLibraryA"));
    GetProcAddress_Addr=ImporterGetRemoteAPIAddress(IH_fdProcessInfo->hProcess, (unsigned int)GetProcAddress(kernel32, "GetProcAddress"));
    WriteProcessMemory_Addr=ImporterGetRemoteAPIAddress(IH_fdProcessInfo->hProcess, (unsigned int)GetProcAddress(kernel32, "WriteProcessMemory"));

    HANDLE hFile=CreateFileA("loaded_binary.mem", GENERIC_ALL, 0, 0, OPEN_EXISTING, 0, 0);
    DWORD high=0,filesize=GetFileSize(hFile, &high);
    BYTE* dump_addr=(BYTE*)VirtualAlloc(VirtualAlloc(0, filesize+0x1000, MEM_RESERVE, PAGE_EXECUTE_READWRITE), filesize+0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    ReadFile(hFile, dump_addr, filesize, &high, 0);
    CloseHandle(hFile);
    unsigned int result_addr=0;

    // Find VirtualProtect address
    result_addr=FindDwordInMemory(dump_addr, VirtualProtect_Addr, filesize);
    if(result_addr)
        VirtualProtect_Addr=(unsigned int)(result_addr+g_fdImageBase);
    else
        VirtualProtect_Addr=0;

    g_PtrTargetData->VirtualProtect_Addr=VirtualProtect_Addr;


    // Find OutputDebugStringA address
    result_addr=FindDwordInMemory(dump_addr, OutputDebugStringA_Addr, filesize);
    if(result_addr)
        OutputDebugStringA_Addr=(unsigned int)(result_addr+g_fdImageBase);
    else
        OutputDebugStringA_Addr=0;

    g_PtrTargetData->OutputDebugStringA_Addr=OutputDebugStringA_Addr;


    // Find GetEnvironmentVariableA address
    result_addr=FindDwordInMemory(dump_addr, GetEnvironmentVariableA_Addr, filesize);
    if(result_addr)
        GetEnvironmentVariableA_Addr=(unsigned int)(result_addr+g_fdImageBase);
    else
        GetEnvironmentVariableA_Addr=0;

    g_PtrTargetData->GetEnvironmentVariableA_Addr=GetEnvironmentVariableA_Addr;


    // Find SetEnvironmentVariableA address
    result_addr=FindDwordInMemory(dump_addr, SetEnvironmentVariableA_Addr, filesize);
    if(result_addr)
        SetEnvironmentVariableA_Addr=(unsigned int)(result_addr+g_fdImageBase);
    else
        SetEnvironmentVariableA_Addr=0;

    g_PtrTargetData->SetEnvironmentVariableA_Addr=SetEnvironmentVariableA_Addr;


    // Find LoadLibraryA address
    result_addr=FindDwordInMemory(dump_addr, LoadLibraryA_Addr, filesize);
    if(result_addr)
        LoadLibraryA_Addr=(unsigned int)(result_addr+g_fdImageBase);
    else
        LoadLibraryA_Addr=0;

    g_PtrTargetData->LoadLibraryA_Addr=LoadLibraryA_Addr;


    // Find GetProcAddress address
    result_addr=FindDwordInMemory(dump_addr, GetProcAddress_Addr, filesize);
    if(result_addr)
        GetProcAddress_Addr=(unsigned int)(result_addr+g_fdImageBase);
    else
        GetProcAddress_Addr=0;

    g_PtrTargetData->GetProcAddress_Addr=GetProcAddress_Addr;


    // Find WriteProcessMemory address
    result_addr=FindDwordInMemory(dump_addr, WriteProcessMemory_Addr, filesize);
    if(result_addr)
        WriteProcessMemory_Addr=(unsigned int)(result_addr+g_fdImageBase);
    else
        WriteProcessMemory_Addr=0;

    g_PtrTargetData->WriteProcessMemory_Addr=WriteProcessMemory_Addr;

    // Free the memory and close the handle
    VirtualFree(dump_addr, filesize+0x1000, MEM_DECOMMIT);
}


void IH_cbOutputDebugStringA() //Callback for OutputDebugStringA
{
    // Increment total counter
    g_OutputDebugStringATotalCount++;

    // Check if we landed on the correct place.
    char debug_string[256]="";
    unsigned int esp_addr=(long)GetContextData(UE_ESP), string_addr;
    ReadProcessMemory(IH_fdProcessInfo->hProcess, (void*)(esp_addr+4), &string_addr, 4, 0);
    ReadProcessMemory(IH_fdProcessInfo->hProcess, (void*)string_addr, &debug_string, 255, 0);
    if(debug_string[16]=='%' and debug_string[17]=='s')
        g_OutputDebugStringAMinorCount++;

    ///The second call to OutputDebugString("%s%s%s%s%s%s%s%s%s%...s%s%s%s%s%s%s"); is the call we need.
    if(g_OutputDebugStringAMinorCount==2)
    {
        // Declare some variables
        unsigned int originalCRCVals[5]= {0}; // Original CRC values array
        int CRCBase=0; 						// Stack difference for retrieving the CRC values
        unsigned int ebp_addr=GetContextData(UE_EBP),esp_addr=GetContextData(UE_ESP),bp_addr=0;
        BYTE search_bytes[1024]= {0xFF};

        g_OutputDebugStringAMinorCount=0;

        // Read the executable code to obtain the CRC base
        ReadProcessMemory(IH_fdProcessInfo->hProcess, (void*)esp_addr, &bp_addr, 4, 0); ///Get the return address.
        ReadProcessMemory(IH_fdProcessInfo->hProcess, (void*)bp_addr, search_bytes, 1024, 0); ///Read the actual disassembly.
        CRCBase=0x100-IH_FindCrcStart(search_bytes); ///Use a pattern to find the CRC base and NEG this base.

        unsigned int crc_check_call=FindEB6APattern(search_bytes, 1024);
        bool arma960=false;
        unsigned int push_addr=0;
        if(crc_check_call) //Old versions will not have special stuff
        {
            unsigned int final_call=FindCallPattern(search_bytes+crc_check_call, 1024-crc_check_call);
            if(final_call)
            {
                final_call+=crc_check_call;
                push_addr=Find960Pattern(search_bytes+crc_check_call, 1024-crc_check_call);
                if(push_addr and push_addr<final_call)
                    arma960=true;
                push_addr+=crc_check_call+2;
            }
        }
        if(!CRCBase)
        {
            g_ErrorMessageCallback((char*)"There was an error! please contact me, I can fix it", (char*)"Error!");
            //TerminateProcess(IH_fdProcessInfo->hProcess, 0);
            //DetachDebugger(IH_fdProcessInfo->dwProcessId);
            StopDebug();
            return;
        }

        ///Read the CRC values from the variable stack.
        originalCRCVals[0]=0;
        originalCRCVals[1]=0;
        originalCRCVals[2]=0;
        originalCRCVals[3]=0;
        originalCRCVals[4]=0;

        ReadProcessMemory(IH_fdProcessInfo->hProcess, (void*)(ebp_addr-CRCBase), &originalCRCVals[0], 4, 0);
        if(!arma960)
        {
            ReadProcessMemory(IH_fdProcessInfo->hProcess, (void*)(ebp_addr-CRCBase-8), &originalCRCVals[1], 4, 0);
            ReadProcessMemory(IH_fdProcessInfo->hProcess, (void*)(ebp_addr-CRCBase-12), &originalCRCVals[2], 4, 0);
            ReadProcessMemory(IH_fdProcessInfo->hProcess, (void*)(ebp_addr-CRCBase-16), &originalCRCVals[3], 4, 0);
            ReadProcessMemory(IH_fdProcessInfo->hProcess, (void*)(ebp_addr-CRCBase-20), &originalCRCVals[4], 4, 0);
        }
        else
        {
            unsigned int crc_read_addr=0;
            memcpy(&crc_read_addr, search_bytes+push_addr, 4);
            ReadProcessMemory(IH_fdProcessInfo->hProcess, (void*)crc_read_addr, &originalCRCVals[1], 16, 0);
        }

        // Fill CRCs
        g_PtrTargetData->CRCBase=CRCBase;

        g_PtrTargetData->CrcOriginalVals[0]=originalCRCVals[0];
        g_PtrTargetData->CrcOriginalVals[1]=originalCRCVals[1];
        g_PtrTargetData->CrcOriginalVals[2]=originalCRCVals[2];
        g_PtrTargetData->CrcOriginalVals[3]=originalCRCVals[3];
        g_PtrTargetData->CrcOriginalVals[4]=originalCRCVals[4];

        g_PtrTargetData->OutputDebugCount=g_OutputDebugStringATotalCount;


        // Arma960 support
        g_PtrTargetData->Arma960=arma960;
        g_PtrTargetData->Arma960_add=push_addr;

        ///Termintate the process and detach the debugger.
        //TerminateProcess(IH_fdProcessInfo->hProcess, 0);
        //DetachDebugger(IH_fdProcessInfo->dwProcessId);
        StopDebug();

        // Call ending callback
        g_EndingCallback();
    }
}

void IH_cbVirtualProtect() // Callback for VirtualProtect
{
    unsigned int security_addr=0,esp_addr=0,code_size=0;
    esp_addr=(unsigned int)GetContextData(UE_ESP);
    ReadProcessMemory(IH_fdProcessInfo->hProcess, (const void*)(esp_addr+4), &security_addr, 4, 0);
    ReadProcessMemory(IH_fdProcessInfo->hProcess, (const void*)(esp_addr+8), &code_size, 4, 0);

    BYTE* header_code=(BYTE*)malloc2(0x1000);
    ReadProcessMemory(IH_fdProcessInfo->hProcess, (void*)(security_addr-0x1000), header_code, 0x1000, 0);
    if(*(unsigned short*)header_code != 0x5A4D) //not a PE file
    {
        free2(header_code);
        return;
    }
    free2(header_code);

    char szSecurityAddrRegister[4]=""; //Register that contains a pointer to security.dll

    DeleteAPIBreakPoint((char*)"kernel32.dll", (char*)"VirtualProtect", UE_APISTART);
    SetAPIBreakPoint((char*)"kernel32.dll", (char*)"OutputDebugStringA", UE_BREAKPOINT, UE_APISTART, (void*)IH_cbOutputDebugStringA);

    DumpMemory(IH_fdProcessInfo->hProcess, (void*)security_addr, code_size, (char*)"security_code.mem");

    if(GetContextData(UE_EAX)==security_addr)
        strcpy(szSecurityAddrRegister, "EAX");

    else if(GetContextData(UE_ECX)==security_addr)
        strcpy(szSecurityAddrRegister, "ECX");

    else if(GetContextData(UE_EDX)==security_addr)
        strcpy(szSecurityAddrRegister, "EDX");

    else if(GetContextData(UE_EBX)==security_addr)
        strcpy(szSecurityAddrRegister, "EBX");

    else if(GetContextData(UE_ESI)==security_addr)
        strcpy(szSecurityAddrRegister, "ESI");

    else if(GetContextData(UE_EDI)==security_addr)
        strcpy(szSecurityAddrRegister, "EDI");

    else
    {
        g_ErrorMessageCallback((char*)"There was an error recovering the correct register.\n\nThe program will quit now!", (char*)"Error!");
        ExitProcess(1);
    }

    g_PtrTargetData->CodeSize=code_size;

    strcpy(g_PtrTargetData->SecurityAddrRegister, szSecurityAddrRegister);
}

void IH_cbOpenMutexA() //Callback for OpenMutexA
{
    char mutex_name[20]="";
    long mutex_addr=0;
    long esp_addr=0;
    DeleteAPIBreakPoint((char*)"kernel32.dll", (char*)"OpenMutexA", UE_APISTART);
    esp_addr=(long)GetContextData(UE_ESP)+12;
    ReadProcessMemory(IH_fdProcessInfo->hProcess, (const void*)esp_addr, &mutex_addr, 4, 0);
    ReadProcessMemory(IH_fdProcessInfo->hProcess, (const void*)mutex_addr, &mutex_name, 20, 0);
    CreateMutexA(0, FALSE, mutex_name);
    if(GetLastError()==ERROR_SUCCESS)
    {
        SetAPIBreakPoint((char*)"kernel32.dll", (char*)"VirtualProtect", UE_BREAKPOINT, UE_APISTART, (void*)IH_cbVirtualProtect);
    }
    else
    {
        char log_message[50]="";
        wsprintfA(log_message, "Failed to create mutex %s", mutex_name);
        g_ErrorMessageCallback((char*)log_message, (char*)"Error!");
    }
}


void IH_cbEntryPoint() //Entry callback
{
    g_fdImageBase=GetDebuggedFileBaseAddress();
    g_PtrTargetData->ImageBase=g_fdImageBase;

    g_PtrTargetData->OEP=(unsigned int)(g_fdImageBase+g_fdEntryPoint);

    // Retrieve useful data from IAT
    IH_GetImportTableAddresses();

    // Search free space
    IH_GetFreeSpaceAddr();

    SetAPIBreakPoint((char*)"kernel32.dll", (char*)"OpenMutexA", UE_BREAKPOINT, UE_APISTART, (void*)IH_cbOpenMutexA);
}


void IH_cbDllEntryPoint() //DLL Entry callback
{
    g_fdImageBase=GetDebuggedDLLBaseAddress();
    g_PtrTargetData->ImageBase=g_fdImageBase;
    g_PtrTargetData->OEP=(unsigned int)(g_fdImageBase+g_fdEntryPoint);

    // Retrieve useful data from IAT
    IH_GetImportTableAddresses();

    // Search free space
    IH_GetFreeSpaceAddr();

    SetAPIBreakPoint((char*)"kernel32.dll", (char*)"VirtualProtect", UE_BREAKPOINT, UE_APISTART, (void*)IH_cbVirtualProtect);
}


DWORD WINAPI IH_DebugThread(LPVOID lpStartAddress) //Thread for debugging
{
    g_bFileIsDll=false;
    g_fdImageBase=0;
    g_fdEntryPoint=0;
    IH_fdProcessInfo=0;

    g_OutputDebugStringATotalCount=0;
    g_OutputDebugStringAMinorCount=0;



    DWORD IH_bytes_read=0;


    FILE_STATUS_INFO inFileStatus= {0};
    IsPE32FileValidEx(g_szFileName, UE_DEPTH_SURFACE, &inFileStatus);
    if(inFileStatus.FileIs64Bit)
    {
        g_ErrorMessageCallback((char*)"64-bit files are not (yet) supported!", (char*)"Error!");
        return 0;
    }
    HANDLE hFile, fileMap;
    ULONG_PTR va;

    //g_fdImageBase=(long)GetPE32Data(g_szFileName, 0, UE_IMAGEBASE);
    //g_PtrTargetData->ImageBase=g_fdImageBase;

    g_fdEntryPoint=(long)GetPE32Data(g_szFileName, 0, UE_OEP);

    StaticFileLoad(g_szFileName, UE_ACCESS_READ, false, &hFile, &IH_bytes_read, &fileMap, &va);

    g_fdEntrySectionNumber=GetPE32SectionNumberFromVA(va, g_fdEntryPoint+GetPE32Data(g_szFileName, 0, UE_IMAGEBASE));
    g_PtrTargetData->EntrySectionNumber=g_fdEntrySectionNumber;

    StaticFileClose(hFile);
    g_fdEntrySectionSize= (long)GetPE32Data(g_szFileName, g_fdEntrySectionNumber, UE_SECTIONVIRTUALSIZE);
    g_fdEntrySectionOffset=(long)GetPE32Data(g_szFileName, g_fdEntrySectionNumber, UE_SECTIONVIRTUALOFFSET);

    g_bFileIsDll=inFileStatus.FileIsDLL;


    if(g_bFileIsDll==false)
    {
        IH_fdProcessInfo=(LPPROCESS_INFORMATION)InitDebugEx(g_szFileName, 0, 0, (void*)IH_cbEntryPoint);
    }
    else
    {
        IH_fdProcessInfo=(LPPROCESS_INFORMATION)InitDLLDebug(g_szFileName, false, 0, 0, (void*)IH_cbDllEntryPoint);
    }

    if(IH_fdProcessInfo)
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


bool IH_Debugger(char* szFileName, IH_InlineHelperData_t* ptrTargetData, cbStd EndingCallback, cbErrorMessage ErrorMessageCallback)
{
    FILE_STATUS_INFO fileStatus= {0};
    bool bFileIsDll;

    g_EndingCallback=EndingCallback;
    g_ErrorMessageCallback=ErrorMessageCallback;
    g_szFileName=szFileName;
    g_PtrTargetData=ptrTargetData;

    memset(g_PtrTargetData, 0, sizeof(IH_InlineHelperData_t));

    IsPE32FileValidEx(szFileName, UE_DEPTH_SURFACE, &fileStatus);
    bFileIsDll=fileStatus.FileIsDLL;
    CreateThread(0, 0, IH_DebugThread, 0, 0, 0);
    return bFileIsDll;
}












