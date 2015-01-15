#include "CertTool_debugger.h"

//Superglobal
bool CT_isdebugging = false; //Is retrieving cert info?

//global
unsigned int encrypted_cert_real_size = 0; //size of the current piece
unsigned int end_big_loop = 0; //end of the certificate loop
unsigned int magic_value_addr = 0; //address of the magic values place
unsigned int magic_ebp_sub = 0; //ebp difference to retrieve the magic from
unsigned int magic_byte = 0; //address of the compare of the crc byte
unsigned int noteax = 0; //address of the sym check place (not [reg])
unsigned int salt_func_addr = 0; //Address of the salt function
unsigned int salt_register = 0; //Register to retrieve salt from
unsigned int tea_decrypt = 0; //address of the tea decrypt function

int cert_func_count = 0; //Counter of passes on the NextDword function
int return_counter = 0; //arma9.6
int other_seed_counter = 0; //arma9.6

unsigned short cmp_data = 0; //cmp [reg],[reg] bytes for disassembly

unsigned char magic_byte_cert = 0; //correct crc byte
unsigned char* encrypted_cert_real = 0; //certificate container byte parts

bool fdFileIsDll = false; //Debugged is dll?
bool patched_magic_jump = false; //bool to ensure we can retrieve all certificates (dynamically)

LPPROCESS_INFORMATION fdProcessInfo = 0; //process info
UINT register_magic_byte = 0; //register (titsEngine form) to retrieve the current byte from
BYTE salt_code[61] = {0}; //Bytes of the salt code (for disassembly)

void CT_cbGetSalt()
{
    CT_cert_data->salt = GetContextData(salt_register);
    StopDebug();
}

void CT_RetrieveSaltValue()
{
    if(!salt_func_addr)
    {
        StopDebug();
        return;
    }
    DISASM MyDisasm = {0};
    MyDisasm.EIP = (UIntPtr)salt_code;
    int len = 0;
    int xor_count = 0;
    for(;;)
    {
        len = Disasm(&MyDisasm);
        if(len == UNKNOWN_OPCODE)
            break;
        if(MyDisasm.EIP != (UIntPtr)salt_code and MyDisasm.Instruction.Mnemonic[0] == 'x' and MyDisasm.Instruction.Mnemonic[1] == 'o' and MyDisasm.Instruction.Mnemonic[2] == 'r')
            xor_count++;
        if(xor_count == 3)
            break;
        MyDisasm.EIP += len;
        if(MyDisasm.EIP >= (unsigned int)salt_code + 60)
            break;
    }
    if(xor_count != 3)
    {
        StopDebug();
        return;
    }
    salt_register = DetermineRegisterFromText(MyDisasm.Argument1.ArgMnemonic);
    unsigned int salt_breakpoint = MyDisasm.EIP - ((unsigned int)salt_code) + salt_func_addr + len;
    if(!salt_register)
    {
        StopDebug();
        return;
    }
    SetContextData(UE_EIP, salt_func_addr);
    SetBPX(salt_breakpoint, UE_BREAKPOINT, (void*)CT_cbGetSalt);
}

void CT_cbEndBigLoop()
{
    DeleteBPX(end_big_loop);
    DeleteBPX(tea_decrypt);
    DeleteBPX(magic_byte);
    encrypted_cert_real_size += 4;
    unsigned char* final_data = (unsigned char*)malloc2(encrypted_cert_real_size);
    memset(final_data, 0, encrypted_cert_real_size);
    memcpy(final_data, encrypted_cert_real, encrypted_cert_real_size - 4);
    free2(encrypted_cert_real);
    CT_cert_data->encrypted_data = final_data;
    CT_cert_data->encrypted_size = encrypted_cert_real_size;
    encrypted_cert_real_size = 0;
    CT_RetrieveSaltValue();
}

void CT_cbTeaDecrypt()
{
    unsigned int esp = GetContextData(UE_ESP);
    unsigned int values[2] = {0};
    if(!ReadProcessMemory(fdProcessInfo->hProcess, (void*)(esp + 4), &values, 8, 0))
    {
        CT_FatalError(rpmerror());
        return;
    }
    unsigned char first_5_bytes[5] = "";
    memcpy(first_5_bytes, &values[1], 4);
    first_5_bytes[4] = magic_byte_cert;
    unsigned char* new_data = (unsigned char*)malloc2(values[1]);
    if(!ReadProcessMemory(fdProcessInfo->hProcess, (void*)values[0], new_data, values[1], 0))
    {
        CT_FatalError(rpmerror());
        return;
    }
    unsigned char* temp = (unsigned char*)malloc2(encrypted_cert_real_size + values[1] + 5);
    if(encrypted_cert_real)
    {
        memcpy(temp, encrypted_cert_real, encrypted_cert_real_size);
        free2(encrypted_cert_real);
    }
    encrypted_cert_real = temp;
    memcpy(encrypted_cert_real + encrypted_cert_real_size, first_5_bytes, 5);
    memcpy(encrypted_cert_real + encrypted_cert_real_size + 5, new_data, values[1]);
    free2(new_data);
    encrypted_cert_real_size += values[1] + 5;
}

void CT_cbMagicJump()
{
    if(!patched_magic_jump)
    {
        BYTE eb[2] = {0xEB, 0x90};
        WriteProcessMemory(fdProcessInfo->hProcess, (void*)(magic_byte + 2), &eb, 1, 0); //patch JNZ->JMP
        eb[0] = 0x90;
        WriteProcessMemory(fdProcessInfo->hProcess, (void*)noteax, &eb, 2, 0);
        SetBPX(tea_decrypt, UE_BREAKPOINT, (void*)CT_cbTeaDecrypt);
        SetBPX(end_big_loop, UE_BREAKPOINT, (void*)CT_cbEndBigLoop);
        DISASM MyDisasm = {0};
        MyDisasm.EIP = (UIntPtr)&cmp_data;
        Disasm(&MyDisasm);
        char register_retrieve[10] = "";
        strncpy(register_retrieve, MyDisasm.Argument2.ArgMnemonic, 3);
        patched_magic_jump = true;
        register_magic_byte = DetermineRegisterFromText(register_retrieve);
    }
    magic_byte_cert = (unsigned char)GetContextData(register_magic_byte);
}

void CT_cbMagicValue()
{
    DeleteHardwareBreakPoint(UE_DR1);
    unsigned int retrieve_addr = GetContextData(UE_EBP) - magic_ebp_sub - 4;
    unsigned int magic_values[2] = {0};
    if(!ReadProcessMemory(fdProcessInfo->hProcess, (void*)retrieve_addr, magic_values, 8, 0))
    {
        CT_FatalError(rpmerror());
        return;
    }
    CT_cert_data->magic1 = magic_values[0];
    CT_cert_data->magic2 = magic_values[1];
    if(end_big_loop)
        SetBPX(magic_byte, UE_BREAKPOINT, (void*)CT_cbMagicJump);
    else
        CT_RetrieveSaltValue();
}

//Arma v9.60 and higher (probably)
UINT CT_DetermineRegisterFromByte(unsigned char byte)
{
    switch(byte)
    {
    case 0x45:
        return UE_EAX;
    case 0x4D:
        return UE_ECX;
    case 0x55:
        return UE_EDX;
    case 0x5D:
        return UE_EBX;
    case 0x65:
        return UE_ESP;
    case 0x6D:
        return UE_EBP;
    case 0x75:
        return UE_ESI;
    case 0x7D:
        return UE_EDI;
    }
    return 0;
}

void CT_SortArray(unsigned int* a, int size)
{
    unsigned int* cpy = (unsigned int*)malloc2(size * 4);
    memcpy(cpy, a, size * 4);
    unsigned int* biggest = &cpy[0];
    for(int i = 0; i < size; i++)
    {
        for(int j = 0; j < size; j++)
        {
            if(cpy[j] > *biggest)
                biggest = &cpy[j];
        }
        a[size - i - 1] = *biggest;
        *biggest = 0;
    }
}

void CT_cbGetOtherSeed()
{
    unsigned int eip = GetContextData(UE_EIP);
    DeleteBPX(eip);
    unsigned char reg_byte = 0;
    if(!ReadProcessMemory(fdProcessInfo->hProcess, (void*)(eip + 1), &reg_byte, 1, 0))
    {
        CT_FatalError(rpmerror());
        return;
    }
    CT_cert_data->decrypt_addvals[other_seed_counter] = GetContextData(CT_DetermineRegisterFromByte(reg_byte));
    other_seed_counter++;
    if(other_seed_counter == 4)
    {
        other_seed_counter = 0;
        if(!magic_value_addr)
            CT_RetrieveSaltValue();
    }
}

void CT_cbOtherSeeds()
{
    puts("cbOtherSeeds");
    unsigned int eip = GetContextData(UE_EIP);
    unsigned char* eip_data = (unsigned char*)malloc2(0x10000);
    if(!ReadProcessMemory(fdProcessInfo->hProcess, (void*)eip, eip_data, 0x10000, 0))
    {
        CT_FatalError(rpmerror());
        return;
    }
    unsigned int stdcall = CT_FindStdcallPattern(eip_data, 0x10000);
    if(!stdcall)
    {
        stdcall = CT_FindCall2Pattern(eip_data, 0x10000);
        if(!stdcall)
        {
            CT_FatalError("Could not find call pattern...");
            return;
        }
    }
    eip_data += stdcall;
    unsigned int size = 0x10000 - stdcall;
    unsigned int retn = size = CT_FindReturnPattern(eip_data, size);
    if(!retn)
    {
        CT_FatalError("Could not find RET");
        return;
    }

    unsigned int and_addrs[4] = {0};

    for(int i = 0; i < 4; i++)
    {
        and_addrs[i] = CT_FindAndPattern2(eip_data, size);
        if(!and_addrs[i])
            and_addrs[i] = CT_FindAndPattern1(eip_data, size);
        if(!and_addrs[i])
        {
            CT_FatalError("Could not find AND [REG],[VAL]");
            return;
        }
        size -= and_addrs[i];
        eip_data += and_addrs[i];
        if(i)
            and_addrs[i] += and_addrs[i - 1];
    }
    CT_SortArray(and_addrs, 4);

    other_seed_counter = 0;
    for(int i = 0; i < 4; i++)
        SetBPX(and_addrs[i] + eip + stdcall, UE_BREAKPOINT, (void*)CT_cbGetOtherSeed);

    free2(eip_data);
}

void CT_cbReturnSeed1()
{
    DeleteBPX(GetContextData(UE_EIP));
    unsigned int esp = GetContextData(UE_ESP);
    unsigned int _stack = 0;
    if(!ReadProcessMemory(fdProcessInfo->hProcess, (void*)esp, &_stack, 4, 0))
    {
        CT_FatalError(rpmerror());
        return;
    }
    return_counter++;
    if(return_counter != 2)
    {
        unsigned char* return_bytes = (unsigned char*)malloc2(0x1000);
        if(!ReadProcessMemory(fdProcessInfo->hProcess, (void*)_stack, return_bytes, 0x1000, 0))
        {
            CT_FatalError(rpmerror());
            return;
        }
        unsigned int retn = CT_FindReturnPattern(return_bytes, 0x1000);
        free2(return_bytes);
        if(!retn)
        {
            CT_FatalError("Could not find return");
            return;
        }
        SetBPX(retn + _stack, UE_BREAKPOINT, (void*)CT_cbReturnSeed1);
    }
    else
    {
        SetContextData(UE_ESP, GetContextData(UE_ESP) + 4);
        SetContextData(UE_EIP, _stack);
        CT_cbOtherSeeds();
    }
}

void CT_cbSeed1()
{
    DeleteBPX(GetContextData(UE_EIP));
    unsigned int ecx = GetContextData(UE_ECX);
    if(!ReadProcessMemory(fdProcessInfo->hProcess, (void*)ecx, &(CT_cert_data->decrypt_seed[0]), 4, 0))
    {
        CT_FatalError(rpmerror());
        return;
    }
}

void CT_cbCertificateFunction()
{
    if(!cert_func_count)
        cert_func_count++;
    else if(cert_func_count == 1)
    {
        DeleteBPX(GetContextData(UE_EIP));
        long retn_eax = GetContextData(UE_EAX);
        MEMORY_BASIC_INFORMATION mbi = {0};
        unsigned int mem_size = 0x10000;
        if(VirtualQueryEx(fdProcessInfo->hProcess, (void*)retn_eax, &mbi, sizeof(MEMORY_BASIC_INFORMATION)))
            mem_size = mbi.RegionSize - (retn_eax - (unsigned int)mbi.BaseAddress);
        BYTE* certificate_code = (BYTE*)malloc2(mem_size);
        if(!ReadProcessMemory(fdProcessInfo->hProcess, (void*)retn_eax, certificate_code, mem_size, 0))
        {
            free2(certificate_code);
            CT_FatalError("Failed to read process memory...");
        }
        //Arma 9.60 support
        puts("errorfuck");
        unsigned int esp = GetContextData(UE_ESP);
        unsigned int _stack = 0;
        if(!ReadProcessMemory(fdProcessInfo->hProcess, (void*)esp, &_stack, 4, 0))
        {
            CT_FatalError(rpmerror());
            return;
        }
        unsigned char* return_bytes = (unsigned char*)malloc2(0x1000);
        if(!ReadProcessMemory(fdProcessInfo->hProcess, (void*)_stack, return_bytes, 0x1000, 0))
        {
            CT_FatalError(rpmerror());
            return;
        }
        unsigned int push100 = CT_FindPush100Pattern(return_bytes, 0x1000);
        unsigned int retn = CT_FindReturnPattern(return_bytes, 0x1000);
        if(!retn)
            CT_FindReturnPattern2(return_bytes, 0x1000);
        if(push100 and push100 < retn)
        {
            unsigned int call = CT_FindCall1Pattern(return_bytes + push100, 0x1000 - push100);
            if(!call)
                call = CT_FindCall2Pattern(return_bytes + push100, 0x1000 - push100);
            if(!call)
            {
                if(MessageBoxA(CT_shared, "Could not find call, continue?", "Continue?", MB_ICONERROR | MB_YESNO) == IDYES)
                    if(!magic_value_addr)
                        CT_RetrieveSaltValue();
            }
            else
            {
                SetBPX(_stack + call + push100, UE_BREAKPOINT, (void*)CT_cbSeed1);
                return_counter = 0;
                SetBPX(_stack + retn, UE_BREAKPOINT, (void*)CT_cbReturnSeed1);
            }
            CT_cert_data->raw_size = mem_size;
            CT_cert_data->raw_data = (unsigned char*)malloc2(mem_size);
            memcpy(CT_cert_data->raw_data, certificate_code, mem_size);
        }
        else
        {
            free2(return_bytes);
            //Get raw certificate data
            unsigned int cert_start = CT_FindCertificateMarkers(certificate_code, mem_size);
            if(!cert_start)
                cert_start = CT_FindCertificateMarkers2(certificate_code, mem_size);
            if(!cert_start)
            {
                free2(certificate_code);
                if(MessageBoxA(CT_shared, "Could not find start markers, continue?", "Continue?", MB_ICONERROR | MB_YESNO) == IDYES)
                {
                    if(!magic_value_addr)
                        CT_RetrieveSaltValue();
                }
                else
                    StopDebug();
                return;
            }
            CT_cert_data->raw_size = mem_size;
            CT_cert_data->raw_data = (unsigned char*)malloc2(mem_size);
            memcpy(CT_cert_data->raw_data, certificate_code, mem_size);

            if(!magic_value_addr)
                CT_RetrieveSaltValue();
        }
    }
    else
        DeleteBPX(GetContextData(UE_EIP));
}

void CT_cbVirtualProtect()
{
    long esp_addr = GetContextData(UE_ESP);
    unsigned int security_code_base = 0, security_code_size = 0;
    if(!ReadProcessMemory(fdProcessInfo->hProcess, (void*)(esp_addr + 4), &security_code_base, 4, 0))
    {
        CT_FatalError(rpmerror());
        return;
    }
    if(!ReadProcessMemory(fdProcessInfo->hProcess, (void*)(esp_addr + 8), &security_code_size, 4, 0))
    {
        CT_FatalError(rpmerror());
        return;
    }
    BYTE* security_code = (BYTE*)malloc2(security_code_size);
    BYTE* header_code = (BYTE*)malloc2(0x1000);
    if(!ReadProcessMemory(fdProcessInfo->hProcess, (void*)security_code_base, security_code, security_code_size, 0))
    {
        CT_FatalError(rpmerror());
        return;
    }
    if(!ReadProcessMemory(fdProcessInfo->hProcess, (void*)(security_code_base - 0x1000), header_code, 0x1000, 0))
    {
        CT_FatalError(rpmerror());
        return;
    }
    if(*(unsigned short*)header_code != 0x5A4D) //not a PE file
    {
        free2(header_code);
        return;
    }
    DeleteAPIBreakPoint((char*)"kernel32.dll", (char*)"VirtualProtect", UE_APISTART);
    IMAGE_DOS_HEADER* pdh = (IMAGE_DOS_HEADER*)((DWORD)header_code);
    IMAGE_NT_HEADERS* pnth = (IMAGE_NT_HEADERS*)((DWORD)header_code + pdh->e_lfanew);
    CT_cert_data->timestamp = pnth->FileHeader.TimeDateStamp;
    free2(header_code);

    //Certificate data
    unsigned int breakpoint_addr = CT_FindCertificateFunctionNew(security_code, security_code_size);
    if(!breakpoint_addr)
        breakpoint_addr = CT_FindCertificateFunctionOld(security_code, security_code_size);
    if(!breakpoint_addr)
    {
        CT_FatalError("Could not find NextDword...");
        return;
    }
    SetBPX((security_code_base + breakpoint_addr), UE_BREAKPOINT, (void*)CT_cbCertificateFunction);

    //Magic
    magic_value_addr = CT_FindMagicPattern(security_code, security_code_size, &magic_ebp_sub);
    if(magic_value_addr)
        SetHardwareBreakPoint((security_code_base + magic_value_addr), UE_DR1, UE_HARDWARE_EXECUTE, UE_HARDWARE_SIZE_1, (void*)CT_cbMagicValue);

    //Magic MD5=0
    if(magic_value_addr)
    {
        unsigned int end_search = CT_FindEndInitSymVerifyPattern(security_code + magic_value_addr, security_code_size - magic_value_addr);
        unsigned int md5_move = CT_FindPubMd5MovePattern(security_code + magic_value_addr, security_code_size - magic_value_addr);
        if(end_search and md5_move and md5_move > end_search) //Arma with MD5=0 in SymVerify
            CT_cert_data->zero_md5_symverify = true;
    }
    else if(CT_cert_data->timestamp < 0x49000000) //~v6 (before sometimes it failed)
        CT_cert_data->zero_md5_symverify = true;

    //Encrypted cert data
    unsigned int push400 = CT_FindDecryptKey1Pattern(security_code, security_code_size);
    if(push400)
    {
        magic_byte = CT_FindMagicJumpPattern(security_code + push400, security_code_size - push400, &cmp_data);
        if(magic_byte)
        {
            magic_byte += push400;
            unsigned int pushff = CT_FindPushFFPattern(security_code + magic_byte, security_code_size - magic_byte);
            if(pushff)
            {
                pushff += magic_byte;
                tea_decrypt = CT_FindTeaDecryptPattern(security_code + pushff, security_code_size - magic_byte);
                if(tea_decrypt)
                {
                    tea_decrypt += pushff;
                    noteax = CT_FindVerifySymPattern(security_code + tea_decrypt, security_code_size - tea_decrypt);
                    if(noteax)
                    {
                        noteax += tea_decrypt;
                        end_big_loop = CT_FindReturnPattern(security_code + noteax, security_code_size - noteax);
                        //end_big_loop=CT_FindEndLoopPattern(security_code+noteax, security_code_size-noteax);
                        if(end_big_loop)
                        {
                            end_big_loop += noteax + security_code_base;
                            noteax += security_code_base;
                            tea_decrypt += security_code_base;
                            magic_byte += security_code_base;
                        }
                    }
                }
            }
        }
    }

    if(CT_FindECDSAVerify(security_code, security_code_size))
        CT_cert_data->checksumv8 = true;
    if(CT_cert_data->timestamp > 0x4C100000) //v7.40 (just before)
    {
        //Salt
        salt_func_addr = FindSalt1Pattern(security_code, security_code_size); //v9.60
        if(!salt_func_addr)
            salt_func_addr = FindSalt2Pattern(security_code, security_code_size);
        if(salt_func_addr)
        {
            memcpy(salt_code, (void*)(salt_func_addr + security_code), 60);
            salt_func_addr += (unsigned int)security_code_base;
        }
    }
    free2(security_code);
}

void CT_cbOpenMutexA()
{
    char mutex_name[20] = "";
    long mutex_addr = 0;
    long esp_addr = 0;
    unsigned int return_addr = 0;
    DeleteAPIBreakPoint((char*)"kernel32.dll", (char*)"OpenMutexA", UE_APISTART);
    esp_addr = (long)GetContextData(UE_ESP);
    if(!ReadProcessMemory(fdProcessInfo->hProcess, (const void*)esp_addr, &return_addr, 4, 0))
    {
        CT_FatalError(rpmerror());
        return;
    }
    if(!ReadProcessMemory(fdProcessInfo->hProcess, (const void*)(esp_addr + 12), &mutex_addr, 4, 0))
    {
        CT_FatalError(rpmerror());
        return;
    }
    if(!ReadProcessMemory(fdProcessInfo->hProcess, (const void*)mutex_addr, &mutex_name, 20, 0))
    {
        CT_FatalError(rpmerror());
        return;
    }
    CreateMutexA(0, FALSE, mutex_name);
    if(GetLastError() == ERROR_SUCCESS)
        SetAPIBreakPoint((char*)"kernel32.dll", (char*)"VirtualProtect", UE_BREAKPOINT, UE_APISTART, (void*)CT_cbVirtualProtect);
    else
    {
        char log_message[256] = "";
        sprintf(log_message, "[Fail] Failed to create mutex %s", mutex_name);
        CT_FatalError(log_message);
    }
}

void CT_cbEntry()
{
    FixIsDebuggerPresent(fdProcessInfo->hProcess, true);
    if(!fdFileIsDll)
        SetAPIBreakPoint((char*)"kernel32.dll", (char*)"OpenMutexA", UE_BREAKPOINT, UE_APISTART, (void*)CT_cbOpenMutexA);
    else
        SetAPIBreakPoint((char*)"kernel32.dll", (char*)"VirtualProtect", UE_BREAKPOINT, UE_APISTART, (void*)CT_cbVirtualProtect);
}

DWORD WINAPI CT_FindCertificates(void* lpvoid)
{
    CT_created_log = false;
    CT_isdebugging = true;
    patched_magic_jump = false;
    fdProcessInfo = 0;
    magic_value_addr = 0;
    encrypted_cert_real = 0;
    encrypted_cert_real_size = 0;
    cert_func_count = 0;

    if(CT_cert_data)
    {
        if(CT_cert_data->projectid)
            free2(CT_cert_data->projectid);
        if(CT_cert_data->customer_service)
            free2(CT_cert_data->customer_service);
        if(CT_cert_data->website)
            free2(CT_cert_data->website);
        if(CT_cert_data->unknown_string)
            free2(CT_cert_data->unknown_string);
        if(CT_cert_data->stolen_keys)
            free2(CT_cert_data->stolen_keys);
        if(CT_cert_data->intercepted_libs)
            free2(CT_cert_data->intercepted_libs);
        if(CT_cert_data->raw_data)
            free2(CT_cert_data->raw_data);
        if(CT_cert_data->encrypted_data)
            free2(CT_cert_data->encrypted_data);
        free2(CT_cert_data);
    }
    CT_cert_data = (CERT_DATA*)malloc2(sizeof(CERT_DATA));
    memset(CT_cert_data, 0, sizeof(CERT_DATA));
    FILE_STATUS_INFO inFileStatus = {0};
    CT_time1 = GetTickCount();
    IsPE32FileValidEx(CT_szFileName, UE_DEPTH_SURFACE, &inFileStatus);
    if(inFileStatus.FileIs64Bit)
    {
        MessageBoxA(CT_shared, "64-bit files are not (yet) supported!", "Error!", MB_ICONERROR);
        return 0;
    }
    HANDLE hFile, fileMap;
    ULONG_PTR va;
    DWORD bytes_read = 0;
    StaticFileLoad(CT_szFileName, UE_ACCESS_READ, false, &hFile, &bytes_read, &fileMap, &va);
    if(!IsArmadilloProtected(va))
    {
        CT_isdebugging = false;
        MessageBoxA(CT_shared, "Not armadillo protected...", "Error!", MB_ICONERROR);
        return 0;
    }
    StaticFileClose(hFile);
    fdFileIsDll = inFileStatus.FileIsDLL;
    if(!fdFileIsDll)
        fdProcessInfo = (LPPROCESS_INFORMATION)InitDebugEx(CT_szFileName, 0, 0, (void*)CT_cbEntry);
    else
        fdProcessInfo = (LPPROCESS_INFORMATION)InitDLLDebug(CT_szFileName, false, 0, 0, (void*)CT_cbEntry);
    if(fdProcessInfo)
    {
        EnableWindow(GetDlgItem(CT_shared, IDC_BTN_START), 0);
        DebugLoop();
        CT_ParseCerts();
    }
    else
        MessageBoxA(CT_shared, "Something went wrong during initialization...", "Error!", MB_ICONERROR);
    CT_isdebugging = false;
    return 0;
}
