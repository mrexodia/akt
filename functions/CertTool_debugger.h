#include "CertTool_global.h"

void CT_cbGetSalt()
{
    CT_cert_data->salt=GetContextData(CT_salt_register);
    StopDebug();
}

void CT_RetrieveSaltValue()
{
    if(!CT_salt_func_addr)
    {
        StopDebug();
        return;
    }
    DISASM MyDisasm= {0};
    MyDisasm.EIP=(UIntPtr)CT_salt_code;
    int len=0;
    int xor_count=0;
    for(;;)
    {
        len=Disasm(&MyDisasm);
        if(len==UNKNOWN_OPCODE)
            break;
        if(MyDisasm.EIP!=(UIntPtr)CT_salt_code and MyDisasm.Instruction.Mnemonic[0]=='x' and MyDisasm.Instruction.Mnemonic[1]=='o' and MyDisasm.Instruction.Mnemonic[2]=='r')
            xor_count++;
        if(xor_count==3)
            break;
        MyDisasm.EIP+=len;
        if(MyDisasm.EIP>=(unsigned int)CT_salt_code+60)
            break;
    }
    if(xor_count!=3)
    {
        StopDebug();
        return;
    }
    CT_salt_register=DetermineRegisterFromText(MyDisasm.Argument1.ArgMnemonic);
    CT_salt_breakpoint=MyDisasm.EIP-((unsigned int)CT_salt_code)+CT_salt_func_addr+len;
    if(!CT_salt_register)
    {
        StopDebug();
        return;
    }
    SetContextData(UE_EIP, CT_salt_func_addr);
    SetBPX(CT_salt_breakpoint, UE_BREAKPOINT, (void*)CT_cbGetSalt);
}

void CT_cbEndBigLoop()
{
    DeleteBPX(CT_end_big_loop);
    DeleteBPX(CT_tea_decrypt);
    DeleteBPX(CT_magic_byte);
    CT_encrypted_cert_real_size+=4;
    unsigned char* final_data=(unsigned char*)malloc(CT_encrypted_cert_real_size);
    memset(final_data, 0, CT_encrypted_cert_real_size);
    memcpy(final_data, CT_encrypted_cert_real, CT_encrypted_cert_real_size-4);
    free(CT_encrypted_cert_real);
    CT_cert_data->encrypted_data=final_data;
    CT_cert_data->encrypted_size=CT_encrypted_cert_real_size;
    CT_encrypted_cert_real_size=0;
    CT_RetrieveSaltValue();
}

void CT_cbTeaDecrypt()
{
    unsigned int esp=GetContextData(UE_ESP);
    unsigned int values[2]= {0};
    ReadProcessMemory(CT_fdProcessInfo->hProcess, (void*)(esp+4), &values, 8, 0);
    unsigned char first_5_bytes[5]="";
    memcpy(first_5_bytes, &values[1], 4);
    first_5_bytes[4]=CT_magic_byte_cert;
    unsigned char* new_data=(unsigned char*)malloc(values[1]);
    ReadProcessMemory(CT_fdProcessInfo->hProcess, (void*)values[0], new_data, values[1], 0);
    unsigned char* temp=(unsigned char*)malloc(CT_encrypted_cert_real_size+values[1]+5);
    if(CT_encrypted_cert_real)
    {
        memcpy(temp, CT_encrypted_cert_real, CT_encrypted_cert_real_size);
        free(CT_encrypted_cert_real);
    }
    CT_encrypted_cert_real=temp;
    memcpy(CT_encrypted_cert_real+CT_encrypted_cert_real_size, first_5_bytes, 5);
    memcpy(CT_encrypted_cert_real+CT_encrypted_cert_real_size+5, new_data, values[1]);
    free(new_data);
    CT_encrypted_cert_real_size+=values[1]+5;
}

void CT_cbMagicJump()
{
    if(!CT_patched_magic_jump)
    {
        BYTE eb[2]= {0xEB,0x90};
        WriteProcessMemory(CT_fdProcessInfo->hProcess, (void*)(CT_magic_byte+2), &eb, 1, 0); //patch JNZ->JMP
        eb[0]=0x90;
        WriteProcessMemory(CT_fdProcessInfo->hProcess, (void*)CT_noteax, &eb, 2, 0);
        SetBPX(CT_tea_decrypt, UE_BREAKPOINT, (void*)CT_cbTeaDecrypt);
        SetBPX(CT_end_big_loop, UE_BREAKPOINT, (void*)CT_cbEndBigLoop);
        DISASM MyDisasm= {0};
        MyDisasm.EIP=(UIntPtr)&CT_cmp_data;
        Disasm(&MyDisasm);
        char register_retrieve[10]="";
        strncpy(register_retrieve, MyDisasm.Argument2.ArgMnemonic, 3);
        CT_patched_magic_jump=true;
        CT_register_magic_byte=DetermineRegisterFromText(register_retrieve);
    }
    CT_magic_byte_cert=(unsigned char)GetContextData(CT_register_magic_byte);
}

void CT_cbMagicValue()
{
    DeleteHardwareBreakPoint(UE_DR1);
    unsigned int retrieve_addr=GetContextData(UE_EBP)-CT_magic_ebp_sub-4;
    unsigned int magic_values[2]= {0};
    ReadProcessMemory(CT_fdProcessInfo->hProcess, (void*)retrieve_addr, magic_values, 8, 0);
    CT_cert_data->magic1=magic_values[0];
    CT_cert_data->magic2=magic_values[1];
    if(CT_end_big_loop)
        SetBPX(CT_magic_byte, UE_BREAKPOINT, (void*)CT_cbMagicJump);
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
    unsigned int* cpy=(unsigned int*)malloc(size*4);
    memcpy(cpy, a, size*4);
    unsigned int* biggest=&cpy[0];
    for(int i=0; i<size; i++)
    {
        for(int j=0; j<size; j++)
        {
            if(cpy[j]>*biggest)
                biggest=&cpy[j];
        }
        a[size-i-1]=*biggest;
        *biggest=0;
    }
}

void CT_cbGetOtherSeed()
{
    unsigned int eip=GetContextData(UE_EIP);
    DeleteBPX(eip);
    unsigned char reg_byte=0;
    ReadProcessMemory(CT_fdProcessInfo->hProcess, (void*)(eip+1), &reg_byte, 1, 0);
    CT_cert_data->decrypt_addvals[CT_other_seed_counter]=GetContextData(CT_DetermineRegisterFromByte(reg_byte));
    CT_other_seed_counter++;
    if(CT_other_seed_counter==4)
    {
        CT_other_seed_counter=0;
        if(!CT_magic_value_addr)
            CT_RetrieveSaltValue();
    }
}

void CT_cbOtherSeeds()
{
    unsigned int eip=GetContextData(UE_EIP);
    unsigned char* eip_data=(unsigned char*)malloc(0x10000);
    ReadProcessMemory(CT_fdProcessInfo->hProcess, (void*)eip, eip_data, 0x10000, 0);
    unsigned int stdcall=CT_FindStdcallPattern(eip_data, 0x10000);
    if(!stdcall)
    {
        stdcall=CT_FindCall2Pattern(eip_data, 0x10000);
        if(!stdcall)
        {
            CT_FatalError("Could not find call pattern...");
            return;
        }
    }
    eip_data+=stdcall;
    unsigned int size=0x10000-stdcall;
    unsigned int retn=CT_FindReturnPattern(eip_data, size);

    unsigned int and_addrs[4]= {0};

    for(int i=0; i<4; i++)
    {
        and_addrs[i]=CT_FindAndPattern2(eip_data, size);
        if(!and_addrs[i])
            and_addrs[i]=CT_FindAndPattern1(eip_data, size);
        if(!and_addrs[i] or and_addrs[i]>retn)
        {
            CT_FatalError("Could not find AND [REG],[VAL]");
            return;
        }
        size-=and_addrs[i];
        eip_data+=and_addrs[i];
        retn-=and_addrs[i];
        if(i)
            and_addrs[i]+=and_addrs[i-1];
    }
    CT_SortArray(and_addrs, 4);

    CT_other_seed_counter=0;
    for(int i=0; i<4; i++)
        SetBPX(and_addrs[i]+eip+stdcall, UE_BREAKPOINT, (void*)CT_cbGetOtherSeed);

    free(eip_data);
}

void CT_cbReturnSeed1()
{
    DeleteBPX(GetContextData(UE_EIP));
    unsigned int esp=GetContextData(UE_ESP);
    unsigned int _stack=0;
    ReadProcessMemory(CT_fdProcessInfo->hProcess, (void*)esp, &_stack, 4, 0);
    CT_return_counter++;
    if(CT_return_counter!=2)
    {
        unsigned char* return_bytes=(unsigned char*)malloc(0x1000);
        ReadProcessMemory(CT_fdProcessInfo->hProcess, (void*)_stack, return_bytes, 0x1000, 0);
        unsigned int retn=CT_FindReturnPattern(return_bytes, 0x1000);
        free(return_bytes);
        if(!retn)
        {
            CT_FatalError("Could not find return");
            return;
        }
        SetBPX(retn+_stack, UE_BREAKPOINT, (void*)CT_cbReturnSeed1);
    }
    else
    {
        SetContextData(UE_ESP, GetContextData(UE_ESP)+4);
        SetContextData(UE_EIP, _stack);
        CT_cbOtherSeeds();
    }
}

void CT_cbSeed1()
{
    DeleteBPX(GetContextData(UE_EIP));
    unsigned int ecx=GetContextData(UE_ECX);
    ReadProcessMemory(CT_fdProcessInfo->hProcess, (void*)ecx, &(CT_cert_data->decrypt_seed[0]), 4, 0);
}

void CT_cbCertificateFunction()
{
    if(!CT_cert_func_count)
        CT_cert_func_count++;
    else if(CT_cert_func_count==1)
    {
        DeleteHardwareBreakPoint(UE_DR0);
        long retn_eax=GetContextData(UE_EAX);
        BYTE* certificate_code=(BYTE*)malloc(0x10000);
        if(ReadProcessMemory(CT_fdProcessInfo->hProcess, (void*)retn_eax, certificate_code, 0x10000, 0))
        {
            //Arma 9.60 support
            unsigned int esp=GetContextData(UE_ESP);
            unsigned int _stack=0;
            ReadProcessMemory(CT_fdProcessInfo->hProcess, (void*)esp, &_stack, 4, 0);
            unsigned char* return_bytes=(unsigned char*)malloc(0x1000);
            ReadProcessMemory(CT_fdProcessInfo->hProcess, (void*)_stack, return_bytes, 0x1000, 0);
            unsigned int push100=CT_FindPush100Pattern(return_bytes, 0x1000);
            unsigned int retn=CT_FindReturnPattern(return_bytes, 0x1000);
            if(!retn)
                CT_FindReturnPattern2(return_bytes, 0x1000);
            if(push100<retn)
            {
                unsigned int call=CT_FindCall1Pattern(return_bytes+push100, 0x1000-push100);
                if(!call)
                    call=CT_FindCall2Pattern(return_bytes+push100, 0x1000-push100);
                if(!call)
                {
                    if(MessageBoxA(CT_shared, "Could not find call, continue?", "Continue?", MB_ICONERROR|MB_YESNO)==IDYES)
                        if(!CT_magic_value_addr)
                            CT_RetrieveSaltValue();
                }
                else
                {
                    SetBPX(_stack+call+push100, UE_BREAKPOINT, (void*)CT_cbSeed1);
                    CT_return_counter=0;
                    SetBPX(_stack+retn, UE_BREAKPOINT, (void*)CT_cbReturnSeed1);
                }
                CT_cert_data->raw_size=0x10000;
                CT_cert_data->raw_data=(unsigned char*)malloc(0x10000);
                memcpy(CT_cert_data->raw_data, certificate_code, 0x10000);
            }
            else
            {
                free(return_bytes);
                //Get raw certificate data
                unsigned int cert_start=CT_FindCertificateMarkers(certificate_code, 0x10000);
                if(!cert_start)
                    cert_start=CT_FindCertificateMarkers2(certificate_code, 0x10000);
                if(!cert_start)
                {
                    free(certificate_code);
                    if(MessageBoxA(CT_shared, "Could not find start markers, continue?", "Continue?", MB_ICONERROR|MB_YESNO)==IDYES)
                    {
                        if(!CT_magic_value_addr)
                            CT_RetrieveSaltValue();
                    }
                    else
                        StopDebug();
                    return;
                }
                cert_start+=4;
                CT_cert_data->initial_diff=cert_start+1;
                unsigned int cert_end=CT_FindCertificateEndMarkers(certificate_code+cert_start, 0x10000-cert_start);
                if(cert_end) //Unsigned/Default certificates are not stored here...
                {
                    CT_cert_data->raw_size=cert_end;
                    CT_cert_data->raw_data=(unsigned char*)malloc(cert_end);
                    memcpy(CT_cert_data->raw_data, certificate_code+cert_start, cert_end);
                    CT_cert_data->raw_data++;
                    CT_cert_data->raw_size--;
                }

                //Get first dword
                memcpy(&CT_cert_data->first_dw, certificate_code, 4);

                //Get project id
                short projectid_size=0;
                memcpy(&projectid_size, certificate_code, 2);
                CT_cert_data->projectid=(char*)malloc(projectid_size+1);
                memset(CT_cert_data->projectid, 0, projectid_size+1);
                memcpy(CT_cert_data->projectid, certificate_code+2, projectid_size);

                free(certificate_code);

                if(!CT_magic_value_addr)
                    CT_RetrieveSaltValue();
            }
        }
        else
        {
            free(certificate_code);
            CT_FatalError("Failed to read process memory...");
        }
    }
    else
        DeleteHardwareBreakPoint(UE_DR0);
}

void CT_cbVirtualProtect()
{
    DeleteAPIBreakPoint((char*)"kernel32.dll", (char*)"VirtualProtect", UE_APISTART);
    long esp_addr=GetContextData(UE_ESP);
    unsigned int security_code_base=0,security_code_size=0;
    ReadProcessMemory(CT_fdProcessInfo->hProcess, (void*)(esp_addr+4), &security_code_base, 4, 0);
    ReadProcessMemory(CT_fdProcessInfo->hProcess, (void*)(esp_addr+8), &security_code_size, 4, 0);
    BYTE* security_code=(BYTE*)malloc(security_code_size);
    ReadProcessMemory(CT_fdProcessInfo->hProcess, (void*)security_code_base, security_code, security_code_size, 0);

    //Certificate data
    unsigned int breakpoint_addr=CT_FindCertificateFunctionNew(security_code, security_code_size);
    if(!breakpoint_addr)
        breakpoint_addr=CT_FindCertificateFunctionOld(security_code, security_code_size);
    if(!breakpoint_addr)
    {
        CT_FatalError("Could not find NextDword...");
        return;
    }
    SetHardwareBreakPoint((security_code_base+breakpoint_addr), UE_DR0, UE_HARDWARE_EXECUTE, UE_HARDWARE_SIZE_1, (void*)CT_cbCertificateFunction);

    //Magic
    CT_magic_value_addr=CT_FindMagicPattern(security_code, security_code_size, &CT_magic_ebp_sub);
    if(CT_magic_value_addr)
        SetHardwareBreakPoint((security_code_base+CT_magic_value_addr), UE_DR1, UE_HARDWARE_EXECUTE, UE_HARDWARE_SIZE_1, (void*)CT_cbMagicValue);

    //Magic MD5=0
    if(CT_magic_value_addr)
    {
        unsigned int end_search=CT_FindEndInitSymVerifyPattern(security_code+CT_magic_value_addr, security_code_size-CT_magic_value_addr);
        unsigned int md5_move=CT_FindPubMd5MovePattern(security_code+CT_magic_value_addr, security_code_size-CT_magic_value_addr);
        if(end_search and md5_move and md5_move>end_search) //Arma with MD5=0 in SymVerify
            CT_cert_data->zero_md5_symverify=true;
    }

    //Encrypted cert data
    unsigned int push400=CT_FindDecryptKey1Pattern(security_code, security_code_size);
    if(push400)
    {
        CT_magic_byte=CT_FindMagicJumpPattern(security_code+push400, security_code_size-push400, &CT_cmp_data);
        if(CT_magic_byte)
        {
            CT_magic_byte+=push400;
            unsigned int pushff=CT_FindPushFFPattern(security_code+CT_magic_byte, security_code_size-CT_magic_byte);
            if(pushff)
            {
                pushff+=CT_magic_byte;
                CT_tea_decrypt=CT_FindTeaDecryptPattern(security_code+pushff, security_code_size-CT_magic_byte);
                if(CT_tea_decrypt)
                {
                    CT_tea_decrypt+=pushff;
                    CT_noteax=CT_FindVerifySymPattern(security_code+CT_tea_decrypt, security_code_size-CT_tea_decrypt);
                    if(CT_noteax)
                    {
                        CT_noteax+=CT_tea_decrypt;
                        CT_end_big_loop=CT_FindEndLoopPattern(security_code+CT_noteax, security_code_size-CT_noteax);
                        if(CT_end_big_loop)
                        {
                            CT_end_big_loop+=CT_noteax+security_code_base;
                            CT_noteax+=security_code_base;
                            CT_tea_decrypt+=security_code_base;
                            CT_magic_byte+=security_code_base;
                        }
                    }
                }
            }
        }
    }

    if(CT_FindECDSAVerify(security_code, security_code_size))
        CT_cert_data->checksumv8=true;

    //Salt
    CT_salt_func_addr=FindSalt1Pattern(security_code, security_code_size); //v9.60
    if(!CT_salt_func_addr)
        CT_salt_func_addr=FindSalt2Pattern(security_code, security_code_size);
    if(CT_salt_func_addr)
    {
        memcpy(CT_salt_code, (void*)(CT_salt_func_addr+security_code), 60);
        CT_salt_func_addr+=(unsigned int)security_code_base;
    }
    free(security_code);
}

void CT_cbOpenMutexA()
{
    char mutex_name[20]="";
    long mutex_addr=0;
    long esp_addr=0;
    unsigned int return_addr=0;
    DeleteAPIBreakPoint((char*)"kernel32.dll", (char*)"OpenMutexA", UE_APISTART);
    esp_addr=(long)GetContextData(UE_ESP);
    ReadProcessMemory(CT_fdProcessInfo->hProcess, (const void*)esp_addr, &return_addr, 4, 0);
    ReadProcessMemory(CT_fdProcessInfo->hProcess, (const void*)(esp_addr+12), &mutex_addr, 4, 0);
    ReadProcessMemory(CT_fdProcessInfo->hProcess, (const void*)mutex_addr, &mutex_name, 20, 0);
    CreateMutexA(0, FALSE, mutex_name);
    if(GetLastError()==ERROR_SUCCESS)
        SetAPIBreakPoint((char*)"kernel32.dll", (char*)"VirtualProtect", UE_BREAKPOINT, UE_APISTART, (void*)CT_cbVirtualProtect);
    else
    {
        char log_message[256]="";
        sprintf(log_message, "[Fail] Failed to create mutex %s", mutex_name);
        CT_FatalError(log_message);
    }
}

void CT_cbEntry()
{
    if(!CT_fdFileIsDll)
        SetAPIBreakPoint((char*)"kernel32.dll", (char*)"OpenMutexA", UE_BREAKPOINT, UE_APISTART, (void*)CT_cbOpenMutexA);
    else
        SetAPIBreakPoint((char*)"kernel32.dll", (char*)"VirtualProtect", UE_BREAKPOINT, UE_APISTART, (void*)CT_cbVirtualProtect);
}

DWORD WINAPI CT_FindCertificates(void* lpvoid)
{
    CT_created_log=false;
    CT_isdebugging=true;
    CT_patched_magic_jump=false;
    CT_fdProcessInfo=0;
    CT_magic_value_addr=0;
    CT_encrypted_cert_real=0;
    CT_encrypted_cert_real_size=0;
    CT_cert_func_count=0;

    if(CT_cert_data)
    {
        if(CT_cert_data->projectid)
            free(CT_cert_data->projectid);
        if(CT_cert_data->raw_data)
            free(CT_cert_data->raw_data);
        if(CT_cert_data->encrypted_data)
            free(CT_cert_data->encrypted_data);
        free(CT_cert_data);
    }
    CT_cert_data=(CERT_DATA*)malloc(sizeof(CERT_DATA));
    memset(CT_cert_data, 0, sizeof(CERT_DATA));
    InitVariables(program_dir, (CT_DATA*)CT_cert_data, StopDebug, 1, GetParent(CT_shared));
    FILE_STATUS_INFO inFileStatus = {0};
    CT_time1=GetTickCount();
    if(IsPE32FileValidEx(CT_szFileName, UE_DEPTH_DEEP, &inFileStatus))
    {
        if(inFileStatus.FileIs64Bit)
        {
            MessageBoxA(CT_shared, "64-bit files are not (yet) supported!", "Error!", MB_ICONERROR);
            return 0;
        }
        HANDLE hFile, fileMap;
        ULONG_PTR va;
        DWORD bytes_read=0;
        StaticFileLoad(CT_szFileName, UE_ACCESS_READ, false, &hFile, &bytes_read, &fileMap, &va);
        if(!IsArmadilloProtected(va))
        {
            InitVariables(program_dir, 0, StopDebug, 0, 0);
            CT_isdebugging=false;
            MessageBoxA(CT_shared, "Not armadillo protected...", "Error!", MB_ICONERROR);
            return 0;
        }
        StaticFileClose(hFile);
        CT_fdFileIsDll = inFileStatus.FileIsDLL;
        if(!CT_fdFileIsDll)
            CT_fdProcessInfo = (LPPROCESS_INFORMATION)InitDebugEx(CT_szFileName, NULL, NULL, (void*)CT_cbEntry);
        else
            CT_fdProcessInfo = (LPPROCESS_INFORMATION)InitDLLDebug(CT_szFileName, false, NULL, NULL, (void*)CT_cbEntry);
        if(CT_fdProcessInfo)
        {
            EnableWindow(GetDlgItem(CT_shared, IDC_BTN_START), 0);
            DebugLoop();
            InitVariables(program_dir, 0, StopDebug, 0, 0);
            CT_ParseCerts();
        }
        else
            MessageBoxA(CT_shared, "Something went wrong during initialization...", "Error!", MB_ICONERROR);
    }
    else
        MessageBoxA(CT_shared, "This is not a valid PE file...", "Error!", MB_ICONERROR);
    InitVariables(program_dir, 0, StopDebug, 0, 0);
    CT_isdebugging=false;
    return 0;
}
