#include "Misc_checksum.h"

unsigned int MakeChecksumV3(unsigned int sym)
{
    unsigned long hash[4]= {0,0,0,0};
    md5(hash, &sym, 4);
    return ((((hash[2]^hash[3])^hash[1])^hash[0])^sym);
}

unsigned int MakeChecksumV8(unsigned int sym, unsigned int salt)
{
    unsigned int dword[2]= {sym, salt};
    unsigned long hash[4];
    for(int i=0; i<1000; i++)
    {
        md5(hash, &dword, 8);
        dword[0]=(((hash[2]^hash[3])^hash[1])^hash[0]);
    }
    return dword[0];
}

void MSC_cbGetSalt()
{
    char temp_buffer[10]="";
    MSC_project_salt=GetContextData(MSC_salt_register);
    sprintf(temp_buffer, "%.8X", MSC_project_salt);
    SetDlgItemTextA(MSC_shared, IDC_EDT_SALT, temp_buffer);
    StopDebug();
}

void MSC_RetrieveSaltValue()
{
    if(!MSC_salt_func_addr)
    {
        MSC_FatalError("Salt not found!");
        return;
    }
    DISASM MyDisasm;
    memset(&MyDisasm, 0, sizeof(DISASM));
    MyDisasm.EIP=(UIntPtr)MSC_salt_code;
    int len=0;
    int xor_count=0;
    for(;;)
    {
        len=Disasm(&MyDisasm);
        if(len!=UNKNOWN_OPCODE)
        {
            if(MyDisasm.EIP!=(UIntPtr)MSC_salt_code and MyDisasm.Instruction.Mnemonic[0]=='x' and MyDisasm.Instruction.Mnemonic[1]=='o' and MyDisasm.Instruction.Mnemonic[2]=='r')
                xor_count++;
            if(xor_count==3)
                break;
            MyDisasm.EIP=MyDisasm.EIP+(UIntPtr)len;
            if(MyDisasm.EIP>=(unsigned int)MSC_salt_code+60)
                break;
        }
        else
            break;
    }
    if(xor_count!=3)
    {
        MSC_FatalError("Something went wrong...");
        StopDebug();
        return;
    }
    MSC_salt_register=DetermineRegisterFromText(MyDisasm.Argument1.ArgMnemonic);
    MSC_salt_breakpoint=MyDisasm.EIP-((unsigned int)MSC_salt_code)+MSC_salt_func_addr+len;
    if(!MSC_salt_register)
    {
        MSC_FatalError("Something went wrong...");
        StopDebug();
        return;
    }
    SetContextData(UE_EIP, MSC_salt_func_addr);
    SetBPX(MSC_salt_breakpoint, UE_BREAKPOINT, (void*)MSC_cbGetSalt);
}

void MSC_SALT_cbOpenMutexA2()
{
    DeleteAPIBreakPoint((char*)"kernel32.dll", (char*)"OpenMutexA", UE_APISTART);
    MSC_RetrieveSaltValue();
}

void MSC_SALT_cbVirtualProtect()
{
    DeleteAPIBreakPoint((char*)"kernel32.dll", (char*)"VirtualProtect", UE_APISTART);

    long esp_addr=GetContextData(UE_ESP);
    unsigned int security_code_base=0,security_code_size=0;
    ReadProcessMemory(MSC_fdProcessInfo->hProcess, (void*)(esp_addr+4), &security_code_base, 4, 0);
    ReadProcessMemory(MSC_fdProcessInfo->hProcess, (void*)(esp_addr+8), &security_code_size, 4, 0);
    BYTE* security_code=(BYTE*)malloc2(security_code_size);
    ReadProcessMemory(MSC_fdProcessInfo->hProcess, (void*)security_code_base, security_code, security_code_size, 0);
    MSC_salt_func_addr=FindSalt1Pattern(security_code, security_code_size); //9.60Beta1
    if(!MSC_salt_func_addr)
        MSC_salt_func_addr=FindSalt2Pattern(security_code, security_code_size);
    if(MSC_salt_func_addr)
    {
        memcpy(MSC_salt_code, (void*)(MSC_salt_func_addr+security_code), 60);
        MSC_salt_func_addr+=(unsigned int)security_code_base;
    }
    SetAPIBreakPoint((char*)"kernel32.dll", (char*)"OpenMutexA", UE_BREAKPOINT, UE_APISTART, (void*)MSC_SALT_cbOpenMutexA2);
    free2(security_code);
}

void MSC_SALT_cbOpenMutexA()
{
    char mutex_name[20]="";
    long mutex_addr=0;
    long esp_addr=0;
    unsigned int return_addr=0;
    DeleteAPIBreakPoint((char*)"kernel32.dll", (char*)"OpenMutexA", UE_APISTART);
    esp_addr=(long)GetContextData(UE_ESP);
    ReadProcessMemory(MSC_fdProcessInfo->hProcess, (const void*)esp_addr, &return_addr, 4, 0);
    ReadProcessMemory(MSC_fdProcessInfo->hProcess, (const void*)(esp_addr+12), &mutex_addr, 4, 0);
    ReadProcessMemory(MSC_fdProcessInfo->hProcess, (const void*)mutex_addr, &mutex_name, 20, 0);
    CreateMutexA(0, FALSE, mutex_name);
    if(GetLastError()==ERROR_SUCCESS)
        SetAPIBreakPoint((char*)"kernel32.dll", (char*)"VirtualProtect", UE_BREAKPOINT, UE_APISTART, (void*)MSC_SALT_cbVirtualProtect);
    else
    {
        char log_message[256]="";
        sprintf(log_message, "[Fail] Failed to create mutex %s", mutex_name);
        MSC_FatalError(log_message);
    }
}

void MSC_SALT_cbEntry()
{
    FixIsDebuggerPresent(MSC_fdProcessInfo->hProcess, true);
    if(!MSC_fdFileIsDll)
        SetAPIBreakPoint((char*)"kernel32.dll", (char*)"OpenMutexA", UE_BREAKPOINT, UE_APISTART, (void*)MSC_SALT_cbOpenMutexA);
    else
        SetAPIBreakPoint((char*)"kernel32.dll", (char*)"VirtualProtect", UE_BREAKPOINT, UE_APISTART, (void*)MSC_SALT_cbVirtualProtect);
}

DWORD WINAPI MSC_GetSalt(void* lpvoid)
{
    MSC_salt_func_addr=0;
    MSC_salt_register=0;
    MSC_project_salt=0;
    HWND btn=GetDlgItem(MSC_shared, IDC_BTN_GETSALT);
    EnableWindow(btn, 0);
    MSC_isdebugging=true;
    MSC_fdFileIsDll=false;
    MSC_fdProcessInfo=0;
    FILE_STATUS_INFO inFileStatus= {0};
    IsPE32FileValidEx(MSC_szFileName, UE_DEPTH_SURFACE, &inFileStatus);
    if(inFileStatus.FileIs64Bit)
    {
        MessageBoxA(MSC_shared, "64-bit files are not (yet) supported!", "Error!", MB_ICONERROR);
        return 0;
    }
    HANDLE hFile, fileMap;
    ULONG_PTR va;
    DWORD bytes_read=0;
    StaticFileLoad(MSC_szFileName, UE_ACCESS_READ, false, &hFile, &bytes_read, &fileMap, &va);
    if(!IsArmadilloProtected(va))
    {
        EnableWindow(btn, 1);
        MSC_isdebugging=false;
        MessageBoxA(MSC_shared, "Not armadillo protected...", "Error!", MB_ICONERROR);
        return 0;
    }
    StaticFileClose(hFile);
    MSC_fdFileIsDll=inFileStatus.FileIsDLL;
    if(!MSC_fdFileIsDll)
    {
        MSC_fdProcessInfo=(LPPROCESS_INFORMATION)InitDebugEx(MSC_szFileName, 0, 0, (void*)MSC_SALT_cbEntry);
    }
    else
    {
        MSC_fdProcessInfo=(LPPROCESS_INFORMATION)InitDLLDebug(MSC_szFileName, false, 0, 0, (void*)MSC_SALT_cbEntry);
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
    MSC_isdebugging=false;
    return 0;
}

unsigned long MSC_CHK_a;

unsigned long MSC_CHK_mult(long p, long q)
{
    unsigned long p1=p/10000L, p0=p%10000L, q1=q/10000L, q0=q%10000L;
    return (((p0*q1+p1*q0) % 10000L) * 10000L+p0*q0) % 100000000L;
}

unsigned long MSC_CHK_NextRandomRange(long range)
{
    MSC_CHK_a=(MSC_CHK_mult(MSC_CHK_a, 31415821L)+1) % 100000000L;
    return (((MSC_CHK_a/10000L)*range)/10000L);
}

unsigned char* MSC_CHK_GetCryptBytes(unsigned int seed, unsigned int size)
{
    MSC_CHK_a=seed;
    unsigned char* arry=(unsigned char*)malloc2(size+4);
    memset(arry, 0, size+4);
    for(unsigned int x=0; x<size+4; x++)
        arry[x]=(unsigned char)(MSC_CHK_NextRandomRange(256)&0xFF);
    return arry+4;
}

unsigned char* MSC_CHK_Decrypt(unsigned char** data, unsigned char** rand, unsigned int size)
{
    if(!size)
        return data[0];
    for(unsigned int i=0; i<size; i++)
        data[0][i]^=rand[0][i];
    data[0]+=size;
    rand[0]+=size;
    return data[0]-size;
}

bool MSC_CHK_DecryptCerts(unsigned int* seed, unsigned char* raw_data, unsigned int raw_size)
{
    puts("chk_decrypt");
    if(!raw_data or !raw_size or !seed)
        return 0;
    unsigned int real_cert_size=FindBAADF00DPattern(raw_data, raw_size);
    if(!real_cert_size)
        real_cert_size=raw_size;
    unsigned char* rand=MSC_CHK_GetCryptBytes(seed[0], real_cert_size);
    unsigned char* decr=(unsigned char*)malloc2(real_cert_size);
    memcpy(decr, raw_data, real_cert_size);
    free2(raw_data);
    MSC_CHK_Decrypt(&decr, &rand, 16);
    decr+=6;
    unsigned short* projectID_size=(unsigned short*)MSC_CHK_Decrypt(&decr, &rand, 2);
    if(*projectID_size)
        MSC_CHK_Decrypt(&decr, &rand, *projectID_size);
    unsigned short* customerSER_size=(unsigned short*)MSC_CHK_Decrypt(&decr, &rand, 2);
    if(*customerSER_size)
        MSC_CHK_Decrypt(&decr, &rand, *customerSER_size);
    unsigned short* website_size=(unsigned short*)MSC_CHK_Decrypt(&decr, &rand, 2);
    if(*website_size)
        MSC_CHK_Decrypt(&decr, &rand, *website_size);
    decr+=seed[1];
    unsigned char* stolen_size=MSC_CHK_Decrypt(&decr, &rand, 1);
    while(*stolen_size)
    {
        MSC_CHK_Decrypt(&decr, &rand, *stolen_size);
        stolen_size=MSC_CHK_Decrypt(&decr, &rand, 1);
    }
    decr+=seed[2];
    unsigned short* libs_size=(unsigned short*)MSC_CHK_Decrypt(&decr, &rand, 2);
    if(*libs_size)
        MSC_CHK_Decrypt(&decr, &rand, *libs_size);
    decr+=seed[3];
    unsigned char* start=decr;
    MSC_CHK_Decrypt(&decr, &rand, 1);
    unsigned char* signature_size=MSC_CHK_Decrypt(&decr, &rand, 1);
    while(*signature_size)
    {
        MSC_CHK_Decrypt(&decr, &rand, (*signature_size)+4);
        MSC_CHK_Decrypt(&decr, &rand, 1);
        signature_size=MSC_CHK_Decrypt(&decr, &rand, 1);
    }
    bool found=false;
    if(FindDwordInMemory(start, MSC_checksum, decr-start))
        found=true;
    free2(decr);
    free2(rand);
    return found;
}

void MSC_CHK_cbGetOtherSeed()
{
    MSC_CHK_other_seed_counter++;
    unsigned int eip=GetContextData(UE_EIP);
    DeleteBPX(eip);
    unsigned char reg_byte=0;
    ReadProcessMemory(MSC_fdProcessInfo->hProcess, (void*)(eip+1), &reg_byte, 1, 0);
    MSC_CHK_seeds[MSC_CHK_other_seed_counter]=GetContextData(MSC_DetermineRegisterFromByte(reg_byte));
    if(MSC_CHK_other_seed_counter==4)
    {
        DeleteBPX(eip);
        StopDebug();
        MSC_CHK_other_seed_counter=0;
        bool found=MSC_CHK_DecryptCerts(MSC_CHK_seeds, MSC_CHK_raw_data, 0x10000);
        EnableWindow(GetDlgItem(MSC_shared, IDC_CHK_FOUNDCHECKSUM), 1);
        CheckDlgButton(MSC_shared, IDC_CHK_FOUNDCHECKSUM, found);
        free2(MSC_CHK_raw_data);
    }
}

void MSC_CHK_cbOtherSeeds()
{
    unsigned int eip=GetContextData(UE_EIP);
    unsigned char* eip_data=(unsigned char*)malloc2(0x10000);
    ReadProcessMemory(MSC_fdProcessInfo->hProcess, (void*)eip, eip_data, 0x10000, 0);
    unsigned int stdcall=MSC_FindStdcallPattern(eip_data, 0x10000);
    if(!stdcall)
    {
        stdcall=MSC_FindCall2Pattern(eip_data, 0x10000);
        if(!stdcall)
        {
            MSC_FatalError("Could not find call pattern...");
            return;
        }
    }
    eip_data+=stdcall;
    unsigned int size=0x10000-stdcall;
    unsigned int retn=MSC_FindReturnPattern(eip_data, size);

    unsigned int and_addrs[4]= {0};

    for(int i=0; i<4; i++)
    {
        and_addrs[i]=MSC_FindAndPattern2(eip_data, size);
        if(!and_addrs[i])
            and_addrs[i]=MSC_FindAndPattern1(eip_data, size);
        if(!and_addrs[i] or and_addrs[i]>retn)
        {
            MSC_FatalError("Could not find AND [REG],[VAL]");
            return;
        }
        size-=and_addrs[i];
        eip_data+=and_addrs[i];
        retn-=and_addrs[i];
        if(i)
            and_addrs[i]+=and_addrs[i-1];
    }
    MSC_SortArray(and_addrs, 4);

    MSC_CHK_other_seed_counter=0;
    for(int i=0; i<4; i++)
        SetBPX(and_addrs[i]+eip+stdcall, UE_BREAKPOINT, (void*)MSC_CHK_cbGetOtherSeed);
    free2(eip_data);
}

void MSC_CHK_cbReturnSeed1()
{
    DeleteBPX(GetContextData(UE_EIP));
    unsigned int esp=GetContextData(UE_ESP);
    unsigned int _stack=0;
    ReadProcessMemory(MSC_fdProcessInfo->hProcess, (void*)esp, &_stack, 4, 0);
    MSC_CHK_return_counter++;
    if(MSC_CHK_return_counter!=2)
    {
        unsigned char* return_bytes=(unsigned char*)malloc2(0x1000);
        ReadProcessMemory(MSC_fdProcessInfo->hProcess, (void*)_stack, return_bytes, 0x1000, 0);
        unsigned int retn=MSC_FindReturnPattern(return_bytes, 0x1000);
        free2(return_bytes);
        if(!retn)
        {
            MSC_FatalError("Could not find return");
            return;
        }
        SetBPX(retn+_stack, UE_BREAKPOINT, (void*)MSC_CHK_cbReturnSeed1);
    }
    else
    {
        SetContextData(UE_ESP, GetContextData(UE_ESP)+4);
        SetContextData(UE_EIP, _stack);
        MSC_CHK_cbOtherSeeds();
    }
}

void MSC_CHK_cbSeed1()
{
    DeleteBPX(GetContextData(UE_EIP));
    unsigned int ecx=GetContextData(UE_ECX);
    ReadProcessMemory(MSC_fdProcessInfo->hProcess, (void*)ecx, &MSC_CHK_seeds[0], 4, 0);
}

void MSC_CHK_cbCertificateFunction()
{
    if(!MSC_cert_func_count)
        MSC_cert_func_count++;
    else if(MSC_cert_func_count==1)
    {
        DeleteHardwareBreakPoint(UE_DR0);
        MSC_cert_func_count=0;
        long retn_eax=GetContextData(UE_EAX);
        BYTE* certificate_code=(BYTE*)malloc2(0x10000);
        if(!ReadProcessMemory(MSC_fdProcessInfo->hProcess, (void*)retn_eax, certificate_code, 0x10000, 0))
        {
            free2(certificate_code);
            MSC_FatalError("Failed to read process memory...");
        }
        //Arma 9.60 support
        unsigned int esp=GetContextData(UE_ESP);
        unsigned int _stack=0;
        ReadProcessMemory(MSC_fdProcessInfo->hProcess, (void*)esp, &_stack, 4, 0);
        unsigned char* return_bytes=(unsigned char*)malloc2(0x1000);
        ReadProcessMemory(MSC_fdProcessInfo->hProcess, (void*)_stack, return_bytes, 0x1000, 0);
        unsigned int push100=MSC_FindPush100Pattern(return_bytes, 0x1000);
        unsigned int retn=MSC_FindReturnPattern(return_bytes, 0x1000);
        if(!retn)
            MSC_FindReturnPattern2(return_bytes, 0x1000);
        if(!retn)
        {
            MSC_FatalError("Could not find return...");
            free2(certificate_code);
            return;
        }
        if(push100<retn)
        {
            unsigned int call=MSC_FindCall1Pattern(return_bytes+push100, 0x1000-push100);
            if(!call)
                call=MSC_FindCall2Pattern(return_bytes+push100, 0x1000-push100);
            if(!call)
            {
                MSC_FatalError("Could not find call...");
                free2(certificate_code);
                return;
            }
            else
            {
                MSC_CHK_raw_data=certificate_code;
                SetBPX(_stack+call+push100, UE_BREAKPOINT, (void*)MSC_CHK_cbSeed1);
                MSC_CHK_return_counter=0;
                SetBPX(_stack+retn, UE_BREAKPOINT, (void*)MSC_CHK_cbReturnSeed1);
            }
        }
        else
        {
            free2(return_bytes);
            EnableWindow(GetDlgItem(MSC_shared, IDC_CHK_FOUNDCHECKSUM), 1);
            bool found=false;
            if(FindDwordInMemory(certificate_code, MSC_checksum, 0x10000))
                found=true;
            CheckDlgButton(MSC_shared, IDC_CHK_FOUNDCHECKSUM, found);
            free2(certificate_code);
            StopDebug();
        }
    }
    else
        DeleteHardwareBreakPoint(UE_DR0);
}

void MSC_CHK_cbVirtualProtect()
{
    DeleteAPIBreakPoint((char*)"kernel32.dll", (char*)"VirtualProtect", UE_APISTART);

    long esp_addr=GetContextData(UE_ESP);
    unsigned int security_code_base=0,security_code_size=0;
    ReadProcessMemory(MSC_fdProcessInfo->hProcess, (void*)(esp_addr+4), &security_code_base, 4, 0);
    ReadProcessMemory(MSC_fdProcessInfo->hProcess, (void*)(esp_addr+8), &security_code_size, 4, 0);
    BYTE* security_code=(BYTE*)malloc2(security_code_size);
    ReadProcessMemory(MSC_fdProcessInfo->hProcess, (void*)security_code_base, security_code, security_code_size, 0);

    unsigned int breakpoint_addr=MSC_FindCertificateFunctionNew(security_code, security_code_size);
    if(!breakpoint_addr)
        breakpoint_addr=MSC_FindCertificateFunctionOld(security_code, security_code_size);
    if(!breakpoint_addr)
    {
        MSC_FatalError("Could not find NextDword...");
        return;
    }
    SetHardwareBreakPoint((security_code_base+breakpoint_addr), UE_DR0, UE_HARDWARE_EXECUTE, UE_HARDWARE_SIZE_1, (void*)MSC_CHK_cbCertificateFunction);
    free2(security_code);
}

void MSC_CHK_cbOpenMutexA()
{
    char mutex_name[20]="";
    long mutex_addr=0;
    long esp_addr=0;
    unsigned int return_addr=0;
    DeleteAPIBreakPoint((char*)"kernel32.dll", (char*)"OpenMutexA", UE_APISTART);
    esp_addr=(long)GetContextData(UE_ESP);
    ReadProcessMemory(MSC_fdProcessInfo->hProcess, (const void*)esp_addr, &return_addr, 4, 0);
    ReadProcessMemory(MSC_fdProcessInfo->hProcess, (const void*)(esp_addr+12), &mutex_addr, 4, 0);
    ReadProcessMemory(MSC_fdProcessInfo->hProcess, (const void*)mutex_addr, &mutex_name, 20, 0);
    CreateMutexA(0, FALSE, mutex_name);
    if(GetLastError()==ERROR_SUCCESS)
        SetAPIBreakPoint((char*)"kernel32.dll", (char*)"VirtualProtect", UE_BREAKPOINT, UE_APISTART, (void*)MSC_CHK_cbVirtualProtect);
    else
    {
        char log_message[256]="";
        sprintf(log_message, "[Fail] Failed to create mutex %s", mutex_name);
        MSC_FatalError(log_message);
    }
}

void MSC_CHK_cbEntry()
{
    FixIsDebuggerPresent(MSC_fdProcessInfo->hProcess, true);
    if(!MSC_fdFileIsDll)
        SetAPIBreakPoint((char*)"kernel32.dll", (char*)"OpenMutexA", UE_BREAKPOINT, UE_APISTART, (void*)MSC_CHK_cbOpenMutexA);
    else
        SetAPIBreakPoint((char*)"kernel32.dll", (char*)"VirtualProtect", UE_BREAKPOINT, UE_APISTART, (void*)MSC_CHK_cbVirtualProtect);
}

DWORD WINAPI MSC_FindChecksum(void* lpvoid)
{
    HWND btn=GetDlgItem(MSC_shared, IDC_BTN_FINDCHECKSUM);
    EnableWindow(GetDlgItem(MSC_shared, IDC_CHK_FOUNDCHECKSUM), 0);
    EnableWindow(btn, 0);
    MSC_isdebugging=true;
    MSC_fdFileIsDll=false;
    MSC_fdProcessInfo=0;
    FILE_STATUS_INFO inFileStatus= {0};
    IsPE32FileValidEx(MSC_szFileName, UE_DEPTH_SURFACE, &inFileStatus);
    HANDLE hFile, fileMap;
    ULONG_PTR va;
    DWORD bytes_read=0;
    StaticFileLoad(MSC_szFileName, UE_ACCESS_READ, false, &hFile, &bytes_read, &fileMap, &va);
    if(!IsArmadilloProtected(va))
    {
        EnableWindow(btn, 1);
        MSC_isdebugging=false;
        MessageBoxA(MSC_shared, "Not armadillo protected...", "Error!", MB_ICONERROR);
        return 0;
    }
    StaticFileClose(hFile);
    MSC_fdFileIsDll=inFileStatus.FileIsDLL;
    if(!MSC_fdFileIsDll)
    {
        MSC_fdProcessInfo=(LPPROCESS_INFORMATION)InitDebugEx(MSC_szFileName, 0, 0, (void*)MSC_CHK_cbEntry);
    }
    else
    {
        MSC_fdProcessInfo=(LPPROCESS_INFORMATION)InitDLLDebug(MSC_szFileName, false, 0, 0, (void*)MSC_CHK_cbEntry);
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
    MSC_isdebugging=false;
    return 0;
}
