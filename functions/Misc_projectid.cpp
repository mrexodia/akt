#include "Misc_projectid.h"

unsigned int MSC_FindCertificateFunctionOld(BYTE* d, unsigned int size)
{
    for(unsigned int i=0; i<size; i++) //8B4424048B5424088B0883C004890AC3
        if(d[i]==0x8B and d[i+1]==0x44 and d[i+2]==0x24 and d[i+3]==0x04 and d[i+4]==0x8B and d[i+5]==0x54 and d[i+6]==0x24 and d[i+7]==0x08 and d[i+8]==0x8B and d[i+9]==0x08 and d[i+10]==0x83 and d[i+11]==0xC0 and d[i+12]==0x04 and d[i+13]==0x89 and d[i+14]==0x0A and d[i+15]==0xC3)
            return i+15;
    return 0;
}

unsigned int MSC_FindCertificateFunctionNew(BYTE* d, unsigned int size)
{
    for(unsigned int i=0; i<size; i++) //558BEC8B450C8B4D088B1189108B450883C0045DC3
        if(d[i]==0x55 and d[i+1]==0x8B and d[i+2]==0xEC and d[i+3]==0x8B and d[i+4]==0x45 and d[i+5]==0x0C and d[i+6]==0x8B and d[i+7]==0x4D and d[i+8]==0x08 and d[i+9]==0x8B and d[i+10]==0x11 and d[i+11]==0x89 and d[i+12]==0x10 and d[i+13]==0x8B and d[i+14]==0x45 and d[i+15]==0x08 and d[i+16]==0x83 and d[i+17]==0xC0 and d[i+18]==0x04 and d[i+19]==0x5D and d[i+20]==0xC3)
            return i+20;
    return 0;
}

unsigned int MSC_FindCertificateMarkers(BYTE* d, unsigned int size)
{
    for(unsigned int i=0; i<size; i++) //002D2A00
        if(d[i]==0x00 and d[i+1]==0x2D and d[i+2]==0x2A and d[i+3]==0x00)
            return i;
    return 0;
}

unsigned int MSC_FindCertificateMarkers2(BYTE* d, unsigned int size)
{
    for(unsigned int i=0; i<size; i++) //002B2A00
        if(d[i]==0x00 and d[i+1]==0x2B and d[i+2]==0x2A and d[i+3]==0x00)
            return i;
    return 0;
}

//arma960 support
unsigned long MSC_a;

unsigned long MSC_mult(long p, long q)
{
    unsigned long p1=p/10000L, p0=p%10000L, q1=q/10000L, q0=q%10000L;
    return (((p0*q1+p1*q0) % 10000L) * 10000L+p0*q0) % 100000000L;
}

unsigned long MSC_NextRandomRange(long range)
{
    MSC_a=(MSC_mult(MSC_a, 31415821L)+1) % 100000000L;
    return (((MSC_a/10000L)*range)/10000L);
}

unsigned char* MSC_GetCryptBytes(unsigned int seed, unsigned int size)
{
    MSC_a=seed;
    unsigned char* arry=(unsigned char*)malloc(size+4);
    memset(arry, 0, size+4);
    for(unsigned int x=0; x<size+4; x++)
        arry[x]=MSC_NextRandomRange(256);
    return arry+4;
}

unsigned char* MSC_Decrypt(unsigned char** data, unsigned char** rand, unsigned int size)
{
    if(!size)
        return data[0];
    for(unsigned int i=0; i<size; i++)
        data[0][i]^=rand[0][i];
    data[0]+=size;
    rand[0]+=size;
    return data[0]-size;
}

char* MSC_DecryptCerts(unsigned int* seed, unsigned char* raw_data, unsigned int raw_size)
{
    char* projectid;
    if(!raw_data or !raw_size or !seed)
        return 0;
    unsigned int real_cert_size=FindBAADF00DPattern(raw_data, raw_size);
    raw_size=real_cert_size;
    if(!real_cert_size)
        real_cert_size=0x10000;
    unsigned char* rand=MSC_GetCryptBytes(seed[0], real_cert_size);
    unsigned char* decr=(unsigned char*)malloc(raw_size);
    memcpy(decr, raw_data, raw_size);
    free(raw_data);
    MSC_Decrypt(&decr, &rand, 16);
    decr+=6;
    unsigned short* projectID_size=(unsigned short*)MSC_Decrypt(&decr, &rand, 2);
    if(*projectID_size)
        MSC_Decrypt(&decr, &rand, *projectID_size);
    projectid=(char*)malloc(*projectID_size+1);
    memset(projectid, 0, *projectID_size+1);
    memcpy(projectid, decr-*projectID_size, *projectID_size);
    free(decr);
    free(rand);
    return projectid;
}

void MSC_cbGetOtherSeed()
{
    OutputDebugStringA("arma960");
    MSC_other_seed_counter++;
    unsigned int eip=GetContextData(UE_EIP);
    DeleteBPX(eip);
    unsigned char reg_byte=0;
    ReadProcessMemory(MSC_fdProcessInfo->hProcess, (void*)(eip+1), &reg_byte, 1, 0);
    MSC_seeds[MSC_other_seed_counter]=GetContextData(MSC_DetermineRegisterFromByte(reg_byte));
    if(MSC_other_seed_counter==4)
    {
        DeleteBPX(eip);
        StopDebug();
        MSC_other_seed_counter=0;
        char* projid=MSC_DecryptCerts(MSC_seeds, MSC_raw_data, 0x10000);
        SetDlgItemTextA(MSC_shared, IDC_EDT_PROJECTID, projid);
        free(projid);
        free(MSC_raw_data);
    }
}

void MSC_cbOtherSeeds()
{
    unsigned int eip=GetContextData(UE_EIP);
    unsigned char* eip_data=(unsigned char*)malloc(0x10000);
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

    MSC_other_seed_counter=0;
    for(int i=0; i<4; i++)
        SetBPX(and_addrs[i]+eip+stdcall, UE_BREAKPOINT, (void*)MSC_cbGetOtherSeed);
    free(eip_data);
}

void MSC_cbReturnSeed1()
{
    DeleteBPX(GetContextData(UE_EIP));
    unsigned int esp=GetContextData(UE_ESP);
    unsigned int _stack=0;
    ReadProcessMemory(MSC_fdProcessInfo->hProcess, (void*)esp, &_stack, 4, 0);
    MSC_return_counter++;
    if(MSC_return_counter!=2)
    {
        unsigned char* return_bytes=(unsigned char*)malloc(0x1000);
        ReadProcessMemory(MSC_fdProcessInfo->hProcess, (void*)_stack, return_bytes, 0x1000, 0);
        unsigned int retn=MSC_FindReturnPattern(return_bytes, 0x1000);
        free(return_bytes);
        if(!retn)
        {
            MSC_FatalError("Could not find return");
            return;
        }
        SetBPX(retn+_stack, UE_BREAKPOINT, (void*)MSC_cbReturnSeed1);
    }
    else
    {
        SetContextData(UE_ESP, GetContextData(UE_ESP)+4);
        SetContextData(UE_EIP, _stack);
        MSC_cbOtherSeeds();
    }
}

void MSC_cbSeed1()
{
    DeleteBPX(GetContextData(UE_EIP));
    unsigned int ecx=GetContextData(UE_ECX);
    ReadProcessMemory(MSC_fdProcessInfo->hProcess, (void*)ecx, &MSC_seeds[0], 4, 0);
}

void MSC_cbCertificateFunction()
{
    OutputDebugStringA("projectid_960");
    if(!MSC_cert_func_count)
        MSC_cert_func_count++;
    else if(MSC_cert_func_count==1)
    {
        DeleteHardwareBreakPoint(UE_DR0);
        MSC_cert_func_count=0;
        long retn_eax=GetContextData(UE_EAX);
        BYTE* certificate_code=(BYTE*)malloc(0x10000);
        if(ReadProcessMemory(MSC_fdProcessInfo->hProcess, (void*)retn_eax, certificate_code, 0x10000, 0))
        {
            //TODO: Decrypt
            //Arma 9.60 support
            unsigned int esp=GetContextData(UE_ESP);
            unsigned int _stack=0;
            ReadProcessMemory(MSC_fdProcessInfo->hProcess, (void*)esp, &_stack, 4, 0);
            unsigned char* return_bytes=(unsigned char*)malloc(0x1000);
            ReadProcessMemory(MSC_fdProcessInfo->hProcess, (void*)_stack, return_bytes, 0x1000, 0);
            unsigned int push100=MSC_FindPush100Pattern(return_bytes, 0x1000);
            unsigned int retn=MSC_FindReturnPattern(return_bytes, 0x1000);
            if(!retn)
                MSC_FindReturnPattern2(return_bytes, 0x1000);
            if(!retn)
            {
                MSC_FatalError("Could not find return...");
                free(certificate_code);
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
                    free(certificate_code);
                    return;
                }
                else
                {
                    MSC_raw_data=certificate_code;
                    SetBPX(_stack+call+push100, UE_BREAKPOINT, (void*)MSC_cbSeed1);
                    MSC_return_counter=0;
                    SetBPX(_stack+retn, UE_BREAKPOINT, (void*)MSC_cbReturnSeed1);
                }
            }
            else
            {
                unsigned int certificate_start=MSC_FindCertificateMarkers(certificate_code, 0x10000);
                if(!certificate_start)
                    certificate_start=MSC_FindCertificateMarkers2(certificate_code, 0x10000);
                if(certificate_start)
                {
                    char project_name[65536]="";
                    WORD project_name_size=0;
                    memcpy(&project_name_size, certificate_code, 2);
                    memcpy(project_name, (certificate_code+2), project_name_size);
                    free(certificate_code);
                    SetDlgItemTextA(MSC_shared, IDC_EDT_PROJECTID, project_name);
                    StopDebug();
                }
                else
                {
                    free(certificate_code);
                    MSC_FatalError("Failed to locate project ID...");
                }
            }
        }
        else
        {
            free(certificate_code);
            MSC_FatalError("Failed to read process memory...");
        }
    }
    else
        DeleteHardwareBreakPoint(UE_DR0);
}


void MSC_PRJ_cbVirtualProtect()
{
    OutputDebugStringA("cbVirtualProtect (ProjectID)");
    DeleteAPIBreakPoint((char*)"kernel32.dll", (char*)"VirtualProtect", UE_APISTART);

    long esp_addr=GetContextData(UE_ESP);
    unsigned int security_code_base=0,security_code_size=0;
    ReadProcessMemory(MSC_fdProcessInfo->hProcess, (void*)(esp_addr+4), &security_code_base, 4, 0);
    ReadProcessMemory(MSC_fdProcessInfo->hProcess, (void*)(esp_addr+8), &security_code_size, 4, 0);
    BYTE* security_code=(BYTE*)malloc(security_code_size);
    ReadProcessMemory(MSC_fdProcessInfo->hProcess, (void*)security_code_base, security_code, security_code_size, 0);

    unsigned int breakpoint_addr=MSC_FindCertificateFunctionNew(security_code, security_code_size);
    if(!breakpoint_addr)
        breakpoint_addr=MSC_FindCertificateFunctionOld(security_code, security_code_size);
    if(!breakpoint_addr)
    {
        MSC_FatalError("Could not find NextDword...");
        return;
    }
    SetHardwareBreakPoint((security_code_base+breakpoint_addr), UE_DR0, UE_HARDWARE_EXECUTE, UE_HARDWARE_SIZE_1, (void*)MSC_cbCertificateFunction);
    free(security_code);
}

void MSC_PRJ_cbOpenMutexA()
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
        SetAPIBreakPoint((char*)"kernel32.dll", (char*)"VirtualProtect", UE_BREAKPOINT, UE_APISTART, (void*)MSC_PRJ_cbVirtualProtect);
    else
    {
        char log_message[256]="";
        sprintf(log_message, "[Fail] Failed to create mutex %s", mutex_name);
        MSC_FatalError(log_message);
    }
}

void MSC_PRJ_cbEntry()
{
    if(!MSC_fdFileIsDll)
        SetAPIBreakPoint((char*)"kernel32.dll", (char*)"OpenMutexA", UE_BREAKPOINT, UE_APISTART, (void*)MSC_PRJ_cbOpenMutexA);
    else
        SetAPIBreakPoint((char*)"kernel32.dll", (char*)"VirtualProtect", UE_BREAKPOINT, UE_APISTART, (void*)MSC_PRJ_cbVirtualProtect);
}

DWORD WINAPI MSC_GetProjectID(void* lpvoid)
{
    HWND btn=GetDlgItem(MSC_shared, IDC_BTN_GETPROJECTID);
    EnableWindow(btn, 0);
    MSC_isdebugging=true;
    MSC_fdFileIsDll = false;
    MSC_fdProcessInfo = NULL;
    FILE_STATUS_INFO inFileStatus = {0};
    if(IsPE32FileValidEx(MSC_szFileName, UE_DEPTH_DEEP, &inFileStatus))
    {
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
        MSC_fdFileIsDll = inFileStatus.FileIsDLL;
        if(!MSC_fdFileIsDll)
        {
            MSC_fdProcessInfo = (LPPROCESS_INFORMATION)InitDebugEx(MSC_szFileName, NULL, NULL, (void*)MSC_PRJ_cbEntry);
        }
        else
        {
            MSC_fdProcessInfo = (LPPROCESS_INFORMATION)InitDLLDebug(MSC_szFileName, false, NULL, NULL, (void*)MSC_PRJ_cbEntry);
        }
        if(MSC_fdProcessInfo)
        {
            DebugLoop();
        }
        else
        {
            MessageBoxA(MSC_shared, "Something went wrong during initialization...", "Error!", MB_ICONERROR);
        }
    }
    else
    {
        MessageBoxA(MSC_shared, "This is not a valid PE file...", "Error!", MB_ICONERROR);
    }
    EnableWindow(btn, 1);
    MSC_isdebugging=false;
    return 0;
}
