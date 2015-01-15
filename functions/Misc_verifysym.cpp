#include "Misc_verifysym.h"

unsigned int MSC_FindMagicPattern(BYTE* d, unsigned int size, unsigned int* ebp_sub)
{
    for(unsigned int i = 0; i < size; i++) //8813000089
        if(d[i] == 0x88 and d[i + 1] == 0x13 and d[i + 2] == 0x00 and d[i + 3] == 0x00 and d[i + 4] == 0x89)
        {
            unsigned char ebp_sub1 = d[i + 6];
            if(ebp_sub1 > 0x7F)
                *ebp_sub = 0x100 - ebp_sub1;
            else
                *ebp_sub = 0 - ebp_sub1;
            return i + 7;
        }
    return 0;
}

void MSC_cbMagicValue()
{
    DeleteHardwareBreakPoint(UE_DR1);
    unsigned int retrieve_addr = GetContextData(UE_EBP) - MSC_VR_magic_ebp_sub - 4;
    unsigned int magic_values[2] = {0};
    ReadProcessMemory(MSC_fdProcessInfo->hProcess, (void*)retrieve_addr, magic_values, 8, 0);
    char temp[10] = "";
    sprintf(temp, "%.8X", magic_values[0]);
    SetDlgItemTextA(MSC_shared, IDC_EDT_MAGIC1, temp);
    sprintf(temp, "%.8X", magic_values[1]);
    SetDlgItemTextA(MSC_shared, IDC_EDT_MAGIC2, temp);
    StopDebug();
}

void MSC_VR_cbVirtualProtect()
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

    MSC_VR_magic_value_addr = MSC_FindMagicPattern(security_code, security_code_size, &MSC_VR_magic_ebp_sub);
    if(MSC_VR_magic_value_addr)
        SetHardwareBreakPoint((security_code_base + MSC_VR_magic_value_addr), UE_DR1, UE_HARDWARE_EXECUTE, UE_HARDWARE_SIZE_1, (void*)MSC_cbMagicValue);

    free2(security_code);
}

void MSC_VR_cbOpenMutexA()
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
        SetAPIBreakPoint((char*)"kernel32.dll", (char*)"VirtualProtect", UE_BREAKPOINT, UE_APISTART, (void*)MSC_VR_cbVirtualProtect);
    else
    {
        char log_message[256] = "";
        sprintf(log_message, "[Fail] Failed to create mutex %s", mutex_name);
        MSC_FatalError(log_message);
    }
}

void MSC_VR_cbEntry()
{
    FixIsDebuggerPresent(MSC_fdProcessInfo->hProcess, true);
    if(!MSC_fdFileIsDll)
        SetAPIBreakPoint((char*)"kernel32.dll", (char*)"OpenMutexA", UE_BREAKPOINT, UE_APISTART, (void*)MSC_VR_cbOpenMutexA);
    else
        SetAPIBreakPoint((char*)"kernel32.dll", (char*)"VirtualProtect", UE_BREAKPOINT, UE_APISTART, (void*)MSC_VR_cbVirtualProtect);
}

DWORD WINAPI MSC_VR_GetMagic(void* lpvoid)
{
    HWND btn = GetDlgItem(MSC_shared, IDC_BTN_GETMAGIC);
    EnableWindow(btn, 0);
    MSC_isdebugging = true;
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
        MSC_fdProcessInfo = (LPPROCESS_INFORMATION)InitDebugEx(MSC_szFileName, 0, 0, (void*)MSC_VR_cbEntry);
    }
    else
    {
        MSC_fdProcessInfo = (LPPROCESS_INFORMATION)InitDLLDebug(MSC_szFileName, false, 0, 0, (void*)MSC_VR_cbEntry);
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

unsigned int MSC_VR_GenerateNumber_core(int push_value, int* in_value)
{
    int val1 = *in_value / 0x2710;
    int val2 = *in_value % 0x2710;
    int res1 = val2 * 0x16BD;
    int res2 = val1 * 0x16BD;
    int res3 = val2 * 0xC45;
    unsigned int new1 = res2 + res3;
    unsigned int new2 = new1 % 0x2710;
    unsigned int new3 = new2 * 0x2710;
    unsigned int new4 = new3 + res1;
    unsigned int div1 = new4 % 0x5F5E100 + 1;
    unsigned int div2 = div1 % 0x5F5E100;
    *in_value = div2;
    unsigned int div3 = div2 / 0x2710;
    unsigned int div4 = div3 * push_value;
    unsigned int ret1 = div4 / 0x2710;
    return ret1;
}

unsigned int MSC_VR_GenerateNumberDword(int* in_value)
{
    unsigned char val1 = (unsigned char)MSC_VR_GenerateNumber_core(0x100, in_value);
    unsigned char val2 = (unsigned char)MSC_VR_GenerateNumber_core(0x100, in_value);
    unsigned char val3 = (unsigned char)MSC_VR_GenerateNumber_core(0x100, in_value);
    unsigned char val4 = (unsigned char)MSC_VR_GenerateNumber_core(0x100, in_value);
    return (((val1 << 24) | (val2 << 16)) | (val3 << 8)) | val4;
}

void MSC_VR_TEA_Decrypt(unsigned int* k, unsigned char* data, unsigned int length, int flag) //TODO: never used
{
    unsigned int v0, v1, sum, i;
    unsigned int delta = 0x9e3779b9;
    unsigned int k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3];
    unsigned int* lpData, *ptrEnd;

    lpData = (unsigned int*)data;
    ptrEnd = (unsigned int*)&data[4 * ((length >> 2) & 0x3FFFFFFE)];

    if(lpData < ptrEnd)
    {
        do
        {
            v0 = *lpData;
            v1 = lpData[1];
            sum = 0xC6EF3720;
            for(i = 0; i < 32; i++)
            {
                v1 -= ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
                v0 -= ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
                sum -= delta;
            }
            *lpData = v0;
            *(lpData + 1) = v1;
            lpData += 2;
            if(flag < 0)
            {
                k1 = v0;
                k3 = v1;
            }
        }
        while(lpData < ptrEnd);
    }
}

void MSC_VR_TEA_Decrypt_Nrounds(unsigned int* k, unsigned int* data, unsigned int rounds)
{
    unsigned int v0, v1, sum, i;
    unsigned int delta = 0x9e3779b9;
    unsigned int k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3];

    v0 = data[0];
    v1 = data[1];
    while(rounds--)
    {
        sum = 0xC6EF3720;
        for(i = 0; i < 32; i++)
        {
            v1 -= ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
            v0 -= ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
            sum -= delta;
        }
    }
    data[0] = v0;
    //data[1]=v1;
}

int MSC_VR_brute(unsigned int _magic1, unsigned int _magic2, unsigned int _sym, unsigned int _md5_ecdsa, unsigned char* data, unsigned int data_size)
{
    unsigned int magic1 = _magic1;
    unsigned int magic2 = _magic2;
    unsigned int sym = _sym;
    unsigned int md5_ecdsa = _md5_ecdsa;

    unsigned int sym_xor_magic1 = magic1 ^ sym;
    unsigned int sym_xor_magic1_mul_10_plus_1 = (magic1 ^ sym) * 10 + 1;
    unsigned int sym_xor_md5_ecdsa = sym ^ md5_ecdsa;
    unsigned int sym_not_xor_magic1 = magic1 ^ ~sym;

    MSC_VR_buffer_400 = (unsigned int*)malloc2(0x400);
    for(unsigned int i = 0; i < 0x100; i++) //loop1
    {
        unsigned int val1 = MSC_VR_GenerateNumberDword((int*)&sym_xor_magic1);
        unsigned int val2 = MSC_VR_GenerateNumberDword((int*)&sym_xor_md5_ecdsa);
        unsigned int val3 = MSC_VR_GenerateNumberDword((int*)&sym_xor_magic1_mul_10_plus_1);
        unsigned int val4 = val1 ^ val2 ^ val3 ^ sym;
        MSC_VR_buffer_400[i] = val4;
    }
    unsigned int new_value = MSC_VR_GenerateNumber_core(0x10, (int*)&sym_xor_magic1) + MSC_VR_GenerateNumber_core(0x10, (int*)&sym_xor_md5_ecdsa);
    unsigned char shr = (unsigned char)new_value;
    for(unsigned int i = 0, j = 0; i < magic2; i++, j++) //loop2
    {
        if(j == 0x100)
            j = 0;
        unsigned int new_value_and3 = (MSC_VR_buffer_400[j] >> shr) & 3;
        if(!new_value_and3)
        {
            MSC_VR_buffer_400[j] |= MSC_VR_GenerateNumberDword((int*)&sym_xor_magic1);
            MSC_VR_GenerateNumberDword((int*)&sym_xor_md5_ecdsa);
        }
        else
        {
            if(new_value_and3 == 1)
            {
                MSC_VR_buffer_400[j] &= MSC_VR_GenerateNumberDword((int*)&sym_xor_md5_ecdsa);
                MSC_VR_GenerateNumberDword((int*)&sym_xor_magic1);
            }
            else
                MSC_VR_buffer_400[j] ^= (MSC_VR_GenerateNumberDword((int*)&sym_xor_magic1)^MSC_VR_GenerateNumberDword((int*)&sym_xor_md5_ecdsa));
        }
    }
    unsigned int hash[4] = {0};
    md5((long unsigned int*)hash, (void*)MSC_VR_buffer_400, 0x400);
    free2(MSC_VR_buffer_400);
    unsigned int rounds = MSC_VR_GenerateNumber_core(0x190, (int*)&sym_not_xor_magic1) + 0x321;
    unsigned int buf_size = 0, mini_crc = 0, keyA = 0; //, keyB=0;
    unsigned char key_mini_crc = hash[0] & 7;
    unsigned char* p_block = 0;
    const unsigned char* p_certs = data;
    const unsigned char* p_certs_array_end = data + data_size;
    //unsigned int k=0, block_size=0;
    while(1)
    {
        if(p_certs < p_certs_array_end)
        {
            buf_size = *(unsigned int*)p_certs;
            p_certs += 4;
            if(buf_size)
            {
                mini_crc = *p_certs;
                p_certs++;
                if(key_mini_crc == mini_crc)
                {
                    p_block = (unsigned char*)malloc2(8);
                    memcpy(p_block, p_certs, 8);
                    p_certs = p_certs + buf_size;
                    MSC_VR_TEA_Decrypt_Nrounds((unsigned int*)hash, (unsigned int*)p_block, rounds + 2);
                    keyA = *(unsigned int*)(p_block);
                    free2(p_block);
                    if(keyA == 0xFFFFFFFF || ((keyA & 0xFFFFFFF0) == 0))
                        return 1;

                    /*p_block=(unsigned char*)malloc2(buf_size);
                    memcpy(p_block, p_certs, buf_size);
                    p_certs=p_certs+buf_size;
                    TEA_Decrypt(hash, p_block, buf_size, -1);
                    if(rounds) //loop3 (rounds=magic2)
                    {
                        block_size=1024;
                        if(buf_size<1024)
                            block_size=buf_size;
                        k=rounds;
                        do
                        {
                            TEA_Decrypt(hash, p_block, block_size, 0);
                        }
                        while(--k);
                    }
                    TEA_Decrypt(hash, p_block, buf_size, -1);
                    keyA=*(unsigned int*)(p_block+buf_size-8);
                    keyB=*(unsigned int*)(p_block+buf_size-4);
                    free2(p_block);
                    if(keyA==~keyB)
                        return 1;*/
                }
                else
                    p_certs = p_certs + buf_size;
            }
            else
                break;
        }
        else
            break;
    }
    return 0;
}

void MSC_VR_StepProgressBar(int total_keys)
{
    SendDlgItemMessageA(MSC_shared, IDC_PROGRESS_SYMVERIFY, PBM_SETRANGE, 0, MAKELPARAM(0, total_keys));
    SendDlgItemMessageA(MSC_shared, IDC_PROGRESS_SYMVERIFY, PBM_SETSTEP, 1, 0);
    SendDlgItemMessageA(MSC_shared, IDC_PROGRESS_SYMVERIFY, PBM_STEPIT, 0, 0);
}

DWORD WINAPI MSC_VR_BruteThread(LPVOID arg)
{
    //Initialization
    EnableWindow(GetDlgItem(MSC_shared, IDC_BTN_VERIFYSYM), 0);
    CheckDlgButton(MSC_shared, IDC_CHK_ISVALIDSYM, 0);
    SendDlgItemMessageA(MSC_shared, IDC_PROGRESS_SYMVERIFY, PBM_SETPOS, 0, 0);
    unsigned int _magic1, _magic2, _md5;
    sscanf(MSC_VR_magic1, "%X", &_magic1);
    sscanf(MSC_VR_magic2, "%X", &_magic2);
    sscanf(MSC_VR_md5_text, "%X", &_md5);

    //Read cert file
    unsigned char* data;
    unsigned int data_size = 0;
    HANDLE hFile = CreateFileA(MSC_VR_certpath, GENERIC_ALL, 0, 0, OPEN_EXISTING, 0, 0);
    if(hFile == INVALID_HANDLE_VALUE)
    {
        MessageBoxA(MSC_shared, "Could not open certs file...", "Error!", MB_ICONERROR);
        EnableWindow(GetDlgItem(MSC_shared, IDC_BTN_VERIFYSYM), 1);
        return 1;
    }
    data_size = GetFileSize(hFile, 0);
    data = (unsigned char*)malloc2(data_size);
    DWORD read = 0;
    ReadFile(hFile, data, data_size, &read, 0);
    CloseHandle(hFile);

    //Read keys
    MSC_VR_keys = (char*)malloc2(max_bufsize);
    memset(MSC_VR_keys, 0, max_bufsize);
    MSC_VR_keys_format = (char*)malloc2(max_bufsize);
    memset(MSC_VR_keys_format, 0, max_bufsize);
    MSC_VR_key_array = (unsigned int*)malloc2((max_bufsize / 8) * 4);
    memset(MSC_VR_key_array, 0, (max_bufsize / 8) * 4);
    char single_key[10] = "";
    hFile = CreateFileA(MSC_VR_keyspath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
    if(hFile == INVALID_HANDLE_VALUE)
    {
        MessageBoxA(MSC_shared, "Failed to open file...", "Error!", MB_ICONERROR);
        EnableWindow(GetDlgItem(MSC_shared, IDC_BTN_VERIFYSYM), 1);
        return 1;
    }
    int len = GetFileSize(hFile, 0);
    if(len > max_bufsize)
    {
        MessageBoxA(MSC_shared, "File too big...", "Error!", MB_ICONERROR);
        EnableWindow(GetDlgItem(MSC_shared, IDC_BTN_VERIFYSYM), 1);
        return 1;
    }
    read = 0;
    ReadFile(hFile, MSC_VR_keys, len, &read, 0);
    CloseHandle(hFile);
    for(int i = 0, j = 0; i < len; i++)
    {
        if((MSC_VR_keys[i] > 64 and MSC_VR_keys[i] < 71) or (MSC_VR_keys[i] > 47 and MSC_VR_keys[i] < 58) or (MSC_VR_keys[i] > 96 and MSC_VR_keys[i] < 103)) //1234567890ABCDEFabcdef
            j += sprintf(MSC_VR_keys_format + j, "%c", MSC_VR_keys[i]);
    }
    len = strlen(MSC_VR_keys_format);
    int i = 0;
    int j = 0;
    while(i != len)
    {
        strncpy(single_key, MSC_VR_keys_format + i, 8);
        _strupr(single_key);
        sscanf(single_key, "%X", &MSC_VR_key_array[j]);
        j++;
        i += 8;
    }
    free2(MSC_VR_keys);
    free2(MSC_VR_keys_format);

    //Actual brute force...
    for(int k = 0; k != j; k++)
    {
        if(MSC_VR_brute(_magic1, _magic2, MSC_VR_key_array[k], _md5, data, data_size))
        {
            char valid[10] = "";
            sprintf(valid, "%.8X", MSC_VR_key_array[k]);
            SetDlgItemTextA(MSC_shared, IDC_EDT_SYMFOUND, valid);
            free2(MSC_VR_key_array);
            free2(data);
            CheckDlgButton(MSC_shared, IDC_CHK_ISVALIDSYM, 1);
            EnableWindow(GetDlgItem(MSC_shared, IDC_BTN_VERIFYSYM), 1);
            return 0;
        }
        MSC_VR_StepProgressBar(j);
    }

    //Free memory
    free2(MSC_VR_key_array);
    free2(data);
    SetDlgItemTextA(MSC_shared, IDC_EDT_SYMFOUND, "NO_VALID");
    EnableWindow(GetDlgItem(MSC_shared, IDC_BTN_VERIFYSYM), 1);
    return 0;
}
