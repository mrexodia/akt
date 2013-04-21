#include "VersionFind_global.h"

unsigned int FindAnd20Pattern(BYTE* d, unsigned int size)
{
    for(unsigned int i=0; i<size; i++) //83E?20
        if(d[i]==0x83 and(d[i+1]>>4)==0x0E and d[i+2]==0x20)
            return i;
    return 0;
}

unsigned int FindAnd40000Pattern(BYTE* d, unsigned int size)
{
    for(unsigned int i=0; i<size; i++) //81E?00000400
        if(d[i]==0x81 and(d[i+1]>>4)==0x0E and d[i+2]==0x00 and d[i+3]==0x00 and d[i+4]==0x04 and d[i+5]==0x00)
            return i;
    return 0;
}

void VF_cbRetrieveRawOptions()
{
    DeleteBPX(GetContextData(UE_EIP));
    VF_raw_options=GetContextData(VF_raw_options_reg);
    StopDebug();
}

void VF_cbMutexReturn()
{
    unsigned int eip=GetContextData(UE_EIP);
    DeleteBPX(eip);
    BYTE* eip_data=(BYTE*)malloc(100);
    ReadProcessMemory(VF_fdProcessInfo->hProcess, (void*)eip, eip_data, 100, 0);
    int and20=FindAnd20Pattern(eip_data, 100);
    if(!and20)
        VF_FatalError("Could not find 'and [reg],20'");
    unsigned int andreg=eip_data[and20+1]&0x0F;
    VF_raw_options_reg=0xFFFFFFFF;
    switch(andreg)
    {
    case 0:
        VF_raw_options_reg=UE_EAX;
        break;
    case 1:
        VF_raw_options_reg=UE_ECX;
        break;
    case 2:
        VF_raw_options_reg=UE_EDX;
        break;
    case 3:
        VF_raw_options_reg=UE_EBX;
        break;
    case 5:
        VF_raw_options_reg=UE_EBP;
        break;
    case 6:
        VF_raw_options_reg=UE_ESI;
        break;
    case 7:
        VF_raw_options_reg=UE_EDI;
        break;
    }
    if(VF_raw_options_reg==0xFFFFFFFF)
        VF_FatalError("Could not determine raw options register");
    SetBPX((and20+eip), UE_BREAKPOINT, (void*)VF_cbRetrieveRawOptions);
}

void VF_cbOpOpenMutexA()
{
    long esp_addr=0;
    unsigned int return_addr=0;
    DeleteAPIBreakPoint((char*)"kernel32.dll", (char*)"OpenMutexA", UE_APISTART);
    esp_addr=(long)GetContextData(UE_ESP);
    ReadProcessMemory(VF_fdProcessInfo->hProcess, (const void*)esp_addr, &return_addr, 4, 0);
    SetBPX(return_addr, UE_BREAKPOINT, (void*)VF_cbMutexReturn);
}

void VF_cbOpGetCommandLine()
{
    DeleteAPIBreakPoint((char*)"kernel32.dll", (char*)"GetCommandLineA", UE_APISTART);
    DeleteAPIBreakPoint((char*)"kernel32.dll", (char*)"GetCommandLineW", UE_APISTART);
    BYTE* data=(BYTE*)malloc(VF_fdEntrySectionSize);
    ReadProcessMemory(VF_fdProcessInfo->hProcess, (void*)VF_fdEntrySectionOffset, data, VF_fdEntrySectionSize, 0);
    int and40000=FindAnd40000Pattern(data, VF_fdEntrySectionSize);
    if(!and40000)
        VF_FatalError("Could not find 'and [reg],40000'");
    unsigned int andreg=data[and40000+1]&0x0F;
    VF_raw_options_reg=0xFFFFFFFF;
    switch(andreg)
    {
    case 0:
        VF_raw_options_reg=UE_EAX;
        break;
    case 1:
        VF_raw_options_reg=UE_ECX;
        break;
    case 2:
        VF_raw_options_reg=UE_EDX;
        break;
    case 3:
        VF_raw_options_reg=UE_EBX;
        break;
    case 5:
        VF_raw_options_reg=UE_EBP;
        break;
    case 6:
        VF_raw_options_reg=UE_ESI;
        break;
    case 7:
        VF_raw_options_reg=UE_EDI;
        break;
    }
    if(VF_raw_options_reg==0xFFFFFFFF)
        VF_FatalError("Could not determine raw options register");
    SetBPX((and40000+VF_fdEntrySectionOffset), UE_BREAKPOINT, (void*)VF_cbRetrieveRawOptions);
}

void VF_cbOpEntry()
{
    if(!VF_fdFileIsDll)
        SetAPIBreakPoint((char*)"kernel32.dll", (char*)"OpenMutexA", UE_BREAKPOINT, UE_APISTART, (void*)VF_cbOpOpenMutexA);
    else
    {
        SetAPIBreakPoint((char*)"kernel32.dll", (char*)"GetCommandLineA", UE_BREAKPOINT, UE_APISTART, (void*)VF_cbOpGetCommandLine);
        SetAPIBreakPoint((char*)"kernel32.dll", (char*)"GetCommandLineW", UE_BREAKPOINT, UE_APISTART, (void*)VF_cbOpGetCommandLine);
    }
}

bool IsMinimalProtection(ULONG_PTR va)
{
    OutputDebugStringA("IsMinimalProtection");
    int offset=GetPE32Data(VF_szFileName, VF_fdEntrySectionNumber, UE_SECTIONRAWOFFSET);
    BYTE firstbytes[2]= {0};
    memcpy(firstbytes, (void*)(va+offset), 2);
    if(firstbytes[0]==0x60 and firstbytes[1]==0xE8)
        return false;
    return true;
}

bool VF_RawOptions()
{
    VF_fdFileIsDll = false;
    VF_fdImageBase = NULL;
    VF_fdEntryPoint = NULL;
    VF_fdProcessInfo = NULL;
    FILE_STATUS_INFO inFileStatus = {0};
    if(IsPE32FileValidEx(VF_szFileName, UE_DEPTH_SURFACE, &inFileStatus))
    {
        if(inFileStatus.FileIs64Bit)
        {
            MessageBoxA(VF_shared, "64-bit files are not (yet) supported!", "Error!", MB_ICONERROR);
            return 0;
        }
        HANDLE hFile, fileMap;
        ULONG_PTR va;
        DWORD bytes_read;
        VF_fdImageBase = (long)GetPE32Data(VF_szFileName, NULL, UE_IMAGEBASE);
        VF_fdEntryPoint = (long)GetPE32Data(VF_szFileName, NULL, UE_OEP);
        StaticFileLoad(VF_szFileName, UE_ACCESS_READ, false, &hFile, &bytes_read, &fileMap, &va);
        if(!IsArmadilloProtected(va))
        {
            MessageBoxA(VF_shared, "Not armadillo protected...", "Error!", MB_ICONERROR);
        }
        else
        {
            VF_fdEntrySectionNumber = GetPE32SectionNumberFromVA(va, VF_fdEntryPoint+VF_fdImageBase);
            VF_fdEntrySectionOffset = (long)GetPE32Data(VF_szFileName, VF_fdEntrySectionNumber, UE_SECTIONVIRTUALOFFSET)+VF_fdImageBase;
            VF_fdEntrySectionSize = (long)GetPE32Data(VF_szFileName, VF_fdEntrySectionNumber, UE_SECTIONVIRTUALSIZE);
            StaticFileClose(hFile);
            VF_minimal=IsMinimalProtection(va);
            VF_fdFileIsDll = inFileStatus.FileIsDLL;
            if(!VF_fdFileIsDll)
            {
                VF_fdProcessInfo = (LPPROCESS_INFORMATION)InitDebugEx(VF_szFileName, NULL, NULL, (void*)VF_cbOpEntry);
            }
            else
            {
                VF_fdProcessInfo = (LPPROCESS_INFORMATION)InitDLLDebug(VF_szFileName, false, NULL, NULL, (void*)VF_cbOpEntry);
            }
            if(VF_fdProcessInfo)
            {
                DebugLoop();
                return true;
            }
            else
            {
                MessageBoxA(VF_shared, "Something went wrong during initialization...", "Error!", MB_ICONERROR);
            }
        }
    }
    else
    {
        MessageBoxA(VF_shared, "This is not a valid PE file...", "Error!", MB_ICONERROR);
    }
    return false;
}
