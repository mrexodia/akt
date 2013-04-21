#include "VersionFind_global.h"

unsigned int FindUsbPattern(BYTE* d, unsigned int size)
{
    for(unsigned int i=0; i<size; i++) //55534220646576696365
        if(d[i]==0x55 and d[i+1]==0x53 and d[i+2]==0x42 and d[i+3]==0x20 and d[i+4]==0x64 and d[i+5]==0x65 and d[i+6]==0x76 and d[i+7]==0x69 and d[i+8]==0x63 and d[i+9]==0x65)
        {
            while(d[i]!=0)
                i--;
            return i+1;
        }
    return 0;
}

void VF_cbExtraDwordRetrieve()
{
    DeleteBPX(GetContextData(UE_EIP));
    VF_extra_options=GetContextData(VF_extra_options_reg);
    StopDebug();
}

void VF_cbExtraDw()
{
    unsigned int eip=GetContextData(UE_EIP);
    DeleteBPX(eip);
    BYTE* eip_data=(BYTE*)malloc(0x1000);
    ReadProcessMemory(VF_fdProcessInfo->hProcess, (void*)eip, eip_data, 0x1000, 0);
    unsigned int and20=FindAnd20Pattern(eip_data, 0x1000);
    if(!and20)
        VF_FatalError("Could not find 'and [reg],20");
    unsigned int andreg=eip_data[and20+1]&0x0F;
    VF_extra_options_reg=0xFFFFFFFF;
    switch(andreg)
    {
    case 0:
        VF_extra_options_reg=UE_EAX;
        break;
    case 1:
        VF_extra_options_reg=UE_ECX;
        break;
    case 2:
        VF_extra_options_reg=UE_EDX;
        break;
    case 3:
        VF_extra_options_reg=UE_EBX;
        break;
    case 5:
        VF_extra_options_reg=UE_EBP;
        break;
    case 6:
        VF_extra_options_reg=UE_ESI;
        break;
    case 7:
        VF_extra_options_reg=UE_EDI;
        break;
    }
    if(VF_extra_options_reg==0xFFFFFFFF)
        VF_FatalError("Could not determine the register (extradw)");
    free(eip_data);
    SetBPX(and20+eip, UE_BREAKPOINT, (void*)VF_cbExtraDwordRetrieve);
}

void VF_cbExtraVirtualProtect()
{
    OutputDebugStringA("ExtraVirtualProtect");
    DeleteAPIBreakPoint((char*)"kernel32.dll", (char*)"VirtualProtect", UE_APISTART);
    MEMORY_BASIC_INFORMATION mbi= {0};

    unsigned int sec_addr=0;
    unsigned int sec_size=0;
    unsigned int esp_addr=0;
    BYTE* sec_data=0;
    esp_addr=(long)GetContextData(UE_ESP);
    ReadProcessMemory(VF_fdProcessInfo->hProcess, (const void*)((esp_addr)+4), &sec_addr, 4, 0);
    sec_addr-=0x1000;
    VirtualQueryEx(VF_fdProcessInfo->hProcess, (void*)sec_addr, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
    sec_size=mbi.RegionSize;
    sec_data=(BYTE*)malloc(sec_size);
    ReadProcessMemory(VF_fdProcessInfo->hProcess, (const void*)sec_addr, sec_data, sec_size, 0);

    OutputDebugStringA("usbdevice");
    unsigned int usbdevice=FindUsbPattern(sec_data, sec_size);
    if(usbdevice)
    {
        usbdevice+=sec_addr;
        unsigned int usb_push=FindPushAddr(sec_data, sec_size, usbdevice);
        if(!usb_push)
            VF_FatalError("Could not find reference to 'USB Device'");
        unsigned int invalidkey=0;
        for(int i=usb_push; i>0; i--)
        {
            if(sec_data[i]==0x6A and(sec_data[i+1]>>4)==0x00 and sec_data[i+2]==0x6A and(sec_data[i+3]>>4)==0x00 and sec_data[i+4]==0x68)
            {
                invalidkey=i;
                break;
            }
        }
        if(!invalidkey)
            VF_FatalError("Could not find InvalidKey pushes");

        unsigned int extradw_call=0;
        unsigned int dw_extracall=0;

        DISASM MyDisasm;
        memset(&MyDisasm, 0, sizeof(DISASM));
        MyDisasm.EIP=(UIntPtr)sec_data+invalidkey;
        int len=0;
        int call_count=0;
        for(;;)
        {
            len=Disasm(&MyDisasm);
            if(len!=UNKNOWN_OPCODE)
            {
                if(!strncasecmp(MyDisasm.Instruction.Mnemonic, "call", 4))
                    call_count++;
                if(call_count==2)
                    break;
                MyDisasm.EIP=MyDisasm.EIP+(UIntPtr)len;
                if(MyDisasm.EIP>=(unsigned int)sec_data+invalidkey+0x1000) //Safe number (make bigger when needed)
                    break;
            }
            else
                break;
        }
        extradw_call=MyDisasm.EIP-((unsigned int)sec_data);
        memcpy(&dw_extracall, sec_data+extradw_call+1, 4);
        unsigned int extradw_call_dest=(extradw_call+sec_addr)+dw_extracall+5;
        SetBPX(extradw_call_dest, UE_BREAKPOINT, (void*)VF_cbExtraDw);
    }
    else
    {
        MessageBeep(MB_ICONERROR);
        StopDebug();
    }


    free(sec_data);
}

void VF_cbExtraOpenMutexA()
{
    char mutex_name[20]="";
    long mutex_addr=0;
    long esp_addr=0;
    unsigned int return_addr=0;
    DeleteAPIBreakPoint((char*)"kernel32.dll", (char*)"OpenMutexA", UE_APISTART);
    esp_addr=(long)GetContextData(UE_ESP);
    ReadProcessMemory(VF_fdProcessInfo->hProcess, (const void*)esp_addr, &return_addr, 4, 0);
    ReadProcessMemory(VF_fdProcessInfo->hProcess, (const void*)(esp_addr+12), &mutex_addr, 4, 0);
    ReadProcessMemory(VF_fdProcessInfo->hProcess, (const void*)mutex_addr, &mutex_name, 20, 0);
    CreateMutexA(0, FALSE, mutex_name);
    if(GetLastError()==ERROR_SUCCESS)
    {
        SetAPIBreakPoint((char*)"kernel32.dll", (char*)"VirtualProtect", UE_BREAKPOINT, UE_APISTART, (void*)VF_cbExtraVirtualProtect);
    }
    else
    {
        char log_message[256]="";
        sprintf(log_message, "[Fail] Failed to create mutex %s", mutex_name);
        VF_FatalError(log_message);
    }
}

void VF_cbEntry()
{
    if(!VF_fdFileIsDll)
    {
        SetAPIBreakPoint((char*)"kernel32.dll", (char*)"OpenMutexA", UE_BREAKPOINT, UE_APISTART, (void*)VF_cbExtraOpenMutexA);
    }
    else
        SetAPIBreakPoint((char*)"kernel32.dll", (char*)"VirtualProtect", UE_BREAKPOINT, UE_APISTART, (void*)VF_cbExtraVirtualProtect);
}

void VF_ExtraOptions()
{
    OutputDebugStringA("VF_ExtraOptions");
    VF_fdFileIsDll = false;
    VF_fdProcessInfo = NULL;
    FILE_STATUS_INFO inFileStatus = {0};
    if(IsPE32FileValidEx(VF_szFileName, UE_DEPTH_SURFACE, &inFileStatus))
    {
        if(inFileStatus.FileIs64Bit)
        {
            MessageBoxA(VF_shared, "64-bit files are not (yet) supported!", "Error!", MB_ICONERROR);
            return;
        }
        HANDLE hFile, fileMap;
        ULONG_PTR va;
        DWORD bytes_read;
        StaticFileLoad(VF_szFileName, UE_ACCESS_READ, false, &hFile, &bytes_read, &fileMap, &va);
        if(!IsArmadilloProtected(va))
        {
            MessageBoxA(VF_shared, "Not armadillo protected...", "Error!", MB_ICONERROR);
            return;
        }
        StaticFileClose(hFile);
        VF_fdFileIsDll = inFileStatus.FileIsDLL;
        if(!VF_fdFileIsDll)
        {
            VF_fdProcessInfo = (LPPROCESS_INFORMATION)InitDebugEx(VF_szFileName, NULL, NULL, (void*)VF_cbEntry);
        }
        else
        {
            VF_fdProcessInfo = (LPPROCESS_INFORMATION)InitDLLDebug(VF_szFileName, false, NULL, NULL, (void*)VF_cbEntry);
        }
        if(VF_fdProcessInfo)
        {
            DebugLoop();
        }
        else
        {
            MessageBoxA(VF_shared, "Something went wrong during initialization...", "Error!", MB_ICONERROR);
        }
    }
    else
    {
        MessageBoxA(VF_shared, "This is not a valid PE file...", "Error!", MB_ICONERROR);
    }
}

