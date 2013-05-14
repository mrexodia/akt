#include "VersionFind_extraoptions.h"

/**********************************************************************
 *						Module Variables
 *********************************************************************/
// Debugging Variables
static bool g_fdFileIsDll = false;
static LPPROCESS_INFORMATION g_fdProcessInfo;

// Internal Use Variables
static unsigned int g_extra_options_reg=0;
static cbErrorMessage g_ErrorMessageCallback = NULL;

// Output Pointers
static unsigned int* gPtrExtraOptions=0;


/**********************************************************************
 *						Functions
 *********************************************************************/
static void cbDwordRetrieve()
{
    DeleteBPX(GetContextData(UE_EIP));
    *gPtrExtraOptions=GetContextData(g_extra_options_reg);
    StopDebug();
}


static void cbDw()
{
    unsigned int eip=GetContextData(UE_EIP);
    DeleteBPX(eip);
    BYTE* eip_data=(BYTE*)malloc(0x1000);
    ReadProcessMemory(g_fdProcessInfo->hProcess, (void*)eip, eip_data, 0x1000, 0);
    unsigned int and20=VF_FindAnd20Pattern(eip_data, 0x1000);
    if(!and20)
        VF_FatalError("Could not find 'and [reg],20", g_ErrorMessageCallback);
    unsigned int andreg=eip_data[and20+1]&0x0F;
    g_extra_options_reg=0xFFFFFFFF;
    switch(andreg)
    {
    case 0:
        g_extra_options_reg=UE_EAX;
        break;
    case 1:
        g_extra_options_reg=UE_ECX;
        break;
    case 2:
        g_extra_options_reg=UE_EDX;
        break;
    case 3:
        g_extra_options_reg=UE_EBX;
        break;
    case 5:
        g_extra_options_reg=UE_EBP;
        break;
    case 6:
        g_extra_options_reg=UE_ESI;
        break;
    case 7:
        g_extra_options_reg=UE_EDI;
        break;
    }
    if(g_extra_options_reg==0xFFFFFFFF)
        VF_FatalError("Could not determine the register (extradw)", g_ErrorMessageCallback);
    free(eip_data);
    SetBPX(and20+eip, UE_BREAKPOINT, (void*)cbDwordRetrieve);
}


static void cbVirtualProtect()
{
    DeleteAPIBreakPoint((char*)"kernel32.dll", (char*)"VirtualProtect", UE_APISTART);
    MEMORY_BASIC_INFORMATION mbi= {0};

    unsigned int sec_addr=0;
    unsigned int sec_size=0;
    unsigned int esp_addr=0;
    BYTE* sec_data=0;
    esp_addr=(long)GetContextData(UE_ESP);
    ReadProcessMemory(g_fdProcessInfo->hProcess, (const void*)((esp_addr)+4), &sec_addr, 4, 0);
    sec_addr-=0x1000;
    VirtualQueryEx(g_fdProcessInfo->hProcess, (void*)sec_addr, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
    sec_size=mbi.RegionSize;
    sec_data=(BYTE*)malloc(sec_size);
    ReadProcessMemory(g_fdProcessInfo->hProcess, (const void*)sec_addr, sec_data, sec_size, 0);

    unsigned int usbdevice=VF_FindUsbPattern(sec_data, sec_size);
    if(usbdevice)
    {
        usbdevice+=sec_addr;
        unsigned int usb_push=VF_FindPushAddr(sec_data, sec_size, usbdevice);
        if(!usb_push)
            VF_FatalError("Could not find reference to 'USB Device'", g_ErrorMessageCallback);
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
            VF_FatalError("Could not find InvalidKey pushes", g_ErrorMessageCallback);

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
        SetBPX(extradw_call_dest, UE_BREAKPOINT, (void*)cbDw);
    }
    else
    {
        MessageBeep(MB_ICONERROR);
        StopDebug();
    }


    free(sec_data);
}


static void cbOpenMutexA()
{
    char mutex_name[20]="";
    long mutex_addr=0;
    long esp_addr=0;
    unsigned int return_addr=0;
    DeleteAPIBreakPoint((char*)"kernel32.dll", (char*)"OpenMutexA", UE_APISTART);
    esp_addr=(long)GetContextData(UE_ESP);
    ReadProcessMemory(g_fdProcessInfo->hProcess, (const void*)esp_addr, &return_addr, 4, 0);
    ReadProcessMemory(g_fdProcessInfo->hProcess, (const void*)(esp_addr+12), &mutex_addr, 4, 0);
    ReadProcessMemory(g_fdProcessInfo->hProcess, (const void*)mutex_addr, &mutex_name, 20, 0);
    CreateMutexA(0, FALSE, mutex_name);
    if(GetLastError()==ERROR_SUCCESS)
    {
        SetAPIBreakPoint((char*)"kernel32.dll", (char*)"VirtualProtect", UE_BREAKPOINT, UE_APISTART, (void*)cbVirtualProtect);
    }
    else
    {
        char log_message[256]="";
        sprintf(log_message, "[Fail] Failed to create mutex %s", mutex_name);
        VF_FatalError(log_message, g_ErrorMessageCallback);
    }
}


static void cbEntry()
{
    FixIsDebuggerPresent(g_fdProcessInfo->hProcess, true);
    if(!g_fdFileIsDll)
        SetAPIBreakPoint((char*)"kernel32.dll", (char*)"OpenMutexA", UE_BREAKPOINT, UE_APISTART, (void*)cbOpenMutexA);
    else
        SetAPIBreakPoint((char*)"kernel32.dll", (char*)"VirtualProtect", UE_BREAKPOINT, UE_APISTART, (void*)cbVirtualProtect);
}


void VF_ExtraOptions(char* szFileName, unsigned int* extra_options, cbErrorMessage ErrorMessageCallback)
{
    FILE_STATUS_INFO inFileStatus = {0};

    gPtrExtraOptions = extra_options;
    g_fdFileIsDll = false;
    g_fdProcessInfo = NULL;
    g_ErrorMessageCallback = ErrorMessageCallback;

    if(IsPE32FileValidEx(szFileName, UE_DEPTH_SURFACE, &inFileStatus))
    {
        if(inFileStatus.FileIs64Bit)
        {
            ErrorMessageCallback((char*)"64-bit files are not (yet) supported!", (char*)"Error!");
            return;
        }
        HANDLE hFile, fileMap;
        ULONG_PTR va;
        DWORD bytes_read;
        StaticFileLoad(szFileName, UE_ACCESS_READ, false, &hFile, &bytes_read, &fileMap, &va);
        if(!IsArmadilloProtected(va))
        {
            ErrorMessageCallback((char*)"Not armadillo protected...", (char*)"Error!");
            return;
        }
        StaticFileClose(hFile);
        g_fdFileIsDll = inFileStatus.FileIsDLL;
        if(!g_fdFileIsDll)
            g_fdProcessInfo = (LPPROCESS_INFORMATION)InitDebugEx(szFileName, NULL, NULL, (void*)cbEntry);
        else
            g_fdProcessInfo = (LPPROCESS_INFORMATION)InitDLLDebug(szFileName, false, NULL, NULL, (void*)cbEntry);
        if(g_fdProcessInfo)
            DebugLoop();
        else
            ErrorMessageCallback((char*)"Something went wrong during initialization...", (char*)"Error!");
    }
    else
        ErrorMessageCallback((char*)"This is not a valid PE file...", (char*)"Error!");
}
