#include "InlineHelper_decrypt.h"

//TODO: Implement this
/*
-get crc vals
-decrypt
-clear adata
-old entry is free space
-original entry is new entry
-set ep to free space
*/

void IHD_FatalError(const char* msg) //TODO: never used
{
    MessageBoxA(IH_shared, msg, "Fatal Error!", MB_ICONERROR);
    ExitProcess(1);
}

unsigned int IHD_FindJump(BYTE* d, unsigned int size, char* reg)
{
    for(unsigned int i=0; i<size; i++) //61FFE?
        if(d[i]==0x61 and d[i+1]==0xFF and(d[i+2]>>4)==0x0E)
        {
            *reg=d[i+2]^0xE0;
            return i+1;
        }
    return 0;
}

void IHD_cbOEP()
{
    unsigned int eip=GetContextData(UE_EIP);
    DeleteBPX(eip);
    int real_ep_section=GetPE32SectionNumberFromVA(IHD_va, eip);
    unsigned int IHD_epsection_raw_offset=GetPE32DataFromMappedFile(IHD_va, real_ep_section, UE_SECTIONRAWOFFSET);
    unsigned int epsection_offset=GetPE32DataFromMappedFile(IHD_va, real_ep_section, UE_SECTIONVIRTUALOFFSET);
    unsigned int epsection_raw_size=GetPE32DataFromMappedFile(IHD_va, real_ep_section, UE_SECTIONRAWSIZE);
    BYTE* new_data=(BYTE*)malloc(epsection_raw_size);
    ReadProcessMemory(IHD_fdProcessInfo->hProcess, (void*)(epsection_offset+IHD_fdImageBase), new_data, epsection_raw_size, 0);
    char newfile[256]="";
    strcpy(newfile, IHD_szFileName);
    newfile[strlen(newfile)-4]=0;
    strcat(newfile, "_.exe");
    CopyFileA(IHD_szFileName, newfile, FALSE);
    HANDLE hFile=CreateFileA(newfile, GENERIC_ALL, 0, 0, OPEN_EXISTING, 0, 0);
    if(hFile==INVALID_HANDLE_VALUE)
    {
        MessageBoxA(0, "Could not open file!", "Fail..", MB_ICONERROR);
        StopDebug();
    }
    OVERLAPPED ovl= {0};
    ovl.Offset=IHD_epsection_raw_offset;
    WriteFile(hFile, new_data, epsection_raw_size, 0, &ovl);
    CloseHandle(hFile);
    free(new_data);
    char msg[256]="";
    sprintf(msg, "New file written to %s.\n\nShould I set a new EP and clear out the old .adata section?", newfile);
    if(MessageBoxA(0, msg, "Question", MB_ICONQUESTION|MB_YESNO)==IDYES)
    {
        SetPE32Data(newfile, 0, UE_OEP, eip-IHD_fdImageBase);
        hFile=CreateFileA(newfile, GENERIC_ALL, 0, 0, OPEN_EXISTING, 0, 0);
        if(hFile==INVALID_HANDLE_VALUE)
        {
            MessageBoxA(0, "Could not open file!", "Fail..", MB_ICONERROR);
            StopDebug();
        }
        BYTE* empty_mem=(BYTE*)malloc(IHD_fdEntrySectionRawSize);
        memset(empty_mem, 0, IHD_fdEntrySectionRawSize);
        memset(&ovl, 0, sizeof(OVERLAPPED));
        ovl.Offset=IHD_fdEntrySectionRawOffset;
        WriteFile(hFile, empty_mem, IHD_fdEntrySectionRawSize, 0, &ovl);
        free(empty_mem);
        CloseHandle(hFile);
    }
    MessageBoxA(0, "All done!", "Done", MB_ICONINFORMATION);
    StopDebug();
}

void IHD_cbJumpOEP()
{
    DeleteBPX(GetContextData(UE_EIP));
    unsigned int final_reg=0;
    switch(IHD_reg)
    {
    case 0:
        final_reg=UE_EAX;
        break;
    case 1:
        final_reg=UE_ECX;
        break;
    case 2:
        final_reg=UE_EDX;
        break;
    case 3:
        final_reg=UE_EBX;
        break;
    case 4:
        final_reg=UE_ESP;
        break;
    case 5:
        final_reg=UE_EBP;
        break;
    case 6:
        final_reg=UE_ESI;
        break;
    case 7:
        final_reg=UE_EDI;
        break;
    }
    SetBPX(GetContextData(final_reg), UE_BREAKPOINT, (void*)IHD_cbOEP);
}

void IHD_cbGuardPage()
{
    unsigned int eip=GetContextData(UE_EIP);
    unsigned int size_read=(IHD_fdEntrySectionOffset+IHD_fdEntrySectionSize+IHD_fdImageBase)-eip;
    BYTE* data=(BYTE*)malloc(size_read);
    ReadProcessMemory(IHD_fdProcessInfo->hProcess, (void*)eip, data, size_read, 0);
    unsigned int bp_addr=IHD_FindJump(data, size_read, &IHD_reg);
    if(!bp_addr)
    {
        MessageBoxA(IH_shared, "Could not find:\n\npushad\njmp [register]\n\nPlease contact Mr. eXoDia.", "Error!", MB_ICONERROR);
        StopDebug();
    }
    free(data);
    SetHardwareBreakPoint(eip+bp_addr, UE_DR0, UE_HARDWARE_EXECUTE, 1, (void*)IHD_cbJumpOEP);
}

void IHD_cbEntry()
{
    HideDebugger(IHD_fdProcessInfo->hProcess, UE_HIDE_BASIC);
    BYTE entry_byte=0;
    ReadProcessMemory(IHD_fdProcessInfo->hProcess, (void*)(IHD_fdEntryPoint+IHD_fdImageBase), &entry_byte, 1, 0);
    if(entry_byte!=0x60)
    {
        MessageBoxA(IH_shared, "The entry section is not encrypted...", "LOL", MB_ICONERROR);
        StopDebug();
    }
    int total_sections=GetPE32Data(IHD_szFileName, 0, UE_SECTIONNUMBER);
    for(int i=0; i<total_sections; i++)
        if(i!=IHD_fdEntrySectionNumber)
            SetMemoryBPXEx((GetPE32Data(IHD_szFileName, i, UE_SECTIONVIRTUALOFFSET)+IHD_fdImageBase), 0x1000, UE_MEMORY_WRITE, false, (void*)IHD_cbGuardPage);
}

DWORD WINAPI IHD_DebugThread(LPVOID lpStartAddress) //TODO: never used
{
    IHD_fdFileIsDll = false;
    IHD_fdImageBase = NULL;
    IHD_fdLoadedBase = NULL;
    IHD_fdEntryPoint = NULL;
    IHD_fdSizeOfImage = NULL;
    IHD_fdProcessInfo = NULL;
    DWORD IH_bytes_read = NULL;
    FILE_STATUS_INFO inFileStatus = {0};
    if(IsPE32FileValidEx(IHD_szFileName, UE_DEPTH_DEEP, &inFileStatus))
    {
        if(inFileStatus.FileIs64Bit)
        {
            MessageBoxA(IH_shared, "64-bit files are not (yet) supported!", "Error!", MB_ICONERROR);
            return 0;
        }
        HANDLE hFile, fileMap;
        IHD_fdImageBase = (long)GetPE32Data(IHD_szFileName, NULL, UE_IMAGEBASE);
        IHD_fdEntryPoint = (long)GetPE32Data(IHD_szFileName, NULL, UE_OEP);
        IHD_fdSizeOfImage = (long)GetPE32Data(IHD_szFileName, NULL, UE_SIZEOFIMAGE);
        StaticFileLoad(IHD_szFileName, UE_ACCESS_READ, false, &hFile, &IH_bytes_read, &fileMap, &IHD_va);
        IHD_fdEntrySectionNumber = GetPE32SectionNumberFromVA(IHD_va, IHD_fdEntryPoint+IHD_fdImageBase);
        CloseHandle(hFile);
        CloseHandle(fileMap);
        IHD_fdEntrySectionSize= (long)GetPE32Data(IHD_szFileName, IHD_fdEntrySectionNumber, UE_SECTIONVIRTUALSIZE);
        IHD_fdEntrySectionRawOffset=GetPE32Data(IHD_szFileName, IHD_fdEntrySectionNumber, UE_SECTIONRAWOFFSET);
        IHD_fdEntrySectionRawSize=GetPE32Data(IHD_szFileName, IHD_fdEntrySectionNumber, UE_SECTIONRAWSIZE);
        IHD_fdEntrySectionOffset = (long)GetPE32Data(IHD_szFileName, IHD_fdEntrySectionNumber, UE_SECTIONVIRTUALOFFSET);
        IHD_fdFileIsDll = inFileStatus.FileIsDLL;
        if(!IHD_fdFileIsDll)
        {
            IHD_fdProcessInfo = (LPPROCESS_INFORMATION)InitDebugEx(IHD_szFileName, NULL, NULL, (void*)IHD_cbEntry);
        }
        else
        {
            IHD_fdProcessInfo = (LPPROCESS_INFORMATION)InitDLLDebug(IHD_szFileName, false, NULL, NULL, (void*)IHD_cbEntry);
        }
        if(IHD_fdProcessInfo)
        {
            DebugLoop();
            return 0;
        }
        else
        {
            MessageBoxA(IH_shared, "Something went wrong during initialization...", "Error!", MB_ICONERROR);
            return 0;
        }
    }
    else
    {
        MessageBoxA(IH_shared, "This is not a valid PE file...", "Error!", MB_ICONERROR);
    }
    return 1;
}
