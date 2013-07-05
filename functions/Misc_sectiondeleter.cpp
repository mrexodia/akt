#include "Misc_sectiondeleter.h"

static unsigned int overlay_size=0;
static unsigned char* overlay_dump=0;

bool MSC_SD_IsArmadilloProtected(char* va)
{
    unsigned int* va1=(unsigned int*)(va+0x3c);
    unsigned int pe_offset=*va1;
    char* isarma=(char*)(va+pe_offset+0x1A);
    if(memcmp(isarma, "SR", 2))
        return false;
    return true;
}

bool MSC_SD_DumpOverlay(const char* filename)
{
    HANDLE hFile=CreateFileA(filename, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    if(hFile==INVALID_HANDLE_VALUE)
        return false;
    SetFilePointer(hFile, 0, 0, FILE_BEGIN);
    SetEndOfFile(hFile);
    DWORD written=0;
    if(!WriteFile(hFile, overlay_dump, overlay_size, &written, 0))
    {
        CloseHandle(hFile);
        return false;
    }
    CloseHandle(hFile);
    return true;
}

unsigned int MSC_SD_HasOverlay(char* va, unsigned int filesize)
{
    char a[256];
    strcpy(a,"hasoverlay");
    if(overlay_dump)
        free2(overlay_dump);
    IMAGE_DOS_HEADER *pdh;
    IMAGE_NT_HEADERS *pnth;
    IMAGE_SECTION_HEADER *psh;
    pdh=(IMAGE_DOS_HEADER*)((DWORD)va);
    if(pdh->e_magic!=IMAGE_DOS_SIGNATURE)
        return false;
    pnth=(IMAGE_NT_HEADERS*)((DWORD)va+pdh->e_lfanew);
    if(IsBadReadPtr(pnth, 4))
        return false;
    if(pnth->Signature!=IMAGE_NT_SIGNATURE)
        return false;
    if(pnth->FileHeader.Machine!=IMAGE_FILE_MACHINE_I386)
        return false;
    psh=(IMAGE_SECTION_HEADER*)((DWORD)(pnth)+pnth->FileHeader.SizeOfOptionalHeader+sizeof(IMAGE_FILE_HEADER)+sizeof(DWORD));
    int lastsection=pnth->FileHeader.NumberOfSections-1;
    unsigned int sizeofimage=psh[lastsection].PointerToRawData+psh[lastsection].SizeOfRawData;
    if(sizeofimage==filesize)
        return 0;
    unsigned int overlaysize=filesize-sizeofimage;
    overlay_dump=(unsigned char*)malloc2(overlaysize);
    memcpy(overlay_dump, va+sizeofimage, overlaysize);
    return overlaysize;
}

bool MSC_SD_IsValidPe(char* va)
{
    IMAGE_DOS_HEADER *pdh=(IMAGE_DOS_HEADER*)((DWORD)va);
    if(pdh->e_magic==IMAGE_DOS_SIGNATURE)
    {
        IMAGE_NT_HEADERS *pnth=(IMAGE_NT_HEADERS*)((DWORD)va+pdh->e_lfanew);
        if(!IsBadReadPtr(pnth, 4))
        {
            if(pnth->Signature==IMAGE_NT_SIGNATURE and pnth->FileHeader.Machine==IMAGE_FILE_MACHINE_I386)
                return true;
        }
    }
    return false;
}

bool MSC_SD_RemoveWatermark(HWND hwndDlg)
{
    DWORD read=0;
    HANDLE hFile=CreateFileA(MSC_szFileName, GENERIC_READ|GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
    if(hFile==INVALID_HANDLE_VALUE)
    {
        MessageBoxA(hwndDlg, "Could not open file...", "Error!", MB_ICONERROR);
        return false;
    }
    unsigned int filesize=GetFileSize(hFile, 0);
    char* data=(char*)malloc2(filesize);
    if(!data)
    {
        CloseHandle(hFile);
        MessageBoxA(hwndDlg, "Could not allocate memory...", "Error!", MB_ICONERROR);
        return false;
    }
    if(!ReadFile(hFile, data, filesize, &read, 0))
    {
        free2(data);
        CloseHandle(hFile);
        MessageBoxA(hwndDlg, "Could not read file...", "Error!", MB_ICONERROR);
        return false;
    }
    CloseHandle(hFile);
    if(!DeleteFileA(MSC_szFileName))
    {
        free2(data);
        MessageBoxA(hwndDlg, "Could not delete file...", "Error!", MB_ICONERROR);
        return false;
    }
    IMAGE_DOS_HEADER *pdh=(IMAGE_DOS_HEADER*)((DWORD)data);
    IMAGE_NT_HEADERS *pnth=(IMAGE_NT_HEADERS*)((DWORD)data+pdh->e_lfanew);
    pnth->OptionalHeader.MajorLinkerVersion=0;
    pnth->OptionalHeader.MinorLinkerVersion=0;
    hFile=CreateFileA(MSC_szFileName, GENERIC_READ|GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    if(hFile==INVALID_HANDLE_VALUE)
    {
        free2(data);
        MessageBoxA(hwndDlg, "Could not create file...", "Error!", MB_ICONERROR);
        return false;
    }
    read=0;
    if(!WriteFile(hFile, data, filesize, &read, 0))
    {
        free2(data);
        CloseHandle(hFile);
        MessageBoxA(hwndDlg, "Could not write file...", "Error!", MB_ICONERROR);
        return false;
    }
    CloseHandle(hFile);
    free2(data);
    return true;
}

void MSC_SD_LoadFile(HWND hwndDlg)
{
    HANDLE hFile=CreateFileA(MSC_szFileName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
    if(hFile==INVALID_HANDLE_VALUE)
    {
        MessageBoxA(hwndDlg, "Could not open file...", "Error!", MB_ICONERROR);
        return;
    }
    unsigned int filesize=GetFileSize(hFile, 0);
    char* data=(char*)malloc2(filesize);
    if(!data)
    {
        CloseHandle(hFile);
        MessageBoxA(hwndDlg, "Could not allocate memory...", "Error!", MB_ICONERROR);
        return;
    }
    DWORD read=0;
    if(!ReadFile(hFile, data, filesize, &read, 0))
    {
        free2(data);
        CloseHandle(hFile);
        MessageBoxA(hwndDlg, "Could not read file...", "Error!", MB_ICONERROR);
        return;
    }
    CloseHandle(hFile);

    if(!MSC_SD_IsValidPe(data))
    {
        free2(data);
        MessageBoxA(hwndDlg, "Invalid PE file (64 bit is not supported!)...", "Error!", MB_ICONERROR);
        return;
    }

    SendMessageA(MSC_SD_list, LB_RESETCONTENT, 0, 0);
    IMAGE_DOS_HEADER *pdh=(IMAGE_DOS_HEADER*)((DWORD)data);
    IMAGE_NT_HEADERS *pnth=(IMAGE_NT_HEADERS*)((DWORD)data+pdh->e_lfanew);
    IMAGE_SECTION_HEADER *psh=(IMAGE_SECTION_HEADER*)((DWORD)pnth+0xF8);
    MSC_SD_section_info.resource_section=0;
    char name[256]="";
    for(int i=0; i<pnth->FileHeader.NumberOfSections; i++)
    {
        memset(name, ' ', 8);
        name[8]=0;
        memcpy(name, psh[i].Name, strlen((const char*)psh[i].Name));
        unsigned int va=psh[i].VirtualAddress;
        unsigned int va_next=0;
        if(i==pnth->FileHeader.NumberOfSections-1)
            va_next=0xFFFFFFFF;
        else
            va_next=psh[i+1].VirtualAddress;
        MSC_SD_section_info.isDll=false;
        if(pnth->FileHeader.Characteristics&IMAGE_FILE_DLL)
            MSC_SD_section_info.isDll=true;
        if(pnth->OptionalHeader.AddressOfEntryPoint>=va and pnth->OptionalHeader.AddressOfEntryPoint<va_next)
        {
            MSC_SD_section_info.entry_section=i;
            sprintf(name, "%s EP", name);
        }
        if(va==pnth->OptionalHeader.BaseOfCode)
        {
            MSC_SD_section_info.code_section=i;
            memcpy(&MSC_SD_section_info.code_section_bytes, data+psh[i].Misc.PhysicalAddress, 2);
            sprintf(name, "%s Code", name);
        }
        if(va==pnth->OptionalHeader.DataDirectory[0].VirtualAddress)
        {
            MSC_SD_section_info.export_section=i;
            sprintf(name, "%s Exp", name);
        }
        if(va==pnth->OptionalHeader.DataDirectory[1].VirtualAddress)
        {
            MSC_SD_section_info.import_section=i;
            sprintf(name, "%s Imp", name);
        }
        if(va==pnth->OptionalHeader.DataDirectory[2].VirtualAddress)
        {
            MSC_SD_section_info.resource_section=i;
            sprintf(name, "%s Res", name);
        }
        if(va==pnth->OptionalHeader.DataDirectory[5].VirtualAddress)
        {
            MSC_SD_section_info.relocation_section=i;
            sprintf(name, "%s Reloc", name);
        }
        if(va==pnth->OptionalHeader.DataDirectory[9].VirtualAddress)
        {
            MSC_SD_section_info.tls_section=i;
            sprintf(name, "%s TLS", name);
        }
        SendMessageA(MSC_SD_list, LB_ADDSTRING, 0, (LPARAM)name);
    }
    bool haswatermark=MSC_SD_IsArmadilloProtected(data);
    overlay_size=MSC_SD_HasOverlay(data, filesize);
    bool hasoverlay=false;
    if(overlay_size)
        hasoverlay=true;
    bool continue_analysis=true;
    if(MSC_SD_section_info.resource_section and MSC_SD_section_info.code_section and(MSC_SD_section_info.resource_section>MSC_SD_section_info.code_section))
    {
        if(!haswatermark)
        {
            continue_analysis=false;
            if(MessageBoxA(hwndDlg, "This file has no SiliconRealms watermark, continue section analysis?", "No Watermark Found...", MB_ICONQUESTION|MB_YESNO)==IDYES)
                continue_analysis=true;
        }
        if(continue_analysis)
        {
            BYTE good_bytes[2]= {0x60, 0xE8};
            MSC_SD_section_info.first_arma_section=MSC_SD_section_info.code_section;
            if(!memcpy(good_bytes, &MSC_SD_section_info.code_section_bytes, 2))
                MSC_SD_section_info.first_arma_section--;
            if(MSC_SD_section_info.tls_section and MSC_SD_section_info.isDll)
                MSC_SD_section_info.first_arma_section=MSC_SD_section_info.tls_section+1;
            for(int i=MSC_SD_section_info.first_arma_section; i<MSC_SD_section_info.resource_section; i++)
                SendMessageA(MSC_SD_list, LB_SETSEL, true, i);
        }
    }
    EnableWindow(GetDlgItem(hwndDlg, IDC_CHK_WATERMARK), haswatermark);
    CheckDlgButton(hwndDlg, IDC_CHK_WATERMARK, haswatermark);
    EnableWindow(GetDlgItem(hwndDlg, IDC_CHK_OVERLAY), hasoverlay);
    CheckDlgButton(hwndDlg, IDC_CHK_OVERLAY, hasoverlay);
    free2(data);
    EnableWindow(GetDlgItem(hwndDlg, IDC_BTN_DELETESECTIONS), 1);
}

bool MSC_SD_RemoveSection(HWND hwndDlg, int i)
{
    DWORD read=0;
    HANDLE hFile=CreateFileA(MSC_szFileName, GENERIC_READ|GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
    if(hFile==INVALID_HANDLE_VALUE)
    {
        MessageBoxA(hwndDlg, "Could not open file...", "Error!", MB_ICONERROR);
        return false;
    }
    unsigned int filesize=GetFileSize(hFile, 0);
    char* file=(char*)malloc2(filesize);
    if(!file)
    {
        CloseHandle(hFile);
        MessageBoxA(hwndDlg, "Could not allocate memory...", "Error!", MB_ICONERROR);
        return false;
    }
    memset(file, 0, filesize);
    read=0;
    if(!ReadFile(hFile, file, filesize, &read, 0))
    {
        free2(file);
        CloseHandle(hFile);
        MessageBoxA(hwndDlg, "Could not read file...", "Error!", MB_ICONERROR);
        return false;
    }
    CloseHandle(hFile);

    //Delete the old file
    if(!DeleteFileA(MSC_szFileName))
    {
        free2(file);
        MessageBoxA(hwndDlg, "Could not delete file...", "Error!", MB_ICONERROR);
        return false;
    }

    //Get section data
    IMAGE_DOS_HEADER *pdh=(IMAGE_DOS_HEADER*)((DWORD)file);
    IMAGE_NT_HEADERS *pnth=(IMAGE_NT_HEADERS*)((DWORD)file+pdh->e_lfanew);
    IMAGE_SECTION_HEADER *psh=(IMAGE_SECTION_HEADER*)((DWORD)pnth+0xF8);
    unsigned int raw_offset=psh[i].PointerToRawData;
    unsigned int raw_size=psh[i].SizeOfRawData;

    //Remove section data
    char* file_new=(char*)malloc2(filesize-raw_size);
    if(!file_new)
    {
        free2(file);
        MessageBoxA(hwndDlg, "Could not allocate memory...", "Error!", MB_ICONERROR);
        return false;
    }
    memset(file_new, 0, filesize-raw_size);
    memcpy(file_new, file, raw_offset);
    memcpy(file_new+raw_offset, file+raw_offset+raw_size, filesize-(raw_offset+raw_size));

    //Fix header (set raw size to zero and update other raw offsets)
    pdh=(IMAGE_DOS_HEADER*)((DWORD)file_new);
    pnth=(IMAGE_NT_HEADERS*)((DWORD)file_new+pdh->e_lfanew);
    psh=(IMAGE_SECTION_HEADER*)((DWORD)pnth+0xF8);
    psh[i].SizeOfRawData=0;
    int total_sections_left=pnth->FileHeader.NumberOfSections-i-1;
    if(total_sections_left)
        for(int j=i+1; j<pnth->FileHeader.NumberOfSections; j++)
            psh[j].PointerToRawData-=raw_size;

    //Remove section from header
    unsigned int new_section_size=sizeof(IMAGE_SECTION_HEADER)*pnth->FileHeader.NumberOfSections;
    char* new_section=(char*)malloc2(new_section_size);
    if(!new_section)
    {
        free2(file);
        free2(file_new);
        MessageBoxA(hwndDlg, "Could not allocate memory...", "Error!", MB_ICONERROR);
        return false;
    }
    memset(new_section, 0, new_section_size);
    memcpy(new_section, &psh[0], sizeof(IMAGE_SECTION_HEADER)*i);
    if(total_sections_left)
        memcpy(new_section+sizeof(IMAGE_SECTION_HEADER)*i, &psh[i+1], total_sections_left*sizeof(IMAGE_SECTION_HEADER));
    else
        pnth->OptionalHeader.SizeOfImage-=psh[i].Misc.VirtualSize; //Update sizeofimage when the last section is removed...
    memcpy(&psh[0], new_section, new_section_size);
    free2(new_section);
    if(i and i!=pnth->FileHeader.NumberOfSections-1)
        psh[i-1].Misc.VirtualSize+=raw_size; //Update raw size of previous section (otherwise its invalid pe)
    pnth->FileHeader.NumberOfSections--;

    //Write the new file
    hFile=CreateFileA(MSC_szFileName, GENERIC_READ|GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    if(hFile==INVALID_HANDLE_VALUE)
    {
        free2(file);
        free2(file_new);
        MessageBoxA(hwndDlg, "Could not create file...", "Error!", MB_ICONERROR);
        return false;
    }
    read=0;
    if(!WriteFile(hFile, file_new, filesize-raw_size, &read, 0))
    {
        free2(file);
        free2(file_new);
        CloseHandle(hFile);
        MessageBoxA(hwndDlg, "Could not write file...", "Error!", MB_ICONERROR);
        return false;
    }
    CloseHandle(hFile);
    free2(file);
    free2(file_new);
    return true;
}
