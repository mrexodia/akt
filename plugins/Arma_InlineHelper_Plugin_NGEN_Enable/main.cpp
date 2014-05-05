#include "main.h"

///Plugin details.
char plugin_name[]="Re-Enable NGEN (v7.20+?)";

///Global variables.
char dll_dump[MAX_PATH]="";
char register_used[10]="";
unsigned int patch_addr=0;
unsigned char register_byte=0;

void CopyToClipboard(const char* text) ///Copies a string to the clipboard.
{
    HGLOBAL hText;
    char *pText;

    hText = GlobalAlloc(GMEM_DDESHARE | GMEM_MOVEABLE, strlen(text)+1);
    pText = (char*)GlobalLock(hText);
    strcpy(pText, text);

    OpenClipboard(0);
    EmptyClipboard();
    if(!SetClipboardData(CF_OEMTEXT, hText))
    {
        MessageBeep(MB_ICONERROR);
    }
    MessageBeep(MB_ICONINFORMATION);
    CloseClipboard();
}

unsigned int FindPattern(BYTE* d, unsigned int size)
{
    for(unsigned int i=0; i<size; i++) //03??????????5?8D??????????5?E8????????83C41485C074
        if(d[i]==0x03 and (d[i+6]>>4)==0x05 and d[i+7]==0x8D and (d[i+13]>>4)==0x05 and d[i+14]==0xE8 and d[i+19]==0x83 and d[i+20]==0xC4 and d[i+21]==0x14 and d[i+22]==0x85 and d[i+23]==0xC0 and d[i+24]==0x74)
            return i+14;
    return 0;
}

unsigned int FindPatchAddr()
{
    HANDLE hFile=CreateFileA(dll_dump, GENERIC_ALL, 0, 0, OPEN_EXISTING, 0, 0);
    if(hFile==INVALID_HANDLE_VALUE)
        return 0;

    DWORD high=0,filesize=GetFileSize(hFile, &high);
    BYTE* mem_addr=(BYTE*)malloc(filesize);
    if(!ReadFile(hFile, mem_addr, filesize, &high, 0))
    {
        CloseHandle(hFile);
        free(mem_addr);
        return 0;
    }
    CloseHandle(hFile);
    unsigned int retn=FindPattern(mem_addr, filesize);
    free(mem_addr);
    return retn;
}

BOOL CALLBACK DlgMain(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch(uMsg)
    {
    case WM_INITDIALOG:
    {
        char code_text[255]="";
        patch_addr=FindPatchAddr();
        if(!patch_addr)
        {
            MessageBoxA(hwndDlg, "Something went wrong, try loading a .exe file first...", "Error!", MB_ICONERROR);
            EndDialog(hwndDlg, 0);
        }
        else
        {
            sprintf(code_text, "lea edi, dword ptr ds:[%s+0%X]\r\nmov word ptr ds:[edi],3EB", register_used, patch_addr);
            SetDlgItemTextA(hwndDlg, IDC_EDT_CODE, code_text);
        }
    }
    return TRUE;

    case WM_CLOSE:
    {
        EndDialog(hwndDlg, 0);
    }
    return TRUE;

    case WM_COMMAND:
    {
        switch(LOWORD(wParam))
        {
        case IDC_BTN_COPY:
        {
            char code_text[255]="";
            GetDlgItemTextA(hwndDlg, IDC_EDT_CODE, code_text, 255);
            CopyToClipboard(code_text);
        }
        return TRUE;
        }
    }
    return TRUE;
    }
    return FALSE;
}

const char* DLL_EXPORT PluginInfo(void)
{
    return plugin_name;
}

void DLL_EXPORT PluginFunction(HINSTANCE hInst, HWND hwndDlg, const char* register_vp, const char* program_dir, unsigned int imagebase)
{
    sprintf(dll_dump, "%s\\security_code.mem", program_dir);
    strcpy(register_used, register_vp);
    InitCommonControls();
    DialogBox(hInst, MAKEINTRESOURCE(DLG_MAIN), hwndDlg, (DLGPROC)DlgMain);
}

extern "C" BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    return TRUE;
}
