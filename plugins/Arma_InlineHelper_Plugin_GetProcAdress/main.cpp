#include "main.h"

///Plugin details.
char plugin_name[] = "GetProcAddress (5.00+)";
unsigned int imgbase = 0;
unsigned int apis[2] = {0};
char dump[256] = "";

void CopyToClipboard(const char* text) ///Copies a string to the clipboard.
{
    HGLOBAL hText;
    char* pText;

    hText = GlobalAlloc(GMEM_DDESHARE | GMEM_MOVEABLE, strlen(text) + 1);
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

unsigned int FindDwordInMemory(BYTE* dump_addr, unsigned dword_to_find, unsigned int filesize) //Find dword in memory
{
    unsigned int lala = dword_to_find;
    BYTE dword[4] = {0};
    memcpy(dword, &lala, 4);
    for(unsigned int i = 0; i < filesize; i++)
    {
        if(dump_addr[i] == dword[0])
        {
            if(dump_addr[i + 1] == dword[1])
            {
                if(dump_addr[i + 2] == dword[2])
                {
                    if(dump_addr[i + 3] == dword[3])
                    {
                        return i;
                    }
                }
            }
        }
    }
    return 0;
}

void FindPatchAddr()
{
    HANDLE hFile = CreateFileA(dump, GENERIC_ALL, 0, 0, OPEN_EXISTING, 0, 0);
    if(hFile == INVALID_HANDLE_VALUE)
        return;

    DWORD filesize = GetFileSize(hFile, 0);
    BYTE* mem_addr = (BYTE*)malloc(filesize);
    DWORD read = 0;
    if(!ReadFile(hFile, mem_addr, filesize, &read, 0))
    {
        CloseHandle(hFile);
        free(mem_addr);
        return;
    }
    CloseHandle(hFile);
    HINSTANCE k32 = GetModuleHandleA("kernel32.dll");
    unsigned int addr = (unsigned int)GetProcAddress(k32, "LoadLibraryA");
    unsigned int temp = FindDwordInMemory(mem_addr, addr, filesize);
    if(temp)
        apis[0] = temp + imgbase;
    addr = (unsigned int)GetProcAddress(k32, "GetProcAddress");
    temp = FindDwordInMemory(mem_addr, addr, filesize);
    if(temp)
        apis[1] = temp + imgbase;
    free(mem_addr);
    return;
}

BOOL CALLBACK DlgMain(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch(uMsg)
    {
    case WM_INITDIALOG:
    {
        SetDlgItemTextA(hwndDlg, IDC_EDT_DLL, "kernel32.dll");
        FindPatchAddr();
        if(!apis[0] || !apis[1])
        {
            MessageBoxA(hwndDlg, "Something went wrong, try loading a .exe file first...", "Error!", MB_ICONERROR);
            EndDialog(hwndDlg, 0);
            return TRUE;
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
        case IDC_EDT_DLL:
        case IDC_EDT_API:
        {
            char api[256] = "";
            char code[256] = "";
            char message[256] = "";
            char dll[256] = "";
            GetDlgItemTextA(hwndDlg, IDC_EDT_DLL, dll, 256);
            if(!dll[0])
                return TRUE;
            GetDlgItemTextA(hwndDlg, IDC_EDT_API, api, 256);
            if(!api[0])
                return TRUE;
            HMODULE mod = LoadLibraryA(dll);
            if(!mod)
            {
                strcpy(message, " ; Could not load module");
            }
            else
            {
                if(!GetProcAddress(mod, api))
                    strcpy(message, " ; Could not find API");
                FreeLibrary(mod);
            }
            sprintf(code, "call @f%s\r\n\"%s\\0\"\r\n@@:\r\ncall dword ptr ds:[ebp+0x%X] ; lla\r\ncall @f\r\n\"%s\\0\"\r\n@@:\r\npush eax\r\ncall dword ptr ds:[ebp+0x%X] ; gpa",
                    message,
                    dll,
                    apis[0] - imgbase,
                    api,
                    apis[1] - imgbase);
            /*sprintf(code, "jmp @skip_text%s\r\n@dll:\r\n\"%s\\0\"\r\n@import:\r\n\"%s\\0\"\r\n@skip_text:\r\npush @dll\r\ncall dword ptr ds:[0x%X] ; LoadLibraryA\r\npush @import\r\npush eax\r\ncall dword ptr ds:[0x%X] ; GetProcAddress",
                    message, dll, api, apis[0], apis[1]);*/
            SetDlgItemTextA(hwndDlg, IDC_EDT_CODE, code);
        }
        return TRUE;

        case IDC_BTN_COPY:
        {
            char code[256] = "";
            GetDlgItemTextA(hwndDlg, IDC_EDT_CODE, code, 256);
            CopyToClipboard(code);
            SetDlgItemTextA(hwndDlg, IDC_EDT_API, "");
        }
        return TRUE;

        }
    }
    return TRUE;
    }
    return FALSE;
}

DLL_EXPORT const char* PluginInfo(void)
{
    return plugin_name;
}

DLL_EXPORT void PluginFunction(HINSTANCE hInst, HWND hwndDlg, const char* register_vp, const char* program_dir, unsigned int imagebase)
{
    imgbase = imagebase;
    sprintf(dump, "%s\\loaded_binary.mem", program_dir);
    InitCommonControls();
    DialogBox(hInst, MAKEINTRESOURCE(DLG_MAIN), hwndDlg, (DLGPROC)DlgMain);
}

extern "C" BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    return TRUE;
}
