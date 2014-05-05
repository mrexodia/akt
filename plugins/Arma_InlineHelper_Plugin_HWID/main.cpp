#include "main.h"

///Plugin details.
char plugin_name[]="Fingerprint Patcher (v8.0)";

///Global variables.
char dll_dump[MAX_PATH]="";
char register_used[10]="";
unsigned char dword_struct[8]= {0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xC2, 0x08, 0x00};
unsigned int fingerprint_function_addr=0;

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
    CloseClipboard();
}

void FormatTextHex(char* text) ///Formats the entered fingerprint.
{
    char FormatTextHex_format[2048]="";
    int len=strlen(text);
    for(int i=0; i<len; i++)
    {
        if((text[i]>64 and text[i]<71) or (text[i]>47 and text[i]<58))
            sprintf(FormatTextHex_format, "%s%c", FormatTextHex_format, text[i]);
    }
    strcpy(text, FormatTextHex_format);
}

unsigned int FindFingerprintFunctionAddr() ///This function searches the dump of the security DLL code.
{
    HANDLE hFile=CreateFileA(dll_dump, GENERIC_ALL, 0, 0, OPEN_EXISTING, 0, 0);
    if(hFile==INVALID_HANDLE_VALUE)
        return 0;

    DWORD high=0,filesize=GetFileSize(hFile, &high);
    BYTE* security_code=(BYTE*)malloc(filesize);
    if(!ReadFile(hFile, security_code, filesize, &high, 0))
    {
        CloseHandle(hFile);
        free(security_code);
        return 0;
    }
    for(unsigned int i=0; i<filesize; i++) //Pattern : 55 8B EC ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 01 00 00 00 ?? ?? 74
    {
        if(security_code[i]==0x55)
        {
            if(security_code[i+1]==0x8B)
            {
                if(security_code[i+2]==0xEC)
                {
                    if(security_code[i+18]==1)
                    {
                        if(security_code[i+19]==0)
                        {
                            if(security_code[i+20]==0)
                            {
                                if(security_code[i+21]==0)
                                {
                                    if(security_code[i+24]==0x74)
                                    {
                                        CloseHandle(hFile);
                                        free(security_code);
                                        return i;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if(security_code)
        free(security_code);
    CloseHandle(hFile);
    return 0;
}

BOOL CALLBACK DlgMain(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) ///Dialog callback.
{
    switch(uMsg)
    {
    case WM_INITDIALOG:
    {
        fingerprint_function_addr=FindFingerprintFunctionAddr();
        if(!fingerprint_function_addr)
        {
            MessageBoxA(hwndDlg, "Something went wrong, try loading a .exe file first...", "Error!", MB_ICONERROR);
            EndDialog(hwndDlg, 0);
        }
        else
            EnableWindow(GetDlgItem(hwndDlg, IDC_BTN_COPY), FALSE);
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
        case IDC_EDT_HWID:
        {
            char hwid_text[10]="";
            char code_text[255]="";
            GetDlgItemTextA(hwndDlg, IDC_EDT_HWID, hwid_text, 10);
            FormatTextHex(hwid_text);
            unsigned int* struct_addr=(unsigned int*)dword_struct;
            if(hwid_text[0])
            {
                sscanf(hwid_text, "%X", (unsigned int*)(dword_struct+1));
                sprintf(code_text, "lea edi, dword ptr ds:[%s+0%X]\r\nmov dword ptr ds:[edi],0%.08X\r\nlea edi, dword ptr ds:[edi+4]\r\nmov dword ptr ds:[edi],0%.08X", register_used, fingerprint_function_addr, struct_addr[0], struct_addr[1]);
                EnableWindow(GetDlgItem(hwndDlg, IDC_BTN_COPY), TRUE);
                SetDlgItemTextA(hwndDlg, IDC_EDT_CODE, code_text);
            }
            else
            {
                EnableWindow(GetDlgItem(hwndDlg, IDC_BTN_COPY), FALSE);
                SetDlgItemTextA(hwndDlg, IDC_EDT_CODE, "");
            }
        }
        return TRUE;

        case IDC_BTN_COPY:
        {
            char code_text[255]="";
            GetDlgItemTextA(hwndDlg, IDC_EDT_CODE, code_text, 255);
            CopyToClipboard(code_text);
        }
        return TRUE;

        case IDC_BTN_ABOUT:
        {
            MessageBoxA(hwndDlg, "Sample plugin, created by Mr. eXoDia", plugin_name, MB_ICONINFORMATION);
        }
        return TRUE;
        }
    }
    return TRUE;
    }
    return FALSE;
}

/**
Description:
   Make this function return the name to display in the plugin menu.
Arguments:
   None.
*/
const char* DLL_EXPORT PluginInfo(void)
{
    return plugin_name;
}

/**
Description:
   This is the function that is called when the user clicks a menu entry.
Arguments:
   hInst, used for creating dialogs.
   hwndDlg, the HWND of the main dialog (for message boxes or child dialogs).
   register_vp string of the register that has the security base in VirtualProtect.
   program_dir the directory of ArmaInlineHelper.exe, use to get paths to the dumps.
   imagebase ImageBase of the selected process.
*/
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
