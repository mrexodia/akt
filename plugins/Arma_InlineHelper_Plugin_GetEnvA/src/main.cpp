#include "main.h"

///Plugin details.
char plugin_name[] = "GetEnv (v8.0+)";

///Global variables.
HWND mainDlg;
HINSTANCE hDllInst;
char dll_dump[MAX_PATH] = "";
char exe_dump[MAX_PATH] = "";
char register_used[10] = "";
char var_text[256] = "";
char val_text[256] = "";
char main_var_text[256] = "";
char main_val_text[256] = "";
char varval_str[512] = "";
unsigned int getenva_function_addr = 0;
unsigned int getenvw_function_addr = 0;
unsigned int getenvironmentvariablea = 0;
unsigned int setenvironmentvariablea = 0;
unsigned int loadlibrarya = 0;
unsigned int getprocaddress = 0;
unsigned int main_list_selected = 0;
unsigned int imgbase = 0;
bool edit_var = false;

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
    CloseClipboard();
}

void FormatTextHex(char* text) ///Formats the entered fingerprint.
{
    char FormatTextHex_format[2048] = "";
    int len = strlen(text);
    for(int i = 0; i < len; i++)
    {
        if((text[i] > 64 && text[i] < 71) || (text[i] > 47 && text[i] < 58))
            sprintf(FormatTextHex_format, "%s%c", FormatTextHex_format, text[i]);
    }
    strcpy(text, FormatTextHex_format);
}

unsigned int FindGetEnvAAddr()
{
    HANDLE hFile = CreateFileA(dll_dump, GENERIC_ALL, 0, 0, OPEN_EXISTING, 0, 0);
    if(hFile == INVALID_HANDLE_VALUE)
        return 0;
    DWORD high = 0, filesize = GetFileSize(hFile, &high);
    BYTE* security_code = (BYTE*)malloc(filesize);
    if(!ReadFile(hFile, security_code, filesize, &high, 0))
    {
        CloseHandle(hFile);
        free(security_code);
        return 0;
    }
    for(unsigned int i = 0; i < filesize; i++) //Pattern : 55 8B EC 83 EC 0C 53 56 57 6A 00 FF 15 ?? ?? ?? ?? 8B 45 08 50
    {
        if(security_code[i] == 0x55 && security_code[i + 1] == 0x8B && security_code[i + 2] == 0xEC && security_code[i + 3] == 0x83 && security_code[i + 4] == 0xEC)
            if(security_code[i + 5] == 0x0C && security_code[i + 6] == 0x53 && security_code[i + 7] == 0x56 && security_code[i + 8] == 0x57 && security_code[i + 9] == 0x6A)
                if(security_code[i + 10] == 0 && security_code[i + 11] == 0xFF && security_code[i + 12] == 0x15 && security_code[i + 17] == 0x8B && security_code[i + 18] == 0x45)
                    if(security_code[i + 19] == 0x08 && security_code[i + 20] == 0x50)
                    {
                        CloseHandle(hFile);
                        free(security_code);
                        return i;
                    }
    }
    if(security_code)
        free(security_code);
    CloseHandle(hFile);
    return 0;
}

unsigned int FindGetEnvWAddr()
{
    HANDLE hFile = CreateFileA(dll_dump, GENERIC_ALL, 0, 0, OPEN_EXISTING, 0, 0);
    if(hFile == INVALID_HANDLE_VALUE)
        return 0;
    DWORD high = 0, filesize = GetFileSize(hFile, &high);
    BYTE* security_code = (BYTE*)malloc(filesize);
    if(!ReadFile(hFile, security_code, filesize, &high, 0))
    {
        CloseHandle(hFile);
        free(security_code);
        return 0;
    }
    for(unsigned int i = 0, j = 0; i < filesize; i++) //Pattern : 55 8B EC 83 EC 0C 53 56 57 6A 00 FF 15 ?? ?? ?? ?? 8B 45 08 50
    {
        if(security_code[i] == 0x55 && security_code[i + 1] == 0x8B && security_code[i + 2] == 0xEC && security_code[i + 3] == 0x83 && security_code[i + 4] == 0xEC)
            if(security_code[i + 5] == 0x0C && security_code[i + 6] == 0x53 && security_code[i + 7] == 0x56 && security_code[i + 8] == 0x57 && security_code[i + 9] == 0x6A)
                if(security_code[i + 10] == 0 && security_code[i + 11] == 0xFF && security_code[i + 12] == 0x15 && security_code[i + 17] == 0x8B && security_code[i + 18] == 0x45)
                    if(security_code[i + 19] == 0x08 && security_code[i + 20] == 0x50)
                    {
                        if(j)
                        {
                            CloseHandle(hFile);
                            free(security_code);
                            return i;

                        }
                        else
                            j++;
                    }
    }
    if(security_code)
        free(security_code);
    CloseHandle(hFile);
    return 0;
}

unsigned int FindDwordInMemory(BYTE* dump_addr, unsigned dword_to_find, unsigned int filesize)
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

void SeperateVarVal(char* val, char* var, const char* varval, int len)
{
    bool var_done = false;
    for(int i = 0; i < len; i++)
    {
        if(varval[i] != '=')
        {
            if(!var_done)
                sprintf(var, "%s%c", var, varval[i]);
            else
                sprintf(val, "%s%c", val, varval[i]);
        }
        else
            var_done = true;
    }
}

void GenerateCode(bool create_env)
{
    char code_text[65536] = "", current_var[256] = "", current_val[256] = "", env_file[32768] = "";
    int j = sprintf(code_text, "lea edi, dword ptr ds:[%s+0%X]\r\nmov byte ptr ds:[edi],0E9\r\nmov eax, dword ptr ds:[ebp+0%X]\r\nsub eax,edi\r\nsub eax,5\r\ninc edi\r\nmov dword ptr ds:[edi], eax\r\nlea edi, dword ptr ds:[%s+0%X]\r\nmov byte ptr ds:[edi],0E9\r\ncall @f\r\n\"kernel32\\0\"\r\n@@:\r\ncall dword ptr ds:[ebp+0%X]\r\ncall @f\r\n\"GetEnvironmentVariableW\\0\"\r\n@@:\r\npush eax\r\ncall dword ptr ds:[ebp+0%X]\r\nsub eax,edi\r\nsub eax,5\r\ninc edi\r\nmov dword ptr ds:[edi], eax\r\nmov ebx,dword ptr ds:[ebp+0%X]\r\n",
                    register_used,
                    getenva_function_addr,
                    getenvironmentvariablea - imgbase,
                    register_used,
                    getenvw_function_addr,
                    loadlibrarya - imgbase,
                    getprocaddress - imgbase,
                    setenvironmentvariablea - imgbase);
    int list_count = SendDlgItemMessageA(mainDlg, IDC_LIST_VARS, LB_GETCOUNT, 0, 0);
    for(int i = 0, k = 0, len = 0; i < list_count; i++)
    {
        len = SendDlgItemMessageA(mainDlg, IDC_LIST_VARS, LB_GETTEXT, i, (LPARAM)varval_str);
        memset(current_val, 0, 256);
        memset(current_var, 0, 256);
        SeperateVarVal(current_val, current_var, varval_str, len);
        k += sprintf(env_file + k, "%s\r\n", varval_str);
        j += sprintf(code_text + j, "call @f\r\n\"%s\\0\"\r\n@@:\r\ncall @f\r\n\"%s\\0\"\r\n@@:\r\ncall ebx\r\n", current_val, current_var);
    }
    int len = strlen(code_text);
    code_text[len - 2] = 0;
    SetDlgItemTextA(mainDlg, IDC_EDT_CODE, code_text);
    DWORD written = 0;
    DeleteFileA("variables.env");
    HANDLE hFile = CreateFileA("variables.env", GENERIC_ALL, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    if(hFile != INVALID_HANDLE_VALUE)
    {
        WriteFile(hFile, env_file, strlen(env_file), &written, 0);
        CloseHandle(hFile);
    }
    EnableWindow(GetDlgItem(mainDlg, IDC_BTN_COPY), TRUE);
}

void SelectionChanged(HWND hwndDlg)
{
    memset(main_val_text, 0, 256);
    memset(main_var_text, 0, 256);
    main_list_selected = SendDlgItemMessageA(hwndDlg, IDC_LIST_VARS, LB_GETCURSEL, 0, 0);
    int len = SendDlgItemMessageA(hwndDlg, IDC_LIST_VARS, LB_GETTEXT, main_list_selected, (LPARAM)varval_str);
    SeperateVarVal(main_val_text, main_var_text, varval_str, len);
}

int Remove0D0A(char* string)
{
    char string2[256] = "";
    int len = strlen(string);
    for(int i = 0; i < len; i++)
    {
        if(string[i] != 0x0D && string[i] != 0x0A)
            sprintf(string2, "%s%c", string2, string[i]);
    }
    strcpy(string, string2);
    return strlen(string);
}

void ReadEnvFile(const char* filename)
{
    char env_file[32768] = "", varval_temp[256] = "";
    HANDLE hFile = CreateFileA(filename, GENERIC_ALL, 0, 0, OPEN_EXISTING, 0, 0);
    if(hFile != INVALID_HANDLE_VALUE)
    {
        DWORD high, filesize = GetFileSize(hFile, &high);
        ReadFile(hFile, env_file, filesize, &high, 0);
        strcat(env_file, "\n");
        int len = strlen(env_file);
        for(int i = 0; i != len; i++)
        {
            if(env_file[i] == 0x0D || env_file[i] == 0x0A)
            {
                if(Remove0D0A(varval_temp))
                    SendDlgItemMessageA(mainDlg, IDC_LIST_VARS, LB_ADDSTRING, 0, (LPARAM)varval_temp);
                varval_temp[0] = 0;
                if(env_file[i + 1] == 0x0A)
                    i++;
            }
            else
            {
                sprintf(varval_temp, "%s%c", varval_temp, env_file[i]);
            }
        }
        SendDlgItemMessageA(mainDlg, IDC_LIST_VARS, LB_SETCURSEL, 0, 0);
        SelectionChanged(mainDlg);
        GenerateCode(false);
        CloseHandle(hFile);
    }
}

BOOL CALLBACK DlgList(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch(uMsg)
    {
    case WM_INITDIALOG:
    {
        EnableWindow(GetDlgItem(hwndDlg, IDC_BTN_SAVE), FALSE);
        if(edit_var)
        {
            SetWindowTextA(hwndDlg, "Edit Variable");
            SetDlgItemTextA(hwndDlg, IDC_EDT_VAR, main_var_text);
            SetDlgItemTextA(hwndDlg, IDC_EDT_VAL, main_val_text);
        }
    }
    return TRUE;

    case WM_CLOSE:
    {
        SetFocus(GetDlgItem(mainDlg, IDC_LIST_VARS));
        EndDialog(hwndDlg, 0);
    }
    return TRUE;

    case WM_COMMAND:
    {
        switch(LOWORD(wParam))
        {
        case IDC_EDT_VAR:
        {
            if(GetDlgItemTextA(hwndDlg, IDC_EDT_VAR, var_text, 256) && GetDlgItemTextA(hwndDlg, IDC_EDT_VAL, val_text, 256))
                EnableWindow(GetDlgItem(hwndDlg, IDC_BTN_SAVE), TRUE);
            else
                EnableWindow(GetDlgItem(hwndDlg, IDC_BTN_SAVE), FALSE);
        }
        return TRUE;

        case IDC_EDT_VAL:
        {
            if(GetDlgItemTextA(hwndDlg, IDC_EDT_VAR, var_text, 256) && GetDlgItemTextA(hwndDlg, IDC_EDT_VAL, val_text, 256))
                EnableWindow(GetDlgItem(hwndDlg, IDC_BTN_SAVE), TRUE);
            else
                EnableWindow(GetDlgItem(hwndDlg, IDC_BTN_SAVE), FALSE);
        }
        return TRUE;

        case IDC_BTN_SAVE:
        {
            char final_text[512] = "";
            sprintf(final_text, "%s=%s", var_text, val_text);
            if(!edit_var)
            {
                SendDlgItemMessageA(mainDlg, IDC_LIST_VARS, LB_ADDSTRING, 0, (LPARAM)final_text);
                main_list_selected = SendDlgItemMessageA(mainDlg, IDC_LIST_VARS, LB_GETCOUNT, 0, 0) - 1;
            }
            else
            {
                SendDlgItemMessageA(mainDlg, IDC_LIST_VARS, LB_DELETESTRING, main_list_selected, 0);
                SendDlgItemMessageA(mainDlg, IDC_LIST_VARS, LB_INSERTSTRING, main_list_selected, (LPARAM)final_text);
            }
            SendDlgItemMessageA(mainDlg, IDC_LIST_VARS, LB_SETCURSEL, main_list_selected, 0);
            SelectionChanged(mainDlg);
            GenerateCode(true);
            SendMessageA(hwndDlg, WM_CLOSE, 0, 0);
        }
        return TRUE;

        case IDC_BTN_CANCEL:
        {
            SendMessageA(hwndDlg, WM_CLOSE, 0, 0);
        }
        return TRUE;
        }
    }
    return TRUE;
    }
    return FALSE;
}

BOOL CALLBACK DlgMain(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch(uMsg)
    {
    case WM_INITDIALOG:
    {
        mainDlg = hwndDlg;
        getenva_function_addr = FindGetEnvAAddr();
        getenvw_function_addr = FindGetEnvWAddr();
        if(!getenva_function_addr || !getenvw_function_addr)
        {
            MessageBoxA(hwndDlg, "Something went wrong, try loading a .exe file first...", "Error!", MB_ICONERROR);
            EndDialog(hwndDlg, 0);
        }
        else
        {
            HANDLE hFile = CreateFileA(exe_dump, GENERIC_ALL, 0, 0, OPEN_EXISTING, 0, 0);
            DWORD high = 0, filesize = GetFileSize(hFile, &high);
            BYTE* dump_addr = (BYTE*)malloc(filesize);
            ReadFile(hFile, dump_addr, filesize, &high, 0);

            getenvironmentvariablea = FindDwordInMemory(dump_addr, (unsigned int)GetProcAddress(GetModuleHandle("kernel32"), "GetEnvironmentVariableA"), filesize);
            if(!getenvironmentvariablea)
            {
                MessageBoxA(hwndDlg, "Something went wrong, try loading a .exe file first...", "Error!", MB_ICONERROR);
                free(dump_addr);
                EndDialog(hwndDlg, 0);
            }
            getenvironmentvariablea += imgbase;
            setenvironmentvariablea = FindDwordInMemory(dump_addr, (unsigned int)GetProcAddress(GetModuleHandle("kernel32"), "SetEnvironmentVariableA"), filesize);
            if(!setenvironmentvariablea)
            {
                MessageBoxA(hwndDlg, "Something went wrong, try loading a .exe file first...", "Error!", MB_ICONERROR);
                free(dump_addr);
                EndDialog(hwndDlg, 0);
            }
            setenvironmentvariablea += imgbase;
            loadlibrarya = FindDwordInMemory(dump_addr, (unsigned int)GetProcAddress(GetModuleHandle("kernel32"), "LoadLibraryA"), filesize);
            if(!loadlibrarya)
            {
                MessageBoxA(hwndDlg, "Something went wrong, try loading a .exe file first...", "Error!", MB_ICONERROR);
                free(dump_addr);
                EndDialog(hwndDlg, 0);
            }
            loadlibrarya += imgbase;
            getprocaddress = FindDwordInMemory(dump_addr, (unsigned int)GetProcAddress(GetModuleHandle("kernel32"), "GetProcAddress"), filesize);
            if(!getprocaddress)
            {
                MessageBoxA(hwndDlg, "Something went wrong, try loading a .exe file first...", "Error!", MB_ICONERROR);
                free(dump_addr);
                EndDialog(hwndDlg, 0);
            }
            getprocaddress += imgbase;
            free(dump_addr);
            CloseHandle(hFile);
            EnableWindow(GetDlgItem(hwndDlg, IDC_BTN_COPY), FALSE);
            ReadEnvFile("variables.env");
        }
    }
    return TRUE;

    case WM_CLOSE:
    {
        EndDialog(hwndDlg, 0);
    }
    return TRUE;

    case WM_DROPFILES:
    {
        char szFileName[MAX_PATH] = "", file_ext[5] = "";
        DragQueryFileA((HDROP)wParam, NULL, szFileName, MAX_PATH);
        strcpy(file_ext, (szFileName + strlen(szFileName) - 4));
        if(!strcmp(file_ext, ".env"))
        {
            ReadEnvFile(szFileName);
        }
    }
    return TRUE;

    case WM_COMMAND:
    {
        switch(LOWORD(wParam))
        {
        case IDC_BTN_ADD:
        {
            edit_var = false;
            DialogBox(hDllInst, MAKEINTRESOURCE(DLG_LIST), hwndDlg, (DLGPROC)DlgList);
        }
        return TRUE;

        case IDC_BTN_EDIT:
        {
            edit_var = true;
            DialogBox(hDllInst, MAKEINTRESOURCE(DLG_LIST), hwndDlg, (DLGPROC)DlgList);
        }
        return TRUE;

        case IDC_BTN_DELETE:
        {
            if(MessageBoxA(hwndDlg, "Are you sure you want to delete this variable from list?", varval_str, MB_ICONQUESTION | MB_YESNO) == IDYES)
            {
                SendDlgItemMessageA(hwndDlg, IDC_LIST_VARS, LB_DELETESTRING, main_list_selected, 0);
                main_list_selected = 0;
                GenerateCode(true);
                int testzero = SendDlgItemMessageA(hwndDlg, IDC_LIST_VARS, LB_GETCOUNT, 0, 0);
                if(!testzero)
                {
                    SetDlgItemTextA(hwndDlg, IDC_EDT_CODE, "");
                    EnableWindow(GetDlgItem(hwndDlg, IDC_BTN_COPY), FALSE);
                }
                else
                {
                    SendDlgItemMessageA(hwndDlg, IDC_LIST_VARS, LB_SETCURSEL, (testzero - 1), 0);
                    SelectionChanged(hwndDlg);
                }
            }
        }
        return TRUE;

        case IDC_BTN_CLEAR:
        {
            if(MessageBoxA(hwndDlg, "Are you sure you want to clear the complete variable list?", "Question", MB_ICONQUESTION | MB_YESNO) == IDYES)
            {
                SetDlgItemTextA(hwndDlg, IDC_EDT_CODE, "");
                EnableWindow(GetDlgItem(hwndDlg, IDC_BTN_COPY), FALSE);
                SendDlgItemMessageA(hwndDlg, IDC_LIST_VARS, LB_RESETCONTENT, main_list_selected, 0);
                main_list_selected = 0;
            }
        }
        return TRUE;

        case IDC_LIST_VARS:
        {
            switch(HIWORD(wParam))
            {
            case LBN_SELCHANGE:
            {
                SelectionChanged(hwndDlg);
            }
            return TRUE;
            }
        }
        return TRUE;

        case IDC_BTN_COPY:
        {
            SetFocus(GetDlgItem(hwndDlg, IDC_EDT_CODE));
            char code_text[65536] = "";
            GetDlgItemTextA(hwndDlg, IDC_EDT_CODE, code_text, 65536);
            CopyToClipboard(code_text);
        }
        return TRUE;

        case IDC_BTN_ABOUT:
        {
            SetFocus(GetDlgItem(hwndDlg, IDC_LIST_VARS));
            MessageBoxA(hwndDlg, "Environment Variable Injection Plugin by Mr. eXoDia", plugin_name, MB_ICONINFORMATION);
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
DLL_EXPORT const char* PluginInfo(void)
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
   imagebase, ImageBase of the selected process.
*/
DLL_EXPORT void PluginFunction(HINSTANCE hInst, HWND hwndDlg, const char* register_vp, const char* program_dir, unsigned int imagebase)
{
    imgbase = imagebase;
    hDllInst = hInst;
    sprintf(dll_dump, "%s\\security_code.mem", program_dir);
    sprintf(exe_dump, "%s\\loaded_binary.mem", program_dir);
    strcpy(register_used, register_vp);
    InitCommonControls();
    DialogBox(hDllInst, MAKEINTRESOURCE(DLG_MAIN), hwndDlg, (DLGPROC)DlgMain);
}

extern "C" BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    return TRUE;
}
