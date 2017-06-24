#include "main.h"

///Plugin details.
char plugin_name[] = "ECDSA_Verify (v7.40+)";

///Global variables.
char dll_dump[MAX_PATH] = "";
char register_used[10] = "";
unsigned int ecdsaverify_function_addr = 0;

unsigned int FindECDSAVerifyFunctionAddr()
{
    HANDLE hFile = CreateFileA(dll_dump, GENERIC_ALL, 0, 0, OPEN_EXISTING, 0, 0);
    if(hFile == INVALID_HANDLE_VALUE)
        return 0;

    DWORD high = 0, filesize = GetFileSize(hFile, &high);
    BYTE* mem_addr = (BYTE*)malloc(filesize);
    if(!ReadFile(hFile, mem_addr, filesize, &high, 0))
    {
        CloseHandle(hFile);
        free(mem_addr);
        return 0;
    }
    for(unsigned int i = 0; i < filesize; i++) //Pattern: 51 E8 ?? ?? ?? ?? 83 C4 0C F7 D8 1B C0 83 C0 01 5D C3
    {
        if(mem_addr[i] == 0x51)
        {
            if(mem_addr[i + 1] == 0xE8)
            {
                if(mem_addr[i + 6] == 0x83)
                {
                    if(mem_addr[i + 7] == 0xC4)
                    {
                        if(mem_addr[i + 8] == 0x0C)
                        {
                            if(mem_addr[i + 9] == 0xF7)
                            {
                                if(mem_addr[i + 10] == 0xD8)
                                {
                                    if(mem_addr[i + 11] == 0x1B)
                                    {
                                        if(mem_addr[i + 12] == 0xC0)
                                        {
                                            if(mem_addr[i + 13] == 0x83)
                                            {
                                                if(mem_addr[i + 14] == 0xC0)
                                                {
                                                    if(mem_addr[i + 15] == 0x01)
                                                    {
                                                        if(mem_addr[i + 16] == 0x5D)
                                                        {
                                                            if(mem_addr[i + 17] == 0xC3)
                                                            {
                                                                free(mem_addr);
                                                                CloseHandle(hFile);
                                                                return i + 13;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if(mem_addr)
        free(mem_addr);
    CloseHandle(hFile);
    return 0;
}

BOOL CALLBACK DlgMain(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch(uMsg)
    {
    case WM_INITDIALOG:
    {
        char code_text[255] = "";
        ecdsaverify_function_addr = FindECDSAVerifyFunctionAddr();
        if(!ecdsaverify_function_addr)
        {
            MessageBoxA(hwndDlg, "Something went wrong, try loading a .exe file first...", "Error!", MB_ICONERROR);
            EndDialog(hwndDlg, 0);
        }
        else
        {
            sprintf(code_text, "lea edi, dword ptr ds:[%s+0%X]\r\nmov dword ptr ds:[edi],5D40C033", register_used, ecdsaverify_function_addr);
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
    sprintf(dll_dump, "%s\\security_code.mem", program_dir);
    strcpy(register_used, register_vp);
    InitCommonControls();
    DialogBox(hInst, MAKEINTRESOURCE(DLG_MAIN), hwndDlg, (DLGPROC)DlgMain);
}

extern "C" BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    return TRUE;
}
