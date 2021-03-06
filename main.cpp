#include "main.h"

char settings_ini[256] = "";
bool start_ontop = false;
int bkColor = GetSysColor(15);
HBRUSH hbr = CreateSolidBrush(bkColor);

typedef BOOL(WINAPI *ChangeWindowMessageFilter_p)(
    _In_ UINT  message,
    _In_ DWORD dwFlag
    );

static BOOL MyChangeWindowMessageFilter(UINT message, DWORD dwFlag)
{
    static ChangeWindowMessageFilter_p func = (ChangeWindowMessageFilter_p)GetProcAddress(GetModuleHandleW(L"user32.dll"), "ChangeWindowMessageFilter");
    return func ? func(message, dwFlag) : FALSE;
}

BOOL CALLBACK DlgMain(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch(uMsg)
    {
    case WM_INITDIALOG:
    {
        char rnd_title[256] = "";
        WORD rnd_word[2] = {0};
        rnd_word[0] = (GetTickCount() & 0xFFFF);
        sprintf(rnd_title, "[%.04X] %s", rnd_word[0]^rnd_word[1], caption);
        SetWindowTextA(hwndDlg, rnd_title);
        SendMessageA(hwndDlg, WM_SETICON, ICON_BIG, (LPARAM)LoadIconA(hInst, MAKEINTRESOURCE(IDI_ICON1)));
        SendMessageA(hwndDlg, WM_SETICON, ICON_SMALL, (LPARAM)LoadIconA(hInst, MAKEINTRESOURCE(IDI_ICON2)));
        InitTabStruct(hwndDlg, IDC_TAB1, true, true);
        SetEngineVariable(UE_ENGINE_NO_CONSOLE_WINDOW, true);
        AddTabbedDialog(hInst, hwndDlg, "KeyGen", DLG_KEYCREATE, KG_DlgKeyGenerate, 0, 1);
        AddTabbedDialog(hInst, hwndDlg, "Analysis", DLG_ANALYSIS, DlgAnalysis, 0, 1);
        AddTabbedDialog(hInst, hwndDlg, "EncDec", DLG_ENCDEC, DlgEncDec, 0, 1);
        AddTabbedDialog(hInst, hwndDlg, "Version", DLG_VERSION, VF_DlgMain, 1, 1);
        AddTabbedDialog(hInst, hwndDlg, "Certs", DLG_CERTTOOL, CT_DlgMain, 1, 1);
        AddTabbedDialog(hInst, hwndDlg, "Inline", DLG_INLINEHELPER, IH_DlgMain, 1, 1);
        AddTabbedDialog(hInst, hwndDlg, "EVLog", DLG_EVLOG, EV_DlgMain, 1, 1);
        //AddTabbedDialog(hInst, hwndDlg, "Nano", DLG_NANO, MSC_DlgMain, 0, 0);
        AddTabbedDialog(hInst, hwndDlg, "Misc", DLG_MISC, MSC_DlgMain, 1, 1);
        //SelectTab(hwndDlg, 4);
        if(start_ontop)
        {
            SetWindowPos(hwndDlg, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
            CheckDlgButton(hwndDlg, IDC_CHK_ONTOP, 1);
        }

        int c_MSGFLT_ALLOW = 1;
        MyChangeWindowMessageFilter(WM_DROPFILES, c_MSGFLT_ALLOW);
        MyChangeWindowMessageFilter(WM_COPYDATA, c_MSGFLT_ALLOW);
        MyChangeWindowMessageFilter(0x0049, c_MSGFLT_ALLOW);
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
        case IDC_CHK_ONTOP:
        {
            NoFocus();
            start_ontop = !!IsDlgButtonChecked(hwndDlg, LOWORD(wParam));
            if(start_ontop)
                SetWindowPos(hwndDlg, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
            else
                SetWindowPos(hwndDlg, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
        }
        return TRUE;

        case IDC_BTN_EXIT:
        {
            NoFocus();
            SendMessageA(hwndDlg, WM_CLOSE, 0, 0);
        }
        return TRUE;

        case IDC_BTN_ABOUT:
        {
            NoFocus();
            DialogBoxA(hInst, MAKEINTRESOURCE(DLG_ABOUT), hwndDlg, DlgAbout);
        }
        return TRUE;

        case IDC_BTN_HELP:
        {
            NoFocus();
            SendMessageA(hwndDlg, WM_HELP, 0, 0);
        }
        return TRUE;
        }
    }
    return TRUE;
    }
    return FALSE;
}

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
    hInst = hInstance;
    InitCommonControls();
    LoadLibrary("riched20.dll");
    GetModuleFileNameA(hInst, sg_szAKTDirectory, 256);
    int i = strlen(sg_szAKTDirectory);
    while(sg_szAKTDirectory[i] != '\\')
        i--;
    sg_szAKTDirectory[i] = 0;
    strcpy(program_dir, sg_szAKTDirectory);
    strcpy(sg_szPluginIniFilePath, sg_szAKTDirectory);
    strcat(sg_szPluginIniFilePath, "\\plugins\\plugins.ini");
    strcpy(sg_loaded_binary, sg_szAKTDirectory);
    strcat(sg_loaded_binary, "\\loaded_binary.mem");
    DeleteFile(sg_loaded_binary);
    strcpy(sg_security_code, sg_szAKTDirectory);
    strcat(sg_security_code, "\\security_code.mem");
    DeleteFile(sg_security_code);
    DeleteFileA(sg_szPluginIniFilePath);
    IH_GetPluginList();
    SetCurrentDirectoryA(sg_szAKTDirectory);

    char setting[10] = "";
    sprintf(settings_ini, "%s\\Armadillo_KeyTool.ini", sg_szAKTDirectory);
    GetPrivateProfileStringA("Settings", "ontop", "", setting, 10, settings_ini);
    if(setting[0] == '1')
        start_ontop = true;

    GetPrivateProfileStringA("Settings", "nologversion", "", setting, 10, settings_ini);
    if(setting[0] == '1')
        log_version = false;

    GetPrivateProfileStringA("Settings", "nologcerttool", "", setting, 10, settings_ini);
    if(setting[0] == '1')
        CT_logtofile = false;

    int retn = DialogBox(hInst, MAKEINTRESOURCE(DLG_MAIN), 0, DlgMain);

    if(start_ontop)
        setting[0] = '1';
    else
        setting[0] = '0';

    WritePrivateProfileStringA("Settings", "ontop", setting, settings_ini);

    if(!CT_logtofile)
        setting[0] = '1';
    else
        setting[0] = '0';
    WritePrivateProfileStringA("Settings", "nologcerttool", setting, settings_ini);

    if(!log_version)
        setting[0] = '1';
    else
        setting[0] = '0';
    WritePrivateProfileStringA("Settings", "nologversion", setting, settings_ini);
    DeleteFile(sg_szPluginIniFilePath);
    DeleteFile(sg_loaded_binary);
    DeleteFile(sg_security_code);
    return retn;
}
