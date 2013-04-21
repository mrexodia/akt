#include "CertTool_dialog.h"

char CT_szProgramDir[256]=""; //debugged program dir

BOOL CALLBACK CT_DlgMain(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch(uMsg)
    {
    case WM_INITDIALOG:
    {
        CT_shared=hwndDlg;
        ShowWindow(GetDlgItem(hwndDlg, IDC_BTN_PAUSE), 0);
        ShowWindow(GetDlgItem(hwndDlg, IDC_STC_STATUS), 0);
        ShowWindow(GetDlgItem(hwndDlg, IDC_PROGRESS_BRUTE), 0);
        CT_brute_initialized=InitializeSymBruteLibrary(hwndDlg);
        CT_brute_dlp_initialized=InitializeDlpBruteLibrary(hwndDlg);
        if(!CT_brute_initialized and !CT_brute_dlp_initialized)
            EnableWindow(GetDlgItem(hwndDlg, IDC_CHK_BRUTE), 0);
        EnableWindow(GetDlgItem(hwndDlg, IDC_BTN_BRUTESETTINGS), 0);
        EnableWindow(GetDlgItem(hwndDlg, IDC_CHK_BRUTESYMVERIFY), 0);
        EnableWindow(GetDlgItem(hwndDlg, IDC_CHK_BRUTENOSYMMETRIC), 0);
        EnableWindow(GetDlgItem(hwndDlg, IDC_CHK_BRUTESHUTDOWN), 0);
        CheckDlgButton(hwndDlg, IDC_CHK_LOGFILE, CT_logtofile);
    }
    return TRUE;

    case WM_HELP:
    {
        char id[10]="";
        sprintf(id, "%d", IDS_HELPCERTTOOL);
        SetEnvironmentVariableA("HELPID", id);
        SetEnvironmentVariableA("HELPTITLE", "Certs Help");
        DialogBox(hInst, MAKEINTRESOURCE(DLG_HELP), hwndDlg, DlgHelp);
    }
    return TRUE;

    case WM_DROPFILES:
    {
        if(CT_isdebugging)
            return TRUE;
        DragQueryFileA((HDROP)wParam, NULL, CT_szFileName, MAX_PATH);
        strcpy(CT_szProgramDir, CT_szFileName);
        int len=strlen(CT_szProgramDir);
        while(CT_szProgramDir[len]!='\\')
            len--;
        CT_szProgramDir[len]=0;
        strcpy(CT_szLogFile, CT_szFileName);
        len=strlen(CT_szLogFile);
        while(CT_szLogFile[len]!='.' and len)
            len--;
        if(len)
            CT_szLogFile[len]=0;
        strcpy(CT_szAktLogFile, CT_szLogFile);
        strcpy(CT_szCryptCertFile, CT_szLogFile);
        strcpy(CT_szRawCertFile, CT_szLogFile);
        strcat(CT_szLogFile, "_cert.log");
        strcat(CT_szAktLogFile, "_cert.akt");
        strcat(CT_szCryptCertFile, "_cert.bin");
        strcat(CT_szRawCertFile, "_raw.cert");
        SetDlgItemTextA(hwndDlg, IDC_EDT_FILE, CT_szFileName);
    }
    return TRUE;

    case WM_COMMAND:
    {
        switch(LOWORD(wParam))
        {
        case IDC_BTN_PAUSE:
        {
            NoFocus();
            char new_title[100]="||";
            if(CT_brute_is_paused)
                CT_brute_is_paused=false;
            else
            {
                strcpy(new_title, ">");
                CT_brute_is_paused=true;
            }
            SetDlgItemTextA(hwndDlg, IDC_BTN_PAUSE, new_title);
        }
        return TRUE;

        case IDC_BTN_BRUTESETTINGS:
        {
            if(CT_isparsing)
                return TRUE;
            NoFocus();
            BruteSettings(hwndDlg);
        }
        return TRUE;

        case IDC_BTN_START:
        {
            NoFocus();
            if(!CT_isdebugging)
                CreateThread(0, 0, CT_FindCertificates, 0, 0, 0);
        }
        return TRUE;

        case IDC_CHK_BRUTESHUTDOWN:
        {
            NoFocus();
            CT_brute_shutdown=IsDlgButtonChecked(hwndDlg, IDC_CHK_BRUTESHUTDOWN);
        }
        return TRUE;

        case IDC_CHK_BRUTESYMVERIFY:
        {
            if(CT_isparsing)
                return TRUE;
            NoFocus();
            CT_brute_symverify=IsDlgButtonChecked(hwndDlg, IDC_CHK_BRUTESYMVERIFY);
        }
        return TRUE;

        case IDC_CHK_BRUTE:
        {
            if(CT_isparsing)
                return TRUE;
            NoFocus();
            CT_brute=IsDlgButtonChecked(hwndDlg, IDC_CHK_BRUTE);
            if(CT_brute_initialized)
            {
                EnableWindow(GetDlgItem(hwndDlg, IDC_CHK_BRUTESHUTDOWN), CT_brute);
                EnableWindow(GetDlgItem(hwndDlg, IDC_CHK_BRUTENOSYMMETRIC), CT_brute);
                EnableWindow(GetDlgItem(hwndDlg, IDC_CHK_BRUTESYMVERIFY), CT_brute);
                EnableWindow(GetDlgItem(hwndDlg, IDC_BTN_BRUTESETTINGS), CT_brute);
            }
        }
        return TRUE;

        case IDC_CHK_BRUTENOSYMMETRIC:
        {
            if(CT_isparsing)
                return TRUE;
            NoFocus();
            CT_brute_nosym=IsDlgButtonChecked(hwndDlg, IDC_CHK_BRUTENOSYMMETRIC);
            CheckDlgButton(hwndDlg, IDC_CHK_BRUTESYMVERIFY, 0);
            CheckDlgButton(hwndDlg, IDC_CHK_BRUTESHUTDOWN, 0);
            if(CT_brute_initialized)
            {
                bool enable=true;
                if(CT_brute_nosym)
                    enable=false;
                EnableWindow(GetDlgItem(hwndDlg, IDC_CHK_BRUTESHUTDOWN), enable);
                EnableWindow(GetDlgItem(hwndDlg, IDC_CHK_BRUTESYMVERIFY), enable);
                EnableWindow(GetDlgItem(hwndDlg, IDC_BTN_BRUTESETTINGS), enable);
            }
        }
        return TRUE;

        case IDC_CHK_LOGFILE:
        {
            if(CT_isparsing)
                return TRUE;
            NoFocus();
            CT_logtofile=IsDlgButtonChecked(hwndDlg, IDC_CHK_LOGFILE);
        }
        return TRUE;
        }
    }
    return TRUE;
    }
    return FALSE;
}
