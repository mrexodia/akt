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
        DragQueryFileA((HDROP)wParam, 0, CT_szFileName, MAX_PATH);
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
        strcpy(CT_szStolenKeysRaw, CT_szLogFile);
        strcpy(CT_szStolenKeysLog, CT_szLogFile);
        strcat(CT_szLogFile, "_cert.log");
        strcat(CT_szAktLogFile, "_cert.akt");
        strcat(CT_szCryptCertFile, "_cert.bin");
        strcat(CT_szRawCertFile, "_raw.cert");
        strcat(CT_szStolenKeysRaw, "_stolen.keys");
        strcat(CT_szStolenKeysLog, "_stolenkeys.log");
        SetDlgItemTextA(hwndDlg, IDC_EDT_FILE, CT_szFileName);
    }
    return TRUE;

    case WM_CONTEXTMENU:
    {
        if(GetDlgCtrlID((HWND)wParam)==IDC_LIST_CERT) //double click
        {
            LeftClick();
            LeftClick();
        }
    }
    return TRUE;

    case WM_COMMAND:
    {
        switch(LOWORD(wParam))
        {
        case IDC_LIST_CERT:
        {
            switch(HIWORD(wParam))
            {
            case LBN_DBLCLK: //double/right click
            {
                HWND list=GetDlgItem(hwndDlg, IDC_LIST_CERT);
                int cursel=SendMessageA(list, LB_GETCURSEL, 0, 0);
                char str[256]="";
                SendMessageA(list, LB_GETTEXT, cursel, (LPARAM)str);
                if(!strlen(str) or strstr(str, "Global Information:") or strstr(str, "Public Certificate Information:") or strstr(str, "Intercepted Libraries:"))
                    return TRUE;
                if(strstr(str, "BaseP")) //handle base point (md5, diff, basep)
                {
                    char* b=str+10;
                    unsigned int basep=0;
                    unsigned int size=0;
                    unsigned int diff=0;
                    unsigned int md5=0;
                    sscanf(b, "%u (Size=%X, Diff=%X, MD5=%08X)", &basep, &size, &diff, &md5);
                    HMENU myMenu=0;
                    myMenu=CreatePopupMenu();
                    AppendMenu(myMenu, MF_STRING, 4, "&MD5");
                    AppendMenu(myMenu, MF_STRING, 1, "&BaseP");
                    AppendMenu(myMenu, MF_STRING, 2, "&Size");
                    AppendMenu(myMenu, MF_STRING, 3, "&Diff");
                    POINT cursorPos;
                    GetCursorPos(&cursorPos);
                    SetForegroundWindow(hwndDlg);
                    UINT MenuItemClicked=TrackPopupMenu(myMenu, TPM_RETURNCMD|TPM_NONOTIFY, cursorPos.x, cursorPos.y, 0, hwndDlg, 0);
                    SendMessage(hwndDlg, WM_NULL, 0, 0);
                    switch(MenuItemClicked)
                    {
                    case 1:
                        sprintf(str, "%u", basep);
                        break;
                    case 2:
                        sprintf(str, "%X", size);
                        break;
                    case 3:
                        sprintf(str, "%X", diff);
                        break;
                    case 4:
                        sprintf(str, "%.8X", md5);
                        break;
                    }
                    //sprintf(str, "%u\n%X\n%X\n%.8X", basep, size, diff, md5);
                    //MessageBoxA(hwndDlg, str, "BaseP", 0);
                }
                else if(strstr(str, " Level ")) //handle level
                {
                    int leveladd=-1; //signed v2 is standard
                    if(strstr(str, "Short V3"))
                        leveladd=19;
                    else if(strstr(str, "Signed V3"))
                        leveladd=9;
                    int len=strlen(str)-1;
                    if(str[len]!=':')
                        return TRUE;
                    str[len]=0; //remove ':'
                    len--;
                    while(isdigit(str[len]))
                        len--;
                    int level=0;
                    sscanf(str+len, "%d", &level);
                    level+=leveladd;
                    sprintf(str, "%X", level);
                    //MessageBoxA(hwndDlg, str, "Raw Level (HEX)", 0);
                }
                else if(str[0]==' ' and str[1]==' ' and (str[2]=='+' or str[2]=='-')) //intercepted library
                {
                    strcpy(str, str+3);
                    //MessageBoxA(hwndDlg, str+3, "Library Name", 0);
                }
                else if(str[13]==':') //Global Information
                {
                    strcpy(str, str+15);
                    //MessageBoxA(hwndDlg, str+15, "Global Information", 0);
                }
                else if(str[8]==':') //Certificate Information
                {
                    strcpy(str, str+10);
                    //MessageBoxA(hwndDlg, str+10, "Certificate Information", 0);
                }
                CopyToClipboard(str);
                MessageBeep(MB_ICONINFORMATION);
                //MessageBoxA(hwndDlg, str, "str", 0);
            }
            break;
            }
        }
        return TRUE;

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
