#include "_global.h"

DWORD WINAPI VF_DebugThread(void* lpVoid)
{
    ResetContent(true);
    VF_raw_options=0;
    VF_extra_options=0;
    VF_version[0]=0;
    HWND hwndDlg=VF_shared;
    char temp[10]="";
    char* log_text=(char*)malloc(4096);
    char log_location[256]="";
    char filename_nopath[256]="";
    memset(log_text, 0, 4096);

    if(!VF_RawOptions())
    {
        free(log_text);
        return 0;
    }

    sprintf(temp, "%.8X", VF_raw_options);
    SetDlgItemTextA(hwndDlg, IDC_EDT_RAWOPTIONS, temp);

    VF_Version();
    SetDlgItemTextA(hwndDlg, IDC_EDT_VERSIONNUM, VF_version);

    VF_ExtraOptions();
    sprintf(temp, "%.8X", VF_extra_options);
    SetDlgItemTextA(hwndDlg, IDC_EDT_EXTRAOPTIONS, temp);

    ARMA_OPTIONS op= {0};
    EXTRA_OPTIONS eo= {0};
    if(VF_extra_options)
    {
        FillArmaExtraOptionsStruct(VF_extra_options, &eo);
        FillArmaOptionsStruct(VF_raw_options, VF_version, &op, &eo);
    }
    else
        FillArmaOptionsStruct(VF_raw_options, VF_version, &op, 0);
    if(VF_extra_options or VF_raw_options or VF_version[0])
    {
        if(log_version)
        {
            strcpy(log_location, VF_szFileName);
            int len=strlen(log_location);
            while(len and log_location[len]!='.')
                len--;
            if(len)
            {
                log_location[len]=0;
                sprintf(log_location, "%s_version.log", log_location);
            }
            else
                sprintf(log_location, "%s_version.log", VF_szFileName);

            len=strlen(VF_szFileName);
            while(VF_szFileName[len]!='\\')
                len--;
            strcpy(filename_nopath, VF_szFileName+len+1);
            sprintf(log_text, "File:\r\n>%s\r\n", filename_nopath);
        }
        PrintArmaOptionsStruct(&op, log_text);
        if(log_version)
        {
            DeleteFileA(log_location);
            HANDLE hFile=CreateFileA(log_location, GENERIC_ALL, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
            if(hFile==INVALID_HANDLE_VALUE)
            {
                if(MessageBoxA(IH_shared, "Could not write log file, wanna copy the log to clipboard?", "Error", MB_ICONERROR|MB_YESNO)==IDYES)
                    CopyToClipboard(log_text);
            }
            else
            {
                DWORD written=0;
                WriteFile(hFile, log_text, strlen(log_text), &written, 0);
                CloseHandle(hFile);
            }
        }
    }
    free(log_text);
    return 0;
}

BOOL CALLBACK VF_DlgMain(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch(uMsg)
    {
    case WM_INITDIALOG:
    {
        VF_shared=hwndDlg;
        ew(IDC_BTN_CALCFROMRAW, 0);
        CheckDlgButton(hwndDlg, IDC_CHK_LOG, log_version);
    }
    return TRUE;

    case WM_CLOSE:
    {
        EndDialog(hwndDlg, 0);
    }
    return TRUE;

    case WM_HELP:
    {
        char id[10]="";
        sprintf(id, "%d", IDS_HELPVERSION);
        SetEnvironmentVariableA("HELPID", id);
        SetEnvironmentVariableA("HELPTITLE", "Version Help");
        DialogBox(hInst, MAKEINTRESOURCE(DLG_HELP), hwndDlg, DlgHelp);
    }
    return TRUE;

    case WM_DROPFILES:
    {
        DragQueryFileA((HDROP)wParam, NULL, VF_szFileName, 256);
        CreateThread(0, 0, VF_DebugThread, 0, 0, 0);
    }
    return TRUE;

    case WM_COMMAND:
    {
        switch(LOWORD(wParam))
        {
        case IDC_CHK_LOG:
        {
            NoFocus();
            log_version=IsDlgButtonChecked(hwndDlg, LOWORD(wParam));
        }
        return TRUE;

        case IDC_BTN_CALCFROMRAW:
        {
            NoFocus();
            ResetContent(false);
            ARMA_OPTIONS op= {0};
            EXTRA_OPTIONS eo= {0};
            if(VF_extra_options)
            {
                FillArmaExtraOptionsStruct(VF_extra_options, &eo);
                FillArmaOptionsStruct(VF_raw_options, VF_version, &op, &eo);
            }
            else
                FillArmaOptionsStruct(VF_raw_options, VF_version, &op, 0);
            PrintArmaOptionsStruct(&op, false);
        }
        return TRUE;

        case IDC_EDT_RAWOPTIONS:
        {
            char str[11]="";
            if(GetDlgItemTextA(hwndDlg, IDC_EDT_RAWOPTIONS, str, 10))
            {
                ew(IDC_BTN_CALCFROMRAW, 1);
                sscanf(str, "%X", &VF_raw_options);
            }
        }
        return TRUE;

        case IDC_EDT_EXTRAOPTIONS:
        {
            char str[11]="";
            if(GetDlgItemTextA(hwndDlg, IDC_EDT_EXTRAOPTIONS, str, 10))
            {
                ew(IDC_BTN_CALCFROMRAW, 1);
                sscanf(str, "%X", &VF_extra_options);
            }
        }
        return TRUE;
        }
    }
    return TRUE;
    }
    return FALSE;
}
