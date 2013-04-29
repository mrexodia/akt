#include "VersionFind_dialog.h"

/**********************************************************************
 *						Module Variables
 *********************************************************************/
static char g_szFileName[256]="";

static char g_version[20];

static unsigned int g_raw_options=0;
static unsigned int g_extra_options=0;
static bool g_minimal;

static HWND g_shared_hwnd;


/**********************************************************************
 *						Functions
 *********************************************************************/
DWORD WINAPI VF_DebugThread(void* lpVoid)
{
    ResetContent(true);
    g_raw_options=0;
    g_extra_options=0;
    g_version[0]=0;
    HWND hwndDlg=g_shared_hwnd;
    char temp[10]="";
    char* log_text=(char*)malloc(4096);
    char log_location[256]="";
    char filename_nopath[256]="";
    memset(log_text, 0, 4096);

    if(!VF_RawOptions(g_szFileName, &g_raw_options, &g_minimal, VF_ErrorMessageCallback))
    {
        free(log_text);
        return 0;
    }

    sprintf(temp, "%.8X", g_raw_options);
    SetDlgItemTextA(hwndDlg, IDC_EDT_RAWOPTIONS, temp);

    VF_Version(g_szFileName, g_version, VF_ErrorMessageCallback);
    SetDlgItemTextA(hwndDlg, IDC_EDT_VERSIONNUM, g_version);

    VF_ExtraOptions(g_szFileName, &g_extra_options, VF_ErrorMessageCallback);
    sprintf(temp, "%.8X", g_extra_options);
    SetDlgItemTextA(hwndDlg, IDC_EDT_EXTRAOPTIONS, temp);

    ARMA_OPTIONS op= {0};
    EXTRA_OPTIONS eo= {0};
    if(g_extra_options)
    {
        FillArmaExtraOptionsStruct(g_extra_options, &eo);
        FillArmaOptionsStruct(g_raw_options, g_version, &op, &eo, g_minimal);
    }
    else
        FillArmaOptionsStruct(g_raw_options, g_version, &op, 0, g_minimal);
    if(g_extra_options or g_raw_options or g_version[0])
    {
        if(log_version)
        {
            strcpy(log_location, g_szFileName);
            int len=strlen(log_location);
            while(len and log_location[len]!='.')
                len--;
            if(len)
            {
                log_location[len]=0;
                sprintf(log_location, "%s_version.log", log_location);
            }
            else
                sprintf(log_location, "%s_version.log", g_szFileName);

            len=strlen(g_szFileName);
            while(g_szFileName[len]!='\\')
                len--;
            strcpy(filename_nopath, g_szFileName+len+1);
            sprintf(log_text, "File:\r\n>%s\r\n", filename_nopath);
        }
        PrintArmaOptionsStruct(&op, log_text, g_raw_options, g_extra_options);
        if(log_version)
        {
            DeleteFileA(log_location);
            HANDLE hFile=CreateFileA(log_location, GENERIC_ALL, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
            if(hFile==INVALID_HANDLE_VALUE)
            {
                if(MessageBoxA(g_shared_hwnd, "Could not write log file, wanna copy the log to clipboard?", "Error", MB_ICONERROR|MB_YESNO)==IDYES)
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

void VF_ErrorMessageCallback(char* szMessage, char* szTitle)
{
    MessageBoxA(g_shared_hwnd, szMessage, szTitle, MB_ICONERROR);
}

BOOL CALLBACK VF_DlgMain(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch(uMsg)
    {
    case WM_INITDIALOG:
    {
        g_shared_hwnd=hwndDlg;
        EnableWin(IDC_BTN_CALCFROMRAW, 0);
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
        DragQueryFileA((HDROP)wParam, NULL, g_szFileName, 256);
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
            if(g_extra_options)
            {
                FillArmaExtraOptionsStruct(g_extra_options, &eo);
                FillArmaOptionsStruct(g_raw_options, g_version, &op, &eo, g_minimal);
            }
            else
                FillArmaOptionsStruct(g_raw_options, g_version, &op, 0, g_minimal);
            PrintArmaOptionsStruct(&op, false, g_raw_options, g_extra_options);
        }
        return TRUE;

        case IDC_EDT_RAWOPTIONS:
        {
            char str[11]="";
            if(GetDlgItemTextA(hwndDlg, IDC_EDT_RAWOPTIONS, str, 10))
            {
                EnableWin(IDC_BTN_CALCFROMRAW, 1);
                sscanf(str, "%X", &g_raw_options);
            }
        }
        return TRUE;

        case IDC_EDT_EXTRAOPTIONS:
        {
            char str[11]="";
            if(GetDlgItemTextA(hwndDlg, IDC_EDT_EXTRAOPTIONS, str, 10))
            {
                EnableWin(IDC_BTN_CALCFROMRAW, 1);
                sscanf(str, "%X", &g_extra_options);
            }
        }
        return TRUE;
        }
    }
    return TRUE;
    }
    return FALSE;
}


void CheckButton(int id)
{
    CheckDlgButton(g_shared_hwnd, id, 1);
}


void UncheckButton(int id)
{
    CheckDlgButton(g_shared_hwnd, id, 0);
}


void EnableWin(int id, bool a)
{
    EnableWindow(GetDlgItem(g_shared_hwnd, id), a);
}


void ResetContent(bool clear_all)
{
    HWND hwndDlg=g_shared_hwnd;
    if(clear_all)
    {
        SetDlgItemTextA(hwndDlg, IDC_EDT_VERSIONNUM, "");
        SetDlgItemTextA(hwndDlg, IDC_EDT_RAWOPTIONS, "");
        SetDlgItemTextA(hwndDlg, IDC_EDT_EXTRAOPTIONS, "");
    }
    EnableWin(IDC_RADIO_ENHANCEDSOFTICE, 1);
    EnableWin(IDC_RADIO_NORMALNOSOFTICE, 1);
    EnableWin(IDC_RADIO_SPLASHNONE, 1);
    EnableWin(IDC_RADIO_SPLASHDEFAULT, 1);
    EnableWin(IDC_RADIO_SPLASHBITMAP, 1);
    EnableWin(IDC_CHK_OTHERNOCLOCKBACK, 1);
    EnableWin(IDC_CHK_OTHERNOCLOCKFORWARD, 1);
    EnableWin(IDC_CHK_OTHERSCREENSAVER, 1);
    EnableWin(IDC_CHK_OTHERDISABLEINFO, 1);
    EnableWin(IDC_CHK_OTHERIGNOREINFO, 1);
    EnableWin(IDC_CHK_OTHERDISABLEREGISTER, 1);
    EnableWin(IDC_CHK_OTHERDISABLEUNREGISTER, 1);
    EnableWin(IDC_CHK_OTHERAUTOREVERT, 1);
    EnableWin(IDC_CHK_STANDARDHWID, 1);
    EnableWin(IDC_CHK_ENHANCEDHWID, 1);
    UncheckButton(IDC_RADIO_MINIMAL);
    UncheckButton(IDC_CHK_IATELIMINATION);
    UncheckButton(IDC_RADIO_STANDARD);
    UncheckButton(IDC_RADIO_DEBUGBLOCKER);
    UncheckButton(IDC_RADIO_COPYMEM2);
    UncheckButton(IDC_CHK_CODESPLICING);
    UncheckButton(IDC_CHK_NANOMITES);
    UncheckButton(IDC_CHK_MEMPROTECTION);
    UncheckButton(IDC_RADIO_BACKUPVARIABLE);
    UncheckButton(IDC_RADIO_BACKUPFIXED);
    UncheckButton(IDC_RADIO_BACKUPMAIN);
    UncheckButton(IDC_RADIO_BACKUPNOKEYS);
    UncheckButton(IDC_RADIO_COMPRESSIONBEST);
    UncheckButton(IDC_RADIO_COMPRESSIONBETTER);
    UncheckButton(IDC_RADIO_COMPRESSIONMINIMAL);
    UncheckButton(IDC_CHK_OTHERDIGITALRIVER);
    UncheckButton(IDC_CHK_OTHERDISABLEUNREGISTER);
    UncheckButton(IDC_CHK_OTHERNOCLOCKFORWARD);
    UncheckButton(IDC_CHK_OTHERNOCLOCKBACK);
    UncheckButton(IDC_CHK_OTHERDONTFALLBACK);
    UncheckButton(IDC_CHK_OTHERDISABLEMONITOR);
    UncheckButton(IDC_CHK_OTHERDISABLEINFO);
    UncheckButton(IDC_CHK_OTHERDISABLEREGISTER);
    UncheckButton(IDC_CHK_OTHERAUTOREVERT);
    UncheckButton(IDC_CHK_OTHERIGNOREINFO);
    UncheckButton(IDC_CHK_OTHERSCREENSAVER);
    UncheckButton(IDC_CHK_OTHERESELLERATE);
    UncheckButton(IDC_CHK_OTHERALLOWONE);
    UncheckButton(IDC_CHK_OTHEREXTERNALENV);
    UncheckButton(IDC_RADIO_SPLASHNONE);
    UncheckButton(IDC_RADIO_SPLASHDEFAULT);
    UncheckButton(IDC_RADIO_SPLASHBITMAP);
    UncheckButton(IDC_RADIO_ENHANCEDSOFTICE);
    UncheckButton(IDC_RADIO_NORMALNOSOFTICE);
    UncheckButton(IDC_CHK_STANDARDHWID);
    UncheckButton(IDC_CHK_ENHANCEDHWID);
}

void PrintArmaOptionsStructGui(ARMA_OPTIONS* op)
{
    bool set_other_options_log=false;
    if(op->raw_options)
    {
        EnableWin(IDC_RADIO_DEBUGBLOCKER, 1);
        EnableWin(IDC_RADIO_MINIMAL, 1);
        EnableWin(IDC_RADIO_STANDARD, 1);
        EnableWin(IDC_RADIO_COPYMEM2, 1);
        EnableWin(IDC_CHK_IATELIMINATION, 1);
        EnableWin(IDC_CHK_CODESPLICING, 1);
        EnableWin(IDC_CHK_NANOMITES, 1);
        EnableWin(IDC_CHK_MEMPROTECTION, 1);
        EnableWin(IDC_RADIO_BACKUPNOKEYS, 1);
        EnableWin(IDC_RADIO_BACKUPMAIN, 1);
        EnableWin(IDC_RADIO_BACKUPFIXED, 1);
        EnableWin(IDC_RADIO_BACKUPVARIABLE, 1);
        EnableWin(IDC_RADIO_COMPRESSIONMINIMAL, 1);
        EnableWin(IDC_RADIO_COMPRESSIONBETTER, 1);
        EnableWin(IDC_RADIO_COMPRESSIONBEST, 1);
        EnableWin(IDC_CHK_OTHEREXTERNALENV, 1);
        EnableWin(IDC_CHK_OTHERALLOWONE, 1);
        EnableWin(IDC_CHK_OTHERDISABLEMONITOR, 1);
        EnableWin(IDC_CHK_OTHERESELLERATE, 1);
        EnableWin(IDC_CHK_OTHERDIGITALRIVER, 1);
        EnableWin(IDC_CHK_OTHERDONTFALLBACK, 1);

        if(op->debug_blocker)
        {
            if(!op->copymem2)
            {
                CheckButton(IDC_RADIO_DEBUGBLOCKER);
            }
        }
        else
        {
            if(op->nosectioncrypt)
            {
                CheckButton(IDC_RADIO_MINIMAL);
            }
            else
            {
                CheckButton(IDC_RADIO_STANDARD);
            }
        }
        if(op->copymem2)
        {
            CheckButton(IDC_RADIO_COPYMEM2);
        }
        if(op->iat_elimination)
        {
            CheckButton(IDC_CHK_IATELIMINATION);
        }
        if(op->code_splicing)
        {
            CheckButton(IDC_CHK_CODESPLICING);
        }
        if(op->nanomites)
        {
            CheckButton(IDC_CHK_NANOMITES);
        }
        if(op->mem_patch_protection)
        {
            CheckButton(IDC_CHK_MEMPROTECTION);
        }
        switch(op->backupkey)
        {
        case BACKUPKEY_NOKEYS:
        {
            CheckButton(IDC_RADIO_BACKUPNOKEYS);
        }
        break;
        case BACKUPKEY_NOBACKUP:
        {
            CheckButton(IDC_RADIO_BACKUPMAIN);
        }
        break;
        case BACKUPKEY_FIXED:
        {
            CheckButton(IDC_RADIO_BACKUPFIXED);
        }
        break;
        case BACKUPKEY_VARIABLE:
        {
            CheckButton(IDC_RADIO_BACKUPVARIABLE);
        }
        break;
        }
        switch(op->compression)
        {
        case COMPRESSION_MINIMAL:
        {
            CheckButton(IDC_RADIO_COMPRESSIONMINIMAL);
        }
        break;
        case COMPRESSION_BETTER:
        {
            CheckButton(IDC_RADIO_COMPRESSIONBETTER);
        }
        break;
        case COMPRESSION_BEST:
        {
            CheckButton(IDC_RADIO_COMPRESSIONBEST);
        }
        break;
        }
        if(op->has_other_options)
        {
            set_other_options_log=true;
            if(op->external_envvars)
            {
                CheckButton(IDC_CHK_OTHEREXTERNALENV);
            }
            if(op->allow_one_copy)
            {
                CheckButton(IDC_CHK_OTHERALLOWONE);
            }
            if(op->disable_monitor)
            {
                CheckButton(IDC_CHK_OTHERDISABLEMONITOR);
            }
            if(op->esellerate)
            {
                CheckButton(IDC_CHK_OTHERESELLERATE);
            }
            if(op->digital_river)
            {
                CheckButton(IDC_CHK_OTHERDIGITALRIVER);
            }
            if(op->dontfallback)
            {
                CheckButton(IDC_CHK_OTHERDONTFALLBACK);
            }
        }
    }
    else
    {
        EnableWin(IDC_RADIO_DEBUGBLOCKER, 0);
        EnableWin(IDC_RADIO_MINIMAL, 0);
        EnableWin(IDC_RADIO_STANDARD, 0);
        EnableWin(IDC_RADIO_COPYMEM2, 0);
        EnableWin(IDC_CHK_IATELIMINATION, 0);
        EnableWin(IDC_CHK_CODESPLICING, 0);
        EnableWin(IDC_CHK_NANOMITES, 0);
        EnableWin(IDC_CHK_MEMPROTECTION, 0);
        EnableWin(IDC_RADIO_BACKUPNOKEYS, 0);
        EnableWin(IDC_RADIO_BACKUPMAIN, 0);
        EnableWin(IDC_RADIO_BACKUPFIXED, 0);
        EnableWin(IDC_RADIO_BACKUPVARIABLE, 0);
        EnableWin(IDC_RADIO_COMPRESSIONMINIMAL, 0);
        EnableWin(IDC_RADIO_COMPRESSIONBETTER, 0);
        EnableWin(IDC_RADIO_COMPRESSIONBEST, 0);
        EnableWin(IDC_CHK_OTHEREXTERNALENV, 0);
        EnableWin(IDC_CHK_OTHERALLOWONE, 0);
        EnableWin(IDC_CHK_OTHERDISABLEMONITOR, 0);
        EnableWin(IDC_CHK_OTHERESELLERATE, 0);
        EnableWin(IDC_CHK_OTHERDIGITALRIVER, 0);
        EnableWin(IDC_CHK_OTHERDONTFALLBACK, 0);
        //disable all
    }
    if(op->extra_options) //Enable everything
    {
        EnableWin(IDC_RADIO_ENHANCEDSOFTICE, 1);
        EnableWin(IDC_RADIO_NORMALNOSOFTICE, 1);
        EnableWin(IDC_RADIO_SPLASHNONE, 1);
        EnableWin(IDC_RADIO_SPLASHDEFAULT, 1);
        EnableWin(IDC_RADIO_SPLASHBITMAP, 1);
        EnableWin(IDC_CHK_OTHERNOCLOCKBACK, 1);
        EnableWin(IDC_CHK_OTHERNOCLOCKFORWARD, 1);
        EnableWin(IDC_CHK_OTHERSCREENSAVER, 1);
        EnableWin(IDC_CHK_OTHERDISABLEINFO, 1);
        EnableWin(IDC_CHK_OTHERIGNOREINFO, 1);
        EnableWin(IDC_CHK_OTHERDISABLEREGISTER, 1);
        EnableWin(IDC_CHK_OTHERDISABLEUNREGISTER, 1);
        EnableWin(IDC_CHK_OTHERAUTOREVERT, 1);
        EnableWin(IDC_CHK_STANDARDHWID, 1);
        EnableWin(IDC_CHK_ENHANCEDHWID, 1);

        if(op->extra_options->no_clockback)
        {
            CheckButton(IDC_CHK_OTHERNOCLOCKBACK);
        }
        if(op->extra_options->no_clockforward)
        {
            CheckButton(IDC_CHK_OTHERNOCLOCKFORWARD);
        }
        if(op->extra_options->screensaver_protocols)
        {
            CheckButton(IDC_CHK_OTHERSCREENSAVER);
        }
        if(op->extra_options->disable_info)
        {
            CheckButton(IDC_CHK_OTHERDISABLEINFO);
        }
        if(op->extra_options->ignore_info)
        {
            CheckButton(IDC_CHK_OTHERIGNOREINFO);
        }
        if(op->extra_options->disable_register)
        {
            CheckButton(IDC_CHK_OTHERDISABLEREGISTER);
        }
        if(op->extra_options->disable_unregister)
        {
            CheckButton(IDC_CHK_OTHERDISABLEUNREGISTER);
        }
        if(op->extra_options->autorevert)
        {
            CheckButton(IDC_CHK_OTHERAUTOREVERT);
        }
        if(op->extra_options->standard_hwid)
        {
            CheckButton(IDC_CHK_STANDARDHWID);
        }
        if(op->extra_options->enhanced_hwid)
        {
            CheckButton(IDC_CHK_ENHANCEDHWID);
        }
        if(op->extra_options->enhanced_softice)
        {
            CheckButton(IDC_RADIO_ENHANCEDSOFTICE);
        }
        else
        {
            CheckButton(IDC_RADIO_NORMALNOSOFTICE);
        }
        switch(op->extra_options->splash_type)
        {
        case SPLASH_NONE:
        {
            CheckButton(IDC_RADIO_SPLASHNONE);
        }
        break;
        case SPLASH_DEFAULT:
        {
            CheckButton(IDC_RADIO_SPLASHDEFAULT);
        }
        break;
        case SPLASH_BITMAP:
        {
            CheckButton(IDC_RADIO_SPLASHBITMAP);
        }
        break;
        }
    }
    else //Disable Everything
    {
        EnableWin(IDC_RADIO_ENHANCEDSOFTICE, 0);
        EnableWin(IDC_RADIO_NORMALNOSOFTICE, 0);
        EnableWin(IDC_RADIO_SPLASHNONE, 0);
        EnableWin(IDC_RADIO_SPLASHDEFAULT, 0);
        EnableWin(IDC_RADIO_SPLASHBITMAP, 0);
        EnableWin(IDC_CHK_OTHERNOCLOCKBACK, 0);
        EnableWin(IDC_CHK_OTHERNOCLOCKFORWARD, 0);
        EnableWin(IDC_CHK_OTHERSCREENSAVER, 0);
        EnableWin(IDC_CHK_OTHERDISABLEINFO, 0);
        EnableWin(IDC_CHK_OTHERIGNOREINFO, 0);
        EnableWin(IDC_CHK_OTHERDISABLEREGISTER, 0);
        EnableWin(IDC_CHK_OTHERDISABLEUNREGISTER, 0);
        EnableWin(IDC_CHK_OTHERAUTOREVERT, 0);
        EnableWin(IDC_CHK_STANDARDHWID, 0);
        EnableWin(IDC_CHK_ENHANCEDHWID, 0);
    }
}

void PrintArmaOptionsStruct(ARMA_OPTIONS* op, char* log, unsigned int raw_options, unsigned int extra_options)
{
    VF_PrintArmaOptionsStructLog(op, log, raw_options, extra_options);
    PrintArmaOptionsStructGui(op);
}
