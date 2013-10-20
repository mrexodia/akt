#include "EVLog_maindlg.h"

char EV_program_dir[256]=""; //program dir

BOOL CALLBACK EV_DlgMain(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch(uMsg)
    {
    case WM_INITDIALOG:
    {
        EV_shared=hwndDlg;
        EV_list_hwnd=GetDlgItem(hwndDlg, IDC_LIST);
    }
    return TRUE;

    case WM_CLOSE:
    {
        EndDialog(hwndDlg, 0);
    }
    return TRUE;

    case WM_BROWSE:
    {
        SendMessageA(EV_list_hwnd, LB_RESETCONTENT, 0, 0);
        strcpy(EV_szFileName, (const char*)wParam);
        strcpy(EV_program_dir, EV_szFileName);
        int i=strlen(EV_program_dir);
        while(EV_program_dir[i]!='\\')
            i--;
        EV_program_dir[i]=0;
        CreateThread(0, 0, EV_DebugThread, 0, 0, 0);
    }
    return TRUE;

    case WM_DROPFILES:
    {
        SendMessageA(EV_list_hwnd, LB_RESETCONTENT, 0, 0);
        DragQueryFileA((HDROP)wParam, 0, EV_szFileName, MAX_PATH);
        strcpy(EV_program_dir, EV_szFileName);
        int i=strlen(EV_program_dir);
        while(EV_program_dir[i]!='\\')
            i--;
        EV_program_dir[i]=0;
        CreateThread(0, 0, EV_DebugThread, 0, 0, 0);
    }
    return TRUE;

    case WM_CONTEXTMENU:
    {
        if(GetDlgCtrlID((HWND)wParam)==IDC_LIST)
        {
            LeftClick();
            LeftClick();
        }
    }
    return TRUE;

    case WM_HELP:
    {
        char id[10]="";
        sprintf(id, "%d", IDS_HELPEVLOG);
        SetEnvironmentVariableA("HELPID", id);
        SetEnvironmentVariableA("HELPTITLE", "EVLog Help");
        DialogBox(hInst, MAKEINTRESOURCE(DLG_HELP), hwndDlg, DlgHelp);
    }
    return TRUE;

    case WM_COMMAND:
    {
        switch(LOWORD(wParam))
        {
        case IDC_LIST:
        {
            switch(HIWORD(wParam))
            {
            case LBN_DBLCLK:
            {
                int cursel=SendMessageA(EV_list_hwnd, LB_GETCURSEL, 0, 0);
                int count=SendMessageA(EV_list_hwnd, LB_GETCOUNT, 0, 0);
                if(!count)
                    return TRUE;
                char line_text[1024]="";
                char var_name[512]="";
                char var_value[512]="";
                SendMessageA(EV_list_hwnd, LB_GETTEXT, cursel, (LPARAM)line_text);
                int len=strlen(line_text);
                for(int i=0,j=0,k=0,l=0; i<len; i++)
                {
                    if(line_text[i]=='=')
                    {
                        i++;
                        j=1;
                    }
                    if(!j)
                        k+=sprintf(var_name+k, "%c", line_text[i]);
                    else
                        l+=sprintf(var_value+l, "%c", line_text[i]);
                }
                HMENU myMenu=0;
                myMenu=CreatePopupMenu();
                AppendMenu(myMenu, MF_STRING, 1, "Copy Variable &Name");
                if(strcmp(var_value, "(0)"))
                    AppendMenu(myMenu, MF_STRING, 2, "Copy Variable &Value");
                AppendMenu(myMenu, MF_STRING, 3, "Copy &Line");
                POINT cursorPos;
                GetCursorPos(&cursorPos);
                SetForegroundWindow(hwndDlg);
                UINT MenuItemClicked=TrackPopupMenu(myMenu, TPM_RETURNCMD|TPM_NONOTIFY, cursorPos.x, cursorPos.y, 0, hwndDlg, 0);
                SendMessage(hwndDlg, WM_NULL, 0, 0);
                switch(MenuItemClicked)
                {
                case 1:
                    CopyToClipboard(var_name);
                    break;
                case 2:
                    CopyToClipboard(var_value);
                    break;
                case 3:
                    CopyToClipboard(line_text);
                    break;
                }
            }
            return TRUE;
            }
        }
        return TRUE;

        case IDC_BTN_DUMP:
        {
            char massive_string[32768]="", single_string[255]="Coded by Mr. eXoDia // T.P.o.D.T 2012\r\n\r\n";
            int total=SendDlgItemMessage(hwndDlg, IDC_LIST, LB_GETCOUNT, 0, 0);
            for(int i=0; i!=total; i++)
            {
                SendDlgItemMessage(hwndDlg, IDC_LIST, LB_GETTEXT, (WPARAM)i, (LPARAM)single_string);
                sprintf(massive_string, "%s%s\r\n", massive_string, single_string);
            }
            char log_filename[MAX_PATH]="";
            log_filename[0]=0;
            OPENFILENAME ofstruct;
            memset(&ofstruct, 0, sizeof(ofstruct));
            ofstruct.lStructSize=sizeof(ofstruct);
            ofstruct.hwndOwner=hwndDlg;
            ofstruct.hInstance=hInst;
            ofstruct.lpstrFilter="Log files (*.log)\0*.log\0\0";
            ofstruct.lpstrFile=log_filename;
            ofstruct.nMaxFile=MAX_PATH;
            ofstruct.lpstrInitialDir=EV_program_dir;
            ofstruct.lpstrTitle="Save file";
            ofstruct.lpstrDefExt="log";
            ofstruct.Flags=OFN_EXTENSIONDIFFERENT|OFN_HIDEREADONLY|OFN_NONETWORKBUTTON|OFN_OVERWRITEPROMPT;
            GetSaveFileName(&ofstruct);
            if(!log_filename[0])
                return TRUE;
            HANDLE hFile=CreateFileA(log_filename, GENERIC_ALL, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
            if(hFile==INVALID_HANDLE_VALUE)
            {
                MessageBoxA(hwndDlg, "Could not create the file, maybe it's in use...", "Error!", MB_ICONERROR);
                return TRUE;
            }
            DWORD written=0;
            if(!WriteFile(hFile, massive_string, strlen(massive_string), &written, 0))
            {
                CloseHandle(hFile);
                MessageBoxA(hwndDlg, "Could not write to the file, maybe it's in use...", "Error!", MB_ICONERROR);
                return TRUE;
            }
            CloseHandle(hFile);
        }
        return TRUE;
        }
    }
    return TRUE;
    }
    return FALSE;
}
