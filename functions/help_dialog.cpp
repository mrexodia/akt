#include "help_dialog.h"

bool help_open = false;

BOOL CALLBACK DlgHelp(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch(uMsg)
    {
    case WM_INITDIALOG:
    {
        SendMessageA(hwndDlg, WM_SETICON, ICON_BIG, (LPARAM)LoadIconA(hInst, MAKEINTRESOURCE(IDI_ICON1)));
        char help_text[4096] = "";
        char help_title[2048] = "";
        if(!GetEnvironmentVariableA("HELPID", help_text, 2048) || !GetEnvironmentVariableA("HELPTITLE", help_title, 2048) || help_open)
        {
            EndDialog(hwndDlg, 0);
            return TRUE;
        }
        help_open = true;
        SetWindowTextA(hwndDlg, help_title);
        int id = 0;
        sscanf(help_text, "%d", &id);
        if(!id)
        {
            EndDialog(hwndDlg, 0);
            return TRUE;
        }
        if(!LoadStringA(hInst, id, help_text, 4096))
        {
            EndDialog(hwndDlg, 0);
            return TRUE;
        }
        SetDlgItemTextA(hwndDlg, IDC_EDT_HELPTEXT, help_text);
    }
    return TRUE;

    case WM_CLOSE:
    {
        help_open = false;
        EndDialog(hwndDlg, 0);
    }
    return TRUE;
    }
    return FALSE;
}
