#include "about.h"

BOOL CALLBACK DlgAbout(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch(uMsg)
    {
    case WM_INITDIALOG:
    {
        MessageBeep(MB_ICONINFORMATION);
        char stc_txt[50]="";
        sprintf(stc_txt, "%s (%s)", caption, date_compile);
        SetDlgItemTextA(hwndDlg, IDC_STC_TITLE, stc_txt);
    }
    return TRUE;

    case WM_COMMAND:
    {
        switch(LOWORD(wParam))
        {
        case IDC_BTN_OK:
        {
            EndDialog(hwndDlg, 0);
        }
        return TRUE;
        }
    }
    return TRUE;
    }
    return FALSE;
}
