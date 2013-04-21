#include "analysis.h"

int keyinfo_level=0;
unsigned int sym_xorval=0;

BOOL CALLBACK DlgAnalysis(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch(uMsg)
    {
    case WM_INITDIALOG:
    {
        SetLevelList(hwndDlg);
        SetDlgItemTextA(hwndDlg, IDC_EDT_HWID, "0000-0000");
        keyinfo_level=0;
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
        sprintf(id, "%d", IDS_HELPANALYZE);
        SetEnvironmentVariableA("HELPID", id);
        SetEnvironmentVariableA("HELPTITLE", "Analysis Help");
        DialogBox(hInst, MAKEINTRESOURCE(DLG_HELP), hwndDlg, DlgHelp);
    }
    return TRUE;

    case WM_COMMAND:
    {
        switch(LOWORD(wParam))
        {
        case IDC_BTN_ANALYZE:
        {
            NoFocus();
            char keyinfo_name[1024]="";
            char keyinfo_hwid[10]="";
            char keyinfo_key[1024]="";
            unsigned hwid=0;

            GetDlgItemTextA(hwndDlg, IDC_EDT_NAME, keyinfo_name, 1024);
            if(!GetDlgItemTextA(hwndDlg, IDC_EDT_SERIAL, keyinfo_key, 1024))
            {
                SetDlgItemTextA(hwndDlg, IDC_EDT_ADVLOG, "You need to enter a serial!");
                return TRUE;
            }
            int len=GetDlgItemTextA(hwndDlg, IDC_EDT_HWID, keyinfo_hwid, 10);
            if(len)
            {
                FormatHex(keyinfo_hwid);
                sscanf(keyinfo_hwid, "%X", &hwid);
            }

            KeyInformation info= {0};

            if(RetrieveKeyInfo(keyinfo_level, keyinfo_name, hwid, keyinfo_key, &info, hwndDlg, IDC_EDT_ADVLOG))
            {
                char temp[100]="";
                HWND log=GetDlgItem(hwndDlg, IDC_EDT_ADVLOG);
                bool xorsym=false;
                if(hwid)
                {
                    if(!xorsym)
                    {
                        xorsym=true;
                        AddLogMessage(log, "Symmetric key changes:", false);
                    }
                    sprintf(temp, "%.8X^%.8X=%.8X (keytemplateID^hwid=sym)", (unsigned int)info.symkey^hwid, (unsigned int)hwid, (unsigned int)info.symkey);
                    AddLogMessage(log, temp, false);
                }
                if(sym_xorval)
                {
                    if(!xorsym)
                    {
                        xorsym=true; //TODO: remove?
                        AddLogMessage(log, "Symmetric key changes:", false);
                    }
                    sprintf(temp, "%.8X^%.8X=%.8X (sym^xorval=newsym)", (unsigned int)info.symkey, (unsigned int)sym_xorval, (unsigned int)info.symkey^sym_xorval);
                    AddLogMessage(log, temp, false);
                }
                sprintf(temp, "%.8X", (unsigned int)info.symkey^sym_xorval);
                SetDlgItemTextA(hwndDlg, IDC_EDT_SYM, temp);
                sprintf(temp, "%.4d-%.2d-%.2d", info.createdyear, info.createdmonth, info.createdday);
                SetDlgItemTextA(hwndDlg, IDC_EDT_DATE, temp);
                sprintf(temp, "%d", info.otherinfo[0]);
                SetDlgItemTextA(hwndDlg, IDC_EDT_OTHER0, temp);
                sprintf(temp, "%d", info.otherinfo[1]);
                SetDlgItemTextA(hwndDlg, IDC_EDT_OTHER1, temp);
                sprintf(temp, "%d", info.otherinfo[2]);
                SetDlgItemTextA(hwndDlg, IDC_EDT_OTHER2, temp);
                sprintf(temp, "%d", info.otherinfo[3]);
                SetDlgItemTextA(hwndDlg, IDC_EDT_OTHER3, temp);
                sprintf(temp, "%d", info.otherinfo[4]);
                SetDlgItemTextA(hwndDlg, IDC_EDT_OTHER4, temp);
                sprintf(temp, "%.8X", (unsigned int)info.uninstallcode);
                SetDlgItemTextA(hwndDlg, IDC_EDT_UNINSTALLCODE, temp);
                if(info.keystring_length)
                    SetDlgItemTextA(hwndDlg, IDC_EDT_KEYSTRING, info.keystring);
                else
                    SetDlgItemTextA(hwndDlg, IDC_EDT_KEYSTRING, "No KeyString embedded in this key...");
                sprintf(temp, "%d", info.keystring_length);
                SetDlgItemTextA(hwndDlg, IDC_EDT_KEYSTRING_LENGTH, temp);
                SendMessageA(log, WM_VSCROLL, SB_BOTTOM, 0);
            }
        }
        return TRUE;

        case IDC_CHK_DIGITALRIVER: ///Digital River checkbox.
        {
            NoFocus();
            if(IsDlgButtonChecked(hwndDlg, LOWORD(wParam)))
            {
                CheckDlgButton(hwndDlg, IDC_CHK_ESELLERATE, BST_UNCHECKED);
                sym_xorval=0x91827364; ///Official XOR value of DigitalRiver tagged keys...
            }
            else
                sym_xorval=0;
        }
        return TRUE;

        case IDC_CHK_ESELLERATE: ///eSellerate checkbox.
        {
            NoFocus();
            if(IsDlgButtonChecked(hwndDlg, LOWORD(wParam)))
            {
                CheckDlgButton(hwndDlg, IDC_CHK_DIGITALRIVER, BST_UNCHECKED);
                sym_xorval=0x19283746; ///Official XOR value of eSellerate tagged keys...
            }
            else
                sym_xorval=0;
        }
        return TRUE;

        case IDC_COMBO_LEVEL:
        {
            switch(HIWORD(wParam))
            {
            case CBN_SELCHANGE:
            {
                bool isNoSeperator=true;
                keyinfo_level=SendDlgItemMessageA(hwndDlg, LOWORD(wParam), CB_GETCURSEL, 0, 0);
                if(keyinfo_level==1 or keyinfo_level==6 or keyinfo_level==16)
                    isNoSeperator=false;
                bool en=isNoSeperator;
                EnableWindow(GetDlgItem(hwndDlg, IDC_EDT_NAME), en);
                EnableWindow(GetDlgItem(hwndDlg, IDC_EDT_SERIAL), en);
                EnableWindow(GetDlgItem(hwndDlg, IDC_EDT_HWID), en);
                EnableWindow(GetDlgItem(hwndDlg, IDC_BTN_ANALYZE), en);
                EnableWindow(GetDlgItem(hwndDlg, IDC_CHK_DIGITALRIVER), en);
                EnableWindow(GetDlgItem(hwndDlg, IDC_CHK_ESELLERATE), en);

                if(keyinfo_level>1 and keyinfo_level<6)
                    keyinfo_level--;
                else if(keyinfo_level>6 and keyinfo_level<16)
                    keyinfo_level-=2;
                else if(keyinfo_level>16)
                    keyinfo_level-=3;
            }
            return TRUE;
            }
        }
        return TRUE;
        }
    }
    return TRUE;
    }
    return FALSE;
}
