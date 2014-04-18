#include "encdec.h"

BOOL CALLBACK DlgEncDec(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch(uMsg)
    {
    case WM_INITDIALOG:
    {
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
        sprintf(id, "%d", IDS_HELPKEYFUNCTIONS);
        SetEnvironmentVariableA("HELPID", id);
        SetEnvironmentVariableA("HELPTITLE", "Key Functions Help");
        DialogBox(hInst, MAKEINTRESOURCE(DLG_HELP), hwndDlg, DlgHelp);
    }
    return TRUE;

    case WM_COMMAND:
    {
        switch(LOWORD(wParam))
        {
        case IDC_BTN_DECODE:
        {
            char serial[512]="";
            char keybytes_string[1024]="";
            unsigned char keybytes[512]= {0};
            if(GetDlgItemTextA(hwndDlg, IDC_EDT_ENCODED, serial, 512))
            {
                int keylength=DecodeShortV3(serial, !!IsDlgButtonChecked(hwndDlg, IDC_CHK_LVL10_DECODE), keybytes, 512);
                ByteArrayToString(keybytes, keybytes_string, keylength, 1024);
                SetDlgItemTextA(hwndDlg, IDC_EDT_DECODED, keybytes_string);
                SetFocus(GetDlgItem(hwndDlg, IDC_EDT_DECODED));
            }
        }
        return TRUE;

        case IDC_BTN_ENCODE:
        {
            char keybytes_string[1024]="";
            unsigned char keybytes[512]= {0};
            char serial[512]="";
            if(GetDlgItemTextA(hwndDlg, IDC_EDT_DECODED, keybytes_string, 1024))
            {
                int keylength=StringToByteArray(keybytes_string, keybytes, 512);
                strcpy(serial, EncodeShortV3(keybytes, keylength, !!IsDlgButtonChecked(hwndDlg, IDC_CHK_LVL10_ENCODE)));
                SetDlgItemTextA(hwndDlg, IDC_EDT_ENCODED, serial);
                SetFocus(GetDlgItem(hwndDlg, IDC_EDT_ENCODED));
            }
        }
        return TRUE;

        case IDC_BTN_DECRYPT:
        {
            char encrypted[1024]="";
            unsigned char keybytes[512]= {0};
            char decrypted[1024]="";
            char name[1024]="";
            if(GetDlgItemTextA(hwndDlg, IDC_EDT_ENCRYPTED, encrypted, 1024) and GetDlgItemTextA(hwndDlg, IDC_EDT_NAME_DECRYPT, name, 1024))
            {
                FormatHex(encrypted);
                int keylength=StringToByteArray(encrypted, keybytes, 512);
                EncryptSignedKey(keybytes, keylength, name, 0);
                ByteArrayToString(keybytes, decrypted, keylength, 1024);
                SetDlgItemTextA(hwndDlg, IDC_EDT_DECRYPTED, decrypted);
                SetFocus(GetDlgItem(hwndDlg, IDC_EDT_DECRYPTED));
            }
        }
        return TRUE;

        case IDC_BTN_ENCRYPT:
        {
            char decrypted[1024]="";
            unsigned char keybytes[512]= {0};
            char encrypted[1024]="";
            char name[1024]="";
            if(GetDlgItemTextA(hwndDlg, IDC_EDT_DECRYPTED, decrypted, 1024) and GetDlgItemTextA(hwndDlg, IDC_EDT_NAME_ENCRYPT, name, 1024))
            {
                FormatHex(decrypted);
                int keylength=StringToByteArray(decrypted, keybytes, 512);
                EncryptSignedKey(keybytes, keylength, name, 0);
                ByteArrayToString(keybytes, encrypted, keylength, 1024);
                SetDlgItemTextA(hwndDlg, IDC_EDT_ENCRYPTED, encrypted);
                SetFocus(GetDlgItem(hwndDlg, IDC_EDT_ENCRYPTED));
            }
        }
        return TRUE;
        }
    }
    return TRUE;
    }
    return FALSE;
}
