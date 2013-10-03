#include "keygenerate.h"

int keygenerate_level=0;
unsigned int keygenerate_sym_xorval=0;
HBRUSH br_static=CreateSolidBrush(GetSysColor(15));

void KG_GenerateEcdsaParameters(const char* encryptiontemplate, char* private_text, char* basepoint_text, char* public_x_text, char* public_y_text)
{
    EC_PARAMETER Base;
    EC_KEYPAIR Signer;
    ECC_POINT temp;
    char encryption_template[512];
    char rndinitstring[1024];
    unsigned long i[4];
    unsigned int basepointinit;
    BigInt test=BigInt_Create();
    BigInt secretkeyhash=BigInt_Create();
    BigInt prime_order=BigInt_Create();
    CookText(encryption_template, encryptiontemplate);
    md5(i, encryption_template, strlen(encryption_template));
    basepointinit=i[0];
    sprintf(basepoint_text, "%u", basepointinit);
    ECC_InitializeTable();
    BigInt_FromString(ECC_PRIMEORDER, 10, prime_order);
    BigIntToField(prime_order, &Base.pnt_order);
    Field_Clear(&Base.cofactor);
    Base.cofactor.e[ECC_NUMWORD]=2;
    Base.crv.form=1;
    Field_Set(&Base.crv.a2);
    Field_Set(&Base.crv.a6);
    InitRandomGenerator(basepointinit);
    ECC_RandomPoint(&temp, &Base.crv);
    ECC_PointDouble(&temp, &Base.pnt, &Base.crv);
    strcpy(rndinitstring, encryption_template);
    strcat(rndinitstring, "PVTKEY");
    BigInt_Hash(rndinitstring, strlen(rndinitstring), secretkeyhash);
    ECC_KeyGenerationPrimitive(&Base, &Signer, secretkeyhash);
    FieldToBigInt(&Signer.pblc_key.x, test);
    BigInt_ToString(test, 10, public_x_text);
    FieldToBigInt(&Signer.pblc_key.y, test);
    BigInt_ToString(test, 10, public_y_text);
    FieldToBigInt(&Signer.prvt_key, test);
    BigInt_ToString(test, 10, private_text);
    BigInt_Destroy(test);
    BigInt_Destroy(secretkeyhash);
    BigInt_Destroy(prime_order);
}

bool KG_GeneratePvtY(int level, char* keytemplate, char* pvt_text, char* y_text)
{
    char tmp[256]="";
    BigInt p, p1, pub, pvt, y, temp, temp2;
    int size, keysystem;
    if(level==29)
    {
        char basepoint_text[10]="", public_x_text[100]="", public_y_text[100]="";
        KG_GenerateEcdsaParameters(keytemplate, pvt_text, basepoint_text, public_x_text, public_y_text);
        sprintf(y_text, "%s,%s,%s", basepoint_text, public_x_text, public_y_text);
        return true;
    }
    else if(level>=20)
    {
        keysystem=KS_SHORTV3;
        level=level-20;
        if(level>8)
            return false;
    }
    else if(level>=10)
    {
        keysystem=KS_V3;
        level=level-10;
        if(level>8)
            return false;
    }
    else
    {
        keysystem=KS_V2;
        if(level<0 or level>3)
            return false;
    }
    size=level+4;
    p=BigInt_Create();
    p1=BigInt_Create();
    pub=BigInt_Create();
    pvt=BigInt_Create();
    y=BigInt_Create();
    temp=BigInt_Create();
    temp2=BigInt_Create();
    BigInt_Set(temp, 1);
    BigInt_Shift(temp, size*8, p);
    BigInt_Set(temp, primeoffsets[level]);
    BigInt_Add(p, temp, temp2);
    BigInt_Copy(p, temp2);
    BigInt_Subtract(p, BigInt_One(), p1);
    sprintf(tmp, "%u Level Public Key", level);
    GenerateKeyNumberFromString(tmp, p, &pub, keysystem, ((keysystem==KS_V3 || keysystem==KS_SHORTV3) ? level+1 : 0));
    GenerateKeyNumberFromString(keytemplate, p, &pvt, keysystem, ((keysystem==KS_V3 || keysystem==KS_SHORTV3) ? level+1 : 0));
    BigInt_ToString(pvt, 16, pvt_text);
    BigInt_PowerModulus(pub, pvt, p, y);
    BigInt_ToString(y, 16, y_text);
    BigInt_Destroy(temp2);
    BigInt_Destroy(temp);
    BigInt_Destroy(y);
    BigInt_Destroy(pvt);
    BigInt_Destroy(pub);
    BigInt_Destroy(p1);
    BigInt_Destroy(p);
    return true;
}

unsigned int KG_GenerateSymmetric(int level, char* encryption_template)
{
    char temp[512]="";
    unsigned long i[4]= {0};
    CookText(temp, encryption_template);
    if(level>=20)
    {
        GetKeyMD5(i, temp, 0);
        return (i[0]^i[1]);
    }
    return crc32(temp, strlen(temp), NewCRC32);
}

BOOL CALLBACK KG_DlgKeyGenerate(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch(uMsg)
    {
    case WM_INITDIALOG:
    {
        SetLevelList(hwndDlg);
        SetDlgItemTextA(hwndDlg, IDC_EDT_HWID, "0000-0000");
        bool en=false;
        EnableWindow(GetDlgItem(hwndDlg, IDC_EDT_OTHER1), en);
        EnableWindow(GetDlgItem(hwndDlg, IDC_EDT_OTHER2), en);
        EnableWindow(GetDlgItem(hwndDlg, IDC_EDT_OTHER3), en);
        EnableWindow(GetDlgItem(hwndDlg, IDC_EDT_OTHER4), en);
        EnableWindow(GetDlgItem(hwndDlg, IDC_EDT_KEYSTRING), en);
        EnableWindow(GetDlgItem(hwndDlg, IDC_EDT_PVT), en);
        EnableWindow(GetDlgItem(hwndDlg, IDC_EDT_Y), en);
        ShowWindow(GetDlgItem(hwndDlg, IDC_CHK_BABOON), 0);
        keygenerate_level=-1;
        SYSTEMTIME systime= {0};
        GetSystemTime(&systime);
        char temp[20]="";
        sprintf(temp, "%d", MakeDate(systime.wYear, systime.wMonth, systime.wDay));
        SetDlgItemTextA(hwndDlg, IDC_EDT_DATE, temp);
        sprintf(temp, "%.4d-%.2d-%.2d", systime.wYear, systime.wMonth, systime.wDay);
        SetDlgItemTextA(hwndDlg, IDC_EDT_DATEYMD, temp);
        SendDlgItemMessageA(hwndDlg, IDC_EDT_KEYSTRING, EM_SETLIMITTEXT, 255, 0);
    }
    return TRUE;

    case WM_CONTEXTMENU:
    {
        if(GetDlgCtrlID((HWND)wParam)==IDC_EDT_SERIAL)
        {
            char serial[2048]="";
            int len=GetDlgItemTextA(hwndDlg, IDC_EDT_SERIAL, serial, 2048);
            if(!len)
                return TRUE;
            HMENU myMenu=0;
            myMenu=CreatePopupMenu();
            AppendMenu(myMenu, MF_STRING, 1, "Copy Serial");
            POINT cursorPos;
            GetCursorPos(&cursorPos);
            SetForegroundWindow(hwndDlg);
            UINT MenuItemClicked=TrackPopupMenu(myMenu, TPM_RETURNCMD|TPM_NONOTIFY, cursorPos.x, cursorPos.y, 0, hwndDlg, 0);
            SendMessage(hwndDlg, WM_NULL, 0, 0);
            if(MenuItemClicked==1)
            {
                CopyToClipboard(serial);
                MessageBeep(MB_ICONINFORMATION);
            }
        }
    }
    return TRUE;

    case WM_HELP:
    {
        char id[10]="";
        sprintf(id, "%d", IDS_HELPKEYGEN);
        SetEnvironmentVariableA("HELPID", id);
        SetEnvironmentVariableA("HELPTITLE", "KeyGen Help");
        DialogBox(hInst, MAKEINTRESOURCE(DLG_HELP), hwndDlg, DlgHelp);
    }
    return TRUE;

    case WM_COMMAND:
    {
        switch(LOWORD(wParam))
        {
        case IDC_BTN_GENERATE:
        {
            NoFocus();
            char name[512]="";
            char keystring[512]="";
            char pvt[512]="";
            char y[512]="";
            char hwid[10]="";
            char sym[10]="";
            char templ[512]="";
            unsigned int sy=0,hw=0;

            GetDlgItemTextA(hwndDlg, IDC_EDT_NAME, name, 512);
            GetDlgItemTextA(hwndDlg, IDC_EDT_KEYSTRING, keystring, 256);
            GetDlgItemTextA(hwndDlg, IDC_EDT_HWID, hwid, 10);
            GetDlgItemTextA(hwndDlg, IDC_EDT_SYM, sym, 10);
            FormatHex(hwid);
            FormatHex(sym);

            sscanf(hwid, "%X", &hw);
            sscanf(sym, "%X", &sy);
            sprintf(sym, "%.8X", sy);
            SetDlgItemTextA(hwndDlg, IDC_EDT_SYM, sym);

            GetDlgItemTextA(hwndDlg, IDC_EDT_PVT, pvt, 512);
            int len=GetDlgItemTextA(hwndDlg, IDC_EDT_Y, y, 512);
            int comma_count=0;
            for(int i=0; i<len; i++)
                if(y[i]==',')
                    comma_count++;
            bool baboon=IsDlgButtonChecked(hwndDlg, IDC_CHK_BABOON);
            if(keygenerate_level==29 and comma_count!=2 and !baboon)
            {
                AddLogMessage(GetDlgItem(hwndDlg, IDC_EDT_ADVLOG), "Invalid ECDSA Public format...\nUse: ", true);
                return TRUE;
            }
            if(((!*pvt) or(!*y)) and keygenerate_level!=-1 and !baboon)
            {
                if(GetDlgItemTextA(hwndDlg, IDC_EDT_TEMPLATE, templ, 512))
                {
                    KG_GeneratePvtY(keygenerate_level, templ, pvt, y);
                    SetDlgItemTextA(hwndDlg, IDC_EDT_PVT, pvt);
                    SetDlgItemTextA(hwndDlg, IDC_EDT_Y, y);
                }
                else
                {
                    AddLogMessage(GetDlgItem(hwndDlg, IDC_EDT_ADVLOG), "You should enter the values for the key signing...", true);
                    return TRUE;
                }
            }

            int date=GetDlgItemInt(hwndDlg, IDC_EDT_DATE, 0, 0);
            int other0=GetDlgItemInt(hwndDlg, IDC_EDT_OTHER0, 0, 0)&65535;
            int other1=GetDlgItemInt(hwndDlg, IDC_EDT_OTHER1, 0, 0)&65535;
            int other2=GetDlgItemInt(hwndDlg, IDC_EDT_OTHER2, 0, 0)&65535;
            int other3=GetDlgItemInt(hwndDlg, IDC_EDT_OTHER3, 0, 0)&65535;
            int other4=GetDlgItemInt(hwndDlg, IDC_EDT_OTHER4, 0, 0)&65535;

            SetDlgItemInt(hwndDlg, IDC_EDT_DATE, date, 1);
            if(IsDlgButtonChecked(hwndDlg, IDC_CHK_MODKEY))
                date=65344;
            SetDlgItemInt(hwndDlg, IDC_EDT_OTHER0, other0, 0);
            if(keygenerate_level!=-1)
            {
                SetDlgItemInt(hwndDlg, IDC_EDT_OTHER1, other1, 0);
                SetDlgItemInt(hwndDlg, IDC_EDT_OTHER2, other2, 0);
                SetDlgItemInt(hwndDlg, IDC_EDT_OTHER3, other3, 0);
                SetDlgItemInt(hwndDlg, IDC_EDT_OTHER4, other4, 0);
            }
            InitVariables(program_dir, 0, 0, 1, hwndDlg);
            SetDlgItemTextA(hwndDlg, IDC_EDT_SERIAL, CreateSignedKey(keygenerate_level, sy, keygenerate_sym_xorval, pvt, y, keystring, date, name, hw, other0, other1, other2, other3, other4, baboon, GetDlgItem(hwndDlg, IDC_EDT_ADVLOG)));
            SendMessageA(GetDlgItem(hwndDlg, IDC_EDT_ADVLOG), WM_VSCROLL, SB_BOTTOM, 0);
            InitVariables(program_dir, 0, 0, 0, 0);
        }
        return TRUE;

        case IDC_BTN_MAKEDATE:
        {
            NoFocus();
            char date_text[20]="";
            char new_date[20]="";
            int len=GetDlgItemTextA(hwndDlg, IDC_EDT_DATEYMD, date_text, 20);
            for(int i=0,j=0; i<len; i++)
                if(date_text[i]!='-')
                    j+=sprintf(new_date+j, "%c", date_text[i]);
            len=strlen(new_date);
            UINT dest_id;

            HMENU myMenu=0;
            myMenu=CreatePopupMenu();

            if(len!=8)
                AppendMenuA(myMenu, MF_STRING|MF_GRAYED, 3, "Error!");
            else
            {
                AppendMenu(myMenu, MF_STRING, 1, "Date");
                AppendMenu(myMenu, MF_STRING, 2, "oth0");
            }
            POINT cursorPos;
            GetCursorPos(&cursorPos);
            SetForegroundWindow(hwndDlg);
            UINT MenuItemClicked=TrackPopupMenu(myMenu, TPM_RETURNCMD|TPM_NONOTIFY, cursorPos.x, cursorPos.y, 0, hwndDlg, 0);
            SendMessage(hwndDlg, WM_NULL, 0, 0);
            switch(MenuItemClicked)
            {
            case 1:
                dest_id=IDC_EDT_DATE;
                break;
            case 2:
                dest_id=IDC_EDT_OTHER0;
                break;
            case 3:
                return TRUE;
                break;
            }

            char y[5]="",m[3]="",d[3]="";
            int y_=0,m_=0,d_=0;
            strncpy(y, new_date, 4);
            strncpy(m, new_date+4, 2);
            strncpy(d, new_date+6, 2);
            sscanf(y, "%d", &y_);
            sscanf(m, "%d", &m_);
            sscanf(d, "%d", &d_);
            sprintf(date_text, "%d", MakeDate(y_, m_, d_));
            SetDlgItemTextA(hwndDlg, dest_id, date_text);
        }
        return TRUE;

        case IDC_CHK_BABOON:
        {
            NoFocus();
            bool baboon=true;
            if(IsDlgButtonChecked(hwndDlg, IDC_CHK_BABOON))
                baboon=false;
            EnableWindow(GetDlgItem(hwndDlg, IDC_EDT_PVT), baboon);
            EnableWindow(GetDlgItem(hwndDlg, IDC_EDT_Y), baboon);
        }
        return TRUE;

        case IDC_BTN_CALC:
        {
            NoFocus();
            char temp[1024]="";
            char temp2[256]="";
            UINT MenuItemClicked=1;
            HMENU myMenu=0;
            char clipboard[256]="";
            char pvt[1024]="";
            char y[1024]="";

            if(!GetDlgItemTextA(hwndDlg, IDC_EDT_TEMPLATE, temp, 1024))
                return TRUE;

            KG_GeneratePvtY(keygenerate_level, temp, pvt, y);
            sprintf(temp, "%.8X", KG_GenerateSymmetric(keygenerate_level, temp));

            if(keygenerate_level>=0)
            {
                myMenu=CreatePopupMenu();
                AppendMenuA(myMenu, MF_STRING, 4, "Sym Only");
                if(keygenerate_level==29)
                    AppendMenu(myMenu, MF_STRING, 1, "Pvt, ECDSA, Sym");
                else
                    AppendMenu(myMenu, MF_STRING, 1, "Pvt, Y, Sym");
                if(keygenerate_level==29)
                    AppendMenu(myMenu, MF_STRING, 2, "Pvt, ECDSA");
                else
                    AppendMenu(myMenu, MF_STRING, 2, "Pvt, Y");
                PasteFromClipboard(clipboard, 256);
                FormatHex(clipboard);
                int len=strlen(clipboard);
                if(len and len<9)
                {
                    unsigned int clipboard_sym=0;
                    sscanf(clipboard, "%X", &clipboard_sym);
                    if(keygenerate_level==29)
                        sprintf(temp2, "Pvt, ECDSA, Sym: %.8X", clipboard_sym);
                    else
                        sprintf(temp2, "Pvt, Y, Sym: %.8X", clipboard_sym);
                    AppendMenu(myMenu, MF_STRING, 3, temp2);
                }
                POINT cursorPos;
                GetCursorPos(&cursorPos);
                SetForegroundWindow(hwndDlg);
                MenuItemClicked=TrackPopupMenu(myMenu, TPM_RETURNCMD|TPM_NONOTIFY, cursorPos.x, cursorPos.y, 0, hwndDlg, 0);
                SendMessage(hwndDlg, WM_NULL, 0, 0);
            }
            switch(MenuItemClicked)
            {
            case 1:
            {
                SetDlgItemTextA(hwndDlg, IDC_EDT_Y, y);
                SetDlgItemTextA(hwndDlg, IDC_EDT_PVT, pvt);
                SetDlgItemTextA(hwndDlg, IDC_EDT_SYM, temp);
            }
            break;

            case 2:
            {
                SetDlgItemTextA(hwndDlg, IDC_EDT_Y, y);
                SetDlgItemTextA(hwndDlg, IDC_EDT_PVT, pvt);
            }
            break;

            case 3:
            {
                SetDlgItemTextA(hwndDlg, IDC_EDT_Y, y);
                SetDlgItemTextA(hwndDlg, IDC_EDT_PVT, pvt);
                SetDlgItemTextA(hwndDlg, IDC_EDT_SYM, clipboard);
            }
            break;

            case 4:
            {
                SetDlgItemTextA(hwndDlg, IDC_EDT_SYM, temp);
            }
            break;
            }
            if(keygenerate_level>=0)
                DestroyMenu(myMenu);
        }
        return TRUE;

        case IDC_CHK_DIGITALRIVER: ///Digital River checkbox.
        {
            NoFocus();
            if(IsDlgButtonChecked(hwndDlg, LOWORD(wParam)))
            {
                CheckDlgButton(hwndDlg, IDC_CHK_ESELLERATE, 0);
                keygenerate_sym_xorval=0x91827364; ///Official XOR value of DigitalRiver tagged keys...
            }
            else
                keygenerate_sym_xorval=0;
        }
        return TRUE;

        case IDC_CHK_ESELLERATE: ///eSellerate checkbox.
        {
            NoFocus();
            if(IsDlgButtonChecked(hwndDlg, LOWORD(wParam)))
            {
                CheckDlgButton(hwndDlg, IDC_CHK_DIGITALRIVER, 0);
                keygenerate_sym_xorval=0x19283746; ///Official XOR value of eSellerate tagged keys...
            }
            else
                keygenerate_sym_xorval=0;
        }
        return TRUE;

        case IDC_CHK_MODKEY:
        {
            NoFocus();
        }
        return TRUE;

        case IDC_COMBO_LEVEL:
        {
            switch(HIWORD(wParam))
            {
            case CBN_SELCHANGE:
            {
                bool isNoSeperator=true;
                keygenerate_level=SendDlgItemMessageA(hwndDlg, LOWORD(wParam), CB_GETCURSEL, 0, 0);
                if(keygenerate_level==1 or keygenerate_level==6 or keygenerate_level==16)
                    isNoSeperator=false;

                if(!keygenerate_level)
                    keygenerate_level--;
                else if(keygenerate_level>1 and keygenerate_level<6) //signed v2
                    keygenerate_level-=2;
                else if(keygenerate_level>6 and keygenerate_level<16) //signed v3
                    keygenerate_level+=3;
                else if(keygenerate_level>16) //short v3
                    keygenerate_level+=3;
                bool en=isNoSeperator;
                EnableWindow(GetDlgItem(hwndDlg, IDC_EDT_NAME), en);
                EnableWindow(GetDlgItem(hwndDlg, IDC_EDT_HWID), en);
                EnableWindow(GetDlgItem(hwndDlg, IDC_EDT_TEMPLATE), en);
                EnableWindow(GetDlgItem(hwndDlg, IDC_BTN_CALC), en);
                EnableWindow(GetDlgItem(hwndDlg, IDC_CHK_DIGITALRIVER), en);
                EnableWindow(GetDlgItem(hwndDlg, IDC_CHK_ESELLERATE), en);
                EnableWindow(GetDlgItem(hwndDlg, IDC_EDT_SYM), en);
                EnableWindow(GetDlgItem(hwndDlg, IDC_EDT_DATEYMD), en);
                EnableWindow(GetDlgItem(hwndDlg, IDC_EDT_DATE), en);
                EnableWindow(GetDlgItem(hwndDlg, IDC_BTN_MAKEDATE), en);
                EnableWindow(GetDlgItem(hwndDlg, IDC_EDT_OTHER0), en);
                EnableWindow(GetDlgItem(hwndDlg, IDC_BTN_GENERATE), en);

                if(keygenerate_level==-1)
                    en=false;
                EnableWindow(GetDlgItem(hwndDlg, IDC_EDT_OTHER1), en);
                EnableWindow(GetDlgItem(hwndDlg, IDC_EDT_OTHER2), en);
                EnableWindow(GetDlgItem(hwndDlg, IDC_EDT_OTHER3), en);
                EnableWindow(GetDlgItem(hwndDlg, IDC_EDT_OTHER4), en);
                EnableWindow(GetDlgItem(hwndDlg, IDC_EDT_PVT), en);
                EnableWindow(GetDlgItem(hwndDlg, IDC_EDT_Y), en);
                en=false;
                if(keygenerate_level>18 and isNoSeperator)
                    en=true;
                EnableWindow(GetDlgItem(hwndDlg, IDC_EDT_KEYSTRING), en);

                /*char temp[10]="";
                sprintf(temp, "%d", keygenerate_level);*/
                if(isNoSeperator)
                {
                    SetDlgItemTextA(hwndDlg, IDC_EDT_PVT, "");
                    SetDlgItemTextA(hwndDlg, IDC_EDT_Y, "");
                }
                bool baboon=false;
                if(keygenerate_level==29)
                {
                    SetDlgItemTextA(hwndDlg, IDC_STC_YPUB, "ECDSA Public:");
                    baboon=true;
                }
                else
                {
                    SetDlgItemTextA(hwndDlg, IDC_STC_YPUB, "Y:");
                    CheckDlgButton(hwndDlg, IDC_CHK_BABOON, 0);
                }
                ShowWindow(GetDlgItem(hwndDlg, IDC_CHK_BABOON), baboon);
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
