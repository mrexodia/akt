#include "Misc_dialog.h"

vector<ArmaLicenseEntry_t> g_ArmaLicenseEntryList;

static void FillLicRemovalList(HWND list, vector<ArmaLicenseEntry_t>* lic_entry)
{
    unsigned int itemLength=0;
    unsigned int widestItemIndex=0;
    // Clear the list box
    SendMessageA(list, LB_RESETCONTENT, 0, 0);
    // Add license files to the list box
    for(int wI=0; wI<(int)lic_entry->size(); wI++)
    {
        SendMessageA(list, LB_ADDSTRING, 0, (LPARAM)lic_entry->at(wI).Path.data());

        if(strlen(lic_entry->at(wI).Path.data())>itemLength)
        {
            itemLength=strlen(lic_entry->at(wI).Path.data());
            widestItemIndex=wI;
        }
    }
    // Set the maximal horizontal scroll size
    if(lic_entry->size())
        UpdateHorizontalScrollLen(list, lic_entry->at(widestItemIndex).Path.data());
    else
        UpdateHorizontalScrollLen(list, "");
    // Select all items
    SendMessageA(list, LB_SETSEL, TRUE, -1);

    //MessageBoxA(MSC_shared, "Check carefully all items from the list before deleting them!", "Warning", MB_ICONWARNING);
}

BOOL CALLBACK MSC_DlgMain(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch(uMsg)
    {
    case WM_INITDIALOG:
    {
        MSC_shared=hwndDlg;
        memset(MSC_projectID, 0, 65536);
        MSC_SD_list=GetDlgItem(hwndDlg, IDC_LIST_SECTIONS);
        EnableWindow(GetDlgItem(hwndDlg, IDC_BTN_DELETESECTIONS), 0);
        EnableWindow(GetDlgItem(hwndDlg, IDC_CHK_WATERMARK), 0);
        EnableWindow(GetDlgItem(hwndDlg, IDC_CHK_OVERLAY), 0);
        EnableWindow(GetDlgItem(hwndDlg, IDC_BTN_GENERATE), 0);
        EnableWindow(GetDlgItem(hwndDlg, IDC_BTN_FINDCHECKSUM), 0);
        EnableWindow(GetDlgItem(hwndDlg, IDC_CHK_FOUNDCHECKSUM), 0);
        SendMessageA(hwndDlg, WM_COMMAND, IDC_BTN_TODAY, 0);
    }
    return TRUE;

    case WM_CLOSE:
    {
        EndDialog(hwndDlg, 0);
    }
    return TRUE;

    case WM_BROWSE:
    {
        if(MSC_isdebugging)
            return TRUE;
        strcpy(MSC_szFileName, (const char*)wParam);
        strcpy(MSC_program_dir, MSC_szFileName);
        int i=strlen(MSC_program_dir);
        while(MSC_program_dir[i]!='\\')
            i--;
        MSC_program_dir[i]=0;
        SetDlgItemTextA(hwndDlg, IDC_EDT_FILE, MSC_szFileName);
        EnableWindow(GetDlgItem(hwndDlg, IDC_CHK_WATERMARK), 0);
        EnableWindow(GetDlgItem(hwndDlg, IDC_CHK_OVERLAY), 0);
        EnableWindow(GetDlgItem(hwndDlg, IDC_BTN_DELETESECTIONS), 0);
    }
    return TRUE;

    case WM_DROPFILES:
    {
        if(MSC_isdebugging)
            return TRUE;
        DragQueryFileA((HDROP)wParam, 0, MSC_szFileName, MAX_PATH);
        strcpy(MSC_program_dir, MSC_szFileName);
        int i=strlen(MSC_program_dir);
        while(MSC_program_dir[i]!='\\')
            i--;
        MSC_program_dir[i]=0;
        SetDlgItemTextA(hwndDlg, IDC_EDT_FILE, MSC_szFileName);
        EnableWindow(GetDlgItem(hwndDlg, IDC_CHK_WATERMARK), 0);
        EnableWindow(GetDlgItem(hwndDlg, IDC_CHK_OVERLAY), 0);
        EnableWindow(GetDlgItem(hwndDlg, IDC_BTN_DELETESECTIONS), 0);
    }
    return TRUE;

    case WM_HELP:
    {
        char id[10]="";
        sprintf(id, "%d", IDS_HELPMISC);
        SetEnvironmentVariableA("HELPID", id);
        SetEnvironmentVariableA("HELPTITLE", "Misc Help");
        DialogBox(hInst, MAKEINTRESOURCE(DLG_HELP), hwndDlg, DlgHelp);
    }
    return TRUE;

    case WM_CONTEXTMENU:
    {
        if(GetDlgCtrlID((HWND)wParam)==IDC_EDT_FIXCLOCKKEY)
        {
            char serial[2048]="";
            int len=GetDlgItemTextA(hwndDlg, IDC_EDT_FIXCLOCKKEY, serial, 2048);
            if(!len)
                return TRUE;
            HMENU myMenu=0;
            myMenu=CreatePopupMenu();
            AppendMenu(myMenu, MF_STRING, 1, "Copy FixClock Key");
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

    case WM_COMMAND:
    {
        switch(LOWORD(wParam))
        {
        case IDC_BTN_GETMAGIC: //VerifySym
        {
            if(!MSC_isdebugging and MSC_szFileName[0])
                CreateThread(0, 0, MSC_VR_GetMagic, 0, 0, 0);
        }
        return TRUE;

        case IDC_BTN_VERIFYSYM: //VerifySym
        {
            HMENU myMenu=CreatePopupMenu();
            bool has_one=false;
            char sym_text[10]="";
            if(GetDlgItemTextA(hwndDlg, IDC_EDT_MAGIC1, MSC_VR_magic1, 10) and GetDlgItemTextA(hwndDlg, IDC_EDT_MAGIC2, MSC_VR_magic2, 10) and GetDlgItemTextA(hwndDlg, IDC_EDT_MD5, MSC_VR_md5_text, 10))
            {
                char menu_text[50]="";
                if(GetDlgItemTextA(hwndDlg, IDC_EDT_SYMFOUND, sym_text, 10) and MSC_VR_certpath[0])
                {
                    has_one=true;
                    sprintf(menu_text, "&Verify %s", sym_text);
                    AppendMenuA(myMenu, MF_STRING, 1, menu_text);
                }
                if(MSC_VR_certpath[0] and MSC_VR_keyspath[0])
                {
                    has_one=true;
                    AppendMenuA(myMenu, MF_STRING, 2, "Verify &List");
                }
                if(!has_one)
                    return TRUE;

                POINT cursorPos;
                GetCursorPos(&cursorPos);
                SetForegroundWindow(hwndDlg);
                UINT MenuItemClicked=TrackPopupMenu(myMenu, TPM_RETURNCMD|TPM_NONOTIFY, cursorPos.x, cursorPos.y, 0, hwndDlg, 0);
                SendMessage(hwndDlg, WM_NULL, 0, 0);
                switch(MenuItemClicked)
                {
                case 1:
                {
                    unsigned int _magic1, _magic2, _md5, _sym;
                    sscanf(MSC_VR_magic1, "%X", &_magic1);
                    sscanf(MSC_VR_magic2, "%X", &_magic2);
                    sscanf(MSC_VR_md5_text, "%X", &_md5);
                    sscanf(sym_text, "%X", &_sym);

                    unsigned char* data;
                    unsigned int data_size=0;
                    HANDLE hFile=CreateFileA(MSC_VR_certpath, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
                    if(hFile==INVALID_HANDLE_VALUE)
                    {
                        MessageBoxA(hwndDlg, "Could not open certs file...", "Error!", MB_ICONERROR);
                        EnableWindow(GetDlgItem(MSC_shared, IDC_BTN_VERIFYSYM), 1);
                        return TRUE;
                    }
                    data_size=GetFileSize(hFile, 0);
                    data=(unsigned char*)malloc2(data_size);
                    DWORD read=0;
                    ReadFile(hFile, data, data_size, &read, 0);
                    CloseHandle(hFile);
                    bool isvalid=false;
                    if(MSC_VR_brute(_magic1, _magic2, _sym, _md5, data, data_size))
                        isvalid=true;
                    CheckDlgButton(hwndDlg, IDC_CHK_ISVALIDSYM, isvalid);
                }
                break;

                case 2:
                {
                    CreateThread(0, 0, MSC_VR_BruteThread, 0, 0, 0);
                }
                break;
                }
            }
        }
        return TRUE;

        case IDC_BTN_CERTBIN: //VerifySym
        {
            HMENU myMenu=CreatePopupMenu();
            if(MSC_VR_certpath[0])
            {
                char* filename_nopath;
                char menu_text[256]="";
                int len=strlen(MSC_VR_certpath);
                while(MSC_VR_certpath[len]!='\\')
                    len--;
                filename_nopath=MSC_VR_certpath+len+1;
                sprintf(menu_text, "Using %s", filename_nopath);
                AppendMenuA(myMenu, MF_STRING|MF_GRAYED, 0, menu_text);
            }
            AppendMenuA(myMenu, MF_STRING, 1, "&Browse...");
            if(MSC_szFileName[0])
            {
                int len=strlen(MSC_szFileName);
                char* ext=MSC_szFileName+(len-3);
                if(!strcasecmp(ext, "bin"))
                    AppendMenuA(myMenu, MF_STRING, 2, "&Use Selected File...");
            }

            POINT cursorPos;
            GetCursorPos(&cursorPos);
            SetForegroundWindow(hwndDlg);
            UINT MenuItemClicked=TrackPopupMenu(myMenu, TPM_RETURNCMD|TPM_NONOTIFY, cursorPos.x, cursorPos.y, 0, hwndDlg, 0);
            SendMessage(hwndDlg, WM_NULL, 0, 0);
            switch(MenuItemClicked)
            {
            case 1:
            {
                OPENFILENAME ofstruct;
                memset(&ofstruct, 0, sizeof(ofstruct));
                ofstruct.lStructSize=sizeof(ofstruct);
                ofstruct.hwndOwner=hwndDlg;
                ofstruct.hInstance=hInst;
                ofstruct.lpstrFilter="Binary Files (*.bin)\0*.bin\0\0";
                ofstruct.lpstrFile=MSC_VR_certpath;
                ofstruct.nMaxFile=256;
                ofstruct.lpstrDefExt="bin";
                ofstruct.Flags=OFN_EXTENSIONDIFFERENT|OFN_HIDEREADONLY|OFN_NONETWORKBUTTON;
                GetOpenFileName(&ofstruct);
            }
            break;

            case 2:
            {
                strcpy(MSC_VR_certpath, MSC_szFileName);
            }
            break;
            }
        }
        return TRUE;

        case IDC_CHK_CHECKALLMD5: //VerifySym
        {
            MSC_VR_check_all_md5=IsDlgButtonChecked(hwndDlg, IDC_CHK_CHECKALLMD5);
            bool enable=true;
            if(MSC_VR_check_all_md5)
                enable=false;
            EnableWindow(GetDlgItem(hwndDlg, IDC_EDT_MD5), enable);
        }
        return TRUE;

        case IDC_BTN_SYMLIST: //VerifySym
        {
            HMENU myMenu=CreatePopupMenu();
            if(MSC_VR_keyspath[0])
            {
                char* filename_nopath;
                char menu_text[256]="";
                int len=strlen(MSC_VR_keyspath);
                while(MSC_VR_keyspath[len]!='\\')
                    len--;
                filename_nopath=MSC_VR_keyspath+len+1;
                sprintf(menu_text, "Using %s", filename_nopath);
                AppendMenuA(myMenu, MF_STRING|MF_GRAYED, 0, menu_text);
            }
            AppendMenuA(myMenu, MF_STRING, 1, "&Browse...");
            if(MSC_szFileName[0])
            {
                int len=strlen(MSC_szFileName);
                char* ext=MSC_szFileName+(len-3);
                if(!strcasecmp(ext, "txt"))
                    AppendMenuA(myMenu, MF_STRING, 2, "&Use Selected File...");
            }

            POINT cursorPos;
            GetCursorPos(&cursorPos);
            SetForegroundWindow(hwndDlg);
            UINT MenuItemClicked=TrackPopupMenu(myMenu, TPM_RETURNCMD|TPM_NONOTIFY, cursorPos.x, cursorPos.y, 0, hwndDlg, 0);
            SendMessage(hwndDlg, WM_NULL, 0, 0);
            switch(MenuItemClicked)
            {
            case 1:
            {
                OPENFILENAME ofstruct;
                memset(&ofstruct, 0, sizeof(ofstruct));
                ofstruct.lStructSize=sizeof(ofstruct);
                ofstruct.hwndOwner=hwndDlg;
                ofstruct.hInstance=hInst;
                ofstruct.lpstrFilter="Text Files (*.txt)\0*.txt\0\0";
                ofstruct.lpstrFile=MSC_VR_keyspath;
                ofstruct.nMaxFile=256;
                ofstruct.lpstrDefExt="txt";
                ofstruct.Flags=OFN_EXTENSIONDIFFERENT|OFN_HIDEREADONLY|OFN_NONETWORKBUTTON;
                GetOpenFileName(&ofstruct);
            }
            break;

            case 2:
            {
                strcpy(MSC_VR_keyspath, MSC_szFileName);
            }
            break;
            }
        }
        return TRUE;

        case IDC_BTN_GETSALT: //GenerateChecksum
        {
            SetFocus(GetDlgItem(hwndDlg, IDC_EDT_SALT));
            if(!MSC_isdebugging and MSC_szFileName[0])
                CreateThread(0, 0, MSC_GetSalt, 0, 0, 0);
        }
        return TRUE;

        case IDC_BTN_FINDCHECKSUM: //GenerateChecksum
        {
            if(!MSC_isdebugging and MSC_szFileName[0])
                CreateThread(0, 0, MSC_FindChecksum, 0, 0, 0);
        }
        return TRUE;

        case IDC_CHK_SALT: //GenerateChecksum
        case IDC_EDT_SALT:
        case IDC_EDT_SYM:
        {
            char sym_[10]="";
            char salt_[10]="";
            char chk_[10]="";
            if(!GetDlgItemTextA(hwndDlg, IDC_EDT_SYM, sym_, 10))
            {
                EnableWindow(GetDlgItem(hwndDlg, IDC_BTN_FINDCHECKSUM), 0);
                SetDlgItemTextA(hwndDlg, IDC_EDT_CHK, "");
                return TRUE;
            }
            EnableWindow(GetDlgItem(hwndDlg, IDC_BTN_FINDCHECKSUM), 1);
            GetDlgItemTextA(hwndDlg, IDC_EDT_SALT, salt_, 10);
            unsigned int sym=0;
            unsigned int salt=0;
            sscanf(sym_, "%X", &sym);
            sscanf(salt_, "%X", &salt);
            if(IsDlgButtonChecked(hwndDlg, IDC_CHK_SALT))
                MSC_checksum=MakeChecksumV8(sym, salt);
            else
                MSC_checksum=MakeChecksumV3(sym);
            sprintf(chk_, "%.8X", MSC_checksum);
            SetDlgItemTextA(hwndDlg, IDC_EDT_CHK, chk_);
        }
        return TRUE;

        case IDC_BTN_GETDATE1: //Date tool
        {
            char date_text[20]="";
            char new_date[20]="";
            int len=GetDlgItemTextA(hwndDlg, IDC_EDT_DATEYMD1, date_text, 20);
            for(int i=0,j=0; i<len; i++)
                if(date_text[i]!='-')
                    j+=sprintf(new_date+j, "%c", date_text[i]);
            len=strlen(new_date);
            if(len!=8)
            {
                SetDlgItemTextA(hwndDlg, IDC_EDT_DATE1, "Error");
                return TRUE;
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
            SetDlgItemTextA(hwndDlg, IDC_EDT_DATE1, date_text);
        }
        return TRUE;

        case IDC_BTN_GETDATE2: //Date tool
        {
            char date_formatted[11]="";
            unsigned short year=0;
            unsigned short month=0;
            unsigned short day=0;
            unsigned short date=0;
            BOOL translated=FALSE;
            date=GetDlgItemInt(hwndDlg, IDC_EDT_DATE2, &translated, FALSE);
            InterpretDate(date, &year, &month, &day);
            sprintf(date_formatted, "%04d-%02d-%02d", year, month, day);
            SetDlgItemTextA(hwndDlg, IDC_EDT_DATEYMD2, date_formatted);
        }
        return TRUE;

        case IDC_BTN_TODAY: //Date tool
        {
            SYSTEMTIME systime= {0};
            GetSystemTime(&systime);
            char temp[20]="";
            sprintf(temp, "%d", MakeDate(systime.wYear, systime.wMonth, systime.wDay));
            SetDlgItemTextA(hwndDlg, IDC_EDT_DATE1, temp);
            sprintf(temp, "%.4d-%.2d-%.2d", systime.wYear, systime.wMonth, systime.wDay);
            SetDlgItemTextA(hwndDlg, IDC_EDT_DATEYMD2, temp);
        }
        return TRUE;

        case IDC_BTN_GETPROJECTID: //FixClock
        {
            if(!MSC_isdebugging and MSC_szFileName[0])
                CreateThread(0, 0, MSC_GetProjectID, 0, 0, 0);
        }
        return TRUE;

        case IDC_EDT_PROJECTID: //FixClock
        {
            bool enable=false;
            if(GetDlgItemTextA(hwndDlg, IDC_EDT_PROJECTID, MSC_projectID, 65536))
                enable=true;
            EnableWindow(GetDlgItem(hwndDlg, IDC_BTN_GENERATE), enable);
        }
        return TRUE;

        case IDC_BTN_GENERATE: //FixClock
        {
            srand(GetTickCount());
            int oth0=rand()%65535;
            SYSTEMTIME systime= {0};
            GetSystemTime(&systime);
            unsigned short today=MakeDate(systime.wYear, systime.wMonth, systime.wDay);
            SetDlgItemTextA(hwndDlg, IDC_EDT_FIXCLOCKKEY, CreateSignedKey(-1, 0x12345678, 0, 0, 0, 0, today, MSC_projectID, 0, oth0, 0, 0, 0, 0, false, 0));
        }
        return TRUE;

        case IDC_BTN_GETSECTIONS: //Section deleter
        {
            if(MSC_szFileName[0])
                MSC_SD_LoadFile(hwndDlg);
        }
        return TRUE;

        case IDC_CHK_OVERLAY: //Section deleter
        {
            int len=strlen(MSC_szFileName);
            while(MSC_szFileName[len]!='\\')
                len--;

            char filename[256]="";
            strcpy(filename, MSC_szFileName+len+1);

            len=strlen(filename);
            int start=len;
            for(int i=0; i<len; i++)
                if(filename[i]=='.')
                {
                    start=i;
                    break;
                }
            strcpy(filename+start, "_overlay.bin");
            OPENFILENAME ofstruct;
            memset(&ofstruct, 0, sizeof(ofstruct));
            ofstruct.lStructSize=sizeof(ofstruct);
            ofstruct.hwndOwner=hwndDlg;
            ofstruct.hInstance=hInst;
            ofstruct.lpstrFilter="Dump files (*.bin)\0*.bin\0\0";
            ofstruct.lpstrFile=filename;
            ofstruct.nMaxFile=256;
            ofstruct.lpstrInitialDir=MSC_program_dir;
            ofstruct.lpstrTitle="Save file";
            ofstruct.lpstrDefExt="bin";
            ofstruct.Flags=OFN_EXTENSIONDIFFERENT|OFN_HIDEREADONLY|OFN_NONETWORKBUTTON|OFN_OVERWRITEPROMPT;
            GetSaveFileName(&ofstruct);
            if(MSC_SD_DumpOverlay(filename))
                MessageBoxA(hwndDlg, "Overlay dumped!", "Success!", MB_ICONINFORMATION);
            else
                MessageBoxA(hwndDlg, "Could not dump overlay...", "Error...", MB_ICONERROR);
        }
        return TRUE;

        case IDC_BTN_DELETESECTIONS: //Section deleter
        {
            char backup_file[256]="";
            sprintf(backup_file, "%s.bak", MSC_szFileName);
            if(!CopyFileA(MSC_szFileName, backup_file, false))
                if(MessageBoxA(hwndDlg, "Could not create backup, continue?", "Question", MB_ICONQUESTION|MB_YESNO)==IDNO)
                    return TRUE;

            bool removedwatermark=IsDlgButtonChecked(hwndDlg, IDC_CHK_WATERMARK);
            if(removedwatermark)
            {
                if(!MSC_SD_RemoveWatermark(hwndDlg))
                    return TRUE;
            }
            MSC_SD_updated_sections=false;
            if(SendMessageA(MSC_SD_list, LB_GETSELCOUNT, 0, 0))
            {
                int total_items=SendMessageA(MSC_SD_list, LB_GETCOUNT, 0, 0);
                for(int i=0,j=0; j<total_items; i++,j++)
                {
                    if(SendMessageA(MSC_SD_list, LB_GETSEL, j, 0))
                    {
                        MSC_SD_updated_sections=true;
                        if(!MSC_SD_RemoveSection(hwndDlg, i))
                            return TRUE;
                        i--;
                    }
                }
            }
            if(MSC_SD_updated_sections or removedwatermark)
                MSC_SD_LoadFile(hwndDlg);
        }
        return TRUE;

        case IDC_BTN_GETCURSYM: //GetCurrentSym
        {
            if(!MSC_isdebugging and MSC_szFileName[0])
                CreateThread(0, 0, MSC_CurSymDebugThread, 0, 0, 0);
        }
        return TRUE;

        case IDC_BTN_GETLICENSEDATA:
        {
            if(MSC_isdebugging or !MSC_szFileName[0])
                return TRUE;

            HWND list=GetDlgItem(hwndDlg, IDC_LIST_LICENSES);
            LRPARSTRUCT* par=(LRPARSTRUCT*)malloc2(sizeof(LRPARSTRUCT));
            par->parFileName=MSC_szFileName;
            par->parArmaLicenseEntryListPtr=&g_ArmaLicenseEntryList;
            par->list=list;
            par->isdebugging=&MSC_isdebugging;
            par->filllist=(cbGenericTwoArg)FillLicRemovalList;
            par->hwndDlg=hwndDlg;
            CreateThread(0, 0, LR_GetArmaLicenseDataThread, par, 0, 0);
        }
        return TRUE;

        case IDC_BTN_REMOVESELLLICDATA:
        {
            unsigned int itemLength=0;
            unsigned int widestItemIndex=0;
            HWND list=GetDlgItem(hwndDlg, IDC_LIST_LICENSES);
            int totalNbrOfItems=SendMessageA(list, LB_GETCOUNT, 0, 0);
            for(int wI=0; wI<totalNbrOfItems; wI++)
            {
                if(SendMessageA(list, LB_GETSEL, wI, 0))
                {
                    //printf("Remove %s\n", g_ArmaLicenseEntryList.at(wI).Path.data());
                    LR_RemoveSingleArmaLicenseData(g_ArmaLicenseEntryList.at(wI));
                    g_ArmaLicenseEntryList.erase(g_ArmaLicenseEntryList.begin() + wI);
                    SendMessageA(list, LB_DELETESTRING, wI, 0);
                    wI--;
                    totalNbrOfItems--;
                }
            }
            // Search the longer string
            for(int wI=0; wI<(int)g_ArmaLicenseEntryList.size(); wI++)
            {
                if(strlen(g_ArmaLicenseEntryList.at(wI).Path.data())>itemLength)
                {
                    itemLength=strlen(g_ArmaLicenseEntryList.at(wI).Path.data());
                    widestItemIndex=wI;
                }
            }
            // Set the maximal horizontal scroll size
            if(g_ArmaLicenseEntryList.size()>0)
                UpdateHorizontalScrollLen(list, g_ArmaLicenseEntryList.at(widestItemIndex).Path.data());
            else
                UpdateHorizontalScrollLen(list, "");
            //TODO: remove this
            char command[256]="";
            sprintf(command, "start %s INFO", MSC_szFileName);
            system(command);
        }
        return TRUE;
        }
    }
    return TRUE;
    }
    return FALSE;
}
