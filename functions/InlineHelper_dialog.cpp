#include "InlineHelper_dialog.h"

BOOL CALLBACK IH_DlgMain(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch(uMsg)
    {
    case WM_INITDIALOG:
    {
        IH_shared=hwndDlg;
        EnableWindow(GetDlgItem(hwndDlg, IDC_BTN_INLINE), FALSE);
        EnableWindow(GetDlgItem(hwndDlg, IDC_BTN_COPY), FALSE);
    }
    return TRUE;

    case WM_HELP:
    {
        char id[10]="";
        sprintf(id, "%d", IDS_HELPINLINE);
        SetEnvironmentVariableA("HELPID", id);
        SetEnvironmentVariableA("HELPTITLE", "Inline Help");
        DialogBox(hInst, MAKEINTRESOURCE(DLG_HELP), hwndDlg, DlgHelp);
    }
    return TRUE;

    case WM_DROPFILES:
    {
        //Get the dropped file name.
        DragQueryFileA((HDROP)wParam, NULL, IH_szFileName, 256);

        //Retrieve the directory of the file.
        int i=strlen(IH_szFileName)-1;
        int j=0;
        while(IH_szFileName[i]!='\\')
        {
            i--;
            j++;
        }
        strncpy(IH_debugProgramDir, IH_szFileName, strlen(IH_szFileName)-j-1);

        //Retrieve stuff.
        CreateThread(0, 0, IH_DebugThread, 0, 0, 0);
    }
    return TRUE;

    case WM_COMMAND:
    {
        switch(LOWORD(wParam))
        {
        case IDC_BTN_INLINE:
        {
            NoFocus();
            if(!IH_empty_entry)
            {
                MessageBoxA(hwndDlg, "You need to specify the place to start the inline...", "N00B!", MB_ICONERROR);
                return TRUE;
            }
            char patch_filename[256]="";
            patch_filename[0]=0;
            OPENFILENAME ofstruct;
            memset(&ofstruct, 0, sizeof(ofstruct));
            ofstruct.lStructSize=sizeof(ofstruct);
            ofstruct.hwndOwner=hwndDlg;
            ofstruct.hInstance=hInst;
            if(!IH_fdFileIsDll)
                ofstruct.lpstrFilter="Executable files (*.exe)\0*.exe\0\0";
            else
                ofstruct.lpstrFilter="Executable files (*.dll)\0*.dll\0\0";
            ofstruct.lpstrFile=patch_filename;
            ofstruct.nMaxFile=256;
            ofstruct.lpstrInitialDir=IH_debugProgramDir;
            ofstruct.lpstrTitle="Save file";
            if(!IH_fdFileIsDll)
                ofstruct.lpstrDefExt="exe";
            else
                ofstruct.lpstrDefExt="dll";
            ofstruct.Flags=OFN_EXTENSIONDIFFERENT|OFN_HIDEREADONLY|OFN_NONETWORKBUTTON|OFN_OVERWRITEPROMPT;
            GetSaveFileName(&ofstruct);
            if(!patch_filename[0])
            {
                MessageBoxA(hwndDlg, "You must select a file...", "Warning", MB_ICONWARNING);
                return TRUE;
            }

            CopyFileA(IH_szFileName, patch_filename, FALSE);
            SetPE32Data(patch_filename, NULL, UE_OEP, IH_empty_entry-IH_fdImageBase);
            long newflags=(long)GetPE32Data(patch_filename, IH_fdEntrySectionNumber, UE_SECTIONFLAGS);
            SetPE32Data(patch_filename, IH_fdEntrySectionNumber, UE_SECTIONFLAGS, (newflags|0x80000000));

            IH_GenerateAsmCode();
            CopyToClipboard(IH_code_text);
            MessageBoxA(hwndDlg, "1) Open the file you just saved with OllyDbg\n2) Open Multimate Assembler v1.5+\n3) Paste the code\n4) Modify the code to do something with the Security DLL\n5) Save the patched file with OllyDbg\n6) Enjoy!", "Instructions", MB_ICONINFORMATION);
        }
        return TRUE;

        case IDC_EDT_FREESPACE:
        {
            char free_temp[10]="";
            GetDlgItemTextA(hwndDlg, IDC_EDT_FREESPACE, free_temp, 10);
            sscanf(FormatTextHex(free_temp), "%X", &IH_empty_entry);
        }
        return TRUE;

        case IDC_BTN_COPY:
        {
            NoFocus();
            if(IH_code_text[0])
            {
                IH_GenerateAsmCode();
                CopyToClipboard(IH_code_text);
                MessageBoxA(hwndDlg, "Code copied to clipboard!", "Yay!", MB_ICONINFORMATION);
            }
            else
                MessageBoxA(hwndDlg, "There is no code to copy, please load a file first...", "Error!", MB_ICONERROR);
        }
        return TRUE;

        case IDC_BTN_PLUGINS:
        {
            NoFocus();
            char total_found_s[5]="";
            char plugin_name[100]="";
            char plugin_dll[100]="";
            char dll_to_load[256]="";
            char temp_str[5]="";
            int total_found=0;
            GetPrivateProfileStringA("Plugins", "total_found", "", total_found_s, 4, IH_plugin_ini_file);
            sscanf(total_found_s, "%d", &total_found);
            if(total_found)
            {
                HMENU myMenu=NULL;
                myMenu=CreatePopupMenu();
                for(int i=1; i!=(total_found+1); i++)
                {
                    sprintf(temp_str, "%d", i);
                    GetPrivateProfileStringA(temp_str, "plugin_name", "", plugin_name, 100, IH_plugin_ini_file);
                    AppendMenuA(myMenu, MF_STRING, i, plugin_name);
                }
                POINT cursorPos;
                GetCursorPos(&cursorPos);
                SetForegroundWindow(hwndDlg);
                UINT MenuItemClicked=TrackPopupMenu(myMenu, TPM_RETURNCMD | TPM_NONOTIFY, cursorPos.x, cursorPos.y, 0, hwndDlg, NULL);
                SendMessage(hwndDlg, WM_NULL, 0, 0);
                if(!MenuItemClicked)
                    return TRUE;

                sprintf(temp_str, "%d", (int)MenuItemClicked);
                GetPrivateProfileStringA(temp_str, "plugin_dll", "", plugin_dll, 100, IH_plugin_ini_file);
                sprintf(dll_to_load, "plugins\\%s", plugin_dll);

                PLUGIN_INST=LoadLibraryA(dll_to_load);
                if(!PLUGIN_INST)
                    MessageBoxA(hwndDlg, "There was an error loading the plugin", plugin_dll, MB_ICONERROR);
                else
                {
                    PluginFunction=(PLUGFUNC)GetProcAddress(PLUGIN_INST, "PluginFunction");
                    if(!PluginFunction)
                        MessageBoxA(hwndDlg, "The export \"PluginFunction\" could not be found, please contact the plugin supplier", plugin_dll, MB_ICONERROR);
                    else
                    {
                        if(!IH_fdImageBase)
                            IH_fdImageBase=0x400000;

                        PluginFunction(PLUGIN_INST, hwndDlg, IH_security_addr_register, IH_program_dir, IH_fdImageBase);
                        FreeLibrary(PLUGIN_INST);
                        SetForegroundWindow(hwndDlg);
                    }
                }
            }
            else
            {
                HMENU myMenu=NULL;
                myMenu=CreatePopupMenu();
                AppendMenuA(myMenu, MF_STRING|MF_GRAYED, 1, "No plugins found :(");
                POINT cursorPos;
                GetCursorPos(&cursorPos);
                SetForegroundWindow(hwndDlg);
                TrackPopupMenu(myMenu, TPM_RETURNCMD | TPM_NONOTIFY, cursorPos.x, cursorPos.y, 0, hwndDlg, NULL);
            }
        }
        return TRUE;

        case IDC_EDT_OEP:
        {
            char temp_oep[10]="";
            GetDlgItemTextA(hwndDlg, IDC_EDT_OEP, temp_oep, 10);
            sscanf(temp_oep, "%X", &IH_OEP);
        }
        return TRUE;
        }
    }
    return TRUE;
    }
    return FALSE;
}
