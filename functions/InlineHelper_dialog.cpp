#include "InlineHelper_dialog.h"

/**********************************************************************
 *                      Module Variables
 *********************************************************************/
static char g_szFileName[256] = "";             // Debugged program filename
static char g_szTargetDir[256] = "";    // String for the directory of the debugged program

static bool g_FileIsDll = false;                // Flag for DLL

static char g_codeText[4096] = "";          // String for the inline asm code

static IH_InlineHelperData_t g_TargetData;

static HWND g_HWND;                                 // HWND of the main window


/**********************************************************************
 *                      Functions
 *********************************************************************/
BOOL CALLBACK IH_DlgMain(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch(uMsg)
    {
    case WM_INITDIALOG:
    {
        g_HWND = hwndDlg;
        EnableWindow(GetDlgItem(hwndDlg, IDC_BTN_INLINE), FALSE);
        EnableWindow(GetDlgItem(hwndDlg, IDC_BTN_COPY), FALSE);
    }
    return TRUE;

    case WM_HELP:
    {
        char id[10] = "";
        sprintf(id, "%d", IDS_HELPINLINE);
        SetEnvironmentVariableA("HELPID", id);
        SetEnvironmentVariableA("HELPTITLE", "Inline Help");
        DialogBox(hInst, MAKEINTRESOURCE(DLG_HELP), hwndDlg, DlgHelp);
    }
    return TRUE;

    case WM_BROWSE:
    {
        strcpy(g_szFileName, (const char*)wParam);
        //Retrieve the directory of the file.
        int i = strlen(g_szFileName) - 1;
        int j = 0;
        while(g_szFileName[i] != '\\')
        {
            i--;
            j++;
        }
        strncpy(g_szTargetDir, g_szFileName, strlen(g_szFileName) - j - 1);

        //Retrieve stuff.
        EnableWindow(GetDlgItem(g_HWND, IDC_BTN_INLINE), FALSE);
        EnableWindow(GetDlgItem(g_HWND, IDC_BTN_COPY), FALSE);
        SendDlgItemMessageA(g_HWND, IDC_EDT_OEP, EM_SETREADONLY, 0, 0); //Enable change of OEP...
        DragAcceptFiles(g_HWND, FALSE);

        g_FileIsDll = IH_Debugger(g_szFileName, &g_TargetData, IH_DebugEnd_Callback, IH_ErrorMessageCallback);
    }
    return TRUE;

    case WM_DROPFILES:
    {
        //Get the dropped file name.
        DragQueryFileA((HDROP)wParam, 0, g_szFileName, 256);

        //Retrieve the directory of the file.
        int i = strlen(g_szFileName) - 1;
        int j = 0;
        while(g_szFileName[i] != '\\')
        {
            i--;
            j++;
        }
        strncpy(g_szTargetDir, g_szFileName, strlen(g_szFileName) - j - 1);

        //Retrieve stuff.
        EnableWindow(GetDlgItem(g_HWND, IDC_BTN_INLINE), FALSE);
        EnableWindow(GetDlgItem(g_HWND, IDC_BTN_COPY), FALSE);
        SendDlgItemMessageA(g_HWND, IDC_EDT_OEP, EM_SETREADONLY, 0, 0); //Enable change of OEP...
        DragAcceptFiles(g_HWND, FALSE);

        g_FileIsDll = IH_Debugger(g_szFileName, &g_TargetData, IH_DebugEnd_Callback, IH_ErrorMessageCallback);
    }
    return TRUE;

    case WM_COMMAND:
    {
        switch(LOWORD(wParam))
        {
        case IDC_BTN_INLINE:
        {
            NoFocus();
            if(!(g_TargetData.EmptyEntry))
            {
                MessageBoxA(hwndDlg, "You need to specify the place to start the inline...", "N00B!", MB_ICONERROR);
                return TRUE;
            }
            char patch_filename[256] = "";
            patch_filename[0] = 0;
            OPENFILENAME ofstruct;
            memset(&ofstruct, 0, sizeof(ofstruct));
            ofstruct.lStructSize = sizeof(ofstruct);
            ofstruct.hwndOwner = hwndDlg;
            ofstruct.hInstance = hInst;
            if(!g_FileIsDll)
                ofstruct.lpstrFilter = "Executable files (*.exe)\0*.exe\0\0";
            else
                ofstruct.lpstrFilter = "Executable files (*.dll)\0*.dll\0\0";
            ofstruct.lpstrFile = patch_filename;
            ofstruct.nMaxFile = 256;
            ofstruct.lpstrInitialDir = g_szTargetDir;
            ofstruct.lpstrTitle = "Save file";
            if(!g_FileIsDll)
                ofstruct.lpstrDefExt = "exe";
            else
                ofstruct.lpstrDefExt = "dll";
            ofstruct.Flags = OFN_EXTENSIONDIFFERENT | OFN_HIDEREADONLY | OFN_NONETWORKBUTTON | OFN_OVERWRITEPROMPT;
            GetSaveFileName(&ofstruct);
            if(!patch_filename[0])
            {
                MessageBoxA(hwndDlg, "You must select a file...", "Warning", MB_ICONWARNING);
                return TRUE;
            }

            CopyFileA(g_szFileName, patch_filename, FALSE);
            SetPE32Data(patch_filename, 0, UE_OEP, g_TargetData.EmptyEntry - g_TargetData.ImageBase);
            long newflags = (long)GetPE32Data(patch_filename, g_TargetData.EntrySectionNumber, UE_SECTIONFLAGS);
            SetPE32Data(patch_filename, g_TargetData.EntrySectionNumber, UE_SECTIONFLAGS, (newflags | 0x80000000));

            IH_GenerateAsmCode(g_codeText, g_TargetData);
            CopyToClipboard(g_codeText);
            MessageBoxA(hwndDlg, "1) Open the file you just saved with OllyDbg\n2) Open Multimate Assembler v1.5+\n3) Paste the code\n4) Modify the code to do something with the Security DLL\n5) Save the patched file with OllyDbg\n6) Enjoy!", "Instructions", MB_ICONINFORMATION);
        }
        return TRUE;

        case IDC_EDT_FREESPACE:
        {
            char free_temp[10] = "";
            GetDlgItemTextA(hwndDlg, IDC_EDT_FREESPACE, free_temp, 10);
            sscanf(FormatTextHex(free_temp), "%X", &(g_TargetData.EmptyEntry));
        }
        return TRUE;

        case IDC_BTN_COPY:
        {
            NoFocus();
            if(g_codeText[0])
            {
                IH_GenerateAsmCode(g_codeText, g_TargetData);
                CopyToClipboard(g_codeText);
                MessageBoxA(hwndDlg, "Code copied to clipboard!", "Yay!", MB_ICONINFORMATION);
            }
            else
                MessageBoxA(hwndDlg, "There is no code to copy, please load a file first...", "Error!", MB_ICONERROR);
        }
        return TRUE;

        case IDC_BTN_PLUGINS:
        {
            NoFocus();
            PLUGFUNC PluginFunction;
            HINSTANCE PLUGIN_INST;
            char total_found_s[5] = "";
            char plugin_name[100] = "";
            char plugin_dll[100] = "";
            char dll_to_load[256] = "";
            char temp_str[5] = "";
            int total_found = 0;
            GetPrivateProfileStringA("Plugins", "total_found", "", total_found_s, 4, sg_szPluginIniFilePath);
            sscanf(total_found_s, "%d", &total_found);
            if(total_found)
            {
                HMENU myMenu = 0;
                myMenu = CreatePopupMenu();
                for(int i = 1; i != (total_found + 1); i++)
                {
                    sprintf(temp_str, "%d", i);
                    GetPrivateProfileStringA(temp_str, "plugin_name", "", plugin_name, 100, sg_szPluginIniFilePath);
                    AppendMenuA(myMenu, MF_STRING, i, plugin_name);
                }
                POINT cursorPos;
                GetCursorPos(&cursorPos);
                SetForegroundWindow(hwndDlg);
                UINT MenuItemClicked = TrackPopupMenu(myMenu, TPM_RETURNCMD | TPM_NONOTIFY, cursorPos.x, cursorPos.y, 0, hwndDlg, 0);
                SendMessage(hwndDlg, WM_NULL, 0, 0);
                if(!MenuItemClicked)
                    return TRUE;

                sprintf(temp_str, "%d", (int)MenuItemClicked);
                GetPrivateProfileStringA(temp_str, "plugin_dll", "", plugin_dll, 100, sg_szPluginIniFilePath);
                sprintf(dll_to_load, "plugins\\%s", plugin_dll);

                PLUGIN_INST = LoadLibraryA(dll_to_load);
                if(!PLUGIN_INST)
                    MessageBoxA(hwndDlg, "There was an error loading the plugin", plugin_dll, MB_ICONERROR);
                else
                {
                    PluginFunction = (PLUGFUNC)GetProcAddress(PLUGIN_INST, "PluginFunction");
                    if(!PluginFunction)
                        MessageBoxA(hwndDlg, "The export \"PluginFunction\" could not be found, please contact the plugin supplier", plugin_dll, MB_ICONERROR);
                    else
                    {
                        if(!g_TargetData.ImageBase)
                            g_TargetData.ImageBase = 0x400000;

                        ShowWindow(GetParent(hwndDlg), 0);
                        PluginFunction(PLUGIN_INST, hwndDlg, g_TargetData.SecurityAddrRegister, sg_szAKTDirectory, g_TargetData.ImageBase);
                        ShowWindow(GetParent(hwndDlg), 1);
                        FreeLibrary(PLUGIN_INST);
                        SetForegroundWindow(hwndDlg);

                    }
                }
            }
            else
            {
                HMENU myMenu = 0;
                myMenu = CreatePopupMenu();
                AppendMenuA(myMenu, MF_STRING | MF_GRAYED, 1, "No plugins found :(");
                POINT cursorPos;
                GetCursorPos(&cursorPos);
                SetForegroundWindow(hwndDlg);
                TrackPopupMenu(myMenu, TPM_RETURNCMD | TPM_NONOTIFY, cursorPos.x, cursorPos.y, 0, hwndDlg, 0);
            }
        }
        return TRUE;

        case IDC_EDT_OEP:
        {
            char temp_oep[10] = "";
            GetDlgItemTextA(hwndDlg, IDC_EDT_OEP, temp_oep, 10);
            sscanf(temp_oep, "%X", &(g_TargetData.OEP));
        }
        return TRUE;
        }
    }
    return TRUE;
    }
    return FALSE;
}

void IH_ErrorMessageCallback(char* szMessage, char* szTitle)
{
    MessageBoxA(g_HWND, szMessage, szTitle, MB_ICONERROR);
}


void IH_DebugEnd_Callback(void)
{
    char szBuffer[20] = "";

    sprintf(szBuffer, "%08X", g_TargetData.EmptyEntry);
    SetDlgItemTextA(g_HWND, IDC_EDT_FREESPACE, szBuffer);

    sprintf(szBuffer, "%08X", g_TargetData.VirtualProtect_Addr);
    SetDlgItemTextA(g_HWND, IDC_EDT_VP, szBuffer);

    sprintf(szBuffer, "%08X", g_TargetData.OutputDebugStringA_Addr);
    SetDlgItemTextA(g_HWND, IDC_EDT_ODSA, szBuffer);

    sprintf(szBuffer, "%08X", g_TargetData.GetEnvironmentVariableA_Addr);
    SetDlgItemTextA(g_HWND, IDC_EDT_GEVA, szBuffer);

    sprintf(szBuffer, "%08X", g_TargetData.SetEnvironmentVariableA_Addr);
    SetDlgItemTextA(g_HWND, IDC_EDT_SEVA, szBuffer);

    sprintf(szBuffer, "%08X", g_TargetData.LoadLibraryA_Addr);
    SetDlgItemTextA(g_HWND, IDC_EDT_LLA, szBuffer);

    sprintf(szBuffer, "%08X", g_TargetData.GetProcAddress_Addr);
    SetDlgItemTextA(g_HWND, IDC_EDT_GPA, szBuffer);

    sprintf(szBuffer, "%08X", g_TargetData.WriteProcessMemory_Addr);
    SetDlgItemTextA(g_HWND, IDC_EDT_WPM, szBuffer);

    sprintf(szBuffer, "%02X", g_TargetData.CRCBase);
    SetDlgItemTextA(g_HWND, IDC_EDT_CRCBASE, szBuffer);

    sprintf(szBuffer, "%08X", g_TargetData.CrcOriginalVals[0]);
    SetDlgItemTextA(g_HWND, IDC_EDT_CRC1, szBuffer);

    sprintf(szBuffer, "%08X", g_TargetData.CrcOriginalVals[1]);
    SetDlgItemTextA(g_HWND, IDC_EDT_CRC2, szBuffer);

    sprintf(szBuffer, "%08X", g_TargetData.CrcOriginalVals[2]);
    SetDlgItemTextA(g_HWND, IDC_EDT_CRC3, szBuffer);

    sprintf(szBuffer, "%08X", g_TargetData.CrcOriginalVals[3]);
    SetDlgItemTextA(g_HWND, IDC_EDT_CRC4, szBuffer);

    sprintf(szBuffer, "%08X", g_TargetData.CrcOriginalVals[4]);
    SetDlgItemTextA(g_HWND, IDC_EDT_CRC5, szBuffer);

    SetDlgItemInt(g_HWND, IDC_EDT_COUNTER, g_TargetData.OutputDebugCount, TRUE);

    sprintf(szBuffer, "%08X", g_TargetData.OEP);
    SetDlgItemTextA(g_HWND, IDC_EDT_OEP, szBuffer);

    // Generate code
    IH_GenerateAsmCode(g_codeText, g_TargetData);
    SetEnvironmentVariableA("DEBUG HERE", "");
    EnableWindow(GetDlgItem(g_HWND, IDC_BTN_INLINE), TRUE);
    EnableWindow(GetDlgItem(g_HWND, IDC_BTN_COPY), TRUE);
    DragAcceptFiles(g_HWND, TRUE);
}




