#ifndef _TABS_H
#define _TABS_H

#define _WIN32_WINNT 0x0501
#define WINVER 0x0501
#define _WIN32_IE 0x0500

#include <windows.h>
#include <uxtheme.h>
#include <stdio.h>
#include <commctrl.h>

#define MAX_TABS 10

//Tab structure, contains all needed information
typedef struct tag_dlghdr
{
    DLGPROC father_proc;           //used for automatic tab switching
    int total_tabs;                //tab counter
    HWND hwndTab;                  //tab control
    HWND hwndDisplay;              //current child dialog box
    DLGTEMPLATE *apRes[MAX_TABS];  //dialog template
    DLGPROC windowProc[MAX_TABS];  //window procedure
    WNDPROC tabWndProcOld;         //original wndproc from tab...
    HINSTANCE dlg_hinst[MAX_TABS]; //hinst for the dialog
    HWND dlg_hwnd[MAX_TABS];       //different window handles
    UINT dlg_id[MAX_TABS];         //dialog id (resource id)
    bool auto_resize_window;       //auto_resize flags
    bool auto_resize_tab_control;  //auto_resize flags
    bool accept_files[MAX_TABS];   //accept files flag
    bool handles_help[MAX_TABS];   //Handles the WM_HELP message?
    RECT tabRect;                  //child window placing
    char* tab_name[MAX_TABS];      //tab name
} DLGHDR;

void WINAPI OnChildDialogInit(HWND hwndDlg);
BOOL CALLBACK tab_hook(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
void OnSelChanged(HWND hwndDlg);
void SelectTab(HWND hwndDlg, int id);
BOOL CALLBACK notify_hook(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
BOOL CALLBACK DropFileSubClass(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
DLGTEMPLATE* DoLockDlgRes(HINSTANCE hInstance, LPCTSTR lpszResName);
void InitTabStruct(HWND hwndDlg, UINT tab_id, bool auto_resize_window, bool auto_resize_tab_control);
void print_rect(RECT* r, const char* title);
void AddTabbedDialog(HINSTANCE hInstance, HWND hwndDlg, const char* tab_title, UINT dlg_id, DLGPROC dlg_proc, bool accept_files, bool handles_help);

#endif
