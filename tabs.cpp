#include "tabs.h"

HBRUSH g_hbrBkgnd = CreateSolidBrush(0);

//Places the window in the tab rectangle, also resizes the window when specified
void WINAPI OnChildDialogInit(HWND hwndDlg)
{
    HWND hwndParent=GetParent(hwndDlg);
    DLGHDR* pHdr=(DLGHDR*)GetWindowLong(hwndParent, GWL_USERDATA);
    UINT flags=SWP_SHOWWINDOW|SWP_NOZORDER;
    if(!pHdr->auto_resize_window)
        flags|=SWP_NOSIZE;

    RECT TabRect;
    GetWindowRect(pHdr->hwndTab, &TabRect);
    MapWindowPoints(HWND_DESKTOP, GetParent(pHdr->hwndTab), (POINT *)&TabRect, 2);
    SendMessage(pHdr->hwndTab, TCM_ADJUSTRECT, false, (LPARAM)&TabRect);
    TabRect.right  -= TabRect.left; // .right  == width
    TabRect.bottom -= TabRect.top;  // .bottom == heigth
    SetWindowPos(hwndDlg, HWND_BOTTOM, TabRect.left-1, TabRect.top, TabRect.right, TabRect.bottom, flags);

    //SetWindowPos(hwndDlg, NULL, pHdr->tabRect.left-1, pHdr->tabRect.top-6, pHdr->tabRect.right, pHdr->tabRect.bottom, flags);
    //SetWindowPos(hwndDlg, NULL, pHdr->tabRect.left, pHdr->tabRect.top, pHdr->tabRect.right, pHdr->tabRect.bottom, flags);
    return;
}

//Hook for the child dialog to process the dialog initialization (window position and size)
BOOL CALLBACK tab_hook(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    HWND hwndParent=GetParent(hwndDlg);
    DLGHDR* pHdr=(DLGHDR*)GetWindowLong(hwndParent, GWL_USERDATA);
    int iSel=TabCtrl_GetCurSel(pHdr->hwndTab);
    switch(uMsg)
    {
    case WM_INITDIALOG:
    {
        OnChildDialogInit(hwndDlg);
    }
    break;
    }
    return CallWindowProc((WNDPROC)pHdr->windowProc[iSel], hwndDlg, uMsg, wParam, lParam);
}

//Creates or shows the child dialog, old dialog is hidden
void OnSelChanged(HWND hwndDlg)
{
    //Get the dialog header data.
    DLGHDR* pHdr=(DLGHDR*)GetWindowLong(hwndDlg, GWL_USERDATA);
    //Get the index of the selected tab.
    int iSel=TabCtrl_GetCurSel(pHdr->hwndTab);
    //Set some local variables for code size
    HWND* dlg_hwnd=&pHdr->dlg_hwnd[iSel]; //Should save a little memory, we just set a local variable with a pointer
    //DragAcceptFiles(pHdr->hwndTab, pHdr->accept_files[iSel]); //Accept files when specified to do so...
    DragAcceptFiles(pHdr->hwndTab, 1); //Accept files when specified to do so...
    HWND* hwnd_dis=&pHdr->hwndDisplay; //Same trick here
    //Disable and hide the old window (so use input stays)
    if(*hwnd_dis)
    {
        EnableWindow(*hwnd_dis, 0);
        ShowWindow(*hwnd_dis, 0);
    }
    //We want to process the WM_INITDIALOG message only once
    if(!*dlg_hwnd)
    {
        *dlg_hwnd=CreateDialogIndirect(pHdr->dlg_hinst[iSel], (DLGTEMPLATE*)pHdr->apRes[iSel], hwndDlg, tab_hook);
        EnableThemeDialogTexture(*dlg_hwnd, ETDT_USETABTEXTURE);
    }

    //Already processed, just view and enable the window.
    else
    {
        EnableWindow(*dlg_hwnd, 1);
        ShowWindow(*dlg_hwnd, 1);
    }
    *hwnd_dis=*dlg_hwnd;
    return;
}

//Sets & Activates a new tab
void SelectTab(HWND hwndDlg, int id)
{
    DLGHDR* pHdr=(DLGHDR*)GetWindowLong(hwndDlg, GWL_USERDATA);
    TabCtrl_SetCurSel(pHdr->hwndTab, id);
    OnSelChanged(hwndDlg);
}

//Hooks the WM_NOTIFY message of the main window to detect selection changes
BOOL CALLBACK notify_hook(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    DLGHDR* pHdr=(DLGHDR*)GetWindowLong(hwndDlg, GWL_USERDATA);
    switch(uMsg)
    {
    case WM_HELP:
    {
        int iSel=TabCtrl_GetCurSel(pHdr->hwndTab);
        if(pHdr->handles_help[iSel])
            SendMessageA(pHdr->dlg_hwnd[iSel], WM_HELP, wParam, lParam);
    }
    break;

    case WM_NOTIFY:
    {
        switch(((LPNMHDR)lParam)->code)
        {
        case TCN_SELCHANGE:
        {
            OnSelChanged(hwndDlg);
        }
        return TRUE;
        }
    }
    break;
    }
    return CallWindowProc((WNDPROC)pHdr->father_proc, hwndDlg, uMsg, wParam, lParam);
}

//Handles file drag & drop
BOOL CALLBACK DropFileSubClass(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    HWND hwndParent=GetParent(hwndDlg);
    DLGHDR* pHdr=(DLGHDR*)GetWindowLong(hwndParent, GWL_USERDATA);
    switch(uMsg)
    {
    case WM_DROPFILES:
    {
        int iSel=TabCtrl_GetCurSel(pHdr->hwndTab);
        if(pHdr->accept_files[iSel]) //Tab selected that accepts files
        {
            SendMessageA(pHdr->dlg_hwnd[iSel], WM_DROPFILES, wParam, 0);
        }
        else //Create menu with supported tabs
        {
            int totalTabs=TabCtrl_GetItemCount(pHdr->hwndTab);
            HMENU myMenu=NULL;
            myMenu=CreatePopupMenu();

            bool accept;
            int counter=0;
            while(counter<totalTabs)
            {
                accept=pHdr->accept_files[counter];
                if(accept)
                {
                    AppendMenuA(myMenu, MF_STRING, counter, pHdr->tab_name[counter]);
                }
                counter++;
            }

            POINT cursorPos;
            GetCursorPos(&cursorPos);
            SetForegroundWindow(hwndParent);
            UINT MenuItemClicked=TrackPopupMenu(myMenu, TPM_RETURNCMD | TPM_NONOTIFY, cursorPos.x, cursorPos.y, 0, hwndParent, NULL);
            SendMessage(hwndParent, WM_NULL, 0, 0);
            if(!MenuItemClicked)
                return TRUE;

            SelectTab(hwndParent, MenuItemClicked);
            SendMessageA(pHdr->dlg_hwnd[MenuItemClicked], WM_DROPFILES, wParam, 0);
        }
    }
    return TRUE;
    }
    return CallWindowProc(pHdr->tabWndProcOld, hwndDlg, uMsg, wParam, lParam);
}

//Loads and locks a dialog resource (for creating the child dialog)
DLGTEMPLATE* DoLockDlgRes(HINSTANCE hInstance, LPCTSTR lpszResName)
{
    HRSRC hrsrc=FindResource(NULL, lpszResName, RT_DIALOG);
    HGLOBAL hglb=LoadResource(hInstance, hrsrc);
    return (DLGTEMPLATE*)LockResource(hglb);
}

//Initialize the structure for the tab control (currently only one control is supported)
void InitTabStruct(HWND hwndDlg, UINT tab_id, bool auto_resize_window, bool auto_resize_tab_control)
{
    DLGHDR* pHdr=(DLGHDR*)LocalAlloc(LPTR, sizeof(DLGHDR));
    SetWindowLong(hwndDlg, GWL_USERDATA, (LONG)pHdr);
    pHdr->father_proc=(DLGPROC)SetWindowLong(hwndDlg, DWL_DLGPROC, (LONG)notify_hook);
    pHdr->hwndTab=GetDlgItem(hwndDlg, tab_id);
    pHdr->total_tabs=0;
    pHdr->auto_resize_window=auto_resize_window;
    pHdr->auto_resize_tab_control=auto_resize_tab_control;
    pHdr->tabWndProcOld=(WNDPROC)SetWindowLong(pHdr->hwndTab, GWLP_WNDPROC, (LONG)DropFileSubClass);
}

//Used for debugging, prints information about a specified rectangle
void print_rect(RECT* r, const char* title)
{
    char print_text[512]="";
    sprintf(print_text, "left (x of the upper-left corner):\r\n%d\r\ntop (y upper-left corner):\r\n%d\r\nright (x lower-right corner):\r\n%d\r\nbottom (y lower-right corner):\r\n%d\r\nheight (bottom-top)\r\n%d\r\nwidth (right-left)\r\n%d", (int)r->left, (int)r->top, (int)r->right, (int)r->bottom, (int)(r->bottom-r->top), (int)(r->right-r->left));
    if(title)
        MessageBoxA(0, print_text, title, MB_ICONINFORMATION);
    else
        MessageBoxA(0, print_text, "", MB_ICONINFORMATION);
}

//Adds a tab with embedded (child) dialog to the tabcontrol... (Call InitTabStruct first)
void AddTabbedDialog(HINSTANCE hInstance, HWND hwndDlg, const char* tab_title, UINT dlg_id, DLGPROC dlg_proc, bool accept_files, bool handles_help)
{
    //DWORD dwDlgBase=GetDialogBaseUnits();
    //int cxMargin=LOWORD(dwDlgBase)/4;
    //int cyMargin=HIWORD(dwDlgBase)/8;
    int* total_tabs=0;
    TCITEM tab;
    //RECT rcTab;
    //Retrieve our tab structure
    DLGHDR* pHdr=(DLGHDR*)GetWindowLong(hwndDlg, GWL_USERDATA);
    //Assign some pointers to local vars for code size
    HWND hwndTab=pHdr->hwndTab;
    total_tabs=&pHdr->total_tabs;
    HINSTANCE* dlg_hinst=&pHdr->dlg_hinst[*total_tabs];
    //Inserts a tab
    tab.mask=TCIF_TEXT; //Just text
    tab.pszText=(char*)tab_title; //Title
    TabCtrl_InsertItem(hwndTab, *total_tabs, &tab); //Insert the tab
    //Backup name for later use
    int namelen=strlen(tab_title);
    char* namebak=(char*)malloc(namelen+1);
    memset(namebak, 0, namelen+1);
    strcpy(namebak, tab_title);
    //Add the specified dialog in the structure
    if(hInstance)
        *dlg_hinst=hInstance;
    else
        *dlg_hinst=GetModuleHandleA(0);
    pHdr->apRes[*total_tabs]=DoLockDlgRes(*dlg_hinst, MAKEINTRESOURCE(dlg_id));
    pHdr->dlg_id[*total_tabs]=dlg_id;
    //pHdr->apRes[*total_tabs]->style=DS_CONTROL | DS_SHELLFONT | WS_BORDER | WS_VISIBLE | WS_CHILDWINDOW;
    pHdr->windowProc[*total_tabs]=dlg_proc;
    pHdr->accept_files[*total_tabs]=accept_files;
    pHdr->handles_help[*total_tabs]=handles_help;
    pHdr->tab_name[*total_tabs]=namebak;
    total_tabs[0]++;
    //Determine a bounding rectangle that is large enough to
    //contain the largest child dialog box.
    /*SetRectEmpty(&rcTab);
    for(int i=0; i<*total_tabs; i++)
    {
        if(pHdr->apRes[i]->cx>rcTab.right)
            rcTab.right=pHdr->apRes[i]->cx;
        if(pHdr->apRes[i]->cy>rcTab.bottom)
            rcTab.bottom=pHdr->apRes[i]->cy;
    }
    //Map the rectangle from dialog box units to pixels.
    MapDialogRect(hwndDlg, &rcTab);
    //Calculate how large to make the tab control, so
    //the display area can accommodate all the child dialog boxes.
    TabCtrl_AdjustRect(hwndTab, TRUE, &rcTab);

    OffsetRect(&rcTab, cxMargin-rcTab.left, cyMargin-rcTab.top);
    //Calculate the display rectangle.
    RECT rcDisplay= {0};
    CopyRect(&rcDisplay, &rcTab);
    TabCtrl_AdjustRect(hwndTab, FALSE, &rcDisplay);
    pHdr->tabRect.right=rcDisplay.right-rcDisplay.left;
    pHdr->tabRect.bottom=rcDisplay.bottom-rcDisplay.top;
    //Set the size and position of the tab control
    UINT flags=SWP_NOZORDER|SWP_NOMOVE;
    if(!pHdr->auto_resize_tab_control)
        flags|=SWP_NOSIZE;
    if(!pHdr->auto_resize_window)
        SetWindowPos(hwndTab, NULL, rcTab.left, rcTab.top, rcTab.right-rcTab.left, rcTab.bottom-rcTab.top+2, flags);
    else
        SetWindowPos(hwndTab, NULL, rcTab.left, rcTab.top, rcTab.right-rcTab.left-2, rcTab.bottom-rcTab.top, flags);
    RECT tab_rect= {0};
    RECT wrect= {0};
    GetWindowRect(hwndTab, &tab_rect);
    GetWindowRect(hwndDlg, &wrect);
    //Calculate tab starting point
    tab_rect.left-=wrect.left;
    pHdr->tabRect.left=tab_rect.left;
    tab_rect.top-=wrect.top;
    pHdr->tabRect.top=tab_rect.top;*/
    OnSelChanged(hwndDlg);
}
