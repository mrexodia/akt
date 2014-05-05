#ifndef _IH_DIALOG_H
#define _IH_DIALOG_H

#include "InlineHelper_global.h"
#include "InlineHelper_debugger.h"
#include "help_dialog.h"


/**********************************************************************
 *						Prototypes
 *********************************************************************/
BOOL CALLBACK IH_DlgMain(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
void IH_ErrorMessageCallback(char* szMessage, char* szTitle);
void IH_DebugEnd_Callback(void);

#endif
