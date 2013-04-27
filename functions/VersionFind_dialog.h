#ifndef _VF_DIALOG_H
#define _VF_DIALOG_H

#include "VersionFind_global.h"
#include "VersionFind_decode.h"
#include "VersionFind_extraoptions.h"
#include "VersionFind_rawoptions.h"
#include "VersionFInd_version.h"

#include "help_dialog.h"

/**********************************************************************
 *						Prototypes
 *********************************************************************/
BOOL CALLBACK VF_DlgMain(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
DWORD WINAPI VF_DebugThread(void* lpVoid);
void ErrorMessageCallback(char* szMessage, char* szTitle);
void CheckButton(int id);
void UncheckButton(int id);
void EnableWin(int id, bool a);
void ResetContent(bool clear_all);
void PrintArmaOptionsStruct(ARMA_OPTIONS* op, char* log, unsigned int raw_options, unsigned int extra_options);

#endif
