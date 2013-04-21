#ifndef _VF_DIALOG_H
#define _VF_DIALOG_H

#include "VersionFind_global.h"
#include "VersionFind_decode.h"
#include "VersionFind_extraoptions.h"
#include "VersionFind_rawoptions.h"
#include "VersionFInd_version.h"

#include "help_dialog.h"

DWORD WINAPI VF_DebugThread(void* lpVoid);
BOOL CALLBACK VF_DlgMain(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

#endif
