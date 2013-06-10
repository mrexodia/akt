#ifndef _MSC_SECTIONDELETER_H
#define _MSC_SECTIONDELETER_H

#include "Misc_global.h"

bool MSC_SD_IsArmadilloProtected(char* va);
bool MSC_SD_IsValidPe(char* va);
bool MSC_SD_RemoveWatermark(HWND hwndDlg);
void MSC_SD_LoadFile(HWND hwndDlg);
bool MSC_SD_RemoveSection(HWND hwndDlg, int i);

#endif
