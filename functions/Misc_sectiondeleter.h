#ifndef _MSC_SECTIONDELETER_H
#define _MSC_SECTIONDELETER_H

#include "Misc_global.h"

bool MSC_SD_IsArmadilloProtected(char* va);
unsigned int MSC_SD_HasOverlay(char* va, unsigned int filesize);
bool MSC_SD_DumpOverlay(const char* filename);
bool MSC_SD_IsValidPe(char* va);
bool MSC_SD_RemoveWatermark(HWND hwndDlg);
void MSC_SD_LoadFile(HWND hwndDlg);
bool MSC_SD_RemoveSection(HWND hwndDlg, int i);

#endif
