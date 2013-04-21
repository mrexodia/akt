#ifndef _CT_BRUTE_H
#define _CT_BRUTE_H

#include "CertTool_global.h"
#include "CertTool_parser.h"
#include "Misc_verifysym.h"


bool InitializeSymBruteLibrary(HWND hwndDlg);
bool InitializeDlpBruteLibrary(HWND hwndDlg);
void cbBruteError(const char* error_msg);
void cbBrutePrintFound(unsigned long hash, unsigned long key);
void cbBruteProgess(double checked, double all, time_t* start);

#endif
