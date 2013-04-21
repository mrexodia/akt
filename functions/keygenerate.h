#ifndef _KEYGENERATE_H
#define _KEYGENERATE_H

#include "_global.h"
#include "help_dialog.h"

void KG_GenerateEcdsaParameters(const char* encryptiontemplate, char* private_text, char* basepoint_text, char* public_x_text, char* public_y_text);
bool KG_GeneratePvtY(int level, char* keytemplate, char* pvt_text, char* y_text);
unsigned int KG_GenerateSymmetric(int level, char* encryption_template);
BOOL CALLBACK KG_DlgKeyGenerate(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

#endif
