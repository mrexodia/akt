#ifndef _CT_PARSER_H
#define _CT_PARSER_H

#include "CertTool_global.h"
#include "CertTool_decrypt.h"

void CT_AddToLog(HWND list, const char* text);
void CT_AddLogMessage(HWND list, const char* text);
void CT_ParseCerts();

#endif
