#ifndef _CT_PARSER_H
#define _CT_PARSER_H

#include "CertTool_global.h"
#include "CertTool_decrypt.h"
#include "CertTool_brute.h"

extern bool CT_created_log;
extern bool CT_isparsing;

void CT_AddToLog(HWND list, const char* text);
void CT_AddLogMessage(HWND list, const char* text);
void CT_ParseCerts();

#endif
