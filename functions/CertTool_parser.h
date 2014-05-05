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

#define v400h 0x42400000
#define v410420l 0x42100000
#define v410420h 0x42B00000
#define v430604l 0x42A00000
#define v430604h 0x48F00000
#define v620740l 0x48900000
#define v620740h 0x4C900000
#define v800h 0x4C300000

#define fcustomerservice 0x1
#define fwebsite 0x10
#define funknown 0x100

#endif
