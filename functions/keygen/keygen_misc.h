#ifndef _KEYGENMISC_H
#define _KEYGENMISC_H

#include <windows.h>
#include <stdio.h>
#include <ctime>

void AddLogMessage(HWND log, const char* m, bool first);
int ByteArray2String(unsigned char* s, char* d, int s_len, int d_len);
int String2ByteArray(const char* s, unsigned char* d, int d_len);
void CookText(char *target, const char *source);
void InterpretDate(unsigned short keymade, unsigned short *year, unsigned short *month, unsigned short *day);
unsigned long hextoint(const char *string);

#endif
