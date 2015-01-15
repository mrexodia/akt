#ifndef _KEYGENINFO_H
#define _KEYGENINFO_H

#include "keygen_misc.h"
#include "keygen_blowfish.h"
#include "keygen_bigint.h"
#include "keygen_crc32.h"

#include <windows.h>
#include <stdio.h>

/*
    -----------------------------------------------
    Key information functions, to take a key apart.
    -----------------------------------------------
*/

struct KeyInformation
{
    unsigned short createdyear, createdmonth, createdday;
    unsigned short otherinfo[5];
    unsigned long symkey;
    unsigned long uninstallcode;
    char keystring[256];
    int keystring_length;
};

int hexdigit(char c);
const char* GetTwoHexDigits(const char* c, unsigned char* value);
char RetrieveKeyInfo(int level_input, const char* name_, unsigned long hardwareID, const char* origkey_, struct KeyInformation* keyinfo, HWND hwndDlg, UINT control_id);

#endif
