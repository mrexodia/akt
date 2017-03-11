#ifndef _KEYGENMAIN_H
#define _KEYGENMAIN_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <windows.h>
#include <time.h>
#define USECLOCKTICKS
#include "keygen_misc.h"
#include "keygen_bigint.h"
#include "keygen_md5.h"
#include "keygen_random.h"
#include "keygen_ecc.h"
#include "keygen_blowfish.h"
#include "keygen_crc32.h"
#include "keygen_info.h"

#define KS_V1 -1
#define KS_V2 0
#define KS_V3 1
#define KS_SHORTV3 2

extern const int primeoffsetcount, primeoffsets[];

const char* CreateKey(unsigned int symmetric_key, unsigned int sym_xor, const char* regname, unsigned short otherinfo, unsigned long hardwareID, short today, HWND log);
unsigned char* AddByte(unsigned char* c, unsigned char n);
unsigned char* AddShort(unsigned char* c, unsigned short n);
unsigned char* AddLong(unsigned char* c, unsigned long n);
void mystrrev(char* str);
CRC32 GetKeyCRC(char* keytext, int period);
void GetKeyMD5(unsigned long* i, const char* keytext, int period);
void GenerateKeyNumberFromString(char* string, BigInt p, BigInt* keynumber, int keysystem, int v3level);
int MakeEccSignature(unsigned char* keybytes, int* keylength, char* name_to_make_key_for, int level, const char* prvt_text, const char* public_text, bool baboon, HWND log);
int MakeSignature(unsigned char* keybytes, int* keylength, char* name_encryptkey, int level, const char* pvt_kg_txt, const char* y_kg_txt, bool baboon, HWND log);
void EncryptSignedKey(unsigned char* keybytes, int keylength, char* encryptkey, HWND log);
const char* CreateSignedKey(int level, unsigned int symmetric_key, unsigned int sym_xor, const char* pvt_kg_txt, const char* y_kg_txt, const char* keystring, short today, const char* _name_to_make_key_for, unsigned long hardwareID, unsigned short otherinfo1, unsigned short otherinfo2, unsigned short otherinfo3, unsigned short otherinfo4, unsigned short otherinfo5, bool baboon, HWND log = 0);
unsigned short MakeDate(unsigned int year, unsigned int month, unsigned int day);

#endif
