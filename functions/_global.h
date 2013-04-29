#ifndef _GLOBAL_H
#define _GLOBAL_H

#define _WIN32_WINNT 0x0501
#define WINVER 0x0501
#define _WIN32_IE 0x0500

#include <windows.h>
#include <commctrl.h>

#include "..\resource.h"
#include "..\TitanEngine\TitanEngine.h"
#include "..\BeaEngine/BeaEngine.h"
#include "..\exception/akt_exception.h"

#include "keygen\keygen_main.h"

#include "Basics.h"


extern char sg_szAKTDirectory[256];
extern char sg_szPluginIniFilePath[256];

extern HINSTANCE hInst;
extern bool log_version;
extern char program_dir[256];

UINT DetermineRegisterFromText(char* reg_text);
unsigned int FindDwordInMemory(BYTE* dump_addr, unsigned dword_to_find, unsigned int filesize);
void LeftClick();
void PasteFromClipboard(char* d, int maxlen);
void CopyToClipboard(const char* text);
char* FormatTextHex(const char* text);
void SetLevelList(HWND hwndDlg);
void NoFocus();
bool IsHexChar(char c);
void FormatHex(char* string);
int StringToByteArray(const char* s, unsigned char* d, int d_len);
int ByteArrayToString(unsigned char* s, char* d, int s_len, int d_len);
char* EncodeShortV3(unsigned char* keybytes, int keylength, bool level10);
int DecodeShortV3(const char* serial, bool level10, unsigned char* dest, int dest_len);
unsigned int FindBAADF00DPattern(BYTE* d, unsigned int size);
unsigned int FindSalt1Pattern(BYTE* d, unsigned int size);
unsigned int FindSalt2Pattern(BYTE* d, unsigned int size);
bool IsArmadilloProtected(ULONG_PTR va);

#endif
