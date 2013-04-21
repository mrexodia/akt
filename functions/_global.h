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

//#include "help_dialog.h"
//#include "about.h"
//#include "encdec.h"
//#include "analysis.h"
//#include "keygenerate.h"
//#include "InlineHelper_plugins.h"
//#include "InlineHelper_codegen.h"
//#include "InlineHelper_debugger.h"
//#include "InlineHelper_dialog.h"
//#include "InlineHelper_decrypt.h"
//#include "EVLog_debugger.h"
//#include "EVLog_maindlg.h"
//#include "VersionFind_version.h"
//#include "VersionFind_rawoptions.h"
//#include "VersionFind_extraoptions.h"
//#include "VersionFind_decode.h"
//#include "VersionFind_dialog.h"
//#include "Misc_currentsym.h"
//#include "Misc_sectiondeleter.h"
//#include "Misc_projectid.h"
//#include "Misc_checksum.h"
//#include "Misc_verifysym.h"
//#include "Misc_dialog.h"
//#include "CertTool_decrypt.h"
//#include "CertTool_parser.h"
//#include "CertTool_debugger.h"
//#include "CertTool_brute.h"
//#include "CertTool_dialog.h"


extern HINSTANCE hInst;
extern bool log_version;
extern bool help_open;
extern char program_dir[256];
extern char FormatTextHex_format[1024];

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
