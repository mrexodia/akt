#ifndef _CT_BRUTE_H
#define _CT_BRUTE_H

#include "CertTool_global.h"
#include "CertTool_parser.h"
#include "Misc_verifysym.h"

typedef struct _hash_list
{
    int count;
    unsigned long hash[32];
} hash_list;

typedef void (*PRINT_FOUND)(unsigned long hash, unsigned long key);
typedef void (*PRINT_PROGRESS)(double checked, double all, time_t* start);
typedef void (*PRINT_ERROR)(const char* error_msg);

typedef void (*BRUTESTART)(int alg, hash_list *list, unsigned long from, unsigned long to, unsigned long* param);
typedef void (*SETCALLBACKS)(PRINT_FOUND cb1, PRINT_PROGRESS cb2, PRINT_ERROR cb3);
typedef void (*BRUTESTOP)();
typedef void (*BRUTESETTINGS)(HWND parent);
typedef int(*UPDATEKEYS)(int level, const char* y_txt);
typedef int(*SOLVEDLP)(const char* pvt_txt);

extern HINSTANCE hBrute;
extern BRUTESTART BruteStart;
extern SETCALLBACKS BruteSetCallbacks;
extern BRUTESTOP BruteStop;
extern BRUTESETTINGS BruteSettings;

void cbBruteProgess(double checked, double all, time_t* start);
void cbBrutePrintFound(unsigned long hash, unsigned long key);
void cbBruteError(const char* error_msg);

extern HINSTANCE hBruteDlp;
extern UPDATEKEYS UpdateKeys;
extern SOLVEDLP SolveDlp;

extern int CT_total_sym_found;
extern char* CT_section_name;
extern bool CT_brute_is_paused;
extern bool CT_brute_shutdown;
extern bool CT_brute;
extern bool CT_brute_initialized;
extern bool CT_brute_dlp_initialized;
extern bool CT_brute_nosym;
extern bool CT_brute_symverify;

struct BRUTE_DATA
{
    unsigned int magic1;
    unsigned int magic2;
    unsigned int md5;
    unsigned char* encrypted_data;
    unsigned int encrypted_size;
};

extern BRUTE_DATA* CT_current_brute;

bool InitializeSymBruteLibrary(HWND hwndDlg);
bool InitializeDlpBruteLibrary(HWND hwndDlg);
void cbBruteError(const char* error_msg);
void cbBrutePrintFound(unsigned long hash, unsigned long key);
void cbBruteProgess(double checked, double all, time_t* start);

#endif
