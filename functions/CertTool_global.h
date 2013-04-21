#ifndef _CT_GLOBAL
#define _CT_GLOBAL

#include "_global.h"

extern HWND CT_shared;

extern char CT_szFileName[256];
extern char CT_szProgramDir[256];
extern char CT_szLogFile[256];
extern char CT_szAktLogFile[256];
extern char CT_szCryptCertFile[256];
extern char CT_szRawCertFile[256];
extern bool CT_created_log;
extern bool CT_isdebugging;
extern bool CT_isparsing;
extern bool CT_logtofile;
extern bool CT_brute;
extern bool CT_brute_initialized;
extern bool CT_brute_dlp_initialized;
extern bool CT_brute_nosym;
extern bool CT_brute_symverify;
extern bool CT_fdFileIsDll;
extern unsigned int CT_time1;

struct CERT_DATA
{
    unsigned char* raw_data;
    unsigned char* encrypted_data;
    char* projectid;
    //char* customerservice;
    //char* website;
    unsigned int projectid_diff;
    unsigned int initial_diff;
    unsigned int raw_size;
    unsigned int encrypted_size;
    unsigned int first_dw;
    unsigned int magic1;
    unsigned int magic2;
    unsigned int salt;
    unsigned int decrypt_seed[3];
    unsigned int decrypt_addvals[4];
    bool checksumv8;
    bool zero_md5_symverify;
};

struct BRUTE_DATA
{
    unsigned int magic1;
    unsigned int magic2;
    unsigned int md5;
    unsigned char* encrypted_data;
    unsigned int encrypted_size;
};

extern BRUTE_DATA* CT_current_brute;
extern CERT_DATA* CT_cert_data;

extern unsigned int CT_magic_value_addr;
extern unsigned int CT_magic_ebp_sub;
extern unsigned int CT_magic_byte;
extern unsigned int CT_tea_decrypt;
extern unsigned int CT_noteax;
extern unsigned int CT_end_big_loop;
extern unsigned char CT_magic_byte_cert;
extern unsigned short CT_cmp_data;
extern unsigned char* CT_encrypted_cert_real;
extern unsigned int CT_encrypted_cert_real_size;
extern bool CT_patched_magic_jump;
extern UINT CT_register_magic_byte;
extern unsigned int CT_salt_func_addr;
extern unsigned int CT_salt_register;
extern unsigned int CT_salt_breakpoint;
extern BYTE CT_salt_code[61];
extern int CT_cert_func_count;
extern LPPROCESS_INFORMATION CT_fdProcessInfo;

typedef struct _hash_list
{
    int count;
    unsigned long hash[32];
} hash_list;

typedef void (*PRINT_FOUND)(unsigned long hash, unsigned long key);
typedef void (*PRINT_PROGRESS)(double checked, double all, time_t* start);
typedef void (*PRINT_ERROR)(const char* error_msg);

typedef void (*BRUTESTART)(int alg, hash_list *list, unsigned long from, unsigned long to, unsigned long param);
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

extern int CT_return_counter;
extern int CT_other_seed_counter;

void CT_FatalError(const char* msg);
int CT_NextSeed(int data);
unsigned int CT_FindCertificateFunctionOld(BYTE* d, unsigned int size);
unsigned int CT_FindCertificateFunctionNew(BYTE* d, unsigned int size);
unsigned int CT_FindCertificateMarkers(BYTE* d, unsigned int size);
unsigned int CT_FindCertificateMarkers2(BYTE* d, unsigned int size);
unsigned int CT_FindCertificateEndMarkers(BYTE* mem_addr, unsigned int size);
unsigned int CT_FindMagicPattern(BYTE* d, unsigned int size, unsigned int* ebp_sub);
unsigned int CT_FindEndInitSymVerifyPattern(BYTE* d, unsigned int size);
unsigned int CT_FindPubMd5MovePattern(BYTE* d, unsigned int size);
unsigned int CT_FindDecryptKey1Pattern(BYTE* d, unsigned int size);
unsigned int CT_FindMagicJumpPattern(BYTE* d, unsigned int size, unsigned short* data);
unsigned int CT_FindECDSAVerify(BYTE* d, unsigned int size);
unsigned int CT_FindPushFFPattern(BYTE* d, unsigned int size);
unsigned int CT_FindTeaDecryptPattern(BYTE* d, unsigned int size);
unsigned int CT_FindNextDwordPattern(BYTE* d, unsigned int size);
unsigned int CT_FindReturnPattern(BYTE* d, unsigned int size);
unsigned int CT_FindReturnPattern2(BYTE* d, unsigned int size);
unsigned int CT_FindPush100Pattern(BYTE* d, unsigned int size);
unsigned int CT_FindCall1Pattern(BYTE* d, unsigned int size);
unsigned int CT_FindCall2Pattern(BYTE* d, unsigned int size);
unsigned int CT_FindAndPattern1(BYTE* d, unsigned int size);
unsigned int CT_FindAndPattern2(BYTE* d, unsigned int size);
unsigned int CT_FindStdcallPattern(BYTE* d, unsigned int size);
unsigned int CT_FindVerifySymPattern(BYTE* d, unsigned int size);
unsigned int CT_FindEndLoopPattern(BYTE* d, unsigned int size);

#endif
