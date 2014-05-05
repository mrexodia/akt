#ifndef _MSC_GLOBAL_H
#define _MSC_GLOBAL_H

#include "_global.h"

//GetCurrentSym
extern HWND MSC_shared;
extern char MSC_szFileName[256];
extern char MSC_program_dir[256];
extern LPPROCESS_INFORMATION MSC_fdProcessInfo ;
extern bool MSC_fdFileIsDll;
extern unsigned int MSC_current_sym;
extern bool MSC_getversion_set;
extern bool MSC_isdebugging;
extern unsigned int MSC_magic_addr;

//ClockBack
extern char MSC_projectID[65536];

//ProjectID
extern int MSC_cert_func_count;

void MSC_FatalError(const char* msg);

//Checksum
extern unsigned int MSC_checksum;

extern unsigned int MSC_salt_func_addr;
extern unsigned int MSC_salt_register;
extern unsigned int MSC_salt_breakpoint;
extern unsigned int MSC_project_salt;
extern BYTE MSC_salt_code[61];

///arma960 (checksum)
extern int MSC_CHK_return_counter;
extern int MSC_CHK_other_seed_counter;
extern unsigned int MSC_CHK_seeds[5];
extern unsigned char* MSC_CHK_raw_data;
///arma960 (projectid)
extern int MSC_return_counter;
extern int MSC_other_seed_counter;
extern unsigned int MSC_seeds[5];
extern unsigned char* MSC_raw_data;

//VerifySym
extern char MSC_VR_certpath[256];
extern char MSC_VR_keyspath[256];
extern char MSC_VR_magic1[10], MSC_VR_magic2[10], MSC_VR_md5_text[10];
extern char* MSC_VR_keys;
extern char* MSC_VR_keys_format;
extern unsigned int* MSC_VR_key_array;
extern unsigned int* MSC_VR_buffer_400;
extern bool MSC_VR_check_all_md5;
extern unsigned int MSC_VR_magic_value_addr;
extern unsigned int MSC_VR_magic_ebp_sub;

//Section Deleter
extern HWND MSC_SD_list;
extern bool MSC_SD_updated_sections;

struct SECTION_ANALYSIS
{
    int entry_section;
    int code_section;
    int export_section;
    int import_section;
    int resource_section;
    int relocation_section;
    int tls_section;
    int first_arma_section;
    unsigned char code_section_bytes[2];
    bool isDll;
};

extern SECTION_ANALYSIS MSC_SD_section_info;

UINT MSC_DetermineRegisterFromByte(unsigned char byte);
void MSC_SortArray(unsigned int* a, int size);
unsigned int MSC_FindReturnPattern(BYTE* d, unsigned int size);
unsigned int MSC_FindReturnPattern2(BYTE* d, unsigned int size);
unsigned int MSC_FindPush100Pattern(BYTE* d, unsigned int size);
unsigned int MSC_FindCall1Pattern(BYTE* d, unsigned int size);
unsigned int MSC_FindCall2Pattern(BYTE* d, unsigned int size);
unsigned int MSC_FindAndPattern1(BYTE* d, unsigned int size);
unsigned int MSC_FindAndPattern2(BYTE* d, unsigned int size);
unsigned int MSC_FindStdcallPattern(BYTE* d, unsigned int size);

#endif
