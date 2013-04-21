#ifndef _CT_GLOBAL
#define _CT_GLOBAL

#include "_global.h"

HWND CT_shared;

char CT_szFileName[256]=""; //debugged program
char CT_szProgramDir[256]=""; //debugged program dir
char CT_szLogFile[256]=""; //_cert.log file
char CT_szAktLogFile[256]=""; //_cert.tpodt file
char CT_szCryptCertFile[256]=""; //_cert.bin file
char CT_szRawCertFile[256]=""; //_raw.cert file
bool CT_created_log=false; //bool for if our log was created
bool CT_isdebugging=false; //Is retrieving cert info?
bool CT_isparsing=false; //Is parsing certificate info?
bool CT_logtofile=true; //Create log files?
bool CT_brute=false; //Solve certs?
bool CT_brute_initialized=false; //initialized sym brute lib?
bool CT_brute_dlp_initialized=false; //initialized dlp brute lib?
bool CT_brute_nosym=false; //Skip sym solving?
bool CT_brute_symverify=false; //verify symmetric before taking it as valid?
bool CT_fdFileIsDll=false; //Debugged is dll?
unsigned int CT_time1=0; //For duration calculation.

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

BRUTE_DATA* CT_current_brute;
CERT_DATA* CT_cert_data;

unsigned int CT_magic_value_addr=0; //address of the magic values place
unsigned int CT_magic_ebp_sub=0; //ebp difference to retrieve the magic from
unsigned int CT_magic_byte=0; //address of the compare of the crc byte
unsigned int CT_tea_decrypt=0; //address of the tea decrypt function
unsigned int CT_noteax=0; //address of the sym check place (not [reg])
unsigned int CT_end_big_loop=0; //end of the certificate loop
unsigned char CT_magic_byte_cert=0; //correct crc byte
unsigned short CT_cmp_data=0; //cmp [reg],[reg] bytes for disassembly
unsigned char* CT_encrypted_cert_real=0; //certificate container byte parts
unsigned int CT_encrypted_cert_real_size=0; //size of the current piece
bool CT_patched_magic_jump=false; //bool to ensure we can retrieve all certificates (dynamically)
UINT CT_register_magic_byte=0; //register (titsEngine form) to retrieve the current byte from
unsigned int CT_salt_func_addr=0; //Address of the salt function
unsigned int CT_salt_register=0; //Register to retrieve salt from
unsigned int CT_salt_breakpoint=0; //Place to retrieve the salt from register
BYTE CT_salt_code[61]= {0}; //Bytes of the salt code (for disassembly)
int CT_cert_func_count=0; //Counter of passes on the NextDword function
LPPROCESS_INFORMATION CT_fdProcessInfo = NULL; //process info

//Brute
typedef struct _hash_list
{
    int count;
    unsigned long hash[32];
} hash_list;

//Callback typedefs
typedef void (*PRINT_FOUND)(unsigned long hash, unsigned long key);
typedef void (*PRINT_PROGRESS)(double checked, double all, time_t* start);
typedef void (*PRINT_ERROR)(const char* error_msg);

//DLL typedefs
typedef void (*BRUTESTART)(int alg, hash_list *list, unsigned long from, unsigned long to, unsigned long param);
typedef void (*SETCALLBACKS)(PRINT_FOUND cb1, PRINT_PROGRESS cb2, PRINT_ERROR cb3);
typedef void (*BRUTESTOP)();
typedef void (*BRUTESETTINGS)(HWND parent);
typedef int(*UPDATEKEYS)(int level, const char* y_txt);
typedef int(*SOLVEDLP)(const char* pvt_txt);

//Brute global vars
HINSTANCE hBrute;
BRUTESTART BruteStart;
SETCALLBACKS BruteSetCallbacks;
BRUTESTOP BruteStop;
BRUTESETTINGS BruteSettings;

//Brute callbacks
void cbBruteProgess(double checked, double all, time_t* start);
void cbBrutePrintFound(unsigned long hash, unsigned long key);
void cbBruteError(const char* error_msg);

//Dlp brute
HINSTANCE hBruteDlp;
UPDATEKEYS UpdateKeys;
SOLVEDLP SolveDlp;

int CT_total_sym_found=0;
char* CT_section_name=0;
bool CT_brute_is_paused=false;
bool CT_brute_shutdown=false;

//Arma 9.60 seed retrieve for decryption
//int CT_NextDword_count=0;
int CT_return_counter=0;
int CT_other_seed_counter=0;

void CT_FatalError(const char* msg)
{
    MessageBoxA(CT_shared, msg, "Fatal Error!", MB_ICONERROR);
    StopDebug();
}

int CT_NextSeed(int data)
{
    int a = data % 10000;
    int res;
    res = 10000 * ((3141 * a  + (data / 10000) * 5821) % 10000u);
    return (a * 5821 + res + 1) % 100000000u;
}

unsigned int CT_FindCertificateFunctionOld(BYTE* d, unsigned int size)
{
    for(unsigned int i=0; i<size; i++) //8B4424048B5424088B0883C004890AC3
        if(d[i]==0x8B and d[i+1]==0x44 and d[i+2]==0x24 and d[i+3]==0x04 and d[i+4]==0x8B and d[i+5]==0x54 and d[i+6]==0x24 and d[i+7]==0x08 and d[i+8]==0x8B and d[i+9]==0x08 and d[i+10]==0x83 and d[i+11]==0xC0 and d[i+12]==0x04 and d[i+13]==0x89 and d[i+14]==0x0A and d[i+15]==0xC3)
            return i+15;
    return 0;
}

unsigned int CT_FindCertificateFunctionNew(BYTE* d, unsigned int size)
{
    for(unsigned int i=0; i<size; i++) //558BEC8B450C8B4D088B1189108B450883C0045DC3
        if(d[i]==0x55 and d[i+1]==0x8B and d[i+2]==0xEC and d[i+3]==0x8B and d[i+4]==0x45 and d[i+5]==0x0C and d[i+6]==0x8B and d[i+7]==0x4D and d[i+8]==0x08 and d[i+9]==0x8B and d[i+10]==0x11 and d[i+11]==0x89 and d[i+12]==0x10 and d[i+13]==0x8B and d[i+14]==0x45 and d[i+15]==0x08 and d[i+16]==0x83 and d[i+17]==0xC0 and d[i+18]==0x04 and d[i+19]==0x5D and d[i+20]==0xC3)
            return i+20;
    return 0;
}

unsigned int CT_FindCertificateMarkers(BYTE* d, unsigned int size)
{
    for(unsigned int i=0; i<size; i++) //002D2A00
        if(d[i]==0x00 and d[i+1]==0x2D and d[i+2]==0x2A and d[i+3]==0x00)
            return i;
    return 0;
}

unsigned int CT_FindCertificateMarkers2(BYTE* d, unsigned int size)
{
    for(unsigned int i=0; i<size; i++) //002B2A00
        if(d[i]==0x00 and d[i+1]==0x2B and d[i+2]==0x2A and d[i+3]==0x00)
            return i;
    return 0;
}

unsigned int CT_FindCertificateEndMarkers(BYTE* mem_addr, unsigned int size)
{
    for(unsigned int i=0; i<size; i++)
    {
        if(mem_addr[i]==0x00 and mem_addr[i+1]==0x00 and mem_addr[i+2]==0x00)
            return i;
    }
    return 0;
}

unsigned int CT_FindMagicPattern(BYTE* d, unsigned int size, unsigned int* ebp_sub)
{
    for(unsigned int i=0; i<size; i++) //8813000089
        if(d[i]==0x88 and d[i+1]==0x13 and d[i+2]==0x00 and d[i+3]==0x00 and d[i+4]==0x89)
        {
            unsigned char ebp_sub1=d[i+6];
            if(ebp_sub1>0x7F)
                *ebp_sub=0x100-ebp_sub1;
            else
                *ebp_sub=0-ebp_sub1;
            return i+7;
        }
    return 0;
}

unsigned int CT_FindEndInitSymVerifyPattern(BYTE* d, unsigned int size)
{
    for(unsigned int i=0; i<size; i++) //00010000
        if(d[i]==0x00 and d[i+1]==0x01 and d[i+2]==0x00 and d[i+3]==0x00)
            return i;
    return 0;
}

unsigned int CT_FindPubMd5MovePattern(BYTE* d, unsigned int size)
{
    for(unsigned int i=0; i<size; i++) //8B????????00
        if(d[i]==0x8B and d[i+5]==0x00)
            return i;
    return 0;
}

unsigned int CT_FindDecryptKey1Pattern(BYTE* d, unsigned int size) //C++ function to search bytes
{
    for(unsigned int i=0; i<size; i++) //E9????????6800040000
        if(d[i]==0xE9 and d[i+5]==0x68 and d[i+6]==0x00 and d[i+7]==0x04 and d[i+8]==0x00 and d[i+9]==0x00)
            return i;
    return 0;
}

unsigned int CT_FindMagicJumpPattern(BYTE* d, unsigned int size, unsigned short* data)
{
    for(unsigned int i=0; i<size; i++) //3B??74??8B
        if(d[i]==0x3B and d[i+2]==0x74 and d[i+4]==0x8B)
        {
            memcpy(data, d+i, 2);
            return i;
        }
    return 0;
}

unsigned int CT_FindECDSAVerify(BYTE* d, unsigned int size)
{
    for(unsigned int i=0; i<size; i++) //51E8????????83C40CF7D81BC083C0015DC3
        if(d[i]==0x51 and d[i+1]==0xE8 and d[i+6]==0x83 and d[i+7]==0xC4 and d[i+8]==0x0C and d[i+9]==0xF7 and d[i+10]==0xD8 and d[i+11]==0x1B and d[i+12]==0xC0 and d[i+13]==0x83 and d[i+14]==0xC0 and d[i+15]==0x01 and d[i+16]==0x5D and d[i+17]==0xC3)
            return i;
    return 0;
}

unsigned int CT_FindPushFFPattern(BYTE* d, unsigned int size)
{
    for(unsigned int i=0; i<size; i++) //6AFF
        if(d[i]==0x6A and d[i+1]==0xFF)
            return i;
    return 0;
}

unsigned int CT_FindTeaDecryptPattern(BYTE* d, unsigned int size)
{
    for(unsigned int i=0; i<size; i++) //E8????????83
        if(d[i]==0xE8 and d[i+5]==0x83)
            return i;
    return 0;
}

unsigned int CT_FindNextDwordPattern(BYTE* d, unsigned int size)
{
    for(unsigned int i=0; i<size; i++) //558BEC??????????????????????????????045DC3
        if(d[i]==0x55 and d[i+1]==0x8B and d[i+2]==0xEC and d[i+18]==0x04 and d[i+19]==0x5D and d[i+20]==0xC3)
            return i+20;
    return 0;
}

unsigned int CT_FindReturnPattern(BYTE* d, unsigned int size)
{
    for(unsigned int i=0; i<size; i++) //5DC?
        if(d[i]==0x5D and(d[i+1]>>4)==0x0C)
            return i+1;
    return 0;
}

unsigned int CT_FindReturnPattern2(BYTE* d, unsigned int size)
{
    for(unsigned int i=0; i<size; i++) //C3
        if(d[i]==0xC3)
            return i;
    return 0;
}

unsigned int CT_FindPush100Pattern(BYTE* d, unsigned int size)
{
    for(unsigned int i=0; i<size; i++) //6800010000
        if(d[i]==0x68 and d[i+1]==0x00 and d[i+2]==0x01 and d[i+3]==0x00 and d[i+4]==0x00)
            return i;
    return 0;
}

unsigned int CT_FindCall1Pattern(BYTE* d, unsigned int size)
{
    for(unsigned int i=0; i<size; i++) //E8????????88
        if(d[i]==0xE8 and d[i+5]==0x88)
            return i;
    return 0;
}

unsigned int CT_FindCall2Pattern(BYTE* d, unsigned int size)
{
    for(unsigned int i=0; i<size; i++) //E8
        if(d[i]==0xE8)
            return i;
    return 0;
}

unsigned int CT_FindAndPattern1(BYTE* d, unsigned int size)
{
    for(unsigned int i=0; i<size; i++) //83E???03
        if(d[i]==0x83 and(d[i+1]>>4)==0x0E and d[i+3]==0x03)
            return i+3;
    return 0;
}

unsigned int CT_FindAndPattern2(BYTE* d, unsigned int size)
{
    for(unsigned int i=0; i<size; i++) //81E?????????03
        if(d[i]==0x81 and(d[i+1]>>4)==0x0E and d[i+6]==0x03)
            return i+5;
    return 0;
}

unsigned int CT_FindStdcallPattern(BYTE* d, unsigned int size)
{
    for(unsigned int i=0; i<size; i++) //E8????????83
        if(d[i]==0xE8 and d[i+5]==0x83)
            return i;
    return 0;
}

unsigned int CT_FindVerifySymPattern(BYTE* d, unsigned int size)
{
    for(unsigned int i=0; i<size; i++) //F7
        if(d[i]==0xF7)
            return i;
    return 0;
}

unsigned int CT_FindEndLoopPattern(BYTE* d, unsigned int size)
{
    for(unsigned int i=0; i<size; i++) //E9????????8B????89
        if(d[i]==0xE9 and d[i+5]==0x8B and d[i+8]==0x89)
            return i+5;
    return 0;
}

#endif
