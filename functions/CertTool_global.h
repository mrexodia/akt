#ifndef _CT_GLOBAL_H
#define _CT_GLOBAL_H

#include "_global.h"

extern HWND CT_shared;

extern char CT_szFileName[256];
extern char CT_szLogFile[256];
extern char CT_szAktLogFile[256];
extern char CT_szCryptCertFile[256];
extern char CT_szRawCertFile[256];
extern char CT_szStolenKeysRaw[256];
extern char CT_szStolenKeysLog[256];

extern bool CT_logtofile;
extern unsigned int CT_time1;

struct CERT_DATA
{
    unsigned char* raw_data;
    unsigned char* encrypted_data;
    char* projectid;
    char* customer_service;
    char* website;
    char* unknown_string;
    unsigned char* stolen_keys;
    unsigned int stolen_keys_size;
    unsigned int stolen_keys_diff;
    unsigned char* intercepted_libs;
    unsigned int intercepted_libs_size;
    unsigned int projectid_diff;
    unsigned int initial_diff;
    unsigned int raw_size;
    unsigned int encrypted_size;
    unsigned int first_dw;
    unsigned int magic1;
    unsigned int magic2;
    unsigned int salt;
    unsigned int decrypt_seed[4]; //initial, projectid, certificate, stolen keys
    unsigned int decrypt_addvals[4];
    bool checksumv8;
    bool zero_md5_symverify;
    unsigned int timestamp;
};

extern CERT_DATA* CT_cert_data;

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
