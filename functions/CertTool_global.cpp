#include "CertTool_global.h"

HWND CT_shared; //shared window handle

char CT_szFileName[256] = ""; //debugged program
char CT_szLogFile[256] = ""; //_cert.log file
char CT_szAktLogFile[256] = ""; //_cert.tpodt file
char CT_szCryptCertFile[256] = ""; //_cert.bin file
char CT_szRawCertFile[256] = ""; //_raw.cert file
char CT_szStolenKeysRaw[256] = ""; //_stolen.keys file
char CT_szStolenKeysLog[256] = ""; //_stolenkeys.log

bool CT_logtofile = true; //Create log files?
unsigned int CT_time1 = 0; //For duration calculation.

CERT_DATA* CT_cert_data;

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
    for(unsigned int i = 0; i < size; i++) //8B4424048B5424088B0883C004890AC3
        if(d[i] == 0x8B and d[i + 1] == 0x44 and d[i + 2] == 0x24 and d[i + 3] == 0x04 and d[i + 4] == 0x8B and d[i + 5] == 0x54 and d[i + 6] == 0x24 and d[i + 7] == 0x08 and d[i + 8] == 0x8B and d[i + 9] == 0x08 and d[i + 10] == 0x83 and d[i + 11] == 0xC0 and d[i + 12] == 0x04 and d[i + 13] == 0x89 and d[i + 14] == 0x0A and d[i + 15] == 0xC3)
            return i + 15;
    return 0;
}

unsigned int CT_FindCertificateFunctionNew(BYTE* d, unsigned int size)
{
    for(unsigned int i = 0; i < size; i++) //558BEC8B450C8B4D088B1189108B450883C0045DC3
        if(d[i] == 0x55 and d[i + 1] == 0x8B and d[i + 2] == 0xEC and d[i + 3] == 0x8B and d[i + 4] == 0x45 and d[i + 5] == 0x0C and d[i + 6] == 0x8B and d[i + 7] == 0x4D and d[i + 8] == 0x08 and d[i + 9] == 0x8B and d[i + 10] == 0x11 and d[i + 11] == 0x89 and d[i + 12] == 0x10 and d[i + 13] == 0x8B and d[i + 14] == 0x45 and d[i + 15] == 0x08 and d[i + 16] == 0x83 and d[i + 17] == 0xC0 and d[i + 18] == 0x04 and d[i + 19] == 0x5D and d[i + 20] == 0xC3)
            return i + 20;
    return 0;
}

unsigned int CT_FindCertificateMarkers(BYTE* d, unsigned int size)
{
    for(unsigned int i = 0; i < size; i++) //002D2A00
        if(d[i] == 0x00 and d[i + 1] == 0x2D and d[i + 2] == 0x2A and d[i + 3] == 0x00)
            return i;
    return 0;
}

unsigned int CT_FindCertificateMarkers2(BYTE* d, unsigned int size)
{
    for(unsigned int i = 0; i < size; i++) //002B2A00
        if(d[i] == 0x00 and d[i + 1] == 0x2B and d[i + 2] == 0x2A and d[i + 3] == 0x00)
            return i;
    return 0;
}

unsigned int CT_FindCertificateEndMarkers(BYTE* mem_addr, unsigned int size)
{
    for(unsigned int i = 0; i < size; i++)
    {
        if(mem_addr[i] == 0x00 and mem_addr[i + 1] == 0x00 and mem_addr[i + 2] == 0x00)
            return i;
    }
    return 0;
}

unsigned int CT_FindMagicPattern(BYTE* d, unsigned int size, unsigned int* ebp_sub)
{
    for(unsigned int i = 0; i < size; i++) //8813000089
        if(d[i] == 0x88 and d[i + 1] == 0x13 and d[i + 2] == 0x00 and d[i + 3] == 0x00 and d[i + 4] == 0x89)
        {
            unsigned char ebp_sub1 = d[i + 6];
            if(ebp_sub1 > 0x7F)
                *ebp_sub = 0x100 - ebp_sub1;
            else
                *ebp_sub = 0 - ebp_sub1;
            return i + 7;
        }
    return 0;
}

unsigned int CT_FindEndInitSymVerifyPattern(BYTE* d, unsigned int size)
{
    for(unsigned int i = 0; i < size; i++) //00010000
        if(d[i] == 0x00 and d[i + 1] == 0x01 and d[i + 2] == 0x00 and d[i + 3] == 0x00)
            return i;
    return 0;
}

unsigned int CT_FindPubMd5MovePattern(BYTE* d, unsigned int size)
{
    for(unsigned int i = 0; i < size; i++) //8B????????00
        if(d[i] == 0x8B and d[i + 5] == 0x00)
            return i;
    return 0;
}

unsigned int CT_FindDecryptKey1Pattern(BYTE* d, unsigned int size) //C++ function to search bytes
{
    for(unsigned int i = 0; i < size; i++) //E9????????6800040000
        if(d[i] == 0xE9 and d[i + 5] == 0x68 and d[i + 6] == 0x00 and d[i + 7] == 0x04 and d[i + 8] == 0x00 and d[i + 9] == 0x00)
            return i;
    return 0;
}

unsigned int CT_FindMagicJumpPattern(BYTE* d, unsigned int size, unsigned short* data)
{
    for(unsigned int i = 0; i < size; i++) //3B??74??8B
        if(d[i] == 0x3B and d[i + 2] == 0x74 and d[i + 4] == 0x8B)
        {
            memcpy(data, d + i, 2);
            return i;
        }
    return 0;
}

unsigned int CT_FindECDSAVerify(BYTE* d, unsigned int size)
{
    for(unsigned int i = 0; i < size; i++) //51E8????????83C40CF7D81BC083C0015DC3
        if(d[i] == 0x51 and d[i + 1] == 0xE8 and d[i + 6] == 0x83 and d[i + 7] == 0xC4 and d[i + 8] == 0x0C and d[i + 9] == 0xF7 and d[i + 10] == 0xD8 and d[i + 11] == 0x1B and d[i + 12] == 0xC0 and d[i + 13] == 0x83 and d[i + 14] == 0xC0 and d[i + 15] == 0x01 and d[i + 16] == 0x5D and d[i + 17] == 0xC3)
            return i;
    return 0;
}

unsigned int CT_FindPushFFPattern(BYTE* d, unsigned int size)
{
    for(unsigned int i = 0; i < size; i++) //6AFF
        if(d[i] == 0x6A and d[i + 1] == 0xFF)
            return i;
    return 0;
}

unsigned int CT_FindTeaDecryptPattern(BYTE* d, unsigned int size)
{
    for(unsigned int i = 0; i < size; i++) //E8????????83
        if(d[i] == 0xE8 and d[i + 5] == 0x83)
            return i;
    return 0;
}

unsigned int CT_FindNextDwordPattern(BYTE* d, unsigned int size) //TODO: never used
{
    for(unsigned int i = 0; i < size; i++) //558BEC??????????????????????????????045DC3
        if(d[i] == 0x55 and d[i + 1] == 0x8B and d[i + 2] == 0xEC and d[i + 18] == 0x04 and d[i + 19] == 0x5D and d[i + 20] == 0xC3)
            return i + 20;
    return 0;
}

unsigned int CT_FindReturnPattern(BYTE* d, unsigned int size)
{
    for(unsigned int i = 0; i < size; i++) //5DC[2/3]
        if(d[i] == 0x5D and (d[i + 1] == 0xC2 or d[i + 1] == 0xC3))
            return i + 1;
    return 0;
}

unsigned int CT_FindReturnPattern2(BYTE* d, unsigned int size)
{
    for(unsigned int i = 0; i < size; i++) //C3
        if(d[i] == 0xC3)
            return i;
    return 0;
}

unsigned int CT_FindPush100Pattern(BYTE* d, unsigned int size)
{
    for(unsigned int i = 0; i < size; i++) //6800010000
        if(d[i] == 0x68 and d[i + 1] == 0x00 and d[i + 2] == 0x01 and d[i + 3] == 0x00 and d[i + 4] == 0x00)
            return i;
    return 0;
}

unsigned int CT_FindCall1Pattern(BYTE* d, unsigned int size)
{
    for(unsigned int i = 0; i < size; i++) //E8????????88
        if(d[i] == 0xE8 and d[i + 5] == 0x88)
            return i;
    return 0;
}

unsigned int CT_FindCall2Pattern(BYTE* d, unsigned int size)
{
    for(unsigned int i = 0; i < size; i++) //E8
        if(d[i] == 0xE8)
            return i;
    return 0;
}

unsigned int CT_FindAndPattern1(BYTE* d, unsigned int size)
{
    for(unsigned int i = 0; i < size; i++) //83E???03
        if(d[i] == 0x83 and (d[i + 1] >> 4) == 0x0E and d[i + 3] == 0x03)
            return i + 3;
    return 0;
}

unsigned int CT_FindAndPattern2(BYTE* d, unsigned int size)
{
    for(unsigned int i = 0; i < size; i++) //81E?????????03
        if(d[i] == 0x81 and (d[i + 1] >> 4) == 0x0E and d[i + 6] == 0x03)
            return i + 5;
    return 0;
}

unsigned int CT_FindStdcallPattern(BYTE* d, unsigned int size)
{
    for(unsigned int i = 0; i < size; i++) //E8????????83
        if(d[i] == 0xE8 and d[i + 5] == 0x83)
            return i;
    return 0;
}

unsigned int CT_FindVerifySymPattern(BYTE* d, unsigned int size)
{
    for(unsigned int i = 0; i < size; i++) //F7
        if(d[i] == 0xF7)
            return i;
    return 0;
}

unsigned int CT_FindEndLoopPattern(BYTE* d, unsigned int size)
{
    for(unsigned int i = 0; i < size; i++) //E9????????8B????89
        if(d[i] == 0xE9 and d[i + 5] == 0x8B and d[i + 8] == 0x89)
            return i + 5;
    return 0;
}
