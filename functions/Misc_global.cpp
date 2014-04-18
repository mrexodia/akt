#include "Misc_global.h"

//GetCurrentSym
HWND MSC_shared;
char MSC_szFileName[256]="";
char MSC_program_dir[256]="";
LPPROCESS_INFORMATION MSC_fdProcessInfo=0;
bool MSC_fdFileIsDll=false;
unsigned int MSC_current_sym=0;
bool MSC_getversion_set=false;
bool MSC_isdebugging=false;
unsigned int MSC_magic_addr=0;

//ClockBack
char MSC_projectID[65536];

//ProjectID
int MSC_cert_func_count=0;

void MSC_FatalError(const char* msg)
{
    MessageBoxA(MSC_shared, msg, "Fatal Error!", MB_ICONERROR);
    StopDebug();
}

//Checksum
unsigned int MSC_checksum=0;

unsigned int MSC_salt_func_addr=0; //Address of the salt function
unsigned int MSC_salt_register=0; //Register to retrieve salt from
unsigned int MSC_salt_breakpoint=0; //Place to retrieve the salt from register
unsigned int MSC_project_salt=0; //actual salt value
BYTE MSC_salt_code[61]= {0}; //Bytes of the salt code (for disassembly)

///arma960 (checksum)
int MSC_CHK_return_counter=0;
int MSC_CHK_other_seed_counter=0;
unsigned int MSC_CHK_seeds[5]= {0};
unsigned char* MSC_CHK_raw_data=0;
///arma960 (projectid)
int MSC_return_counter=0;
int MSC_other_seed_counter=0;
unsigned int MSC_seeds[5]= {0};
unsigned char* MSC_raw_data=0;

//VerifySym
char MSC_VR_certpath[256]="";
char MSC_VR_keyspath[256]="";
char MSC_VR_magic1[10]="", MSC_VR_magic2[10]="", MSC_VR_md5_text[10]="";
char* MSC_VR_keys;
char* MSC_VR_keys_format;
unsigned int* MSC_VR_key_array;
unsigned int* MSC_VR_buffer_400;
bool MSC_VR_check_all_md5=false;
unsigned int MSC_VR_magic_value_addr=0; //address of the magic values place
unsigned int MSC_VR_magic_ebp_sub=0; //ebp difference to retrieve the magic from

//Section Deleter
HWND MSC_SD_list;
bool MSC_SD_updated_sections=false;

//arma960
//Arma v9.60 and higher (probably)
UINT MSC_DetermineRegisterFromByte(unsigned char byte)
{
    switch(byte)
    {
    case 0x45:
        return UE_EAX;
    case 0x4D:
        return UE_ECX;
    case 0x55:
        return UE_EDX;
    case 0x5D:
        return UE_EBX;
    case 0x65:
        return UE_ESP;
    case 0x6D:
        return UE_EBP;
    case 0x75:
        return UE_ESI;
    case 0x7D:
        return UE_EDI;
    }
    return 0;
}

void MSC_SortArray(unsigned int* a, int size)
{
    unsigned int* cpy=(unsigned int*)malloc2(size*4);
    memcpy(cpy, a, size*4);
    unsigned int* biggest=&cpy[0];
    for(int i=0; i<size; i++)
    {
        for(int j=0; j<size; j++)
        {
            if(cpy[j]>*biggest)
                biggest=&cpy[j];
        }
        a[size-i-1]=*biggest;
        *biggest=0;
    }
}

SECTION_ANALYSIS MSC_SD_section_info= {0};

unsigned int MSC_FindReturnPattern(BYTE* d, unsigned int size)
{
    for(unsigned int i=0; i<size; i++) //5DC?
        if(d[i]==0x5D and(d[i+1]>>4)==0x0C)
            return i+1;
    return 0;
}

unsigned int MSC_FindReturnPattern2(BYTE* d, unsigned int size)
{
    for(unsigned int i=0; i<size; i++) //C3
        if(d[i]==0xC3)
            return i;
    return 0;
}

unsigned int MSC_FindPush100Pattern(BYTE* d, unsigned int size)
{
    for(unsigned int i=0; i<size; i++) //6800010000
        if(d[i]==0x68 and d[i+1]==0x00 and d[i+2]==0x01 and d[i+3]==0x00 and d[i+4]==0x00)
            return i;
    return 0;
}

unsigned int MSC_FindCall1Pattern(BYTE* d, unsigned int size)
{
    for(unsigned int i=0; i<size; i++) //E8????????88
        if(d[i]==0xE8 and d[i+5]==0x88)
            return i;
    return 0;
}

unsigned int MSC_FindCall2Pattern(BYTE* d, unsigned int size)
{
    for(unsigned int i=0; i<size; i++) //E8
        if(d[i]==0xE8)
            return i;
    return 0;
}

unsigned int MSC_FindAndPattern1(BYTE* d, unsigned int size)
{
    for(unsigned int i=0; i<size; i++) //83E???03
        if(d[i]==0x83 and(d[i+1]>>4)==0x0E and d[i+3]==0x03)
            return i+3;
    return 0;
}

unsigned int MSC_FindAndPattern2(BYTE* d, unsigned int size)
{
    for(unsigned int i=0; i<size; i++) //81E?????????03
        if(d[i]==0x81 and(d[i+1]>>4)==0x0E and d[i+6]==0x03)
            return i+5;
    return 0;
}

unsigned int MSC_FindStdcallPattern(BYTE* d, unsigned int size)
{
    for(unsigned int i=0; i<size; i++) //E8????????83
        if(d[i]==0xE8 and d[i+5]==0x83)
            return i;
    return 0;
}
