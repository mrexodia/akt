#include "_global.h"

HINSTANCE hInst;
bool log_version=true; //Log version...
bool help_open=false; //Prevent double help screens.
char program_dir[256]="";
char FormatTextHex_format[1024]=""; //String for hex format

UINT DetermineRegisterFromText(char* reg_text)
{
    if(!strnicmp(reg_text, "edi", 3))
        return UE_EDI;
    if(!strnicmp(reg_text, "esi", 3))
        return UE_ESI;
    if(!strnicmp(reg_text, "ebx", 3))
        return UE_EBX;
    if(!strnicmp(reg_text, "edx", 3))
        return UE_EDX;
    if(!strnicmp(reg_text, "ecx", 3))
        return UE_ECX;
    if(!strnicmp(reg_text, "eax", 3))
        return UE_EAX;
    if(!strnicmp(reg_text, "ebp", 3))
        return UE_EBP;
    if(!strnicmp(reg_text, "esp", 3))
        return UE_ESP;
    return 0;
}

unsigned int FindDwordInMemory(BYTE* dump_addr, unsigned dword_to_find, unsigned int filesize) //Find dword in memory
{
    unsigned int lala=dword_to_find;
    BYTE dword[4]= {0};
    memcpy(dword, &lala, 4);
    for(unsigned int i=0; i<filesize; i++)
    {
        if(dump_addr[i]==dword[0])
        {
            if(dump_addr[i+1]==dword[1])
            {
                if(dump_addr[i+2]==dword[2])
                {
                    if(dump_addr[i+3]==dword[3])
                    {
                        return i;
                    }
                }
            }
        }
    }
    return 0;
}

void LeftClick()
{
    INPUT Input= {0};
    Input.type=INPUT_MOUSE;
    Input.mi.dwFlags=MOUSEEVENTF_LEFTDOWN;
    SendInput(1, &Input, sizeof(INPUT));
    ZeroMemory(&Input, sizeof(INPUT));
    Input.type=INPUT_MOUSE;
    Input.mi.dwFlags=MOUSEEVENTF_LEFTUP;
    SendInput(1, &Input, sizeof(INPUT));
}

void PasteFromClipboard(char* d, int maxlen)
{
    OpenClipboard(0);
    const char* data=(const char*)GetClipboardData(CF_OEMTEXT);
    CloseClipboard();
    if(!data)
    {
        strcpy(d, "");
        return;
    }
    if(strlen(data)>(unsigned int)maxlen)
    {
        memset(d, 0, maxlen);
        memcpy(d, data, maxlen-1);
    }
    else
        strcpy(d, data);
}

void CopyToClipboard(const char* text)
{
    HGLOBAL hText;
    char *pText;
    int len=strlen(text);

    hText = GlobalAlloc(GMEM_DDESHARE | GMEM_MOVEABLE, len+1);
    pText = (char*)GlobalLock(hText);
    strcpy(pText, text);

    OpenClipboard(0);
    EmptyClipboard();
    if(len)
        if(!SetClipboardData(CF_OEMTEXT, hText))
            MessageBeep(MB_ICONERROR);
    CloseClipboard();
}

char* FormatTextHex(const char* text)
{
    int len=strlen(text);
    FormatTextHex_format[0]=0;
    for(int i=0; i<len; i++)
        if((text[i]>64 and text[i]<71) or(text[i]>47 and text[i]<58))
            sprintf(FormatTextHex_format, "%s%c", FormatTextHex_format, text[i]);
    return FormatTextHex_format;
}

void SetLevelList(HWND hwndDlg)
{
    SendDlgItemMessageA(hwndDlg, IDC_COMBO_LEVEL, CB_ADDSTRING, 0, (LPARAM)"Unsigned Level 0");
    SendDlgItemMessageA(hwndDlg, IDC_COMBO_LEVEL, CB_ADDSTRING, 0, (LPARAM)"-----------------");
    SendDlgItemMessageA(hwndDlg, IDC_COMBO_LEVEL, CB_ADDSTRING, 0, (LPARAM)"Signed V2 Level 1");
    SendDlgItemMessageA(hwndDlg, IDC_COMBO_LEVEL, CB_ADDSTRING, 0, (LPARAM)"Signed V2 Level 2");
    SendDlgItemMessageA(hwndDlg, IDC_COMBO_LEVEL, CB_ADDSTRING, 0, (LPARAM)"Signed V2 Level 3");
    SendDlgItemMessageA(hwndDlg, IDC_COMBO_LEVEL, CB_ADDSTRING, 0, (LPARAM)"Signed V2 Level 4");
    SendDlgItemMessageA(hwndDlg, IDC_COMBO_LEVEL, CB_ADDSTRING, 0, (LPARAM)"-----------------");
    SendDlgItemMessageA(hwndDlg, IDC_COMBO_LEVEL, CB_ADDSTRING, 0, (LPARAM)"Signed V3 Level 1");
    SendDlgItemMessageA(hwndDlg, IDC_COMBO_LEVEL, CB_ADDSTRING, 0, (LPARAM)"Signed V3 Level 2");
    SendDlgItemMessageA(hwndDlg, IDC_COMBO_LEVEL, CB_ADDSTRING, 0, (LPARAM)"Signed V3 Level 3");
    SendDlgItemMessageA(hwndDlg, IDC_COMBO_LEVEL, CB_ADDSTRING, 0, (LPARAM)"Signed V3 Level 4");
    SendDlgItemMessageA(hwndDlg, IDC_COMBO_LEVEL, CB_ADDSTRING, 0, (LPARAM)"Signed V3 Level 5");
    SendDlgItemMessageA(hwndDlg, IDC_COMBO_LEVEL, CB_ADDSTRING, 0, (LPARAM)"Signed V3 Level 6");
    SendDlgItemMessageA(hwndDlg, IDC_COMBO_LEVEL, CB_ADDSTRING, 0, (LPARAM)"Signed V3 Level 7");
    SendDlgItemMessageA(hwndDlg, IDC_COMBO_LEVEL, CB_ADDSTRING, 0, (LPARAM)"Signed V3 Level 8");
    SendDlgItemMessageA(hwndDlg, IDC_COMBO_LEVEL, CB_ADDSTRING, 0, (LPARAM)"Signed V3 Level 9");
    SendDlgItemMessageA(hwndDlg, IDC_COMBO_LEVEL, CB_ADDSTRING, 0, (LPARAM)"-----------------");
    SendDlgItemMessageA(hwndDlg, IDC_COMBO_LEVEL, CB_ADDSTRING, 0, (LPARAM)"Short V3 Level 1");
    SendDlgItemMessageA(hwndDlg, IDC_COMBO_LEVEL, CB_ADDSTRING, 0, (LPARAM)"Short V3 Level 2");
    SendDlgItemMessageA(hwndDlg, IDC_COMBO_LEVEL, CB_ADDSTRING, 0, (LPARAM)"Short V3 Level 3");
    SendDlgItemMessageA(hwndDlg, IDC_COMBO_LEVEL, CB_ADDSTRING, 0, (LPARAM)"Short V3 Level 4");
    SendDlgItemMessageA(hwndDlg, IDC_COMBO_LEVEL, CB_ADDSTRING, 0, (LPARAM)"Short V3 Level 5");
    SendDlgItemMessageA(hwndDlg, IDC_COMBO_LEVEL, CB_ADDSTRING, 0, (LPARAM)"Short V3 Level 6");
    SendDlgItemMessageA(hwndDlg, IDC_COMBO_LEVEL, CB_ADDSTRING, 0, (LPARAM)"Short V3 Level 7");
    SendDlgItemMessageA(hwndDlg, IDC_COMBO_LEVEL, CB_ADDSTRING, 0, (LPARAM)"Short V3 Level 8");
    SendDlgItemMessageA(hwndDlg, IDC_COMBO_LEVEL, CB_ADDSTRING, 0, (LPARAM)"Short V3 Level 9");
    SendDlgItemMessageA(hwndDlg, IDC_COMBO_LEVEL, CB_ADDSTRING, 0, (LPARAM)"Short V3 Level 10");
    SendDlgItemMessageA(hwndDlg, IDC_COMBO_LEVEL, CB_SETCURSEL, 0, 0);
}

void NoFocus()
{
    SetFocus(0);
}

bool IsHexChar(char c)
{
    const char* chars="0123456789ABCDEF";
    while(*chars)
        if(*chars++==c)
            return true;
    return false;
}

void FormatHex(char* string)
{
    int len=strlen(string);
    _strupr(string);
    char* new_string=(char*)malloc(len+1);
    memset(new_string, 0, len+1);
    for(int i=0; i<len; i++)
        if(IsHexChar(string[i]))
            sprintf(new_string, "%s%c", new_string, string[i]);
    strcpy(string, new_string);
    free(new_string);
}

int StringToByteArray(const char* s, unsigned char* d, int d_len)
{
    char temp_string[3]="";
    unsigned char temp_byte[4]= {0};
    int len=0;

    memset(d, 0, d_len);

    len=strlen(s);
    if(len%2)
        len--;

    if((len/2)>d_len)
        return -1;

    for(int i=0,j=0; i<(len/2); i++, j+=2)
    {
        temp_string[0]=s[j];
        temp_string[1]=s[j+1];
        sscanf(temp_string, "%X", (unsigned int*)&temp_byte);
        d[i]=temp_byte[0];
    }
    return len/2;
}

int ByteArrayToString(unsigned char* s, char* d, int s_len, int d_len)
{
    memset(d, 0, d_len);
    if(s_len>d_len)
        return -1;
    for(int i=0; i<s_len; i++)
        sprintf(d, "%s%.2X", d, s[i]);
    return strlen(d);
}

char* EncodeShortV3(unsigned char* keybytes, int keylength, bool level10)
{
    char* cc;
    char* shortv3digits=(char*)"0123456789ABCDEFGHJKMNPQRTUVWXYZ";
    static char retval[512]="";
    int level=0;
    int dcount;
    int nn;
    if(level10)
        level=29;
    strcpy(retval, "");
    BigInt n=BigInt_Create();
    BigInt t1=BigInt_Create();
    BigInt t2=BigInt_Create();
    if(level==29)
        BigInt_Set(n, 1);
    for(int x=0; x<keylength; ++x)
    {
        BigInt_Shift(n, 8, t1);
        BigInt_SetU(t2, keybytes[x]);
        BigInt_Add(t1, t2, n);
    }
    cc=retval;
    dcount=6;
    while(BigInt_Compare(n, BigInt_Zero())!=0)
    {
        BigInt_SetU(t2, 32);
        BigInt_Modulus(n, t2, t1);
        nn=BigInt_Get(t1);
        BigInt_Shift(n, -5, t2);
        BigInt_Copy(n, t2);
        if(level==29)
        {
            *cc++=shortv3digits[nn];
            if(--dcount==0)
            {
                dcount=6;
                *cc++='-';
            }
        }
        else
        {
            if(BigInt_Compare(n, BigInt_Zero())==0)
            {
                if(nn<16)
                {
                    *cc++=shortv3digits[nn+16];
                    --dcount;
                }
                else
                {
                    *cc++=shortv3digits[nn];
                    if(--dcount==0)
                    {
                        dcount=6;
                        *cc++='-';
                    }
                    *cc++=shortv3digits[16];
                    --dcount;
                }
            }
            else
            {
                *cc++=shortv3digits[nn];
                if(--dcount==0)
                {
                    dcount=6;
                    *cc++='-';
                }
            }
        }
    }
    if(level==29)
    {
        *cc++='1';
        --dcount;
    }
    while(dcount-->0)
        *cc++='0';
    *cc=0;
    mystrrev(retval);
    BigInt_Destroy(t2);
    BigInt_Destroy(t1);
    BigInt_Destroy(n);
    return retval;
}

int DecodeShortV3(const char* serial, bool level10, unsigned char* dest, int dest_len)
{
    char keybytes_[512];

    char* kb=keybytes_;
    char* keybytes=keybytes_;
    char* k1;
    char* k2;
    bool keystring=false;
    int keylength;
    const char* udigits="0123456789ABCDEFGHJKMNPQRTUVWXYZ";
    const char* ldigits="0123456789abcdefghjkmnpqrtuvwxyz";
    const char* c=serial;
    const char* p;
    unsigned char value=0;
    unsigned char firstdigit=1;
    BigInt n, n2, n3;
    n=BigInt_Create();
    n2=BigInt_Create();
    n3=BigInt_Create();
    int level=0;
    if(level10)
        level=10;
    if(serial==0 || serial[0]==0)
    {
        return 0;
    }
    while(c[0])
    {
        p=strchr(udigits, c[0]); //first the current serial character in udigits
        if(p)
        {
            value=p-udigits;
        }
        else
        {
            p=strchr(ldigits, c[0]); //first the current character in ldigits
            if(p)
            {
                value=p-ldigits;
            }
            else if(c[0]=='i' || c[0]=='I' || c[0]=='l' || c[0]=='L')
            {
                value=1;
            }
            else if(c[0]=='o' || c[0]=='O')
            {
                value=0;
            }
            else if(c[0]=='s' || c[0]=='S')
            {
                value=5;
            }
            else
            {
                value=32;
            }
        }
        c++;

        if(value<32) //must be base32
        {
            if(firstdigit) //ignore the first key character
            {
                if(level==10)
                {
                    /* All level 10 keys start with the digit 1. It
                    doesn't convey any information other than the fact
                    that they're level 10 keys; discard it. */
                    //KeyString starts with 3
                    if(value==3)
                    {
                        value=0;
                        keystring=true;
                    }
                    if(value!=0)
                    {
                        value=0;
                        firstdigit=0;
                    }
                }
                else
                {
                    //KeyString starts with 3
                    if(value==3)
                    {
                        value=0;
                        keystring=true;
                    }
                    if(value!=0 && value>=16)
                    {
                        value-=16;
                        firstdigit=0;
                    }
                }
            }
            BigInt_Shift(n, 5, n2);
            BigInt_SetU(n3, value);
            BigInt_Add(n2, n3, n);
        }
    } //end of loop

    //Spit out the bytes, in reverse order.
    BigInt_Set(n3, 0xFF);
    if(level==10)
    {
        while(BigInt_Compare(n, BigInt_One())>0)
        {
            BigInt_And(n, n3, n2);
            kb[0]=(unsigned char)BigInt_GetU(n2);
            kb++;
            BigInt_Shift(n, -8, n2);
            BigInt_Copy(n, n2);
        }
    }
    else
    {
        while(BigInt_Compare(n, BigInt_Zero())!=0)
        {
            BigInt_And(n, n3, n2);
            kb[0]=(unsigned char)BigInt_GetU(n2);
            kb++;
            BigInt_Shift(n, -8, n2);
            BigInt_Copy(n, n2);
        }
    }
    if((kb-keybytes)%2) //if the length / 2 has a remainder
    {
        kb[0]=0; //discard last byte?
        kb++;
    }
    /* Reverse digits in keybytes */
    k1=keybytes;
    k2=kb-1;
    while(k1<k2)
    {
        char t=k1[0];
        k1[0]=k2[0];
        k2[0]=t;
        k2--;
        k1++;
    }
    BigInt_Destroy(n3);
    BigInt_Destroy(n2);
    BigInt_Destroy(n);
    keylength=kb-keybytes;
    memset(dest, 0, dest_len);
    memcpy(dest, keybytes, keylength);
    return keylength;
}

unsigned int FindBAADF00DPattern(BYTE* d, unsigned int size)
{
    for(unsigned int i=0; i<size; i++) //0DF0ADBA
        if(d[i]==0x0D and d[i+1]==0xF0 and d[i+2]==0xAD and d[i+3]==0xBA)
            return i;
    return 0;
}

unsigned int FindSalt1Pattern(BYTE* d, unsigned int size)
{
    for(unsigned int i=0; i<size; i++) //83??????????000F84????????B?????????C?????8B
        if(d[i]==0x83 and d[i+6]==0x00 and d[i+7]==0x0F and d[i+8]==0x84 and (d[i+13]>>4)==0x0B and (d[i+18]>>4)==0x0C and d[i+21]==0x8B)
            return i+13;
    return 0;
}

unsigned int FindSalt2Pattern(BYTE* d, unsigned int size)
{
    for(unsigned int i=0; i<size; i++) //83??????????000F84????????33C?C?????8B
        if(d[i]==0x83 and d[i+6]==0x00 and d[i+7]==0x0F and d[i+8]==0x84 and d[i+13]==0x33 and (d[i+14]>>4)==0x0C and (d[i+15]>>4)==0x0C and d[i+18]==0x8B)
            return i+13;
    return 0;
}
