#include "main.h"
#include "ecc.h"

///Plugin details.
char plugin_name[]="ECDSA Replace Full (v6.00+)";

///Global variables.
char new_dir[256]="";
char dll_dump[MAX_PATH]="";
char register_used[10]="";

bool ini_file_loaded=false;
bool projectid=false;

unsigned int cert_function_addr=0;
unsigned int md5_replace_addr=0;
unsigned int replace_md5=0;

HINSTANCE hInstance;

BYTE* security_code_mem;
unsigned int security_code_size=0;

void* malloc_(unsigned int size)
{
    return VirtualAlloc(0, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
}

bool free_(void* addr)
{
    return VirtualFree(addr, 0, MEM_RELEASE);
}

static unsigned long CT_a;

static unsigned long CT_mult(long p, long q)
{
    unsigned long p1=p/10000L, p0=p%10000L, q1=q/10000L, q0=q%10000L;
    return (((p0*q1+p1*q0) % 10000L) * 10000L+p0*q0) % 100000000L;
}

static unsigned long CT_NextRandomRange(long range)
{
    CT_a=(CT_mult(CT_a, 31415821L)+1) % 100000000L;
    return (((CT_a/10000L)*range)/10000L);
}

unsigned char* CT_GetCryptBytes(unsigned int seed, unsigned int size)
{
    CT_a=seed;
    unsigned char* arry=(unsigned char*)malloc(size);
    memset(arry, 0, size);
    for(unsigned int x=0; x<size; x++)
        arry[x]=CT_NextRandomRange(256);
    return arry;
}

void CookText(char *target, const char *source)
{
    const char *s=source;
    char *t=target;
    while(*s)
    {
        if(*s==' ' || *s=='\t' || *s=='\r' || *s=='\n') ++s;
        else if(*s>='a' && *s<='z') *t++=((*s++)-'a'+'A');
        else *t++=*s++;
    }
    *t=0;
}

void GenerateEcdsaParameters(const char* encryptiontemplate, char* private_text, char* basepoint_text, char* public_x_text, char* public_y_text)
{
    EC_PARAMETER Base;
    EC_KEYPAIR Signer;
    ECC_POINT temp;
    char encryption_template[512];
    char rndinitstring[1024];
    unsigned long i[4];
    unsigned int basepointinit;
    BigInt test=BigInt_Create();
    BigInt secretkeyhash=BigInt_Create();
    BigInt prime_order=BigInt_Create();
    CookText(encryption_template, encryptiontemplate);
    md5(i, encryption_template, strlen(encryption_template));
    basepointinit=i[0];
    sprintf(basepoint_text, "%u", basepointinit);
    ECC_InitializeTable();
    BigInt_FromString(ECC_PRIMEORDER, 10, prime_order);
    BigIntToField(prime_order, &Base.pnt_order);
    Field_Clear(&Base.cofactor);
    Base.cofactor.e[ECC_NUMWORD]=2;
    Base.crv.form=1;
    Field_Set(&Base.crv.a2);
    Field_Set(&Base.crv.a6);
    InitRandomGenerator(basepointinit);
    ECC_RandomPoint(&temp, &Base.crv);
    ECC_PointDouble(&temp, &Base.pnt, &Base.crv);
    strcpy(rndinitstring, encryption_template);
    strcat(rndinitstring, "PVTKEY");
    BigInt_Hash(rndinitstring, strlen(rndinitstring), secretkeyhash);
    ECC_KeyGenerationPrimitive(&Base, &Signer, secretkeyhash);
    FieldToBigInt(&Signer.pblc_key.x, test);
    BigInt_ToString(test, 10, public_x_text);
    FieldToBigInt(&Signer.pblc_key.y, test);
    BigInt_ToString(test, 10, public_y_text);
    FieldToBigInt(&Signer.prvt_key, test);
    BigInt_ToString(test, 10, private_text);
    BigInt_Destroy(test);
    BigInt_Destroy(secretkeyhash);
    BigInt_Destroy(prime_order);
}

unsigned int FindCertificateFunction(BYTE* mem_addr, unsigned int size)
{
    for(unsigned int i=0; i<size; i++)
    {
        if(mem_addr[i]==0x55)
            if(mem_addr[i+1]==0x8B)
                if(mem_addr[i+2]==0xEC)
                    if(mem_addr[i+18]==0x04)
                        if(mem_addr[i+19]==0x5D)
                            if(mem_addr[i+20]==0xC3)
                                return i+20;
    }
    return 0;
}

unsigned int FindMd5ReplaceAddr(BYTE* mem_addr, unsigned int size)
{
    for(unsigned int i=0; i<size; i++)
    {
        if(mem_addr[i]==0x8B)
            if(mem_addr[i+6]==0x33)
                if(mem_addr[i+12]==0x33)
                    if(mem_addr[i+18]==0x33)
                        if(mem_addr[i+24]==0x8B)
                            if(mem_addr[i+30]==0x89)
                                return i+18;
    }
    return 0;
}

void CopyToClipboard(const char* text)
{
    HGLOBAL hText;
    char *pText;

    hText = GlobalAlloc(GMEM_DDESHARE | GMEM_MOVEABLE, strlen(text)+1);
    pText = (char*)GlobalLock(hText);
    strcpy(pText, text);

    OpenClipboard(0);
    EmptyClipboard();
    if(!SetClipboardData(CF_OEMTEXT, hText))
    {
        MessageBeep(MB_ICONERROR);
    }
    CloseClipboard();
}

int AddListItem(HWND hwndDlg, const char* text)
{
    int list_id=SendDlgItemMessageA(hwndDlg, IDC_LIST_CERTS, LB_ADDSTRING, 0, (LPARAM)text);
    return list_id;
}

struct KEY_ENTRY
{
    unsigned int diff;
    unsigned int md5_dw;
    unsigned int repl_dw;
    unsigned int checksum;
    unsigned int seed2;
    char template_text[16];
    char original_value[100];
    char replace_value[100];
};

struct KEYS
{
    KEY_ENTRY* key_list;
    char* base_code;
    char* repl_code;
    unsigned int seed1;
    unsigned int projectid_diff;
    unsigned int first_dw;
    int total_key_entries;
    unsigned char projectid_byte;
};

KEYS key_vals= {0};

void GenerateCode(HWND hwndDlg)
{
    if(key_vals.base_code)
        free_(key_vals.base_code);
    if(key_vals.repl_code)
        free_(key_vals.repl_code);
    //Cert & MD5 patch code
    char md5_patch_code[8000]="";
    strcpy(md5_patch_code, "@md5_patch:\r\nmov eax, dword ptr ds:[esp-8]\r\nmov eax, dword ptr ds:[eax]\r\n");
    char md5_patch_block[8000]="";

    const char* jump_type=" short ";
    if(md5_replace_addr)
    {
        for(int i=0; i<key_vals.total_key_entries; i++)
        {
            if(key_vals.total_key_entries>10)
            {
                int no_jmp=key_vals.total_key_entries-10;
                if(i<no_jmp)
                    jump_type=" ";
                else
                    jump_type=" short ";
            }
            sprintf(md5_patch_block, "cmp eax,0%X ; %s\r\njne short @skip%d\r\nmov eax,0%X\r\njmp%s@md5_patch_end\r\n@skip%d:\r\n", key_vals.key_list[i].repl_dw, key_vals.key_list[i].template_text, i, key_vals.key_list[i].md5_dw, jump_type, i);
            strcat(md5_patch_code, md5_patch_block);
        }
        strcat(md5_patch_code, "@md5_patch_end:\r\n\"\\xE9\\0\\0\\0\\0\"");
    }
    char cert_patch_code[8000]="";
    sprintf(cert_patch_code, "@cert_patch:\r\ncmp dword ptr ds:[eax],%X\r\nje short @replace\r\nretn\r\n@replace:\r\npushad\r\n", key_vals.first_dw);
    char cert_patch_block[8000]="";
    char cert_patch_final[8000]="";
    if(projectid)
    {
        if(key_vals.seed1 or key_vals.key_list[0].seed2)
        sprintf(cert_patch_code, "%smov byte ptr ds:[eax+0%X], 0%X\r\n", cert_patch_code, key_vals.projectid_diff, key_vals.projectid_byte);
            else
        sprintf(cert_patch_code, "%smov byte ptr ds:[eax+2], 0%X\r\n", cert_patch_code, key_vals.projectid_byte);
    }


    for(int i=0; i<key_vals.total_key_entries; i++)
    {
        sprintf(cert_patch_block, "lea edi, dword ptr ds:[eax+0%X]\r\nlea esi, dword ptr ds:[@patch%d]\r\nmov ecx, %X\r\nrep movs byte ptr es:[edi], byte ptr ds:[esi]\r\n", key_vals.key_list[i].diff, i, strlen(key_vals.key_list[i].replace_value));
        strcat(cert_patch_code, cert_patch_block);

        //v9.60 support
        char replaced_pub_string[1024]="";
        if(key_vals.key_list[i].seed2 or key_vals.seed1)
        {
            unsigned char cpy[256]="";
            strcpy((char*)cpy, key_vals.key_list[i].replace_value);
            int new_pub_len=strlen((char*)cpy);
            unsigned char* rand=CT_GetCryptBytes(key_vals.key_list[i].seed2, new_pub_len);
            for(int i=0,j=0; i<new_pub_len; i++)
            {
                cpy[i]^=rand[i];
                j+=sprintf(replaced_pub_string+j, "\\x%.2X", cpy[i]);
            }
        }
        else
            strcpy(replaced_pub_string, key_vals.key_list[i].replace_value);

        sprintf(cert_patch_block, "@patch%d:\r\n\"%s\\0\"\r\n", i, replaced_pub_string);
        strcat(cert_patch_final, cert_patch_block);
    }
    strcat(cert_patch_code, "popad\r\nretn\r\n");
    strcat(cert_patch_code, cert_patch_final);
    int total_len=strlen(cert_patch_code)+strlen(md5_patch_code);
    key_vals.repl_code=(char*)malloc_(total_len+1);
    if(md5_replace_addr)
    {
        strcpy(key_vals.repl_code, md5_patch_code);
        strcat(key_vals.repl_code, "\r\n");
        strcat(key_vals.repl_code, cert_patch_code);
    }
    else
        strcpy(key_vals.repl_code, cert_patch_code);
    //Base code
    cert_patch_code[0]=0;
    sprintf(cert_patch_code, "lea edi, dword ptr ds:[%s+0%X]\r\nmov byte ptr [edi], 0E9\r\nlea ebx, dword ptr ds:[@cert_patch]\r\nsub ebx, edi\r\nlea ebx, dword ptr ds:[ebx-5]\r\nmov dword ptr [edi+1], ebx\r\n", register_used, cert_function_addr);
    if(md5_replace_addr)
    {
        md5_patch_code[0]=0;
        sprintf(md5_patch_code, "lea edi, dword ptr ds:[%s+0%X]\r\nmov word ptr ds:[edi], 0E990\r\nlea ebx, dword ptr ds:[@md5_patch]\r\nsub ebx, edi\r\nlea ebx, dword ptr ds:[ebx-6]\r\nmov dword ptr ds:[edi+2], ebx\r\ninc edi\r\nlea ebx, dword ptr ds:[@md5_patch_end]\r\nmov eax, ebx\r\nsub edi, eax\r\nmov dword ptr ds:[eax+1], edi\r\n", register_used, md5_replace_addr);
        strcat(cert_patch_code, md5_patch_code);
    }
    key_vals.base_code=(char*)malloc_(strlen(cert_patch_code)+1);
    memset(key_vals.base_code, 0, strlen(cert_patch_code)+1);
    strcpy(key_vals.base_code, cert_patch_code);
    SetDlgItemTextA(hwndDlg, IDC_EDT_CODE_BASE, key_vals.base_code);
    SetDlgItemTextA(hwndDlg, IDC_EDT_CODE_REPL, key_vals.repl_code);
}

void GenerateNewValues()
{
    OutputDebugStringA("GenerateNewValues");
    int number=0;
    char new_template[256]="";
    char pvt[50]="",base[50]="",x[50]="",y[50]="";
    char new_value[100]="";
    char temp[256]="";
    for(int i=0; i<key_vals.total_key_entries; i++)
    {
        unsigned int orig_len=strlen(key_vals.key_list[i].original_value);
        do
        {
            sprintf(new_template, "%d", number);
            number++;
            GenerateEcdsaParameters(new_template, pvt, base, x, y);
            sprintf(new_value, "%s,%s,%s", base, x, y);
        }
        while(strlen(new_value)!=orig_len);
        memset(key_vals.key_list[i].replace_value, 0, 84);
        strcpy(key_vals.key_list[i].replace_value, new_value);
        strcpy(key_vals.key_list[i].template_text, new_template);
        strcpy(temp, new_value);
        _strrev(temp);
        unsigned int* a=(unsigned int*)&temp;
        key_vals.key_list[i].repl_dw=*a;
    }
}

void ReadKeysFile(HWND hwndDlg, const char* dropped_file)
{
    OutputDebugStringA("GenerateNewValues");
    strcpy(new_dir, dropped_file);
    int len=strlen(new_dir);
    while(new_dir[len]!='\\')
        len--;
    new_dir[len]=0;
    SendDlgItemMessageA(hwndDlg, IDC_LIST_CERTS, LB_RESETCONTENT, 0, 0);
    if(key_vals.key_list)
        free_(key_vals.key_list);

    if(key_vals.base_code)
        free_(key_vals.base_code);
    if(key_vals.repl_code)
        free_(key_vals.repl_code);
    memset(&key_vals, 0, sizeof(KEYS));

    char section_names[2048]="";
    char temp[256]="";
    char lvl_text[10]="";

    int len_sections=GetPrivateProfileSectionNamesA(section_names, 2048, dropped_file);
    for(int i=0; i<len_sections; i++)
        if(!section_names[i])
            key_vals.total_key_entries++;

    char** cert_names=(char**)malloc_(4*key_vals.total_key_entries);

    for(int i=0,j=0; i<len_sections; i++)
    {
        if(section_names[i])
            sprintf(temp, "%s%c", temp, section_names[i]);
        else
        {
            lvl_text[0]=0;
            GetPrivateProfileStringA(temp, "level", "", lvl_text, 10, dropped_file);
            if(lvl_text[0] and !strcmp(lvl_text, "29"))
            {
                cert_names[j]=(char*)malloc_(strlen(temp)+1);
                strcpy(cert_names[j], temp);
                j++;
                key_vals.total_key_entries=j;
            }
            temp[0]=0;
        }
    }
    if(key_vals.total_key_entries)
        ini_file_loaded=true;
    else
    {
        ini_file_loaded=false;
        return;
    }
    GetPrivateProfileStringA(cert_names[0], "first_dw", "", temp, 10, dropped_file);
    sscanf(temp, "%X", &key_vals.first_dw);
    //v9.60 support
    GetPrivateProfileStringA(cert_names[0], "seed1", "", temp, 10, dropped_file);
    sscanf(temp, "%X", &key_vals.seed1);
    GetPrivateProfileStringA(cert_names[0], "projectid_diff", "", temp, 10, dropped_file);
    sscanf(temp, "%X", &key_vals.projectid_diff);

    key_vals.key_list=(KEY_ENTRY*)malloc_(sizeof(KEY_ENTRY)*key_vals.total_key_entries);
    memset(key_vals.key_list, 0, sizeof(KEY_ENTRY)*key_vals.total_key_entries);
    for(int i=0; i<key_vals.total_key_entries; i++)
    {
        GetPrivateProfileStringA(cert_names[i], "chk", "", temp, 10, dropped_file);
        sscanf(temp, "%X", &key_vals.key_list[i].checksum);
        //v9.60 support
        GetPrivateProfileStringA(cert_names[i], "seed2", "", temp, 10, dropped_file);
        sscanf(temp, "%X", &key_vals.key_list[i].seed2);
        GetPrivateProfileStringA(cert_names[i], "diff", "", temp, 10, dropped_file);
        sscanf(temp, "%X", &key_vals.key_list[i].diff);
        GetPrivateProfileStringA(cert_names[i], "md5", "", temp, 10, dropped_file);
        sscanf(temp, "%X", &key_vals.key_list[i].md5_dw);
        GetPrivateProfileStringA(cert_names[i], "pub", "", temp, 100, dropped_file);
        free_(cert_names[i]);
        memset(key_vals.key_list[i].original_value, 0, 84);
        strcpy(key_vals.key_list[i].original_value, temp);
        char basep[100]="";
        strcpy(basep, key_vals.key_list[i].original_value);
        wsprintf(temp, "Checksum : %.8X - MD5 : %.8X - Diff : %.8X - BasePoint : %s", key_vals.key_list[i].checksum, key_vals.key_list[i].md5_dw, key_vals.key_list[i].diff, strtok(basep, ","));
        AddListItem(hwndDlg, temp);
    }
    GenerateNewValues();
    GenerateCode(hwndDlg);
    EnableWindow(GetDlgItem(hwndDlg, IDC_BTN_COPY_REPL), 1);
    EnableWindow(GetDlgItem(hwndDlg, IDC_BTN_COPY_BASE), 1);
    EnableWindow(GetDlgItem(hwndDlg, IDC_BTN_SAVE), 1);
    free_(cert_names);
}

bool Initialize(HWND hwndDlg)
{
    HANDLE hFile=CreateFileA(dll_dump, GENERIC_ALL, 0, 0, OPEN_EXISTING, 0, 0);
    if(hFile==INVALID_HANDLE_VALUE)
        return false;

    DWORD high=0;
    security_code_size=GetFileSize(hFile, &high);
    security_code_mem=(BYTE*)malloc_(security_code_size);
    if(!ReadFile(hFile, security_code_mem, security_code_size, &high, 0))
    {
        CloseHandle(hFile);
        free_(security_code_mem);
        return false;
    }
    CloseHandle(hFile);
    md5_replace_addr=FindMd5ReplaceAddr(security_code_mem, security_code_size);
    cert_function_addr=FindCertificateFunction(security_code_mem, security_code_size);
    if(!cert_function_addr)
        return false;
    AddListItem(hwndDlg, "Drag&Drop a .akt file to get started...");
    SendDlgItemMessageA(hwndDlg, IDC_LIST_CERTS, CB_SETCURSEL, 0, 0);
    return true;
}

BOOL CALLBACK DlgMain(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch(uMsg)
    {
    case WM_INITDIALOG:
    {
        HWND p=GetParent(hwndDlg);
        if(p)
        {
            HICON ico=(HICON)SendMessageA(p, WM_GETICON, ICON_SMALL, 0);
            SendMessageA(hwndDlg, WM_SETICON, ICON_SMALL, (LPARAM)ico);
        }
        EnableWindow(GetDlgItem(hwndDlg, IDC_BTN_COPY_REPL), 0);
        EnableWindow(GetDlgItem(hwndDlg, IDC_BTN_COPY_BASE), 0);
        EnableWindow(GetDlgItem(hwndDlg, IDC_BTN_SAVE), 0);
        if(!Initialize(hwndDlg))
        {
            MessageBoxA(hwndDlg, "Something went wrong during the initialization of the plugin.\n\nMaybe the file you are loading is unsupported, please contact me\n(Mr. eXoDia) at mr.exodia.tpodt@gmail.com, I can fix it...", "Error...", MB_ICONERROR);
            SendMessageA(hwndDlg, WM_CLOSE, 0, 0);
        }
    }
    return TRUE;

    case WM_CLOSE:
    {
        EndDialog(hwndDlg, 0);
    }
    return TRUE;

    case WM_DROPFILES:
    {
        char ini_file[256]="";
        DragQueryFileA((HDROP)wParam, NULL, ini_file, 256);
        if(!strcmp(ini_file+(strlen(ini_file)-3), "akt"))
            ReadKeysFile(hwndDlg, ini_file);
        else
            MessageBoxA(hwndDlg, "Please drop a valid file...", "Error!", MB_ICONERROR);
    }
    return TRUE;

    case WM_COMMAND:
    {
        switch(LOWORD(wParam))
        {
        case IDC_LIST_CERTS:
        {
            switch(HIWORD(wParam))
            {
            case CBN_SELCHANGE:
            {
                int current_selected=SendDlgItemMessageA(hwndDlg, IDC_LIST_CERTS, LB_GETCURSEL, 0, 0);
                if(ini_file_loaded)
                {
                    char temp_name[10]="";
                    SetDlgItemTextA(hwndDlg, IDC_EDT_PUBVALS_OLD, key_vals.key_list[current_selected].original_value);
                    sprintf(temp_name, "%X", strlen(key_vals.key_list[current_selected].original_value));
                    SetDlgItemTextA(hwndDlg, IDC_EDT_PUBVALS_OLD_LEN, temp_name);
                    SetDlgItemTextA(hwndDlg, IDC_EDT_PUBVALS_NEW, key_vals.key_list[current_selected].replace_value);
                    sprintf(temp_name, "%X", strlen(key_vals.key_list[current_selected].replace_value));
                    SetDlgItemTextA(hwndDlg, IDC_EDT_PUBVALS_NEW_LEN, temp_name);
                    SetDlgItemTextA(hwndDlg, IDC_EDT_TEMPLATE, key_vals.key_list[current_selected].template_text);
                }
            }
            return TRUE;
            }
        }
        return TRUE;

        case IDC_CHK_PROJECTID:
        {
            projectid=IsDlgButtonChecked(hwndDlg, IDC_CHK_PROJECTID);
            if(ini_file_loaded)
            {
                unsigned int rand_init=~GetTickCount();
                BYTE bytes_gtc[4]= {0};
                bytes_gtc[0]=rand_init>>24;
                bytes_gtc[1]=(rand_init<<8)>>24;
                bytes_gtc[2]=(rand_init<<12)>>24;
                bytes_gtc[3]=(rand_init<<16)>>24;
                BYTE final_byte=bytes_gtc[0]^bytes_gtc[1]^bytes_gtc[2]^bytes_gtc[3];
                if(final_byte<0x20)
                    final_byte+=0x20;
                else if(final_byte>0x7E)
                {
                    final_byte-=0x81;
                    if(final_byte<0x20)
                        final_byte+=0x21;
                }
                //v9.60 support
                unsigned char xor_byte=0;
                if(key_vals.seed1 or key_vals.key_list[0].seed2)
                {
                    CT_a=key_vals.seed1;
                    unsigned int result=CT_NextRandomRange(256);
                    memcpy(&xor_byte, &result, 1);
                }
                key_vals.projectid_byte=final_byte^xor_byte;
                GenerateCode(hwndDlg);
            }
        }
        return TRUE;

        case IDC_BTN_SAVE:
        {
            char* save_file_string=(char*)malloc(0x20000);
            memset(save_file_string, 0, 0x20000);
            char current_line[1024]="";
            int count=SendDlgItemMessageA(hwndDlg, IDC_LIST_CERTS, LB_GETCOUNT, 0, 0);
            for(int i=0; i<count; i++)
            {
                if(i)
                    strcat(save_file_string, "\r\n\r\n");
                if(key_vals.seed1 or key_vals.key_list[0].seed2)
                {
                    sprintf(current_line, "  Chk : %.8X\r\n Size : %X\r\n Diff : %X\r\n  MD5 : %.8X\r\nTempl : %s\r\n Orig : %s\r\n Repl : %s\r\n Seed : %.8X",
                            key_vals.key_list[i].checksum,
                            strlen(key_vals.key_list[i].replace_value),
                            key_vals.key_list[i].diff,
                            key_vals.key_list[i].md5_dw,
                            key_vals.key_list[i].template_text,
                            key_vals.key_list[i].original_value,
                            key_vals.key_list[i].replace_value,
                            key_vals.key_list[i].seed2);
                }
                else
                {
                    sprintf(current_line, "  Chk : %.8X\r\n Size : %X\r\n Diff : %X\r\n  MD5 : %.8X\r\nTempl : %s\r\n Orig : %s\r\n Repl : %s",
                            key_vals.key_list[i].checksum,
                            strlen(key_vals.key_list[i].replace_value),
                            key_vals.key_list[i].diff,
                            key_vals.key_list[i].md5_dw,
                            key_vals.key_list[i].template_text,
                            key_vals.key_list[i].original_value,
                            key_vals.key_list[i].replace_value);
                }
                strcat(save_file_string, current_line);
            }
            char filename[256]="";
            OPENFILENAME ofstruct;
            memset(&ofstruct, 0, sizeof(ofstruct));
            ofstruct.lStructSize=sizeof(ofstruct);
            ofstruct.hwndOwner=hwndDlg;
            ofstruct.hInstance=hInstance;
            ofstruct.lpstrFilter="Log Files (*.log)\0*.log\0\0";
            ofstruct.lpstrFile=filename;
            ofstruct.lpstrInitialDir=new_dir;
            ofstruct.nMaxFile=256;
            ofstruct.lpstrTitle="Save file";
            ofstruct.lpstrDefExt="log";
            ofstruct.Flags=OFN_EXTENSIONDIFFERENT|OFN_HIDEREADONLY|OFN_NONETWORKBUTTON|OFN_OVERWRITEPROMPT;
            GetSaveFileName(&ofstruct);
            if(!filename[0])
            {
                if(MessageBoxA(hwndDlg, "No file selected, would you like to copy to clipboard?", "Question", MB_ICONQUESTION|MB_YESNO)==IDYES)
                {
                    CopyToClipboard(save_file_string);
                    MessageBeep(MB_ICONINFORMATION);
                }
                return TRUE;
            }
            DeleteFile(filename);
            HANDLE hFile=CreateFileA(filename, GENERIC_ALL, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
            if(hFile==INVALID_HANDLE_VALUE)
            {
                MessageBoxA(hwndDlg, "Could not create file!", filename, MB_ICONERROR);
                return TRUE;
            }
            DWORD written=0;
            WriteFile(hFile, save_file_string, strlen(save_file_string), &written, 0);
            CloseHandle(hFile);
            free(save_file_string);
            MessageBeep(MB_ICONINFORMATION);
        }
        return TRUE;

        case IDC_BTN_COPY_BASE:
        {
            CopyToClipboard(key_vals.base_code);
            MessageBeep(MB_ICONINFORMATION);
        }
        return TRUE;

        case IDC_BTN_COPY_REPL:
        {
            CopyToClipboard(key_vals.repl_code);
            MessageBeep(MB_ICONINFORMATION);
        }
        return TRUE;

        case IDC_BTN_ABOUT:
        {
            MessageBoxA(hwndDlg, "Drag & Drop a .akt file to start...", "Armadillo ECDSA Public Parameter Patcher Plugin v0.4", MB_ICONINFORMATION);
        }
        return TRUE;
        }
    }
    return TRUE;
    }
    return FALSE;
}

const char* DLL_EXPORT PluginInfo(void)
{
    return plugin_name;
}

void DLL_EXPORT PluginFunction(HINSTANCE hInst, HWND hwndDlg, const char* register_vp, const char* program_dir, unsigned int imagebase)
{
    hInstance=hInst;
    sprintf(dll_dump, "%s\\security_code.mem", program_dir);
    strcpy(register_used, register_vp);
    InitCommonControls();
    DialogBox(hInst, MAKEINTRESOURCE(DLG_MAIN), hwndDlg, (DLGPROC)DlgMain);
}

extern "C" BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    return TRUE;
}
