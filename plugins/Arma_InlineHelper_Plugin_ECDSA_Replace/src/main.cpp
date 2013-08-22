#include "main.h"
#include "ecc.h"

///Plugin details.
char plugin_name[]="ECDSA Replace (v6.00+)";

///Global variables.
char dll_dump[MAX_PATH]="";
char register_used[10]="";
char base_code[2048]="";
char repl_code[4096]="";
char ini_file[256]="";
char cur_pub_text[256]="";
char cur_dif_text[10]="";
char cur_md5_text[10]="";
char cur_seed1_text[10]="";
char cur_seed2_text[10]="";
char cur_projectid_diff_text[10]="";
char first_dword_text[10]="";

bool ini_file_loaded=false;
bool projectid=false;

unsigned int cert_function_addr=0;
unsigned int md5_replace_addr=0;
unsigned int replace_md5=0;

HINSTANCE hInstance;

int total_certs=0;
char** cert_names=0;

BYTE* security_code_mem;
unsigned int security_code_size=0;

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
    int list_id=SendDlgItemMessageA(hwndDlg, IDC_LIST_CERTS, CB_ADDSTRING, 0, (LPARAM)text);
    return list_id;
}

void ReadIniFile(HWND hwndDlg, const char* ini_file_drop)
{
    ini_file_loaded=true;
    char section_names[2048]="";
    char temp_name[256]="";
    char lvl_text[10]="";
    char md5_text[10]="";
    char init_value[100]="";
    char chk_text[10]="", diff_text[10]="";
    int total_count=0;
    SendDlgItemMessageA(hwndDlg, IDC_LIST_CERTS, CB_RESETCONTENT, 0, 0);
    if(total_certs)
    {
        for(int i=0; i<total_certs; i++)
        {
            free(cert_names[i]);
        }
        free(cert_names);
        total_certs=0;
        cert_names=0;
    }
    int len_sections=GetPrivateProfileSectionNamesA(section_names, 2048, ini_file_drop);
    for(int i=0; i<len_sections; i++)
    {
        if(!section_names[i])
            total_count++;
    }
    total_certs=total_count;
    cert_names=(char**)malloc(total_certs*4);
    for(int i=0,j=0; i<len_sections; i++)
    {
        if(section_names[i])
        {
            sprintf(temp_name, "%s%c", temp_name, section_names[i]);
        }
        else
        {
            memset(lvl_text, 0, 10);
            GetPrivateProfileStringA(temp_name, "level", "", lvl_text, 10, ini_file_drop);
            if(!strcmp(lvl_text, "29"))
            {
                cert_names[j]=(char*)malloc(strlen(temp_name)+1);
                strcpy(cert_names[j], temp_name);
                j++;
                total_certs=j;
            }
            memset(temp_name, 0, 256);
        }
    }
    for(int i=0; i<total_certs; i++)
    {
        GetPrivateProfileStringA(cert_names[i], "chk", "", chk_text, 10, ini_file_drop);
        GetPrivateProfileStringA(cert_names[i], "diff", "", diff_text, 10, ini_file_drop);
        GetPrivateProfileStringA(cert_names[i], "md5", "", md5_text, 10, ini_file_drop);
        GetPrivateProfileStringA(cert_names[i], "pub", "", init_value, 100, ini_file_drop);
        char* test123=strtok(init_value, ",");;
        wsprintf(temp_name, "Checksum : %s - MD5 : %s - Diff : %08s - BasePoint : %s", chk_text, md5_text, diff_text, test123);
        AddListItem(hwndDlg, temp_name);
        memset(temp_name, 0, 256);
    }
    GetPrivateProfileStringA(cert_names[0], "first_dw", "", first_dword_text, 10, ini_file_drop);
    SendDlgItemMessageA(hwndDlg, IDC_LIST_CERTS, CB_SETCURSEL, 0, 0);
    GetPrivateProfileStringA(cert_names[0], "pub", "", cur_pub_text, 256, ini_file);
    GetPrivateProfileStringA(cert_names[0], "diff", "", cur_dif_text, 10, ini_file);
    GetPrivateProfileStringA(cert_names[0], "md5", "", cur_md5_text, 10, ini_file);

    //v9.60 support
    GetPrivateProfileStringA(cert_names[0], "seed1", "", cur_seed1_text, 10, ini_file);
    GetPrivateProfileStringA(cert_names[0], "seed2", "", cur_seed2_text, 10, ini_file);

    SetDlgItemTextA(hwndDlg, IDC_EDT_PUBVALS_OLD, cur_pub_text);
    sprintf(temp_name, "%X", strlen(cur_pub_text));
    SetDlgItemTextA(hwndDlg, IDC_EDT_PUBVALS_OLD_LEN, temp_name);
    if(md5_replace_addr)
        sprintf(base_code, base_code_format+1, register_used, cert_function_addr, register_used, md5_replace_addr, cur_md5_text);
    else
        sprintf(base_code, base_code_format2+1, register_used, cert_function_addr);
    SetDlgItemTextA(hwndDlg, IDC_EDT_CODE_BASE, base_code);
    EnableWindow(GetDlgItem(hwndDlg, IDC_EDT_TEMPLATE), 1);
    EnableWindow(GetDlgItem(hwndDlg, IDC_BTN_COPY_BASE), 1);
}

bool Initialize(HWND hwndDlg)
{
    HANDLE hFile=CreateFileA(dll_dump, GENERIC_ALL, 0, 0, OPEN_EXISTING, 0, 0);
    if(hFile==INVALID_HANDLE_VALUE)
        return false;

    DWORD high=0;
    security_code_size=GetFileSize(hFile, &high);
    security_code_mem=(BYTE*)malloc(security_code_size);
    if(!ReadFile(hFile, security_code_mem, security_code_size, &high, 0))
    {
        CloseHandle(hFile);
        free(security_code_mem);
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
        EnableWindow(GetDlgItem(hwndDlg, IDC_EDT_TEMPLATE), 0);
        EnableWindow(GetDlgItem(hwndDlg, IDC_BTN_COPY_REPL), 0);
        EnableWindow(GetDlgItem(hwndDlg, IDC_BTN_COPY_BASE), 0);
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
        DragQueryFileA((HDROP)wParam, NULL, ini_file, MAX_PATH);
        if(!strcmp(ini_file+(strlen(ini_file)-3), "akt"))
            ReadIniFile(hwndDlg, ini_file);
        else
            MessageBoxA(hwndDlg, "Please drop a valid file...", "Error!", MB_ICONERROR);
    }
    return TRUE;

    case WM_COMMAND:
    {
        switch(LOWORD(wParam))
        {
        case IDC_CHK_PROJECTID:
        {
            projectid=IsDlgButtonChecked(hwndDlg, IDC_CHK_PROJECTID);
            char new_pub_text[100]="";
            if(GetDlgItemTextA(hwndDlg, IDC_EDT_PUBVALS_NEW, new_pub_text, 100))
                SetDlgItemTextA(hwndDlg, IDC_EDT_PUBVALS_NEW, new_pub_text);
        }
        return TRUE;

        case IDC_EDT_TEMPLATE:
        {
            char templ[256]="";
            char base[256]="";
            char x[256]="";
            char y[256]="";
            char pvt[256]="";
            int old_len=strlen(cur_pub_text);
            if(GetDlgItemTextA(hwndDlg, IDC_EDT_TEMPLATE, templ, 256))
            {
                GenerateEcdsaParameters(templ, pvt, base, x, y);
                sprintf(pvt, "%s,%s,%s", base, x, y);
                sprintf(base, "%X", strlen(pvt));
            }
            int len=strlen(pvt);
            if(len==old_len)
            {
                SetDlgItemTextA(hwndDlg, IDC_EDT_PUBVALS_NEW, pvt);
                SetDlgItemTextA(hwndDlg, IDC_EDT_PUBVALS_NEW_LEN, base);
            }
            else
            {
                SetDlgItemTextA(hwndDlg, IDC_EDT_PUBVALS_NEW, "");
                SetDlgItemTextA(hwndDlg, IDC_EDT_PUBVALS_NEW_LEN, "");
            }
        }
        return TRUE;

        case IDC_LIST_CERTS:
        {
            switch(HIWORD(wParam))
            {
            case CBN_SELCHANGE:
            {
                int current_selected=SendDlgItemMessageA(hwndDlg, IDC_LIST_CERTS, CB_GETCURSEL, 0, 0);
                if(ini_file_loaded)
                {
                    char temp_name[10]="";
                    GetPrivateProfileStringA(cert_names[current_selected], "pub", "", cur_pub_text, 256, ini_file);
                    GetPrivateProfileStringA(cert_names[current_selected], "diff", "", cur_dif_text, 10, ini_file);
                    GetPrivateProfileStringA(cert_names[current_selected], "md5", "", cur_md5_text, 10, ini_file);

                    //v9.60 support
                    GetPrivateProfileStringA(cert_names[current_selected], "seed1", "", cur_seed1_text, 10, ini_file);
                    GetPrivateProfileStringA(cert_names[current_selected], "seed2", "", cur_seed2_text, 10, ini_file);
                    GetPrivateProfileStringA(cert_names[current_selected], "projectid_diff", "", cur_projectid_diff_text, 10, ini_file);

                    SetDlgItemTextA(hwndDlg, IDC_EDT_PUBVALS_OLD, cur_pub_text);
                    sprintf(temp_name, "%X", strlen(cur_pub_text));
                    SetDlgItemTextA(hwndDlg, IDC_EDT_PUBVALS_OLD_LEN, temp_name);
                    sprintf(base_code, base_code_format+1, register_used, cert_function_addr, register_used, md5_replace_addr, cur_md5_text);
                    SetDlgItemTextA(hwndDlg, IDC_EDT_CODE_BASE, base_code);
                    EnableWindow(GetDlgItem(hwndDlg, IDC_BTN_COPY_BASE), 1);
                    SetDlgItemTextA(hwndDlg, IDC_EDT_PUBVALS_NEW, "");
                }
            }
            return TRUE;
            }
        }
        return TRUE;

        case IDC_EDT_PUBVALS_NEW:
        {
            char new_pub[256]="";
            char new_byte[10]="";
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
            if(cur_seed1_text[0] and cur_seed2_text[0])
            {
                unsigned int seed1=0;
                sscanf(cur_seed1_text, "%X", &seed1);
                CT_a=seed1;
                unsigned int result=CT_NextRandomRange(256);
                memcpy(&xor_byte, &result, 1);
            }
            sprintf(new_byte, "%X", final_byte^xor_byte);

            int new_pub_len=GetDlgItemTextA(hwndDlg, IDC_EDT_PUBVALS_NEW, new_pub, 256);
            if(new_pub_len)
            {
                char replaced_pub_string[1024]="";
                unsigned int proj_diff=2;
                //v9.60 support
                if(cur_seed1_text[0] and cur_seed2_text[0])
                {
                    sscanf(cur_projectid_diff_text, "%X", &proj_diff);
                    unsigned char cpy[256]="";
                    strcpy((char*)cpy, new_pub);
                    unsigned int seed2=0;
                    sscanf(cur_seed2_text, "%X", &seed2);
                    unsigned char* rand=CT_GetCryptBytes(seed2, new_pub_len);
                    for(int i=0,j=0; i<new_pub_len; i++)
                    {
                        cpy[i]^=rand[i];
                        j+=sprintf(replaced_pub_string+j, "\\x%.2X", cpy[i]);
                    }
                }
                else
                    strcpy(replaced_pub_string, new_pub);

                if(projectid)
                    sprintf(repl_code, repl_code_format2+1, first_dword_text, proj_diff, new_byte, cur_dif_text, new_pub_len, replaced_pub_string);
                else
                    sprintf(repl_code, repl_code_format+1, first_dword_text, cur_dif_text, new_pub_len, replaced_pub_string);
                SetDlgItemTextA(hwndDlg, IDC_EDT_CODE_REPL, repl_code);
                EnableWindow(GetDlgItem(hwndDlg, IDC_BTN_COPY_REPL), 1);
            }
            else
            {
                SetDlgItemTextA(hwndDlg, IDC_EDT_CODE_REPL, "");
                EnableWindow(GetDlgItem(hwndDlg, IDC_BTN_COPY_REPL), 0);
            }
        }
        return TRUE;

        case IDC_BTN_COPY_BASE:
        {
            CopyToClipboard(base_code);
            MessageBeep(MB_ICONINFORMATION);
        }
        return TRUE;

        case IDC_BTN_COPY_REPL:
        {
            CopyToClipboard(repl_code);
            MessageBeep(MB_ICONINFORMATION);
        }
        return TRUE;

        case IDC_BTN_ABOUT:
        {
            MessageBoxA(hwndDlg, "This plugin is very simple... Just Drag&Drop a .akt file created by Armadillo Key Tool,\nselect the certificate you want to use and use the Generate button to create new\npublic vals.\n\nThe Base Code is supposed be copied after: \";PLACE YOU CODE AFTER THIS!!!\"\nThe Replace Code should be appended to your inline code...\n\nMr. eXoDia\nmr.exodia.tpodt@gmail.com", "Armadillo ECDSA Public Parameter Replace Plugin v0.4", MB_ICONINFORMATION);
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
