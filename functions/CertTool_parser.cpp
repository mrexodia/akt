#include "CertTool_parser.h"

//Superglobal variables
bool CT_created_log=false; //bool for if our log was created
bool CT_isparsing=false; //Is parsing certificate info?

/*void listadd(const char* text)
{
    int sel=SendMessageA(list, LB_ADDSTRING, 0, (LPARAM)text);
    SendMessageA(list, LB_SETCURSEL, sel, 0);
}*/

void CT_AddToLog(HWND list, const char* text)
{
    //Add to the listbox
    if(list)
    {
        //listadd(text);
        int sel=SendMessageA(list, LB_ADDSTRING, 0, (LPARAM)text);
        SendMessageA(list, LB_SETCURSEL, sel, 0);
    }

    //Add to the logfile
    if(CT_logtofile)
    {
        int len=strlen(text)+3;
        char* new_text=(char*)malloc2(len);
        memset(new_text, 0, len);
        HANDLE hFile;
        if(!CT_created_log)
        {
            CT_created_log=true;
            DeleteFile(CT_szLogFile);
            hFile=CreateFileA(CT_szLogFile, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_WRITE, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
            if(hFile==INVALID_HANDLE_VALUE)
            {
                if(MessageBoxA(CT_shared, "Could not create log file, continue?", CT_szLogFile, MB_ICONERROR|MB_YESNO)==IDNO)
                {
                    free2(new_text);
                    TerminateThread(GetCurrentThread(), 0);
                    return;
                }
            }
            else
                strcpy(new_text, text);
        }
        else
        {
            hFile=CreateFileA(CT_szLogFile, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
            if(hFile!=INVALID_HANDLE_VALUE)
                sprintf(new_text, "\r\n%s", text);
        }
        if(hFile!=INVALID_HANDLE_VALUE)
        {
            OVERLAPPED ovrl= {0};
            ovrl.Offset=GetFileSize(hFile, 0);
            WriteFile(hFile, new_text, strlen(new_text), 0, &ovrl);
            CloseHandle(hFile);
        }
        free2(new_text);
    }
}

void CT_AddLogMessage(HWND list, const char* text)
{
    int len=strlen(text);
    char current_add[256]="";
    for(int i=0,j=0; i<len; i++)
    {
        if(text[i]!='\r' and text[i]!='\n')
            j+=sprintf(current_add+j, "%c", text[i]);
        else
        {
            if(text[i]=='\r' and text[i+1]=='\n')
                i++;
            CT_AddToLog(list, current_add);
            j=0;
        }
    }
    CT_AddToLog(list, current_add);
}

unsigned char* nextptr(unsigned char** data, unsigned int size)
{
    if(!size)
        return data[0];
    data[0]+=size;
    return data[0]-size;
}

unsigned int GetFlagsFromTimeStamp(unsigned int a)
{
    if(a<v400h)
        return 0;
    else if(a>v410420l && a<v410420h)
        return fcustomerservice;
    else if(a>v430604l && a<v430604h)
        return fcustomerservice|fwebsite;
    else if(a>v620740l && a<v620740h)
        return fcustomerservice|fwebsite|funknown;
    else if(a>v800h)
        return fcustomerservice|fwebsite;
    return 0xFFFFFFFF;
}

void CT_DecodeCerts()
{
    CERT_DATA* cd=CT_cert_data;

    if(!cd->raw_data or !cd->raw_size)
        return;

    unsigned int flags=GetFlagsFromTimeStamp(cd->timestamp);
    if(flags==0xFFFFFFFF)
        return;
    unsigned char* dec=(unsigned char*)malloc2(cd->raw_size);
    unsigned char* dec_start=dec;
    memcpy(dec, cd->raw_data, cd->raw_size);
    free2(cd->raw_data);

    //First DWORD
    memcpy(&cd->first_dw, dec, sizeof(unsigned int));
    //Project ID
    unsigned short* projectID_size=(unsigned short*)nextptr(&dec, sizeof(unsigned short));
    if(*projectID_size)
    {
        cd->projectid=(char*)malloc2(*projectID_size+1);
        memset(cd->projectid, 0, *projectID_size+1);
        memcpy(cd->projectid, nextptr(&dec, *projectID_size), *projectID_size);
    }
    //Customer Service
    if(flags&fcustomerservice)
    {
        unsigned short* customerSER_size=(unsigned short*)nextptr(&dec, sizeof(unsigned short));
        if(*customerSER_size)
        {
            cd->customer_service=(char*)malloc2(*customerSER_size+1);
            memset(cd->customer_service, 0, *customerSER_size+1);
            memcpy(cd->customer_service, nextptr(&dec, *customerSER_size), *customerSER_size);
        }
    }
    //Website
    if(flags&fwebsite)
    {
        unsigned short* website_size=(unsigned short*)nextptr(&dec, sizeof(unsigned short));
        if(*website_size)
        {
            cd->website=(char*)malloc2(*website_size+1);
            memset(cd->website, 0, *website_size+1);
            memcpy(cd->website, nextptr(&dec, *website_size), *website_size);
        }
    }
    //Unknown string
    if(flags&funknown)
    {
        unsigned short* unknown_size=(unsigned short*)nextptr(&dec, sizeof(unsigned short));
        if(*unknown_size)
        {
            cd->unknown_string=(char*)malloc2(*unknown_size+1);
            memset(cd->unknown_string, 0, *unknown_size+1);
            memcpy(cd->unknown_string, nextptr(&dec, *unknown_size), *unknown_size);
        }
    }
    //Stolen Codes KeyBytes
    cd->stolen_keys_diff=dec-dec_start;
    unsigned char* stolen_size=nextptr(&dec, sizeof(unsigned char));
    if(stolen_size)
    {
        unsigned int total_size=0;
        unsigned char* codes=0;
        unsigned char* temp=0;
        while(*stolen_size)
        {
            if(codes)
            {
                if(temp)
                    free2(temp);
                temp=(unsigned char*)malloc2(total_size);
                memcpy(temp, codes, total_size);
                free2(codes);
            }
            codes=(unsigned char*)malloc2(total_size+*stolen_size+2);
            if(temp)
                memcpy(codes, temp, total_size);
            memcpy(codes+total_size, stolen_size, sizeof(unsigned char));
            memcpy(codes+total_size+1, nextptr(&dec, *stolen_size), *stolen_size);
            total_size+=*stolen_size+1;
            stolen_size=nextptr(&dec, 1);
        }
        if(temp)
            free2(temp);
        if(codes)
            memcpy(codes+total_size, stolen_size, 1); //write last key
        cd->stolen_keys_size=total_size;
        cd->stolen_keys=codes;
    }
    //Intercepted libraries
    unsigned short* libs_size=(unsigned short*)nextptr(&dec, 2);
    if(*libs_size)
    {
        cd->intercepted_libs_size=*libs_size;
        cd->intercepted_libs=(unsigned char*)malloc2(*libs_size);
        memset(cd->intercepted_libs, 0, *libs_size);
        memcpy(cd->intercepted_libs, nextptr(&dec, *libs_size), *libs_size);
    }
    //Certificates
    unsigned char* dec_cert=dec;
    cd->initial_diff=dec-dec_start;
    unsigned int real_size=0;

    nextptr(&dec, 1);
    unsigned char* signature_size=nextptr(&dec, 1);
    while(*signature_size)
    {
        real_size+=(*signature_size)+4+1+1; //chk+lvl+pubsize
        nextptr(&dec, (*signature_size)+4);
        nextptr(&dec, 1);
        signature_size=nextptr(&dec, 1);
    }
    if(real_size)
    {
        cd->raw_data=dec_cert;
        cd->raw_size=real_size;
    }
    else
    {
        cd->raw_data=0;
        cd->raw_size=0;
    }
}

void CT_ParseCerts()
{
    CT_isparsing=true;
    bool something_done=false;
    char log_msg[65536]="";
    char byte_string[256]="";
    CERT_DATA* cd=CT_cert_data;
    HWND hwndDlg=CT_shared;
    HWND list=GetDlgItem(hwndDlg, IDC_LIST_CERT);

    SendMessageA(list, LB_RESETCONTENT, 0, 0); //Reset list

    if(cd->decrypt_seed[0])
        CT_DecryptCerts();
    else
        CT_DecodeCerts();

    //Global Information
    if(cd->first_dw or cd->magic1 or cd->magic2 or cd->salt or cd->projectid or cd->decrypt_seed[0])
    {
        something_done=true;
        CT_AddLogMessage(list, "Global Information:");
        if(cd->timestamp)
        {
            sprintf(log_msg, "   TimeStamp : %.8X", cd->timestamp);
            CT_AddLogMessage(list, log_msg);
        }
        if(cd->first_dw)
        {
            sprintf(log_msg, " First DWORD : %.8X", cd->first_dw);
            CT_AddLogMessage(list, log_msg);
        }
        if(cd->projectid)
        {
            sprintf(log_msg, "  Project ID : %s", cd->projectid);
            CT_AddLogMessage(list, log_msg);
        }
        if(cd->customer_service)
        {
            sprintf(log_msg, " CustService : %s", cd->customer_service);
            CT_AddLogMessage(list, log_msg);
        }
        if(cd->website)
        {
            sprintf(log_msg, "     Website : %s", cd->website);
            CT_AddLogMessage(list, log_msg);
        }
        if(cd->unknown_string)
        {
            sprintf(log_msg, "     Unknown : %s (please report if encountered)", cd->unknown_string);
            CT_AddLogMessage(list, log_msg);
        }
        if(cd->magic1 or cd->magic2)
        {
            sprintf(log_msg, "      Magic1 : %.8X\n      Magic2 : %.4X", cd->magic1, cd->magic2);
            CT_AddLogMessage(list, log_msg);
        }
        if(cd->salt)
        {
            sprintf(log_msg, "        Salt : %.8X", cd->salt);
            CT_AddLogMessage(list, log_msg);
        }
        if(cd->decrypt_seed[0])
        {
            sprintf(log_msg, "  Crypt Seed : %.8X (0x%X, 0x%X, 0x%X, 0x%X)", cd->decrypt_seed[0], cd->decrypt_addvals[0], cd->decrypt_addvals[1], cd->decrypt_addvals[2], cd->decrypt_addvals[3]);
            CT_AddLogMessage(list, log_msg);
        }
        CT_AddLogMessage(list, "");
    }

    //Encrypted certificate containers
    if(cd->encrypted_size and cd->encrypted_data)
    {
        DeleteFileA(CT_szCryptCertFile);
        HANDLE hFile=CreateFileA(CT_szCryptCertFile, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_WRITE, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
        if(hFile==INVALID_HANDLE_VALUE)
            MessageBoxA(hwndDlg, "Failed to create file...", CT_szCryptCertFile, MB_ICONERROR);
        else
        {
            DWORD written=0;
            if(WriteFile(hFile, cd->encrypted_data, cd->encrypted_size, &written, 0))
                something_done=true;
            CloseHandle(hFile);
        }
    }

    //Stolen Keys
    if(cd->stolen_keys)
    {
        DeleteFileA(CT_szStolenKeysRaw);
        HANDLE hFile=CreateFileA(CT_szStolenKeysRaw, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_WRITE, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
        if(hFile==INVALID_HANDLE_VALUE)
            MessageBoxA(hwndDlg, "Failed to create file...", CT_szCryptCertFile, MB_ICONERROR);
        else
        {
            DWORD written=0;
            if(WriteFile(hFile, cd->stolen_keys, cd->stolen_keys_size, &written, 0))
                something_done=true;
            CloseHandle(hFile);
        }
        //TODO: parse stolen keys & write to log file
        //DeleteFileA(CT_szStolenKeysLog);
    }

    //Public certificate information
    int level=0;
    int pub_size=0;
    int cert_num=0;
    unsigned int diff=0;
    unsigned int checksum=0;
    unsigned int md5_pub=0;
    unsigned long hash[4]= {0};
    char section_name[256]="";
    CT_section_name=section_name;

    if(cd->raw_size and cd->raw_data)
    {
        DeleteFileA(CT_szAktLogFile);
        something_done=true;
        if(cd->raw_size and cd->raw_data)
        {
            DeleteFileA(CT_szRawCertFile);
            HANDLE hFile=CreateFileA(CT_szRawCertFile, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_WRITE, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
            if(hFile==INVALID_HANDLE_VALUE)
                MessageBoxA(hwndDlg, "Failed to create file...", CT_szRawCertFile, MB_ICONERROR);
            else
            {
                DWORD written=0;
                WriteFile(hFile, cd->raw_data, cd->raw_size, &written, 0);
                CloseHandle(hFile);
            }
        }
        CT_AddLogMessage(list, "Public Certificate Information:");
        unsigned char* data=cd->raw_data;
        unsigned char* data_end=data+cd->raw_size;
        //data++;
        while(data<data_end)
        {
            //Get certificate level and public size
            level=data[0];
            pub_size=data[1];
            data+=2; //We are done with the two bytes

            sprintf(section_name, "Certificate%d", cert_num);

            //Write to _cert.akt file
            sprintf(log_msg, "%d", level);
            WritePrivateProfileStringA(section_name, "level", log_msg, CT_szAktLogFile);
            if(cd->first_dw or cd->magic1 or cd->magic2 or cd->salt or cd->projectid or cd->initial_diff or cd->decrypt_seed[0])
            {
                sprintf(log_msg, "%.8X", cd->first_dw);
                WritePrivateProfileStringA(section_name, "first_dw", log_msg, CT_szAktLogFile);
                if(cd->initial_diff)
                {
                    sprintf(log_msg, "%X", cd->initial_diff);
                    WritePrivateProfileStringA(section_name, "initial_diff", log_msg, CT_szAktLogFile);
                }
                if(cd->salt)
                {
                    sprintf(log_msg, "%.8X", cd->salt);
                    WritePrivateProfileStringA(section_name, "salt", log_msg, CT_szAktLogFile);
                }
                if(cd->magic1 or cd->magic2)
                {
                    sprintf(log_msg, "%.8X", cd->magic1);
                    WritePrivateProfileStringA(section_name, "magic1", log_msg, CT_szAktLogFile);
                    sprintf(log_msg, "%.4X", cd->magic2);
                    WritePrivateProfileStringA(section_name, "magic2", log_msg, CT_szAktLogFile);
                }
            }

            if(level<4 and level>-1) //Signed V2
                sprintf(log_msg, "  Signed V2 Level %d:", level+1);
            else if(level<20 and level>9) //Signed V3
                sprintf(log_msg, "  Signed V3 Level %d:", level-9);
            else if(level<30 and level>19) //Short V3
                sprintf(log_msg, "  Short V3 Level %d:", level-19);
            else
                strcpy(log_msg, "  Level unknown...");
            CT_AddLogMessage(list, log_msg);

            //Get the checksum
            memcpy(&checksum, data, 4);
            data+=4; //We have had the checksum
            sprintf(log_msg, "    Chk : %.8X", checksum);
            CT_AddLogMessage(list, log_msg);

            //Write to _cert.akt file
            sprintf(log_msg, "%.8X", checksum);
            WritePrivateProfileStringA(section_name, "chk", log_msg, CT_szAktLogFile);

            //Calculate public MD5 dword
            memset(byte_string, 0, pub_size);
            for(int i=0; i<pub_size; i++) //Reverse buffer
                byte_string[pub_size-i-1]=data[i];
            md5(hash, byte_string, pub_size); //Hash
            md5_pub=hash[0]^hash[1]^hash[2]^hash[3]; //Xor hash result together

            //Write to _cert.akt file
            sprintf(log_msg, "%.8X", md5_pub);
            WritePrivateProfileStringA(section_name, "md5", log_msg, CT_szAktLogFile);

            if(CT_brute and !CT_brute_nosym)
            {
                //Fill the SymVerify struct
                if(CT_brute_symverify)
                {
                    CT_current_brute=(BRUTE_DATA*)malloc2(sizeof(BRUTE_DATA));
                    memset(CT_current_brute, 0, sizeof(BRUTE_DATA));
                    CT_current_brute->encrypted_data=cd->encrypted_data;
                    CT_current_brute->encrypted_size=cd->encrypted_size;
                    CT_current_brute->magic1=cd->magic1;
                    CT_current_brute->magic2=cd->magic2;
                    if(!cd->zero_md5_symverify and level>19) //v5.xx and v6.xx have zero and Signed keys too
                        CT_current_brute->md5=md5_pub;
                }

                //Setup brute options
                int alg=0;
                if(cd->salt)
                    alg=1;
                hash_list chklist= {0};
                chklist.count=1;
                chklist.hash[0]=checksum;
                CT_total_sym_found=0;
                BruteSetCallbacks(cbBrutePrintFound, cbBruteProgess, cbBruteError);

                //Show brute force interface
                ShowWindow(GetDlgItem(hwndDlg, IDC_BTN_PAUSE), 1);
                ShowWindow(GetDlgItem(hwndDlg, IDC_STC_STATUS), 1);
                ShowWindow(GetDlgItem(hwndDlg, IDC_PROGRESS_BRUTE), 1);

                //Start brute force
                BruteStart(alg, &chklist, 0, 0xFFFFFFFF, cd->salt);

                if(CT_brute_symverify)
                {
                    if(CT_current_brute)
                        free2(CT_current_brute);
                    CT_current_brute=0;
                }

                //Hide brute force interface
                ShowWindow(GetDlgItem(hwndDlg, IDC_BTN_PAUSE), 0);
                ShowWindow(GetDlgItem(hwndDlg, IDC_STC_STATUS), 0);
                ShowWindow(GetDlgItem(hwndDlg, IDC_PROGRESS_BRUTE), 0);

                //Write number of found symmetrics
                sprintf(log_msg, "%d", CT_total_sym_found);
                WritePrivateProfileStringA(section_name, "found_sym", log_msg, CT_szAktLogFile);
            }

            //Log the type
            byte_string[0]=0;
            if(level==29) //ECDSA
            {
                diff=data-cd->raw_data+cd->initial_diff;

                //Write to _cert.akt file
                sprintf(log_msg, "%X", diff);
                WritePrivateProfileStringA(section_name, "diff", log_msg, CT_szAktLogFile);

                //Write to _cert.akt file
                if(cd->decrypt_seed[0])
                {
                    unsigned int seed=cd->decrypt_seed[2];
                    for(int i=0; i<data-cd->raw_data; i++)
                        seed=CT_NextSeed(seed);
                    sprintf(log_msg, "%X", cd->projectid_diff);
                    WritePrivateProfileStringA(section_name, "projectid_diff", log_msg, CT_szAktLogFile);
                    sprintf(log_msg, "%.8X", cd->decrypt_seed[1]);
                    WritePrivateProfileStringA(section_name, "seed1", log_msg, CT_szAktLogFile);
                    sprintf(log_msg, "%.8X", seed);
                    WritePrivateProfileStringA(section_name, "seed2", log_msg, CT_szAktLogFile);
                }

                //Write to _cert.akt file
                memset(log_msg, 0, 256);
                strncpy(log_msg, (const char*)data, pub_size);
                WritePrivateProfileStringA(section_name, "pub", log_msg, CT_szAktLogFile);

                for(int i=0,j=0,k=0; i<pub_size; i++)
                {
                    if(data[i]!=',')
                        k+=sprintf(byte_string+k, "%c", data[i]);
                    else
                    {
                        if(!j)
                            sprintf(log_msg, "  BaseP : %s (Size=%X, Diff=%X, MD5=%.8X)", byte_string, pub_size, diff, md5_pub);
                        else
                            sprintf(log_msg, "  Pub.X : %s", byte_string);
                        CT_AddLogMessage(list, log_msg);
                        j++;
                        k=0;
                    }
                }
                sprintf(log_msg, "  Pub.Y : %s", byte_string);
                CT_AddLogMessage(list, log_msg);
            }
            else //ElGamal
            {
                ByteArrayToString(data, byte_string, pub_size, 256);
                bool add_one=false;
                if(byte_string[0]=='0' and byte_string[1])
                    add_one=true;

                //Write to _cert.akt file
                WritePrivateProfileStringA(section_name, "pub", byte_string+add_one, CT_szAktLogFile);
                if(level>19)
                    sprintf(log_msg, "      Y : %s (MD5=%.8X)", byte_string+add_one, md5_pub);
                else
                    sprintf(log_msg, "      Y : %s", byte_string+add_one);
                CT_AddLogMessage(list, log_msg);

                if(CT_brute and CT_brute_dlp_initialized)
                {
                    char pvt_text[50]="";
                    UpdateKeys(level, byte_string+add_one);
                    SolveDlp(pvt_text);
                    sprintf(log_msg, "    Pvt : %s", pvt_text);
                    CT_AddLogMessage(list, log_msg);
                    WritePrivateProfileStringA(section_name, "pvt", pvt_text, CT_szAktLogFile);
                }
            }
            CT_AddLogMessage(list, "");
            data+=pub_size;
            cert_num++;
        }
        if(!cd->intercepted_libs)
        {
            //Remove the last (always empty) line
            int listcount=SendMessageA(list, LB_GETCOUNT, 0, 0);
            SendMessageA(list, LB_DELETESTRING, listcount-1, 0);
            SendMessageA(list, LB_SETCURSEL, listcount-2, 0);
        }
    }

    //Intercepted libraries
    if(cd->intercepted_libs)
    {
        something_done=true;
        char currentlib[256]="";
        int j=0;
        j+=sprintf(log_msg, "Intercepted Libraries:\n");
        for(unsigned int i=0; i<cd->intercepted_libs_size; i++)
        {
            if(!cd->intercepted_libs[i])
                break;
            i+=sprintf(currentlib, "%s", (const char*)cd->intercepted_libs+i);
            j+=sprintf(log_msg+j, "  %s\n", currentlib);
        }
        log_msg[strlen(log_msg)-1]=0;
        CT_AddLogMessage(list, log_msg);
        CT_AddLogMessage(0, "");
        //Remove the last (always empty) line
        //int listcount=SendMessageA(list, LB_GETCOUNT, 0, 0);
        //SendMessageA(list, LB_DELETESTRING, listcount-1, 0);
        //SendMessageA(list, LB_SETCURSEL, listcount-2, 0);
    }

    if(!something_done)
        return;
    //Elapsed time
    int hour=0;
    int min=0;
    int sec=0;
    int msec=0;
    unsigned int time2=GetTickCount();
    if((time2-CT_time1)>=3600000)
        hour=(((time2-CT_time1)/1000)/60)/60;
    if((time2-CT_time1)>=60000)
        min=(((time2-CT_time1)/1000)/60)-(hour*60);
    if((time2-CT_time1)>=1000)
        sec=((time2-CT_time1)/1000)-((((time2-CT_time1)/1000)/60)*60);
    msec=(time2-CT_time1)-(((time2-CT_time1)/1000)*1000);
    sprintf(log_msg, "  Elapsed Time: %02dh %02dm %02ds %03dms", hour, min, sec, msec);
    CT_AddLogMessage(0, log_msg);
    CT_isparsing=false;
    //Enable controls
    EnableWindow(GetDlgItem(hwndDlg, IDC_BTN_START), 1);

    if(CT_brute and !CT_brute_nosym and CT_brute_shutdown)
    {
        STARTUPINFO si;
        PROCESS_INFORMATION pi;
        memset(&si, 0, sizeof(si));
        memset(&pi, 0, sizeof(pi));
        si.cb = sizeof(si);
        if(!CreateProcess(0, (char*)"shutdown -s -t 60 -f", 0, 0, TRUE, CREATE_DEFAULT_ERROR_MODE, 0, 0, &si, &pi))
            system("start shutdown -s -t 100 -f");
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}
