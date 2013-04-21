#include "CertTool_parser.h"

//Superglobal variables
bool CT_created_log=false; //bool for if our log was created
bool CT_isparsing=false; //Is parsing certificate info?

void CT_AddToLog(HWND list, const char* text)
{
    //Add to the listbox
    if(list)
    {
        int sel=SendMessageA(list, LB_ADDSTRING, 0, (LPARAM)text);
        SendMessageA(list, LB_SETCURSEL, sel, 0);
    }

    //Add to the logfile
    if(CT_logtofile)
    {
        int len=strlen(text)+3;
        char* new_text=(char*)malloc(len);
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
                    free(new_text);
                    TerminateThread(GetCurrentThread(), 0); return;
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
        free(new_text);
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
            current_add[0]=0;
        }
    }
    CT_AddToLog(list, current_add);
}

void CT_ParseCerts()
{
    CT_isparsing=true;
    bool something_done=false;
    char log_msg[256]="";
    char byte_string[256]="";
    CERT_DATA* cd=CT_cert_data;
    HWND hwndDlg=CT_shared;
    HWND list=GetDlgItem(hwndDlg, IDC_LIST_CERT);

    SendMessageA(list, LB_RESETCONTENT, 0, 0); //Reset list

    if(cd->decrypt_seed[0])
        CT_DecryptCerts();

    //Global Information
    if(cd->first_dw or cd->magic1 or cd->magic2 or cd->salt or cd->projectid or cd->decrypt_seed[0])
    {
        something_done=true;
        CT_AddLogMessage(list, "Global Information:");
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
                    CT_current_brute=(BRUTE_DATA*)malloc(sizeof(BRUTE_DATA));
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
                        free(CT_current_brute);
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
                        byte_string[0]=0;
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
        //Remove the last (always empty) line
        int listcount=SendMessageA(list, LB_GETCOUNT, 0, 0);
        SendMessageA(list, LB_DELETESTRING, listcount-1, 0);
        SendMessageA(list, LB_SETCURSEL, listcount-2, 0);
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
