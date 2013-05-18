#include "akt_exception.h"

bool init_done=false;
int handle_exceptions=0;
char* program_dir;
CT_DATA* cert_data;
STOPDEBUG StopDebug;
HWND hwndDlg;

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
    MessageBeep(MB_ICONINFORMATION);
}

LONG CALLBACK ExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
    if(!handle_exceptions)
        return EXCEPTION_CONTINUE_SEARCH;
    char msg[256]="";
    sprintf(msg, "Exception Address: %.8X", (unsigned int)ExceptionInfo->ExceptionRecord->ExceptionAddress);
    MessageBoxA(hwndDlg, msg, "Exception Caught, please report!", MB_ICONINFORMATION);
    /*char log_message[4096]="";
    char log_filename[256]="";
    char log_string[256]="";
    char data_string[1024]="";
    char raw_data_file[256]="";
    char encrypted_data_file[256]="";
    unsigned int addr=(unsigned int)ExceptionInfo->ExceptionRecord->ExceptionAddress;
    SYSTEMTIME st= {0};
    GetLocalTime(&st);
    sprintf(log_string, "exception_%.4d%.2d%.2d_%.2d%.2d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);
    sprintf(log_filename, "%s\\%s.log", program_dir, log_string);

    sprintf(data_string, "Exception Address: %.8X\r\n\r\n",addr);
    strcpy(log_message, data_string);

    if(cert_data)
    {
        sprintf(data_string,
                "Data stucture:\r\n%.8X (raw_data)\r\n%.8X (encrypted_data)\r\n%.8X (projectid)\r\n\r\n%.8X (inital diff)\r\n%.8X (raw_size)\r\n%.8X (encrypted_size)\r\n%.8X (first_dw)\r\n%.8X (magic1)\r\n%.8X (magic2)\r\n%.8X (salt)\r\n%.8X (decrypt_seed1)\r\n%.8X (decrypt_seed2)\r\n%.8X (decrypt_seed3)\r\n%.8X (decrypt_addvals1)\r\n%.8X (decrypt_addvals2)\r\n%.8X (decrypt_addvals3)\r\n%.8X (decrypt_addvals4)\r\n%.8X (checksumv8)\r\n%.8X (zero_md5_symverify)\r\n\r\n",
                (unsigned int)cert_data->raw_data,
                (unsigned int)cert_data->encrypted_data,
                (unsigned int)cert_data->projectid,
                cert_data->initial_diff,
                cert_data->raw_size,
                cert_data->encrypted_size,
                cert_data->first_dw,
                cert_data->magic1,
                cert_data->magic2,
                cert_data->salt,
                cert_data->decrypt_seed[0],
                cert_data->decrypt_seed[1],
                cert_data->decrypt_seed[2],
                cert_data->decrypt_addvals[0],
                cert_data->decrypt_addvals[1],
                cert_data->decrypt_addvals[2],
                cert_data->decrypt_addvals[3],
                (unsigned int)cert_data->checksumv8,
                (unsigned int)cert_data->zero_md5_symverify);
        strcat(log_message, data_string);
        if(cert_data->projectid)
        {
            sprintf(data_string, "Project ID:\r\n%s\r\n\r\n", cert_data->projectid);
            strcat(log_message, data_string);
        }
        if(cert_data->raw_data)
        {
            sprintf(raw_data_file, "%s\\%s_raw_data.bin", program_dir, log_string);
            HANDLE hFile=CreateFileA(raw_data_file, GENERIC_ALL, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
            if(hFile!=INVALID_HANDLE_VALUE)
            {
                DWORD written=0;
                WriteFile(hFile, cert_data->raw_data, cert_data->raw_size, &written, 0);
                CloseHandle(hFile);
                sprintf(data_string, "Dumped raw_data to file:\r\n%s_raw_data.bin\r\n\r\n", log_string);
                strcat(log_message, data_string);
            }
        }
        if(cert_data->encrypted_data)
        {
            sprintf(encrypted_data_file, "%s\\%s_encrypted_data.bin", program_dir, log_string);
            HANDLE hFile=CreateFileA(encrypted_data_file, GENERIC_ALL, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
            if(hFile!=INVALID_HANDLE_VALUE)
            {
                DWORD written=0;
                WriteFile(hFile, cert_data->encrypted_data, cert_data->encrypted_size, &written, 0);
                CloseHandle(hFile);
                sprintf(data_string, "Dumped encrypted_data to file:\r\n%s_encrypted_data.bin\r\n\r\n", log_string);
                strcat(log_message, data_string);
            }
        }
    }
    strcat(log_message, "End of report.");
    HANDLE hFile=CreateFileA(log_filename, GENERIC_ALL, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    if(hFile!=INVALID_HANDLE_VALUE)
    {
        DWORD written=0;
        WriteFile(hFile, log_message, strlen(log_message), &written, 0);
        CloseHandle(hFile);
        sprintf(log_message, "Read %s.log for details", log_string);
        MessageBoxA(hwndDlg, log_message, "Exception occurred!", MB_ICONERROR|MB_SYSTEMMODAL);
    }
    else
    {
        if(MessageBoxA(hwndDlg, "Failed to write log file, do you want to copy it to clipboard?", "Question", MB_ICONQUESTION|MB_SYSTEMMODAL|MB_YESNO)==IDYES)
            CopyToClipboard(log_message);
    }*/
    if(StopDebug)
        StopDebug();
    return EXCEPTION_CONTINUE_SEARCH;
}

void DLL_EXPORT InitVariables(char* var0, CT_DATA* var1, STOPDEBUG var2, int var3, HWND var4)
{
    program_dir=var0;
    cert_data=var1;
    StopDebug=var2;
    handle_exceptions=var3;
    hwndDlg=var4;
}

void DLL_EXPORT AddExceptionHandler()
{
    AddVectoredExceptionHandler(0, ExceptionHandler);
}

void DLL_EXPORT RemoveExceptionHandler()
{
    RemoveVectoredExceptionHandler((void*)ExceptionHandler);
}

extern "C" BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if(!init_done)
    {
        AddExceptionHandler();
        init_done=true;
    }
    return TRUE;
}
