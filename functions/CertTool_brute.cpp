#include "CertTool_brute.h"

///Superglobal
HINSTANCE hBrute;
BRUTESTART BruteStart;
SETCALLBACKS BruteSetCallbacks;
BRUTESTOP BruteStop;
BRUTESETTINGS BruteSettings;

//Dlp brute
HINSTANCE hBruteDlp;
UPDATEKEYS UpdateKeys;
SOLVEDLP SolveDlp;

int CT_total_sym_found = 0; //number of symmetric keys found
char* CT_section_name = 0; //current INI (.akt) section name
bool CT_brute_is_paused = false; //is_paused flag
bool CT_brute_shutdown = false; //shutdown after bruting is finished?
bool CT_brute = false; //Solve certs?
bool CT_brute_initialized = false; //initialized sym brute lib?
bool CT_brute_dlp_initialized = false; //initialized dlp brute lib?
bool CT_brute_nosym = false; //Skip sym solving?
bool CT_brute_symverify = false; //verify symmetric before taking it as valid?

BRUTE_DATA* CT_current_brute;

bool InitializeSymBruteLibrary(HWND hwndDlg)
{
    if(hBrute)
        FreeLibrary(hBrute);
    hBrute = LoadLibraryA("brute_sym_prvt.dll");
    if(!hBrute)
        hBrute = LoadLibraryA("brute_sym.dll");
    if(hBrute)
    {
        BruteStart = (BRUTESTART)GetProcAddress(hBrute, "BruteStart");
        BruteSetCallbacks = (SETCALLBACKS)GetProcAddress(hBrute, "SetCallbacks");
        BruteStop = (BRUTESTOP)GetProcAddress(hBrute, "BruteStop");
        BruteSettings = (BRUTESETTINGS)GetProcAddress(hBrute, "BruteSettings");
        if(BruteStart and BruteSetCallbacks and BruteStop and BruteSettings)
            return true;
        else
        {
            MessageBoxA(hwndDlg, "Please consider fixing brute_sym.dll", "Export problem", MB_ICONERROR);
            FreeLibrary(hBrute);
            return false;
        }
    }
    return false;
}

bool InitializeDlpBruteLibrary(HWND hwndDlg)
{
    if(hBruteDlp)
        FreeLibrary(hBruteDlp);
    hBruteDlp = LoadLibraryA("brute_dlp.dll");
    if(hBruteDlp)
    {
        UpdateKeys = (UPDATEKEYS)GetProcAddress(hBruteDlp, "UpdateKeys");
        SolveDlp = (SOLVEDLP)GetProcAddress(hBruteDlp, "SolveDLP");
        if(UpdateKeys and SolveDlp)
            return true;
        else
        {
            MessageBoxA(hwndDlg, "Please consider fixing brute_dlp.dll", "Export problem", MB_ICONERROR);
            FreeLibrary(hBruteDlp);
            return false;
        }
    }
    return false;
}

void cbBruteError(const char* error_msg)
{
    BruteStop();
    MessageBoxA(CT_shared, error_msg, "Error while bruting...", MB_ICONERROR);
}

void cbBrutePrintFound(unsigned long hash, unsigned long key)
{
    BRUTE_DATA* cb = CT_current_brute;
    if(CT_brute_symverify and cb and cb->encrypted_data and cb->encrypted_size)
    {
        if(!MSC_VR_brute(cb->magic1, cb->magic2, (unsigned int)key, cb->md5, cb->encrypted_data, cb->encrypted_size))
        {
            //TODO: Log found symmetrics to dump file
            return;
        }
        else
            BruteStop();
    }

    char temp[256] = "";
    char temp2[256] = "";
    if(!CT_total_sym_found)
        sprintf(temp, "    Sym : %.8X", (unsigned int)key);
    else
        sprintf(temp, "          %.8X", (unsigned int)key);
    CT_total_sym_found++;

    //Write to .log and .akt files
    CT_AddToLog(GetDlgItem(CT_shared, IDC_LIST_CERT), temp);
    sprintf(temp, "sym%d", CT_total_sym_found);
    sprintf(temp2, "%.8X", (unsigned int)key);
    WritePrivateProfileStringA(CT_section_name, temp, temp2, CT_szAktLogFile);
}

void cbBruteProgess(double checked, double all, time_t* start)
{
    //Calculate the needed values
    double pdone = (checked / all) * 100.0;
    double elaps = (double)(time(0) - *start);
    double estim = ((100.0 - pdone) / (pdone / elaps));
    double speed = checked / elaps;
    int pdone_int = (int)pdone;
    SendDlgItemMessageA(CT_shared, IDC_PROGRESS_BRUTE, PBM_SETPOS, pdone_int, 0); //Set progress bar

    //Set log information
    char log_msg[50] = "";
    if(estim > 86400)
        sprintf(log_msg, "%-.3f%%, %-.2f d, %-.0f h/s", pdone, estim / 86400.0, speed);
    else if(estim > 3600)
        sprintf(log_msg, "%-.3f%%, %-.2f h, %-.0f h/s", pdone, estim / 3600.0, speed);
    else if(estim > 60)
        sprintf(log_msg, "%-.3f%%, %-.2f m, %-.0f h/s", pdone, estim / 60.0, speed);
    else
        sprintf(log_msg, "%-.3f%%, %-.2f s, %-.0f h/s", pdone, estim, speed);
    SetDlgItemTextA(CT_shared, IDC_STC_STATUS, log_msg);

    //Check if we should halt the bruting process
    bool update_time = CT_brute_is_paused;
    time_t pause = time(0);
    while(CT_brute_is_paused)
        Sleep(100);
    if(update_time)
        *start += (time(0) - pause);
}
