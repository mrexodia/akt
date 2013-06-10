/**
 * @file    TEArmaLicenseRemoval.cpp
 * @brief   This library removes all license data used by Armadillo protected target given in parameter.   @n
 *          It has a similar behavior that the "Clear Local Keys For This Project" button of SoftwarePasseport. @n
 *          @n
 *          It is based on two functions : TEGetArmaLicenseData and TERemoveArmaLicenseData. @n
 *          @n
 *          TEGetArmaLicenseData works in the following manner: @n
 *          1. A breakpoint is set on the OpenMutexA API @n
 *          2. On the first hit of the breakpoint. A mutex is created with the same name.
 *          3. Wait until Armadillo call OpenMutexA with the SIMULATEEXPIRED string in parameter @n
 *          4. Set breakpoints on RegOpenKeyExA, RegQueryValueExA and CreateFileA APIs @n
 *          5. Log calls to RegOpenKeyExA, RegQueryValueExA and CreateFileA APIs until one of the following markers happen:
 *          "\\.\SuperBpmDev0", "\\.\SuperBPMDev0", "\\.\SICE", "\\.\NTICE", "\\.\SIWDEBUG", "\\.\SIWVID". @n
 *          6. Filter the log and keep only registry keys and files that exist and that are linked to license @n
 *          7. Add all existing registry keys and files in the list given in parameter of the function TEGetArmaLicenseData. @n
 *          8. Done @n
 *          @n
 *
 * @author  Sigma
 * @version 0.2
 * @date    18 May 2013
 */

#include "LicenceRemoval_debugger.h"


/**************************************************************************
 * 							Global Variables
 **************************************************************************/
static uint32_t    mImageBase     =0;
static uint32_t    mEntryPoint    =0;
static uint32_t    mSizeOfImage   =0;
static HANDLE      mHandle;
static char*       mFileName      =0;

static RegOpenKeyExAContext_t       	mRegOpenKeyExAContext;
static RegQueryValueExAContext_t    	mRegQueryValueExAContext;
static CreateFileAContext_t         	mCreateFileAContext;
static vector<APIContextContainer_t>	mAPIContextContainerList;
static vector<ArmaLicenseEntry_t>*   	mArmaLicenseEntryPtr;
static uint32_t                     	mMutexCallCount=0;
static unsigned int 					mIsGreaterThanArma940=0;

HWND hwndDlg;

/**************************************************************************
 *                              Main
 **************************************************************************/
/**
 * @brief       Thread function, calls LR_GetArmaLicenseData.
 *
 * @param[in]   parstruct      Pointer to a parameter structure
 *
 * @return      Zero.
 */
DWORD WINAPI LR_GetArmaLicenseDataThread(void* parstruct)
{
    LRPARSTRUCT* par=(LRPARSTRUCT*)parstruct;
    bool* isdebugging=par->isdebugging;
    *isdebugging=true;
    hwndDlg=par->hwndDlg;
    LR_GetArmaLicenseData(par->parFileName, par->parArmaLicenseEntryListPtr);
    par->filllist(par->list, par->parArmaLicenseEntryListPtr);
    *isdebugging=false;
    free2(par);
    return 0;
}

/**
 * @brief       This function analyzes dynamically the target given in parameter and makes a list
 *              of all registry keys and files that are used for license data.
 *
 * @param[in]   parFileName                     Path of the file to analyse.
 * @param[out]  parArmaLicenseEntryListPtr      Pointer to a list of ArmaLicenseEntry_t
 *
 * @return      Nothing.
 */
void LR_GetArmaLicenseData(char parFileName[], vector<ArmaLicenseEntry_t>* parArmaLicenseEntryListPtr)
{
    FILE_STATUS_INFO wFileStatus;
    LPPROCESS_INFORMATION wProcessInfo=0;

    mArmaLicenseEntryPtr=parArmaLicenseEntryListPtr;
    mFileName=parFileName;

    // Check if the file to debug has a valid PE
    if(IsPE32FileValidEx(parFileName, UE_DEPTH_DEEP, &wFileStatus)==false)
    {
        LR_Error((char*)"Invalid PE.");
        return;
    }

    printf("Start\n");

    // Get PE Data (ImageBase and OriginalEntryPoint)
    mImageBase=(uint32_t)GetPE32Data(parFileName, 0, UE_IMAGEBASE);
    printf("mImageBase : 0x%08X\n", mImageBase);

    mEntryPoint=(uint32_t)GetPE32Data(parFileName, 0, UE_OEP);
    printf("mEntryPoint : 0x%08X\n", mEntryPoint);

    mSizeOfImage=(uint32_t)GetPE32Data(parFileName, 0, UE_SIZEOFIMAGE);
    printf("mSizeOfImage : 0x%08X\n", mSizeOfImage);

    // Initialize the debugged process
    wProcessInfo=(LPPROCESS_INFORMATION)InitDebug(parFileName, 0, 0);
    mHandle=wProcessInfo->hProcess;
    printf("mHandle : 0x%08X\n", (int32_t)mHandle);

    // Set a breakpint on the entry point
    SetBPX(mImageBase + mEntryPoint, UE_SINGLESHOOT|UE_BREAKPOINT_TYPE_INT3, (void*)LR_EntryPointArma960Callback);

    // Hide Debugger
    FixIsDebuggerPresent(mHandle, true);
    //HideDebugger(mHandle, UE_HIDE_BASIC);

    // Start debugging
    DebugLoop();

    // Final Processing
    LR_ProcessAPIContextLog();
}


/**
 * @brief       This function is the callback for the entry point.
 *
 * @return      Nothing.
 */
void LR_EntryPointArma960Callback()
{
    printf("Entry Point BP hit\n");

    // Clear the mutex call counter
    mMutexCallCount=0;

    // Set a single shoot breakpoint on the OpenMutexA API
    if(SetAPIBreakPoint((char*)"kernel32.dll", (char*)"OpenMutexA", UE_BREAKPOINT|UE_BREAKPOINT_TYPE_LONG_INT3, UE_APISTART, (void*)LR_OpenMutexAArma960Callback)==false)
        printf("OpenMutexA breakpoint has not been set\n");

    // Set a single shoot breakpoint on the VirtualProtect API
    if(SetAPIBreakPoint((char*)"kernel32.dll", (char*)"VirtualProtect", UE_BREAKPOINT|UE_BREAKPOINT_TYPE_LONG_INT3, UE_APISTART, (void*)LR_VirtualProtectCallback)==false)
        printf("VirtualProtect breakpoint has not been set\n");
}


/**
 * @brief       This callback is called when the breakpoint on VirtualProtect hits. In this library this callback is used to retrieve
 * 				the timestamp of the security.dll (Date and time of link) in order to deduce the Armadillo version of the file.
 *
 * @return      Nothing.
 */
void LR_VirtualProtectCallback()
{
    unsigned int wTimeStamp;
    unsigned int wSecurityDLLCodeBaseAddr=0;
    //unsigned int wSecurityDLLCodeSize=0;
    unsigned char* wHeaderCode=(unsigned char*)malloc2(0x1000);
    IMAGE_DOS_HEADER *wDosHeaderPtr;
    IMAGE_NT_HEADERS *wNTHeaderPtr;

    // Get parameter from VirtualProtect (Code Address)
    wSecurityDLLCodeBaseAddr=GetFunctionParameter(mHandle, UE_FUNCTION_STDCALL, 1, UE_PARAMETER_DWORD);

    ReadProcessMemory(mHandle, (void*)(wSecurityDLLCodeBaseAddr - 0x1000), wHeaderCode, 0x1000, 0);

    wDosHeaderPtr=(IMAGE_DOS_HEADER*)((DWORD)wHeaderCode);
    wNTHeaderPtr=(IMAGE_NT_HEADERS*)((DWORD)wHeaderCode + wDosHeaderPtr->e_lfanew);

    wTimeStamp=wNTHeaderPtr->FileHeader.TimeDateStamp;

    if(wTimeStamp>0x50700000) // 0x50624580=9.40 26-09-2012
    {
        mIsGreaterThanArma940=1;
    }

    printf("Security.dll TimeStamp : %d\n", wTimeStamp);

    free2(wHeaderCode);

    DeleteAPIBreakPoint((char*)"kernel32.dll", (char*)"VirtualProtect", UE_APISTART);
}


/**
 * @brief       This callback is called when the breakpoint on OpenMutexA hits. When the SIMULATEEXPIRED string is looked,
 *              breakpoints are set on RegOpenKeyExA, RegQueryValueExA and CreateFileA APIs.
 *
 * @return      Nothing.
 */
void LR_OpenMutexAArma960Callback()
{
    uint32_t wMutexNameAddr;
    int8_t wMutexNameString[32];
    uint32_t wMutexNameLength;

    printf("OpenMutexA BP hit\n");

    mMutexCallCount++;

    // Retrieve the third parameter of the OpenMutexA API that is the name of the mutex
    wMutexNameAddr=GetFunctionParameter(mHandle, UE_FUNCTION_STDCALL, 3, UE_PARAMETER_DWORD);
    printf("wMutexNameAddr : 0x%08X\n", wMutexNameAddr);

    // Copy the mutex name from the protected target
    GetRemoteString(mHandle, (void*)(wMutexNameAddr), (void*)wMutexNameString, 32);
    printf("wMutexNameString : %s\n", &wMutexNameString[0]);

    // Get the length of the mutex name
    wMutexNameLength=strlen((const char*)wMutexNameString);

    if(mMutexCallCount==1)
    {
        CreateMutexA(0, 0, (const CHAR*)wMutexNameString);
    }
    else
    {
        // If the name length is greater than 16 characters, it could be the SIMULATEEXPIRED mutex
        if(wMutexNameLength>16)
        {
            if(!strcmp((const char*)(wMutexNameString + wMutexNameLength - 16), (const char*)":SIMULATEEXPIRED"))
            {
                // Set a breakpoint on the start of RegOpenKeyExA API
                if(SetAPIBreakPoint((char*)"Advapi32.dll", (char*)"RegOpenKeyExA", UE_BREAKPOINT|UE_BREAKPOINT_TYPE_LONG_INT3, UE_APISTART, (void*)LR_RegOpenKeyExAStartArma960BPCallback)==false)
                    printf("RegOpenKeyExA start breakpoint has not been set\n");

                // Set a breakpoint on the start of the RegQueryValueExA API
                if(SetAPIBreakPoint((char*)"Advapi32.dll", (char*)"RegQueryValueExA", UE_BREAKPOINT|UE_BREAKPOINT_TYPE_LONG_INT3, UE_APISTART, (void*)LR_RegQueryValueExAStartArma960BPCallback)==false)
                    printf("RegQueryValueExA start breakpoint has not been set\n");

                // Set a breakpoint on the start of the CreateFileA API
                if(SetAPIBreakPoint((char*)"Kernel32.dll", (char*)"CreateFileA", UE_BREAKPOINT|UE_BREAKPOINT_TYPE_LONG_INT3, UE_APISTART, (void*)LR_CreateFileAStartArma960BPCallback)==false)
                    printf("CreateFileA start breakpoint has not been set\n");
            }
        }

        mAPIContextContainerList.clear();
    }
}


/**
 * @brief       This callback is called when the breakpoint on RegOpenKeyExA hits. API context is logged.
 *
 * @return      Nothing.
 */
void LR_RegOpenKeyExAStartArma960BPCallback()
{
    uint32_t wHKey;
    uint32_t wSubKeyPtr;
    int8_t wSubKeyString[0x100];
    uint32_t wAccess;
    uint32_t wResultHandle;
    APIContextContainer_t wAPIContextContainer;

    printf("RegOpenKeyExA start BP hit\n");

    // Retrieve the first parameter of the RegOpenKeyEx API that is the key handle
    wHKey=GetFunctionParameter(mHandle, UE_FUNCTION_STDCALL, 1, UE_PARAMETER_DWORD);
    printf("wHKey : 0x%08X\n", wHKey);

    // Retrieve the second parameter of the RegOpenKeyEx API that is a pointer to the subkey string
    wSubKeyPtr=GetFunctionParameter(mHandle, UE_FUNCTION_STDCALL, 2, UE_PARAMETER_DWORD);
    printf("wSubKeyPtr : 0x%08X\n", wSubKeyPtr);
    GetRemoteString(mHandle, (LPVOID)wSubKeyPtr, (LPVOID)wSubKeyString, 0x100);
    printf("wSubKeyString : %s\n", wSubKeyString);

    // Retrieve the fourth parameter of the RegOpenKeyEx API that is the acess attribute
    wAccess=GetFunctionParameter(mHandle, UE_FUNCTION_STDCALL, 4, UE_PARAMETER_DWORD);
    printf("wAccess : 0x%08X\n", wAccess);

    // Retrieve the fourth parameter of the RegOpenKeyEx API that is the acess attribute
    wResultHandle=GetFunctionParameter(mHandle, UE_FUNCTION_STDCALL, 5, UE_PARAMETER_DWORD);
    printf("wResultHandle : 0x%08X\n", wResultHandle);

    // Fill the context of the current API call
    mRegOpenKeyExAContext.hKey=(uint32_t)wHKey;
    mRegOpenKeyExAContext.subKeyStr=string((const char*)wSubKeyString);
    mRegOpenKeyExAContext.access=(uint32_t)wAccess;
    mRegOpenKeyExAContext.hkResult=(uint32_t)0;

    wAPIContextContainer.APIType=REG_OPEN_KEY_EX_A_CONTEXT;
    wAPIContextContainer.RegOpenKeyExAContext=mRegOpenKeyExAContext;

    mAPIContextContainerList.push_back(wAPIContextContainer);
}


/**
 * @brief       This callback is called when the breakpoint on RegQueryValueExA hits. API context is logged.
 *
 * @return      Nothing.
 */
void LR_RegQueryValueExAStartArma960BPCallback()
{
    uint32_t wHKey;
    uint32_t wValueKeyPtr;
    int8_t wValueKeyString[0x100];
    APIContextContainer_t wAPIContextContainer;

    printf("RegQueryValueExA start BP hit\n");

    // Retrieve the first parameter of the RegQueryValueExA API that is the key handle
    wHKey=GetFunctionParameter(mHandle, UE_FUNCTION_STDCALL, 1, UE_PARAMETER_DWORD);
    printf("wHKey : 0x%08X\n", wHKey);

    // Retrieve the second parameter of the RegQueryValueExA API that is a pointer to the value name string
    wValueKeyPtr=GetFunctionParameter(mHandle, UE_FUNCTION_STDCALL, 2, UE_PARAMETER_DWORD);
    printf("wValueKeyPtr : 0x%08X\n", wValueKeyPtr);
    GetRemoteString(mHandle, (LPVOID)wValueKeyPtr, (LPVOID)wValueKeyString, 0x100);
    printf("wValueKeyString : %s\n", wValueKeyString);

    // Fill the context of the current API call
    mRegQueryValueExAContext.hKey=(uint32_t)wHKey;
    mRegQueryValueExAContext.valueNameStr=string((const char*)wValueKeyString);

    wAPIContextContainer.APIType=REG_QUERY_VALUE_EX_A_CONTEXT;
    wAPIContextContainer.RegQueryValueExAContext=mRegQueryValueExAContext;

    mAPIContextContainerList.push_back(wAPIContextContainer);
}


/**
 * @brief       This callback is called when the breakpoint on CreateFileA hits.@n
 *              API context is logged.@n
 *              When the end marker ("\\.\SuperBpmDev0", "\\.\SuperBPMDev0", "\\.\SICE", "\\.\NTICE", "\\.\SIWDEBUG", "\\.\SIWVID") occurs,
 *              the right filtering function is called accroding to the Armadillo version that is checked before.@n
 *              Finally, existing registry keys and files are added to the list given in parameter.
 *
 * @return      Nothing.
 */
void LR_CreateFileAStartArma960BPCallback()
{
    uint32_t wFileNamePtr;
    int8_t wFileNameString[0x100];
    APIContextContainer_t wAPIContextContainer;

    printf("CreateFileA start BP hit\n");

    // Retrieve the first parameter of the CreateFileA API that is the file name
    wFileNamePtr=GetFunctionParameter(mHandle, UE_FUNCTION_STDCALL, 1, UE_PARAMETER_DWORD);
    printf("wFileNamePtr : 0x%08X\n", wFileNamePtr);
    GetRemoteString(mHandle, (LPVOID)wFileNamePtr, (LPVOID)wFileNameString, 0x100);
    printf("wFileNameString : %s\n", wFileNameString);

    // If the file name match one of these pattern, it's finish
    /*if((strcmp((const char *)wFileNameString, (const char *)"\\\\.\\SuperBpmDev0")==0)   ||
            (strcmp((const char *)wFileNameString, (const char *)"\\\\.\\SuperBPMDev0")==0)   ||
            (strcmp((const char *)wFileNameString, (const char *)"\\\\.\\SICE")==0)           ||
            (strcmp((const char *)wFileNameString, (const char *)"\\\\.\\NTICE")==0)          ||
            (strcmp((const char *)wFileNameString, (const char *)"\\\\.\\SIWDEBUG")==0)       ||
            (strcmp((const char *)wFileNameString, (const char *)"\\\\.\\SIWVID")==0)         ||
            (strcmp((const char *)(wFileNameString + (strlen((const char *)wFileNameString) - 5)), (const char *)".RREF")==0)
      )*/
    if(!strncmp((char*)wFileNameString, "\\\\.\\", 4) or
            !strcmp((char*)wFileNameString+strlen((char*)wFileNameString)-5, ".RREF"))
    {
        // Stop debugging
        printf("Stop\n");
        StopDebug();
    }
    else
    {
        mCreateFileAContext.fileNameStr=string((const char *)wFileNameString);

        wAPIContextContainer.APIType=CREATE_FILE_A_CONTEXT;
        wAPIContextContainer.CreateFileAContext=mCreateFileAContext;

        mAPIContextContainerList.push_back(wAPIContextContainer);
    }
}


void LR_ProcessAPIContextLog()
{
    uint32_t wI;
    vector<ArmaLicenseEntry_t> wArmaLicenseEntry;

    // Get the version
    /*
    int8_t wVersionString[10];
    uint32_t wVersion;
    TEArmaVersionFinder(mFileName, wVersionString);
    wVersionString[1]=wVersionString[2];
    wVersionString[2]=wVersionString[3];
    wVersionString[3]=0;
    wVersion=string((const char*)wVersionString).toInt();
    */

    printf("\n\n\n\n\n");
    LR_PrintAPIContextContainerList(mAPIContextContainerList);


    wArmaLicenseEntry = LR_FilterAPIContextContainerList(mAPIContextContainerList);

    /*
    if(mIsGreaterThanArma940 == 0)
    {
        // Arma <=940
        wArmaLicenseEntry=LR_FilterAPIContextContainerListArma940AndLess(mAPIContextContainerList);
    }
    else
    {
        // Arma >940
    	wArmaLicenseEntry = LR_FilterAPIContextContainerListArma940AndLess(mAPIContextContainerList);
        //wArmaLicenseEntry = LR_FilterAPIContextContainerListArma960(mAPIContextContainerList);
    }
    */

    for(wI=0; wI<wArmaLicenseEntry.size(); wI++)
    {
        printf("Debug : %s\n", wArmaLicenseEntry.at(wI).Path.c_str());
    }

    *mArmaLicenseEntryPtr=wArmaLicenseEntry;
}


/**
 * @brief       This function is used for debug purpose. It prints all items of a list of APIContextContainer_t.
 *
 * @param[in]   parAPIContextContainerList  List of APIContextContainer_t to print.
 *
 * @return      Nothing.
 */
void LR_PrintAPIContextContainerList(vector<APIContextContainer_t> parAPIContextContainerList)
{
    uint32_t wI;

    for(wI=0; wI<parAPIContextContainerList.size(); wI++)
    {
        if(parAPIContextContainerList.at(wI).APIType==REG_OPEN_KEY_EX_A_CONTEXT)
        {
            printf("RegOpenKeyExAContext_t\n");

            if((HKEY)(parAPIContextContainerList.at(wI).RegOpenKeyExAContext.hKey)==HKEY_LOCAL_MACHINE)
                printf("\tHKey : HKEY_LOCAL_MACHINE\n");
            else if((HKEY)(parAPIContextContainerList.at(wI).RegOpenKeyExAContext.hKey)==HKEY_CLASSES_ROOT)
                printf("\tHKey : HKEY_CLASSES_ROOT\n");
            else if((HKEY)(parAPIContextContainerList.at(wI).RegOpenKeyExAContext.hKey)==HKEY_CURRENT_USER)
                printf("\tHKey : HKEY_CURRENT_USER\n");
            else
                printf("\tHKey : %08X\n", parAPIContextContainerList.at(wI).RegOpenKeyExAContext.hKey);

            printf("\tSubKey : %s\n", parAPIContextContainerList.at(wI).RegOpenKeyExAContext.subKeyStr.data());

            printf("\tHandle : %08X\n", parAPIContextContainerList.at(wI).RegOpenKeyExAContext.hkResult);
        }
        else if(parAPIContextContainerList.at(wI).APIType==REG_QUERY_VALUE_EX_A_CONTEXT)
        {
            printf("RegQueryValueExAContext_t\n");

            printf("\tHKey : %08X\n", parAPIContextContainerList.at(wI).RegQueryValueExAContext.hKey);

            printf("\tValue Name : %s\n", parAPIContextContainerList.at(wI).RegQueryValueExAContext.valueNameStr.data());
        }
        else if(parAPIContextContainerList.at(wI).APIType==CREATE_FILE_A_CONTEXT)
        {
            printf("CreateFileAContext_t\n");

            printf("\tFile Name : %s\n", parAPIContextContainerList.at(wI).CreateFileAContext.fileNameStr.data());
        }
        else {}
    }
}


/**
 * @brief       This function filter a list of APIContextContainer_t items and keep only existin registry keys and files linked to the license.
 *
 * @param[in]   parAPIContextContainerList  List of APIContextContainer_t to filter.
 *
 * @return      Nothing.
 */
vector<ArmaLicenseEntry_t> LR_FilterAPIContextContainerList(vector<APIContextContainer_t> parAPIContextContainerList)
{
    uint32_t wI, wJ;
    uint32_t wListSize = parAPIContextContainerList.size();
    ArmaLicenseEntry_t wTempArmaLicenseEntry;
    vector<ArmaLicenseEntry_t> wArmaLicenseEntryList;

    // Filter License Reg keys
    for(wI = 0; wI < wListSize; wI++)
    {
        if(wI < (wListSize-1))
        {
            if((parAPIContextContainerList.at(wI).APIType == REG_OPEN_KEY_EX_A_CONTEXT) && (parAPIContextContainerList.at(wI+1).APIType == REG_QUERY_VALUE_EX_A_CONTEXT))
            {
                if(parAPIContextContainerList.at(wI).RegOpenKeyExAContext.subKeyStr.find('{') == std::string::npos)
                {
                    if(((HKEY)parAPIContextContainerList.at(wI).RegOpenKeyExAContext.hKey == HKEY_LOCAL_MACHINE) && ((parAPIContextContainerList.at(wI+1).RegQueryValueExAContext.valueNameStr.data())[0] == '{'))
                    {
                        wTempArmaLicenseEntry.Type = REGISTRY_KEY_ENRTY;
                        wTempArmaLicenseEntry.Path = string("HKEY_LOCAL_MACHINE\\") + parAPIContextContainerList.at(wI).RegOpenKeyExAContext.subKeyStr + "\\" + parAPIContextContainerList.at(wI+1).RegQueryValueExAContext.valueNameStr;

                        if(LR_RegKeyExists(HKEY_LOCAL_MACHINE, (LPCSTR)parAPIContextContainerList.at(wI).RegOpenKeyExAContext.subKeyStr.data(), (LPCSTR)parAPIContextContainerList.at(wI+1).RegQueryValueExAContext.valueNameStr.data()) == true)
                            wArmaLicenseEntryList.push_back(wTempArmaLicenseEntry);
                    }
                    else if(((HKEY)parAPIContextContainerList.at(wI).RegOpenKeyExAContext.hKey == HKEY_CURRENT_USER) && ((parAPIContextContainerList.at(wI+1).RegQueryValueExAContext.valueNameStr.data())[0] == '{'))
                    {
                        wTempArmaLicenseEntry.Type = REGISTRY_KEY_ENRTY;
                        wTempArmaLicenseEntry.Path = string("HKEY_CURRENT_USER\\") + parAPIContextContainerList.at(wI).RegOpenKeyExAContext.subKeyStr + "\\" + parAPIContextContainerList.at(wI+1).RegQueryValueExAContext.valueNameStr;

                        if(LR_RegKeyExists(HKEY_CURRENT_USER, (LPCSTR)parAPIContextContainerList.at(wI).RegOpenKeyExAContext.subKeyStr.data(), (LPCSTR)parAPIContextContainerList.at(wI+1).RegQueryValueExAContext.valueNameStr.data()) == true)
                            wArmaLicenseEntryList.push_back(wTempArmaLicenseEntry);
                    }
                }
                else
                {
                    if((HKEY)parAPIContextContainerList.at(wI).RegOpenKeyExAContext.hKey == HKEY_LOCAL_MACHINE)
                    {
                        wTempArmaLicenseEntry.Type = REGISTRY_KEY_ENRTY;
                        wTempArmaLicenseEntry.Path = string("HKEY_LOCAL_MACHINE\\") + parAPIContextContainerList.at(wI).RegOpenKeyExAContext.subKeyStr;

                        if(LR_RegKeyExists(HKEY_LOCAL_MACHINE, (LPCSTR)parAPIContextContainerList.at(wI).RegOpenKeyExAContext.subKeyStr.data(), (LPCSTR)"") == true)
                            wArmaLicenseEntryList.push_back(wTempArmaLicenseEntry);
                    }
                    else if((HKEY)parAPIContextContainerList.at(wI).RegOpenKeyExAContext.hKey == HKEY_CURRENT_USER)
                    {
                        wTempArmaLicenseEntry.Type = REGISTRY_KEY_ENRTY;
                        wTempArmaLicenseEntry.Path = string("HKEY_CURRENT_USER\\") + parAPIContextContainerList.at(wI).RegOpenKeyExAContext.subKeyStr;

                        if(LR_RegKeyExists(HKEY_CURRENT_USER, (LPCSTR)parAPIContextContainerList.at(wI).RegOpenKeyExAContext.subKeyStr.data(), (LPCSTR)"") == true)
                            wArmaLicenseEntryList.push_back(wTempArmaLicenseEntry);
                    }
                    else if((HKEY)parAPIContextContainerList.at(wI).RegOpenKeyExAContext.hKey == HKEY_CLASSES_ROOT)
                    {
                        wTempArmaLicenseEntry.Type = REGISTRY_KEY_ENRTY;
                        wTempArmaLicenseEntry.Path = string("HKEY_CLASSES_ROOT\\") + parAPIContextContainerList.at(wI).RegOpenKeyExAContext.subKeyStr;

                        if(LR_RegKeyExists(HKEY_CLASSES_ROOT, (LPCSTR)parAPIContextContainerList.at(wI).RegOpenKeyExAContext.subKeyStr.data(), (LPCSTR)"") == true)
                            wArmaLicenseEntryList.push_back(wTempArmaLicenseEntry);
                    }
                }
            }
            else
            {
                if(parAPIContextContainerList.at(wI).RegOpenKeyExAContext.subKeyStr.find('{') == std::string::npos)
                {

                }
                else
                {
                    if((HKEY)parAPIContextContainerList.at(wI).RegOpenKeyExAContext.hKey == HKEY_CLASSES_ROOT)
                    {
                        wTempArmaLicenseEntry.Type = REGISTRY_KEY_ENRTY;
                        wTempArmaLicenseEntry.Path = string("HKEY_CLASSES_ROOT\\") + parAPIContextContainerList.at(wI).RegOpenKeyExAContext.subKeyStr;

                        if(LR_RegKeyExists(HKEY_CLASSES_ROOT, (LPCSTR)parAPIContextContainerList.at(wI).RegOpenKeyExAContext.subKeyStr.data(), (LPCSTR)"") == true)
                            wArmaLicenseEntryList.push_back(wTempArmaLicenseEntry);
                    }
                }
            }
        }
    }

    // Filter License Files
    for(wI = 0; wI < wListSize; wI++)
    {
        if(parAPIContextContainerList.at(wI).APIType == CREATE_FILE_A_CONTEXT)
        {
            wTempArmaLicenseEntry.Type = FILE_ENRTY;
            wTempArmaLicenseEntry.Path = parAPIContextContainerList.at(wI).CreateFileAContext.fileNameStr;

            if(LR_FileExists((LPSTR)wTempArmaLicenseEntry.Path.data()) == true)
                wArmaLicenseEntryList.push_back(wTempArmaLicenseEntry);
        }
    }

    // Remove doubles
    for(wI = 0; wI < wArmaLicenseEntryList.size(); wI++)
    {
        for(wJ = 0; wJ < wArmaLicenseEntryList.size(); wJ++)
        {
            if(wI != wJ)
            {
                if((wArmaLicenseEntryList.at(wI).Type == wArmaLicenseEntryList.at(wJ).Type) && (wArmaLicenseEntryList.at(wI).Path.compare(wArmaLicenseEntryList.at(wJ).Path) == 0))
                {
                    wArmaLicenseEntryList.erase(wArmaLicenseEntryList.begin() + wJ);
                    wI = 0;
                    wJ = 0;
                }
            }
        }
    }

    return wArmaLicenseEntryList;
}


/**
 * @brief       This function filter a list of APIContextContainer_t items and keep only existin registry keys and files linked to the license.@n
 *              (Compatible with Armadillo up to 9.40)
 *
 * @param[in]   parAPIContextContainerList  List of APIContextContainer_t to filter.
 *
 * @return      Nothing.
 */
vector<ArmaLicenseEntry_t> LR_FilterAPIContextContainerListArma940AndLess(vector<APIContextContainer_t> parAPIContextContainerList)
{
    uint32_t wI, wJ;
    uint32_t wListSize=parAPIContextContainerList.size();
    ArmaLicenseEntry_t wTempArmaLicenseEntry;
    vector<ArmaLicenseEntry_t> wArmaLicenseEntryList;

    // Filter License Reg keys
    for(wI=0; wI<wListSize; wI++)
    {
        if(wI<(wListSize-1))
        {
            if((parAPIContextContainerList.at(wI).APIType==REG_OPEN_KEY_EX_A_CONTEXT) && (parAPIContextContainerList.at(wI+1).APIType==REG_QUERY_VALUE_EX_A_CONTEXT))
            {
                if(((HKEY)parAPIContextContainerList.at(wI).RegOpenKeyExAContext.hKey==HKEY_LOCAL_MACHINE) && ((parAPIContextContainerList.at(wI+1).RegQueryValueExAContext.valueNameStr.data())[0]=='{'))
                {
                    wTempArmaLicenseEntry.Type=REGISTRY_KEY_ENRTY;
                    wTempArmaLicenseEntry.Path=string("HKEY_LOCAL_MACHINE\\") + parAPIContextContainerList.at(wI).RegOpenKeyExAContext.subKeyStr + "\\" + parAPIContextContainerList.at(wI+1).RegQueryValueExAContext.valueNameStr;

                    if(LR_RegKeyExists(HKEY_LOCAL_MACHINE, (LPCSTR)parAPIContextContainerList.at(wI).RegOpenKeyExAContext.subKeyStr.data(), (LPCSTR)parAPIContextContainerList.at(wI+1).RegQueryValueExAContext.valueNameStr.data())==true)
                        wArmaLicenseEntryList.push_back(wTempArmaLicenseEntry);
                }
                else if(((HKEY)parAPIContextContainerList.at(wI).RegOpenKeyExAContext.hKey==HKEY_CLASSES_ROOT) && (!strncmp(parAPIContextContainerList.at(wI).RegOpenKeyExAContext.subKeyStr.data(), "CLSID\\{", 7)))
                {
                    wTempArmaLicenseEntry.Type=REGISTRY_KEY_ENRTY;
                    wTempArmaLicenseEntry.Path=string("HKEY_CLASSES_ROOT\\") + parAPIContextContainerList.at(wI).RegOpenKeyExAContext.subKeyStr;

                    if(LR_RegKeyExists(HKEY_CLASSES_ROOT, (LPCSTR)parAPIContextContainerList.at(wI).RegOpenKeyExAContext.subKeyStr.data(), (LPCSTR)"")==true)
                        wArmaLicenseEntryList.push_back(wTempArmaLicenseEntry);
                }
            }
        }
    }

    // Filter License Files
    for(wI=0; wI<wListSize; wI++)
    {
        if(parAPIContextContainerList.at(wI).APIType==CREATE_FILE_A_CONTEXT)
        {
            wTempArmaLicenseEntry.Type=FILE_ENRTY;
            wTempArmaLicenseEntry.Path=parAPIContextContainerList.at(wI).CreateFileAContext.fileNameStr;

            if(LR_FileExists((LPSTR)wTempArmaLicenseEntry.Path.data())==true)
                wArmaLicenseEntryList.push_back(wTempArmaLicenseEntry);
        }
    }


    // Remove doubles
    for(wI=0; wI<wArmaLicenseEntryList.size(); wI++)
    {
        for(wJ=0; wJ<wArmaLicenseEntryList.size(); wJ++)
        {
            if(wI!=wJ)
            {
                if((wArmaLicenseEntryList.at(wI).Type==wArmaLicenseEntryList.at(wJ).Type) && !(wArmaLicenseEntryList.at(wI).Path.compare(wArmaLicenseEntryList.at(wJ).Path)))
                {
                    wArmaLicenseEntryList.erase(wArmaLicenseEntryList.begin() + wJ);
                    wI=0;
                    wJ=0;
                }
            }
        }
    }

    return wArmaLicenseEntryList;
}


/**
 * @brief       This function filter a list of APIContextContainer_t items and keep only existin registry keys and files linked to the license.@n
 *              (Compatible with Armadillo 9.60)
 *
 * @param[in]   parAPIContextContainerList  List of APIContextContainer_t to filter.
 *
 * @return      Nothing.
 */
vector<ArmaLicenseEntry_t> LR_FilterAPIContextContainerListArma960(vector<APIContextContainer_t> parAPIContextContainerList)
{
    uint32_t wI, wJ;
    uint32_t wListSize=parAPIContextContainerList.size();
    ArmaLicenseEntry_t wTempArmaLicenseEntry;
    vector<ArmaLicenseEntry_t> wArmaLicenseEntryList;

    // Filter License Reg keys
    for(wI=0; wI<wListSize; wI++)
    {
        if(wI<(wListSize-1))
        {
            if((parAPIContextContainerList.at(wI).APIType==REG_OPEN_KEY_EX_A_CONTEXT) && (parAPIContextContainerList.at(wI+1).APIType==REG_QUERY_VALUE_EX_A_CONTEXT))
            {
                if(((HKEY)parAPIContextContainerList.at(wI).RegOpenKeyExAContext.hKey==HKEY_CURRENT_USER) && !(parAPIContextContainerList.at(wI).RegOpenKeyExAContext.subKeyStr.compare("Software\\Licenses")))
                {
                    wTempArmaLicenseEntry.Type=REGISTRY_KEY_ENRTY;
                    wTempArmaLicenseEntry.Path=string("HKEY_CURRENT_USER\\") + parAPIContextContainerList.at(wI).RegOpenKeyExAContext.subKeyStr + "\\" + parAPIContextContainerList.at(wI+1).RegQueryValueExAContext.valueNameStr;

                    if(LR_RegKeyExists(HKEY_CURRENT_USER, (LPCSTR)wTempArmaLicenseEntry.Path.substr(18, wTempArmaLicenseEntry.Path.find("{") - 18 - 1).data(), (LPCSTR)wTempArmaLicenseEntry.Path.substr(wTempArmaLicenseEntry.Path.find("{")).data())==true)
                        wArmaLicenseEntryList.push_back(wTempArmaLicenseEntry);
                }
                else if(((HKEY)parAPIContextContainerList.at(wI).RegOpenKeyExAContext.hKey==HKEY_CURRENT_USER) && (strncmp(parAPIContextContainerList.at(wI).RegOpenKeyExAContext.subKeyStr.data(), "Software\\Classes", 16)==0))
                {
                    wTempArmaLicenseEntry.Type=REGISTRY_KEY_ENRTY;
                    wTempArmaLicenseEntry.Path=string("HKEY_CURRENT_USER\\") + parAPIContextContainerList.at(wI).RegOpenKeyExAContext.subKeyStr;

                    if(LR_RegKeyExists(HKEY_CURRENT_USER, (LPCSTR)wTempArmaLicenseEntry.Path.substr(18).data(), (LPCSTR)"")==true)
                        wArmaLicenseEntryList.push_back(wTempArmaLicenseEntry);
                }
                else if(((HKEY)parAPIContextContainerList.at(wI).RegOpenKeyExAContext.hKey==HKEY_CLASSES_ROOT) && (strncmp(parAPIContextContainerList.at(wI).RegOpenKeyExAContext.subKeyStr.data(), "CLSID\\{", 7)==0))
                {
                    wTempArmaLicenseEntry.Type=REGISTRY_KEY_ENRTY;
                    wTempArmaLicenseEntry.Path=string("HKEY_CLASSES_ROOT\\") + parAPIContextContainerList.at(wI).RegOpenKeyExAContext.subKeyStr;

                    if(LR_RegKeyExists(HKEY_CLASSES_ROOT, (LPCSTR)wTempArmaLicenseEntry.Path.substr(18).data(), (LPCSTR)"")==true)
                        wArmaLicenseEntryList.push_back(wTempArmaLicenseEntry);
                }
            }
        }
    }

    // Filter License Files
    for(wI=0; wI<wListSize; wI++)
    {
        if(parAPIContextContainerList.at(wI).APIType==CREATE_FILE_A_CONTEXT)
        {
            wTempArmaLicenseEntry.Type=FILE_ENRTY;
            wTempArmaLicenseEntry.Path=parAPIContextContainerList.at(wI).CreateFileAContext.fileNameStr;

            if(LR_FileExists((LPSTR)wTempArmaLicenseEntry.Path.data())==true)
                wArmaLicenseEntryList.push_back(wTempArmaLicenseEntry);
        }
    }


    // Remove doubles
    for(wI=0; wI<wArmaLicenseEntryList.size(); wI++)
    {
        for(wJ=0; wJ<wArmaLicenseEntryList.size(); wJ++)
        {
            if(wI!=wJ)
            {
                if((wArmaLicenseEntryList.at(wI).Type==wArmaLicenseEntryList.at(wJ).Type) && (wArmaLicenseEntryList.at(wI).Path.compare(wArmaLicenseEntryList.at(wJ).Path)==0))
                {
                    wArmaLicenseEntryList.erase(wArmaLicenseEntryList.begin() + wJ);
                    wI=0;
                    wJ=0;
                }
            }
        }
    }

    return wArmaLicenseEntryList;
}


/**
 * @brief       This function checks if the key given in parameter exists or not. @n
 *              If the key to check is not a value, parKeyValueName need to be a 0 string.
 *
 * @param[in]   parKeyHandle        Handle to the parent key.
 * @param[in]   parSubKeyName       Name of the substring.
 * @param[in]   parKeyValueName     Name of the value.
 *
 * @return      True in case of success. @n
 *              False in case of error.
 */
bool LR_RegKeyExists(HKEY parKeyHandle, LPCSTR parSubKeyName, LPCSTR parKeyValueName)
{
    HKEY wTempKeyHandle;
    uint32_t wValueDataSize;

    if(RegOpenKeyExA(parKeyHandle, parSubKeyName, 0, KEY_READ, &wTempKeyHandle)==ERROR_SUCCESS)
    {
        if(parKeyValueName[0]!='\0')
        {
            if(RegQueryValueExA(wTempKeyHandle, parKeyValueName, 0, 0, 0, (DWORD*)&wValueDataSize)==ERROR_SUCCESS)
            {
                RegCloseKey(wTempKeyHandle);
                return true;
            }
            else
            {
                RegCloseKey(wTempKeyHandle);
                return false;
            }
        }
        else
        {
            RegCloseKey(wTempKeyHandle);
            return true;
        }
    }
    else
    {
        return false;
    }
}


/**
 * @brief       This function checks if the file given in parameter exists or not. @n
 *
 * @param[in]   parFileName     Path of the file.
 *
 * @return      True in case of success. @n
 *              False in case of error.
 */
bool LR_FileExists(LPSTR parFileName)
{
    HANDLE wTemFileHandle;

    wTemFileHandle=CreateFileA(parFileName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

    if(wTemFileHandle!=INVALID_HANDLE_VALUE)
    {
        CloseHandle(wTemFileHandle);
        return true;
    }
    else
    {
        return false;
    }
}


/**
 * @brief       This function removes all items from the list given in parameter.
 *
 * @param[in]   parArmaLicenseEntry  List of ArmaLicenseEntry_t to remove.
 *
 * @return      Nothing.
 */
void LR_RemoveArmaLicenseData(vector<ArmaLicenseEntry_t> parArmaLicenseEntry)
{
    uint32_t wI;

    for(wI=0; wI<parArmaLicenseEntry.size(); wI++)
    {
        if(parArmaLicenseEntry.at(wI).Type==REGISTRY_KEY_ENRTY)
        {
            string wHKey=parArmaLicenseEntry.at(wI).Path.substr(0, parArmaLicenseEntry.at(wI).Path.find("\\"));

            if(wHKey.compare(string("HKEY_LOCAL_MACHINE"))==0)
            {
                if(LR_DeleteRegKeyAuto(HKEY_LOCAL_MACHINE, (LPSTR)parArmaLicenseEntry.at(wI).Path.substr(parArmaLicenseEntry.at(wI).Path.find("\\")+1).data())==true)
                    printf("%s key has been deleted.\n", parArmaLicenseEntry.at(wI).Path.data());
                else
                    printf("%s key has not been deleted.\n", parArmaLicenseEntry.at(wI).Path.data());
            }
            else if(wHKey.compare(string("HKEY_CLASSES_ROOT"))==0)
            {
                if(LR_DeleteRegKeyAuto(HKEY_CLASSES_ROOT, (LPSTR)parArmaLicenseEntry.at(wI).Path.substr(parArmaLicenseEntry.at(wI).Path.find("\\")+1).data())==true)
                    printf("%s key has been deleted.\n", parArmaLicenseEntry.at(wI).Path.data());
                else
                    printf("%s key has not been deleted.\n", parArmaLicenseEntry.at(wI).Path.data());
            }
            else if(wHKey.compare(string("HKEY_CURRENT_USER"))==0)
            {
                if(LR_DeleteRegKeyAuto(HKEY_CURRENT_USER, (LPSTR)parArmaLicenseEntry.at(wI).Path.substr(parArmaLicenseEntry.at(wI).Path.find("\\")+1).data())==true)
                    printf("%s key has been deleted.\n", parArmaLicenseEntry.at(wI).Path.data());
                else
                    printf("%s key has not been deleted.\n", parArmaLicenseEntry.at(wI).Path.data());
            }
            else if(wHKey.compare(string("HKEY_USERS"))==0)
            {
                if(LR_DeleteRegKeyAuto(HKEY_USERS, (LPSTR)parArmaLicenseEntry.at(wI).Path.substr(parArmaLicenseEntry.at(wI).Path.find("\\")+1).data())==true)
                    printf("%s key has been deleted.\n", parArmaLicenseEntry.at(wI).Path.data());
                else
                    printf("%s key has not been deleted.\n", parArmaLicenseEntry.at(wI).Path.data());
            }
            else
            {
                printf("Bad entry.\n");
            }
        }
        else if(parArmaLicenseEntry.at(wI).Type==FILE_ENRTY)
        {
            if(DeleteFileA(parArmaLicenseEntry.at(wI).Path.data())!=0)
                printf("%s file has been deleted.\n", parArmaLicenseEntry.at(wI).Path.data());
            else
                printf("%s file has not been deleted.\n", parArmaLicenseEntry.at(wI).Path.data());
        }
        else
        {
            printf("Bad entry.\n");
        }
    }
}


/**
 * @brief       This function removes the item given in parameter.
 *
 * @param[in]   parArmaLicenseEntry  Item to remove.
 *
 * @return      Nothing.
 */
void LR_RemoveSingleArmaLicenseData(ArmaLicenseEntry_t parArmaLicenseEntry)
{
    if(parArmaLicenseEntry.Type==REGISTRY_KEY_ENRTY)
    {
        string wHKey=parArmaLicenseEntry.Path.substr(0, parArmaLicenseEntry.Path.find("\\"));

        if(wHKey.compare(string("HKEY_LOCAL_MACHINE"))==0)
        {
            if(LR_DeleteRegKeyAuto(HKEY_LOCAL_MACHINE, (LPSTR)parArmaLicenseEntry.Path.substr(parArmaLicenseEntry.Path.find("\\")+1).data())==true)
                printf("%s key has been deleted.\n", parArmaLicenseEntry.Path.data());
            else
                printf("%s key has not been deleted.\n", parArmaLicenseEntry.Path.data());
        }
        else if(wHKey.compare(string("HKEY_CLASSES_ROOT"))==0)
        {
            if(LR_DeleteRegKeyAuto(HKEY_CLASSES_ROOT, (LPSTR)parArmaLicenseEntry.Path.substr(parArmaLicenseEntry.Path.find("\\")+1).data())==true)
                printf("%s key has been deleted.\n", parArmaLicenseEntry.Path.data());
            else
                printf("%s key has not been deleted.\n", parArmaLicenseEntry.Path.data());
        }
        else if(wHKey.compare(string("HKEY_CURRENT_USER"))==0)
        {
            if(LR_DeleteRegKeyAuto(HKEY_CURRENT_USER, (LPSTR)parArmaLicenseEntry.Path.substr(parArmaLicenseEntry.Path.find("\\")+1).data())==true)
                printf("%s key has been deleted.\n", parArmaLicenseEntry.Path.data());
            else
                printf("%s key has not been deleted.\n", parArmaLicenseEntry.Path.data());
        }
        else if(wHKey.compare(string("HKEY_USERS"))==0)
        {
            if(LR_DeleteRegKeyAuto(HKEY_USERS, (LPSTR)parArmaLicenseEntry.Path.substr(parArmaLicenseEntry.Path.find("\\")+1).data())==true)
                printf("%s key has been deleted.\n", parArmaLicenseEntry.Path.data());
            else
                printf("%s key has not been deleted.\n", parArmaLicenseEntry.Path.data());
        }
        else
        {
            printf("Bad entry.\n");
        }
    }
    else if(parArmaLicenseEntry.Type==FILE_ENRTY)
    {
        if(DeleteFileA(parArmaLicenseEntry.Path.data())!=0)
            printf("%s file has been deleted.\n", parArmaLicenseEntry.Path.data());
        else
            printf("%s file has not been deleted.\n", parArmaLicenseEntry.Path.data());
    }
    else
    {
        printf("Bad entry.\n");
    }
}


/**
 * @brief       This function deletes the key (Node or Value) given in parameter from the registry. @n
 *              1. The key given in parameter is considered as a node. @n
 *              2. The function tries to open the parSubKey with RegOpenKeyExA. @n
 *              3. In case of success, key is recursively deleted. @n
 *              4. In case of error, the function considers that the key was a value. So, the parSubKey
 *              is split in a subkey string and a value name to be deleted. @n
 *
 * @param[in]   parHKey     Handle to an opened key.
 * @param[in]   parSubKey   Subkey string (Can be a node or a value).
 *
 * @return      True in case of success. @n
 *              False in case of error.
 */
bool LR_DeleteRegKeyAuto(HKEY parHKey, LPSTR parSubKey)
{
    HKEY wKeyHandle;
    int32_t wI=0;

    if(RegOpenKeyExA(parHKey, parSubKey, 0, KEY_ALL_ACCESS, &wKeyHandle)==ERROR_SUCCESS)
    {
        return LR_RecursiveRegKeyDelete(parHKey, parSubKey);
    }
    else
    {
        while(parSubKey[wI]!='\0')
        {
            wI++;
        }

        while(parSubKey[wI]!='\\')
        {
            wI--;
        }

        parSubKey[wI]='\0';

        return LR_RegKeyDelete(parHKey, parSubKey, parSubKey+wI+1);
    }
}


/**
 * @brief       This function recursively deletes the key from the registry given in parameter. @n
 *
 * @param[in]   parParentNode   Handle to an opened key.
 * @param[in]   wKeyToDelete    Subkey string (Need to be a node and not a value).
 *
 * @return      True in case of success. @n
 *              False in case of error.
 */
bool LR_RecursiveRegKeyDelete(HKEY parParentNode, LPCSTR wKeyToDelete)
{
    HKEY wKeyHandle;
    int8_t wSubKeyName[0x100];

    // Opens the specified registry key to delete (wKeyToDelete) that is located the "parParentNode" key
    if(RegOpenKeyExA(parParentNode, wKeyToDelete, 0, KEY_ALL_ACCESS, &wKeyHandle)!=ERROR_SUCCESS)
    {
        return false;
    }

    while(RegEnumKeyA(wKeyHandle, 0, (LPSTR)wSubKeyName, 0x100)!=ERROR_NO_MORE_ITEMS)
    {
        if(LR_RecursiveRegKeyDelete(wKeyHandle, (LPCSTR)wSubKeyName)==false)
        {
            break;
        }
    }

    RegCloseKey(wKeyHandle);

    if(RegDeleteKeyA(parParentNode , wKeyToDelete)!=ERROR_SUCCESS)
    {
        return false;
    }
    return true;
}


/**
 * @brief       This function deletes the value from the registry given in parameter. @n
 *
 * @param[in]   parKeyHandle        Handle to an opened key.
 * @param[in]   parSubKeyName       Subkey string (Need to be a node and not a value).
 * @param[in]   parKeyValueName     Value string (Need to be a value and not a node).
 *
 * @return      True in case of success. @n
 *              False in case of error.
 */
bool LR_RegKeyDelete(HKEY parKeyHandle, LPCSTR parSubKeyName, LPCSTR parKeyValueName)
{
    HKEY wTempKeyHandle;

    if(RegOpenKeyExA(parKeyHandle, parSubKeyName, 0, KEY_ALL_ACCESS, &wTempKeyHandle)==ERROR_SUCCESS)
    {
        if(RegDeleteValueA(wTempKeyHandle, parKeyValueName)==ERROR_SUCCESS)
        {
            RegCloseKey(wTempKeyHandle);
            return true;
        }
        else
        {
            RegCloseKey(wTempKeyHandle);
            return false;
        }
    }
    else
    {
        printf("Failed to open Licenses registry key.\n");
        return false;
    }
}


/**************************************************************************
 * 							Error Routines
 **************************************************************************/
/**
 * @brief       This function stops the debugger and prints the message given in parameter. @n
 *
 * @param[in]   parString   Error to print.
 *
 * @return      Nothing.
 */
void LR_Error(char* parString)
{
    // Stop debugging
    //printf("Fatal Error : \"%s\" -> Stop Debug\n", parString);
    MessageBoxA(hwndDlg, parString, "Fatal Error!", MB_ICONERROR);
    StopDebug();
}
