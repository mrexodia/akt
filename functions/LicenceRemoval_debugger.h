#ifndef LICENCEREMOVAL_DEBUGGER_H_INCLUDED
#define LICENCEREMOVAL_DEBUGGER_H_INCLUDED

#include "_global.h"

/*
#include "TEArmaPatterns.h"
#include "TESearchInMemory.h"
#include "TEArmaVersionFinder.h"
#include "TitanEngineCustomAPI.h"
*/
using namespace std;

/**************************************************************************
 * 							Enumerations
 **************************************************************************/
/**
 * @brief  Type of API.
 */
typedef enum
{
    REG_OPEN_KEY_EX_A_CONTEXT,      /*!< RegOpenKeyExA*/
    REG_QUERY_VALUE_EX_A_CONTEXT,   /*!< RegQueryValueExA*/
    CREATE_FILE_A_CONTEXT           /*!< CreateFileA*/
} APIType_t;


/**
 * @brief  Type of item.
 */
typedef enum
{
    REGISTRY_KEY_ENRTY,     /*!< Registry key.*/
    FILE_ENRTY              /*!< File.*/
} ArmaLicenseEntryType_t;


/**************************************************************************
 * 							Structures
 **************************************************************************/

/**
 * @brief   RegOpenKeyExA API context structure. @n
 *          This structure can contain usefull parameters given to the RegOpenKeyExA API.
 */
typedef struct
{
    uint32_t    hKey;           /*!< Handle to an open registry key.*/
    string     subKeyStr;      /*!< Name of the registry subkey to be opened.*/
    uint32_t    access;         /*!< Mask that specifies the desired access rights to the key to be opened.*/
    uint32_t    hkResult;       /*!< Variable that receives a handle to the opened key.*/
} RegOpenKeyExAContext_t;


/**
 * @brief   RegQueryValueExA API context structure. @n
 *          This structure can contain usefull parameters given to the RegQueryValueExA API.
 */
typedef struct
{
    uint32_t    hKey;           /*!< Handle to an open registry key.*/
    string     valueNameStr;   /*!< The name of the registry value.*/
} RegQueryValueExAContext_t;


/**
 * @brief   CreateFileA API context structure. @n
 *          This structure can contain usefull parameters given to the CreateFileA API.
 */
typedef struct
{
    string     fileNameStr;    /*!< Name of the file.*/
} CreateFileAContext_t;


/**
 * @brief   API context container. @n
 *          This structure can contain API context structures. @n
 *          Only one API context structure is valid (Valid sutructure is given by the APIType item. @n
 */
typedef struct
{
    APIType_t APIType;                                  /*!< Indicate the valid item..*/
    RegOpenKeyExAContext_t RegOpenKeyExAContext;        /*!< RegOpenKeyExA API context structure.*/
    RegQueryValueExAContext_t RegQueryValueExAContext;  /*!< RegQueryValueExA API context structure.*/
    CreateFileAContext_t CreateFileAContext;            /*!< CreateFileA API context structure.*/
} APIContextContainer_t;


/**
 * @brief   Armadillo license entry.@n
 *          This structure indicates whether the entry is a registry key or a file and contains the full path to the item.@n
 */
typedef struct
{
    ArmaLicenseEntryType_t Type;    /*!< Indicate the type of the entry.*/
    string Path;                   /*!< Full path to the entry.*/
} ArmaLicenseEntry_t;

/**
 * @brief   DebugThread parameter structure. @n
 *          This structure contains parameters for the debugging thread.
 */
struct LRPARSTRUCT
{
    char* parFileName;
    vector<ArmaLicenseEntry_t>* parArmaLicenseEntryListPtr;
    HWND list;
    bool* isdebugging;
    cbGenericTwoArg filllist;
    HWND hwndDlg;
};

/**************************************************************************
 * 							Prototypes
 **************************************************************************/
// Public
DWORD WINAPI LR_GetArmaLicenseDataThread(void* parstruct);
void LR_GetArmaLicenseData(char parFileName[], vector<ArmaLicenseEntry_t> *parArmaLicenseEntryListPtr);
void LR_RemoveArmaLicenseData(vector<ArmaLicenseEntry_t> parArmaLicenseEntry);
void LR_RemoveSingleArmaLicenseData(ArmaLicenseEntry_t parArmaLicenseEntry);

// Private
// Callback
void LR_EntryPointArma960Callback();
void LR_OpenMutexAArma960Callback();
void LR_VirtualProtectCallback();
void LR_RegOpenKeyExAStartArma960BPCallback();
void LR_RegQueryValueExAStartArma960BPCallback();
void LR_CreateFileAStartArma960BPCallback();

// Registry key functions
bool LR_RegKeyExists(HKEY parKeyHandle, LPCSTR parSubKeyName, LPCSTR parKeyValueName);
bool LR_FileExists(LPSTR parFileName);
bool LR_RegKeyDelete(HKEY parKeyHandle, LPCSTR parSubKeyName, LPCSTR parKeyValueName);
bool LR_RecursiveRegKeyDelete(HKEY parParentNode, LPCSTR wKeyToDelete);
bool LR_DeleteRegKeyAuto(HKEY parHKey, LPSTR parSubKey);

// Filetring functions
vector<ArmaLicenseEntry_t> LR_FilterAPIContextContainerListArma960(vector<APIContextContainer_t> parAPIContextContainerList);
vector<ArmaLicenseEntry_t> LR_FilterAPIContextContainerListArma940AndLess(vector<APIContextContainer_t> parAPIContextContainerList);

// Final processing
void LR_ProcessAPIContextLog();

// Debug
void LR_PrintAPIContextContainerList(vector<APIContextContainer_t> parAPIContextContainerList);

// Error
void LR_Error(char* parString);

#endif // LICENCEREMOVAL_DEBUGGER_H_INCLUDED
