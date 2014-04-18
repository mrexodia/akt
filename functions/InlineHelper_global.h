#ifndef _IH_GLOBAL_H
#define _IH_GLOBAL_H

#include "_global.h"


/**********************************************************************
 *						Type Definitions
 *********************************************************************/
typedef char*(*PLUGINFO)(void);

typedef void(*PLUGFUNC)(HINSTANCE hInst, HWND hwndDlg, const char* register_vp, const char* progdir, unsigned int imagebase);

typedef struct _IH_InlineHelperData_t
{
    // PE data
    long ImageBase; 					// Process image base
    long EntrySectionNumber ; 			// Number of sections
    char SecurityAddrRegister[4]; 		// Register that contains a pointer to security.dll

    // APIs addresses
    unsigned int GetEnvironmentVariableA_Addr;
    unsigned int SetEnvironmentVariableA_Addr;
    unsigned int LoadLibraryA_Addr;
    unsigned int GetProcAddress_Addr;
    unsigned int WriteProcessMemory_Addr;
    unsigned int OutputDebugStringA_Addr;
    unsigned int VirtualProtect_Addr;

    // OEP
    unsigned int OEP;					// Old entry point (for inline code)

    // Free Space Entry (Empty Entry)
    unsigned int EmptyEntry;			// Start of free space

    // CRC
    unsigned int CrcOriginalVals[5]; 	// Original CRC values array
    int CRCBase; 						// Stack difference for retrieving the CRC values

    // Output Debug Counter
    int OutputDebugCount; 				// Total count of hits on OutputDebugStringA

    // VirtualProtect info
    unsigned int CodeSize;

    // Arma 960 support
    bool Arma960;
    unsigned int Arma960_add;
} IH_InlineHelperData_t;

#endif
