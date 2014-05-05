
/*****************************************************************************

  Realign.h
  ---------

  for version: 1.5

  Include file for Realign.dll.

  by yoda

*****************************************************************************/

#ifndef __Realign_h__
#define __Realign_h__

//
// constants
//
#define REALIGN_MODE_NORMAL     0
#define REALIGN_MODE_HARDCORE   1
#define REALIGN_MODE_NICE       2

// Macro to check the success of the functions "RealignPE" and "WipeReloc".
// For a full list of error codes have a look at "realignDLL.c".
#define REALIGNDLLAPI_SUCCESS(RetValue) (RetValue < 0xF0000000 && RetValue > 30)

// return type definition and success checking macro for "ReBasePEImage"
typedef enum _ReBaseErr
{
	RB_OK = 0,
	RB_INVALIDPE,
	RB_NORELOCATIONINFO,
	RB_INVALIDRVA,
	RB_INVALIDNEWBASE,
	RB_ACCESSVIOLATION
} ReBaseErr;

#define rbOK(ret)(ret == RB_OK)

//
// function prototypes
//

#ifdef __cplusplus
extern "C"
{
#endif // __cplusplus

BOOL      __stdcall TruncateFile(CHAR* szFilePath,DWORD dwNewFsize);
DWORD     __stdcall RealignPE(LPVOID AddressOfMapFile,DWORD dwFsize,BYTE bRealignMode);
DWORD     __stdcall WipeReloc(void* pMap, DWORD dwFsize);
BOOL      __stdcall ValidatePE(void* pPEImage, DWORD dwFileSize);
ReBaseErr __stdcall ReBasePEImage(void* pPE, DWORD dwNewBase);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // __Realign_h__
