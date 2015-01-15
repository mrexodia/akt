//  realign_supp.h : supplement header file for realign.dll
//  Author: DLL to Lib version 2.00
//  Date: Monday, May 20, 2013
//  Description: The declaration of the realign.dll's entry-point function.
//  Prototype: BOOL WINAPI xxx_DllMain(HINSTANCE hinstance, DWORD fdwReason, LPVOID lpvReserved);
//  Parameters:
//      hinstance
//        Handle to current instance of the application. Use AfxGetInstanceHandle()
//        to get the instance handle if your project has MFC support.
//      fdwReason
//        Specifies a flag indicating why the entry-point function is being called.
//      lpvReserved
//        Specifies further aspects of DLL initialization and cleanup. Should always
//        be set to NULL;
//  Comment: Please see the help document for detail information about the entry-point
//       function
//  Homepage: http://www.binary-soft.com
//  Technical Support: support@binary-soft.com
/////////////////////////////////////////////////////////////////////

#if !defined(D2L_REALIGN_SUPP_H__5C026254_54EE_5687_6503_167E03AE66A6__INCLUDED_)
#define D2L_REALIGN_SUPP_H__5C026254_54EE_5687_6503_167E03AE66A6__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#ifdef __cplusplus
extern "C" {
#endif


#include <windows.h>

/* This is realign.dll's entry-point function. You should call it to do necessary
 initialization and finalization. */

BOOL WINAPI REALIGN_DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);


#ifdef __cplusplus
}
#endif

#endif // !defined(D2L_REALIGN_SUPP_H__5C026254_54EE_5687_6503_167E03AE66A6__INCLUDED_)