#ifndef __DLL_H__
#define __DLL_H__

#include <windows.h>
#include "global.h"

#define DLL_EXPORT __declspec(dllexport)

#ifdef __cplusplus
extern "C"
{
#endif

void DLL_EXPORT BruteSettings(HWND parent);
void DLL_EXPORT BruteStop();
void DLL_EXPORT BruteStart(int alg, hash_list* list, unsigned long from, unsigned long to, unsigned long* param);
void DLL_EXPORT SetCallbacks(PRINT_FOUND cb1, PRINT_PROGRESS cb2, PRINT_ERROR cb3);

#ifdef __cplusplus
}
#endif

#endif
