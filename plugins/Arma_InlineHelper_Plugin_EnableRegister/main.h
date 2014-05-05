#ifndef __MAIN_H__
#define __MAIN_H__

#include <windows.h>
#include <commctrl.h>
#include <stdio.h>
#include "resource.h"

#ifdef BUILD_DLL
#define DLL_EXPORT __declspec(dllexport)
#else
#define DLL_EXPORT __declspec(dllimport)
#endif


#ifdef __cplusplus
extern "C"
{
#endif

    const char* DLL_EXPORT PluginInfo(void);
    void DLL_EXPORT PluginFunction(HINSTANCE hInst, HWND hwndDlg, const char* register_vp, const char* program_dir, unsigned int imagebase);

#ifdef __cplusplus
}
#endif

#endif
