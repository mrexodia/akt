#ifndef __MAIN_H__
#define __MAIN_H__

#define _WIN32_WINNT 0x0501

#include <windows.h>
#include <stdio.h>

typedef bool(*STOPDEBUG)(void);

struct CT_DATA
{
    unsigned char* raw_data;
    unsigned char* encrypted_data;
    char* projectid;
    unsigned int initial_diff;
    unsigned int raw_size;
    unsigned int encrypted_size;
    unsigned int first_dw;
    unsigned int magic1;
    unsigned int magic2;
    unsigned int salt;
    unsigned int decrypt_seed[3];
    unsigned int decrypt_addvals[4];
    bool checksumv8;
    bool zero_md5_symverify;
};

#ifdef BUILD_DLL
#define DLL_EXPORT __declspec(dllexport)
#else
#define DLL_EXPORT __declspec(dllimport)
#endif


#ifdef __cplusplus
extern "C"
{
#endif

    void DLL_EXPORT InitVariables(char* var0, CT_DATA* var1, STOPDEBUG var2, int var3, HWND var4);
    void DLL_EXPORT RemoveExceptionHandler();
    void DLL_EXPORT AddExceptionHandler();

#ifdef __cplusplus
}
#endif

#endif // __MAIN_H__
