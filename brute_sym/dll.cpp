#ifdef BUILD_DLL

#include "dll.h"
#include "brute.h"
#include <algorithm>

CALLBACKS callbacks;

int stop=0;

void DLL_EXPORT BruteSettings(HWND parent)
{
    MessageBoxA(parent, "No settings to tweak :)", "Example Brute DLL", MB_ICONINFORMATION);
}

void DLL_EXPORT BruteStop()
{
    stop=1;
}

void DLL_EXPORT SetCallbacks(PRINT_FOUND cb1, PRINT_PROGRESS cb2, PRINT_ERROR cb3)
{
    callbacks.print_found=cb1;
    callbacks.print_progress=cb2;
    callbacks.print_error=cb3;
}

void DLL_EXPORT BruteStart(int alg, hash_list *list, unsigned long from, unsigned long to, unsigned long* param)
{
    time_t start;
    start=time(NULL);
    unsigned long to_=to;
    if(alg==6 or alg==7 or alg==8)
        to_=100000000u;

    std::sort(&list->hash[0], &list->hash[list->count]);
    brute(alg, list, from, to_, (unsigned int*)param, &start, &stop, &callbacks);
    stop=0;
}

extern "C" BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    return TRUE;
}

#endif
