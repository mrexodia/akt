#include <windows.h>
#include <stdio.h>
#include <commctrl.h>

HINSTANCE PLUGIN_INST;
typedef char*(__stdcall *PLUGINFO)(void);
typedef void(__stdcall *PLUGFUNC)(HINSTANCE hInst, HWND hwndDlg, const char* register_vp, const char* progdir, unsigned int imagebase);
PLUGINFO PluginInfo;
PLUGFUNC PluginFunction;

int main()
{
    char curdir[256]="",search_string[256]="";
    GetModuleFileNameA(GetModuleHandle(0), curdir, 256);
    int len=strlen(curdir);
    while(curdir[len]!='\\')
        len--;
    curdir[len]=0;
    sprintf(search_string, "%s\\*.dll", curdir);
    InitCommonControls();
    WIN32_FIND_DATA search_struct;
    HANDLE hSearch;
    hSearch=FindFirstFileA(search_string, &search_struct);
    if(hSearch==INVALID_HANDLE_VALUE)
    {
        puts("Error while searching *.dll!\n");
        system("pause");
        return 0;
    }
    strcpy(search_string, search_struct.cFileName);
    printf(" Plugin DLL : %s\n", search_string);
    FindClose(hSearch);
    PLUGIN_INST=LoadLibraryA(search_string);
    if(!PLUGIN_INST)
    {
        puts("Error loading plugin DLL!\n");
        system("pause");
        return 0;
    }
    PluginInfo=(PLUGINFO)GetProcAddress(PLUGIN_INST, "PluginInfo");
    if(!PluginInfo)
    {
        puts("Error loading PluginInfo!\n");
        system("pause");
        return 0;
    }
    PluginFunction=(PLUGFUNC)GetProcAddress(PLUGIN_INST, "PluginFunction");
    if(!PluginFunction)
    {
        puts("Error loading PluginFunction!\n");
        system("pause");
        return 0;
    }
    printf("Plugin Name : %s\n\n", PluginInfo());
    PluginFunction(PLUGIN_INST, 0, "EAX", curdir, 0x400000);
    puts("Testing ended!\n");
    return 0;
}
