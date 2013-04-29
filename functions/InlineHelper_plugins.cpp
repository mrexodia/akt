#include "InlineHelper_plugins.h"

/**********************************************************************
 *						Functions
 *********************************************************************/
void IH_GetPluginList(void)
{
	PLUGFUNC PluginFunction;
	PLUGINFO PluginInfo;
	HINSTANCE PLUGIN_INST;
    char plugin_search[256]="";
    char plugin_name[1024]="";
    char plugin_counter_s[10]="";
    int plugin_counter=0;

    WIN32_FIND_DATA find_struct;
    HANDLE search_handle;

    strcpy(plugin_search, sg_szAKTDirectory);
    strcat(plugin_search, "\\plugins");
    SetCurrentDirectoryA(plugin_search);
    strcat(plugin_search, "\\*.dll");
    search_handle=FindFirstFileA(plugin_search, &find_struct);
    if(search_handle)
    {
        ///do ini operations
        PLUGIN_INST=LoadLibraryA(find_struct.cFileName);
        if(PLUGIN_INST)
        {
            PluginInfo=(PLUGINFO)GetProcAddress(PLUGIN_INST, "PluginInfo");
            PluginFunction=(PLUGFUNC)GetProcAddress(PLUGIN_INST, "PluginFunction");
            if(!PluginInfo)
            {
                MessageBoxA(0, "Invalid plugin:\n\nThe export 'PluginInfo' could not be found.", find_struct.cFileName, MB_ICONERROR);
            }
            else if(PluginFunction==0)
            {
                MessageBoxA(0, "Invalid plugin:\n\nThe export 'PluginFunction' could not be found.", find_struct.cFileName, MB_ICONERROR);
            }
            else
            {
                plugin_counter++;
                strcpy(plugin_name, PluginInfo());
                sprintf(plugin_counter_s, "%d", plugin_counter);
                WritePrivateProfileStringA("Plugins", "total_found", plugin_counter_s, sg_szPluginIniFilePath);
                WritePrivateProfileStringA(plugin_counter_s, "plugin_dll", find_struct.cFileName, sg_szPluginIniFilePath);
                WritePrivateProfileStringA(plugin_counter_s, "plugin_name", plugin_name, sg_szPluginIniFilePath);
            }
            FreeLibrary(PLUGIN_INST);
        }
        if(FindNextFileA(search_handle, &find_struct))
        {
            ///do ini operations
            PLUGIN_INST=LoadLibraryA(find_struct.cFileName);
            if(PLUGIN_INST)
            {
                PluginInfo=(PLUGINFO)GetProcAddress(PLUGIN_INST, "PluginInfo");
                PluginFunction=(PLUGFUNC)GetProcAddress(PLUGIN_INST, "PluginFunction");
                if(!PluginInfo)
                {
                    MessageBoxA(0, "Invalid plugin:\n\nThe export 'PluginInfo' could not be found.", find_struct.cFileName, MB_ICONERROR);
                }
                else if(PluginFunction==0)
                {
                    MessageBoxA(0, "Invalid plugin:\n\nThe export 'PluginFunction' could not be found.", find_struct.cFileName, MB_ICONERROR);
                }
                else
                {
                    plugin_counter++;
                    strcpy(plugin_name, PluginInfo());
                    sprintf(plugin_counter_s, "%d", plugin_counter);
                    WritePrivateProfileStringA("Plugins", "total_found", plugin_counter_s, sg_szPluginIniFilePath);
                    WritePrivateProfileStringA(plugin_counter_s, "plugin_dll", find_struct.cFileName, sg_szPluginIniFilePath);
                    WritePrivateProfileStringA(plugin_counter_s, "plugin_name", plugin_name, sg_szPluginIniFilePath);
                }
                FreeLibrary(PLUGIN_INST);
            }
            for(;;)
            {
                FindNextFileA(search_handle, &find_struct);
                if(GetLastError()!=ERROR_NO_MORE_FILES)
                {
                    ///do ini operations
                    PLUGIN_INST=LoadLibraryA(find_struct.cFileName);
                    if(PLUGIN_INST)
                    {
                        PluginInfo=(PLUGINFO)GetProcAddress(PLUGIN_INST, "PluginInfo");
                        PluginFunction=(PLUGFUNC)GetProcAddress(PLUGIN_INST, "PluginFunction");
                        if(!PluginInfo)
                        {
                            MessageBoxA(0, "Invalid plugin:\n\nThe export 'PluginInfo' could not be found.", find_struct.cFileName, MB_ICONERROR);
                        }
                        else if(PluginFunction==0)
                        {
                            MessageBoxA(0, "Invalid plugin:\n\nThe export 'PluginFunction' could not be found.", find_struct.cFileName, MB_ICONERROR);
                        }
                        else
                        {
                            plugin_counter++;
                            strcpy(plugin_name, PluginInfo());
                            sprintf(plugin_counter_s, "%d", plugin_counter);
                            WritePrivateProfileStringA("Plugins", "total_found", plugin_counter_s, sg_szPluginIniFilePath);
                            WritePrivateProfileStringA(plugin_counter_s, "plugin_dll", find_struct.cFileName, sg_szPluginIniFilePath);
                            WritePrivateProfileStringA(plugin_counter_s, "plugin_name", plugin_name, sg_szPluginIniFilePath);
                        }
                        FreeLibrary(PLUGIN_INST);
                    }
                }
                else
                {
                    FindClose(search_handle);
                    return;
                }
            }
        }
        FindClose(search_handle);
        return;
    }
    WritePrivateProfileStringA("Plugins", "total_found", "0", sg_szPluginIniFilePath);
    return;
}
