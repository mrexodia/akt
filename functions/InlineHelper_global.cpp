#include "InlineHelper_global.h"

//Global vars
long IH_fdImageBase = NULL; //Process image base
long IH_fdEntryPoint = NULL; //Process entry
long IH_fdEntrySectionNumber = NULL; //entry section number
long IH_fdEntrySectionSize = NULL; //entry section size
long IH_fdEntrySectionOffset = NULL; //entry section offset

char IH_program_dir[256]=""; //Program directory
char IH_current_dir[256]=""; //Current directory
char IH_szFileName[256]=""; //Debugged program filename
char IH_code_text[2048]=""; //String for the inline asm code
char IH_debugProgramDir[256]=""; //String for the directory of the debugged program
char IH_security_addr_register[4]=""; //Register that contains a pointer to security.dll

int IH_outputdebugcount=0; //Counter for correct hits on OutputDebugStringA
int IH_outputdebugcount_total=0; //Total count of hits on OutputDebugStringA
int IH_crc_base=0; //Stack difference for retrieving the CRC values

unsigned int IH_addr_VirtualProtect; //ptr VirtualProtect
unsigned int IH_addr_OutputDebugStringA; //ptr OutputDebugStringA
unsigned int IH_addr_GetEnvironmentVariableA; //ptr GetEnvA
unsigned int IH_addr_SetEnvironmentVariableA; //ptr SetEnvA
unsigned int IH_addr_LoadLibraryA; //ptr LLA
unsigned int IH_addr_GetProcAddress; //ptr GPA
unsigned int IH_addr_WriteProcessMemory; //ptr WPM
unsigned int IH_empty_entry=0; //Start of free space
unsigned int IH_crc_original_vals[5]= {0}; //Original CRC values array
unsigned int IH_OEP=0; //Old entrypoint (for inline code)

bool IH_fdFileIsDll=false; //Flag for DLL

//Debugger
DWORD IH_bytes_read=0; //Global variable for rpm and rf
HWND IH_shared; //hwnd of the main window
LPPROCESS_INFORMATION IH_fdProcessInfo; //Process information structure

//Plugins
HINSTANCE PLUGIN_INST;
PLUGINFO PluginInfo;
PLUGFUNC PluginFunction;
char IH_plugin_ini_file[256]="";

//Dialog
HBRUSH hb=CreateSolidBrush(GetSysColor(15));
RECT rc;

//Decrypt
HWND IHD_shared;
bool IHD_fdFileIsDll = false;
LPPROCESS_INFORMATION IHD_fdProcessInfo = NULL;
long IHD_fdImageBase = NULL;
ULONG_PTR IHD_va;
long IHD_fdLoadedBase = NULL;
long IHD_fdEntryPoint = NULL;
long IHD_fdSizeOfImage = NULL;
long IHD_fdEntrySectionNumber = NULL;
long IHD_fdEntrySectionSize = NULL;
long IHD_fdEntrySectionOffset = NULL;
long IHD_fdEntrySectionRawOffset=0;
long IHD_fdEntrySectionRawSize=0;
DWORD IHD_bytes_read=0;
char IHD_szFileName[256]="";
char IHD_log_message[256]="";
char IHD_reg=0;

unsigned int IHD_newentry=0;
unsigned int IHD_freespace=0;
BYTE* IHD_decryptSectionData;
unsigned int IHD_epsection_raw_offset=0;
bool IH_arma960=false;
unsigned int IH_arma960_add=0;

unsigned int IH_FindCallPattern(BYTE* d, unsigned int size)
{
    for(unsigned int i=0; i<size; i++) //E8????????83
        if(d[i]==0xE8 and d[i+5]==0x83)
            return i;
    return 0;
}

unsigned int IH_FindEB6APattern(BYTE* d, unsigned int size)
{
    for(unsigned int i=0; i<size; i++) //EB??6A
        if(d[i]==0xEB and d[i+2]==0x6A)
            return i;
    return 0;
}

unsigned int IH_Find960Pattern(BYTE* d, unsigned int size)
{
    for(unsigned int i=0; i<size; i++) //5?68????????E8
        if((d[i]>>4)==0x05 and d[i+1]==0x68 and d[i+6]==0xE8)
            return i;
    return 0;
}
