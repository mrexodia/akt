#include "InlineHelper_codegen.h"

/**********************************************************************
 *						Functions
 *********************************************************************/
void IH_GenerateAsmCode(char* codeText, bool fileIsDll, IH_InlineHelperData_t targetData)
{
    char crc_replace_code[2048]="";
    if(targetData.Arma960)
    {
        sprintf(crc_replace_code, "mov dword ptr ds:[ebp-0%X],0%X\r\nmov eax,dword ptr ds:[esp]\r\nmov eax,dword ptr ds:[eax+0%X]\r\nmov dword ptr ds:[eax],0%X\r\nmov dword ptr ds:[eax+4],0%X\r\nmov dword ptr ds:[eax+8],0%X\r\nmov dword ptr ds:[eax+0C],0%X",
                targetData.CRCBase,
                targetData.CrcOriginalVals[0],
                targetData.Arma960_add,
                targetData.CrcOriginalVals[1],
                targetData.CrcOriginalVals[2],
                targetData.CrcOriginalVals[3],
                targetData.CrcOriginalVals[4]);
    }
    else
    {
        sprintf(crc_replace_code, "mov dword ptr ds:[ebp-0%X],0%X\r\nmov dword ptr ds:[ebp-%X],0%X\r\nmov dword ptr ds:[ebp-%X],0%X\r\nmov dword ptr ds:[ebp-%X],0%X\r\nmov dword ptr ds:[ebp-%X],0%X\r\n",
                targetData.CRCBase,
                targetData.CrcOriginalVals[0],
                targetData.CRCBase+8,
                targetData.CrcOriginalVals[1],
                targetData.CRCBase+12,
                targetData.CrcOriginalVals[2],
                targetData.CRCBase+16,
                targetData.CrcOriginalVals[3],
                targetData.CRCBase+20,
                targetData.CrcOriginalVals[4]);
    }
    if(!fileIsDll)
    {
        sprintf(codeText, template_text+1,
                targetData.EmptyEntry,
                targetData.OutputDebugStringA_Addr,
                targetData.VirtualProtect_Addr,
                targetData.OEP,
                targetData.OutputDebugCount,
                crc_replace_code,
                targetData.SecurityAddrRegister);
    }
    else
    {
        sprintf(codeText, dll_template_text+1,
                targetData.EmptyEntry,
                targetData.OutputDebugStringA_Addr,
                targetData.VirtualProtect_Addr,
                targetData.WriteProcessMemory_Addr,
                targetData.OEP,
                targetData.OutputDebugCount,
                crc_replace_code,
                targetData.SecurityAddrRegister);
    }
}
