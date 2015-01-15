#include "InlineHelper_codegen.h"

/**********************************************************************
 *                      Functions
 *********************************************************************/
void IH_GenerateAsmCode(char* codeText, IH_InlineHelperData_t targetData)
{
    char crc_replace_code[2048] = "";
    if(targetData.Arma960)
    {
        sprintf(crc_replace_code, "mov dword ptr ds:[ebp-%X],%X\r\nmov eax,dword ptr ds:[esp+4]\r\nmov eax,dword ptr ds:[eax+%X]\r\nmov dword ptr ds:[eax],%X\r\nmov dword ptr ds:[eax+4],%X\r\nmov dword ptr ds:[eax+8],%X\r\nmov dword ptr ds:[eax+0C],%X",
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
        sprintf(crc_replace_code, "mov dword ptr ds:[ebp-%X],%X\r\nmov dword ptr ds:[ebp-%X],%X\r\nmov dword ptr ds:[ebp-%X],%X\r\nmov dword ptr ds:[ebp-%X],%X\r\nmov dword ptr ds:[ebp-%X],%X",
                targetData.CRCBase,
                targetData.CrcOriginalVals[0],
                targetData.CRCBase + 8,
                targetData.CrcOriginalVals[1],
                targetData.CRCBase + 12,
                targetData.CrcOriginalVals[2],
                targetData.CRCBase + 16,
                targetData.CrcOriginalVals[3],
                targetData.CRCBase + 20,
                targetData.CrcOriginalVals[4]);
    }
    unsigned int imgbase = targetData.ImageBase;
    sprintf(codeText, template_text,
            targetData.EmptyEntry - imgbase,
            targetData.EmptyEntry + 6 - imgbase,
            targetData.OutputDebugStringA_Addr - imgbase,
            targetData.VirtualProtect_Addr - imgbase,
            targetData.VirtualProtect_Addr - imgbase,
            targetData.OutputDebugCount,
            targetData.OutputDebugStringA_Addr - imgbase,
            crc_replace_code,
            targetData.OEP - imgbase,
            targetData.SecurityAddrRegister);
}
