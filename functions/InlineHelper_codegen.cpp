#include "InlineHelper_codegen.h"

/**********************************************************************
 *						Functions
 *********************************************************************/
void IH_GenerateAsmCode(const char* szFileName, char* codeText, bool fileIsDll, IH_InlineHelperData_t targetData)
{
    char szModuleName[256]="";
    int len=strlen(szFileName);
    while(szFileName[len]!='\\')
        len--;
    strcpy(szModuleName, szFileName+len+1);
    len=strlen(szModuleName);
    for(int i=0; i<len; i++)
        if(szModuleName[i]=='.')
        {
            szModuleName[i]=0;
            break;
        }
    if(strlen(szModuleName)>8)
        szModuleName[8]=0;
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
        sprintf(crc_replace_code, "mov dword ptr ds:[ebp-0%X],0%X\r\nmov dword ptr ds:[ebp-%X],0%X\r\nmov dword ptr ds:[ebp-%X],0%X\r\nmov dword ptr ds:[ebp-%X],0%X\r\nmov dword ptr ds:[ebp-%X],0%X",
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
    unsigned int imgbase=targetData.ImageBase;
    sprintf(codeText, template_text+1,
            szModuleName,
            targetData.EmptyEntry-imgbase,
            targetData.EmptyEntry+6-imgbase,
            targetData.OutputDebugStringA_Addr-imgbase,
            targetData.VirtualProtect_Addr-imgbase,
            targetData.VirtualProtect_Addr-imgbase,
            targetData.SecurityAddrRegister,
            targetData.OutputDebugStringA_Addr-imgbase,
            crc_replace_code,
            szModuleName,
            targetData.OEP-imgbase);
}
