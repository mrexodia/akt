#include "InlineHelper_codegen.h"

void IH_GenerateAsmCode()
{
    char crc_replace_code[2048]="";
    if(IH_arma960)
    {
        sprintf(crc_replace_code, "mov dword ptr ds:[ebp-0%X],0%X\r\nmov eax,dword ptr ds:[esp]\r\nmov eax,dword ptr ds:[eax+0%X]\r\nmov dword ptr ds:[eax],0%X\r\nmov dword ptr ds:[eax+4],0%X\r\nmov dword ptr ds:[eax+8],0%X\r\nmov dword ptr ds:[eax+0C],0%X",
                IH_crc_base,
                IH_crc_original_vals[0],
                IH_arma960_add,
                IH_crc_original_vals[1],
                IH_crc_original_vals[2],
                IH_crc_original_vals[3],
                IH_crc_original_vals[4]);
    }
    else
    {
        sprintf(crc_replace_code, "mov dword ptr ds:[ebp-0%X],0%X\r\nmov dword ptr ds:[ebp-%X],0%X\r\nmov dword ptr ds:[ebp-%X],0%X\r\nmov dword ptr ds:[ebp-%X],0%X\r\nmov dword ptr ds:[ebp-%X],0%X\r\n",
                IH_crc_base,
                IH_crc_original_vals[0],
                IH_crc_base+8,
                IH_crc_original_vals[1],
                IH_crc_base+12,
                IH_crc_original_vals[2],
                IH_crc_base+16,
                IH_crc_original_vals[3],
                IH_crc_base+20,
                IH_crc_original_vals[4]);
    }
    if(!IH_fdFileIsDll)
    {
        sprintf(IH_code_text, template_text+1,
                IH_empty_entry,
                IH_addr_OutputDebugStringA,
                IH_addr_VirtualProtect,
                IH_OEP,
                IH_outputdebugcount_total,
                crc_replace_code,
                IH_security_addr_register);
    }
    else
    {
        sprintf(IH_code_text, dll_template_text+1,
                IH_empty_entry,
                IH_addr_OutputDebugStringA,
                IH_addr_VirtualProtect,
                IH_addr_WriteProcessMemory,
                IH_OEP,
                IH_outputdebugcount_total,
                crc_replace_code,
                IH_security_addr_register);
    }
}
