#include "VersionFind_decode.h"

/**********************************************************************
 *						Functions
 *********************************************************************/
void FillArmaExtraOptionsStruct(unsigned int raw, EXTRA_OPTIONS* eo)
{
    memset(eo, 0, sizeof(EXTRA_OPTIONS));
    eo->raw_extra_options=raw;
    if(raw&0x2)
        eo->splash_type=SPLASH_BITMAP;
    else if(raw&0x1)
        eo->splash_type=SPLASH_DEFAULT;
    else
        eo->splash_type=SPLASH_NONE;
    if(raw&0x80)
        eo->enhanced_softice=true;
    if(raw&0x4)
    {
        eo->standard_hwid=true;
        eo->has_other_options=true;
    }
    if(raw&0x8)
    {
        eo->enhanced_hwid=true;
        eo->has_other_options=true;
    }
    if(raw&0x200)
    {
        eo->no_clockback=true;
        eo->has_other_options=true;
    }
    if(raw&0x400)
    {
        eo->no_clockforward=true;
        eo->has_other_options=true;
    }
    if(raw&0x800)
    {
        eo->screensaver_protocols=true;
        eo->has_other_options=true;
    }
    if((raw&0x2000)==0)
    {
        eo->disable_info=true;
        eo->has_other_options=true;
    }
    if(raw&0x4000)
    {
        eo->autorevert=true;
        eo->has_other_options=true;
    }
    if((raw&0x8000)==0)
    {
        eo->disable_register=true;
        eo->has_other_options=true;
    }
    if((raw&0x20000)==0)
    {
        eo->disable_unregister=true;
        eo->has_other_options=true;
    }
    if(raw&0x40000)
    {
        eo->ignore_info=true;
        eo->has_other_options=true;
    }
}


void FillArmaOptionsStruct(unsigned int raw, const char* ver, ARMA_OPTIONS* op, EXTRA_OPTIONS* eo, bool bIsMinimal)
{
    memset(op, 0, sizeof(ARMA_OPTIONS));
    if(eo)
        op->extra_options=eo;
    if(!raw)
        return;
    op->raw_options=raw;
    strcpy(op->version, ver);
    op->nosectioncrypt=bIsMinimal;
    //Backupkey
    if(!(raw&0x10000))
        op->backupkey=BACKUPKEY_NOKEYS;
    else if(raw&0x8000)
        op->backupkey=BACKUPKEY_VARIABLE;
    else if(raw&0x4000)
        op->backupkey=BACKUPKEY_FIXED;
    else
        op->backupkey=BACKUPKEY_NOBACKUP;
    //Compression
    if(raw&0x3) //TODO: fix this!
        op->compression=COMPRESSION_BEST;
    else if(raw&0x1)
        op->compression=COMPRESSION_BETTER;
    else
        op->compression=COMPRESSION_MINIMAL;
    //protection options
    if(raw&0x10)
        op->debug_blocker=true;
    if(raw&0xFF000000)
        op->copymem2=true;
    if(raw&0x400000)
        op->iat_elimination=true;
    if(raw&0x200000)
        op->code_splicing=true;
    if(raw&0x200)
        op->nanomites=true;
    if(raw&0x8)
        op->mem_patch_protection=true;
    //other options
    if(!(raw&0x40))
    {
        op->external_envvars=true;
        op->has_other_options=true;
    }
    if(raw&0x20)
    {
        op->allow_one_copy=true;
        op->has_other_options=true;
    }
    if(raw&0x2000)
    {
        op->disable_monitor=true;
        op->has_other_options=true;
    }
    if(raw&0x1000)
    {
        op->esellerate=true;
        op->has_other_options=true;
    }
    if(raw&0x100000)
    {
        op->digital_river=true;
        op->has_other_options=true;
    }
    if(raw&0x100)
    {
        op->dontfallback=true;
        op->has_other_options=true;
    }
}
