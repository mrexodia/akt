#include "VersionFind_decode.h"

/**********************************************************************
 *                      Functions
 *********************************************************************/
void FillArmaExtraOptionsStruct(unsigned int raw, EXTRA_OPTIONS* eo)
{
    memset(eo, 0, sizeof(EXTRA_OPTIONS));
    eo->raw_extra_options = raw;
    if(raw & 0x2)
        eo->splash_type = SPLASH_BITMAP;
    else if(raw & 0x1)
        eo->splash_type = SPLASH_DEFAULT;
    else
        eo->splash_type = SPLASH_NONE;
    if(raw & 0x80)
        eo->enhanced_softice = true;
    if(raw & 0x4)
    {
        eo->standard_hwid = true;
        eo->has_other_options = true;
    }
    if(raw & 0x8)
    {
        eo->enhanced_hwid = true;
        eo->has_other_options = true;
    }
    if(raw & 0x200)
    {
        eo->no_clockback = true;
        eo->has_other_options = true;
    }
    if(raw & 0x400)
    {
        eo->no_clockforward = true;
        eo->has_other_options = true;
    }
    if(raw & 0x800)
    {
        eo->screensaver_protocols = true;
        eo->has_other_options = true;
    }
    if((raw & 0x2000) == 0)
    {
        eo->disable_info = true;
        eo->has_other_options = true;
    }
    if(raw & 0x4000)
    {
        eo->autorevert = true;
        eo->has_other_options = true;
    }
    if((raw & 0x8000) == 0)
    {
        eo->disable_register = true;
        eo->has_other_options = true;
    }
    if((raw & 0x20000) == 0)
    {
        eo->disable_unregister = true;
        eo->has_other_options = true;
    }
    if(raw & 0x40000)
    {
        eo->ignore_info = true;
        eo->has_other_options = true;
    }
}

void FillArmaOptionsStruct(unsigned int raw, const char* ver, ARMA_OPTIONS* op, EXTRA_OPTIONS* eo, bool bIsMinimal)
{
    memset(op, 0, sizeof(ARMA_OPTIONS));
    if(eo)
        op->extra_options = eo;
    if(!raw)
        return;
    op->raw_options = raw;
    strcpy(op->version, ver);
    op->nosectioncrypt = bIsMinimal;
    //Backupkey
    if(!(raw & 0x10000))
        op->backupkey = BACKUPKEY_NOKEYS;
    else if(raw & 0x8000)
        op->backupkey = BACKUPKEY_VARIABLE;
    else if(raw & 0x4000)
        op->backupkey = BACKUPKEY_FIXED;
    else
        op->backupkey = BACKUPKEY_NOBACKUP;
    //Compression
    if(raw & 0x3) //TODO: fix this!
        op->compression = COMPRESSION_BEST;
    else if(raw & 0x1)
        op->compression = COMPRESSION_BETTER;
    else
        op->compression = COMPRESSION_MINIMAL;
    //protection options
    if(raw & 0x10)
        op->debug_blocker = true;
    if(raw & 0xFF000000)
        op->copymem2 = true;
    if(raw & 0x400000)
        op->iat_elimination = true;
    if(raw & 0x200000)
        op->code_splicing = true;
    if(raw & 0x200)
        op->nanomites = true;
    if(raw & 0x8)
        op->mem_patch_protection = true;
    //other options
    if(!(raw & 0x40))
    {
        op->external_envvars = true;
        op->has_other_options = true;
    }
    if(raw & 0x20)
    {
        op->allow_one_copy = true;
        op->has_other_options = true;
    }
    if(raw & 0x2000)
    {
        op->disable_monitor = true;
        op->has_other_options = true;
    }
    if(raw & 0x1000)
    {
        op->esellerate = true;
        op->has_other_options = true;
    }
    if(raw & 0x100000)
    {
        op->digital_river = true;
        op->has_other_options = true;
    }
    if(raw & 0x100)
    {
        op->dontfallback = true;
        op->has_other_options = true;
    }
}

void VF_PrintArmaOptionsStructLog(ARMA_OPTIONS* op, char* log, unsigned int raw_options, unsigned int extra_options)
{
    bool set_other_options_log = false;
    if(op->raw_options)
    {
        sprintf(log, "%s\r\nProtection Options:\r\n", log);
        if(op->debug_blocker)
        {
            if(!op->copymem2)
            {
                sprintf(log, "%s>Debug-Blocker\r\n", log);
            }
        }
        else
        {
            if(op->nosectioncrypt)
            {
                sprintf(log, "%s>Minimal Protection\r\n", log);
            }
            else
            {
                sprintf(log, "%s>Standard Protection\r\n", log);
            }
        }
        if(op->copymem2)
        {
            sprintf(log, "%s>Debug-Blocker + CopyMem2\r\n", log);
        }
        if(op->iat_elimination)
        {
            sprintf(log, "%s>Enable Import Table Elimination\r\n", log);
        }
        if(op->code_splicing)
        {
            sprintf(log, "%s>Enable Strategic Code Splicing\r\n", log);
        }
        if(op->nanomites)
        {
            sprintf(log, "%s>Enable Nanomites Processing\r\n", log);
        }
        if(op->mem_patch_protection)
        {
            sprintf(log, "%s>Enable Memory-Patching Protections\r\n", log);
        }
        sprintf(log, "%s\r\nBackup Key Options:\r\n", log);
        switch(op->backupkey)
        {
        case BACKUPKEY_NOKEYS:
        {
            sprintf(log, "%s>No Registry Keys at All\r\n", log);
        }
        break;
        case BACKUPKEY_NOBACKUP:
        {
            sprintf(log, "%s>Main Key Only, No Backup Keys\r\n", log);
        }
        break;
        case BACKUPKEY_FIXED:
        {
            sprintf(log, "%s>Fixed Backup Keys\r\n", log);
        }
        break;
        case BACKUPKEY_VARIABLE:
        {
            sprintf(log, "%s>Variable Backup Keys\r\n", log);
        }
        break;
        }
        sprintf(log, "%s\r\nCompression Options:\r\n", log);
        switch(op->compression)
        {
        case COMPRESSION_MINIMAL:
        {
            sprintf(log, "%s>Minimal/Fastest Compression\r\n", log);
        }
        break;
        case COMPRESSION_BETTER:
        {
            sprintf(log, "%s>Better/Slower Compression\r\n", log);
        }
        break;
        case COMPRESSION_BEST:
        {
            sprintf(log, "%s>Best/Slowest Compression\r\n", log);
        }
        break;
        }
        if(op->has_other_options)
        {
            sprintf(log, "%s\r\nOther Options:\r\n", log);
            set_other_options_log = true;
            if(op->external_envvars)
            {
                sprintf(log, "%s>Store Environment Variables Externally\r\n", log);
            }
            if(op->allow_one_copy)
            {
                sprintf(log, "%s>Allow Only One Copy\r\n", log);
            }
            if(op->disable_monitor)
            {
                sprintf(log, "%s>Disable Monitoring Thread\r\n", log);
            }
            if(op->esellerate)
            {
                sprintf(log, "%s>Use eSellerate Edition Keys\r\n", log);
            }
            if(op->digital_river)
            {
                sprintf(log, "%s>Use Digital River Edition Keys\r\n", log);
            }
            if(op->dontfallback)
            {
                sprintf(log, "%s>Don't Fall Back to Stand-Alone Mode (Server)\r\n", log);
            }
        }
    }
    if(op->extra_options) //Enable everything
    {
        if(!set_other_options_log and op->extra_options->has_other_options)
            sprintf(log, "%s\r\nOther Options:\r\n", log);
        if(op->extra_options->no_clockback)
        {
            sprintf(log, "%s>Don't Report Clock-Back\r\n", log);
        }
        if(op->extra_options->no_clockforward)
        {
            sprintf(log, "%s>Don't Report Clock-Forward\r\n", log);
        }
        if(op->extra_options->screensaver_protocols)
        {
            sprintf(log, "%s>Use Screen Saver Protocols\r\n", log);
        }
        if(op->extra_options->disable_info)
        {
            sprintf(log, "%s>Disable INFO command\r\n", log);
        }
        if(op->extra_options->ignore_info)
        {
            sprintf(log, "%s>Ignore INFO command\r\n", log);
        }
        if(op->extra_options->disable_register)
        {
            sprintf(log, "%s>Disable REGISTER command\r\n", log);
        }
        if(op->extra_options->disable_unregister)
        {
            sprintf(log, "%s>Disable UNREGISTER command\r\n", log);
        }
        if(op->extra_options->autorevert)
        {
            sprintf(log, "%s>Auto-Revert On Invalid Key\r\n", log);
        }
        if(op->extra_options->standard_hwid)
        {
            sprintf(log, "%s>Standard Fingerprint in RegDlg\r\n", log);
        }
        if(op->extra_options->enhanced_hwid)
        {
            sprintf(log, "%s>Enhanced Fingerprint in RegDlg\r\n", log);
        }
        sprintf(log, "%s\r\nSoftICE Detection:\r\n", log);
        if(op->extra_options->enhanced_softice)
        {
            sprintf(log, "%s>Enhanced SoftICE Protection\r\n", log);
        }
        else
        {
            sprintf(log, "%s>Normal/No SoftICE Protection\r\n", log);
        }
        sprintf(log, "%s\r\nSplash Screen:\r\n", log);
        switch(op->extra_options->splash_type)
        {
        case SPLASH_NONE:
        {
            sprintf(log, "%s>No Splash Screen\r\n", log);
        }
        break;
        case SPLASH_DEFAULT:
        {
            sprintf(log, "%s>Default Splash Screen\r\n", log);
        }
        break;
        case SPLASH_BITMAP:
        {
            sprintf(log, "%s>Bitmap Splash Screen\r\n", log);
        }
        break;
        }
    }
    if(op->version[0])
        sprintf(log, "%s\r\nVersion Number:\r\n>%s\r\n", log, op->version);
    if(extra_options or raw_options)
        sprintf(log, "%s\r\nRaw Values:", log);
    if(raw_options)
        sprintf(log, "%s\r\n>%.8X (Raw Options)", log, op->raw_options);
    if(extra_options)
        sprintf(log, "%s\r\n>%.8X (Extra Options)", log, op->extra_options->raw_extra_options);
}
