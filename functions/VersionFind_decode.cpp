#include "VersionFind_decode.h"

void ck(int id)
{
    CheckDlgButton(VF_shared, id, 1);
}

void uk(int id)
{
    CheckDlgButton(VF_shared, id, 0);
}

void ew(int id, bool a)
{
    EnableWindow(GetDlgItem(VF_shared, id), a);
}

void ResetContent(bool clear_all)
{
    HWND hwndDlg=VF_shared;
    if(clear_all)
    {
        SetDlgItemTextA(hwndDlg, IDC_EDT_VERSIONNUM, "");
        SetDlgItemTextA(hwndDlg, IDC_EDT_RAWOPTIONS, "");
        SetDlgItemTextA(hwndDlg, IDC_EDT_EXTRAOPTIONS, "");
    }
    ew(IDC_RADIO_ENHANCEDSOFTICE, 1);
    ew(IDC_RADIO_NORMALNOSOFTICE, 1);
    ew(IDC_RADIO_SPLASHNONE, 1);
    ew(IDC_RADIO_SPLASHDEFAULT, 1);
    ew(IDC_RADIO_SPLASHBITMAP, 1);
    ew(IDC_CHK_OTHERNOCLOCKBACK, 1);
    ew(IDC_CHK_OTHERNOCLOCKFORWARD, 1);
    ew(IDC_CHK_OTHERSCREENSAVER, 1);
    ew(IDC_CHK_OTHERDISABLEINFO, 1);
    ew(IDC_CHK_OTHERIGNOREINFO, 1);
    ew(IDC_CHK_OTHERDISABLEREGISTER, 1);
    ew(IDC_CHK_OTHERDISABLEUNREGISTER, 1);
    ew(IDC_CHK_OTHERAUTOREVERT, 1);
    ew(IDC_CHK_STANDARDHWID, 1);
    ew(IDC_CHK_ENHANCEDHWID, 1);
    uk(IDC_RADIO_MINIMAL);
    uk(IDC_CHK_IATELIMINATION);
    uk(IDC_RADIO_STANDARD);
    uk(IDC_RADIO_DEBUGBLOCKER);
    uk(IDC_RADIO_COPYMEM2);
    uk(IDC_CHK_CODESPLICING);
    uk(IDC_CHK_NANOMITES);
    uk(IDC_CHK_MEMPROTECTION);
    uk(IDC_RADIO_BACKUPVARIABLE);
    uk(IDC_RADIO_BACKUPFIXED);
    uk(IDC_RADIO_BACKUPMAIN);
    uk(IDC_RADIO_BACKUPNOKEYS);
    uk(IDC_RADIO_COMPRESSIONBEST);
    uk(IDC_RADIO_COMPRESSIONBETTER);
    uk(IDC_RADIO_COMPRESSIONMINIMAL);
    uk(IDC_CHK_OTHERDIGITALRIVER);
    uk(IDC_CHK_OTHERDISABLEUNREGISTER);
    uk(IDC_CHK_OTHERNOCLOCKFORWARD);
    uk(IDC_CHK_OTHERNOCLOCKBACK);
    uk(IDC_CHK_OTHERDONTFALLBACK);
    uk(IDC_CHK_OTHERDISABLEMONITOR);
    uk(IDC_CHK_OTHERDISABLEINFO);
    uk(IDC_CHK_OTHERDISABLEREGISTER);
    uk(IDC_CHK_OTHERAUTOREVERT);
    uk(IDC_CHK_OTHERIGNOREINFO);
    uk(IDC_CHK_OTHERSCREENSAVER);
    uk(IDC_CHK_OTHERESELLERATE);
    uk(IDC_CHK_OTHERALLOWONE);
    uk(IDC_CHK_OTHEREXTERNALENV);
    uk(IDC_RADIO_SPLASHNONE);
    uk(IDC_RADIO_SPLASHDEFAULT);
    uk(IDC_RADIO_SPLASHBITMAP);
    uk(IDC_RADIO_ENHANCEDSOFTICE);
    uk(IDC_RADIO_NORMALNOSOFTICE);
    uk(IDC_CHK_STANDARDHWID);
    uk(IDC_CHK_ENHANCEDHWID);
}

void PrintArmaOptionsStruct(ARMA_OPTIONS* op, char* log)
{
    bool set_other_options_log=false;
    if(op->raw_options)
    {
        ew(IDC_RADIO_DEBUGBLOCKER, 1);
        ew(IDC_RADIO_MINIMAL, 1);
        ew(IDC_RADIO_STANDARD, 1);
        ew(IDC_RADIO_COPYMEM2, 1);
        ew(IDC_CHK_IATELIMINATION, 1);
        ew(IDC_CHK_CODESPLICING, 1);
        ew(IDC_CHK_NANOMITES, 1);
        ew(IDC_CHK_MEMPROTECTION, 1);
        ew(IDC_RADIO_BACKUPNOKEYS, 1);
        ew(IDC_RADIO_BACKUPMAIN, 1);
        ew(IDC_RADIO_BACKUPFIXED, 1);
        ew(IDC_RADIO_BACKUPVARIABLE, 1);
        ew(IDC_RADIO_COMPRESSIONMINIMAL, 1);
        ew(IDC_RADIO_COMPRESSIONBETTER, 1);
        ew(IDC_RADIO_COMPRESSIONBEST, 1);
        ew(IDC_CHK_OTHEREXTERNALENV, 1);
        ew(IDC_CHK_OTHERALLOWONE, 1);
        ew(IDC_CHK_OTHERDISABLEMONITOR, 1);
        ew(IDC_CHK_OTHERESELLERATE, 1);
        ew(IDC_CHK_OTHERDIGITALRIVER, 1);
        ew(IDC_CHK_OTHERDONTFALLBACK, 1);

        sprintf(log, "%s\r\nProtection Options:\r\n", log);
        if(op->debug_blocker)
        {
            if(!op->copymem2)
            {
                ck(IDC_RADIO_DEBUGBLOCKER);
                sprintf(log, "%s>Debug-Blocker\r\n", log);
            }
        }
        else
        {
            if(op->nosectioncrypt)
            {
                ck(IDC_RADIO_MINIMAL);
                sprintf(log, "%s>Minimal Protection\r\n", log);
            }
            else
            {
                ck(IDC_RADIO_STANDARD);
                sprintf(log, "%s>Standard Protection\r\n", log);
            }
        }
        if(op->copymem2)
        {
            ck(IDC_RADIO_COPYMEM2);
            sprintf(log, "%s>Debug-Blocker + CopyMem2\r\n", log);
        }
        if(op->iat_elimination)
        {
            ck(IDC_CHK_IATELIMINATION);
            sprintf(log, "%s>Enable Import Table Elimination\r\n", log);
        }
        if(op->code_splicing)
        {
            ck(IDC_CHK_CODESPLICING);
            sprintf(log, "%s>Enable Strategic Code Splicing\r\n", log);
        }
        if(op->nanomites)
        {
            ck(IDC_CHK_NANOMITES);
            sprintf(log, "%s>Enable Nanomites Processing\r\n", log);
        }
        if(op->mem_patch_protection)
        {
            ck(IDC_CHK_MEMPROTECTION);
            sprintf(log, "%s>Enable Memory-Patching Protections\r\n", log);
        }
        sprintf(log, "%s\r\nBackup Key Options:\r\n", log);
        switch(op->backupkey)
        {
        case BACKUPKEY_NOKEYS:
        {
            ck(IDC_RADIO_BACKUPNOKEYS);
            sprintf(log, "%s>No Registry Keys at All\r\n", log);
        }
        break;
        case BACKUPKEY_NOBACKUP:
        {
            ck(IDC_RADIO_BACKUPMAIN);
            sprintf(log, "%s>Main Key Only, No Backup Keys\r\n", log);
        }
        break;
        case BACKUPKEY_FIXED:
        {
            ck(IDC_RADIO_BACKUPFIXED);
            sprintf(log, "%s>Fixed Backup Keys\r\n", log);
        }
        break;
        case BACKUPKEY_VARIABLE:
        {
            ck(IDC_RADIO_BACKUPVARIABLE);
            sprintf(log, "%s>Variable Backup Keys\r\n", log);
        }
        break;
        }
        sprintf(log, "%s\r\nCompression Options:\r\n", log);
        switch(op->compression)
        {
        case COMPRESSION_MINIMAL:
        {
            ck(IDC_RADIO_COMPRESSIONMINIMAL);
            sprintf(log, "%s>Minimal/Fastest Compression\r\n", log);
        }
        break;
        case COMPRESSION_BETTER:
        {
            ck(IDC_RADIO_COMPRESSIONBETTER);
            sprintf(log, "%s>Better/Slower Compression\r\n", log);
        }
        break;
        case COMPRESSION_BEST:
        {
            ck(IDC_RADIO_COMPRESSIONBEST);
            sprintf(log, "%s>Best/Slowest Compression\r\n", log);
        }
        break;
        }
        if(op->has_other_options)
        {
            sprintf(log, "%s\r\nOther Options:\r\n", log);
            set_other_options_log=true;
            if(op->external_envvars)
            {
                ck(IDC_CHK_OTHEREXTERNALENV);
                sprintf(log, "%s>Store Environment Variables Externally\r\n", log);
            }
            if(op->allow_one_copy)
            {
                ck(IDC_CHK_OTHERALLOWONE);
                sprintf(log, "%s>Allow Only One Copy\r\n", log);
            }
            if(op->disable_monitor)
            {
                ck(IDC_CHK_OTHERDISABLEMONITOR);
                sprintf(log, "%s>Disable Monitoring Thread\r\n", log);
            }
            if(op->esellerate)
            {
                ck(IDC_CHK_OTHERESELLERATE);
                sprintf(log, "%s>Use eSellerate Edition Keys\r\n", log);
            }
            if(op->digital_river)
            {
                ck(IDC_CHK_OTHERDIGITALRIVER);
                sprintf(log, "%s>Use Digital River Edition Keys\r\n", log);
            }
            if(op->dontfallback)
            {
                ck(IDC_CHK_OTHERDONTFALLBACK);
                sprintf(log, "%s>Don't Fall Back to Stand-Alone Mode (Server)\r\n", log);
            }
        }
    }
    else
    {
        ew(IDC_RADIO_DEBUGBLOCKER, 0);
        ew(IDC_RADIO_MINIMAL, 0);
        ew(IDC_RADIO_STANDARD, 0);
        ew(IDC_RADIO_COPYMEM2, 0);
        ew(IDC_CHK_IATELIMINATION, 0);
        ew(IDC_CHK_CODESPLICING, 0);
        ew(IDC_CHK_NANOMITES, 0);
        ew(IDC_CHK_MEMPROTECTION, 0);
        ew(IDC_RADIO_BACKUPNOKEYS, 0);
        ew(IDC_RADIO_BACKUPMAIN, 0);
        ew(IDC_RADIO_BACKUPFIXED, 0);
        ew(IDC_RADIO_BACKUPVARIABLE, 0);
        ew(IDC_RADIO_COMPRESSIONMINIMAL, 0);
        ew(IDC_RADIO_COMPRESSIONBETTER, 0);
        ew(IDC_RADIO_COMPRESSIONBEST, 0);
        ew(IDC_CHK_OTHEREXTERNALENV, 0);
        ew(IDC_CHK_OTHERALLOWONE, 0);
        ew(IDC_CHK_OTHERDISABLEMONITOR, 0);
        ew(IDC_CHK_OTHERESELLERATE, 0);
        ew(IDC_CHK_OTHERDIGITALRIVER, 0);
        ew(IDC_CHK_OTHERDONTFALLBACK, 0);
        //disable all
    }
    if(op->extra_options) //Enable everything
    {
        ew(IDC_RADIO_ENHANCEDSOFTICE, 1);
        ew(IDC_RADIO_NORMALNOSOFTICE, 1);
        ew(IDC_RADIO_SPLASHNONE, 1);
        ew(IDC_RADIO_SPLASHDEFAULT, 1);
        ew(IDC_RADIO_SPLASHBITMAP, 1);
        ew(IDC_CHK_OTHERNOCLOCKBACK, 1);
        ew(IDC_CHK_OTHERNOCLOCKFORWARD, 1);
        ew(IDC_CHK_OTHERSCREENSAVER, 1);
        ew(IDC_CHK_OTHERDISABLEINFO, 1);
        ew(IDC_CHK_OTHERIGNOREINFO, 1);
        ew(IDC_CHK_OTHERDISABLEREGISTER, 1);
        ew(IDC_CHK_OTHERDISABLEUNREGISTER, 1);
        ew(IDC_CHK_OTHERAUTOREVERT, 1);
        ew(IDC_CHK_STANDARDHWID, 1);
        ew(IDC_CHK_ENHANCEDHWID, 1);

        if(!set_other_options_log and op->extra_options->has_other_options)
            sprintf(log, "%s\r\nOther Options:\r\n", log);
        if(op->extra_options->no_clockback)
        {
            ck(IDC_CHK_OTHERNOCLOCKBACK);
            sprintf(log, "%s>Don't Report Clock-Back\r\n", log);
        }
        if(op->extra_options->no_clockforward)
        {
            ck(IDC_CHK_OTHERNOCLOCKFORWARD);
            sprintf(log, "%s>Don't Report Clock-Forward\r\n", log);
        }
        if(op->extra_options->screensaver_protocols)
        {
            ck(IDC_CHK_OTHERSCREENSAVER);
            sprintf(log, "%s>Use Screen Saver Protocols\r\n", log);
        }
        if(op->extra_options->disable_info)
        {
            ck(IDC_CHK_OTHERDISABLEINFO);
            sprintf(log, "%s>Disable INFO command\r\n", log);
        }
        if(op->extra_options->ignore_info)
        {
            ck(IDC_CHK_OTHERIGNOREINFO);
            sprintf(log, "%s>Ignore INFO command\r\n", log);
        }
        if(op->extra_options->disable_register)
        {
            ck(IDC_CHK_OTHERDISABLEREGISTER);
            sprintf(log, "%s>Disable REGISTER command\r\n", log);
        }
        if(op->extra_options->disable_unregister)
        {
            ck(IDC_CHK_OTHERDISABLEUNREGISTER);
            sprintf(log, "%s>Disable UNREGISTER command\r\n", log);
        }
        if(op->extra_options->autorevert)
        {
            ck(IDC_CHK_OTHERAUTOREVERT);
            sprintf(log, "%s>Auto-Revert On Invalid Key\r\n", log);
        }
        if(op->extra_options->standard_hwid)
        {
            ck(IDC_CHK_STANDARDHWID);
            sprintf(log, "%s>Standard Fingerprint in RegDlg\r\n", log);
        }
        if(op->extra_options->enhanced_hwid)
        {
            ck(IDC_CHK_ENHANCEDHWID);
            sprintf(log, "%s>Enhanced Fingerprint in RegDlg\r\n", log);
        }
        sprintf(log, "%s\r\nSoftICE Detection:\r\n", log);
        if(op->extra_options->enhanced_softice)
        {
            ck(IDC_RADIO_ENHANCEDSOFTICE);
            sprintf(log, "%s>Enhanced SoftICE Protection\r\n", log);
        }
        else
        {
            ck(IDC_RADIO_NORMALNOSOFTICE);
            sprintf(log, "%s>Normal/No SoftICE Protection\r\n", log);
        }
        sprintf(log, "%s\r\nSplash Screen:\r\n", log);
        switch(op->extra_options->splash_type)
        {
        case SPLASH_NONE:
        {
            ck(IDC_RADIO_SPLASHNONE);
            sprintf(log, "%s>No Splash Screen\r\n", log);
        }
        break;
        case SPLASH_DEFAULT:
        {
            ck(IDC_RADIO_SPLASHDEFAULT);
            sprintf(log, "%s>Default Splash Screen\r\n", log);
        }
        break;
        case SPLASH_BITMAP:
        {
            ck(IDC_RADIO_SPLASHBITMAP);
            sprintf(log, "%s>Bitmap Splash Screen\r\n", log);
        }
        break;
        }
    }
    else //Disable Everything
    {
        ew(IDC_RADIO_ENHANCEDSOFTICE, 0);
        ew(IDC_RADIO_NORMALNOSOFTICE, 0);
        ew(IDC_RADIO_SPLASHNONE, 0);
        ew(IDC_RADIO_SPLASHDEFAULT, 0);
        ew(IDC_RADIO_SPLASHBITMAP, 0);
        ew(IDC_CHK_OTHERNOCLOCKBACK, 0);
        ew(IDC_CHK_OTHERNOCLOCKFORWARD, 0);
        ew(IDC_CHK_OTHERSCREENSAVER, 0);
        ew(IDC_CHK_OTHERDISABLEINFO, 0);
        ew(IDC_CHK_OTHERIGNOREINFO, 0);
        ew(IDC_CHK_OTHERDISABLEREGISTER, 0);
        ew(IDC_CHK_OTHERDISABLEUNREGISTER, 0);
        ew(IDC_CHK_OTHERAUTOREVERT, 0);
        ew(IDC_CHK_STANDARDHWID, 0);
        ew(IDC_CHK_ENHANCEDHWID, 0);
    }
    if(op->version[0])
        sprintf(log, "%s\r\nVersion Number:\r\n>%s\r\n", log, op->version);
    if(VF_extra_options or VF_raw_options)
        sprintf(log, "%s\r\nRaw Values:", log);
    if(VF_raw_options)
        sprintf(log, "%s\r\n>%.8X (Raw Options)", log, op->raw_options);
    if(VF_extra_options)
        sprintf(log, "%s\r\n>%.8X (Extra Options)", log, op->extra_options->raw_extra_options);
}

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

void FillArmaOptionsStruct(unsigned int raw, const char* ver, ARMA_OPTIONS* op, EXTRA_OPTIONS* eo)
{
    memset(op, 0, sizeof(ARMA_OPTIONS));
    if(eo)
        op->extra_options=eo;
    if(!raw)
        return;
    op->raw_options=raw;
    strcpy(op->version, ver);
    op->nosectioncrypt=VF_minimal;
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
    if(raw&0x3)
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
