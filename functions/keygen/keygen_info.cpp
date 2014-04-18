#include "keygen_info.h"

/*
	-----------------------------------------------
	Key information functions, to take a key apart.
	-----------------------------------------------
*/

int hexdigit(char c)
{
    if(c>='0' && c<='9') return (c-'0');
    else if(c>='a' && c<='f') return (c-'a'+10);
    else if(c>='A' && c<='F') return (c-'A'+10);
    return -1;
}

const char *GetTwoHexDigits(const char *c, unsigned char *value)
{
    int digit1=-1, digit2=-1;
    while(digit1<0)
    {
        if(*c==0) return 0;
        digit1=hexdigit(*c++);
    }
    while(digit2<0)
    {
        if(*c==0) return 0;
        digit2=hexdigit(*c++);
    }
    *value=(unsigned char)((digit1<<4)|digit2);
    return c;
}

char RetrieveKeyInfo(int level_input, const char* name_, unsigned long hardwareID, const char* origkey_, struct KeyInformation* keyinfo, HWND hwndDlg, UINT control_id)
{
    unsigned short keydatecreated=0, keyotherinfo[5]= {0,0,0,0,0};
    unsigned long keytemplateID=0;

    HWND log=(HWND)0;
    char log_msg[1024]="";
    char name[1024]="";
    char serial[1024]="";
    char* origkey=serial;
    strcpy(origkey, origkey_);
    strcpy(name, name_);
    bool firstlog=true;

    bool keystring=false;
    char keystring_text[256]="";

    struct CipherKeyStruct *cipherkey;
    char cooked[512]="";
    int x, v3=0, shortv3=0;
    int level=level_input;

    if(hwndDlg && control_id)
        log=GetDlgItem(hwndDlg, control_id);

    if(level>=14)
    {
        shortv3=1;
        level=level-13;
        //ShortV3 keys can have signature levels 1 through 10 now
        if(level<1 || level>10)
            return 0;
    }
    else if(level>=5)
    {
        v3=1; //TODO: remove?
        level=level-4;
        //V3 keys can now have signature levels 1 through 9
        if(level<1 || level>9)
            return 0;
    }
    else if(level!=0)
    {
        //V2 keys can only have signature levels 1 through 4
        if(level<1 || level>4)
            return 0;
    }

    bool key_appears_nameless=false;
    const char* nameless_check=origkey;
    while(*nameless_check=='0' || *nameless_check=='-')
        nameless_check++;
    if(*nameless_check=='2' && shortv3)
        key_appears_nameless=true;

    if(!name[0] || key_appears_nameless) //nameless key?
    {
        if(!shortv3)
        {
            AddLogMessage(log, "Only ShortV3 Keys can be nameless...", true);
            return 0;
        }
        //remove prepended zero bytes
        while(*origkey=='0' || *origkey=='-')
            origkey++;
        //check for the nameless identifier
        if(*origkey!='2')
        {
            AddLogMessage(log, "Key does not appear to be nameless...", true);
            return 0;
        }
        //retrieve the name
        int count1=0,count2=0;
        for(; count2<6; count1++)
            if(origkey[count1]!='-')
            {
                name[count2]=origkey[count1];
                count2++;
            }
        origkey+=count1;
        sprintf(log_msg, "Nameless Key:\r\nName=%s, Key=%s", name, origkey);
        AddLogMessage(log, log_msg, true);
        firstlog=false;
    }

    if(level==0) ///Analyse unsigned keys
    {
        unsigned long k[2]= {0};
        const char *c=origkey;
        int digits=0;
        char cc;
        while(digits<8 && *c)
        {
            cc=hexdigit(*c++);
            if(cc>=0)
            {
                digits++;
                k[0]=(k[0]<<4)|cc;
            }
        }
        while(digits<16 && *c)
        {
            cc=hexdigit(*c++);
            if(cc>=0)
            {
                digits++;
                k[1]=(k[1]<<4)|cc;
            }
        }
        if(log)
        {
            ByteArray2String((unsigned char*)k, log_msg, sizeof(unsigned long)*2, 20);
            AddLogMessage(log, "Enciphered KeyBytes (Len: 8):", true);
            AddLogMessage(log, log_msg, false);
        }
        CookText(cooked, name);
        cipherkey=CreateCipherKey(cooked, strlen(cooked));
        Decipher(cipherkey, (char*)k, sizeof(unsigned long)*2);
        if(log)
        {
            ByteArray2String((unsigned char*)k, log_msg, sizeof(unsigned long)*2, 20);
            AddLogMessage(log, "Deciphered KeyBytes:", false);
            AddLogMessage(log, log_msg, false);
        }
        ReleaseCipherKey(cipherkey);
        keytemplateID=k[0];
        keydatecreated=(unsigned short)(k[1]>>16);
        keyotherinfo[0]=(unsigned short)(k[1]&0xFFFF);
    }
    else
    {
        char keybytes_[512], signature[512], *kb=keybytes_, *keybytes=keybytes_, *k1, *k2;
        int keylength, siglength;
        if(shortv3)
        {
            const char* udigits="0123456789ABCDEFGHJKMNPQRTUVWXYZ";
            const char* ldigits="0123456789abcdefghjkmnpqrtuvwxyz";
            const char* c=origkey;
            const char* p;
            unsigned char value=0;
            unsigned char firstdigit=1;
            BigInt n, n2, n3;
            n=BigInt_Create();
            n2=BigInt_Create();
            n3=BigInt_Create();
            if(origkey==0 || origkey[0]==0)
            {
                return 0;
            }
            while(c[0])
            {
                p=strchr(udigits, c[0]); //first the current serial character in udigits
                if(p)
                {
                    value=p-udigits;
                }
                else
                {
                    p=strchr(ldigits, c[0]); //first the current character in ldigits
                    if(p)
                    {
                        value=p-ldigits;
                    }
                    else if(c[0]=='i' || c[0]=='I' || c[0]=='l' || c[0]=='L')
                    {
                        value=1;
                    }
                    else if(c[0]=='o' || c[0]=='O')
                    {
                        value=0;
                    }
                    else if(c[0]=='s' || c[0]=='S')
                    {
                        value=5;
                    }
                    else
                    {
                        value=32;
                    }
                }
                c++;
                if(value<32) //must be base32
                {
                    if(firstdigit) //ignore the first key character
                    {
                        if(level==10)
                        {
                            /* All level 10 keys start with the digit 1. It
                            doesn't convey any information other than the fact
                            that they're level 10 keys; discard it. */
                            //KeyString starts with 3
                            if(value==3)
                            {
                                value=0;
                                keystring=true;
                            }
                            if(value!=0)
                            {
                                value=0;
                                firstdigit=0;
                            }
                        }
                        else
                        {
                            //KeyString starts with 3
                            if(value==3)
                            {
                                value=0;
                                keystring=true;
                            }
                            if(value!=0 && value>=16)
                            {
                                value-=16;
                                firstdigit=0;
                            }
                        }
                    }
                    BigInt_Shift(n, 5, n2);
                    BigInt_SetU(n3, value);
                    BigInt_Add(n2, n3, n);
                }
            }
            //Spit out the bytes, in reverse order.
            BigInt_Set(n3, 0xFF);
            if(level==10)
            {
                while(BigInt_Compare(n, BigInt_One())>0)
                {
                    BigInt_And(n, n3, n2);
                    kb[0]=(unsigned char)BigInt_GetU(n2);
                    kb++;
                    BigInt_Shift(n, -8, n2);
                    BigInt_Copy(n, n2);
                }
            }
            else
            {
                while(BigInt_Compare(n, BigInt_Zero())!=0)
                {
                    BigInt_And(n, n3, n2);
                    kb[0]=(unsigned char)BigInt_GetU(n2);
                    kb++;
                    BigInt_Shift(n, -8, n2);
                    BigInt_Copy(n, n2);
                }
            }

            if((kb-keybytes)%2) //if the length / 2 has a remainder
            {
                kb[0]=0; //discard last byte?
                kb++;
            }
            /* Reverse digits in keybytes */
            k1=keybytes;
            k2=kb-1;
            while(k1<k2)
            {
                char t=k1[0];
                k1[0]=k2[0];
                k2[0]=t;
                k2--;
                k1++;
            }
            BigInt_Destroy(n3);
            BigInt_Destroy(n2);
            BigInt_Destroy(n);
        }
        else //signed v2 and signed v3
        {
            const char* c=origkey;
            unsigned char value;
            while(c && c[0])
            {
                c=GetTwoHexDigits(c, &value);
                if(c)
                {
                    kb[0]=(char)value;
                    kb++;
                }

            }
        }
        keylength=kb-keybytes;
        int keylength_full=keylength;
        /* Strip off signature here. For ShortV3 Level 10 keys, the signature
        will be the last 28 bytes, always. For earlier keys, it will be the
        last 6+(level*2) bytes. */
        if(level==10 && shortv3==1)
        {
            siglength=28;
        }
        else
        {
            siglength=(level*2)+6;
        }
        memcpy(signature, keybytes+(keylength-siglength), siglength);
        keylength-=siglength;

        if(keylength<6)
        {
            AddLogMessage(log, "Keylength must be bigger then five...", true);
            return 0;
        }

        if(keystring) //skip first zero byte
        {
            if(!keybytes[0] && keybytes[1])
            {
                keybytes++;
                keylength--;
            }
        }

        sprintf(log_msg, "Decoded Key (%d, 0x%X Bytes):", keylength_full, keylength_full);
        AddLogMessage(log, log_msg, firstlog);
        ByteArray2String((unsigned char*)keybytes, log_msg, keylength_full, 1024);
        AddLogMessage(log, log_msg, false);

        sprintf(log_msg, "Signature (%d, 0x%X Bytes):", siglength, siglength);
        AddLogMessage(log, log_msg, false);
        ByteArray2String((unsigned char*)signature, log_msg, siglength, 1024);
        AddLogMessage(log, log_msg, false);

        sprintf(log_msg, "Encrypted KeyBytes (Len: %d, 0x%X):", keylength, keylength);
        AddLogMessage(log, log_msg, false);
        ByteArray2String((unsigned char*)keybytes, log_msg, keylength, 1024);
        AddLogMessage(log, log_msg, false);

        //Decrypt the rest of the key
        CookText(cooked, name);
        unsigned int seed_array=crc32(cooked, strlen(cooked), NewCRC32);
        InitRandomGenerator(seed_array);
        sprintf(log_msg, "NextRandomRange Array (Seed=%.8X):\r\n", seed_array);
        int y;
        for(x=0,y=0; x<keylength; x++)
        {
            unsigned char ran=(unsigned char)(NextRandomRange(256)&0xFF);
            keybytes[x]^=ran;
            y+=sprintf(log_msg+y, "%.2X", ran);
        }
        AddLogMessage(log, log_msg, false);

        AddLogMessage(log, "Decrypted KeyBytes:", false);
        ByteArray2String((unsigned char*)keybytes, log_msg, keylength, 1024);
        AddLogMessage(log, log_msg, false);

        //Assign bytes to their proper locations.
        kb=keybytes;

        if(keystring)
        {
            int keystring_size=0;
            memcpy(&keystring_size, &kb[keylength-1], 1); //Safe conversion of the size
            for(x=0; x<keystring_size; x++)
                keystring_text[x]=kb[keylength-2-x];
            keylength-=keystring_size+1;
            sprintf(log_msg, "KeyString Bytes (Len: %d, 0x%X):", keystring_size+1, keystring_size+1);
            AddLogMessage(log, log_msg, false);
            _strrev(keystring_text);
            ByteArray2String((unsigned char*)keystring_text, log_msg, keystring_size, 1024);
            _strrev(keystring_text);
            sprintf(log_msg, "%s%.2X", log_msg, keystring_size);
            AddLogMessage(log, log_msg, false);
        }

        if(keylength>14)
        {
            for(x=0; x<2; x++)
            {
                keyotherinfo[4]=keyotherinfo[4]<<8;
                keyotherinfo[4]|=(unsigned char)kb[0];
                kb++;
            }
        }
        if(keylength>12)
        {
            for(x=0; x<2; x++)
            {
                keyotherinfo[3]=keyotherinfo[3]<<8;
                keyotherinfo[3]|=(unsigned char)kb[0];
                kb++;
            }
        }
        if(keylength>10)
        {
            for(x=0; x<2; x++)
            {
                keyotherinfo[2]=keyotherinfo[2]<<8;
                keyotherinfo[2]|=(unsigned char)kb[0];
                kb++;
            }
        }
        if(keylength>8)
        {
            for(x=0; x<2; x++)
            {
                keyotherinfo[1]=keyotherinfo[1]<<8;
                keyotherinfo[1]|=(unsigned char)kb[0];
                kb++;
            }
        }
        if(keylength>6)
        {
            for(x=0; x<2; x++)
            {
                keyotherinfo[0]=keyotherinfo[0]<<8;
                keyotherinfo[0]|=(unsigned char)kb[0];
                kb++;
            }
        }
        for(x=0; x<2; x++)
        {
            keydatecreated=keydatecreated<<8;
            keydatecreated|=(unsigned char)kb[0];
            kb++;
        }
        for(x=0; x<4; x++)
        {
            keytemplateID=keytemplateID<<8;
            keytemplateID|=(unsigned char)kb[0];
            kb++;
        }
    }

    //Fill in the KeyInformation struct, if supplied.
    if(keyinfo)
    {
        keyinfo->symkey=keytemplateID^hardwareID;
        InterpretDate(keydatecreated, &keyinfo->createdyear, &keyinfo->createdmonth, &keyinfo->createdday);
        if(log)
        {
            sprintf(log_msg, "Raw datecreated value:\r\n%d (0x%.4X)", keydatecreated, keydatecreated);
            AddLogMessage(log, log_msg, false);
        }
        for(x=0; x<5; x++)
        {
            keyinfo->otherinfo[x]=keyotherinfo[x];
        }
        keyinfo->keystring_length=strlen(keystring_text);
        strcpy(keyinfo->keystring, keystring_text);

        //Generate UninstallCode
        CookText(cooked, name);
        strcat(cooked, origkey);
        keyinfo->uninstallcode=crc32(cooked, strlen(cooked), NewCRC32);
    }
    return 1;
}
