#include "keygen_main.h"


const int primeoffsetcount=9, primeoffsets[]= { 15, 15, 21, 81, 3103, 3643, 2191, 9691, 2887 };

/*
	---------
	CreateKey
	---------

	This is the only function that needs to be externally visible for unsigned
	keys. The "regname" parameter is the name of the person to make the key for;
	it's used as the encryption key for the other information.

	The "keytext" parameter is the "encryption template" for the appropriate
	security certificate -- see the Armadillo documentation for details.

	The "otherinfo" parameter can specify the number of days and/or uses this
	key permits, or the expiration date of the key (in days since 01Jan1999),
	or the version number to expire on, or the number of copies to allow. The
	meaning depends on the certificate. In most cases, the certificate itself
	will specify values for these parameters, and you can leave this at zero.
	If the certificate specifies values for these parameters, the "otherinfo"
	is ignored.

	hardwareID is used only for hardware-locked certificates, and can be set to
	zero for anything else.

	The only cautions for this function... it expects both "regname" and
	"keytext" to be less than 256 bytes, in the calls to CookText(). You may
	wish to confirm that before calling CreateKey().

	To confirm it: CreateKey("Chad Nelson", "Testing", 14, 0) should return a
	key of F806-3E6F-0A27-D091 on 20Jan1999.
*/

const char* CreateKey(unsigned int symmetric_key, unsigned int sym_xor, const char* regname, unsigned short otherinfo, unsigned long hardwareID, short today, HWND log)
{
    static char returntext[25];
    CipherKey *cipherkey;
    unsigned long k[2];
    char cooked[2048]="";
    bool first_log=true;

    char log_msg[1024]="";

    if(*regname==0)
    {
        AddLogMessage(log, "This level does not support nameless keys...", true);
        return "";
    }

    k[0]=symmetric_key;
    if(sym_xor)
    {
        AddLogMessage(log, "Symmetric key changes:", true);
        sprintf(log_msg, "%.8X^%.8X=%.8X (sym^xorval=newsym)", (unsigned int)k[0], (unsigned int)sym_xor, (unsigned int)(k[0]^sym_xor));
        AddLogMessage(log, log_msg, false);
        k[0]^=sym_xor;
        first_log=false;
    }
    if(hardwareID)
    {
        if(first_log)
            AddLogMessage(log, "Symmetric key changes:", true);
        sprintf(log_msg, "%.8X^%.8X=%.8X (sym^hwid=newsym)", (unsigned int)k[0], (unsigned int)hardwareID, (unsigned int)(k[0]^hardwareID));
        AddLogMessage(log, log_msg, false);
        k[0]^=hardwareID;
        first_log=false;
    }
    k[1]=(today<<16)|otherinfo;

    ByteArray2String((unsigned char*)k, cooked, 2*sizeof(unsigned long), 2048);
    sprintf(log_msg, "KeyBytes: (Len: 8)\r\n%s", cooked);
    AddLogMessage(log, log_msg, first_log);
    cooked[0]=0;

    /* Encrypt the key information */
    CookText(cooked, regname);
    sprintf(log_msg, "Cooked name (Len: %d, 0x%X):\r\n%s", strlen(cooked), strlen(cooked), cooked);
    AddLogMessage(log, log_msg, false);

    cipherkey=CreateCipherKey(cooked, strlen(cooked));
    Encipher(cipherkey, (char*)k, 2*sizeof(unsigned long));
    ReleaseCipherKey(cipherkey);

    ByteArray2String((unsigned char*)k, cooked, 2*sizeof(unsigned long), 2048);
    sprintf(log_msg, "Enciphered KeyBytes:\r\n%s", cooked);
    AddLogMessage(log, log_msg, false);
    cooked[0]=0;

    /* Format and return it! */
    wsprintfA(returntext, "%04X-%04X-%04X-%04X", k[0]>>16, k[0]&0xFFFF, k[1]>>16, k[1]&0xFFFF);
    return returntext;
}

unsigned char *AddByte(unsigned char *c, unsigned char n)
{
    *c++=n;
    return c;
}

unsigned char *AddShort(unsigned char *c, unsigned short n)
{
    *c++=(unsigned char)(n>>8);
    *c++=(unsigned char)(n&0xFF);
    return c;
}

unsigned char *AddLong(unsigned char *c, unsigned long n)
{
    *c++=(unsigned char)(n>>24);
    *c++=(unsigned char)(n>>16);
    *c++=(unsigned char)(n>>8);
    *c++=(unsigned char)(n&0xFF);
    return c;
}

void mystrrev(char *str)
{
    /*
    ** strrev() apparently isn't part of the standard C library, or at least
    ** isn't supported on all platforms, because I've had reports that it
    ** isn't available on some. So I wrote this function to replace it.
    */

    char tmp, *s1, *s2;
    s1=str;
    s2=strchr(str, 0)-1;
    while(s1<s2)
    {
        tmp=*s1;
        *s1=*s2;
        *s2=tmp;
        ++s1;
        --s2;
    }
}

CRC32 GetKeyCRC(char *keytext, int period)
{
    char cooked[2048], temp[2048], *s, *t;
    int x, y, len;

    CookText(cooked, keytext);
    if(period==1)
    {
        /* Just reverse the string. strrev() is apparently not supported on
        some CGI systems, so I've written my own version here. */
        strcpy(temp, cooked);
        t=cooked;
        s=strchr(temp, 0)-1;
        while(s>=temp) *t++=*s--;
        *t=0;
    }
    else if(period>1)
    {
        /* Start at the beginning and split the keytext into groups of 'period'
        letters. Reverse each group. */
        strcpy(temp, cooked);
        t=cooked;
        len=strlen(cooked);
        for(x=0; x<(len/period); ++x)
        {
            s=temp+(x*period);
            for(y=period-1; y>=0; --y) *t++=*(s+y);
        }

        /* Now reverse the last group, if there are any characters that haven't
        been handled yet. */
        if((len%period)!=0)
        {
            s=temp+len-1;
            for(y=0; y<len%period; ++y) *t++=*(s-y);
        }

        *t=0;
    }
    return crc32(cooked, strlen(cooked), NewCRC32);
}

void GetKeyMD5(unsigned long *i, const char *keytext, int period)
{
    char cooked[2048];
    int len, x, y;

    CookText(cooked, keytext);
    if(period==1)
    {
        mystrrev(cooked);
    }
    else if(period>1)
    {
        /*
        ** Start at the beginning and split the keytext into groups of 'period'
        ** letters. Reverse each group.
        */
        char temp[2048], *s, *t;

        strcpy(temp, cooked);
        t=cooked;
        len=strlen(cooked);
        for(x=0; x<(len/period); ++x)
        {
            s=temp+(x*period);
            for(y=period-1; y>=0; --y) *t++=*(s+y);
        }

        /*
        ** Now reverse the last group, if there are any characters that haven't
        ** been handled yet.
        */
        if((len%period)!=0)
        {
            s=temp+len-1;
            for(y=0; y<len%period; ++y) *t++=*(s-y);
        }
        *t=0;
    }
    md5(i, cooked, strlen(cooked));
}

void GenerateKeyNumberFromString(char *string, BigInt p, BigInt *keynumber, int keysystem, int v3level)
{
    unsigned long i[4], current[4]= {0,0,0,0};
    BigInt n, n2, n3, exp;
    int x, y;

    n=BigInt_Create();

    if(keysystem==KS_SHORTV3)
    {
        /* The ShortV3 key system uses shorter numbers than the standard v3
        system, but longer ones than the v2 system. ShortV3 numbers are also
        generated using MD5 instead of CRC32. */
        for(x=0; x<4; ++x)
        {
            GetKeyMD5(i, string, x+2);
            for(y=0; y<4; ++y) current[y]^=i[y];
        }

        n2=BigInt_Create();
        n3=BigInt_Create();

        for(x=0; x<4; ++x)
        {
            BigInt_Shift(n, 32, n2);
            BigInt_SetU(n3, current[x]);
            BigInt_Add(n2, n3, n);
        }

        BigInt_Modulus(n, p, *keynumber);

        BigInt_Destroy(n3);
        BigInt_Destroy(n2);
    }
    else if(keysystem==KS_V3)
    {
        /* v2 keys are based on 32 bit numbers; v3 keys use much larger ones,
        32 additional bits per level. */
        n2=BigInt_Create();
        n3=BigInt_Create();
        exp=BigInt_Create();

        BigInt_SetU(n, GetKeyCRC(string, 1));
        BigInt_Copy(exp, n);
        for(x=0; x<v3level; ++x)
        {
            BigInt_Shift(n, 32, n2);
            BigInt_SetU(n3, GetKeyCRC(string, x+2));
            BigInt_Add(n2, n3, n);
        }
        BigInt_PowerModulus(n, exp, p, *keynumber);

        BigInt_Destroy(exp);
        BigInt_Destroy(n3);
        BigInt_Destroy(n2);
    }
    else
    {
        /* V2 keys */
        BigInt_SetU(n, GetKeyCRC(string, 1));
        BigInt_PowerModulus(n, n, p, *keynumber);
    }
    BigInt_Destroy(n);
}

int MakeEccSignature(unsigned char *keybytes, int *keylength, char *name_to_make_key_for, int level, char* prvt_text, char* public_text, bool baboon, HWND log)
{
    EC_PARAMETER Base;
    EC_KEYPAIR Signer;
    SIGNATURE signature;
    char tmp[2048], tmp2[2048], encryption_template[2048], log_msg[1024]="";
    unsigned long x, basepointinit;
    unsigned char *c;
    BigInt stemp=BigInt_Create();
    BigInt stemp2=BigInt_Create();
    BigInt stemp3=BigInt_Create();
    BigInt stemp4=BigInt_Create();

    /* Level 29 (ShortV3 Level 10) is the only level that uses this format. */
    if(level!=29)
        return 0;

    /* Create the message to be signed. That will be the current contents of
    'keybytes' plus the name we're making the key for, not including the
    terminating null. */
    CookText(tmp, name_to_make_key_for);
    sprintf(log_msg, "Cooked Name (Len: %d, 0x%X):\r\n%s", strlen(tmp), strlen(tmp), tmp);
    AddLogMessage(log, log_msg, false);

    memcpy(tmp2, keybytes, *keylength);
    memcpy(tmp2+(*keylength), tmp, strlen(tmp));

    int msg_len=*keylength+strlen(tmp);
    sprintf(log_msg, "Message (Len: %d, 0x%X):", msg_len, msg_len);
    AddLogMessage(log, log_msg, false);
    ByteArray2String((unsigned char*)tmp2, log_msg, msg_len, 1024);
    AddLogMessage(log, log_msg, false);
    int old_keylen=*keylength;

    if(!baboon)
    {
        /* Initialize the ECC system with the base-point and cooked encryption
        template. */
        char basepoint_text[10]="";
        char pubx[100]="", puby[100]="";
        char* pubs=public_text;

        while(*pubs!=',')
        {
            sprintf(basepoint_text, "%s%c", basepoint_text, *pubs);
            pubs++;
        }
        pubs++;
        while(*pubs!=',')
        {
            sprintf(pubx, "%s%c", pubx, *pubs);
            pubs++;
        }
        pubs++;
        strcpy(puby, pubs);

        sscanf(basepoint_text, "%lu", &basepointinit);

        ECC_Initialize(&Base, &Signer, basepointinit, encryption_template, prvt_text, pubx, puby);

        /* Create the signature. */
        BigInt_Set(stemp, 1);
        BigInt_Shift(stemp, 112, stemp4);
        while(1)
        {
            ECC_MakeSignature(tmp2, msg_len, &Base, &Signer.prvt_key, &signature, log);

            /* The signature is now in two FIELDs. Convert them to a single
            BigNumber and write it into the key. I'm reserving 112 bits for each,
            the exact amount that should be needed... we should probably allow for
            113, to be on the safe side, but 112 comes out to an even 28 bytes of
            signature. To ensure that everything fits, we'll check the signature
            parts after we create them, and try again with a different random point
            if either of them are too big. */
            FieldToBigInt(&signature.c, stemp3);
            if(BigInt_Compare(stemp3, stemp4)>0)
                continue;
            BigInt_Shift(stemp3, 112, stemp2);
            FieldToBigInt(&signature.d, stemp3);
            if(BigInt_Compare(stemp3, stemp4)>0)
                continue;
            BigInt_Add(stemp3, stemp2, stemp);
            break;
        }

        c=keybytes+(*keylength);
        BigInt_Set(stemp3, 0xFF);
        for(x=0; x<28; ++x)
        {
            BigInt_And(stemp, stemp3, stemp2);
            c=AddByte(c, (unsigned char)BigInt_GetU(stemp2));
            BigInt_Shift(stemp, -8, stemp2);
            BigInt_Copy(stemp, stemp2);
        }
        *keylength=(c-keybytes);
    }
    else
    {
        String2ByteArray("73EA6DAF91BFFDFFFFFFFFFFFFFF192B24A1DC800400000000000000", keybytes+old_keylen, 28);
        *keylength+=28;
    }

    AddLogMessage(log, "Signature (Len: 28, 0x1C):", false);
    ByteArray2String(keybytes+old_keylen, log_msg, 28, 1024);
    AddLogMessage(log, log_msg, false);

    BigInt_Destroy(stemp4);
    BigInt_Destroy(stemp3);
    BigInt_Destroy(stemp2);
    BigInt_Destroy(stemp);
    return 1;
}

int MakeSignature(unsigned char *keybytes, int *keylength, char *name_encryptkey, int level, char* pvt_kg_txt, char* y_kg_txt, bool baboon, HWND log)
{
    BigInt message, p, p1, pub, pvt, y, temp, temp2, temp3, a, b, k, c1, c2;
    char tmp[2048], tmp2[2048];
    int size, x, keysystem;
    unsigned long i[4], ksource=0;
    unsigned char *c;
    CRC32 crc;
    char log_msg[1024]="";

    /* What kind of key is it? */
    if(level==29)
    {
        /* If the signature level is 29, it's ShortV3 Level 10. That level is
        different from other signed keys; it uses ECC-DSA for the signature,
        rather than standard Elgamal. */
        return MakeEccSignature(keybytes, keylength, name_encryptkey, level, pvt_kg_txt, y_kg_txt, baboon, log);
    }
    else if(level>=20)
    {
        keysystem=KS_SHORTV3;
        level=level-20;
        /* Standard ShortV3 keys can have signature levels 1 through 9 (or
        rather, 0..8) */
        if(level>8)
            return 0;
    }
    else if(level>=10)
    {
        keysystem=KS_V3;
        level=level-10;
        /* V3 keys can now have signature levels 1 through 9 (or rather, 0..8) */
        if(level>8)
            return 0;
    }
    else
    {
        /* V2 keys can only have signature levels 1 through 4 (or rather, 0..3) */
        keysystem=KS_V2;
        if(level<0 || level>3)
            return 0;
    }
    size=level+4;

    message=BigInt_Create();
    p=BigInt_Create();
    p1=BigInt_Create();
    pub=BigInt_Create();
    pvt=BigInt_Create();
    y=BigInt_Create();
    temp=BigInt_Create();
    temp2=BigInt_Create();
    temp3=BigInt_Create();
    a=BigInt_Create();
    b=BigInt_Create();
    k=BigInt_Create();
    c1=BigInt_Create();
    c2=BigInt_Create();

    /*
    ** First we make the "message" that we're going to use. This is much larger
    ** for v3 keys than it was previously. ShortV3 keys sign the MD5 of the
    ** message instead of the message itself -- more efficient that way.
    */
    CookText(tmp, name_encryptkey);
    sprintf(log_msg, "Cooked Name (Len: %d, 0x%X):\r\n%s", strlen(tmp), strlen(tmp), tmp);
    AddLogMessage(log, log_msg, false);

    if(keysystem==KS_SHORTV3)
    {
        memcpy(tmp2, keybytes, *keylength);
        memcpy(tmp2+(*keylength), tmp, strlen(tmp));
        md5(i, tmp2, (*keylength)+strlen(tmp));
        for(x=0; x<4; ++x)
        {
            BigInt_Shift(message, 32, temp2);
            BigInt_SetU(temp3, i[x]);
            BigInt_Add(temp2, temp3, message);
        }
    }
    else if(keysystem==KS_V3)
    {
        BigInt_SetU(message, crc32((char *)keybytes, *keylength, NewCRC32));
        for(x=0; x<level+1; ++x)
        {
            BigInt_Shift(message, 32, temp2);
            BigInt_SetU(temp3, GetKeyCRC(tmp, x));
            BigInt_Add(temp2, temp3, message);
        }
    }
    else
    {
        crc=crc32(tmp, strlen(tmp), NewCRC32);
        crc=crc32((char *)keybytes, *keylength, crc);
        BigInt_SetU(message, crc);
    }
    AddLogMessage(log, "Signature message:", false);
    BigInt_ToString(message, 16, log_msg);
    AddLogMessage(log, log_msg, false);

    /* Now we grab a large prime number. Armadillo uses several precalculated
    primes, based on the level (size). */
    BigInt_Set(temp, 1);
    BigInt_Shift(temp, size*8, p);
    BigInt_Set(temp, primeoffsets[level]);
    BigInt_Add(p, temp, temp2);
    BigInt_Copy(p, temp2);
    BigInt_Subtract(p, BigInt_One(), p1);
    /*BigNumber(2).Power((level+4)*8)+primeoffsets[level];*/
    AddLogMessage(log, "Large prime number:", false);
    BigInt_ToString(p, 16, log_msg);
    AddLogMessage(log, log_msg, false);

    /* Generate the public and private keys, and the 'y' value */
    sprintf(tmp, "%u Level Public Key", level);

    GenerateKeyNumberFromString(tmp, p, &pub, keysystem, ((keysystem==KS_V3 || keysystem==KS_SHORTV3) ? level+1 : 0));
    AddLogMessage(log, "Public Key:", false);
    BigInt_ToString(pub, 16, log_msg);
    AddLogMessage(log, log_msg, false);

    GenerateKeyNumberFromString(tmp, p, &pvt, keysystem, ((keysystem==KS_V3 || keysystem==KS_SHORTV3) ? level+1 : 0));
    BigInt_FromString(pvt_kg_txt, 16, pvt);
    BigInt_PowerModulus(pub, pvt, p, y);
    BigInt_FromString(y_kg_txt, 16, y);

    /* Get random value for k -- must remain secret! Prepare to repeat if necessary. */
    if(!ksource)
        ksource=GetRandomSeed();
    sprintf(tmp, "%.8X", (unsigned int)ksource);

    sprintf(log_msg, "Random Seed:\r\n%s", tmp);
    AddLogMessage(log, log_msg, false);

    while(1)
    {
        BigInt_Set(temp, 0);
        for(x=0; x<5; ++x)
        {
            BigInt_Shift(temp, 4, temp2);
            BigInt_SetU(temp3, GetKeyCRC(tmp, x+2));
            BigInt_Add(temp2, temp3, temp);
        };
        BigInt_Modulus(temp, p, k); /* Make sure it's less than 'p' */

        /* If k and p1 have a common factor, it won't work. Check for it. */
        while(1)
        {
            BigInt_GCD(k, p1, temp);
            if(BigInt_Compare(temp, BigInt_One())==0)
                break;

            BigInt_Add(k, BigInt_One(), temp);
            BigInt_Copy(k, temp);
            if(BigInt_Compare(k, p)>=0)
                BigInt_Set(k, 3);
        }

        /* Make signature, 'a' and 'b' parts. */
        BigInt_PowerModulus(pub, k, p, a);
        BigInt_Multiply(pvt, a, temp);
        BigInt_Subtract(message, temp, temp2); /*temp2=(message-(pvt*a))*/
        BigInt_ModularInverse(k, p1, b); /*b=ModularInverse(k, p-1)*/

        /* Check it! We shouldn't have to, but there used to be a rare bug in
        the BigInt_ModularInverse function... about one out of every 224 times,
        it would return an inverse that wasn't right. Should be fixed now, so
        this code shouldn't be necessary, but it doesn't impact the speed very
        much, so we've left it in here as a "belt and suspenders" fix. */

        BigInt_Multiply(k, b, temp);
        BigInt_Modulus(temp, p1, temp3);
        if(!BigInt_Compare(temp3, BigInt_One())==0)
        {
#ifdef DEBUG
            printf("ModularInverse returned the wrong answer!\n");
            BigInt_Dump(k, "k");
            BigInt_Dump(p1, "p1");
#endif
            continue;
        }
        BigInt_Multiply(b, temp2, temp); /*temp=b*temp2*/
        BigInt_Modulus(temp, p1, b); /*b=temp%(p-1)*/
        /*b=((message-(pvt*a))*BigNumber::ModularInverse(k, p-1)).Mod(p-1);*/

        /* Check the size of the parts. */
        BigInt_Set(temp, 256);
        BigInt_Shift(BigInt_One(), size*8, temp2);
        if(BigInt_Compare(a, temp)>=0 && BigInt_Compare(a, temp2)<0 && BigInt_Compare(b, temp)>=0 && BigInt_Compare(b, temp2)<0)
        {
            /* Check the signature, to ensure it's okay. Not needed, it's just
            here for debugging purposes. */
            /*
            BigInt_PowerModulus(y, a, p, c1);
            BigInt_PowerModulus(a, b, p, temp);
            BigInt_Multiply(temp, c1, temp2);
            BigInt_Modulus(temp2, p, c1);
            BigInt_PowerModulus(pub, message, p, c2);
            if (BigInt_Compare(c1, c2)==0) {
            	printf("Signature good!\n");
            	break;
            } else printf("Signature error!\n");
            */
            break;
        }
    }

    int oldkeylen=*keylength;

    /* Write the signature into the key */
    c=keybytes+(*keylength);
    BigInt_Set(temp2, 0xFF);
    for(x=0; x<size; x++)
    {
        BigInt_And(a, temp2, temp);
        c=AddByte(c, (unsigned char)BigInt_GetU(temp));
        BigInt_Shift(a, -8, temp);
        BigInt_Copy(a, temp);

        BigInt_And(b, temp2, temp);
        c=AddByte(c, (unsigned char)BigInt_GetU(temp));
        BigInt_Shift(b, -8, temp);
        BigInt_Copy(b, temp);
    }
    *keylength=(c-keybytes);
    int siglen=*keylength-oldkeylen;
    sprintf(log_msg, "Signature (Len: %d, 0x%X):", siglen, siglen);
    AddLogMessage(log, log_msg, false);
    ByteArray2String(keybytes+oldkeylen, log_msg, siglen, 1024);
    AddLogMessage(log, log_msg, false);

    BigInt_Destroy(c2);
    BigInt_Destroy(c1);
    BigInt_Destroy(k);
    BigInt_Destroy(b);
    BigInt_Destroy(a);
    BigInt_Destroy(temp3);
    BigInt_Destroy(temp2);
    BigInt_Destroy(temp);
    BigInt_Destroy(y);
    BigInt_Destroy(pvt);
    BigInt_Destroy(pub);
    BigInt_Destroy(p1);
    BigInt_Destroy(p);
    BigInt_Destroy(message);
    return 1;
}

void EncryptSignedKey(unsigned char *keybytes, int keylength, char *encryptkey, HWND log)
{
    char tmp[2048]="";
    char log_msg[1024]="";
    CookText(tmp, encryptkey);
    unsigned int seed=crc32(tmp, strlen(tmp), NewCRC32);
    InitRandomGenerator(seed);
    tmp[0]=0;
    for(int x=0; x<keylength; x++)
    {
        int nextran=NextRandomRange(256);
        keybytes[x]^=nextran;
        if(log)
            sprintf(tmp, "%s%.2X", tmp, nextran);
    }
    if(log)
    {
        sprintf(log_msg, "NextRandomRange Array (Seed=%.8X)\r\n%s", seed, tmp);
        AddLogMessage(log, log_msg, false);
    }
}

const char* CreateSignedKey(int level, unsigned int symmetric_key, unsigned int sym_xor, char* pvt_kg_txt, char* y_kg_txt, char* keystring, short today, char* _name_to_make_key_for, unsigned long hardwareID, unsigned short otherinfo1, unsigned short otherinfo2, unsigned short otherinfo3, unsigned short otherinfo4, unsigned short otherinfo5, bool baboon, HWND log)
{
    static char retval[1024]="";
    char name_to_make_key_for[1024]="", *cc, *cc2, *shortv3digits=(char*)"0123456789ABCDEFGHJKMNPQRTUVWXYZ";
    int otherinfocount, x, nn, dcount, keylength=0, nameless=0, retval_add=0;
    unsigned long symmetrickey;
    unsigned char *c, keybytes[512]= {0};
    BigInt n, t1, t2;
    bool useskeystring=false;
    bool first_log=true;
    char log_msg[1024]="";
    char keystr[256]="";
    char temp[1024]="";

    /* Make a copy of the name -- might not be safe to change the original. */
    if(_name_to_make_key_for)
        strcpy(name_to_make_key_for, _name_to_make_key_for);
    else
        strcpy(name_to_make_key_for, "");

    /* If the signature level is less than zero, he wants to make a v1
    (unsigned) key. Route the call to that function instead, and ignore the
    parameters that aren't used in that type. */
    if(level<0)
        return CreateKey(symmetric_key, sym_xor, name_to_make_key_for, otherinfo1, hardwareID, today, log);

    //CookText(temp, encryption_template);
    if(level>=20)
    {
        //ShortV3 format
        //GetKeyMD5(i, temp, 0);
        ///Inject Symmetric Key here...
        symmetrickey=symmetric_key;

        //Is this a "nameless" key? If so, make up a name for it.
        if(*name_to_make_key_for==0)
        {
            nameless=1;
            nn=strlen(shortv3digits);
            cc=name_to_make_key_for;
            *cc++='2';
            for(x=0; x<5; ++x)
                *cc++=shortv3digits[NextRandomRange(nn)];
            *cc++=0;
        }
    }
    else
    {
        /* V2 or conventional V3 format */
        ///Inject Symmetric Key here...
        symmetrickey=symmetric_key;

        if(*name_to_make_key_for==0)
        {
            /* Can't make nameless keys for any other format. */
            AddLogMessage(log, "This level does not support nameless keys...", true);
            return "";
        }
    }

    //Symmetric key mod
    if(sym_xor)
    {

        AddLogMessage(log, "Symmetric key changes:", true);
        sprintf(log_msg, "%.8X^%.8X=%.8X (sym^xorval=newsym)", (unsigned int)symmetrickey, (unsigned int)sym_xor, (unsigned int)(symmetrickey^sym_xor));
        AddLogMessage(log, log_msg, false);
        symmetrickey^=sym_xor;
        first_log=false;
    }
    if(hardwareID)
    {
        if(first_log)
            AddLogMessage(log, "Symmetric key changes:", true);
        sprintf(log_msg, "%.8X^%.8X=%.8X (sym^hwid=newsym)", (unsigned int)symmetrickey, (unsigned int)hardwareID, (unsigned int)(symmetrickey^hardwareID));
        AddLogMessage(log, log_msg, false);
        symmetrickey^=hardwareID;
        first_log=false;
    }

    /* How many otherinfo values are we going to use? */
    if(otherinfo5)
        otherinfocount=5;
    else if(otherinfo4)
        otherinfocount=4;
    else if(otherinfo3)
        otherinfocount=3;
    else if(otherinfo2)
        otherinfocount=2;
    else if(otherinfo1)
        otherinfocount=1;
    else
        otherinfocount=0;

    /* Put the unsigned key together */
    c=keybytes;
    if(otherinfocount>=5)
        c=AddShort(c, otherinfo5);
    if(otherinfocount>=4)
        c=AddShort(c, otherinfo4);
    if(otherinfocount>=3)
        c=AddShort(c, otherinfo3);
    if(otherinfocount>=2)
        c=AddShort(c, otherinfo2);
    if(otherinfocount>=1)
        c=AddShort(c, otherinfo1);
    c=AddShort(c, today);
    c=AddLong(c, symmetrickey);
    keylength=c-keybytes;

    //Append keystring
    if(keystring and keystring[0])
    {
        strcpy(keystr, keystring);
        //keystr[85]=0; //maximum 85 characters...
        int len=strlen(keystr);
        _strrev(keystr); //reverse bytes
        memcpy(&keystr[len], &len, 1); //safe conversion
        //keystr[len]=len; //set length byte
        len++;
        memcpy(keybytes+keylength, keystr, len); //append to the keybytes
        keylength+=len; //update the length
        useskeystring=true;
        ByteArray2String((unsigned char*)keystr, temp, len, 1024);
        sprintf(log_msg, "KeyString Bytes (Len: %d, 0x%X)\r\n%s", len, len, temp);
        AddLogMessage(log, log_msg, first_log);
        first_log=false;
    }

    ByteArray2String(keybytes, temp, keylength, 1024);
    sprintf(log_msg, "KeyBytes (Len: %d, 0x%X):\r\n%s", keylength, keylength, temp);
    AddLogMessage(log, log_msg, first_log);

    /* Encrypt the key */
    EncryptSignedKey(keybytes, keylength, name_to_make_key_for, log);

    ByteArray2String(keybytes, temp, keylength, 1024);
    sprintf(log_msg, "Encrypted KeyBytes:\r\n%s", temp);
    AddLogMessage(log, log_msg, false);

    /* Now add the signature of this key. */
    if(MakeSignature(keybytes, &keylength, name_to_make_key_for, level, pvt_kg_txt, y_kg_txt, baboon, log))
    {
        sprintf(log_msg, "Signed KeyBytes (Len: %d, 0x%X):", keylength, keylength);
        AddLogMessage(log, log_msg, false);
        ByteArray2String(keybytes, log_msg, keylength, 1024);
        AddLogMessage(log, log_msg, false);
        /* Make it into a string */
        strcpy(retval, "");
        if(level>=20)
        {
            /* ShortV3 format */
            n=BigInt_Create();
            t1=BigInt_Create();
            t2=BigInt_Create();

            /* When I created the ShortV3 keysystem, I didn't take into account
            that some keys would have zero-bytes at the beginning, so I had to
            change Armadillo later to deal with that case, which made it slower
            to recognize keys than it should have been. For the new level 10
            ShortV3 keys, I've learned my lesson: I'm setting the first bit on
            the key, which we'll strip off when we interpret it. */
            if(level==29)
                BigInt_Set(n, 1);

            for(x=0; x<keylength; ++x)
            {
                BigInt_Shift(n, 8, t1);
                BigInt_SetU(t2, keybytes[x]);
                BigInt_Add(t1, t2, n);
            }

            cc=retval;
            dcount=6;
            while(BigInt_Compare(n, BigInt_Zero())!=0)
            {
                BigInt_SetU(t2, 32);
                BigInt_Modulus(n, t2, t1);
                nn=BigInt_Get(t1);

                BigInt_Shift(n, -5, t2);
                BigInt_Copy(n, t2);

                if(level==29)
                {
                    /* For the new ShortV3 Level 10 keys, I'm just going to
                    insist that all of them start with the digit '1'. That way,
                    when we're taking them apart, we'll always know which level
                    to use for it immediately, we don't have to try different
                    combinations of levels and extra-info like we did with the
                    earlier ones. */
                    *cc++=shortv3digits[nn];
                    if(--dcount==0)
                    {
                        dcount=6;
                        *cc++='-';
                    }
                }
                else
                {
                    /*
                    ** Ensure that the first digit is outside the range of 0..9
                    ** and A..F. To do this, we'll either add 16 to the first
                    ** digit (if it's less than 16), or add an extra digit.
                    */
                    if(BigInt_Compare(n, BigInt_Zero())==0)
                    {
                        if(nn<16)
                        {
                            *cc++=shortv3digits[nn+16];
                            --dcount;
                        }
                        else
                        {
                            *cc++=shortv3digits[nn];
                            if(--dcount==0)
                            {
                                dcount=6;
                                *cc++='-';
                            }
                            *cc++=shortv3digits[16];
                            --dcount;
                        }
                    }
                    else
                    {
                        *cc++=shortv3digits[nn];
                        if(--dcount==0)
                        {
                            dcount=6;
                            *cc++='-';
                        }
                    }
                }
            }
            if(level==29)
            {
                if(dcount==0)
                {
                    dcount=6;
                    *cc++='-';
                }
                *cc++='1';
                --dcount;
            }
            if(useskeystring)
            {
                if(dcount==0)
                {
                    dcount=6;
                    *cc++='-';
                }
                *cc++='3';
                --dcount;
            }
            if(nameless)
            {
                if(dcount==0)
                {
                    dcount=6;
                    *cc++='-';
                }
                cc2=name_to_make_key_for+strlen(name_to_make_key_for)-1;
                while(cc2>=name_to_make_key_for)
                {
                    *cc++=*cc2--;
                    if(--dcount==0)
                    {
                        dcount=6;
                        *cc++='-';
                    }
                }
            }
            while(dcount-->0)
                *cc++='0';
            *cc=0;
            mystrrev(retval);
            if(!memcmp(retval, "000000-", 7))
                retval_add=7;
            BigInt_Destroy(t2);
            BigInt_Destroy(t1);
            BigInt_Destroy(n);
        }
        else
        {
            /* V2 or conventional V3 format */
            for(x=0; x<keylength; x+=2)
            {
                if(x>0)
                    strcat(retval, "-");
                sprintf(strchr(retval, 0), "%02X%02X", (unsigned char)keybytes[x], (unsigned char)keybytes[x+1]);
            }
        }
    }
    else
    {
        AddLogMessage(log, "Signature error!", true);
        return "";
    }
    return retval+retval_add;
}

/*
	--------
	MakeDate
	--------

	Most implimentations can ignore this function. It creates an Armadillo-
	formatted date, for use in the "otherinfo" parameter of CreateKey for
	expire-by-date keys. The year should be the four-digit year, the month
	should be 1 to 12, and the day should be 1 to 31. It returns 0xFFFF on
	error (bad date or date before 01Jan99). The maximum year is 2037.
*/

unsigned short MakeDate(unsigned int year, unsigned int month, unsigned int day)
{
    const unsigned long secondsperday=(24*60*60);
    const int dateoffset=10592;

    struct tm tm= {0};
    tm.tm_year=year-1900;
    tm.tm_mon=month-1;
    tm.tm_mday=day+1;
    tm.tm_hour=0;
    tm.tm_min=0;
    tm.tm_sec=0;
    unsigned long seconds=mktime(&tm);
    if(seconds==(unsigned long)(-1))
        return (unsigned short)(-1);

    long days=(seconds/secondsperday);
    if(days<dateoffset)
        return (unsigned short)(-1);

    return (unsigned short)(days-dateoffset);
}
