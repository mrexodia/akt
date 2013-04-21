/*
	---------------
	Encryption Code
	---------------

	The decryption code is also included here, although it isn't needed for
	creating keys.
*/

typedef struct CipherKeyStruct
{
    unsigned long S[4][256];
    unsigned long P[18];
} CipherKey;

const int MAXKEYBYTES=56; /* 448-bit maximum key; additional bits ignored. */
const int N=16;

static unsigned long F(CipherKey *bc, unsigned long x)
{
    return ((bc->S[0][(x>>24)&0xFF] + bc->S[1][(x>>16)&0xFF])
            ^ bc->S[2][(x>>8)&0xFF]) + bc->S[3][x&0xFF];
}

static void encipher(CipherKey *c, unsigned long *xl, unsigned long *xr)
{
    unsigned long Xl=*xl, Xr=*xr, temp;
    short i;

    for(i=0; i<N; ++i)
    {
        Xl=Xl^c->P[i];
        Xr=F(c, Xl)^Xr;
        temp=Xl;
        Xl=Xr;
        Xr=temp;
    }
    temp=Xl;
    Xl=Xr;
    Xr=temp;
    Xr=Xr^c->P[N];
    Xl=Xl^c->P[N+1];
    *xl=Xl;
    *xr=Xr;
}

static void decipher(CipherKey *c, unsigned long *xl, unsigned long *xr)
{
    unsigned long Xl=*xl, Xr=*xr, temp;
    short i;

    for(i=N+1; i>1; --i)
    {
        Xl=Xl^c->P[i];
        Xr=F(c, Xl)^Xr;
        temp=Xl;
        Xl=Xr;
        Xr=temp;
    }
    temp=Xl;
    Xl=Xr;
    Xr=temp;
    Xr=Xr^c->P[1];
    Xl=Xl^c->P[0];
    *xl=Xl;
    *xr=Xr;
}

static void initialize(CipherKey *c, const char *keybytes, int keylength, unsigned long seed)
{
    int i, j, k;

    const unsigned long ps[18]=
    {
        0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344, 0xa4093822, 0x299f31d0,
        0x082efa98, 0xec4e6c89, 0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
        0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917, 0x9216d5d9, 0x8979fb1b,
    };
    unsigned long datal=0, datar=0;

    /* Initialize P array */
    for(i=0; i<18; ++i) c->P[i]=ps[i];

    /* Initialize S-boxes with pseudo-random number generator */
    InitRandomGenerator(seed);
    for(i=0; i<4; ++i) for(j=0; j<256; ++j) c->S[i][j]=NextRandomNumber();

    for(i=0, j=0; i<N+2; ++i)
    {
        unsigned long data=0;
        for(k=0; k<4; ++k)
        {
            data=(data<<8)|keybytes[j];
            if(++j>=keylength) j=0;
        }
        c->P[i]^=data;
    }

#ifdef DEBUG
    printf("PData:\n");
    for(i=0; i<N+2; i+=2)
    {
        encipher(c, &datal, &datar);
        c->P[i]=datal;
        c->P[i+1]=datar;

        printf("    datal=%08X, datar=%08X\n", datal, datar);
    }

    printf("\nSData:\n");
    for(i=0; i<4; ++i) for(j=0; j<256; j+=2)
        {
            encipher(c, &datal, &datar);
            c->S[i][j]=datal;
            c->S[i][j+1]=datar;

            printf("    datal=%08X, datar=%08X\n", datal, datar);
        }
#else
    for(i=0; i<N+2; i+=2)
    {
        encipher(c, &datal, &datar);
        c->P[i]=datal;
        c->P[i+1]=datar;
    }
    for(i=0; i<4; ++i)
    {
        for(j=0; j<256; j+=2)
        {
            encipher(c, &datal, &datar);
            c->S[i][j]=datal;
            c->S[i][j+1]=datar;
        }
    }
#endif
}

static CipherKey *CreateCipherKey(const char *keybytes, int length)
{
    CipherKey *newkey=(CipherKey*)malloc(sizeof(CipherKey));
    initialize(newkey, keybytes, length, 0x31415921);
    return newkey;
}

static void ReleaseCipherKey(CipherKey *key)
{
    free(key);
}

static void Encipher(CipherKey *key, char *buffer, int length)
{
    unsigned long *p, *e;
    length&=(~0x07); /* Round down to the next-lower multiple of 8 bytes */
    for(p=(unsigned long *)buffer, e=p+(length/4); p<e; p+=2)
        encipher(key, p, p+1);
}

static void Decipher(CipherKey *key, char *buffer, int length)
{
    unsigned long *p, *e;
    length&=(~0x07); /* Round down to the next-lower multiple of 8 bytes */
    for(p=(unsigned long *)buffer, e=p+(length/4); p<e; p+=2)
        decipher(key, p, p+1);
}
