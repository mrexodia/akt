#include "keygen_crc32.h"

/*
	------------
	CRC Function
	------------

	Note that this function does not release its allocated memory (table32). The
	code assumes that the operating system releases all of a program's allocated
	memory when the program exits. If your system does not, you must explicitly
	add a function to release it, and call it before your program exits.
*/

CRC32 *table32=0;

unsigned long reflect(unsigned long source, int b)
{
    unsigned long sourcemask=0x01, targetmask=(0x01 << (b-1)), target=0;
    while(targetmask)
    {
        if(source & sourcemask) target|=targetmask;
        sourcemask<<=1;
        targetmask>>=1;
    }
    return target;
}

/* 'calc' is the macro for the actual CRC calculations. */
#define calc(crc, table, c) { crc=table[alphamask&(*c^crc)]^(crc>>8); }

CRC32 crc32(const char *s, unsigned long length, CRC32 crc)
{
    const int BITS=32;
    const int alphabits=8;						/* Number of bits in a character */
    const int alphabet=(1L<<alphabits);			/* Number of symbols in table */
    const int alphamask=(alphabet-1);			/* Mask for these bits */
    const CRC32 poly32=0x04C11DB7;				/* CRC32 standard */
    const CRC32 topbit=(CRC32)(1L<<(BITS-1));
    const char *c, *e;
    int x, b;
    CRC32 r;

    if(!table32)
    {
        table32=(CRC32*)malloc(alphabet*sizeof(CRC32));
        for(x=0; x<alphabet; ++x)
        {
            r=reflect(x, alphabits) << (BITS-alphabits);
            for(b=0; b<alphabits; ++b)
            {
                if(r&topbit)
                    r=(r<<1)^poly32;
                else
                    r<<=1;
            }
            table32[x]=(CRC32)(reflect(r, BITS));
        }
    }

    for(c=s, e=s+length; c<e; ++c)
        calc(crc, table32, c);
    return crc;
}
