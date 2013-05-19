#include "keygen_md5.h"

/*
	--------
	MD5 code
	--------

	An implementation of the RSA MD5 algorithm, a cryptographically secure
	hashing algorithm that produces a 128-bit hash value from input of an
	arbitrary length. Used for the ShortV3 key system.
*/

#define RotateLeft(x,n) (((x) << n)|((x) >> (32-n)))
#define FF(A,B,C,D,X,S,T) (RotateLeft(((B & C)|(~B & D))+A+X+T, S)+B)
#define GG(A,B,C,D,X,S,T) (RotateLeft(((B & D)|(C & ~D))+A+X+T, S)+B)
#define HH(A,B,C,D,X,S,T) (RotateLeft((B^C^D)+A+X+T, S)+B)
#define II(A,B,C,D,X,S,T) (RotateLeft((C^ (B|~D))+A+X+T, S)+B)

void TransformBlock(unsigned long *i, const unsigned char *in)
{
    const int s1[]= { 7, 12, 17, 22 };
    const int s2[]= { 5, 9, 14, 20 };
    const int s3[]= { 4, 11, 16, 23 };
    const int s4[]= { 6, 10, 15, 21 };

    unsigned long a=i[0], b=i[1], c=i[2], d=i[3], X[16], *dp=X;
    const unsigned char *p=in, *in_end=p+64;

    /* Transfer it to the unsigned long array, in reverse-byte format */
    while(p<in_end)
    {
        *dp++=((unsigned long)(*(p+0)))|((unsigned long)(*(p+1))<<8)|((unsigned long)(*(p+2))<<16)|((unsigned long)(*(p+3))<<24);
        p+=4;
    }

    /* Round 1 */
    a=FF(a, b, c, d, X[ 0], s1[0], 0xd76aa478);
    d=FF(d, a, b, c, X[ 1], s1[1], 0xe8c7b756);
    c=FF(c, d, a, b, X[ 2], s1[2], 0x242070db);
    b=FF(b, c, d, a, X[ 3], s1[3], 0xc1bdceee);
    a=FF(a, b, c, d, X[ 4], s1[0], 0xf57c0faf);
    d=FF(d, a, b, c, X[ 5], s1[1], 0x4787c62a);
    c=FF(c, d, a, b, X[ 6], s1[2], 0xa8304613);
    b=FF(b, c, d, a, X[ 7], s1[3], 0xfd469501);
    a=FF(a, b, c, d, X[ 8], s1[0], 0x698098d8);
    d=FF(d, a, b, c, X[ 9], s1[1], 0x8b44f7af);
    c=FF(c, d, a, b, X[10], s1[2], 0xffff5bb1);
    b=FF(b, c, d, a, X[11], s1[3], 0x895cd7be);
    a=FF(a, b, c, d, X[12], s1[0], 0x6b901122);
    d=FF(d, a, b, c, X[13], s1[1], 0xfd987193);
    c=FF(c, d, a, b, X[14], s1[2], 0xa679438e);
    b=FF(b, c, d, a, X[15], s1[3], 0x49b40821);

    /* Round 2 */
    a=GG(a, b, c, d, X[ 1], s2[0], 0xf61e2562);
    d=GG(d, a, b, c, X[ 6], s2[1], 0xc040b340);
    c=GG(c, d, a, b, X[11], s2[2], 0x265e5a51);
    b=GG(b, c, d, a, X[ 0], s2[3], 0xe9b6c7aa);
    a=GG(a, b, c, d, X[ 5], s2[0], 0xd62f105d);
    d=GG(d, a, b, c, X[10], s2[1], 0x02441453);
    c=GG(c, d, a, b, X[15], s2[2], 0xd8a1e681);
    b=GG(b, c, d, a, X[ 4], s2[3], 0xe7d3fbc8);
    a=GG(a, b, c, d, X[ 9], s2[0], 0x21e1cde6);
    d=GG(d, a, b, c, X[14], s2[1], 0xc33707d6);
    c=GG(c, d, a, b, X[ 3], s2[2], 0xf4d50d87);
    b=GG(b, c, d, a, X[ 8], s2[3], 0x455a14ed);
    a=GG(a, b, c, d, X[13], s2[0], 0xa9e3e905);
    d=GG(d, a, b, c, X[ 2], s2[1], 0xfcefa3f8);
    c=GG(c, d, a, b, X[ 7], s2[2], 0x676f02d9);
    b=GG(b, c, d, a, X[12], s2[3], 0x8d2a4c8a);

    /* Round 3 */
    a=HH(a, b, c, d, X[ 5], s3[0], 0xfffa3942);
    d=HH(d, a, b, c, X[ 8], s3[1], 0x8771f681);
    c=HH(c, d, a, b, X[11], s3[2], 0x6d9d6122);
    b=HH(b, c, d, a, X[14], s3[3], 0xfde5380c);
    a=HH(a, b, c, d, X[ 1], s3[0], 0xa4beea44);
    d=HH(d, a, b, c, X[ 4], s3[1], 0x4bdecfa9);
    c=HH(c, d, a, b, X[ 7], s3[2], 0xf6bb4b60);
    b=HH(b, c, d, a, X[10], s3[3], 0xbebfbc70);
    a=HH(a, b, c, d, X[13], s3[0], 0x289b7ec6);
    d=HH(d, a, b, c, X[ 0], s3[1], 0xeaa127fa);
    c=HH(c, d, a, b, X[ 3], s3[2], 0xd4ef3085);
    b=HH(b, c, d, a, X[ 6], s3[3], 0x04881d05);
    a=HH(a, b, c, d, X[ 9], s3[0], 0xd9d4d039);
    d=HH(d, a, b, c, X[12], s3[1], 0xe6db99e5);
    c=HH(c, d, a, b, X[15], s3[2], 0x1fa27cf8);
    b=HH(b, c, d, a, X[ 2], s3[3], 0xc4ac5665);

    /* Round 4 */
    a=II(a, b, c, d, X[ 0], s4[0], 0xf4292244);
    d=II(d, a, b, c, X[ 7], s4[1], 0x432aff97);
    c=II(c, d, a, b, X[14], s4[2], 0xab9423a7);
    b=II(b, c, d, a, X[ 5], s4[3], 0xfc93a039);
    a=II(a, b, c, d, X[12], s4[0], 0x655b59c3);
    d=II(d, a, b, c, X[ 3], s4[1], 0x8f0ccc92);
    c=II(c, d, a, b, X[10], s4[2], 0xffeff47d);
    b=II(b, c, d, a, X[ 1], s4[3], 0x85845dd1);
    a=II(a, b, c, d, X[ 8], s4[0], 0x6fa87e4f);
    d=II(d, a, b, c, X[15], s4[1], 0xfe2ce6e0);
    c=II(c, d, a, b, X[ 6], s4[2], 0xa3014314);
    b=II(b, c, d, a, X[13], s4[3], 0x4e0811a1);
    a=II(a, b, c, d, X[ 4], s4[0], 0xf7537e82);
    d=II(d, a, b, c, X[11], s4[1], 0xbd3af235);
    c=II(c, d, a, b, X[ 2], s4[2], 0x2ad7d2bb);
    b=II(b, c, d, a, X[ 9], s4[3], 0xeb86d391);

    /* Add the transformed values to the current checksum */
    i[0]+=a;
    i[1]+=b;
    i[2]+=c;
    i[3]+=d;
}

void md5(unsigned long *i, const void *bytes, unsigned long length)
{
    const unsigned char *p=(const unsigned char *)bytes;
    unsigned long bytesremaining=length, d;
    unsigned char buffer[128], *b;

    /* Initialize the MD5 values */
    i[0]=0x67452301;
    i[1]=0xefcdab89;
    i[2]=0x98badcfe;
    i[3]=0x10325476;

    /* Do the transform on the initial data, up to the last block */
    while(bytesremaining>64)
    {
        TransformBlock(i, p);
        bytesremaining-=64;
        p+=64;
    }

    /* Pad the block according to the MD5 spec */
    memset(buffer, 0, 128);
    memcpy(buffer, p, bytesremaining);
    buffer[bytesremaining++]=0x80;

    /*
    ** Add the 64-bit size to the end of the first block if there's room,
    ** otherwise the second. This function is designed to handle a maximum
    ** byte length of 4GB, which should be plenty for our purposes.
    */
    if(bytesremaining<=56)
    {
        /* There's room. Only need one added group. */
        /*
        Can't use these two lines, because they don't work on big-endian
        *(unsigned long*)(buffer+56)=(length<<3);
        *(unsigned long*)(buffer+60)=(length>>29);
        */

        b=buffer+56;
        d=length<<3;
        *b++=(unsigned char)(d&0xFF);
        d>>=8;
        *b++=(unsigned char)(d&0xFF);
        d>>=8;
        *b++=(unsigned char)(d&0xFF);
        d>>=8;
        *b++=(unsigned char)(d&0xFF);
        d>>=8;
        d=length>>29;
        *b++=(unsigned char)(d&0xFF);
        d>>=8;
        *b++=(unsigned char)(d&0xFF);
        d>>=8;
        *b++=(unsigned char)(d&0xFF);
        d>>=8;
        *b++=(unsigned char)(d&0xFF);
        d>>=8;

        TransformBlock(i, buffer);
    }
    else
    {
        /* Not enough room, we'll have to spill over to a second block. */
        /*
        Can't use these two lines, because they don't work on big-endian
        *(unsigned long*)(buffer+120)=(length<<3);
        *(unsigned long*)(buffer+124)=(length>>29);
        */

        b=buffer+120;
        d=length<<3;
        *b++=(unsigned char)(d&0xFF);
        d>>=8;
        *b++=(unsigned char)(d&0xFF);
        d>>=8;
        *b++=(unsigned char)(d&0xFF);
        d>>=8;
        *b++=(unsigned char)(d&0xFF);
        d>>=8;
        d=length>>29;
        *b++=(unsigned char)(d&0xFF);
        d>>=8;
        *b++=(unsigned char)(d&0xFF);
        d>>=8;
        *b++=(unsigned char)(d&0xFF);
        d>>=8;
        *b++=(unsigned char)(d&0xFF);
        d>>=8; //TODO: remove?

        TransformBlock(i, buffer);
        TransformBlock(i, buffer+64);
    }

    /*
    ** And we're done. Normally we would have to do some extra work to spit out
    ** the MD5 information, low-byte first in A,B,C,D order (step 5 of the
    ** description), but I only need it for binary uses, so the four unsigned
    ** longs are enough.
    */
}
