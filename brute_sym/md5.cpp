#include "md5.h"

#define RotateLeft(x,n) (((x) << n) | ((x) >> (32-n)))
#define FF(A,B,C,D,X,S,T) (RotateLeft(((B & C)|(~B & D))+A+X+T, S)+B)
#define GG(A,B,C,D,X,S,T) (RotateLeft(((B & D)|(C & ~D))+A+X+T, S)+B)
#define HH(A,B,C,D,X,S,T) (RotateLeft((B^C^D)+A+X+T, S)+B)
#define II(A,B,C,D,X,S,T) (RotateLeft((C^ (B | ~D))+A+X+T, S)+B)

unsigned int TransformBlock(unsigned int x0, unsigned int x1, unsigned int x2, unsigned int x14)
{
    unsigned int a=0x67452301, b=0xefcdab89, c=0x98badcfe, d=0x10325476;
    // Round 1
    a=FF(a, b, c, d, x0, 7, 0xd76aa478);
    d=FF(d, a, b, c, x1, 12, 0xe8c7b756);
    c=FF(c, d, a, b, x2, 17, 0x242070db);
    b=FF(b, c, d, a, 0, 22, 0xc1bdceee);
    a=FF(a, b, c, d, 0, 7, 0xf57c0faf);
    d=FF(d, a, b, c, 0, 12, 0x4787c62a);
    c=FF(c, d, a, b, 0, 17, 0xa8304613);
    b=FF(b, c, d, a, 0, 22, 0xfd469501);
    a=FF(a, b, c, d, 0, 7, 0x698098d8);
    d=FF(d, a, b, c, 0, 12, 0x8b44f7af);
    c=FF(c, d, a, b, 0, 17, 0xffff5bb1);
    b=FF(b, c, d, a, 0, 22, 0x895cd7be);
    a=FF(a, b, c, d, 0, 7, 0x6b901122);
    d=FF(d, a, b, c, 0, 12, 0xfd987193);
    c=FF(c, d, a, b, x14, 17, 0xa679438e);
    b=FF(b, c, d, a, 0, 22, 0x49b40821);
    // Round 2
    a=GG(a, b, c, d, x1, 5, 0xf61e2562);
    d=GG(d, a, b, c, 0, 9, 0xc040b340);
    c=GG(c, d, a, b, 0, 14, 0x265e5a51);
    b=GG(b, c, d, a, x0, 20, 0xe9b6c7aa);
    a=GG(a, b, c, d, 0, 5, 0xd62f105d);
    d=GG(d, a, b, c, 0, 9, 0x02441453);
    c=GG(c, d, a, b, 0, 14, 0xd8a1e681);
    b=GG(b, c, d, a, 0, 20, 0xe7d3fbc8);
    a=GG(a, b, c, d, 0, 5, 0x21e1cde6);
    d=GG(d, a, b, c, x14, 9, 0xc33707d6);
    c=GG(c, d, a, b, 0, 14, 0xf4d50d87);
    b=GG(b, c, d, a, 0, 20, 0x455a14ed);
    a=GG(a, b, c, d, 0, 5, 0xa9e3e905);
    d=GG(d, a, b, c, x2, 9, 0xfcefa3f8);
    c=GG(c, d, a, b, 0, 14, 0x676f02d9);
    b=GG(b, c, d, a, 0, 20, 0x8d2a4c8a);
    // Round 3
    a=HH(a, b, c, d, 0, 4, 0xfffa3942);
    d=HH(d, a, b, c, 0, 11, 0x8771f681);
    c=HH(c, d, a, b, 0, 16, 0x6d9d6122);
    b=HH(b, c, d, a, x14, 23, 0xfde5380c);
    a=HH(a, b, c, d, x1, 4, 0xa4beea44);
    d=HH(d, a, b, c, 0, 11, 0x4bdecfa9);
    c=HH(c, d, a, b, 0, 16, 0xf6bb4b60);
    b=HH(b, c, d, a, 0, 23, 0xbebfbc70);
    a=HH(a, b, c, d, 0, 4, 0x289b7ec6);
    d=HH(d, a, b, c, x0, 11, 0xeaa127fa);
    c=HH(c, d, a, b, 0, 16, 0xd4ef3085);
    b=HH(b, c, d, a, 0, 23, 0x04881d05);
    a=HH(a, b, c, d, 0, 4, 0xd9d4d039);
    d=HH(d, a, b, c, 0, 11, 0xe6db99e5);
    c=HH(c, d, a, b, 0, 16, 0x1fa27cf8);
    b=HH(b, c, d, a, x2, 23, 0xc4ac5665);
    // Round 4
    a=II(a, b, c, d, x0, 6, 0xf4292244);
    d=II(d, a, b, c, 0, 10, 0x432aff97);
    c=II(c, d, a, b, x14, 15, 0xab9423a7);
    b=II(b, c, d, a, 0, 21, 0xfc93a039);
    a=II(a, b, c, d, 0, 6, 0x655b59c3);
    d=II(d, a, b, c, 0, 10, 0x8f0ccc92);
    c=II(c, d, a, b, 0, 15, 0xffeff47d);
    b=II(b, c, d, a, x1, 21, 0x85845dd1);
    a=II(a, b, c, d, 0, 6, 0x6fa87e4f);
    d=II(d, a, b, c, 0, 10, 0xfe2ce6e0);
    c=II(c, d, a, b, 0, 15, 0xa3014314);
    b=II(b, c, d, a, 0, 21, 0x4e0811a1);
    a=II(a, b, c, d, 0, 6, 0xf7537e82);
    d=II(d, a, b, c, 0, 10, 0xbd3af235);
    c=II(c, d, a, b, x2, 15, 0x2ad7d2bb);
    b=II(b, c, d, a, 0, 21, 0xeb86d391);

    a+=0x67452301;
    b+=0xefcdab89;
    c+=0x98badcfe;
    d+=0x10325476;
    return a^b^c^d;
}

unsigned int GenerateChecksumV8(unsigned int sym, unsigned int salt)
{
    unsigned int a=sym;
    for(int i=0; i<1000; i++)
        a=TransformBlock(a, salt, 0x80, 0x40);
    return a;
}
