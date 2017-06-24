/*
* Copyright 2013
* cypher <the.cypher@gmail.com>
*
* kernel functions derived from mr.exodia's research, THX!

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License version 3 as
published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#define GenerateChecksumV3(sym) (TransformBlock(sym, 0x80, 0, 0x20)^sym)

/* The basic MD5 functions */
#define F(x, y, z)                        ((z) ^ ((x) & ((y) ^ (z))))
#define G(x, y, z)                        ((y) ^ ((z) & ((x) ^ (y))))
#define H(x, y, z)                        ((x) ^ (y) ^ (z))
#define I(x, y, z)                        ((y) ^ ((x) | ~(z)))

/* The MD5 transformation for all four rounds. */
#define STEP(f, a, b, c, d, x, t, s) \
(a) += f((b), (c), (d)) + (x) + (t); \
(a) = (((a) << (s)) | (((a) & 0xffffffff) >> (32 - (s)))); \
(a) += (b);

static unsigned int TransformBlock(unsigned int x0, unsigned int x1, unsigned int x2, unsigned int x14)
{
    unsigned int a=0x67452301, b=0xefcdab89, c=0x98badcfe, d=0x10325476;

    /* Round 1 */
    STEP(F, a, b, c, d, x0, 0xd76aa478, 7)
    STEP(F, d, a, b, c, x1, 0xe8c7b756, 12)
    STEP(F, c, d, a, b, x2, 0x242070db, 17)
    STEP(F, b, c, d, a, 0, 0xc1bdceee, 22)
    STEP(F, a, b, c, d, 0, 0xf57c0faf, 7)
    STEP(F, d, a, b, c, 0, 0x4787c62a, 12)
    STEP(F, c, d, a, b, 0, 0xa8304613, 17)
    STEP(F, b, c, d, a, 0, 0xfd469501, 22)
    STEP(F, a, b, c, d, 0, 0x698098d8, 7)
    STEP(F, d, a, b, c, 0, 0x8b44f7af, 12)
    STEP(F, c, d, a, b, 0, 0xffff5bb1, 17)
    STEP(F, b, c, d, a, 0, 0x895cd7be, 22)
    STEP(F, a, b, c, d, 0, 0x6b901122, 7)
    STEP(F, d, a, b, c, 0, 0xfd987193, 12)
    STEP(F, c, d, a, b, x14, 0xa679438e, 17)
    STEP(F, b, c, d, a, 0, 0x49b40821, 22)

    /* Round 2 */
    STEP(G, a, b, c, d, x1, 0xf61e2562, 5)
    STEP(G, d, a, b, c, 0, 0xc040b340, 9)
    STEP(G, c, d, a, b, 0, 0x265e5a51, 14)
    STEP(G, b, c, d, a, x0, 0xe9b6c7aa, 20)
    STEP(G, a, b, c, d, 0, 0xd62f105d, 5)
    STEP(G, d, a, b, c, 0, 0x02441453, 9)
    STEP(G, c, d, a, b, 0, 0xd8a1e681, 14)
    STEP(G, b, c, d, a, 0, 0xe7d3fbc8, 20)
    STEP(G, a, b, c, d, 0, 0x21e1cde6, 5)
    STEP(G, d, a, b, c, x14, 0xc33707d6, 9)
    STEP(G, c, d, a, b, 0, 0xf4d50d87, 14)
    STEP(G, b, c, d, a, 0, 0x455a14ed, 20)
    STEP(G, a, b, c, d, 0, 0xa9e3e905, 5)
    STEP(G, d, a, b, c, x2, 0xfcefa3f8, 9)
    STEP(G, c, d, a, b, 0, 0x676f02d9, 14)
    STEP(G, b, c, d, a, 0, 0x8d2a4c8a, 20)

    /* Round 3 */
    STEP(H, a, b, c, d, 0, 0xfffa3942, 4)
    STEP(H, d, a, b, c, 0, 0x8771f681, 11)
    STEP(H, c, d, a, b, 0, 0x6d9d6122, 16)
    STEP(H, b, c, d, a, x14, 0xfde5380c, 23)
    STEP(H, a, b, c, d, x1, 0xa4beea44, 4)
    STEP(H, d, a, b, c, 0, 0x4bdecfa9, 11)
    STEP(H, c, d, a, b, 0, 0xf6bb4b60, 16)
    STEP(H, b, c, d, a, 0, 0xbebfbc70, 23)
    STEP(H, a, b, c, d, 0, 0x289b7ec6, 4)
    STEP(H, d, a, b, c, x0, 0xeaa127fa, 11)
    STEP(H, c, d, a, b, 0, 0xd4ef3085, 16)
    STEP(H, b, c, d, a, 0, 0x04881d05, 23)
    STEP(H, a, b, c, d, 0, 0xd9d4d039, 4)
    STEP(H, d, a, b, c, 0, 0xe6db99e5, 11)
    STEP(H, c, d, a, b, 0, 0x1fa27cf8, 16)
    STEP(H, b, c, d, a, x2, 0xc4ac5665, 23)

    /* Round 4 */
    STEP(I, a, b, c, d, x0, 0xf4292244, 6)
    STEP(I, d, a, b, c, 0, 0x432aff97, 10)
    STEP(I, c, d, a, b, x14, 0xab9423a7, 15)
    STEP(I, b, c, d, a, 0, 0xfc93a039, 21)
    STEP(I, a, b, c, d, 0, 0x655b59c3, 6)
    STEP(I, d, a, b, c, 0, 0x8f0ccc92, 10)
    STEP(I, c, d, a, b, 0, 0xffeff47d, 15)
    STEP(I, b, c, d, a, x1, 0x85845dd1, 21)
    STEP(I, a, b, c, d, 0, 0x6fa87e4f, 6)
    STEP(I, d, a, b, c, 0, 0xfe2ce6e0, 10)
    STEP(I, c, d, a, b, 0, 0xa3014314, 15)
    STEP(I, b, c, d, a, 0, 0x4e0811a1, 21)
    STEP(I, a, b, c, d, 0, 0xf7537e82, 6)
    STEP(I, d, a, b, c, 0, 0xbd3af235, 10)
    STEP(I, c, d, a, b, x2, 0x2ad7d2bb, 15)
    STEP(I, b, c, d, a, 0, 0xeb86d391, 21)

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

//Arma PRNG NextRandomRange
static unsigned char arma_alg2_byte(int data)
{
    return (((data/10000)<<8)/10000)&0xFF;
}

//Arma PRNG NextSeed
static int arma_alg2_next(int data)
{
    int a=data%10000;
    int res;
    res=10000*((3141*a+(data/10000)*5821)%10000u);
    return (a*5821+res+1)%100000000u;
}

//stolen key brute force
unsigned long arma_alg78_hash(unsigned long i, unsigned long data)
{
    int next=i;
    int res=arma_alg2_byte((next=arma_alg2_next(next)))<<24;
    res|=arma_alg2_byte((next=arma_alg2_next(next)))<<16;
    res|=arma_alg2_byte((next=arma_alg2_next(next)))<<8;
    res|=arma_alg2_byte(arma_alg2_next(next));
    return res^data;
}

/* Some weird behavior with OpenCL and copying data in/out: They must absolutely be of the same data size !
   Using cl_ulong as argument in cpp and unsigned long in .cl doesnt work !
   Therefore using cl_uint and unsigned int for the key/hash. Its size suffices and they both have the same size !
   There is no unsigned long in OpenCL. cl_ulong is actually a unsigned long long

   Also passing in typedef structs as argument is a pain and most often not working correctly because of how OpenCL reads them (padding etc..)
   Therefore passing the structs members as single arguments is much easier.
*/

#define MAX_HASHES 32

//arma v3.7-v7.2
__kernel void arma_alg0(__global unsigned int* out_hashes, __global unsigned int* out_keys, __global unsigned int* in_hashes, const unsigned int from, __global unsigned int* num_keys_found)
{
    unsigned int idx = get_global_id(0);
    unsigned int key = from+idx;
    unsigned int chkSum = GenerateChecksumV3(key);

    if(chkSum==in_hashes[0]) {
        unsigned int num_key = atomic_inc(num_keys_found);
        out_hashes[num_key] = in_hashes[0];
        out_keys[num_key] = key;
    }
}

//arma v7.4+
__kernel void arma_alg1(__global unsigned int* out_hashes, __global unsigned int* out_keys, __global unsigned int* in_hashes, const unsigned int from, __global unsigned int* num_keys_found, const unsigned int salt)
{
    unsigned int idx = get_global_id(0);
    unsigned int key = from+idx;
    unsigned int chkSum = GenerateChecksumV8(key, salt);

    for(int h=0; h<MAX_HASHES; h++) {
        if(chkSum==in_hashes[h]) {
            unsigned int num_key = atomic_inc(num_keys_found);
            out_hashes[num_key] = in_hashes[h];
            out_keys[num_key] = key;
        }
    }
}

//stolen keys v3.7-v7.2
__kernel void arma_alg7(__global unsigned int* out_hashes, __global unsigned int* out_keys, __global unsigned int* in_hashes, const unsigned int from, __global unsigned int* num_keys_found, const unsigned int seed)
{
    unsigned int idx = get_global_id(0);
    int key = arma_alg78_hash(from+idx, seed);
    unsigned int chkSum = GenerateChecksumV3(key);

    if(chkSum==in_hashes[0]) {
        unsigned int num_key = atomic_inc(num_keys_found);
        out_hashes[num_key] = in_hashes[0];
        out_keys[num_key] = key;
    }
}

//stolen keys 7.4+
__kernel void arma_alg8(__global unsigned int* out_hashes, __global unsigned int* out_keys, __global unsigned int* in_hashes, const unsigned int from, __global unsigned int* num_keys_found, const unsigned int seed, const unsigned int salt)
{
    unsigned int idx = get_global_id(0);
    int key = arma_alg78_hash(from+idx, seed);
    unsigned int chkSum = GenerateChecksumV8(key, salt);

    if(chkSum==in_hashes[0]) {
        unsigned int num_key = atomic_inc(num_keys_found);
        out_hashes[num_key] = in_hashes[0];
        out_keys[num_key] = key;
    }
}
