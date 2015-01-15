#include <time.h>
#include "md5.h"

/*
    -------------
    GetRandomSeed
    -------------

    The GetRandomSeed function is designed to seed the random number generator.
    For compatibility with various standard C libraries, we can only make a
    unique seed once every second. If you need to create signed keys faster
    than that, and ensure that they are unique, then you'll have to customize
    this function to either use something that increments more quickly, or that
    stores the result somewhere to ensure that it never returns the same value
    twice. We've included a preprocessor definition, USECLOCKTICKS, that
    attempts to do this using the clock() function, but it may not work on all
    platforms.
*/

static unsigned long GetRandomSeed(void)
{
#ifdef FOR_TESTING
    return 1000;
#else
#ifdef USECLOCKTICKS
    return time(0) + clock();
#else
    return time(0);
#endif
#endif
}



/*
    -------------------------------
    Pseudo-Random Number Generators
    -------------------------------
*/

#define m 100000000L
#define m1 10000L
#define b 31415821L

static unsigned long a;

static unsigned long mult(long p, long q)
{
    unsigned long p1 = p / m1, p0 = p % m1, q1 = q / m1, q0 = q % m1;
    return (((p0 * q1 + p1 * q0) % m1) * m1 + p0 * q0) % m;
}

static void InitRandomGenerator(unsigned long seed)
{
    a = seed;
}

static unsigned long NextRandomRange(long range)
{
    a = (mult(a, b) + 1) % m;
    return (((a / m1) * range) / m1);
}

static unsigned long NextRandomNumber(void)
{
    long n1 = NextRandomRange(256);
    long n2 = NextRandomRange(256);
    long n3 = NextRandomRange(256);
    long n4 = NextRandomRange(256);
    return (n1 << 24) | (n2 << 16) | (n3 << 8) | n4;
}

/* Improved version, for ECC keys */

static unsigned long aa[4];

static void InitRandomGenerator128(unsigned long* seed)
{
    memcpy(aa, seed, sizeof(unsigned long) * 4);
}

static void NextRandomNumber128(unsigned long* i)
{
    /* Take the existing four double-words and print some form of them to a
    string. Then do the same with a new seed value. Then create the MD5
    signature of that string -- that's the new 128-bit number. */
    unsigned long ii[5];
    char string[256], *c;
    int x, y;

    memcpy(ii, aa, sizeof(unsigned long) * 4);
    ii[4] = GetRandomSeed();

    c = string;
    for(x = 0; x < 5; ++x)
    {
        for(y = 0; y < 8; ++y)
        {
            *c++ = (char)('A' + (ii[x] & 0x0F));
            ii[x] >>= 4;
        }
    }
    md5(aa, string, c - string);
    memcpy(i, aa, sizeof(unsigned long) * 4);
}

#undef b
#undef m1
#undef m

