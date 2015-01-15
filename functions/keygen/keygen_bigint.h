#ifndef _KEYGENBIGINT_H
#define _KEYGENBIGINT_H

#include <cstring>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

#define BITS_PER_DIGIT 8

/*
    In the typedefs below, DIGIT must be at least eight bits long (I don't know
    of any computer where this wouldn't be true), and WORKING_DIGIT must be at
    least twice the size of DIGIT. Modify them as needed.
*/

#if BITS_PER_DIGIT==8
typedef unsigned char DIGIT; /* This must be a minimum of 8 bits long! */
typedef unsigned short WORKING_DIGIT; /* This must be at least twice the size of DIGIT! */
#define DIGIT_HIBIT 0x80
#define WORKING_DIGIT_HIBIT 0x8000
#define DIGIT_MASK 0xFF
#define OVERFLOW_DIGIT 0x100
#elif BITS_PER_DIGIT==16
typedef unsigned short DIGIT;
typedef unsigned long WORKING_DIGIT;
#define DIGIT_HIBIT 0x8000
#define WORKING_DIGIT_HIBIT 0x80000000
#define DIGIT_MASK 0xFFFF
#define OVERFLOW_DIGIT 0x10000L
#else
#error Invalid BITS_PER_DIGIT, must be 8 or 16.
#endif

struct BigIntBase
{
    int length, alloc, negative;
    DIGIT* digits;
};

typedef struct BigIntBase* BigInt;

/* Basic housekeeping functions */
BigInt BigInt_Create(void);
void BigInt_Destroy(BigInt n);
void BigInt_Copy(BigInt target, BigInt source);
void BigInt_Set(BigInt n, signed long init);
void BigInt_SetU(BigInt n, unsigned long init);
signed long BigInt_Get(BigInt n);
unsigned long BigInt_GetU(BigInt n);
int BigInt_Compare(BigInt a, BigInt b);
BigInt BigInt_Zero(void);
BigInt BigInt_One(void);

/* Mathematical operator functions */
void BigInt_Add(BigInt a, BigInt b, BigInt answer);
void BigInt_Subtract(BigInt a, BigInt b, BigInt answer);
void BigInt_Multiply(BigInt a, BigInt b, BigInt answer);
int BigInt_Divide(BigInt a, BigInt b, BigInt answer, BigInt remainder);
void BigInt_Power(BigInt n, BigInt exp, BigInt answer);

/* Logical operator functions */
void BigInt_And(BigInt a, BigInt b, BigInt answer);
void BigInt_Or(BigInt a, BigInt b, BigInt answer);
void BigInt_Xor(BigInt a, BigInt b, BigInt answer);
void BigInt_Shift(BigInt n, int places, BigInt answer); /* Negative 'places' shifts right */
void BigInt_Invert(BigInt n);

/* Specialized functions */
void BigInt_Modulus(BigInt n, BigInt mod, BigInt answer);
void BigInt_PowerModulus(BigInt n, BigInt exp, BigInt modulus, BigInt answer);
void BigInt_GCD(BigInt n, BigInt m, BigInt answer);
int BigInt_ModularInverse(BigInt n, BigInt m, BigInt answer);
int BigInt_IsEven(BigInt n);
int BigInt_IsOdd(BigInt n);
int BigInt_IsZero(BigInt n);
int BigInt_IsOne(BigInt n);

/* String functions */
bool BigInt_FromString(const char* source, int base, BigInt dest);
bool BigInt_FromDecString(const char* source, BigInt dest);
bool BigInt_FromHexString(const char* source, BigInt dest);
bool BigInt_ToHexString(BigInt n, char* d);
void BigInt_ToString(BigInt s, int base, char* d);

#endif
