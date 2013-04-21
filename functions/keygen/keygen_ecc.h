#ifndef _KEYGENECC_H
#define _KEYGENECC_H

#include "keygen_bigint.h"
#include "keygen_random.h"
#include "keygen_misc.h"

#include <windows.h>

/*
	Elliptic-Curve Cryptography code follows. This is the standard Digital
	Signature Algorithm (DSA) modified to use the elliptic-curve discrete
	logarithm problem, rather than the standard one; it provides much stronger
	security for the same number of bits.

	We're using a 113-bit type-2 Koblitz curve ("an elliptic curve whose
	defining equation has coefficients in the binary field F(2)"). This has
	roughly the same strength as 56-bit symmetric encryption, and more than
	512-bit RSA. Solving the Certicom ECC2K-108 challenge (which used a
	slightly weaker curve of the same form) required the equivalent of 500
	years on a single 450MHz machine.

	Note that it is theoretically possible that the very form of Koblitz curves
	may someday allow an attacker to break this scheme much more easily than at
	present. If this ever happens, we'll need to make a new key system before
	someone attacks this one.

	There is already a way to make attacks on it about ten to fifteen times
	easier than it was originally thought, reducing the security by roughly
	four bits; this attack was well-known before the ECC2K-108 challenge was
	solved, and was used in it. This system still provides more than enough
	security against a single attacker, or even a moderately-sized group of
	attackers -- if it takes more than a few weeks of computer time for a
	fifty-person group to crack a key (far larger than any cracking group we
	know of at present), then it's more than strong enough to keep software
	secure against them. This setup should, barring new mathematical
	discoveries, provide enough security to last us until 2010 or 2012 at
	least.
*/

/* The curve parameters we're using. */
#define ECC_NUMBITS	113
#define ECC_TYPE2
#define ECC_PRIMEORDER "5192296858534827627896703833467507"

#ifdef ECC_TYPE2
#define ECC_FIELDPRIME ((ECC_NUMBITS<<1)+1)
#else
#define ECC_FIELDPRIME (ECC_NUMBITS+1)
#endif

typedef	short int ECC_INDEX;
typedef unsigned long ECC_ELEMENT;

#define ECC_ELEMENTBITS	(sizeof(ECC_ELEMENT)*8)

#define	ECC_NUMWORD		(ECC_NUMBITS/ECC_ELEMENTBITS)
#define ECC_UPRSHIFT	(ECC_NUMBITS%ECC_ELEMENTBITS)
#define ECC_MAXLONG		(ECC_NUMWORD+1)

#define ECC_MAXBITS		(ECC_MAXLONG*ECC_ELEMENTBITS)
#define ECC_MAXSHIFT	(ECC_ELEMENTBITS-1)
#define ECC_MSB			(1L<<ECC_MAXSHIFT)

#define ECC_UPRBIT		(1L<<(ECC_UPRSHIFT-1))
#define ECC_UPRMASK		(~(-1L<<ECC_UPRSHIFT))
#define ECC_SUMLOOP(i)	for (i=0; (unsigned int)i<ECC_MAXLONG; i++)

/* Structures used for ECC functions. */

typedef struct
{
    /* The 'e' array must be large enough to accept a 128-bit MD5 signature. */
    ECC_ELEMENT e[ECC_MAXLONG];
} ECC_FIELD;

typedef struct
{
    ECC_FIELD x;
    ECC_FIELD y;
} ECC_POINT;

typedef struct
{
    ECC_INDEX form; /* 'form' is just a fast way to check if a2==0 */
    ECC_FIELD a2; /* if form is zero, then: y^2 + xy = x^3 + a_6 */
    ECC_FIELD a6; /* otherwise: y^2 + xy = x^3 + a_2*x^2 + a_6 ("twist" curve) */
} ECC_CURVE;

/* These structures described in IEEE P1363 Nov. 1997. */

typedef struct
{
    ECC_CURVE crv;
    ECC_POINT pnt;
    ECC_FIELD pnt_order;
    ECC_FIELD cofactor;
} EC_PARAMETER;

typedef struct
{
    ECC_FIELD prvt_key;
    ECC_POINT pblc_key;
} EC_KEYPAIR;

typedef struct
{
    ECC_FIELD c;
    ECC_FIELD d;
} SIGNATURE;

void BigIntToField(BigInt _source, ECC_FIELD *target);
void FieldToBigInt(ECC_FIELD *source, BigInt target);
void ECC_RotateLeft(ECC_FIELD *a);
void ECC_RotateRight(ECC_FIELD *a);
void Field_Clear(ECC_FIELD *a);
void Field_Copy(ECC_FIELD *a, ECC_FIELD *b);
void Field_Set(ECC_FIELD *place);
void ECC_Multiply(ECC_FIELD *a, ECC_FIELD *b, ECC_FIELD *c);
void ECC_Inverse(ECC_FIELD *a, ECC_FIELD *result);
void ECC_RandomFieldOriginal(ECC_FIELD *value);
void ECC_RandomFieldImproved(ECC_FIELD *value);
void ECC_PointCopy(ECC_POINT *p1, ECC_POINT *p2);
void ECC_PointAdd(ECC_POINT *p1, ECC_POINT *p2, ECC_POINT *p3, ECC_CURVE *curv);
void ECC_PointSubtract(ECC_POINT *p1, ECC_POINT *p2, ECC_POINT *p3, ECC_CURVE *curv);
void ECC_PointDouble(ECC_POINT *p1, ECC_POINT *p3, ECC_CURVE *curv);
void ECC_PointMultiply(ECC_FIELD *k, ECC_POINT *p, ECC_POINT *r, ECC_CURVE *curv);
void ECC_KeyGenerationPrimitive(EC_PARAMETER *Base, EC_KEYPAIR *Key, BigInt init);
void BigInt_Hash(char *Message, unsigned long length, BigInt hash_value);
void ECC_MakeSignature(char *Message, unsigned long length, EC_PARAMETER *public_curve, ECC_FIELD *secret_key, SIGNATURE *signature, HWND log);
void ECC_InitializeTable(void);
void ECC_FOFX(ECC_FIELD *x, ECC_CURVE *curv, ECC_FIELD *f);
int ECC_Quadratic(ECC_FIELD *a, ECC_FIELD *b, ECC_FIELD *y);
void ECC_Embed(ECC_FIELD *data, ECC_CURVE *curv, ECC_INDEX incrmt, ECC_INDEX root, ECC_POINT *pnt);
void ECC_RandomPoint(ECC_POINT *point, ECC_CURVE *curve);
void ECC_Initialize(EC_PARAMETER *Base, EC_KEYPAIR *Signer, unsigned long basepointinit, const char *_rndinitstring, char* prvt_text, char* pubx_text, char* puby_text);

#endif
