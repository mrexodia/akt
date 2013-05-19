#include "keygen_bigint.h"

/*
	--------------------
	The BigInt functions
	--------------------
*/

/* private */
void BigInt_Realloc(BigInt n, int newcount, int copydata)
{
    if(newcount<0) newcount=0;
    if(newcount<n->alloc)
    {
        if(copydata)
        {
            if(newcount>n->length) memset(n->digits+n->length, 0, (newcount-n->length)*sizeof(DIGIT));
            n->length=newcount;
        }
        else
        {
            n->length=newcount;
            memset(n->digits, 0, n->length*sizeof(DIGIT));
        }
    }
    else if(copydata)
    {
        DIGIT *olddigits=n->digits;
        n->digits=(DIGIT*)malloc(newcount*sizeof(DIGIT));
        memcpy(n->digits, olddigits, n->length*sizeof(DIGIT));
        memset(n->digits+n->length, 0, (newcount-n->length)*sizeof(DIGIT));
        n->length=n->alloc=newcount;
        free(olddigits);
    }
    else
    {
        free(n->digits);
        n->length=n->alloc=newcount;
        n->digits=(DIGIT*)malloc(newcount*sizeof(DIGIT));
        memset(n->digits, 0, n->length*sizeof(DIGIT));
    }
}

/* private */
void BigInt_FindMSD(BigInt n)
{
    DIGIT *d=n->digits+n->length-1;
    while(d>n->digits && *d==0) --d;
    n->length=(d-n->digits)+1;
    /*
    if (n->length==0) {
    	if (n->alloc<1) BigInt_Realloc(n, 1, 0);
    	n->length=1;
    }
    */
    if(n->length==0 || (n->length==1 && n->digits[0]==0)) n->negative=0;
}

/* private */
int BigInt_Compare_SignOptional(BigInt b1, BigInt b2, int ignoresign)
{
    int z1=0, z2=0, answer=0, x;

    if(!ignoresign)
    {
        /* Are b1 and/or b2 zero? */
        if(b1->length==0 || (b1->length==1 && b1->digits[0]==0)) z1=1;
        if(b2->length==0 || (b2->length==1 && b2->digits[0]==0)) z2=1;

        if(z1 && z2) return 0;
        if(z1) return b2->negative ? 1 : -1;
        if(z2) return b1->negative ? -1 : 1;

        if(b1->negative!=b2->negative) return (b1->negative ? -1 : 1);
    }

    if(b1->length!=b2->length)
    {
        answer=((b1->length<b2->length) ? -1 : 1);
    }
    else
    {
        for(x=b1->length-1; !answer && x>=0; --x) answer=b1->digits[x]-b2->digits[x];
    }

    if(!ignoresign && b1->negative) return -answer;
    return answer;
}

#ifdef DEBUG
void BigInt_Dump(BigInt n, const char *title)
{
    int x;
    if(title && *title) printf("%s\n", title);
    printf("Dump: length=%d, negative=%s\n", n->length, n->negative ? "true" : "false");
    printf("%02X%02X")
#if BITS_PER_DIGIT==8
    for(x=0; x<n->length; x+=2)
        printf("    Digit %02d: %02X%02X\n", x, x+1<n->length ? n->digits[x+1] : 0, n->digits[x]);
#else
    for(x=0; x<n->length; ++x)
        printf("    Digit %d: %04X\n", x, n->digits[x]);
#endif
}
#endif

int BigInt_IsEven(BigInt n)
{
    if(n->length<1) return 1;
    return !(n->digits[0] & 0x01);
}

int BigInt_IsOdd(BigInt n)
{
    if(n->length<1) return 0;
    return (n->digits[0] & 0x01);
}

int BigInt_IsZero(BigInt n)
{
    return (n->length==0 || (n->length==1 && n->digits[0]==0));
}

int BigInt_IsOne(BigInt n)
{
    return (n->length==1 && n->digits[0]==1);
}

BigInt BigInt_Create(void)
{
    struct BigIntBase *b=(struct BigIntBase *)malloc(sizeof(struct BigIntBase));
    b->length=b->alloc=0;
    b->negative=0;
    b->digits=0;
    return b;
}

void BigInt_Destroy(BigInt n)
{
    if(n->digits) free(n->digits);
    free(n);
}

void BigInt_Copy(BigInt target, BigInt source)
{
    BigInt_Realloc(target, source->length, 0);
    target->negative=source->negative;
    memcpy(target->digits, source->digits, source->length*sizeof(DIGIT));
}

void BigInt_Set(BigInt n, signed long init)
{
    int neg=0;
    if(init<0)
    {
        neg=1;
        init=-init;
    }
    BigInt_SetU(n, init);
    n->negative=neg;
}

void BigInt_SetU(BigInt n, unsigned long init)
{
    int index;

    BigInt_Realloc(n, sizeof(unsigned long)/sizeof(DIGIT), 0);
    for(index=0; init; ++index)
    {
        n->digits[index]=(DIGIT)(init&DIGIT_MASK);
        init=init>>BITS_PER_DIGIT;
    }
    BigInt_FindMSD(n);
}

signed long BigInt_Get(BigInt n)
{
    signed long value=BigInt_GetU(n);
    if(value<0) value=-value;
    if(n->negative) value=-value;
    return value;
}

unsigned long BigInt_GetU(BigInt n)
{
    unsigned long value=0;
    int x;

    for(x=(sizeof(unsigned long)/sizeof(DIGIT))-1; x>=0; --x)
    {
        value<<=BITS_PER_DIGIT;
        if(x<n->length) value|=n->digits[x];
    }
    return value;
}

BigInt BigInt_Zero(void)
{
    static BigInt zero=0;
    if(!zero) zero=BigInt_Create();
    return zero;
}

BigInt BigInt_One(void)
{
    static BigInt one=0;
    if(!one)
    {
        one=BigInt_Create();
        BigInt_Set(one, 1);
    }
    return one;
}

int BigInt_Compare(BigInt a, BigInt b)
{
    return BigInt_Compare_SignOptional(a, b, 0);
}

void BigInt_Add(BigInt a, BigInt b, BigInt answer)
{
    DIGIT *ad, *bd, *ansd;
    int level=0, x, carry;
    WORKING_DIGIT n;
    BigInt savedb;
    savedb=BigInt_Zero();

    /* Check for zeros */
    if(a->length==0 || (a->length==1 && a->digits[0]==0))
    {
        BigInt_Copy(answer, b);
        return;
    }
    else if(b->length==0 || (b->length==1 && b->digits[0]==0))
    {
        BigInt_Copy(answer, a);
        return;
    }

    /* Handle mismatched signs, step 1 */
    if(a->negative!=b->negative)
    {
        savedb=BigInt_Create();
        BigInt_Copy(savedb, b);

        /* Bug fix. If 'a' and 'b' aren't the same length, we need to expand
        the shorter one to the same size as the longer one before we invert it.
        This was the original source of the invert problem. */
        if(b->length<a->length) BigInt_Realloc(b, a->length, 1);
        else if(a->length<b->length) BigInt_Realloc(a, b->length, 1);

        level=b->length;
        BigInt_Invert(b);
    }

    /* Make the numbers both the same size */
    if(a->length!=b->length)
    {
        if(a->length>b->length) BigInt_Realloc(b, a->length, 1);
        else BigInt_Realloc(a, b->length, 1);
    }

    /* Allocate one more digit for the answer */
    BigInt_Realloc(answer, a->length+1, 0);
    answer->negative=a->negative;

    carry=0;
    ad=a->digits;
    bd=b->digits;
    ansd=answer->digits;
    for(x=0; x<a->length; ++x)
    {
        n=(WORKING_DIGIT)(*ad++)+(WORKING_DIGIT)(*bd++)+carry;

        if(n>=OVERFLOW_DIGIT)
        {
            carry=1;
            *ansd++=(DIGIT)(n-OVERFLOW_DIGIT);
        }
        else
        {
            carry=0;
            *ansd++=(DIGIT)(n);
        }
    }
    *ansd=carry;

    /* Find the most significant digits, for efficiency */
    BigInt_FindMSD(answer);
    BigInt_FindMSD(b);
    BigInt_FindMSD(a);

    if(level!=0)
    {
        /* Handle mismatched signs, step 2 */
        BigInt_Copy(b, savedb);
        BigInt_Destroy(savedb);

        if(answer->length>level)
        {
            --answer->digits[level];
            BigInt_FindMSD(answer);
        }
        else
        {
            BigInt_Realloc(answer, level, 1);
            BigInt_Invert(answer);

#ifdef DEBUG1
            BigInt_Dump(answer, "inverted, step 2");
#endif
        }
    }
}

void BigInt_Subtract(BigInt a, BigInt b, BigInt answer)
{
    b->negative=!b->negative;
    BigInt_Add(a, b, answer);
    b->negative=!b->negative;
}

void BigInt_Multiply(BigInt a, BigInt b, BigInt answer)
{
    int carry, digit1, digit2, digita;
    DIGIT *ad, *ae, *bd, *be, *ansd;
    WORKING_DIGIT t, addt;

    /* If the numbers are the same, use square instead -- more efficient */
    /*x*/

    /* Allocate the appropriate number of digits */
    BigInt_Realloc(answer, a->length+b->length+1, 0);

    /* Multiply the digits, starting at the least-significant one */
    for(ad=a->digits, ae=ad+a->length, digit1=0; ad<ae; ++ad, ++digit1)
    {
        for(bd=b->digits, be=bd+b->length, digit2=0; bd<be; ++bd, ++digit2)
        {
            /* Multiply the digits and add the result to the answer */
            carry=0;
            digita=digit1+digit2;
            ansd=answer->digits+digita;

            t=(*ad)*(*bd);
            addt=(*ansd)+(t & DIGIT_MASK);
            if(addt >= OVERFLOW_DIGIT) carry=1;
            (*ansd++)=(DIGIT)(addt);

            addt=(*ansd)+((t>>BITS_PER_DIGIT)&DIGIT_MASK)+carry;
            if(addt >= OVERFLOW_DIGIT) carry=1;
            else carry=0;
            (*ansd++)=(DIGIT)(addt);

            while(carry)
            {
                addt=(*ansd)+1;
                (*ansd++)=(DIGIT)addt;
                if(addt<OVERFLOW_DIGIT) break;
            }
        }
    }

    answer->negative=(a->negative ^ b->negative);
    BigInt_FindMSD(answer);
}

int BigInt_Divide(BigInt a, BigInt b, BigInt answer, BigInt remainder)
{
    //TODO: fix something here (memleak temp1 or t)
    int compare, i, signa, signb;
    WORKING_DIGIT high, low, t;
    BigInt temp1, temp2;

    temp1=BigInt_Create();
    temp2=BigInt_Create();

    signa=a->negative;
    a->negative=0;
    signb=b->negative;
    b->negative=0;

    /* Check for divide-by-zero, it's not allowed */
    if(b->length==1 && b->digits[0]==0) return 0;

    /* Compare a and b, to see if we can take a shortcut */
    compare=BigInt_Compare_SignOptional(a, b, 1);
    if(compare<0)
    {
        BigInt_Set(answer, 0);
        BigInt_Copy(remainder, a);
        return 1;
    }
    else if(compare==0)
    {
        BigInt_Set(answer, 1);
        BigInt_Set(remainder, 0);
        return 1;
    }

    BigInt_Realloc(answer, a->length, 0);
    BigInt_Set(remainder, 0);
    for(i=1; i<=a->length; ++i)
    {
        /* remainder=(remainder<<BITS_PER_DIGIT)+a->digits[a->length-i]; */
        BigInt_Copy(temp1, remainder);
        BigInt_Shift(temp1, BITS_PER_DIGIT, remainder);
        remainder->digits[0]=a->digits[a->length-i];

        if(BigInt_Compare_SignOptional(remainder, b, 1)>=0)
        {
            high=OVERFLOW_DIGIT;
            low=0;
            while(low<high)
            {
                t=((high-low)/2)+low;

                /* if ((b*t)>remainder) high=t; else low=t+1; */
                BigInt_Set(temp2, t);
                BigInt_Multiply(b, temp2, temp1);
                if(BigInt_Compare(temp1, remainder)>0) high=t;
                else low=t+1;
            }
            t=low-1;
            answer->digits[a->length-i]=(DIGIT)(t);

            /* remainder=remainder-(b*t) */
            BigInt_Set(temp2, t);
            BigInt_Multiply(b, temp2, temp1);
            BigInt_Subtract(remainder, temp1, temp2);
            BigInt_Copy(remainder, temp2);
        }
        else answer->digits[a->length-i]=0;
    }

    a->negative=signa;
    b->negative=signb;
    answer->negative=(a->negative ^ b->negative);
    BigInt_FindMSD(answer);
    BigInt_Destroy(temp2);
    BigInt_Destroy(temp1);
    return 1;
}

void BigInt_PowerModulus(BigInt n, BigInt exp, BigInt modulus, BigInt answer)
{
    DIGIT *eptr, *eend, emask;
    BigInt p, temp, r;
    r=BigInt_Zero();

    /* If n is negative and the exponent is odd, the answer will be negative. */
    int neg=(n->negative && (exp->digits[0]&0x01));

    p=BigInt_Create();
    temp=BigInt_Create();
    if(modulus) r=BigInt_Create();

    BigInt_Copy(p, n);
    p->negative=0;

    BigInt_Set(answer, 1);

    /* Continue this loop while the exponent is not zero */
    eptr=exp->digits;
    eend=eptr+exp->length;
    emask=0x01;
    while(eptr<eend)
    {
        /* If e is odd, multiply the answer by p */
        if((*eptr) & emask)
        {
            BigInt_Copy(temp, answer);
            BigInt_Multiply(temp, p, answer);

            if(modulus)
            {
                BigInt_Modulus(answer, modulus, r);
                BigInt_Copy(answer, r);
            }
        }

        /* Now square p (mod modulus, if supplied) */
        BigInt_Multiply(p, p, temp);
        if(modulus) BigInt_Modulus(temp, modulus, p);
        else BigInt_Copy(p, temp);

        /* Shift e right by one bit */
        emask<<=1;
        if(emask==0)
        {
            ++eptr;
            emask=0x01;
        }
    }
    answer->negative=neg;

    if(modulus) BigInt_Destroy(r);
    BigInt_Destroy(temp);
    BigInt_Destroy(p);
}

void BigInt_Power(BigInt n, BigInt exp, BigInt answer)
{
    BigInt_PowerModulus(n, exp, 0, answer);
}

void BigInt_And(BigInt a, BigInt b, BigInt answer)
{
    DIGIT *ansd, *anse, *z;

    if(BigInt_IsZero(a) || BigInt_IsZero(b))
    {
        BigInt_Copy(answer, BigInt_Zero());
        BigInt_FindMSD(answer);
        return;
    }
    else if(a->length >= b->length)
    {
        BigInt_Copy(answer, a);
        z=b->digits;
    }
    else
    {
        BigInt_Copy(answer, b);
        z=a->digits;
    }

    ansd=answer->digits;
    anse=ansd+answer->length;
    while(ansd<anse)(*ansd++)&=(*z++);
    BigInt_FindMSD(answer);
}

void BigInt_Or(BigInt a, BigInt b, BigInt answer)
{
    DIGIT *ansd, *anse, *z;

    if(a->length >= b->length)
    {
        BigInt_Copy(answer, a);
        z=b->digits;
    }
    else
    {
        BigInt_Copy(answer, b);
        z=a->digits;
    }

    ansd=answer->digits;
    anse=ansd+answer->length;
    while(ansd<anse)(*ansd++)|=(*z++);
    BigInt_FindMSD(answer);
}

void BigInt_Xor(BigInt a, BigInt b, BigInt answer)
{
    DIGIT *ansd, *anse, *z;

    if(a->length >= b->length)
    {
        BigInt_Copy(answer, a);
        z=b->digits;
    }
    else
    {
        BigInt_Copy(answer, b);
        z=a->digits;
    }

    ansd=answer->digits;
    anse=ansd+answer->length;
    while(ansd<anse)(*ansd++)^=(*z++);
    BigInt_FindMSD(answer);
}

void BigInt_Shift(BigInt n, int places, BigInt answer)
{
    /* Negative 'places' shifts right */
    int bytes, bits, neg=0, x;

    if(places<0)
    {
        neg=1;
        places=-places;
    }
    bytes=places/BITS_PER_DIGIT;
    bits=places%BITS_PER_DIGIT;
    answer->negative=n->negative;
    if(bytes)
    {
        /* Bytes only */
        if(neg)
        {
            /* Right-shift */
            BigInt_Realloc(answer, n->length-bytes, 0);
            for(x=0; x<n->length-bytes; ++x) answer->digits[x]=n->digits[x+bytes];
        }
        else
        {
            /* Left-shift */
            BigInt_Realloc(answer, n->length+bytes+1, 0);
            for(x=0; x<n->length; ++x) answer->digits[x+bytes]=n->digits[x];
        }
    }
    else BigInt_Copy(answer, n);

    if(bits)
    {
        if(neg)
        {
            /* Right-shift */
            for(x=0; x<answer->length; ++x)
            {
                answer->digits[x]>>=bits;
                if(x+1<answer->length) answer->digits[x]|=answer->digits[x+1]<<(BITS_PER_DIGIT-bits);
            }
        }
        else
        {
            /* Left-shift */
            BigInt_Realloc(answer, answer->length+1, 1);
            for(x=answer->length-1; x>=0; --x)
            {
                answer->digits[x]<<=bits;
                if(x-1>=0) answer->digits[x]|=answer->digits[x-1]>>(BITS_PER_DIGIT-bits);
            }
        }
    }
    BigInt_FindMSD(answer);
}

void BigInt_Invert(BigInt n)
{
    WORKING_DIGIT w;
    DIGIT *d, *e;

    d=n->digits;
    e=d+n->length;
    n->negative=!n->negative;
    while(d<e)
    {
        *d=(DIGIT)(OVERFLOW_DIGIT-1-(*d));
        ++d;
    }

    d=n->digits;
    while(d<e)
    {
        w=(*d)+1;
        (*d++)=(DIGIT)(w);
        if(w<OVERFLOW_DIGIT) break;
    }

    BigInt_FindMSD(n);
}

void BigInt_Modulus(BigInt n, BigInt mod, BigInt answer)
{
    BigInt q=BigInt_Create();
    BigInt temp=BigInt_Create();

    if(n->negative)
    {
        BigInt_Divide(n, mod, q, temp);
        BigInt_Subtract(mod, temp, answer);
    }
    else if(BigInt_Compare(n, mod)>=0)
    {
        BigInt_Divide(n, mod, q, answer);
    }
    else BigInt_Copy(answer, n);

    BigInt_Destroy(temp);
    BigInt_Destroy(q);
}

void BigInt_GCD(BigInt _n, BigInt _m, BigInt answer)
{
    BigInt n, m, u1, u2, u3, t1, t2, t3, temp, uninit;
    DIGIT *p, *e, mask;
    int k, t;

    n=BigInt_Create();
    m=BigInt_Create();
    u1=BigInt_Create();
    u2=BigInt_Create();
    u3=BigInt_Create();
    t1=BigInt_Create();
    t2=BigInt_Create();
    t3=BigInt_Create();
    temp=BigInt_Create();

    BigInt_Copy(n, _n);
    BigInt_Copy(m, _m);
    n->negative=m->negative=0;

    /* Factor out any common twos. */
    p=n->digits;
    e=p+n->length;
    t=0;
    while(p<e)
    {
        mask=0x01;
        while(mask)
        {
            if((*p) & mask) break;
            mask<<=1;
            ++t;
        }
        if(mask) break;
        ++p;
    }
    k=t;

    p=m->digits;
    e=p+m->length;
    t=0;
    while(p<e)
    {
        mask=0x01;
        while(mask)
        {
            if((*p) & mask) break;
            mask<<=1;
            ++t;
        }
        if(mask) break;
        ++p;
    }
    if(t<k) k=t;

    if(k)
    {
        BigInt_Shift(n, -k, temp);
        BigInt_Copy(n, temp);
        BigInt_Shift(m, -k, temp);
        BigInt_Copy(m, temp);
    }

    BigInt_Set(u1, 1);
    BigInt_Set(u2, 0);
    BigInt_Copy(u3, n);
    BigInt_Copy(t1, m);
    BigInt_Subtract(n, BigInt_One(), t2);
    BigInt_Copy(t3, m);
    do
    {
        do
        {
            if(!(u3->digits[0] & 0x01))
            {
                if((u1->digits[0] & 0x01) || (u2->digits[0] & 0x01))
                {
                    BigInt_Add(u1, m, temp);
                    BigInt_Copy(u1, temp);
                    BigInt_Add(u2, n, temp);
                    BigInt_Copy(u2, temp);
                }

                BigInt_Shift(u1, -1, temp);
                BigInt_Copy(u1, temp);
                BigInt_Shift(u2, -1, temp);
                BigInt_Copy(u2, temp);
                BigInt_Shift(u3, -1, temp);
                BigInt_Copy(u3, temp);
            }

            if(!(t3->digits[0] & 0x01) || BigInt_Compare(u3, t3)<0)
            {
                /* Swap the u's with the t's */
                uninit=u1;
                u1=t1;
                t1=uninit;
                uninit=u2;
                u2=t2;
                t2=uninit;
                uninit=u3;
                u3=t3;
                t3=uninit;
            }
        }
        while(!(u3->digits[0] & 0x01));

        while(BigInt_Compare(u1, t1)<0 || BigInt_Compare(u2, t2)<0)
        {
            BigInt_Add(u1, m, temp);
            BigInt_Copy(u1, temp);
            BigInt_Add(u2, n, temp);
            BigInt_Copy(u2, temp);
        }

        BigInt_Subtract(u1, t1, temp);
        BigInt_Copy(u1, temp);
        BigInt_Subtract(u2, t2, temp);
        BigInt_Copy(u2, temp);
        BigInt_Subtract(u3, t3, temp);
        BigInt_Copy(u3, temp);
    }
    while(t3->length>1 || t3->digits[0]>0);

    while(BigInt_Compare(u1, m)>=0 && BigInt_Compare(u2, n)>=0)
    {
        BigInt_Subtract(u1, m, temp);
        BigInt_Copy(u1, temp);
        BigInt_Subtract(u2, n, temp);
        BigInt_Copy(u2, temp);
    }

    if(u3->length>1 || u3->digits[0]!=0)
    {
        BigInt_Shift(u3, k, answer);
    }
    else
    {
        BigInt_Shift(BigInt_One(), k, answer);
    }

    BigInt_Destroy(temp);
    BigInt_Destroy(t3);
    BigInt_Destroy(t2);
    BigInt_Destroy(t1);
    BigInt_Destroy(u3);
    BigInt_Destroy(u2);
    BigInt_Destroy(u1);
    BigInt_Destroy(m);
    BigInt_Destroy(n);
}

int BigInt_ModularInverse(BigInt n, BigInt m, BigInt answer)
{
    /* Calculates the modular inverse of n mod m, or (n^(-1)) mod m, defined as
    b, where n*b corresponds to 1 (mod m), using the binary extended GCD
    algorithm. */
    BigInt u1, u2, u3, t1, t2, t3, temp, uninit;
    int t;

    if(m->negative) return 0;
    if(n->negative)
    {
        temp=BigInt_Create();
        n->negative=0;
        t=BigInt_ModularInverse(n, m, temp);
        n->negative=1;
        BigInt_Add(temp, m, answer);
        BigInt_Destroy(temp);
        return t;
    }

    /* If they're both even, then GCD(n,m)!=1, and no inverse is possible. */
    if(BigInt_IsEven(n) && BigInt_IsEven(m)) return 0;

    u1=BigInt_Create();
    u2=BigInt_Create();
    u3=BigInt_Create();
    t1=BigInt_Create();
    t2=BigInt_Create();
    t3=BigInt_Create();
    temp=BigInt_Create();

    BigInt_Set(u1, 1);
    BigInt_Set(u2, 0);
    BigInt_Copy(u3, n);
    BigInt_Copy(t1, m);
    BigInt_Subtract(n, BigInt_One(), t2);
    BigInt_Copy(t3, m);
    do
    {
        do
        {
            if(BigInt_IsEven(u3))
            {
                if(BigInt_IsOdd(u1) || BigInt_IsOdd(u2))
                {
                    BigInt_Add(u1, m, temp);
                    BigInt_Copy(u1, temp);
                    BigInt_Add(u2, n, temp);
                    BigInt_Copy(u2, temp);
                }

                BigInt_Shift(u1, -1, temp);
                BigInt_Copy(u1, temp);
                BigInt_Shift(u2, -1, temp);
                BigInt_Copy(u2, temp);
                BigInt_Shift(u3, -1, temp);
                BigInt_Copy(u3, temp);
            }

            if(BigInt_IsEven(t3) || BigInt_Compare(u3, t3)<0)
            {
                /* Swap the u's with the t's */
                uninit=u1;
                u1=t1;
                t1=uninit;
                uninit=u2;
                u2=t2;
                t2=uninit;
                uninit=u3;
                u3=t3;
                t3=uninit;
            }
        }
        while(BigInt_IsEven(u3));

        while(BigInt_Compare(u1, t1)<0 || BigInt_Compare(u2, t2)<0)
        {
            BigInt_Add(u1, m, temp);
            BigInt_Copy(u1, temp);
            BigInt_Add(u2, n, temp);
            BigInt_Copy(u2, temp);
        }

        BigInt_Copy(temp, u1);
        BigInt_Subtract(temp, t1, u1);
        BigInt_Copy(temp, u2);
        BigInt_Subtract(temp, t2, u2);
        BigInt_Copy(temp, u3);
        BigInt_Subtract(temp, t3, u3);
    }
    while(BigInt_Compare(t3, BigInt_Zero())>0);

    while(BigInt_Compare(u1, m)>=0 && BigInt_Compare(u2, n)>=0)
    {
        BigInt_Subtract(u1, m, temp);
        BigInt_Copy(u1, temp);
        BigInt_Subtract(u2, n, temp);
        BigInt_Copy(u2, temp);
    }

    t=1;
    if(!BigInt_IsOne(u3)) t=0;
    if(t) BigInt_Copy(answer, u1);

    BigInt_Destroy(temp);
    BigInt_Destroy(t3);
    BigInt_Destroy(t2);
    BigInt_Destroy(t1);
    BigInt_Destroy(u3);
    BigInt_Destroy(u2);
    BigInt_Destroy(u1);

    return t;
}

void BigInt_ToString(BigInt s, int base, char* d)
{
    char digits[]="0123456789ABCDEF";
    d[0]=0;
    if(!BigInt_Compare(s, BigInt_Zero()))
    {
        strcpy(d, "0");
        return;
    }
    BigInt ten, answer, remainder, copy_s;
    ten=BigInt_Create();
    remainder=BigInt_Create();
    answer=BigInt_Create();
    copy_s=BigInt_Create();
    BigInt_Copy(copy_s, s);
    BigInt_SetU(ten, base);
    int j=0;
    while(BigInt_Compare(copy_s, BigInt_Zero()))
    {
        BigInt_Divide(copy_s, ten, answer, remainder);
        BigInt_Copy(copy_s, answer);
        j+=sprintf(d+j, "%c", digits[BigInt_Get(remainder)]);
    }
    BigInt_Destroy(ten);
    BigInt_Destroy(remainder);
    BigInt_Destroy(answer);
    BigInt_Destroy(copy_s);
    _strrev(d);
}

bool BigInt_ToHexString(BigInt n, char* d)
{
    if(!n or !d)
        return false;
    if(n->length)
    {
        if(!n->digits or !n->alloc)
            return false;
        if(n->negative)
            strcpy(d, "-");
        for(int i=0,j=0; i<n->length; i++)
        {
            if(!i)
                j+=sprintf(d+j, "%X", n->digits[n->length-1]);
            else
                j+=sprintf(d+j, "%.2X", n->digits[n->length-i-1]);
        }
    }
    else
        strcpy(d, "0");
    return true;
}

bool BigInt_FromHexString(const char* source, BigInt dest)
{
    int len;
    unsigned int c;
    const char* s=source;
    char s_copy[256]="";
    char temp[256]="";
    bool negative=false;

    if(s[0]=='-') //Consider negative numbers
    {
        negative=true;
        s++;
    }
    len=strlen(s);
    if(!len)
    {
        BigInt_Set(dest, 0);
        return false;
    }

    for(int i=0,j=0; i<len; i++) //Format hex characters
        if(isxdigit(s[i]))
            j+=sprintf(temp+j, "%c", s[i]);

    //We hate prepended zeroes
    s=temp;
    while(*s=='0')
        s++;

    len=strlen(s); //Recalculate length
    if(!len)
    {
        BigInt_Set(dest, 0);
        return false;
    }

    if(len%2) //Prepend zero if needed
        sprintf(s_copy, "0%s", s);
    else
        strcpy(s_copy, s);

    memset(temp, 0, 256); //Empty buffer for re-use.

    BigInt_Set(dest, 0);

    if(negative)
        dest->negative=1;

    //Update our bignum struct & alloc memory
    dest->length=strlen(s_copy)/2;
    dest->alloc=dest->length+1;
    dest->digits=(DIGIT*)malloc(dest->alloc);
    memset(dest->digits, 0, dest->alloc); //zero memory

    //Interpret hex chars
    for(int i=0,j=0; i<dest->length; i++,j+=2)
    {
        memcpy(temp, s_copy+j, 2);
        sscanf(temp, "%x", &c);
        dest->digits[dest->length-i-1]=(DIGIT)c;
    }
    return true;
}

bool BigInt_FromDecString(const char* source, BigInt dest)
{
    if(!source or !dest)
        return false;
    const char *c=source;
    BigInt t, t2, base_;
    int neg=0;

    t=BigInt_Create();
    t2=BigInt_Create();
    base_=BigInt_Create();

    BigInt_SetU(base_, 10);
    BigInt_Set(dest, 0);

    if(!strlen(c))
        return false;

    if(*c=='-')
    {
        neg=1;
        ++c;
    }
    if(!strlen(c))
        return false;
    while(*c)
    {
        if(*c>='0' and *c<='9')
        {
            BigInt_Set(t, *c-'0');
            BigInt_Multiply(dest, base_, t2);
            BigInt_Add(t2, t, dest);
        }
        else
            break;
        ++c;
    }

    if(neg and dest->length and dest->digits[0])
        dest->negative=1;

    BigInt_Destroy(base_);
    BigInt_Destroy(t2);
    BigInt_Destroy(t);
    return true;
}

bool BigInt_FromString(const char* source, int base, BigInt dest)
{
    if(base==16)
        return BigInt_FromHexString(source, dest);
    else if(base==10)
        return BigInt_FromDecString(source, dest);
    return false;
}

/*void BigInt_Dump(BigInt n, const char *title, HWND edit)
{
    char log_string[1024]="";
    if(!n or !title)
        return;
    strcpy(log_string, title);
    sprintf(log_string, "%s:\r\n  length : %d\r\n   alloc : %d\r\nnegative : %d\r\n hdigits : ", log_string, n->length, n->alloc, n->negative);
    if(n->length)
    {
        for(int i=0; i<n->length; i++)
        {
            if(!i)
                sprintf(log_string, "%s%X", log_string, n->digits[n->length-i-1]);
            else
                sprintf(log_string, "%s%.2X", log_string, n->digits[n->length-i-1]);
        }
    }
    else
        sprintf(log_string, "%s0", log_string);
    char decimal[256]="";
    BigInt_ToString(n, 10, decimal);
    sprintf(log_string, "%s\r\n ddigits : %s\r\n", log_string, decimal);
    bool iseven=BigInt_IsEven(n);
    bool isodd=BigInt_IsOdd(n);
    bool iszero=BigInt_IsZero(n);
    bool isone=BigInt_IsOne(n);
    sprintf(log_string, "%s   tests : ", log_string);
    if(iseven)
        strcat(log_string, "even ");
    if(isodd)
        strcat(log_string, "odd ");
    if(iszero)
        strcat(log_string, "zero ");
    if(isone)
        strcat(log_string, "one ");
    MessageBoxA(0,log_string,"",0);
}*/
