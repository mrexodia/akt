#include "keygen_ecc.h"

ECC_INDEX ecc_table[2][ECC_FIELDPRIME];
ECC_INDEX ecc_log2m;

void BigIntToField(BigInt _source, ECC_FIELD *target)
{
    BigInt t_me, source;
    int i;

    t_me=BigInt_Create();
    source=BigInt_Create();

    BigInt_Copy(source, _source);
    ECC_SUMLOOP(i) target->e[i]=0;

    i=ECC_MAXLONG-1;
    while(!BigInt_IsZero(source))
    {
        target->e[i--]=BigInt_GetU(source);
        BigInt_Shift(source, -32, t_me);
        BigInt_Copy(source, t_me);
    }

    BigInt_Destroy(source);
    BigInt_Destroy(t_me);
}

void FieldToBigInt(ECC_FIELD *source, BigInt target)
{
    BigInt t_me, t2_me;
    int i;

    t_me=BigInt_Create();
    t2_me=BigInt_Create();

    BigInt_Set(target, 0);

    for(i=0; (unsigned int)i<ECC_MAXLONG; ++i) if(source->e[i]!=0) break;
    for(; (unsigned int)i<ECC_MAXLONG; ++i)
    {
        BigInt_SetU(t_me, source->e[i]);
        BigInt_Shift(target, 32, t2_me);
        BigInt_Add(t2_me, t_me, target);
    }

    BigInt_Destroy(t2_me);
    BigInt_Destroy(t_me);
}

void ECC_RotateLeft(ECC_FIELD *a)
{
    ECC_INDEX i;
    ECC_ELEMENT bit,temp;

    bit=(a->e[0] & ECC_UPRBIT) ? 1L : 0L;
    for(i=ECC_NUMWORD; i>=0; i--)
    {
        temp=(a->e[i] & ECC_MSB) ? 1L : 0L;
        a->e[i]=(a->e[i] << 1)|bit;
        bit=temp;
    }
    a->e[0] &= ECC_UPRMASK;
}

void ECC_RotateRight(ECC_FIELD *a)
{
    ECC_INDEX i;
    ECC_ELEMENT bit,temp;

    bit=(a->e[ECC_NUMWORD] & 1) ? ECC_UPRBIT : 0L;
    ECC_SUMLOOP(i)
    {
        temp=(a->e[i] >> 1) |bit;
        bit=(a->e[i] & 1) ? ECC_MSB : 0L;
        a->e[i]=temp;
    }
    a->e[0] &= ECC_UPRMASK;
}

void Field_Clear(ECC_FIELD *a)
{
    ECC_INDEX i;
    ECC_SUMLOOP(i) a->e[i]=0;
}

void Field_Copy(ECC_FIELD *a, ECC_FIELD *b)
{
    ECC_INDEX i;
    ECC_SUMLOOP(i) b->e[i]=a->e[i];
}

void Field_Set(ECC_FIELD *place)
{
    ECC_INDEX i;
    ECC_SUMLOOP(i) place->e[i]=-1L;
    place->e[0] &= ECC_UPRMASK;
}

void ECC_Multiply(ECC_FIELD *a, ECC_FIELD *b, ECC_FIELD *c)
{
    ECC_INDEX i, j;
    ECC_INDEX zero_index, one_index;
    ECC_FIELD	amatrix[ECC_NUMBITS], copyb;

    Field_Clear(c);
    Field_Copy(b, &copyb);
    Field_Copy(a, &amatrix[0]);
    for(i=1; i<ECC_NUMBITS; i++)
    {
        Field_Copy(&amatrix[i-1], &amatrix[i]);
        ECC_RotateRight(&amatrix[i]);
    }

    zero_index=ecc_table[0][0];
    ECC_SUMLOOP(i) c->e[i]=copyb.e[i] & amatrix[zero_index].e[i];

    for(j=1; j<ECC_NUMBITS; j++)
    {
        ECC_RotateRight(&copyb);
        zero_index=ecc_table[0][j];
        one_index=ecc_table[1][j];
        ECC_SUMLOOP(i) c->e[i] ^= copyb.e[i] & (amatrix[zero_index].e[i] ^ amatrix[one_index].e[i]);
    }
}

void ECC_Inverse(ECC_FIELD *a, ECC_FIELD *result)
{
    ECC_FIELD	shift, temp;
    ECC_INDEX m, s, r, rsft;

    s=ecc_log2m - 1;
    Field_Copy(a, result);
    m=ECC_NUMBITS - 1;

    while(s >= 0)
    {
        r=m >> s;
        Field_Copy(result, &shift);
        for(rsft=0; rsft<(r>>1); rsft++) ECC_RotateLeft(&shift);
        ECC_Multiply(result, &shift, &temp);
        if(r&1)
        {
            ECC_RotateLeft(&temp);
            ECC_Multiply(&temp, a, result);
        }
        else Field_Copy(&temp, result);
        --s;
    }
    ECC_RotateLeft(result);
}

void ECC_RandomFieldOriginal(ECC_FIELD *value)
{
    ECC_INDEX i;
    ECC_SUMLOOP(i) value->e[i]=NextRandomNumber();
    value->e[0]&=ECC_UPRMASK;
}

void ECC_RandomFieldImproved(ECC_FIELD *value)
{
    NextRandomNumber128(value->e);
    value->e[0]&=ECC_UPRMASK;
}

void ECC_PointCopy(ECC_POINT *p1, ECC_POINT *p2)
{
    Field_Copy(&p1->x, &p2->x);
    Field_Copy(&p1->y, &p2->y);
}

void ECC_PointAdd(ECC_POINT *p1, ECC_POINT *p2, ECC_POINT *p3, ECC_CURVE *curv)
{
    ECC_INDEX i;
    ECC_FIELD x1, y1, theta, onex, theta2;

    Field_Clear(&x1);
    Field_Clear(&y1);
    ECC_SUMLOOP(i)
    {
        x1.e[i]=p1->x.e[i] ^ p2->x.e[i];
        y1.e[i]=p1->y.e[i] ^ p2->y.e[i];
    }
    ECC_Inverse(&x1, &onex);
    ECC_Multiply(&onex, &y1, &theta);
    Field_Copy(&theta, &theta2);
    ECC_RotateLeft(&theta2);

    if(curv->form)
    {
        ECC_SUMLOOP(i) p3->x.e[i]=theta.e[i] ^ theta2.e[i] ^ p1->x.e[i] ^ p2->x.e[i] ^ curv->a2.e[i];
    }
    else
    {
        ECC_SUMLOOP(i) p3->x.e[i]=theta.e[i] ^ theta2.e[i] ^ p1->x.e[i] ^ p2->x.e[i];
    }

    ECC_SUMLOOP(i) x1.e[i]=p1->x.e[i] ^ p3->x.e[i];
    ECC_Multiply(&x1, &theta, &theta2);
    ECC_SUMLOOP(i) p3->y.e[i]=theta2.e[i] ^ p3->x.e[i] ^ p1->y.e[i];
}

void ECC_PointSubtract(ECC_POINT *p1, ECC_POINT *p2, ECC_POINT *p3, ECC_CURVE *curv)
{
    ECC_POINT negp;
    ECC_INDEX i;

    Field_Copy(&p2->x, &negp.x);
    Field_Clear(&negp.y);
    ECC_SUMLOOP(i) negp.y.e[i]=p2->x.e[i] ^ p2->y.e[i];
    ECC_PointAdd(p1, &negp, p3, curv);
}

void ECC_PointDouble(ECC_POINT *p1, ECC_POINT *p3, ECC_CURVE *curv)
{
    ECC_FIELD x1, y1, theta, theta2, t1;
    ECC_INDEX i;

    ECC_Inverse(&p1->x, &x1);
    ECC_Multiply(&x1, &p1->y, &y1);
    ECC_SUMLOOP(i) theta.e[i]=p1->x.e[i] ^ y1.e[i];

    Field_Copy(&theta, &theta2);
    ECC_RotateLeft(&theta2);
    if(curv->form)
    {
        ECC_SUMLOOP(i) p3->x.e[i]=theta.e[i] ^ theta2.e[i] ^ curv->a2.e[i];
    }
    else
    {
        ECC_SUMLOOP(i) p3->x.e[i]=theta.e[i] ^ theta2.e[i];
    }

    Field_Set(&y1);
    ECC_SUMLOOP(i) y1.e[i] ^= theta.e[i];
    ECC_Multiply(&y1, &p3->x, &t1);
    Field_Copy(&p1->x, &x1);
    ECC_RotateLeft(&x1);
    ECC_SUMLOOP(i) p3->y.e[i]=x1.e[i] ^ t1.e[i];
}

void ECC_PointMultiply(ECC_FIELD *k, ECC_POINT *p, ECC_POINT *r, ECC_CURVE *curv)
{
    char blncd[ECC_NUMBITS+1];
    ECC_INDEX bit_count, i;
    ECC_ELEMENT notzero;
    ECC_FIELD number;
    ECC_POINT temp;

    /* make sure input multiplier k is not zero. Return point at infinity if it
    is. */
    Field_Copy(k, &number);
    notzero=0;
    ECC_SUMLOOP(i) notzero |= number.e[i];
    if(!notzero)
    {
        Field_Clear(&r->x);
        Field_Clear(&r->y);
        return;
    }

    bit_count=0;
    while(notzero)
    {
        if(number.e[ECC_NUMWORD] & 1)
        {
            blncd[bit_count]=(char)(2 - (number.e[ECC_NUMWORD] & 3));
            if(blncd[bit_count]<0)
            {
                for(i=ECC_NUMWORD; i>=0; i--)
                {
                    number.e[i]++;
                    if(number.e[i]) break;
                }
            }
        }
        else blncd[bit_count]=0;

        number.e[ECC_NUMWORD] &= ~0 << 1;
        ECC_RotateRight(&number);
        bit_count++;
        notzero=0;
        ECC_SUMLOOP(i) notzero |= number.e[i];
    }

    --bit_count;
    ECC_PointCopy(p,r);
    while(bit_count>0)
    {
        ECC_PointDouble(r, &temp, curv);
        bit_count--;
        switch(blncd[bit_count])
        {
        case 1:
            ECC_PointAdd(p, &temp, r, curv);
            break;
        case -1:
            ECC_PointSubtract(&temp, p, r, curv);
            break;
        case 0:
            ECC_PointCopy(&temp, r);
            break;
        }
    }
}

void ECC_KeyGenerationPrimitive(EC_PARAMETER *Base, EC_KEYPAIR *Key, BigInt init)
{
    BigInt key_num=BigInt_Create();
    BigInt point_order=BigInt_Create();
    BigInt quotient=BigInt_Create();
    BigInt remainder=BigInt_Create();
    ECC_FIELD rand_key;

    if(init)
    {
        BigInt_Copy(key_num, init);
    }
    else
    {
        ECC_RandomFieldImproved(&rand_key);
        FieldToBigInt(&rand_key, key_num);
    }

    /* ensure the value is less than point order */
    FieldToBigInt(&Base->pnt_order, point_order);
    BigInt_Divide(key_num, point_order, quotient, remainder);
    BigIntToField(remainder, &Key->prvt_key);

    BigInt_Destroy(remainder);
    BigInt_Destroy(quotient);
    BigInt_Destroy(point_order);
    BigInt_Destroy(key_num);

    ECC_PointMultiply(&Key->prvt_key, &Base->pnt, &Key->pblc_key, &Base->crv);
}

void BigInt_Hash(char *Message, unsigned long length, BigInt hash_value)
{
    unsigned long hash[4];	/* MD5 hash of message */
    BigInt t=BigInt_Create();
    BigInt t2=BigInt_Create();
    BigInt t3=BigInt_Create();
    ECC_INDEX i;

    /* create hash and convert to a BigInt */
    md5(hash, Message, length);
    BigInt_SetU(t, 0);
    for(i=0; i<4; ++i)
    {
        BigInt_SetU(t3, hash[i]);
        BigInt_Shift(t, 32, t2);
        BigInt_Add(t2, t3, t);
    }
    BigInt_Copy(hash_value, t);

    BigInt_Destroy(t3);
    BigInt_Destroy(t2);
    BigInt_Destroy(t);
}

void ECC_MakeSignature(char *Message, unsigned long length, EC_PARAMETER *public_curve, ECC_FIELD *secret_key, SIGNATURE *signature, HWND log)
{
    char log_msg[1024]="";
    EC_KEYPAIR random_key;
    BigInt hash_value=BigInt_Create();
    BigInt x_value=BigInt_Create();
    BigInt y_value=BigInt_Create();

    BigInt k_value=BigInt_Create(); //remainder
    BigInt sig_value=BigInt_Create(); //remainder
    BigInt c_value=BigInt_Create(); //remainder

    BigInt temp=BigInt_Create();
    BigInt temp2=BigInt_Create();

    BigInt quotient=BigInt_Create(); //unused, just for calculation (remainder is used)

    BigInt key_value=BigInt_Create(); //private key
    BigInt point_order=BigInt_Create(); //5192296858534827627896703833467507
    BigInt u_value=BigInt_Create(); //inverse of the random key remainder

    /* compute hash of input message  */
    BigInt_Hash(Message, length, hash_value);

    AddLogMessage(log, "Message Hash (Len: 32, 0x20):", false);
    BigInt_ToString(hash_value, 16, log_msg);
    AddLogMessage(log, log_msg, false);

    /* create random value and generate random point on public curve  */
    ECC_KeyGenerationPrimitive(public_curve, &random_key, 0);

    /* convert x component of random point to an integer modulo the order of
    the base point. This is first part of signature. */
    FieldToBigInt(&public_curve->pnt_order, point_order);
    FieldToBigInt(&random_key.pblc_key.x, x_value);
    FieldToBigInt(&random_key.pblc_key.y, y_value);
    BigInt_Divide(x_value, point_order, quotient, c_value); //c_value=remainder
    BigIntToField(c_value, &signature->c);
    AddLogMessage(log, "Random point:", false);
    char tmp1[1024]="",tmp2[1024]="";
    BigInt_ToString(x_value, 16, tmp1);
    BigInt_ToString(y_value, 16, tmp2);
    sprintf(log_msg, "x=%s, y=%s,", tmp1, tmp2);
    AddLogMessage(log, log_msg, false);

    /* multiply that by signers private key and add to message digest modulo
    the order of the base point. hash value + private key * c value */
    FieldToBigInt(secret_key, key_value); //pvt
    BigInt_Multiply(key_value, c_value, temp);
    BigInt_Add(temp, hash_value, temp2);
    BigInt_Divide(temp2, point_order, quotient, k_value); //k_value=remainder

    /* final step is to multiply by inverse of random key value modulo order of
    base point. */

    FieldToBigInt(&random_key.prvt_key, temp);
    BigInt_ToString(temp, 16, tmp1);
    sprintf(log_msg, "prvt=%s", tmp1);
    AddLogMessage(log, log_msg, false);

    BigInt_ModularInverse(temp, point_order, u_value);
    BigInt_Multiply(u_value, k_value, temp);
    BigInt_Divide(temp, point_order, quotient, sig_value); //sig_value=remainder
    BigIntToField(sig_value, &signature->d);

    BigInt_Destroy(hash_value);
    BigInt_Destroy(x_value);
    BigInt_Destroy(k_value);
    BigInt_Destroy(sig_value);
    BigInt_Destroy(c_value);
    BigInt_Destroy(temp);
    BigInt_Destroy(temp2);
    BigInt_Destroy(quotient);
    BigInt_Destroy(key_value);
    BigInt_Destroy(point_order);
    BigInt_Destroy(u_value);
}

/* These functions are part of the initialization stuff */

void ECC_InitializeTable(void)
{
    /* If you need to reduce the CPU load, you can replace this function with a
    pre-computed table. For the 113-bit type-2 values we're using, it will
    calculate a 225-value 2D table. */
    ECC_ELEMENT ebit, bitsave, bitmask;
    ECC_INDEX k, n, i, twoexp, log2[ECC_FIELDPRIME];

#ifdef ECC_TYPE2
    ECC_INDEX logof[4], j;

    twoexp=1;
    for(i=0; i<ECC_NUMBITS; i++)
    {
        log2[twoexp]=i;
        twoexp=(short)((twoexp << 1) % ECC_FIELDPRIME);
    }

    if(twoexp==1)
    {
        twoexp=2*ECC_NUMBITS;
        for(i=0; i<ECC_NUMBITS; i++)
        {
            log2[twoexp]=i;
            twoexp=(short)((twoexp << 1) % ECC_FIELDPRIME);
        }
    }
    else
    {
        for(i=ECC_NUMBITS; i<ECC_FIELDPRIME-1; i++)
        {
            log2[twoexp]=i;
            twoexp=(short)((twoexp << 1) % ECC_FIELDPRIME);
        }
    }

    /* first element in vector 1 always=1 */
    ecc_table[0][0]=1;
    ecc_table[1][0]=-1;

    n=(ECC_FIELDPRIME - 1)/2;

    twoexp=1;
    for(i=1; i<n; i++)
    {
        twoexp=(short)((twoexp<<1) % ECC_FIELDPRIME);
        logof[0]=log2[ECC_FIELDPRIME + 1 - twoexp];
        logof[1]=log2[ECC_FIELDPRIME - 1 - twoexp];
        logof[2]=log2[twoexp - 1];
        logof[3]=log2[twoexp + 1];
        k=0;
        j=0;
        while(k<2)
        {
            if(logof[j]<n)
            {
                ecc_table[k][i]=logof[j];
                ++k;
            }
            ++j;
        }
    }
#else
    ECC_INDEX logof, index;

    for(i=0; i<ECC_FIELDPRIME; i++) log2[i]=-1;

    twoexp=1;
    for(i=0; i<ECC_FIELDPRIME; i++)
    {
        log2[twoexp]=i;
        twoexp=(short)((twoexp << 1) % ECC_FIELDPRIME);
    }

    n=(ECC_FIELDPRIME - 1)/2;

    ecc_table[0][0]=n;
    for(i=1; i<ECC_FIELDPRIME; i++)
        ecc_table[0][i]=(ecc_table[0][i-1] + 1) % ECC_NUMBITS;

    ecc_table[1][0]= -1; /* never used */
    ecc_table[1][1]=n;
    ecc_table[1][n]=1;

    for(i=2; i<=n; i++)
    {
        index=log2[i];
        logof=log2[ECC_FIELDPRIME - i + 1];
        ecc_table[1][index]=logof;
        ecc_table[1][logof]=index;
    }
    ecc_table[1][log2[n+1]]=log2[n+1];
#endif

    ecc_log2m=0;
    bitsave=(ECC_ELEMENT)(ECC_NUMBITS - 1);
    k=ECC_ELEMENTBITS/2;
    bitmask=-1L<<k;
    while(k)
    {
        ebit=bitsave & bitmask;
        if(ebit)
        {
            ecc_log2m+=k;
            bitsave=ebit;
        }
        k/=2;
        bitmask^=(bitmask >> k);
    }
}

void ECC_FOFX(ECC_FIELD *x, ECC_CURVE *curv, ECC_FIELD *f)
{
    ECC_FIELD x2, x3;
    ECC_INDEX i;

    Field_Copy(x, &x2);
    ECC_RotateLeft(&x2);
    ECC_Multiply(x, &x2, &x3);
    if(curv->form) ECC_Multiply(&x2, &curv->a2, f);
    else Field_Clear(f);
    ECC_SUMLOOP(i) f->e[i] ^= (x3.e[i] ^ curv->a6.e[i]);
}

int ECC_Quadratic(ECC_FIELD *a, ECC_FIELD *b, ECC_FIELD *y)
{
    ECC_INDEX i, l, bits;
    ECC_FIELD x, k, a2;
    ECC_ELEMENT r, t, mask;

    r=0;
    ECC_SUMLOOP(i) r |= a->e[i];
    if(!r)
    {
        Field_Copy(b, &y[0]);
        ECC_RotateRight(&y[0]);
        Field_Copy(&y[0], &y[1]);
        return 0;
    }

    ECC_Inverse(a, &a2);
    ECC_RotateLeft(&a2);

    ECC_Multiply(b, &a2, &k);
    ECC_RotateRight(&k);
    r=0;

    ECC_SUMLOOP(i) r ^= k.e[i];

    mask=-1L;
    for(bits=ECC_ELEMENTBITS/2; bits>0; bits >>= 1)
    {
        mask >>= bits;
        r=((r & mask) ^ (r >> bits));
    }

    if(r)
    {
        Field_Clear(&y[0]);
        Field_Clear(&y[1]);
        return 1;
    }

    Field_Clear(&x);
    mask=1;
    for(bits=0; bits<ECC_NUMBITS ; bits++)
    {
        i=ECC_NUMWORD - bits/ECC_ELEMENTBITS;
        l=ECC_NUMWORD - (bits + 1)/ECC_ELEMENTBITS;

        r=k.e[i] & mask;
        t=x.e[i] & mask;
        r ^= t;

        if(l==i)
        {
            r <<= 1;
            x.e[l] |= r;
            mask <<= 1;
        }
        else
        {
            mask=1;
            if(r) x.e[l]=1;
        }
    }

    r=k.e[0] & ECC_UPRBIT;
    t=x.e[0] & ECC_UPRBIT;
    if(r^t)
    {
        Field_Clear(&y[0]);
        Field_Clear(&y[1]);
        return 2; /* Should be mathematically impossible. */
    }

    ECC_Multiply(a, &x, &y[0]);

    Field_Clear(&y[1]);
    ECC_SUMLOOP(i) y[1].e[i]=y[0].e[i] ^ a->e[i];

    return 0;
}

void ECC_Embed(ECC_FIELD *data, ECC_CURVE *curv, ECC_INDEX incrmt, ECC_INDEX root, ECC_POINT *pnt)
{
    ECC_FIELD f, y[2];
    ECC_INDEX inc=incrmt;

    if((inc<0) || ((unsigned int)inc>ECC_NUMWORD)) inc=0;
    Field_Copy(data, &pnt->x);
    ECC_FOFX(&pnt->x, curv, &f);
    while(ECC_Quadratic(&pnt->x, &f, y))
    {
        pnt->x.e[inc]++;
        ECC_FOFX(&pnt->x, curv, &f);
    }
    Field_Copy(&y[root&1], &pnt->y);
}

void ECC_RandomPoint(ECC_POINT *point, ECC_CURVE *curve)
{
    ECC_FIELD	rf;
    ECC_RandomFieldOriginal(&rf);
    ECC_Embed(&rf, curve, ECC_NUMWORD, (ECC_INDEX)(rf.e[ECC_NUMWORD]&1), point);
}

void ECC_Initialize(EC_PARAMETER *Base, EC_KEYPAIR *Signer, unsigned long basepointinit, const char *_rndinitstring, char* prvt_text, char* pubx_text, char* puby_text)
{
    BigInt secretkeyhash=BigInt_Create();
    BigInt prime_order=BigInt_Create();
    char rndinitstring[1024];
    unsigned long i[4];
    ECC_POINT temp;

    /* Compute the ECC tables. */
    ECC_InitializeTable();

    /* Compute the curve order from Koblitz data. SEGC's "Recommended Elliptic
    Curve Domain Parameters" document has more information on this, but we're
    not using their recommendations because they only provide polynomial curves
    over F(2^m), not "optimal normal basis" curves over the same field (which
    is what we're using). The ECC_PRIMEORDER number came from Michael Rosing's
    example code. */
    BigInt_FromString(ECC_PRIMEORDER, 10, prime_order);
    BigIntToField(prime_order, &Base->pnt_order);
    Field_Clear(&Base->cofactor);
    Base->cofactor.e[ECC_NUMWORD]=2;

    /* Create Koblitz curve of ECC_NUMBITS order. This curve is part of the
    public key, and can be safely shared between users. */
    Base->crv.form=1;
    Field_Set(&Base->crv.a2);
    Field_Set(&Base->crv.a6);
    /*print_curve("Koblitz 113", &Base->crv);*/

    /* Create the base point, with a known order and no cofactor. This point is
    part of the public key, and can be safely shared between many users if
    necessary (but for added security, I'm setting it up so it can also be
    different for everyone). */

    InitRandomGenerator(basepointinit);
    ECC_RandomPoint(&temp, &Base->crv);
    ECC_PointDouble(&temp, &Base->pnt, &Base->crv);
    /*print_point("Random point", &temp);*/
    /*print_point(" Base point ",&Base->pnt);*/

    /* Create the secret key from the encryption template. The secret key
    must be less than order -- this is dealt with by BigInt_Hash. Also note
    that BigInt_Hash only creates a 128-bit secret key; that's okay for our
    purposes, but if you use a field size larger than 128 bits, you'll need to
    extend the hash to the same number of bits or greater, for security. */
    /*strcpy(rndinitstring, _rndinitstring);
    strcat(rndinitstring, "PVTKEY");
    BigInt_Hash(rndinitstring, strlen(rndinitstring), secretkeyhash);
    ECC_KeyGenerationPrimitive(Base, Signer, secretkeyhash);*/
    /*print_field("Signer's secret key", &Signer->prvt_key);*/
    /*print_point("Signers public key", &Signer->pblc_key);*/
    ///Inject ecdsa stuff here...
    BigInt prvt=BigInt_Create();
    BigInt pubx=BigInt_Create();
    BigInt puby=BigInt_Create();

    BigInt_FromString(prvt_text, 10, prvt);
    BigIntToField(prvt, &Signer->prvt_key);

    BigInt_FromString(pubx_text, 10, pubx);
    BigIntToField(pubx, &Signer->pblc_key.x);

    BigInt_FromString(puby_text, 10, puby);
    BigIntToField(puby, &Signer->pblc_key.y);

    /* Reinitialize the random number generators to a new random value, based
    on both the encryption template and the system clock. This ensures that it
    can't be guessed from the time and date unless the attacker also knows the
    encryption template already, which means he could generate all the keys he
    wants without bothering to guess anything. */
    sprintf(rndinitstring, "%sECCRND%u", _rndinitstring, (unsigned int)GetRandomSeed());
    md5(i, rndinitstring, strlen(rndinitstring));
    InitRandomGenerator(i[0]^i[1]^i[2]^i[3]);
    InitRandomGenerator128(i);

    BigInt_Destroy(secretkeyhash);
    BigInt_Destroy(prime_order);
}
