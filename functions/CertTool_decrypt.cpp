#include "CertTool_decrypt.h"

unsigned long CT_a;

unsigned long CT_mult(long p, long q)
{
    unsigned long p1=p/10000L, p0=p%10000L, q1=q/10000L, q0=q%10000L;
    return (((p0*q1+p1*q0) % 10000L) * 10000L+p0*q0) % 100000000L;
}

unsigned long CT_NextRandomRange(long range)
{
    CT_a=(CT_mult(CT_a, 31415821L)+1) % 100000000L;
    return (((CT_a/10000L)*range)/10000L);
}

unsigned char* CT_GetCryptBytes(unsigned int seed, unsigned int size)
{
    CT_a=seed;
    unsigned char* arry=(unsigned char*)malloc(size+4);
    memset(arry, 0, size+4);
    for(unsigned int x=0; x<size+4; x++)
        arry[x]=CT_NextRandomRange(256);
    return arry+4; //Skip first 4 bytes
}

unsigned char* CT_Decrypt(unsigned char** data, unsigned char** rand, unsigned int size)
{
    if(!size)
        return data[0];
    for(unsigned int i=0; i<size; i++)
        data[0][i]^=rand[0][i];
    data[0]+=size;
    rand[0]+=size;
    return data[0]-size;
}

unsigned char* CT_DecryptCerts()
{
    OutputDebugStringA("CT_DecryptCerts");
    CERT_DATA* cd=CT_cert_data;

    if(!cd->raw_data or !cd->raw_size)
        return 0;

    unsigned int real_cert_size=FindBAADF00DPattern(cd->raw_data, cd->raw_size);
    if(!real_cert_size)
        real_cert_size=0x10000;
    unsigned char* rand=CT_GetCryptBytes(cd->decrypt_seed[0], real_cert_size);
    unsigned char* rand_start=rand;
    unsigned char* decr=(unsigned char*)malloc(real_cert_size);
    unsigned char* decr_start=decr;
    memcpy(decr, cd->raw_data, real_cert_size);
    free(cd->raw_data);
    memcpy(&cd->first_dw, decr, 4);
    CT_Decrypt(&decr, &rand, 4*4);
    decr+=2+4; //Skipped bytes

    cd->projectid_diff=decr-decr_start+sizeof(unsigned short); //pointer + word for size, 0x18
    CT_a=cd->decrypt_seed[0];
    for(unsigned int i=0; i<cd->projectid_diff; i++)
        CT_NextRandomRange(256);
    cd->decrypt_seed[1]=CT_a;

    //Project ID
    unsigned short* projectID_size=(unsigned short*)CT_Decrypt(&decr, &rand, 2);
    if(*projectID_size)
    {
        cd->projectid=(char*)malloc(*projectID_size+1);
        memset(cd->projectid, 0, *projectID_size+1);
        memcpy(cd->projectid, CT_Decrypt(&decr, &rand, *projectID_size), *projectID_size);
    }
    //Customer Service
    unsigned short* customerSER_size=(unsigned short*)CT_Decrypt(&decr, &rand, 2);
    if(*customerSER_size)
    {
        //TODO: add this (v4.x +)
        CT_Decrypt(&decr, &rand, *customerSER_size);
    }
    //Website
    unsigned short* website_size=(unsigned short*)CT_Decrypt(&decr, &rand, 2);
    if(*website_size)
    {
        //TODO: add this
        CT_Decrypt(&decr, &rand, *website_size);
    }

    decr+=cd->decrypt_addvals[0]; //add the first seed

    //Stolen Codes KeyBytes
    unsigned char* stolen_size=CT_Decrypt(&decr, &rand, 1);
    while(*stolen_size)
    {
        //TODO: add this
        CT_Decrypt(&decr, &rand, *stolen_size);
        stolen_size=CT_Decrypt(&decr, &rand, 1);
    }
    decr+=cd->decrypt_addvals[1]; //add second seed

    //Intercepted libraries
    unsigned short* libs_size=(unsigned short*)CT_Decrypt(&decr, &rand, 2);
    if(*libs_size)
    {
        //TODO: add this
        CT_Decrypt(&decr, &rand, *libs_size);
    }
    decr+=cd->decrypt_addvals[2];; //add third seed

    //Certificates
    unsigned char* decr_cert=decr;
    cd->initial_diff=decr-decr_start;
    unsigned int real_size=0;

    //Get certificate initial seed
    unsigned int seed_count=rand-rand_start;
    CT_a=cd->decrypt_seed[0];
    for(unsigned int i=0; i<seed_count+4; i++) //+4 for the first inital dword (extraoptions)
        CT_NextRandomRange(256);
    cd->decrypt_seed[2]=CT_a;

    CT_Decrypt(&decr, &rand, 1);
    unsigned char* signature_size=CT_Decrypt(&decr, &rand, 1);
    while(*signature_size)
    {
        real_size+=(*signature_size)+4+1+1; //chk+lvl+pubsize
        CT_Decrypt(&decr, &rand, (*signature_size)+4);
        CT_Decrypt(&decr, &rand, 1);
        signature_size=CT_Decrypt(&decr, &rand, 1);
    }
    if(real_size)
    {
        cd->raw_data=decr_cert;
        cd->raw_size=real_size;
    }
    else
    {
        cd->raw_data=0;
        cd->raw_size=0;
    }
    free(rand);
    return 0;
}
