#include "brute.h"
#include "md5.h"
#include "crc32.h"
#include <windows.h>
#include <stdio.h>

typedef void (*BRUTE_ALG)(unsigned int);
time_t* g_timestart;
int* g_stop;

PRINT_FOUND print_found;
PRINT_PROGRESS print_progress;
PRINT_ERROR print_error;
BRUTE_ALG g_brute_alg;

static hash_list brute_list;

static void print_if_found(unsigned long hash, unsigned long key)
{
    int min=0;
    int max=brute_list.count-1;
    do
    {
        int mid=(max+min)/2;
        unsigned long cmp=brute_list.hash[mid];
        if(cmp==hash)
        {
            print_found(hash, key);
            break;
        }
        else if(cmp>hash)
            max=mid-1;
        else
            min=mid+1;
    }
    while(min<=max);
}

static void alg0(unsigned int sym)
{
    unsigned int sym_=sym;
    print_if_found(GenerateChecksumV3(sym_), sym_);
}

static unsigned int g_salt=0;

static void alg1(unsigned int sym)
{
    unsigned int sym_=sym;
    print_if_found(GenerateChecksumV8(sym_, g_salt), sym_);
}

static int arma_alg2_next(int data) //Arma PRNG NextSeed
{
    int a=data%10000;
    int res;
    res=10000*((3141*a+(data/10000)*5821)%10000u);
    return (a*5821+res+1)%100000000u;
}

static unsigned char arma_alg2_byte(int data) //Arma PRNG NextRandomRange
{
    return (((data/10000)<<8)/10000)&0xFF;
}

static void alg2(unsigned int key)
{
    unsigned int key_=key;
    int next=crc32((const char*)&key, 4, -1);
    int res;
    res=arma_alg2_byte((next=arma_alg2_next(next)))<<24;
    res|=arma_alg2_byte((next=arma_alg2_next(next)))<<16;
    res|=arma_alg2_byte((next=arma_alg2_next(next)))<<8;
    res|=arma_alg2_byte(arma_alg2_next(next));
    print_if_found(res, key_);
}

static void alg5(unsigned int seed)
{
    unsigned int seed_=seed;
    int next=seed;
    int res;
    res=arma_alg2_byte((next=arma_alg2_next(next)))<<24;
    res|=arma_alg2_byte((next=arma_alg2_next(next)))<<16;
    res|=arma_alg2_byte((next=arma_alg2_next(next)))<<8;
    res|=arma_alg2_byte(arma_alg2_next(next));
    print_if_found(res, seed_);
}

static void alg6(unsigned int seed)
{
    int seed_=seed;
    print_if_found(arma_alg2_next(arma_alg2_next(arma_alg2_next(arma_alg2_next(seed_)))), seed_);
}

unsigned long g_data;

int arma_alg78_hash(unsigned long i)
{
    int next=i;
    int res=arma_alg2_byte((next=arma_alg2_next(next)))<<24;
    res|=arma_alg2_byte((next=arma_alg2_next(next)))<<16;
    res|=arma_alg2_byte((next=arma_alg2_next(next)))<<8;
    res|=arma_alg2_byte(arma_alg2_next(next));
    return res^g_data;
}

static void alg7(unsigned int seed)
{
    int seed_=arma_alg78_hash(seed);
    print_if_found(GenerateChecksumV3(seed_), seed_);
}

static void alg8(unsigned int seed)
{
    int seed_=arma_alg78_hash(seed);
    print_if_found(GenerateChecksumV8(seed_, g_salt), seed_);
}

static int lock_val[4]= {0,0,0,0};

static void lock(int lock, int num)
{
    lock_val[lock]=num;
}

static void unlock(int lock)
{
    lock_val[lock]--;
}

static void waitunlock(int lock)
{
    while(lock_val[lock]>0)
        Sleep(1);
}

struct BRUTE_PARAM
{
    int threads;
    unsigned int start;
    unsigned int end;
};

static DWORD WINAPI brute_thread(void* a)
{
    BRUTE_ALG brute_alg=g_brute_alg;
    BRUTE_PARAM* b=(BRUTE_PARAM*)a;
    int threads=b->threads;
    unsigned int step=threads;
    unsigned int start=b->start;
    unsigned int end=b->end;

    unlock(2);
    waitunlock(0);

    for(unsigned int i=start; i<end; i+=step)
    {
        if(!(i%(0x00010000+start)) and *g_stop)
            return 0;
        else if(!(i%0x00010000))
            print_progress((double)i, (double)end, g_timestart);
        brute_alg(i);
    }

    unlock(1);
    return 0;
}

void dothreads(unsigned int from, unsigned int to)
{
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    int threads=si.dwNumberOfProcessors,step=1;
    unsigned long long total=to-from;
    long long remain=(total+step)%(threads*step);
    remain/=step;

    BRUTE_PARAM* a=(BRUTE_PARAM*)malloc(sizeof(BRUTE_PARAM));
    a->threads=threads;

    lock(0, 1);
    lock(1, threads);
    for(int i=0; i<threads; i++)
    {
        lock(2, 1);
        a->start=i*step+from;
        a->end=to-(threads-1-i+remain)*step;
        if(i<remain)
            a->end+=threads*step;
        CreateThread(0, 0, brute_thread, (void*)a, 0, 0);
        waitunlock(2);
    }
    unlock(0);
    waitunlock(1);
    free(a);
}

void brute(int alg, hash_list* list, unsigned int from, unsigned int to, unsigned int* param, time_t* start, int* stop, CALLBACKS* callbacks)
{
    if(!list or !stop or !start or !list->count)
        return;
    memcpy(&brute_list, list, sizeof(hash_list));
    g_salt=*param;
    g_timestart=start;
    g_stop=stop;
    print_found=callbacks->print_found;
    print_progress=callbacks->print_progress;
    print_error=callbacks->print_error;

    switch(alg)
    {
    case 0: //Sym (Arma 3.7 - 7.2)
        g_brute_alg=alg0;
        break;
    case 1: //Sym (Arma 7.4 and higher)
        g_brute_alg=alg1;
        break;
    case 2: //Undocumented (CRC+Random Number)
        g_brute_alg=alg2;
        break;
    case 5: //PRNG Seed brute force
        g_brute_alg=alg5;
        break;
    case 6: //PRNG Previous Seed brute force
        g_brute_alg=alg6;
        break;
    case 7: //KeyBytes brute force (Arma 3.7 - 7.2)
        g_data=param[1];
        g_brute_alg=alg7;
        break;
    case 8: //KeyBytes brute force (Arma 7.4 and higher)
        g_data=param[1];
        g_brute_alg=alg8;
        break;
    default:
        return;
    }

    dothreads(from, to);

    /*
    //single-threaded algo
    BRUTE_ALG brute_alg=g_brute_alg;

    for(unsigned int i=from; i<to; i++) //Test all hashes
    {
        if(!(i%0x00010000))
        {
            if(*stop) //We need to watch the stop variable...
                return;
            print_progress((double)i, (double)to, start);
        }
        brute_alg(i);
    }*/
}
