#ifndef __ARMABRUT_H_
#define __ARMABRUT_H_

#include <time.h>

//Callbacks
typedef void (*PRINT_FOUND)(unsigned long checksum, unsigned long key);
typedef void (*PRINT_PROGRESS)(double checked, double all, time_t* start);
typedef void (*PRINT_ERROR)(const char* error_msg);

struct CALLBACKS
{
    PRINT_FOUND print_found;
    PRINT_PROGRESS print_progress;
    PRINT_ERROR print_error;
};

typedef struct _hash_list
{
	int count;
	unsigned long hash[32];
} hash_list;

#endif
