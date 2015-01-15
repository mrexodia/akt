#ifndef _KEYGENRANDOM_H
#define _KEYGENRANDOM_H

#define USECLOCKTICKS

#include "keygen_md5.h"

#include <ctime>
#include <cstring>

unsigned long GetRandomSeed(void);

unsigned long mult(long p, long q);
void InitRandomGenerator(unsigned long seed);
unsigned long NextRandomRange(long range);
unsigned long NextRandomNumber(void);
void InitRandomGenerator128(unsigned long* seed);
void NextRandomNumber128(unsigned long* i);

#endif
