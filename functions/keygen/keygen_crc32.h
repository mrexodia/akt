#ifndef _KEYGENCRC32_H
#define _KEYGENCRC32_H

#include <stdlib.h>

typedef unsigned long CRC32;
const CRC32 NewCRC32=0xFFFFFFFF;

unsigned long reflect(unsigned long source, int b);
CRC32 crc32(const char *s, unsigned long length, CRC32 crc);

#endif
