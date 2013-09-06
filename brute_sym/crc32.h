#ifndef __CRC32_H__
#define __CRC32_H__

typedef unsigned long CRC32;
CRC32 crc32(const char *s, unsigned long length, CRC32 crc);

#endif
