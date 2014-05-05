#ifndef _KEYGENMD5_H
#define _KEYGENMD5_H

#include <cstring>

void TransformBlock(unsigned long *i, const unsigned char *in);
void md5(unsigned long *i, const void *bytes, unsigned long length);

#endif
