#ifndef _MD5_H
#define _MD5_H

unsigned int TransformBlock(unsigned int x0, unsigned int x1, unsigned int x2, unsigned int x14);
unsigned int GenerateChecksumV8(unsigned int sym, unsigned int salt);
#define GenerateChecksumV3(sym) (TransformBlock(sym, 0x80, 0, 0x20)^sym)

#endif // _MD5_H
