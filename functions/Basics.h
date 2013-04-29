#ifndef BASICS_H_INCLUDED
#define BASICS_H_INCLUDED

#include <windows.h>

/**********************************************************************
 *						Prototypes
 *********************************************************************/
unsigned int FindCallPattern(BYTE* d, unsigned int size);
unsigned int FindEB6APattern(BYTE* d, unsigned int size);
unsigned int Find960Pattern(BYTE* d, unsigned int size);


#endif // BASICS_H_INCLUDED
