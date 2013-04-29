#include "Basics.h"


/**********************************************************************
 *						Functions
 *********************************************************************/
unsigned int FindCallPattern(BYTE* d, unsigned int size)
{
    for(unsigned int i=0; i<size; i++) //E8????????83
        if(d[i]==0xE8 and d[i+5]==0x83)
            return i;
    return 0;
}


unsigned int FindEB6APattern(BYTE* d, unsigned int size)
{
    for(unsigned int i=0; i<size; i++) //EB??6A
        if(d[i]==0xEB and d[i+2]==0x6A)
            return i;
    return 0;
}


unsigned int Find960Pattern(BYTE* d, unsigned int size)
{
    for(unsigned int i=0; i<size; i++) //5?68????????E8
        if((d[i]>>4)==0x05 and d[i+1]==0x68 and d[i+6]==0xE8)
            return i;
    return 0;
}
