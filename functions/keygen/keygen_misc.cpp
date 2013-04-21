#include "keygen_misc.h"

/*
	-----------------------
	Miscellaneous Functions
	-----------------------
*/

void AddLogMessage(HWND log, const char* m, bool first)
{
    if(!log or !m or !m[0])
        return;

    char old_log[4096]="";
    char m_[1024]="";
    char rn[3]="\r\n";
    if(first)
        rn[0]=0;

    sprintf(m_, "%s%s", rn, m);

    int len=strlen(m_);

    int start_write=GetWindowTextA(log, old_log, 4096);
    if(first)
    {
        old_log[0]=0;
        strcpy(old_log, m_);
    }
    else
        memcpy(old_log+start_write, m_, len);
    SetWindowTextA(log, old_log);
}

int ByteArray2String(unsigned char* s, char* d, int s_len, int d_len)
{
    memset(d, 0, d_len);
    if(s_len>d_len)
        return -1;
    for(int i=0; i<s_len; i++)
        sprintf(d, "%s%.2X", d, s[i]);
    return strlen(d);
}

int String2ByteArray(const char* s, unsigned char* d, int d_len)
{
    char temp_string[3]="";
    unsigned char temp_byte[4]= {0};
    int len=0;

    memset(d, 0, d_len);

    len=strlen(s);
    if(len%2)
        len--;

    if((len/2)>d_len)
        return -1;

    for(int i=0,j=0; i<(len/2); i++, j+=2)
    {
        temp_string[0]=s[j];
        temp_string[1]=s[j+1];
        sscanf(temp_string, "%X", (unsigned int*)&temp_byte);
        d[i]=temp_byte[0];
    }
    return len/2;
}

void CookText(char *target, const char *source)
{
    /* Not using toupper() because certain high-ASCII (non-English) characters
    are processed differently after certain DLLs are loaded... it's better
    to have reliability in this function. */
    const char *s=source;
    char *t=target;
    while(*s)
    {
        if(*s==' ' || *s=='\t' || *s=='\r' || *s=='\n') ++s;
        else if(*s>='a' && *s<='z') *t++=((*s++)-'a'+'A');
        else *t++=*s++;
    }
    *t=0;
}

/*
static void CookText(char *target, const char *source) {
	const char *s=source;
	char *t=target;
	while (*s) {
		if (*s==' ') ++s;
		else *t++=toupper(*s++);
	};
	*t=0;
};
*/

/* Armadillo does NOT use time-zone stuff. The NoTimeZoneStuff() call is
designed to clear out the time-zone and daylight-savings-time differences. It's
not strictly necessary, since Armadillo allows for a variation of a day, and
may not be portable (thus the #ifdefs). */
#ifdef _WIN32
void NoTimeZoneStuff(void)
{
    static int firstrun=1;
    if(firstrun)
    {
        _timezone=0;
        putenv("TZ=GMT0");
        firstrun=0;
    }
}
#else
#define NoTimeZoneStuff()
#endif

/*static unsigned short GetToday(void)
{
#ifdef FOR_TESTING
    // This line for debugging only -- 1791 is US Thanksgiving day, 2003.
    return 1791;
#else
    const unsigned long secondsperday=(24*60*60);
    const int dateoffset=10592; // Difference (in days) between 01Jan70 and 01Jan99
    unsigned long days;

    NoTimeZoneStuff();

    days=(time(NULL)/secondsperday);
    return (unsigned short)(days-dateoffset);
#endif
}*/

void InterpretDate(unsigned short keymade, unsigned short *year, unsigned short *month, unsigned short *day)
{
    const unsigned long secondsperday=(24*60*60);
    const int dateoffset=10592; /* Difference (in days) between 01Jan70 and 01Jan99 */
    time_t xtime;
    struct tm *tm;

    //NoTimeZoneStuff();
    xtime=(keymade+dateoffset)*secondsperday+(secondsperday/2);
    tm=gmtime(&xtime);
    if(tm)
    {
        if(year) *year=tm->tm_year+1900;
        if(month) *month=tm->tm_mon+1;
        if(day) *day=tm->tm_mday;
    }
}

unsigned long hextoint(const char *string)
{
    unsigned long r=0;
    const char *c=string;
    while(*c)
    {
        if(*c>='0' && *c<='9') r=(r*16)+(*c-'0');
        else if(*c>='a' && *c<='f') r=(r*16)+(*c-'a')+10;
        else if(*c>='A' && *c<='F') r=(r*16)+(*c-'A')+10;
        ++c;
    }
    return r;
}
