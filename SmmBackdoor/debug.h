
#ifndef _DEBUG_H_
#define _DEBUG_H_

#define MAX_STR_LEN 255

#define DbgStop() while (TRUE) {}

#ifdef BACKDOOR_DEBUG

void DbgMsg(char *lpszFile, int Line, char *lpszMsg, ...);

#else

#define DbgMsg

#endif
#endif
