
#ifndef _TYPES_H_
#define _TYPES_H_

/*
    NT-like types definitions.
*/

// 1 byte signed
typedef char                    CHAR;
typedef char *                  PCHAR;

// 1 byte unsigned
typedef unsigned char           UCHAR;
typedef unsigned char *         PUCHAR;

// 2 byte signed
typedef short                   SHORT;
typedef short *                 PSHORT;

// 2 byte unsigned
typedef unsigned short          USHORT;
typedef unsigned short *        PUSHORT;

// 4 byte signed
typedef long                    LONG;
typedef long *                  PLONG;

// 4 byte unsigned
typedef unsigned long           ULONG;
typedef unsigned long *         PULONG;

// 8 byte signed
typedef long long               LONGLONG;
typedef long long *             PLONGLONG;

// 8 byte unsigned
typedef unsigned long long      ULONGLONG;
typedef unsigned long long *    PULONGLONG;

// pointer sized
typedef void * PVOID;

#endif
