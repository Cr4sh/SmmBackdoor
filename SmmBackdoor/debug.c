#include <Library/UefiRuntimeLib.h>

#include "config.h"
#include "SmmBackdoor.h"
#include "printf.h"
#include "debug.h"
//--------------------------------------------------------------------------------------
#if defined(BACKDOOR_DEBUG)
//--------------------------------------------------------------------------------------
static char *NameFromPath(char *lpszPath)
{
    int i = 0, sep = -1;

    for (i = 0; i < strlen(lpszPath); i += 1)
    {
        if (lpszPath[i] == '\\' || lpszPath[i] == '/')
        {
            sep = i;
        }
    }

    if (sep >= 0)
    {
        return lpszPath + sep + 1;
    }

    return lpszPath;
}
//--------------------------------------------------------------------------------------
void DbgMsg(char *lpszFile, int Line, char *lpszMsg, ...)
{
    va_list arglist;
    char szBuff[MAX_STR_LEN], szOutBuff[MAX_STR_LEN];

    va_start(arglist, lpszMsg);
    tfp_vsprintf(szBuff, lpszMsg, arglist);
    va_end(arglist);

    // build debug message string
    tfp_sprintf(szOutBuff, "%s(%d) : %s", NameFromPath(lpszFile), Line, szBuff);

    // write message into the serial port
    SerialPrint(szOutBuff);
}
//--------------------------------------------------------------------------------------
#endif // BACKDOOR_DEBUG
//--------------------------------------------------------------------------------------
// EoF
