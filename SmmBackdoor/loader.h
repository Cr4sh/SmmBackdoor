
#ifndef _LOADER_H_
#define _LOADER_H_

#if defined(_M_X64) || defined(__amd64__)

typedef EFI_IMAGE_NT_HEADERS64 EFI_IMAGE_NT_HEADERS;

#else

typedef EFI_IMAGE_NT_HEADERS32 EFI_IMAGE_NT_HEADERS;

#endif

#define LDR_UPDATE_RELOCS(_addr_, _old_, _new_)                                                      \
                                                                                                     \
    {                                                                                                \
        EFI_IMAGE_NT_HEADERS *nt_h = (EFI_IMAGE_NT_HEADERS *)RVATOVA((_addr_),                       \
            ((EFI_IMAGE_DOS_HEADER *)(_addr_))->e_lfanew);                                           \
                                                                                                     \
        LdrProcessRelocs(                                                                            \
            (_addr_),                                                                                \
            (PVOID)((PUCHAR)nt_h->OptionalHeader.ImageBase - (PUCHAR)(_old_) + (PUCHAR)(_new_))      \
        );                                                                                           \
    }

VOID LdrProcessRelocs(PVOID Image, PVOID NewBase);
ULONG LdrGetProcAddress(PVOID Image, char *lpszFunctionName);

#endif