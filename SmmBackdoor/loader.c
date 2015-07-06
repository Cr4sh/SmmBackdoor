#include <Library/UefiRuntimeLib.h>
#include <IndustryStandard/PeImage.h>

#include "common.h"
#include "loader.h"
//--------------------------------------------------------------------------------------
VOID LdrProcessRelocs(PVOID Image, PVOID NewBase)
{
    EFI_IMAGE_NT_HEADERS *pHeaders = (EFI_IMAGE_NT_HEADERS *)
        ((PUCHAR)Image + ((EFI_IMAGE_DOS_HEADER *)Image)->e_lfanew);

    ULONG RelocationSize = pHeaders->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;        
    ULONGLONG OldBase = pHeaders->OptionalHeader.ImageBase;

    EFI_IMAGE_BASE_RELOCATION *pRelocation = (EFI_IMAGE_BASE_RELOCATION *)RVATOVA(
        Image,
        pHeaders->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress
    );
    if (pRelocation)
    {
        ULONG Size = 0;
        while (RelocationSize > Size && pRelocation->SizeOfBlock)
        {            
            ULONG Number = (pRelocation->SizeOfBlock - 8) / 2, i = 0;
            PUSHORT Rel = (PUSHORT)((PUCHAR)pRelocation + 8);            

            for (i = 0; i < Number; i++)
            {
                if (Rel[i] > 0)
                {
                    USHORT Type = (Rel[i] & 0xF000) >> 12;
                    PVOID Addr = (PVOID)RVATOVA(Image, pRelocation->VirtualAddress + (Rel[i] & 0x0FFF));                    

                    // check for supporting type
                    if (Type != EFI_IMAGE_REL_BASED_DIR64)
                    {                        
                        return;
                    }
 
                    // fix base
                    *(PULONGLONG)Addr += (ULONGLONG)NewBase - OldBase;
                }
            }

            pRelocation = (EFI_IMAGE_BASE_RELOCATION *)((PUCHAR)pRelocation + pRelocation->SizeOfBlock);
            Size += pRelocation->SizeOfBlock;            
        }
    }
}
//--------------------------------------------------------------------------------------
ULONG LdrGetProcAddress(PVOID Image, char *lpszFunctionName)
{
    EFI_IMAGE_EXPORT_DIRECTORY *pExport = NULL;

    EFI_IMAGE_NT_HEADERS *pHeaders = (EFI_IMAGE_NT_HEADERS *)
        ((PUCHAR)Image + ((EFI_IMAGE_DOS_HEADER *)Image)->e_lfanew);

    if (pHeaders->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
    {
        pExport = (EFI_IMAGE_EXPORT_DIRECTORY *)RVATOVA(
            Image,
            pHeaders->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
        );
    }

    if (pExport)
    {
        PULONG AddressOfFunctions = (PULONG)RVATOVA(Image, pExport->AddressOfFunctions);
        PSHORT AddrOfOrdinals = (PSHORT)RVATOVA(Image, pExport->AddressOfNameOrdinals);
        PULONG AddressOfNames = (PULONG)RVATOVA(Image, pExport->AddressOfNames);
        ULONG i = 0;

        for (i = 0; i < pExport->NumberOfFunctions; i++)
        {
            if (!strcmp((char *)RVATOVA(Image, AddressOfNames[i]), lpszFunctionName))
            {
                return AddressOfFunctions[AddrOfOrdinals[i]];
            }
        }
    }

    return 0;
}
//--------------------------------------------------------------------------------------
// EoF
