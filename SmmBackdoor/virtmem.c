#include <Library/UefiRuntimeLib.h>

#include "config.h"

#include "common.h"
#include "debug.h"
#include "virtmem.h"

#include "../../DuetPkg/DxeIpl/X64/VirtualMemory.h"

// IA32_EFER MSR register
#define IA32_EFER 0xC0000080

// IA32_EFER.LME flag
#define IA32_EFER_LME 0x100

// PS flag of PDPTE and PDE
#define PDPTE_PDE_PS 0x80

// CR0 register flags
#define CR0_WP 0x000010000
#define CR0_PG  0x80000000

// CR4 register flags
#define CR4_PAE 0x20

#if defined(BACKDOOR_DEBUG_MEM)

#define DbgMsgMem DbgMsg

#else

#define DbgMsgMem

#endif

// defined in SmmBackdoor.c
extern UINT64 m_DummyPage;
//--------------------------------------------------------------------------------------
BOOLEAN VirtualAddrRemap(UINT64 Addr, UINT64 NewAddr, UINT64 Cr3)
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
                        X64_PAGE_TABLE_ENTRY_4K *PTEntry = (X64_PAGE_TABLE_ENTRY_4K *)
                            (PFN_TO_PAGE(PDEntry.Bits.PageTableBaseAddress) + PTE_INDEX(Addr) * sizeof(UINT64));

                        if (PTEntry->Bits.Present)
                        {
                            // disable write protection
                            __writecr0(__readcr0() & ~CR0_WP);

                            // remap virtual address to the new physical address
                            PTEntry->Bits.PageTableBaseAddress = PAGE_TO_PFN(NewAddr);                                                        

                            // restore write protection
                            __writecr0(__readcr0() | CR0_WP);

                            // flush TLB
                            __writecr3(__readcr3());
                            
                            return TRUE;
                        }
                    }
                }  
            }
        }
    }

    return FALSE;
}
//--------------------------------------------------------------------------------------
EFI_STATUS VirtualToPhysical(UINT64 Addr, UINT64 *Ret, UINT64 Cr3, UINT64 SmmCr3)
{
    UINT64 PhysAddr = 0;
    EFI_STATUS Status = EFI_INVALID_PARAMETER;    

    X64_PAGE_MAP_AND_DIRECTORY_POINTER_2MB_4K PML4Entry;    

    DbgMsgMem(__FILE__, __LINE__, __FUNCTION__"(): CR3 is 0x%llx, VA is 0x%llx\r\n", Cr3, Addr);

    if (SmmCr3 != 0 && m_DummyPage != 0)
    {
        // map physical address
        if (VirtualAddrRemap(m_DummyPage, PML4_ADDRESS(Cr3), SmmCr3))
        {
            PML4Entry.Uint64 = *(UINT64 *)(m_DummyPage + PML4_INDEX(Addr) * sizeof(UINT64));       

            // revert old mapping
            VirtualAddrRemap(m_DummyPage, m_DummyPage, SmmCr3);
        } 
        else
        {
            return Status;
        }
    }
    else
    {
        PML4Entry.Uint64 = *(UINT64 *)(PML4_ADDRESS(Cr3) + PML4_INDEX(Addr) * sizeof(UINT64));
    }

    DbgMsgMem(
        __FILE__, __LINE__, "PML4E is at 0x%llx[0x%llx]: 0x%llx\r\n", 
        PML4_ADDRESS(Cr3), PML4_INDEX(Addr), PML4Entry.Uint64
    );

    if (PML4Entry.Bits.Present)
    {
        X64_PAGE_MAP_AND_DIRECTORY_POINTER_2MB_4K PDPTEntry;

        if (SmmCr3 != 0 && m_DummyPage != 0)
        {
            // map physical address
            if (VirtualAddrRemap(m_DummyPage, PFN_TO_PAGE(PML4Entry.Bits.PageTableBaseAddress), SmmCr3))
            {
                PDPTEntry.Uint64 = *(UINT64 *)(m_DummyPage + PDPT_INDEX(Addr) * sizeof(UINT64));

                // revert old mapping
                VirtualAddrRemap(m_DummyPage, m_DummyPage, SmmCr3);
            } 
            else
            {
                return Status;
            }
        }
        else
        {
            PDPTEntry.Uint64 = *(UINT64 *)(PFN_TO_PAGE(PML4Entry.Bits.PageTableBaseAddress) + 
                                           PDPT_INDEX(Addr) * sizeof(UINT64));
        }

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

                if (SmmCr3 != 0 && m_DummyPage != 0)
                {
                    // map physical address
                    if (VirtualAddrRemap(m_DummyPage, PFN_TO_PAGE(PDPTEntry.Bits.PageTableBaseAddress), SmmCr3))
                    {
                        PDEntry.Uint64 = *(UINT64 *)(m_DummyPage + PDE_INDEX(Addr) * sizeof(UINT64));       

                        // revert old mapping
                        VirtualAddrRemap(m_DummyPage, m_DummyPage, SmmCr3);
                    } 
                    else
                    {
                        return Status;
                    }
                }
                else
                {
                    PDEntry.Uint64 = *(UINT64 *)(PFN_TO_PAGE(PDPTEntry.Bits.PageTableBaseAddress) +
                                                 PDE_INDEX(Addr) * sizeof(UINT64));
                }

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

                        if (SmmCr3 != 0 && m_DummyPage != 0)
                        {
                            // map physical address
                            if (VirtualAddrRemap(m_DummyPage, PFN_TO_PAGE(PDEntry.Bits.PageTableBaseAddress), SmmCr3))
                            {
                                PTEntry.Uint64 = *(UINT64 *)(m_DummyPage + PTE_INDEX(Addr) * sizeof(UINT64));

                                // revert old mapping
                                VirtualAddrRemap(m_DummyPage, m_DummyPage, SmmCr3);
                            } 
                            else
                            {
                                return Status;
                            }
                        }
                        else
                        {
                            PTEntry.Uint64 = *(UINT64 *)(PFN_TO_PAGE(PDEntry.Bits.PageTableBaseAddress) +
                                                         PTE_INDEX(Addr) * sizeof(UINT64));
                        }

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
//--------------------------------------------------------------------------------------
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
// EoF
