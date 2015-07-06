
  SMM backdoor for UEFI based platforms

*****************************************************************

For more information about this project please read the following article:

http://blog.cr4.sh/2015/07/building-reliable-smm-backdoor-for-uefi.html


Repository contents:

  * SmmBackdoor.py -- Python program that allows to infect PE image of UEFI DXE driver with backdoor code, communicate with installed backdoor to read SMRAM and do some other useful things.

  * SmmBackdoor/ -- source code of UEFI part that runs in System Management Mode.

  * SmmBackdoor.efi, SmmBackdoor.pdb -- UEFI part binary and it's debug symbols.

  * smm_call/ -- proof of concept Linux program that interacts with installed backdoor to get root privileges for it's process.
 

To build SmmBackdoor project you need to have a Windows machine with Visual Studio 2008 and EDK2 source code (https://github.com/tianocore/edk2).

Step by step instruction:

  1. Copy SmmBackdoor subdirectory to EDK2 source code directory.

  2. Edit Conf/target.txt file and set ACTIVE_PLATFORM property value to OvmfPkg/OvmfPkgX64.dsc.

  3. Edit OvmfPkg/OvmfPkgX64.dsc and add the following lines at the end of the file:

    #
    # 3-rd party drivers
    #
    SmmBackdoor/SmmBackdoor.inf {
      <LibraryClasses>
        DebugLib|OvmfPkg/Library/PlatformDebugLibIoPort/PlatformDebugLibIoPort.inf
        MemoryAllocationLib|MdePkg/Library/UefiMemoryAllocationLib/UefiMemoryAllocationLib.inf
    }

  4. Run Visual Studio 2008 Command Prompt and cd to EDK2 directory.

  5. Execute Edk2Setup.bat --pull to configure build environment and download required binaries.

  6. cd SmmBackdoor && build

  7. After compilation resulting PE image file will be created at Build/OvmfX64/DEBUG_VS2008x86/X64/SmmBackdoor/SmmBackdoor/OUTPUT/SmmBackdoor.efi


To run SmmBackdoor.efi as infector payload on example of Intel DQ77KB motherboard:

  1. Dump motherboard firmware using hardware SPI programmer.

  2. Open dumped flash image in UEFITool.

  3. Extract PE image of FFS file with GUID = 26A2481E-4424-46A2-9943-CC4039EAD8F8 and save it to extracted.bin file.

  4. Infect extrated image with SmmBackdoor.efi using SmmBackdoor.py:

    $ python SmmBackdoor.py --infect extracted.bin --output infected.bin --payload SmmBackdoor.efi

  5. In UEFITool replace original PE image with infected.bin.

  6. Save modified flash image to file and write it to the motherboard ROM with programmer.

Backdoor also has debug output capabilities that allows to see DXE phase debug messages on the screen and receive runtime phase debug messages over COM port.


To use SmmBackdoor.py you need to install a pefile Python library (https://pypi.python.org/pypi/pefile) and CHIPSEC framework (https://github.com/chipsec/chipsec) including Python bindings. 

Supported commands:

  * SmmBackdoor.py --infect <source_path> --output <dest_path> --payload <payload_path> - Infect PE image of DXE driver with specified backdoor code.

  * SmmBackdoor.py --test - Check for backdoor presence and print status information from BACKDOOR_INFO structure.

  * SmmBackdoor.py --dump-smram - Dump all available SMRAM regions into the files.

  * SmmBackdoor.py --read-phys <address> - Print hexadecimal dump of physical memory page at given address.

  * SmmBackdoor.py --read-virt <address> - Print hexadecimal dump of virtual memory page at given address.

  * SmmBackdoor.py --timer-enable - Enable periodic timer SMI that required for smm_call (by default it's enabled).

  * SmmBackdoor.py --timer-disable - Disable periodic timer SMI.


smm_call usage:

  * smm_call <code> [<arg_1> [<arg_2>]] - Send specified control code and arguments to SMM backdoor.

  * smm_call --privesc - Ask the backdoor to give a root privileges for caller process and run command shell.


Please note, that this code was tested only with Intel DQ77KB motherboard. You may try to run it on any other UEFI compatible hardware, but some of the backdoor features might not work.


Written by:
Dmytro Oleksiuk (aka Cr4sh)

cr4sh0@gmail.com
http://blog.cr4.sh

