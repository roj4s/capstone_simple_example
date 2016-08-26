__author__ = 'yalu'

from capstone import *
import pefile

if __name__ == "__main__":
    input_file_addr = "b7e33cdb170994033c390ca79344f6f7"
    pe = pefile.PE(input_file_addr)
    entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    code = pe.get_memory_mapped_image()[entry_point:]

    md = Cs(CS_ARCH_X86, CS_MODE_32)

    for i in md.disasm(code, entry_point):
        pass