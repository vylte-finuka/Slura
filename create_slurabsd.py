import struct

# Create a minimal ELF64 executable for AMD64
# This is a simple "hello world" style ELF that just loops

# ELF header
elf_header = b'\x7fELF'  # Magic
elf_header += b'\x02'     # 64-bit
elf_header += b'\x01'     # Little endian
elf_header += b'\x01'     # ELF version
elf_header += b'\x00' * 8 # OS/ABI padding

# e_type = ET_EXEC (2)
# e_machine = x86_64 (62 = 0x3E)
# e_version = 1
# e_entry = 0x1000 (point d'entrée)
# e_phoff = 64 (offset du program header)
# e_shoff = 0 (pas de section header)
# e_flags = 0
# e_ehsize = 64
# e_phentsize = 56
# e_phnum = 1
# e_shentsize = 64
# e_shnum = 0
# e_shstrndx = 0

header = struct.pack('<16sHHIQQQIHHHHHH',
    b'\x7fELF\x02\x01\x01',  # ident
    2,    # e_type (EXEC)
    62,   # e_machine (x86_64)
    1,    # e_version
    0x1000,  # e_entry
    64,   # e_phoff
    0,    # e_shoff
    0,    # e_flags
    64,   # e_ehsize
    56,   # e_phentsize
    1,    # e_phnum
    64,   # e_shentsize
    0,    # e_shnum
    0     # e_shstrndx
)

# Program header (LOAD segment)
# p_type = PT_LOAD (1)
# p_offset = 0
# p_vaddr = 0x1000
# p_paddr = 0x1000
# p_filesz = taille du payload
# p_memsz = taille du payload
# p_flags = R+E (5)
# p_align = 0x1000

payload_size = 4096
ph = struct.pack('<IIQQQQQQ',
    1,        # p_type (LOAD)
    0,        # p_offset
    0x1000,   # p_vaddr
    0x1000,   # p_paddr
    payload_size,  # p_filesz
    payload_size,  # p_memsz
    5,        # p_flags (R+E)
    0x1000    # p_align
)

# Code: infinite loop at entry point
code = b'\xeb\xfe'  # jmp $ (infinite loop)
# Pad to payload_size
payload = code + b'\x00' * (payload_size - len(code))

with open('slurabsd.bin', 'wb') as f:
    f.write(header + ph + payload)

print(f"Created slurabsd.bin: {len(header) + len(ph) + len(payload)} bytes")
print(f"Entry point: 0x{0x1000:X}")