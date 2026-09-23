import struct

# Create a flat binary: just a loop at the beginning
# We'll put the loop at offset 0 in the file.
code = b'\xeb\xfe'  # jmp $ (infinite loop)
# Pad to 4096 bytes with zeros
payload = code + b'\x00' * (4096 - len(code))

with open('slurabsd_fixed.bin', 'wb') as f:
    f.write(payload)

print("Created slurabsd_fixed.bin (flat binary)")
