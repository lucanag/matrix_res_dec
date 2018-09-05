from chacha import ChaCha
import pefile
import struct
import binascii
import sys


if len(sys.argv) > 2:
    fn = sys.argv[1]
    pe = pefile.PE(fn)
    rn = sys.argv[2].upper()
else:
    print("Bad arguments. Proper usage: matrix_rsrc_dec.py [file_name] [resource_name]")

# read CHAK resource
offset = 0x0
size = 0x0
for rsrc in pe.DIRECTORY_ENTRY_RESOURCE.entries:
    for entry in rsrc.directory.entries:
        if entry.name is not None:
            if str(entry.name) == "CHAK":
                offset = entry.directory.entries[0].data.struct.OffsetToData
                size = entry.directory.entries[0].data.struct.Size

chak = pe.get_memory_mapped_image()[offset:offset+size]

# key & ic to ChaCha
keys = chak.splitlines()
key = keys[0]
iv = keys[1]
iv = struct.pack("<q", int(iv))
c = ChaCha(key, iv)

# read the requested resource
offset = 0x0
size = 0x0
for rsrc in pe.DIRECTORY_ENTRY_RESOURCE.entries:
    for entry in rsrc.directory.entries:
        if entry.name is not None:
            if str(entry.name) == rn:
                offset = entry.directory.entries[0].data.struct.OffsetToData
                size = entry.directory.entries[0].data.struct.Size

stream = pe.get_memory_mapped_image()[offset:offset + size]
hex_stream = binascii.unhexlify(binascii.hexlify(stream))
result = c.decrypt(hex_stream)
print("---------")
print(result)
print("---------")
