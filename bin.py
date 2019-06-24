import struct
from bitstring import ConstBitStream

MAGIC = {
    bytes.fromhex('123456781122334455667788'): "jn516x",
    bytes.fromhex('123456782233445566778899'): "jn5178",
}
HEADER_SIZE = 0x38
VERSION_SIZE = 0x4


class FlashHeader:
    def __init__(self, binf):
        self._binf = binf
        if self._binf.buf[:0xc] in MAGIC:
            self._start = 0x0
        else:
            self._start = VERSION_SIZE

    @property
    def has_version(self):
        if self._binf.buf[:0xc] in MAGIC:
            return False
        else:
            return True

    def _slice(self, start, size=1):
        if self.has_version:
            start += 4

        return ConstBitStream(self._binf.buf[start:start + size].tobytes())

    @property
    def version(self):
        if self._start:
            return self._slice(0, 4).uintbe
        else:
            return 0

    @property
    def magic(self):
        return self._slice(0, 12).bytes

    @property
    def config(self):
        return self._slice(0xc).uintbe

    @property
    def status(self):
        return self._slice(0xd).uintbe

    @property
    def app_id(self):
        return self._slice(0xe, 2).uintbe

    @property
    def encryption_init_vector(self):
        return self._slice(0x10, 14)

    @property
    def sw_conf(self):
        return self._slice(0xe, 2)

    @property
    def image_length(self):
        return self._slice(0x20, 4).uintbe

    @property
    def data_flash_start(self):
        return self._slice(0x24, 4).uintbe

    @property
    def data_load_address(self):
        return self._slice(0x28, 2).uintbe

    @property
    def data_length_in_words(self):
        return self._slice(0x2a, 2).uintbe

    @property
    def bss_start_address(self):
        return self._slice(0x2c, 2).uintbe

    @property
    def bss_length_in_words(self):
        return self._slice(0x2e, 2).uintbe

    @property
    def warm_start(self):
        return self._slice(0x30, 4).uintbe

    @property
    def cold_start(self):
        return self._slice(0x34, 4).uintbe

class JennicLoader:
    RAM_BEGIN = 0x4000000

    def __init__(self, a):
        if (a != 0):
            self._a = a
            print ("a", a)

    def load_buffer(self, binf, buf, loadaddr):
        return [True]

    def baddr(self, binf):
        return [0x80000]

    def _check_bytes_versioned(self, buf):
        return len(buf) > (VERSION_SIZE + HEADER_SIZE) \
            and buf[0x04:0x10] in MAGIC

    def _check_bytes_unversioned(self, buf):
        return len(buf) > (HEADER_SIZE) \
            and buf[:0xc] in MAGIC

    def check_bytes(self, buf):
        return [self._check_bytes_versioned(buf) or self._check_bytes_unversioned(buf)]

    def sections(self, binf):
        fheader = FlashHeader(binf)
        offset = VERSION_SIZE if fheader.has_version else 0

        header = {
                "name": ".header",
                "size": HEADER_SIZE,
                "vsize": HEADER_SIZE,
                "paddr": offset,
                "vaddr": self.baddr(binf)[0],
                "perm": 4, # R_PERM_R
                "has_strings": False,
                "add": True,
                "is_data": True,
            }
        data = {
                "name": ".data",
                "size": HEADER_SIZE,
                "vsize": HEADER_SIZE,
                "paddr": offset + fheader.data_flash_start - self.baddr(binf)[0],
                "vaddr": self.RAM_BEGIN + 4 * fheader.data_load_address,
                "perm": 4|2, # R_PERM_R | R_PERM_W
                "has_strings": True,
                "add": True,
                "is_data": True,
            }
        text = {
                "name": ".text",
                "size": data['paddr'] - (offset + HEADER_SIZE),
                "vsize": data['paddr'] - (offset + HEADER_SIZE),
                "paddr": offset + HEADER_SIZE,
                "vaddr": self.baddr(binf)[0] + HEADER_SIZE,
                "perm": 4|1, # R_PERM_R | R_PERM_X
                "arch": "ba2",
                "bits": 32,
                "has_strings": False,
                "add": True,
                "is_data": False,
            }
        return [header, data, text]

    def entries(self, binf):
        return [
            {"vaddr": FlashHeader(binf).cold_start},
            {"vaddr": FlashHeader(binf).warm_start},
        ]

    def info(self, binf):
        jntype = MAGIC[FlashHeader(binf).magic]
        return [{
                "type" : jntype,
                #"bclass" : jntype,
                #"rclass" : jntype,
                "os" : "none",
                "subsystem" : "none",
                "machine" : jntype,
                "arch" : "ba2",
                "has_va" : 1,
                "bits" : 32,
                "big_endian" : 1,
                "dbg_info" : 0,
                }]

def jn5168bin(a):
    loader = JennicLoader(a)

    return {
        "name": "jennic.fw",
        "desc": "JN516x/JN517x firmware loader plugin",
        "license": "BSD",
        "check_bytes": loader.check_bytes,
        "load_buffer": loader.load_buffer,
        "info": loader.info,
        "sections": loader.sections,
        "baddr": loader.baddr,
        "entries": loader.entries,
    }
