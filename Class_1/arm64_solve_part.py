import sys
sys.path.append("../../qiling")

from qiling import *
from qiling.const import QL_VERBOSE
from qiling.os.mapper import QlFsMappedObject
import struct



# if __name__ == "__main__":
#     ql = Qiling(["rootfs/arm64_linux/bin/qilinglab-aarch64"], "rootfs/arm64_linux",verbose=QL_VERBOSE.OFF)
#     ql.run()

class Fake_urandom(QlFsMappedObject):
    def read(self, size):
        if(size > 1):
            return b"\x01" * size
        else:
            return b"\x02"
    def fstat(self): # syscall fstat will ignore it if return -1
        return -1
    def close(self):
        return 0

def my_syscall_uname(ql, write_buf, *args, **kw):
    buf = b'QilingOS\x00' # sysname
    ql.mem.write(write_buf, buf)

    buf = b'30000'.ljust(65, b'\x00') # important!! If not set will `FATAL: kernel too old`
    ql.mem.write(write_buf+65*2, buf)
    buf = b'ChallengeStart'.ljust(65, b'\x00') # version
    ql.mem.write(write_buf+65*3, buf)
    regreturn = 0
    return regreturn


def my_syscall_getrandom(ql, write_buf, write_buf_size, flag , *args, **kw):
    buf = b"\x01" * write_buf_size
    ql.mem.write(write_buf, buf)
    regreturn = 0
    return regreturn

def hook_rand(ql, *args, **kw):
    ql.arch.regs.w0 = 0
    return

def hook_cmp(ql):
    ql.arch.regs.w0 = 1
    return


if __name__ == "__main__":
    ql = Qiling(["rootfs/arm64_linux/bin/qilinglab-aarch64"], "rootfs/arm64_linux" ,verbose=QL_VERBOSE.DISABLED)

    # challenge 1

    # need to align the memory offset and address for mapping.
    # size at least a multiple of 4096 for alignment
    ql.mem.map(0x1000, 0x1000)
    ql.mem.write(0x1337, ql.pack16(1337) )

    # challenge 2
    ql.os.set_syscall("uname", my_syscall_uname)

    # challenge 3
    ql.add_fs_mapper('/dev/urandom', Fake_urandom())
    ql.os.set_syscall("getrandom", my_syscall_getrandom)

    # challenge 4
    base_addr = ql.mem.get_lib_base(ql.targetname) # get pie_base addr

    # 00100fd8 e0 1b 40 b9     ldr        w0,[sp, #local_8]
    # 00100fdc e1 1f 40 b9     ldr        w1,[sp, #local_4]
    # 00100fe0 3f 00 00 6b     cmp        w1,w0

    ql.hook_address(hook_cmp, base_addr + 0xfe0)

    # callenge 5
    ql.os.set_api("rand", hook_rand)

    # end and run
    ql.run()