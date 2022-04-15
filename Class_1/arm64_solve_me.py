import sys
sys.path.append("../../qiling")

from qiling import *
from qiling.const import QL_VERBOSE


if __name__ == "__main__":
    ql = Qiling(["rootfs/arm64_linux/bin/qilinglab-aarch64"], "rootfs/arm64_linux", verbose=QL_VERBOSE.OFF)
    
    ql.run()