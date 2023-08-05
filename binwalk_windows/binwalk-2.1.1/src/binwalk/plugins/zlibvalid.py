import zlib
import binwalk.core.compat
import binwalk.core.plugin
from binwalk.core.common import BlockFile

class ZlibValidPlugin(binwalk.core.plugin.Plugin):
    '''
    Validates zlib compressed data.
    '''
    MODULES = ['Signature']

    MAX_DATA_SIZE = 33 * 1024

    def scan(self, result):
        # If this result is a zlib signature match, try to decompress the data
        if not result.file or not result.description.lower().startswith('zlib'):
            return
            # If byte swapping is enabled, we need to start reading at a swap-size
            # aligned offset, then index in to the read data appropriately.
        adjust = (
            result.offset % self.module.config.swap_size
            if self.module.config.swap_size
            else 0
        )
        offset = result.offset - adjust

        # Seek to and read the suspected zlib data
        fd = self.module.config.open_file(result.file.name)
        fd.seek(offset)
        data = fd.read(self.MAX_DATA_SIZE)[adjust:]
        fd.close()

        # Check if this is valid zlib data. It is valid if:
        #
        #   1. It decompresses without error
        #   2. Decompression fails only because of truncated input
        try:
            zlib.decompress(binwalk.core.compat.str2bytes(data))
        except zlib.error as e:
            # Error -5, incomplete or truncated data input
            if not str(e).startswith("Error -5"):
                result.valid = False

