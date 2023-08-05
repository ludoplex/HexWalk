import os
import binwalk.core.plugin

class LZMAExtractPlugin(binwalk.core.plugin.Plugin):
    '''
    LZMA extractor plugin.
    '''
    MODULES = ['Signature']

    def init(self):
        try:
            # lzma package in Python 2.0 decompress() does not handle multiple
            # compressed streams, only first stream is extracted.
            # backports.lzma package could be used to keep consistent behaviour.
            import lzma
            self.decompressor = lzma.decompress

            # If the extractor is enabled for the module we're currently loaded
            # into, then register self.extractor as a zlib extraction rule.
            if self.module.extractor.enabled:
                self.module.extractor.add_rule(txtrule=None,
                                               regex="^lzma compressed data",
                                               extension="7z",
                                               cmd=self.extractor)
                self.module.extractor.add_rule(txtrule=None,
                                               regex="^xz compressed data",
                                               extension="xz",
                                               cmd=self.extractor)
        except ImportError as e:
            pass

    def extractor(self, fname):
        fname = os.path.abspath(fname)
        outfile = os.path.splitext(fname)[0]

        try:
            with open(fname, "rb") as fpin:
                compressed = fpin.read()
            decompressed = self.decompressor(compressed)

            with open(outfile, "wb") as fpout:
                fpout.write(decompressed)
        except KeyboardInterrupt as e:
            raise e
        except Exception as e:
            return False

        return True
