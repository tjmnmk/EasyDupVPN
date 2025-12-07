import zlib

import config

class Compressor:
    def __init__(self):
        self._compression_enabled = config.Config().get_compression()

    def compress(self, data):
        assert(self._compression_enabled)

        return zlib.compress(data)
        
    def decompress(self, data):
        assert(self._compression_enabled)

        return zlib.decompress(data)
        