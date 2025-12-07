import zlib
import loguru

import config

class Compressor:
    def __init__(self):
        self._compression_enabled = config.Config().get_compression()

    def compress(self, data):
        assert(self._compression_enabled)

        compressed = zlib.compress(data)
        return compressed
        
    def decompress(self, data):
        assert(self._compression_enabled)

        try:
            return zlib.decompress(data)
        except Exception as e:
            loguru.logger.error(f"Decompression failed, is compression / packet splitting enabled on both sides? {e}")
            return None