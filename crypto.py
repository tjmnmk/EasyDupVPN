import nacl.secret
import loguru

import const
import config

class Crypto:
    def __init__(self):
        key = config.Config().get_encryption_key()
        assert(len(key) == const.KEY_LENGTH_HEX // 2)
        self._box = nacl.secret.SecretBox(key)
        
    def encrypt(self, data):
        return self._box.encrypt(data)

    def decrypt(self, encrypted_data):
        try:
            return self._box.decrypt(encrypted_data)
        except Exception as e:
            loguru.logger.error(f"Decryption failed: {e}")