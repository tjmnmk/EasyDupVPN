import nacl.secret

import const
import config

class Crypto:
    def __init__(self):
        key = config.get_encryption_key()
        key = self._decode_hex_key(key)
        self._box = nacl.secret.SecretBox(key)

    def _decode_hex_key(self, hex_key):
        # check key length
        if len(hex_key) != const.KEY_LENGTH_HEX:
            raise ValueError("Invalid hex key length")
        decoded_key = bytes.fromhex(hex_key)

        assert(len(decoded_key) == 32)
        return decoded_key
        
    def encrypt(self, data):
        return self._box.encrypt(data)

    def decrypt(self, encrypted_data):
        return self._box.decrypt(encrypted_data)