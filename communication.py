import socket
import loguru
import random
import time

import config
import const
import crypto

class NonceSet:
    def __init__(self):
        self._set = set()
        self._time = time.time()
    
    def add(self, nonce):
        self._set.add(nonce)
        return True
    
    def check(self, nonce):
        return nonce in self._set
    
    def get_age(self):
        return int(time.time() - self._time)
    
    def get_last_cleared_time(self):
        return self._time
    
    def clear(self):
        self._set.clear()
        self._time = time.time()


class DeduplicationManager:
    def __init__(self):
        self._set1 = NonceSet()
        self._set2 = NonceSet()
        self._ttl = config.Config().get_deduplication_ttl_seconds()

        self._new_set = self._set1
        self._iterations_of_clear_check = 0

    def _clear_if_is_time(self):
        self._iterations_of_clear_check += 1
        if self._iterations_of_clear_check < 1000:
            return
        self._iterations_of_clear_check = 0
        ttl = config.Config().get_deduplication_ttl_seconds()

        # we need to check if both sets are older than ttl, if so, clear the older one
        if self._set1.get_age() > ttl and self._set2.get_age() > ttl:
            if self._set1.get_last_cleared_time() < self._set2.get_last_cleared_time():
                loguru.logger.debug("Clearing deduplication nonce set 1")
                self._set1.clear()
                self._new_set = self._set1
            else:
                loguru.logger.debug("Clearing deduplication nonce set 2")
                self._set2.clear()
                self._new_set = self._set2

    
    def _is_nonce_new(self, nonce):
        if self._set1.check(nonce):
            return False
        if self._set2.check(nonce):
            return False
        
        return True

    def nonce(self, nonce):
        new = self._is_nonce_new(nonce)
        if new:
            self._new_set.add(nonce)
        
        return new

class Communication:
    def __init__(self):
        self._udp = UDP()
        self._number_of_duplicates = config.Config().get_number_of_duplicates()
        self._crypto = crypto.Crypto()
        self._protocol_header = config.Config().get_protocol_header()

        self._deduplication_manager = DeduplicationManager()

    def create_header(self):
        if self._protocol_header:
            header = const.RAWUDPVPN_HEADER_START
        else:
            header = b''
        header += random.randbytes(16) # 16 bytes for deduplication nonce

        return header

    def send_packet(self, data):
        encrypted_data = self._crypto.encrypt(data)
        packet_data = self.create_header() + encrypted_data
        for _ in range(self._number_of_duplicates):
            self._udp.udp_write(packet_data)

    def receive_packet(self):
        packet_data, address, port = self._udp.udp_read()
        if not packet_data:
            return None
        
        if self._protocol_header:
            if not packet_data.startswith(const.RAWUDPVPN_HEADER_START):
                loguru.logger.warning("Received UDP packet with invalid header, discarding")
                return None
            data = packet_data[len(const.RAWUDPVPN_HEADER_START):] # strip header
        else:
            data = packet_data
        
        deduplication_nonce = data[:16]
        data = data[16:] # strip deduplication nonce

        if not self._deduplication_manager.nonce(deduplication_nonce):
            return None
        
        data = self._crypto.decrypt(data)
        if not data:
            return None
        
        loguru.logger.debug(f"Decrypted UDP packet of length {len(data)}")
        self._udp.learn_peer(address, port)
        return data
    
    def fileno(self):
        return self._udp.fileno()
        

class UDP:
    def __init__(self):
        self._host = config.Config().get_listen_address()
        self._port = config.Config().get_listen_port()
        self._peer_host = config.Config().get_peer_address()
        self._peer_port = config.Config().get_peer_port()
        self._peer_dynamic = config.Config().get_learn_peer()
        self._learned_peer = False
        if self._peer_dynamic == "off":
            self._learned_peer = True
        sock = self._udp_open()
        sock.setblocking(False)
        self._sock = sock

    def _udp_open(self):
        loguru.logger.info(f"Opening UDP socket on {self._host}:{self._port}")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.bind((self._host, self._port))
        return sock
    
    def udp_read(self):
        try:
            data, address = self._sock.recvfrom(9000) # TODO: variable buffer size
        except BlockingIOError:
            return None  # No data available
        loguru.logger.debug(f"Read {len(data)} bytes from UDP socket from {address}")

        address, port = address
        return data, address, port
    
    def learn_peer(self, address, port):
        if self._peer_dynamic == "off":
            assert(self._learned_peer == True)
        if self._learned_peer:
            return
        if (address, port) == (self._peer_host, self._peer_port):
            return # no change
        
        loguru.logger.info(f"Learned peer address: {address}:{port}")
        self._peer_host = address
        self._peer_port = port
        if self._peer_dynamic == "learn":
            self._learned_peer = True
    
    def udp_write(self, packet_data):
        loguru.logger.debug(f"Writing {len(packet_data)} bytes to UDP socket to {(self._peer_host, self._peer_port)}")
        if self._peer_host is None or self._peer_port is None:
            loguru.logger.debug("Peer address or port is not learned yet, not sending packet")
            return
        self._sock.sendto(packet_data, (self._peer_host, self._peer_port))

    def fileno(self):
        return self._sock.fileno()
    