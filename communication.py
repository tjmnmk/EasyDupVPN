import socket
import loguru
import random
import time

import config
import const


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
        self._ttl = config.get_deduplication_ttl_seconds()

        self._new_set = self._set1
        self._iterations_of_clear_check = 0

    def _clear_if_is_time(self):
        self._iterations_of_clear_check += 1
        if self._iterations_of_clear_check < 1000:
            return
        ttl = config.get_deduplication_ttl_seconds()

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

    def nonce(self, nonce):
        new = self._is_nonce_new(nonce)
        if new:
            self._new_set.add(nonce)
        
        return new

class Communication:
    def __init__(self):
        self._udp = UDP()
        self._number_of_duplicates = config.get_number_of_duplicates()

        self._deduplication_manager = DeduplicationManager()

    def create_header(self):
        header = const.RAWUDPVPN_HEADER_START
        header += random.randbytes(16) # 16 bytes for deduplication nonce

        return header

    def send_packet(self, data):
        for _ in range(self._number_of_duplicates):
            packet_data = self.create_header() + data
            self._udp.udp_write(packet_data)

    def receive_packet(self):
        packet_data = self._udp.udp_read()
        if not packet_data:
            return None
        
        if not packet_data.startswith(const.RAWUDPVPN_HEADER_START):
            loguru.logger.warning("Received UDP packet with invalid header, discarding")
            return None
        
        data = packet_data[len(const.RAWUDPVPN_HEADER_START):] # strip header
        deduplication_nonce = data[:8]
        data = data[8:] # strip deduplication nonce

        if not self._deduplication_manager.nonce(deduplication_nonce):
            return None
        
        return data
        

class UDP:
    def __init__(self):
        sock = self._udp_open()
        sock.setblocking(False)

        self._host = config.get_listen_address()
        self._port = config.get_listen_port()
        self._peer_host = config.get_peer_address()
        self._peer_port = config.get_peer_port()
        self._udp_size = config.get_udp_mtu()
        self._sock = sock

    def _udp_open(self):
        loguru.logger.info(f"Opening UDP socket on {self._host}:{self._port}")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((self._host, self._port))
        return sock
    
    def udp_read(self):
        loguru.logger.debug("Reading from UDP socket")

        data, address = self._sock.recvfrom(9000) # TODO: variable buffer size
        loguru.logger.debug(f"Read {len(data)} bytes from UDP socket from {address}")
        if address != (self._peer_host, self._peer_port):
            loguru.logger.warning(f"Received UDP packet from unexpected address {address}, expected {(self._peer_host, self._peer_port)}, discarding")
            return None

        return data
    
    def udp_write(self, packet_data):
        loguru.logger.debug(f"Writing {len(packet_data)} bytes to UDP socket to {(self._peer_host, self._peer_port)}")
        self._sock.sendto(packet_data, (self._peer_host, self._peer_port))