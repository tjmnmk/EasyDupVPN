import socket
import loguru
import random
import time
import os
import struct

import config
import const
import crypto
import compressor
import common

class NonceSet:
    def __init__(self):
        self._set = set()
        self._time = time.monotonic()
    
    def add(self, nonce):
        self._set.add(nonce)
        return True
    
    def check(self, nonce):
        return nonce in self._set
    
    def get_age(self):
        return int(time.monotonic() - self._time)
    
    def get_last_cleared_time(self):
        return self._time
    
    def clear(self):
        self._set.clear()
        self._time = time.monotonic()


class PacketSplitterSet:
    def __init__(self):
        self._data = {}
        self._created = time.monotonic()

    def add_part_and_assemble(self, part_index, total_parts, part_data):
        self._data[part_index] = part_data
        # check if all parts are received
        if len(self._data) == total_parts:
            assembled_data = b''.join(self._data[i] for i in range(total_parts))

            return assembled_data
        
        return None

    def age(self):
        return int(time.monotonic() - self._created)


class PacketSplitter:
    def __init__(self):
        self._max_size = config.Config().get_vpn_data_max_size_split()
        self._data = {}
        self._cleanup_iterations = 0

    def split(self, data):
        return common.split_string_to_chunks(data, self._max_size)

    def add_part_and_assemble(self, nonce, part_index, total_parts, part_data):
        loguru.logger.debug(f"Received packet part {part_index + 1}/{total_parts} for nonce {nonce.hex()}")
        self._cleanup_iterations += 1
        if self._cleanup_iterations >= 1000:
            self.cleanup_old()
            self._cleanup_iterations = 0

        if nonce not in self._data:
            self._data[nonce] = PacketSplitterSet()
        
        assembled_data = self._data[nonce].add_part_and_assemble(part_index, total_parts, part_data)
        if assembled_data is not None:
            del self._data[nonce]
            return assembled_data
        
        return None
    
    def cleanup_old(self):
        to_delete = []
        for nonce, splitter_set in self._data.items():
            if splitter_set.age() > 15:  # 15 seconds timeout
                to_delete.append(nonce)
        
        for nonce in to_delete:
            loguru.logger.debug(f"Cleaning up old packet splitter set for nonce {nonce.hex()}")
            del self._data[nonce]


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


class DelayedPacketSender:
    """
    It is not guaranteed that the delayed packet will be sent exactly after the specified delay,
    the send_dalayed_packets() is called only after sending normal packets / recv packets, so if there is no traffic,
    the delayed packets will not be sent.

    This should be ok for most use cases.
    """
    def __init__(self, udp_instance):
        self._packets = []
        self._send_extra_delayed_packet_after = config.Config().get_send_extra_delayed_packet_after()
        self._udp = udp_instance

        self._last_check_time = time.monotonic()

    def add_delayed_packet(self, packet_data):
        send_time = time.monotonic() + self._send_extra_delayed_packet_after
        self._packets.append((send_time, packet_data))

    def send_delayed_packets(self):
        if self._last_check_time + 0.01 > time.monotonic():
            return # check every 10ms
        current_time = time.monotonic()
        for p in self._packets[:]:
            send_time, packet_data = p
            if current_time >= send_time:
                loguru.logger.debug("Sending extra delayed duplicate packet")
                self._udp.udp_write(packet_data)
                self._packets.remove(p)

        self._last_check_time = current_time


class Communication:
    def __init__(self):
        self._udp = UDP()
        self._number_of_duplicates = config.Config().get_number_of_duplicates()
        self._crypto = crypto.Crypto()
        self._protocol_header = config.Config().get_protocol_header()
        self._compression_enabled = config.Config().get_compression()
        self._compression_i = compressor.Compressor()

        self._deduplication_manager = DeduplicationManager()
        self._packet_splits = bool(config.Config().get_vpn_data_max_size_split())
        self._packet_splitter = PacketSplitter()

        self._send_extra_delayed_packet = bool(config.Config().get_send_extra_delayed_packet_after())
        self._delayed_packet_sender = DelayedPacketSender(self._udp)

    def _generate_dedup_nonce(self):
        try:
            dedup_nonce = random.randbytes(16) # 16 bytes for deduplication nonce
        except AttributeError:
            dedup_nonce = os.urandom(16)
        return dedup_nonce

    def create_header(self, part=None, total_parts=None, dedup_nonce=None):
        """
        Header:
        - Protocol header (optional) - when PROTOCOL_HEADER is enabled
        - 16 bytes deduplication nonce - always present
        - 1 byte number of index of this part (optional) - when packet is split
        - 1 byte number of total parts (optional) - when packet is split
        """
        if part is not None:
            assert(total_parts)
            assert(dedup_nonce)

        if self._protocol_header:
            header = const.RAWUDPVPN_HEADER_START
        else:
            header = b''
        
        if dedup_nonce is None:
            dedup_nonce = self._generate_dedup_nonce()
        header += dedup_nonce # add deduplication nonce
        if self._packet_splits:
            header += struct.pack("B", part)  # 1 byte for part index
            header += struct.pack("B", total_parts)  # 1 byte for total parts

        return header

    def send_packet(self, data):
        if self._compression_enabled:
            original_length = len(data)
            data = self._compression_i.compress(data)
            loguru.logger.debug(f"Compressed data length: {len(data)}; original length: {original_length}")
            
        encrypted_data = self._crypto.encrypt(data)
        if not self._packet_splits:
            packet_data = self.create_header() + encrypted_data
            for _ in range(self._number_of_duplicates):
                self._udp.udp_write(packet_data)
            if self._send_extra_delayed_packet:
                self._delayed_packet_sender.add_delayed_packet(packet_data)
        else:
            parts = self._packet_splitter.split(encrypted_data)
            nonce = self._generate_dedup_nonce() # we need same nonce for all parts
            for part_index, part in enumerate(parts):
                packet_data = self.create_header(part=part_index, total_parts=len(parts), dedup_nonce=nonce) + part
                for _ in range(self._number_of_duplicates):
                    self._udp.udp_write(packet_data)
                if self._send_extra_delayed_packet:
                    self._delayed_packet_sender.add_delayed_packet(packet_data)
        if self._send_extra_delayed_packet:
            self._delayed_packet_sender.send_delayed_packets()

    def receive_packet(self):
        # first send any delayed packets if needed
        if self._send_extra_delayed_packet:
            self._delayed_packet_sender.send_delayed_packets()
            
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
        
        if self._packet_splits:
            if len(data) < 2:
                loguru.logger.warning("Received split packet with invalid length, discarding")
                return None
            part_index = data[0]
            total_parts = data[1]
            part_data = data[2:]  # strip part index and total parts

            assembled_data = self._packet_splitter.add_part_and_assemble(
                deduplication_nonce, part_index, total_parts, part_data)
            if assembled_data is None:
                return None  # not all parts received yet
            data = assembled_data

        if not self._deduplication_manager.nonce(deduplication_nonce):
            return None

        data = self._crypto.decrypt(data)
        if not data:
            return None
        
        loguru.logger.debug(f"Decrypted UDP packet of length {len(data)}")
        self._udp.learn_peer(address, port)
        if self._compression_enabled:
            original_length = len(data)
            data = self._compression_i.decompress(data)
            if not data:
                return None
            loguru.logger.debug(f"Decompressed data length: {len(data)}; original length: {original_length}")
            
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
        
        # Increase send buffer for better throughput with packet duplication
        send_buffer_size = 8 * 1024 * 1024  # 8 MB
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, send_buffer_size)
        except Exception as e:
            loguru.logger.warning(f"Failed to set UDP send buffer size: {e}")
        actual_sndbuf = sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
        loguru.logger.info(f"UDP send buffer size: {actual_sndbuf} bytes")
        
        # Also increase receive buffer
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, send_buffer_size)
        except Exception as e:
            loguru.logger.warning(f"Failed to set UDP receive buffer size: {e}")
        actual_rcvbuf = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        loguru.logger.info(f"UDP receive buffer size: {actual_rcvbuf} bytes")
        
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
        try:
            self._sock.sendto(packet_data, (self._peer_host, self._peer_port))
        except Exception as e:
            loguru.logger.error(f"Failed to send UDP packet: {e}")

    def fileno(self):
        return self._sock.fileno()
    