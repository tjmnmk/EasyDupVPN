import json
import ipaddress
import loguru
import re

import const
import exceptions
from singleton import singleton

class ConfigChecks:
    @staticmethod
    def check_ipv4_valid(ipv4):
        if not isinstance(ipv4, str):
            loguru.logger.error(f"IPv4 address must be a string, got {type(ipv4).__name__}")
            return False
        
        try:
            ipaddress.IPv4Address(ipv4)
            return True
        except ipaddress.AddressValueError as e:
            loguru.logger.error(f"IPv4 validation error: {e}")
            return False

    @staticmethod
    def check_ipv6_valid(ipv6):
        if not isinstance(ipv6, str):
            loguru.logger.error(f"IPv6 address must be a string, got {type(ipv6).__name__}")
            return False
        
        try:
            ipaddress.IPv6Address(ipv6)
            return True
        
        except ipaddress.AddressValueError as e:
            loguru.logger.error(f"IPv6 validation error: {e}")
            return False
    
    @staticmethod
    def check_port_valid(port):
        if not isinstance(port, int):
            loguru.logger.error(f"Port must be an integer, got {type(port).__name__}")
            return False
        
        return 0 < port < 65536
    
    @staticmethod
    def mtu_valid(mtu):
        if not isinstance(mtu, int):
            loguru.logger.error(f"MTU must be an integer, got {type(mtu).__name__}")
            return False
        
        return 68 <= mtu <= 9000
    
    @staticmethod
    def ipv6_mtu(mtu):
        if not isinstance(mtu, int):
            loguru.logger.error(f"MTU must be an integer, got {type(mtu).__name__}")
            return False
        
        return 1280 <= mtu <= 9000
    
    @staticmethod
    def key_valid(hex_key):
        if not isinstance(hex_key, str):
            loguru.logger.error(f"Encryption key must be a string, got {type(hex_key).__name__}")
            return False
        
        if len(hex_key) != const.KEY_LENGTH_HEX:
            return False
        try:
            decoded_key = bytes.fromhex(hex_key)
        except ValueError as e:
            loguru.logger.error(f"Hex decoding error: {e}")
            return False
        if len(decoded_key) != 32:
            return False
        
        return True
    
    @staticmethod
    def ipv4_netmask_valid(netmask):
        if not isinstance(netmask, int):
            loguru.logger.error(f"Netmask must be an integer, got {type(netmask).__name__}")
            return False
        if netmask < 0 or netmask > 32:
            return False
        
        return True
    
    @staticmethod
    def ipv6_netmask_valid(netmask):
        if not isinstance(netmask, int):
            loguru.logger.error(f"Netmask must be an integer, got {type(netmask).__name__}")
            return False
        if netmask < 0 or netmask > 128:
            return False
        
        return True
    
    @staticmethod
    def validate_tun_name(name):
        if not isinstance(name, str):
            loguru.logger.error(f"TUN device name must be a string, got {type(name).__name__}")
            return False
        if not name or len(name) > 15:
            return False
        if not re.match(const.TUN_NAME_ALLOWED_REGEX, name):
            return False
        
        return True
    
    @staticmethod
    def validate_number_of_duplicates(num):
        if not isinstance(num, int):
            loguru.logger.error(f"NUMBER_OF_DUPLICATES must be an integer, got {type(num).__name__}")
            return False
        
        if num < 1:
            return False
        
        if num > 5:
            loguru.logger.warning("NUMBER_OF_DUPLICATES greater than 5 may cause performance issues")
        if num == 1:
            loguru.logger.info("NUMBER_OF_DUPLICATES set to 1, no duplication will occur")
        if num > 50:
            return False
        return True
    
    @staticmethod
    def validate_deduplication_ttl_seconds(ttl):
        if not isinstance(ttl, int):
            loguru.logger.error(f"DEDUPLICATION_TTL_SECONDS must be an integer, got {type(ttl).__name__}")
            return False
        
        if ttl < 1 or ttl > 3600:
            return False
        if ttl < 10:
            loguru.logger.warning("DEDUPLICATION_TTL_SECONDS set very low, may cause duplicate packets to be accepted")
        if ttl > 600:
            loguru.logger.warning("DEDUPLICATION_TTL_SECONDS set very high, may cause increased memory usage")
        
        return True
    
    @staticmethod
    def validate_loguru_log_level(level):
        valid_levels = ["TRACE", "DEBUG", "INFO", "SUCCESS", "WARNING", "ERROR", "CRITICAL"]
        if not isinstance(level, str):
            loguru.logger.error(f"LOG_LEVEL must be a string, got {type(level).__name__}")
            return False
        if level not in valid_levels:
            return False
        
        return True
    
    @staticmethod
    def validate_nice_level(nice_level):
        if not isinstance(nice_level, int):
            loguru.logger.error(f"NICE_LEVEL must be an integer, got {type(nice_level).__name__}")
            return False
        
        if nice_level < -20 or nice_level > 19:
            return False
        
        return True
    
    @staticmethod
    def validate_peer_learn(value):
        valid_values = ["off", "learn", "dynamic"]
        if not isinstance(value, str):
            loguru.logger.error(f"PEER_LEARN must be a string, got {type(value).__name__}")
            return False
        if value not in valid_values:
            return False
        
        return True
    
    @staticmethod
    def validate_bool(value):
        if not isinstance(value, bool):
            loguru.logger.error(f"Value must be a boolean, got {type(value).__name__}")
            return False
        
        return True
    
    @staticmethod
    def ip_cidr_valid(cidr):
        try:
            ipaddress.ip_network(cidr, strict=False)
            return True
        except ValueError as e:
            loguru.logger.error(f"CIDR validation error: {e}")
            return False
        
    @staticmethod
    def validate_vpn_data_max_size_split(size):
        if not isinstance(size, int):
            loguru.logger.error(f"VPN_DATA_MAX_SIZE_SPLIT must be an integer, got {type(size).__name__}")
            return False
        
        if size < 0 or size > 9000:
            return False
        
        return True

@singleton
class Config:
    def __init__(self):
        self._settings = {}

    def load_from_file(self, config_file):
        loguru.logger.info(f"Loading configuration from {config_file}")

        try:
            self._settings = json.load(open(config_file, 'r'))
        except Exception as e:
            loguru.logger.error(f"Failed to load configuration file: {e}")
            raise exceptions.ConfigError("Failed to load configuration file")
        
        self._validate_config()

    def _validate_config(self):
        self.get_tun_address_ipv4()
        self.get_tun_address_ipv6()
        self.get_mtu()
        self.get_encryption_key()
        self.get_tun_netmask_ipv4()
        self.get_tun_netmask_ipv6()
        self.get_peer_address()
        self.get_listen_address()
        self.get_device_name()
        self.get_nice_level()
        self.get_number_of_duplicates()
        self.get_deduplication_ttl_seconds()
        self.get_listen_port()
        self.get_peer_port()
        self.get_log_level()
        self.get_learn_peer()
        self.get_protocol_header()
        self.get_compression()

        self._check_for_unknown_settings()

    def _check_for_unknown_settings(self):
        for key in self._settings.keys():
            if key not in const.CONFIG_KNOWN_VALUES and not key.startswith(const.CONFIG_COMMENTS_PREFIXES):
                loguru.logger.warning(f"Unknown configuration key: {key}")

    def _get_value(self, config_key, default=None, required=False, log_level="info"):
        try:
            value = self._settings[config_key]
            return value
        except KeyError:
            if required:
                loguru.logger.error(f"{config_key} not set in configuration")
                raise exceptions.ConfigError(f"{config_key} not set in configuration")
            else:
                if log_level == "info":
                    loguru.logger.info(f"{config_key} not set in configuration, using default {default}")
                elif log_level == "warning":
                    loguru.logger.warning(f"{config_key} not set in configuration")
                return default

    def _get_ip_address(self, config_key):
        try:
            ip_addres = self._settings[config_key]
        except KeyError:
            loguru.logger.warning(f"{config_key} not set in configuration")
            return None
        
        if ":" in ip_addres:
            return self._get_ipv6_address(config_key)
        return self._get_ipv4_address(config_key)
        
    def _get_ipv4_address(self, config_key):
        try:
            ip_address = self._settings[config_key]
        except KeyError:
            loguru.logger.warning(f"{config_key} not set in configuration")
            return None
        
        if not ConfigChecks.check_ipv4_valid(ip_address):
            loguru.logger.error(f"Invalid {config_key} in configuration")
            raise exceptions.ConfigError(f"Invalid {config_key} in configuration")
        
        return ip_address

    def _get_ipv6_address(self, config_key):
        try:
            ipv6_address = self._settings[config_key]
        except KeyError:
            loguru.logger.warning(f"{config_key} not set in configuration")
            return None
        
        if not ConfigChecks.check_ipv6_valid(ipv6_address):
            loguru.logger.error(f"Invalid {config_key} in configuration")
            raise exceptions.ConfigError(f"Invalid {config_key} in configuration")
        
        return ipv6_address

    # Start of getter methods
    def get_tun_address_ipv4(self):
        return self._get_ipv4_address("TUN_ADDRESS_IPV4")
    
    def get_tun_address_ipv6(self):
        return self._get_ipv6_address("TUN_ADDRESS_IPV6")

    def get_mtu(self):
        mtu = self._get_value("MTU", required=True)

        if "IPV6_ADDRESS" in self._settings:
            mtu_check = ConfigChecks.ipv6_mtu
        else:
            mtu_check = ConfigChecks.mtu_valid

        if not mtu_check(mtu):
            loguru.logger.error("Invalid MTU in configuration")
            raise exceptions.ConfigError("Invalid MTU in configuration")
        
        return mtu
    
    def get_encryption_key(self):
        hex_key = self._get_value("ENCRYPTION_KEY", required=True)
        
        if not ConfigChecks.key_valid(hex_key):
            loguru.logger.error("Invalid ENCRYPTION_KEY length in configuration")
            raise exceptions.ConfigError("Invalid ENCRYPTION_KEY length in configuration")
        
        bin_key = bytes.fromhex(hex_key)
        return bin_key
    
    def get_tun_netmask_ipv4(self):
        if self.get_tun_address_ipv4() is None:
            return None
        
        netmask = self._get_value("TUN_NETMASK_IPV4", default=None, log_level="warning")
        if netmask is None:
            return None

        if not ConfigChecks.ipv4_netmask_valid(netmask):
            loguru.logger.error("Invalid TUN_NETMASK_IPV4 in configuration")
            raise exceptions.ConfigError("Invalid TUN_NETMASK_IPV4 in configuration")
        
        return netmask
    
    def get_tun_netmask_ipv6(self):
        if self.get_tun_address_ipv6() is None:
            return None
        
        netmask = self._get_value("TUN_NETMASK_IPV6", default=None, log_level="warning")
        if netmask is None:
            return None

        if not ConfigChecks.ipv6_netmask_valid(netmask):
            loguru.logger.error("Invalid TUN_NETMASK_IPV6 in configuration")
            raise exceptions.ConfigError("Invalid TUN_NETMASK_IPV6 in configuration")
        
        return netmask
    
    def get_peer_address(self):
        if self.get_learn_peer() in ["learn", "dynamic"]:
            loguru.logger.info("PEER_LEARN is enabled, ignoring PEER_ADDRESS value")
            return None
        
        peer_address = self._get_ip_address("PEER_ADDRESS")
        if not peer_address:
            loguru.logger.error("PEER_ADDRESS not set in configuration")
            raise exceptions.ConfigError("PEER_ADDRESS not set in configuration")
        
        return peer_address
    
    def get_listen_address(self):
        listen_address = self._get_ip_address("LISTEN_ADDRESS")
        if not listen_address:
            loguru.logger.error("LISTEN_ADDRESS not set in configuration")
            raise exceptions.ConfigError("LISTEN_ADDRESS not set in configuration")
        
        return listen_address
    
    def get_device_name(self):
        device_name = self._get_value("TUN_DEVICE_NAME", required=True)
        
        if not ConfigChecks.validate_tun_name(device_name):
            loguru.logger.error("Invalid TUN_DEVICE_NAME in configuration")
            raise exceptions.ConfigError("Invalid TUN_DEVICE_NAME in configuration")
        
        return device_name
    
    def get_number_of_duplicates(self):
        num = self._get_value("NUMBER_OF_DUPLICATES", required=True)
        
        if not ConfigChecks.validate_number_of_duplicates(num):
            loguru.logger.error("Invalid NUMBER_OF_DUPLICATES in configuration")
            raise exceptions.ConfigError("Invalid NUMBER_OF_DUPLICATES in configuration")
        
        return num
    
    def get_deduplication_ttl_seconds(self):
        ttl = self._get_value("DEDUPLICATION_TTL_SECONDS", required=True)

        if not ConfigChecks.validate_deduplication_ttl_seconds(ttl):
            loguru.logger.error("Invalid DEDUPLICATION_TTL_SECONDS in configuration")
            raise exceptions.ConfigError("Invalid DEDUPLICATION_TTL_SECONDS in configuration")
        
        return ttl
    
    def get_listen_port(self):       
        listen_port = self._get_value("LISTEN_PORT", required=True)
        
        if not ConfigChecks.check_port_valid(listen_port):
            loguru.logger.error("Invalid LISTEN_PORT in configuration")
            raise exceptions.ConfigError("Invalid LISTEN_PORT in configuration")
        
        return listen_port
    
    def get_peer_port(self):
        if self.get_learn_peer() in ["learn", "dynamic"]:
            loguru.logger.info("PEER_LEARN is enabled, ignoring LISTEN_PORT value")
            return None
        
        peer_port = self._get_value("PEER_PORT", required=True)
        
        if not ConfigChecks.check_port_valid(peer_port):
            loguru.logger.error("Invalid PEER_PORT in configuration")
            raise exceptions.ConfigError("Invalid PEER_PORT in configuration")
        
        return peer_port
    
    def get_log_level(self):
        log_level = self._get_value("LOG_LEVEL", required=True)

        if not ConfigChecks.validate_loguru_log_level(log_level):
            loguru.logger.error("Invalid LOG_LEVEL in configuration")
            raise exceptions.ConfigError("Invalid LOG_LEVEL in configuration")
        
        return log_level
    
    def get_nice_level(self):
        nice_level = self._get_value("NICE_LEVEL", required=True)

        if not ConfigChecks.validate_nice_level(nice_level):
            loguru.logger.error("Invalid NICE_LEVEL in configuration")
            raise exceptions.ConfigError("Invalid NICE_LEVEL in configuration")
        
        return nice_level
       
    def get_learn_peer(self):
        learn_peer = self._get_value("PEER_LEARN", required=True).lower()

        if not ConfigChecks.validate_peer_learn(learn_peer):
            loguru.logger.error("Invalid PEER_LEARN in configuration")
            raise exceptions.ConfigError("Invalid PEER_LEARN in configuration")
        
        return learn_peer
    
    def get_protocol_header(self):
        protocol_header = self._get_value("PROTOCOL_HEADER", default=True, log_level="info")

        if not ConfigChecks.validate_bool(protocol_header):
            loguru.logger.error("PROTOCOL_HEADER must be a boolean (true/false)")
            raise exceptions.ConfigError("PROTOCOL_HEADER must be a boolean (true/false)")
        
        return protocol_header
    
    def get_compression(self):
        compression = self._get_value("COMPRESSION", default=False, log_level="info")

        if not ConfigChecks.validate_bool(compression):
            loguru.logger.error("COMPRESSION must be a boolean (true/false)")
            raise exceptions.ConfigError("COMPRESSION must be a boolean (true/false)")
        
        return compression
    
    def get_default_route(self):
        default_route = self._get_value("DEFAULT_ROUTE", default=False, log_level="info")

        if not ConfigChecks.validate_bool(default_route):
            loguru.logger.error("DEFAULT_ROUTE must be a boolean (true/false)")
            raise exceptions.ConfigError("DEFAULT_ROUTE must be a boolean (true/false)")
        
        return default_route
    
    def get_routes(self):
        try:
            routes = self._settings["ROUTES"]
        except KeyError:
            loguru.logger.info("ROUTES not set in configuration, no routes to add")
            return []
        
        if not isinstance(routes, list):
            loguru.logger.error("ROUTES must be a list in configuration")
            raise exceptions.ConfigError("ROUTES must be a list in configuration")
        
        for route in routes:
            if not ConfigChecks.ip_cidr_valid(route):
                loguru.logger.error(f"Invalid route {route} in ROUTES configuration")
                raise exceptions.ConfigError(f"Invalid route {route} in ROUTES configuration")
        
        return routes
    
    def get_add_routes_peer_ipv4(self):
        peer_tun_ipv4 = self._get_value("ADD_ROUTES_PEER_IPV4", default=None, log_level="info")
        if not peer_tun_ipv4 and len(self.get_routes()) == 0 and not self.get_default_route():
            return None

        if not ConfigChecks.check_ipv4_valid(peer_tun_ipv4):
            loguru.logger.error("ADD_ROUTES_PEER_IPV4 must be a valid IPv4 address")
            raise exceptions.ConfigError("ADD_ROUTES_PEER_IPV4 must be a valid IPv4 address")
        
        return peer_tun_ipv4
    
    def get_add_routes_peer_ipv6(self):
        peer_tun_ipv6 = self._get_value("ADD_ROUTES_PEER_IPV6", default=None, log_level="info")
        if not peer_tun_ipv6 and len(self.get_routes()) == 0 and not self.get_default_route():
            return None

        if not ConfigChecks.check_ipv6_valid(peer_tun_ipv6):
            loguru.logger.error("ADD_ROUTES_PEER_IPV6 must be a valid IPv6 address")
            raise exceptions.ConfigError("ADD_ROUTES_PEER_IPV6 must be a valid IPv6 address")
        
        return peer_tun_ipv6

    def get_vpn_data_max_size_split(self):
        max_size = self._get_value("VPN_DATA_MAX_SIZE_SPLIT", default=0, log_level="info")

        if not ConfigChecks.validate_vpn_data_max_size_split(max_size):
            loguru.logger.error("Invalid VPN_DATA_MAX_SIZE_SPLIT in configuration")
            raise exceptions.ConfigError("Invalid VPN_DATA_MAX_SIZE_SPLIT in configuration")
        
        return max_size