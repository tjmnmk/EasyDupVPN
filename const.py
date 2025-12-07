LINUX_TUNSETIFF = 0x400454ca
LINUX_IFF_TUN = 0x0001
LINUX_IFF_NO_PI = 0x1000

LINUX_MAX_TUN_NAME_LEN = 15

TUN_NAME_ALLOWED_REGEX = r'^[a-zA-Z0-9._-]{1,15}$' # Allowed characters for TUN device names, others characters may be allowed by kernel, but this is a safe subset
KEY_LENGTH_HEX = 64 # 32 bytes in hex representation

RAWUDPVPN_HEADER_START = b'RUV'
"""
SECRET_BOX_HEADER_SIZE = 40 # size of nacl.secret.SecretBox overhead
RAWUDPVPN_HEADER_SIZE = len(RAWUDPVPN_HEADER_START) + 16 # 3 bytes for 'RUV' + 16 bytes for deduplication nonce
UDP_HEADER_SIZE = 8 # standard UDP header size
IP_HEADER_SIZE = 40 # standard IPv6 header size
DEFAULT_TUN_MTU = 1500 - SECRET_BOX_HEADER_SIZE - RAWUDPVPN_HEADER_SIZE - UDP_HEADER_SIZE - IP_HEADER_SIZE - 100 # 100 bytes of safety margin
"""

CONFIG_KNOWN_VALUES = (
    "TUN_ADDRESS_IPV4",
    "TUN_NETMASK_IPV4",
    "TUN_ADDRESS_IPV6",
    "TUN_NETMASK_IPV6",
    "PEER_ADDRESS",
    "PEER_PORT",
    "PEER_LEARN",
    "LISTEN_ADDRESS",
    "LISTEN_PORT",
    "TUN_DEVICE_NAME",
    "MTU",
    "ENCRYPTION_KEY",
    "DEDUPLICATION_TTL_SECONDS",
    "NUMBER_OF_DUPLICATES",
    "LOG_LEVEL",
    "NICE_LEVEL",
    "PROTOCOL_HEADER",
    "COMPRESSION",
    "DEFAULT_ROUTE",
    "ADD_ROUTES",
    "ADD_ROUTES_PEER_IPV4",
    "ADD_ROUTES_PEER_IPV6",
    "PACKET_SPLIT_PARTS",
    "VPN_DATA_MAX_SIZE_SPLIT",
    "SEND_EXTRA_DELAYED_PACKET_AFTER",
)
CONFIG_COMMENTS_PREFIXES = "_comment_"
