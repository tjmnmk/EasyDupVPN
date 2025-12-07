# EasyDupVPN

A simple UDP-based VPN that sends multiple copies of each packet to improve reliability on lossy networks.

## Features

- **Packet Duplication**: Sends configurable number of duplicate packets to combat packet loss
- **Automatic Deduplication**: Removes duplicate packets on the receiving end using nonce-based tracking
- **Encryption**: Uses NaCl (libsodium) for authenticated encryption
- **Compression**: Optional zlib compression to reduce bandwidth usage
- **IPv4 & IPv6 Support**: Configure both IPv4 and IPv6 addresses on the TUN interface
- **NAT Support**: Dynamic peer address learning for clients behind NAT
- **Low Overhead**: Efficient event-driven architecture using `select()`

## Use Cases

- Unstable mobile/wireless connections
- Networks with high packet loss
- Redundant paths where reliability is more important than bandwidth

## Requirements

- Linux (uses TUN interface)
- Python 3.x
- Root privileges (for TUN interface creation)

## Installation

### Arch Linux

```bash
sudo pacman -S python python-loguru python-sh python-pynacl python-psutil
```

### Debian / Ubuntu

```bash
sudo apt install python3 python3-pip
pip install -r requirements.txt
```

Or install system packages (may be older versions):
```bash
sudo apt install python3 python3-loguru python3-sh python3-nacl python3-psutil
```

### Using pip (any distro)

```bash
pip install -r requirements.txt
```

## Configuration

Copy the example configuration file and edit it:

```bash
cp config.example.json config.json
```

### Configuration Options

| Option | Description |
|--------|-------------|
| `TUN_ADDRESS_IPV4` | IPv4 address for the TUN interface |
| `TUN_NETMASK_IPV4` | IPv4 netmask (CIDR notation, e.g., 24) |
| `TUN_ADDRESS_IPV6` | IPv6 address for the TUN interface (optional) |
| `TUN_NETMASK_IPV6` | IPv6 netmask (CIDR notation, e.g., 64) |
| `PEER_ADDRESS` | IP address of the remote peer (ignored if `PEER_LEARN` is enabled) |
| `PEER_PORT` | UDP port of the remote peer (ignored if `PEER_LEARN` is enabled) |
| `PEER_LEARN` | Peer address learning mode: `off`, `learn`, or `dynamic` (see below) |
| `LISTEN_ADDRESS` | Local IP address to bind to (use `0.0.0.0` for all interfaces) |
| `LISTEN_PORT` | Local UDP port to listen on |
| `TUN_DEVICE_NAME` | Name of the TUN interface (max 15 characters) |
| `MTU` | MTU of the TUN interface (recommended: 220 bytes less than network MTU) |
| `ENCRYPTION_KEY` | 64-character hex-encoded encryption key |
| `NUMBER_OF_DUPLICATES` | Number of copies to send for each packet (1-50) |
| `DEDUPLICATION_TTL_SECONDS` | How long to remember seen packets for deduplication (default: 60) |
| `LOG_LEVEL` | Logging verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR` (default: `INFO`) |
| `NICE_LEVEL` | Process priority (-20 to 19, lower = higher priority, default: 0) |
| `PROTOCOL_HEADER` | Add protocol identifier to packets (default: `true`). Set to `false` to make traffic harder to identify as VPN |
| `COMPRESSION` | Enable zlib compression (default: `false`). Both peers must use the same setting |

### PEER_LEARN Modes

| Mode | Description |
|------|-------------|
| `off` | Static peer address - uses `PEER_ADDRESS` and `PEER_PORT` settings |
| `learn` | Learn peer address from first valid incoming packet (useful for NAT) |
| `dynamic` | Re-learn peer address from each incoming packet (for roaming/dynamic IP) |

### NAT Configuration

If one peer is behind NAT, use `PEER_LEARN` on the server (public IP) side:

- **Server** (public IP): Set `PEER_LEARN: "learn"` - will accept connection from any address
- **Client** (behind NAT): Set `PEER_LEARN: "off"` with server's public IP in `PEER_ADDRESS`

The client initiates the connection, and the server learns the client's NATed address from the first valid (authenticated) packet.

### Generate Encryption Key

```bash
sudo ./easydupvpn-genkey
```

This will output a secure 256-bit random key in hexadecimal format.

## Usage

Run with root privileges:

```bash
sudo python3 easydupvpn.py config.json
```

### Example Setup

**Server (192.168.1.1 - public IP):**
```json
{
  "TUN_ADDRESS_IPV4": "10.0.0.1",
  "TUN_NETMASK_IPV4": 24,
  "PEER_LEARN": "learn",
  "LISTEN_ADDRESS": "0.0.0.0",
  "LISTEN_PORT": 8111,
  "TUN_DEVICE_NAME": "tun-edv0",
  "MTU": 1280,
  "ENCRYPTION_KEY": "<same-key-on-both-sides>",
  "NUMBER_OF_DUPLICATES": 3,
  "DEDUPLICATION_TTL_SECONDS": 60,
  "LOG_LEVEL": "INFO",
  "NICE_LEVEL": -10,
  "PROTOCOL_HEADER": true,
  "COMPRESSION": false
}
```

**Client (behind NAT):**
```json
{
  "TUN_ADDRESS_IPV4": "10.0.0.2",
  "TUN_NETMASK_IPV4": 24,
  "PEER_ADDRESS": "192.168.1.1",
  "PEER_PORT": 8111,
  "PEER_LEARN": "off",
  "LISTEN_ADDRESS": "0.0.0.0",
  "LISTEN_PORT": 8111,
  "TUN_DEVICE_NAME": "tun-edv0",
  "MTU": 1280,
  "ENCRYPTION_KEY": "<same-key-on-both-sides>",
  "NUMBER_OF_DUPLICATES": 3,
  "DEDUPLICATION_TTL_SECONDS": 60,
  "LOG_LEVEL": "INFO",
  "NICE_LEVEL": -10,
  "PROTOCOL_HEADER": true,
  "COMPRESSION": false
}
```

## How It Works

1. Packets entering the TUN interface are optionally compressed (if `COMPRESSION` is enabled)
2. Compressed/raw data is encrypted using NaCl SecretBox
3. A random 16-byte nonce is prepended for deduplication
4. The packet is sent `NUMBER_OF_DUPLICATES` times over UDP
5. On the receiving end, duplicate packets are detected and discarded using the nonce
6. The decrypted packet is decompressed (if compression enabled) and written to the TUN interface

## Running as a Service

A systemd service file is included for running EasyDupVPN as a system service.

### Installation

```bash
# Copy files to system directories
sudo mkdir -p /opt/easydupvpn
sudo cp *.py /opt/easydupvpn/
sudo mkdir -p /etc/easydupvpn
sudo cp config.json /etc/easydupvpn/

# Install and enable service
sudo cp easydupvpn.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable easydupvpn
sudo systemctl start easydupvpn
```

### Managing the Service

```bash
# Check status
sudo systemctl status easydupvpn

# View logs
sudo journalctl -u easydupvpn -f

# Restart after config changes
sudo systemctl restart easydupvpn
```

## License

See [LICENSE](LICENSE) file.