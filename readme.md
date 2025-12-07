# EasyDupVPN

A simple UDP-based VPN that sends multiple copies of each packet to improve reliability on lossy networks.

## Features

- **Packet Duplication**: Sends configurable number of duplicate packets to combat packet loss
- **Automatic Deduplication**: Removes duplicate packets on the receiving end using nonce-based tracking
- **Encryption**: Uses NaCl (libsodium) for authenticated encryption
- **IPv4 & IPv6 Support**: Configure both IPv4 and IPv6 addresses on the TUN interface
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
| `PEER_ADDRESS` | IP address of the remote peer |
| `PEER_PORT` | UDP port of the remote peer |
| `LISTEN_ADDRESS` | Local IP address to bind to (use `0.0.0.0` for all interfaces) |
| `LISTEN_PORT` | Local UDP port to listen on |
| `TUN_DEVICE_NAME` | Name of the TUN interface (max 15 characters) |
| `MTU` | MTU of the TUN interface (recommended: 220 bytes less than network MTU) |
| `ENCRYPTION_KEY` | 64-character hex-encoded encryption key |
| `NUMBER_OF_DUPLICATES` | Number of copies to send for each packet (1-50) |
| `DEDUPLICATION_TTL_SECONDS` | How long to remember seen packets for deduplication |

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

**Server (192.168.1.1):**
```json
{
  "TUN_ADDRESS_IPV4": "10.0.0.1",
  "TUN_NETMASK_IPV4": 24,
  "PEER_ADDRESS": "192.168.1.2",
  "PEER_PORT": 8111,
  "LISTEN_ADDRESS": "0.0.0.0",
  "LISTEN_PORT": 8111,
  "TUN_DEVICE_NAME": "tun-edv0",
  "MTU": 1280,
  "ENCRYPTION_KEY": "<same-key-on-both-sides>",
  "NUMBER_OF_DUPLICATES": 3
}
```

**Client (192.168.1.2):**
```json
{
  "TUN_ADDRESS_IPV4": "10.0.0.2",
  "TUN_NETMASK_IPV4": 24,
  "PEER_ADDRESS": "192.168.1.1",
  "PEER_PORT": 8111,
  "LISTEN_ADDRESS": "0.0.0.0",
  "LISTEN_PORT": 8111,
  "TUN_DEVICE_NAME": "tun-edv0",
  "MTU": 1280,
  "ENCRYPTION_KEY": "<same-key-on-both-sides>",
  "NUMBER_OF_DUPLICATES": 3
}
```

## How It Works

1. Packets entering the TUN interface are encrypted using NaCl SecretBox
2. A random 16-byte nonce is prepended for deduplication
3. The packet is sent `NUMBER_OF_DUPLICATES` times over UDP
4. On the receiving end, duplicate packets are detected and discarded using the nonce
5. The decrypted packet is written to the TUN interface

## License

See [LICENSE](LICENSE) file.