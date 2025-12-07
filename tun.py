import os
import fcntl
import struct
import os
import sh
import loguru
import time

import const
import config

class Tun():
    def __init__(self):
        self._device = config.Config().get_device_name()
        self._mtu = config.Config().get_mtu()
        self._ip_address = config.Config().get_tun_address_ipv4()
        self._netmask = config.Config().get_tun_netmask_ipv4()
        self._ipv6_address = config.Config().get_tun_address_ipv6()
        self._ipv6_netmask = config.Config().get_tun_netmask_ipv6()
        self._tun = self._tun_open(self._device)

        self._configure_tun_interface()

    def _configure_tun_interface(self):
        loguru.logger.info(f"Configuring TUN interface {self._device} with MTU {self._mtu}")

        # Device already created by _tun_open(), just configure it
        sh.ip('link', 'set', 'dev', self._device, 'up')
        sh.ip('link', 'set', 'dev', self._device, 'mtu', str(self._mtu))
        if self._ip_address and self._netmask:
            sh.ip('addr', 'add', 'dev', self._device, f'{self._ip_address}/{self._netmask}')
        if self._ipv6_address and self._ipv6_netmask:
            sh.ip('-6', 'addr', 'add', 'dev', self._device, f'{self._ipv6_address}/{self._ipv6_netmask}')

    def _tun_open(self, device):
        loguru.logger.debug(f"Opening TUN device {device}")
        # Open the TUN device file in non-blocking mode
        tun = os.open('/dev/net/tun', os.O_RDWR | os.O_NONBLOCK)

        # Prepare the ifreq structure
        ifr = struct.pack('16sH', device.encode('utf-8'), const.LINUX_IFF_TUN | const.LINUX_IFF_NO_PI)

        # Issue the ioctl to create the TUN device
        fcntl.ioctl(tun, const.LINUX_TUNSETIFF, ifr)

        return os.fdopen(tun, 'r+b', 0)  # 0 = unbuffered
    
    def tun_read(self):
        try:
            data = self._tun.read(self._mtu)
            if data:
                loguru.logger.debug(f"Read {len(data)} bytes from TUN device")
            return data
        except BlockingIOError:
            # No data available in non-blocking mode
            loguru.logger.debug("No data available (EAGAIN)")
            return None
        except OSError as e:
            if e.errno == 11:  # EAGAIN
                loguru.logger.debug("No data available (EAGAIN)")
                return None
            raise
    
    def tun_write(self, data):
        loguru.logger.debug(f"Writing {len(data)} bytes to TUN device")
        return self._tun.write(data)
    
    def _close(self):
        loguru.logger.debug("Closing TUN device")
        self._tun.close()

        loguru.logger.info(f"Deleting TUN interface {self._device}")
        sh.ip('link', 'set', 'dev', self._device, 'down')
        sh.ip('tuntap', 'del', 'dev', self._device, 'mode', 'tun')
