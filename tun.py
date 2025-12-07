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
        
        self._baked_route_removes = []

        self._configure_tun_interface()
        if config.Config().get_default_route():
            self._add_default_route()
        self._add_routes(config.Config().get_routes())

    def _add_routes(self, routes):
        peer4 = config.Config().get_add_routes_peer_ipv4()
        peer6 = config.Config().get_add_routes_peer_ipv6()
        for route in routes:
            loguru.logger.info(f"Adding route {route} via TUN interface {self._device}")
            if ':' in route:
                # IPv6 route
                try:
                    sh.ip('-6', 'route', 'add', route, 'via', peer6, 'dev', self._device)
                    remove_cmd = sh.ip.bake('-6', 'route', 'del', route, 'via', peer6, 'dev', self._device)
                    self._baked_route_removes.append(remove_cmd)
                except sh.ErrorReturnCode as e:
                    if e.exit_code != 2: # if err == 2 then route already exists
                        loguru.logger.error(f"Failed to add IPv6 route {route}: {e}")
            else:
                # IPv4 route
                try:
                    sh.ip('route', 'add', route, 'via', peer4, 'dev', self._device)
                    remove_cmd = sh.ip.bake('route', 'del', route, 'via', peer4, 'dev', self._device)
                    self._baked_route_removes.append(remove_cmd)
                except sh.ErrorReturnCode as e:
                    if e.exit_code != 2: # if err == 2 then route already exists
                        loguru.logger.error(f"Failed to add IPv4 route {route}: {e}")

    def _add_default_route(self):
        # keep peer route
        peer_ip = config.Config().get_peer_address()
        peer_gw = self._linux_get_route_for_destination(peer_ip)
        if peer_gw is None:
            loguru.logger.error(f"Cannot determine gateway for peer {peer_ip}, not adding default route")
            return
        if peer_gw != "skip":
            try:
                sh.ip('route', 'add', peer_ip, 'via', peer_gw)
                remove_cmd = sh.ip.bake('route', 'del', peer_ip, 'via', peer_gw)
                self._baked_route_removes.append(remove_cmd)
            except sh.ErrorReturnCode as e:
                # if err == 2 then route already exists
                if e.exit_code != 2:
                    loguru.logger.error(f"Failed to add route to peer {peer_ip} via {peer_gw}: {e}")

        loguru.logger.info(f"Adding default route via TUN interface {self._device}")
        
        routes = ("0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1")
        self._add_routes(routes)

    def _linux_get_route_for_destination(self, destination_ip):
        try:
            output = sh.ip('route', 'get', destination_ip)
        except sh.ErrorReturnCode as e:
            loguru.logger.error(f"Failed to get route for {destination_ip}: {e}")
            return None
        
        if output.find("via") == -1:
            loguru.logger.info(f"No route found for {destination_ip}, probably local network, skipping adding peer route")
            return "skip"
        
        parts = output.split()
        via_index = parts.index("via")
        gateway_ip = parts[via_index + 1]

        return gateway_ip

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
        try:
            return self._tun.write(data)
        except BlockingIOError:
            loguru.logger.debug("No space available to write (EAGAIN), data not written")
            return None
        except OSError as e:
            if e.errno == 22:  # EINVAL
                loguru.logger.error("Invalid data provided to TUN device (EINVAL), data not written, is compression enabled on both sides?")
                return None
            loguru.logger.error(f"Error writing to TUN device: {e}")
            return None
    
    def close(self):
        loguru.logger.info("Cleaning up TUN device and routes...")
        for cmd in self._baked_route_removes:
            try:
                cmd()
            except sh.ErrorReturnCode as e:
                loguru.logger.debug(f"Failed to remove route during cleanup: {e}")

        loguru.logger.debug("Closing TUN device")
        try:
            self._tun.close()
        except Exception as e:
            loguru.logger.debug(f"Error closing TUN device: {e}")

        loguru.logger.info(f"Deleting TUN interface {self._device}")
        try:
            sh.ip('link', 'set', 'dev', self._device, 'down')
        except sh.ErrorReturnCode as e:
            loguru.logger.debug(f"Failed to bring down TUN interface {self._device}tr: {e}")
        try:
            sh.ip('tuntap', 'del', 'dev', self._device, 'mode', 'tun')
        except sh.ErrorReturnCode as e:
            loguru.logger.debug(f"Failed to delete TUN interface {self._device}: {e}")  

    def fileno(self):
        return self._tun.fileno()
