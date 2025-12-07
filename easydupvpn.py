#! /usr/bin/env python3

import sys
import select
import loguru

import communication
import config
import tun


class MainWorker:
    def __init__(self):
        self.communication_i = communication.Communication()
        self.tun_i = tun.Tun()
        
    def run(self):
        # File descriptors to watch for reading
        read_fds = [self.tun_i, self.communication_i]
        
        while True:
            # Wait for data on either TUN or UDP (timeout 1 second for safety)
            readable, _, _ = select.select(read_fds, [], [], 1.0)
            
            for fd in readable:
                if fd is self.tun_i:
                    data = self.tun_i.tun_read()
                    if data:
                        loguru.logger.debug(f"Data from TUN: {data}")
                        loguru.logger.debug(f"Sending packet of length {len(data)} from TUN to UDP")
                        self.communication_i.send_packet(data)
                
                elif fd is self.communication_i:
                    data = self.communication_i.receive_packet()
                    if data:
                        loguru.logger.debug(f"Data from UDP: {data}")
                        loguru.logger.debug(f"Writing packet of length {len(data)} from UDP to TUN")
                        self.tun_i.tun_write(data)

def main():
    try:
        config_file = sys.argv[1]
    except IndexError:
        loguru.logger.error("Configuration file path not provided")
        sys.exit(1)

    config.Config().load_from_file(config_file)
    # Set log level
    log_level = config.Config().get_log_level()
    loguru.logger.remove()
    loguru.logger.add(sys.stderr, level=log_level)
    MainWorker().run()

if __name__ == "__main__":
    main()
