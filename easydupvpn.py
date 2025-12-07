#! /usr/bin/env python3

import sys
import loguru
import select
import psutil

import communication
import config
import tun


class MainWorker:
    def __init__(self):
        self.communication_i = communication.Communication()
        self.tun_i = tun.Tun()
        
    def run(self):   
        tun_fd = self.tun_i.fileno()
        comm_fd = self.communication_i.fileno()

        while True:
            selectable, _, _ = select.select([tun_fd, comm_fd], [], [])

            if tun_fd in selectable:
                data = self.tun_i.tun_read()
                if data:
                    loguru.logger.debug(f"Data from TUN: {data}")
                    loguru.logger.debug(f"Sending packet of length {len(data)} from TUN to UDP")
                    self.communication_i.send_packet(data)

            if comm_fd in selectable:
                data = self.communication_i.receive_packet()
                if data:
                    loguru.logger.debug(f"Data from UDP: {data}")
                    loguru.logger.debug(f"Writing packet of length {len(data)} from UDP to TUN")
                    self.tun_i.tun_write(data)

def nice_process(nice_level):
    try:
        p = psutil.Process()
        p.nice(nice_level)
        loguru.logger.info(f"Set process nice level to {nice_level}")
    except Exception as e:
        loguru.logger.warning(f"Failed to set process nice level: {e}")

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

    nice_level = config.Config().get_nice_level()
    nice_process(nice_level)
    
    MainWorker().run()

if __name__ == "__main__":
    main()
