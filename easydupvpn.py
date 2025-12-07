#! /usr/bin/env python3

import sys
import loguru
import time

import communication
import config
import tun


class MainWorker:
    def __init__(self):
        self.communication_i = communication.Communication()
        self.tun_i = tun.Tun()
        
    def run(self):   
        continue_fast = True
        while True:
            if not continue_fast:
                time.sleep(0.0001) # 100 us
            continue_fast = False

            data = self.tun_i.tun_read()
            if data:
                continue_fast = True
                self.communication_i.send_packet(data)

            data = self.communication_i.receive_packet()
            if data:
                continue_fast = True
                self.tun_i.tun_write(data)

def main():
    try:
        config_file = sys.argv[1]
    except IndexError:
        loguru.logger.error("Configuration file path not provided")
        sys.exit(1)

    config.Config().load_from_file(config_file)
    MainWorker().run()

if __name__ == "__main__":
    main()
