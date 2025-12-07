import sys
import loguru
import time

import communication
import config
import tun


class MainWorker:
    def __init__(self):
        communication = communication.Communication()
        tun = tun.Tun()

    def run(self):
        continue_fast = True
        while True:
            if not continue_fast:
                time.sleep(0.0001) # 100 us
            continue_fast = False

            data = tun.tun_read()
            if data:
                continue_fast = True
                communication.send_data(data)

            data = communication.receive_data()
            if data:
                continue_fast = True
                tun.tun_write(data)

def main():
    try:
        config_file = sys.argv[1]
    except IndexError:
        loguru.logger.error("Configuration file path not provided")
        sys.exit(1)

    MainWorker().run()

if __name__ == "__main__":
    main()
