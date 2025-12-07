#! /usr/bin/env python3

import sys
import loguru
import select
import psutil
import os
import traceback

import communication
import config
import tun


class MainWorker:
    def __init__(self):
        self.communication_i = communication.Communication()
        self.tun_i = tun.Tun()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Called automatically when leaving 'with' block"""
        loguru.logger.info("Cleaning up...")
        try:
            self.tun_i.close()
        except Exception as e:
            loguru.logger.error(f"Error during cleanup: {e}")
        try:
            exit_command = config.Config().get_run_command_on_exit()
            if exit_command:
                loguru.logger.info(f"Running exit command: {exit_command}")
                ret_code = os.system(exit_command)
                if ret_code != 0:
                    loguru.logger.error(f"Exit command exited with code {ret_code}")
                else:
                    loguru.logger.info(f"Exit command exited with code {ret_code}")
        except Exception as e:
            loguru.logger.error(f"Error running exit command: {e}")
        return False
        
    def run(self):   
        tun_fd = self.tun_i.fileno()
        comm_fd = self.communication_i.fileno()

        # Run command after TUN is ready
        setup_command = config.Config().get_run_command_after_tun_ready()
        if setup_command:
            loguru.logger.info(f"Running setup command: {setup_command}")
            ret_code = os.system(setup_command)
            if ret_code != 0:
                loguru.logger.error(f"Setup command exited with code {ret_code}")
            else:
                loguru.logger.info(f"Setup command exited with code {ret_code}")

        while True:
            # Use 0.1 second (100ms) timeout to allow delayed packet checking
            selectable, _, _ = select.select([tun_fd, comm_fd], [], [], 0.1)
            
            # Always check for delayed packets to send
            self.communication_i.check_delayed_packets()
            self.communication_i.keepalive_ping()

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
    
    with MainWorker() as worker:
        worker.run()

if __name__ == "__main__":
    try:
        main()
    # Catch keyboard interrupt to allow graceful exit
    except KeyboardInterrupt:
        loguru.logger.info("Received keyboard interrupt, exiting...")
        sys.exit(0)
    # Catch sigterm
    except SystemExit:
        loguru.logger.info("Received termination signal, exiting...")
        sys.exit(0)
    except Exception as e:
        loguru.logger.exception(f"Unhandled exception in main: {e}")
        raise