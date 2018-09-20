#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging

from os import dup, fdopen, getenv, name as os_name
from os.path import expanduser
from socket import socket, error as socket_error, timeout as socket_timeout
from subprocess import Popen, PIPE, STDOUT

DEFAULT_PORT = 8022
HOME_DIRECTORY = expanduser('~')
IS_WINDOWS = os_name == 'nt'

if IS_WINDOWS:
    SHELL_COMMAND = 'cmd'
else:
    SHELL_COMMAND = ['bash', '-i']

log = logging.getLogger(__name__)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')


def add_log_handler(log_handler):
    log_handler.setFormatter(formatter)
    log.addHandler(log_handler)
    log.setLevel(log.getEffectiveLevel())


def setup_logger():
    log_level = getenv('LOG_LEVEL', 'INFO')
    log.setLevel(logging.getLevelName(log_level))
    log_file = getenv('LOG_FILE')
    add_log_handler(logging.StreamHandler())

    if log_file:
        handler = logging.FileHandler(log_file, encoding='utf-8')
        handler.setLevel(log_level)
        add_log_handler(handler)


def attach_process_unix(client_socket):
    return Popen(SHELL_COMMAND,
                 cwd=HOME_DIRECTORY,
                 stdin=client_socket,
                 stdout=client_socket,
                 stderr=client_socket).wait()


def attach_process_windows(client_socket):
    import Queue
    import threading

    def output_reader(exit_event, source, destination, output_queue):
        while not exit_event.is_set():
            try:
                received = source.read(2048)

                if received:
                    output_queue.put((destination, received))
            except socket_timeout:
                pass
            except (socket_error, OSError, IOError) as e:
                log.exception('read', exc_info=e)
                exit_event.set()

    event = threading.Event()
    data_queue = Queue.Queue()
    process = Popen(SHELL_COMMAND,
                    cwd=HOME_DIRECTORY,
                    stdin=PIPE,
                    stdout=PIPE,
                    stderr=STDOUT,
                    universal_newlines=True)

    client_input = fdopen(dup(client_socket.fileno()), "rb", 65536)
    client_output = fdopen(dup(client_socket.fileno()), "wb", 65536)
    socket_reader = threading.Thread(target=output_reader, args=(event, client_input, process.stdin, data_queue))
    process_reader = threading.Thread(target=output_reader, args=(event, process.stdout, client_output, data_queue))

    socket_reader.start()
    process_reader.start()

    while not event.is_set():
        try:
            io, data = data_queue.get(block=False)
            io.write(data + '\n')
        except Queue.Empty:
            break
        except (socket_error, IOError) as write_error:
            log.exception('write', exc_info=write_error)
            event.set()

    process.terminate()
    client_input.close()
    client_output.close()
    socket_reader.join()
    process_reader.join()

    return process.wait()


def handle_client(client_socket):
    log.info('starting a shell')

    attach_process = attach_process_windows if IS_WINDOWS else attach_process_unix

    try:
        log.info('process ended with exit code %d', attach_process(client_socket))
    except (OSError, ValueError) as error:
        log.exception('error during remote shell process', exc_info=error)


def main(bind_address, bind_port):
    log.info('starting server at %s:%d', bind_address, bind_port)
    server_socket = socket()

    try:
        server_socket.bind((bind_address, bind_port))
        server_socket.listen(1)
    except socket_error as error:
        log.fatal('failed to bind and listen: %s', error)
        exit(1)
    log.info('started listening')

    while True:
        log.info('waiting for connection')

        try:
            client_socket, client_address = server_socket.accept()
        except socket_error as error:
            log.error('failed to accept a connection: %s', error)
            break
        except KeyboardInterrupt:
            log.info('exiting gracefully')
            break

        log.info('received a connection from %s:%d', client_address[0], client_address[1])
        handle_client(client_socket)
        log.info('closing connection')

        try:
            client_socket.close()
        except socket_error as error:
            log.exception('error during closing connection', exc_info=error)


if __name__ == '__main__':
    silent_mode = getenv('SILENT')

    if not silent_mode:
        setup_logger()
    else:
        log.addHandler(logging.NullHandler())

    address = getenv('ADDRESS', '0.0.0.0')
    port = getenv('PORT', DEFAULT_PORT)

    try:
        port = int(port)

        if not 0 < port < 65536:
            raise ValueError('port number must be between 0 and 65535')
    except ValueError as port_error:
        log.warning('invalid port number: %s, using default port %d', port_error, DEFAULT_PORT)
        port = DEFAULT_PORT

    main(address, port)
