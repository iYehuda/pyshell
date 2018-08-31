#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging

from os import getenv
from socket import socket, error as socket_error
from subprocess import Popen

DEFAULT_PORT = 8022

log = logging.getLogger(__name__)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')


def add_log_handler(log_handler):
    log_handler.setFormatter(formatter)
    log.addHandler(log_handler)
    log.setLevel(log.getEffectiveLevel())


def setup_logger():
    log_level = getenv('LOG_LEVEL', 'INFO')
    
    if log_level:
        log.setLevel(logging.getLevelName(log_level))
    
    log_file = getenv('LOG_FILE')

    if log_file:
        handler = logging.FileHandler(log_file, encoding='utf-8')
        handler.setLevel(log_level)
        add_log_handler(handler)

    add_log_handler(logging.StreamHandler())


def handle_client(client_socket):
    log.info('starting a shell')

    try:
        process = Popen('/bin/bash -i',
                        shell=True,
                        stdin=client_socket,
                        stdout=client_socket,
                        stderr=client_socket)
        log.info('waiting for process to end')
        log.info('process ended with exit code %d', process.wait())
    except Exception as error:
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
