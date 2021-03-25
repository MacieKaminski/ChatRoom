#!/usr/bin/env python3

import threading
import socket
import argparse
import os
import syslog


class Server(threading.Thread):
    def __init__(self, host, port):
        super().__init__()
        self.connections = []
        self.host = host
        self.port = port
    
    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # listening socket
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # we will bind to previously used socket
        sock.bind((self.host, self.port))

        sock.listen(1)
        print('Listening at', sock.getsockname())
        syslog.syslog(syslog.LOG_INFO, 'Listening at' + str(sock.getsockname()))

        while True:

            # Accept new connection
            sc, sockname = sock.accept()
            print('Accepted a new connection from {} to {}'.format(sc.getpeername(), sc.getsockname()))
            syslog.syslog(syslog.LOG_INFO, 'Accepted a new connection from {} to {}'.format(sc.getpeername(), sc.getsockname()))

            # Create new thread
            server_socket = ServerSocket(sc, sockname, self)
            
            # Make the thread daemon so it ends whenever the main thread ends
            server_socket.daemon = True
            
            # Start new thread
            server_socket.start()

            # Add thread to active connections
            self.connections.append(server_socket)
            print('Ready to receive messages from', sc.getpeername())
            syslog.syslog(syslog.LOG_NOTICE, 'Ready to receive messages from' + str(sc.getpeername()))

    def broadcast(self, message, source):
        for connection in self.connections:  # sending messages to all clients except sending one

            # Send to all connected clients except the source client
            if connection.sockname != source:
                connection.send(message)
    
    def remove_connection(self, connection):
        self.connections.remove(connection)


class ServerSocket(threading.Thread):
    def __init__(self, sc, sockname, server):
        super().__init__()
        self.sc = sc
        self.sockname = sockname
        self.server = server
    
    def run(self):
        # receiving data from clients and sending it to all other clients
        while True:
            message = self.sc.recv(1024).decode('ascii')
            if message:
                print('{} says {!r}'.format(self.sockname, message))
                syslog.syslog(syslog.LOG_NOTICE, '{} says {!r}'.format(self.sockname, message))
                self.server.broadcast(message, self.sockname)
            else:
                # Client has closed the socket, exit the thread
                print('{} has closed the connection'.format(self.sockname))
                syslog.syslog(syslog.LOG_NOTICE, '{} has closed the connection'.format(self.sockname))
                self.sc.close()
                server.remove_connection(self)
                return
    
    def send(self, message):
        self.sc.sendall(message.encode('ascii'))  # sending message to server


def exit(server):
    # typing "q" in the command line closes all connections and exit
    while True:
        ipt = input('')
        if ipt == 'q':
            print('All connections closed.')
            syslog.syslog(syslog.LOG_INFO, 'All connections closed.')
            for connection in server.connections:
                connection.sc.close()
            print('Server shut down.')
            syslog.syslog(syslog.LOG_INFO, 'Server shut down.')
            os._exit(0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Chatroom Server')
    parser.add_argument('host', help='Interface the server listens at')
    parser.add_argument('-p', metavar='PORT', type=int, default=1060,
                        help='TCP port (default 1060)')
    args = parser.parse_args()

    # Create and start server thread
    server = Server(args.host, args.p)
    server.start()

    exit = threading.Thread(target=exit, args=(server,))
    exit.start()