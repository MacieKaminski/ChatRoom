#!/usr/bin/env python3

import threading
import socket
import argparse
import os
import sys
import tkinter as tk
import syslog


# thread listening for user input from command line and sending data to server
class Send(threading.Thread):
    def __init__(self, sock, name):
        super().__init__()
        self.sock = sock
        self.name = name

    def run(self):
        while True:
            print('{}: '.format(self.name), end='') 
            syslog.syslog(syslog.LOG_NOTICE, '{}: '.format(self.name), end='')
            sys.stdout.flush()
            message = sys.stdin.readline()[:-1]

            # type 'QUIT' to leave the chatroom
            if message == 'QUIT':
                self.sock.sendall('Server: {} has left the chat.'.format(self.name).encode('ascii'))
                break
            
            # send message to server for broadcasting
            else:
                self.sock.sendall('{}: {}'.format(self.name, message).encode('ascii'))
        
        print('\nProgram closed')
        syslog.syslog(syslog.LOG_INFO, '\nProgram closed')
        self.sock.close()
        os._exit(0)


# thread listening for incoming messages from server
class Receive(threading.Thread):
    def __init__(self, sock, name):
        super().__init__()
        self.sock = sock
        self.name = name
        self.messages = None

    def run(self):
        while True:
            message = self.sock.recv(1024).decode('ascii')

            if message:

                if self.messages:
                    self.messages.insert(tk.END, message)

                    print('\r{}\n{}: '.format(message, self.name), end='')
                    syslog.syslog(syslog.LOG_NOTICE, '\r{}\n{}: '.format(message, self.name), end='')

                else:
                    print('\r{}\n{}: '.format(message, self.name), end='')
                    syslog.syslog(syslog.LOG_NOTICE, '\r{}\n{}: '.format(message, self.name), end='')
            
            else:
                # server has closed the socket, exit the program
                print('\nLost connection with server. Program will be closed.')
                syslog.syslog(syslog.LOG_INFO, '\nLost connection with the server. Program will be closed.')
                self.sock.close()
                os._exit(0)


class Client:
    def __init__(self, host, port):
        self.host = host  # IP address of server's listening socket
        self.port = port  # port number of server's listening socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.name = None  # user name
        self.messages = None
    
    def start(self):
        print('Connecting to {}:{}'.format(self.host, self.port))
        syslog.syslog(syslog.LOG_INFO, 'Connecting to {}:{}'.format(self.host, self.port))
        self.sock.connect((self.host, self.port))  # connecting to server
        print('Successfully connected to {}:{}'.format(self.host, self.port))
        syslog.syslog(syslog.LOG_INFO, 'Successfully connected to {}:{}'.format(self.host, self.port))
        
        print()
        # getting user name
        self.name = input('Enter your name: ')

        print()
        print('Welcome, {}!'.format(self.name))
        syslog.syslog(syslog.LOG_NOTICE, 'Welcome, {}!'.format(self.name))

        # create send and receive threads
        send = Send(self.sock, self.name)
        receive = Receive(self.sock, self.name)

        # sake the thread daemon so it ends whenever the main thread ends
        send.daemon = True
        receive.daemon = True

        # start send and receive threads
        send.start()
        receive.start()

        self.sock.sendall('Server: {} has joined the chat.'.format(self.name).encode('ascii'))
        print("\rTo leave the chatroom type 'QUIT'\n")
        print('{}: '.format(self.name), end='')
        syslog.syslog(syslog.LOG_NOTICE, "\rTo leave the chatroom type 'QUIT'\n")
        syslog.syslog(syslog.LOG_NOTICE, '{}: '.format(self.name), end='')

        return receive

    def send(self, text_input):
        # sending text_input data from GUI
        message = text_input.get()
        text_input.delete(0, tk.END)
        self.messages.insert(tk.END, '{}: {}'.format(self.name, message))

        # type 'QUIT' to leave the chatroom
        if message == 'QUIT':
            self.sock.sendall('Server: {} has left the chat.'.format(self.name).encode('ascii'))
            
            print('\nProgram closed')
            syslog.syslog(syslog.LOG_INFO, '\nProgram closed')
            self.sock.close()
            os._exit(0)
        
        # send message to server for broadcasting
        else:
            self.sock.sendall('{}: {}'.format(self.name, message).encode('ascii'))


def main(host, port):
    # GUI
    client = Client(host, port)
    receive = client.start()

    window = tk.Tk()
    window.title('Chatroom')

    frm_messages = tk.Frame(master=window)
    scrollbar = tk.Scrollbar(master=frm_messages)
    messages = tk.Listbox(
        master=frm_messages, 
        yscrollcommand=scrollbar.set
    )
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y, expand=False)
    messages.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    client.messages = messages
    receive.messages = messages

    frm_messages.grid(row=0, column=0, columnspan=2, sticky="nsew")

    frm_entry = tk.Frame(master=window)
    text_input = tk.Entry(master=frm_entry)
    text_input.pack(fill=tk.BOTH, expand=True)
    text_input.bind("<Return>", lambda x: client.send(text_input))

    btn_send = tk.Button(
        master=window,
        text='Send',
        command=lambda: client.send(text_input)
    )

    frm_entry.grid(row=1, column=0, padx=10, sticky="ew")
    btn_send.grid(row=1, column=1, pady=10, sticky="ew")

    window.rowconfigure(0, minsize=500, weight=1)
    window.rowconfigure(1, minsize=50, weight=0)
    window.columnconfigure(0, minsize=500, weight=1)
    window.columnconfigure(1, minsize=200, weight=0)

    window.mainloop()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Chatroom Server')
    parser.add_argument('host', help='Interface the server listens at')
    parser.add_argument('-p', metavar='PORT', type=int, default=1060,
                        help='TCP port (default 1060)')
    args = parser.parse_args()

    main(args.host, args.p)
