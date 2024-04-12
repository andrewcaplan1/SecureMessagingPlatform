# Called when server receives a new incoming connection. Stores the socket in the
# selectors registry.
import json
import selectors
import time
import types
import socket


class Node:
    def __init__(self, listen_host, listen_port, user_id):

        self.username = user_id

        # TCP socket for listening for new connections
        self.listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen_sock.bind((listen_host, listen_port))
        # return data immediately, used to manage multi connections
        self.listen_sock.setblocking(False)
        # FIXME: does this block?
        self.listen_sock.listen()

        # use selectors module to manage multiple peer connections
        self.sel = selectors.DefaultSelector()
        # register this as a listening socket, monitor with sel.select()
        self.sel.register(self.listen_sock, selectors.EVENT_READ)

        self.user_socks = {}  # map of user to socket

    def register_client(self, c_socket):
        connect, address = c_socket.accept()
        print(f"Received connection from {address}")
        connect.setblocking(False)  # to avoid BlockingIOError

        # wrap data in SimpleNamespace class
        data = types.SimpleNamespace(addr=address, inb=b"", outb=b"")
        # we use bitwise OR because we want to know when conn is ready for reading and writing
        events = selectors.EVENT_READ | selectors.EVENT_WRITE
        self.sel.register(connect, events, data=data)

    def send(self, dest_sock, msg_type, content, protocol_step=""):
        json_request = {
            'type': msg_type,
            'step': protocol_step,
            'src': self.username,
            'dest': dest_sock.getsockname(),
            'time': time.time(),
            'content': content
        }
        print(f"Sending message: {json_request}")
        dest_sock.send(json.dumps(json_request).encode('utf-8'))