# Called when server receives a new incoming connection. Stores the socket in the
# selectors registry.
import json
import os
import selectors
import time
import types
import socket

from cryptography.hazmat.primitives import hashes

p = 1299827


# are the times within 5 minutes of each other?
def valid_time(time1, time2):
    return 300 > math.abs(time1 - time2)


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

    def send(self, dest_sock, msg_type, **content):
        json_request = {
            'type': msg_type,
            'step': protocol_step,
            'src': self.username,
            'dest': dest_sock.getsockname(),
        }
        for label, value in content:
            json_request[label] = value
        print(f"Sending message: {json_request}")
        dest_sock.send(json.dumps(json_request).encode('utf-8'))

    # SPEKE!
    def half_diffie_hellman(self, password, random):
        digest = hashes.Hash(hashes.SHA256())
        digest.update(password.encode('utf-8'))
        pass_hash = int.from_bytes(digest.finalize(), 'big')
        # https://datatracker.ietf.org/doc/rfc3526/?include_text=1
        # p = int(2 ** 2048 - 2 ** 1984 - 1 + 2 ^ 64 * ((2 ** 1918 * math.pi) + 124476))
        # g = (pass_hash ** 2) % p  # same as pow(pass_hash, 2, p)
        g = pow(pass_hash, 2, p)  # hash(w)^2 mod p
        return pow(g, random, p)  # g^a mod p

    def encrypt(self, init_vector, key, content):
        # encrypt plaintext with symmetric key
        cipher = Cipher(algorithms.AES(key), modes.CBC(init_vector))
        encryptor = cipher.encryptor()

        # need paddings b/c CBC mode needs data to be a multiple of the block length (128)
        padder = padding.PKCS7(128).padder()
        padded_pt = padder.update(content)
        padded_pt += padder.finalize()
        ciphertext = encryptor.update(padded_pt) + encryptor.finalize()
        return ciphertext

    def decrypt(self, init_vector, key, ciphertext):
        # decrypt ciphertext with symmetric key
        cipher = Cipher(algorithms.AES(key), modes.CBC(init_vector))
        decryptor = cipher.decryptor()
        padded_text = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        unpadded_pt = unpadder.update(padded_text)
        unpadded_pt += unpadder.finalize()
        return unpadded_pt
