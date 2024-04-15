import json
import os
import selectors
import time
import types
import socket
import sys
import time
import base64
import math

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


p = 1299827


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

        self.user_socks = {}  # map of username to socket

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
            'src': self.username,
            'dest': dest_sock.getsockname(),
        }
        # print(content)
        for label, value in content.items():
            if isinstance(value, bytes):
                if label == 'tgt':
                    print("TGT was byte and now encoded base64")
                # print("Encoding to bytes: ", label, value)
                json_request[label] = base64.standard_b64encode(value).decode('utf-8')
            else:
                # print("not bytes: ", label, value)
                json_request[label] = value
        print(f"Sending message: {json_request}")
        dest_sock.send(json.dumps(json_request).encode('utf-8'))

    # SPEKE!
    def hash_and_diffie_hellman(self, password, random):
        digest = hashes.Hash(hashes.SHA256())
        digest.update(password.encode('utf-8'))
        pass_hash = int.from_bytes(digest.finalize(), 'big')
        # https://datatracker.ietf.org/doc/rfc3526/?include_text=1
        # p = int(2 ** 2048 - 2 ** 1984 - 1 + 2 ^ 64 * ((2 ** 1918 * math.pi) + 124476))
        g = pow(pass_hash, 2, p)  # hash(w)^2 mod p
        return pow(g, random, p)  # g^a mod p

    # SPEKE!
    def half_diffie_hellman(self, pass_hash, random):
        # digest = hashes.Hash(hashes.SHA256())
        # digest.update(password.encode('utf-8'))
        # pass_hash = int.from_bytes(digest.finalize(), 'big')
        # https://datatracker.ietf.org/doc/rfc3526/?include_text=1
        # p = int(2 ** 2048 - 2 ** 1984 - 1 + 2 ^ 64 * ((2 ** 1918 * math.pi) + 124476))
        g = pow(pass_hash, 2, p)  # hash(w)^2 mod p
        return pow(g, random, p)  # g^a mod p

    def encrypt(self, init_vector, key, plain_bytes):
        # encrypt plaintext with symmetric key
        cipher = Cipher(algorithms.AES(key), modes.CBC(init_vector))
        encryptor = cipher.encryptor()

        # need paddings b/c CBC mode needs data to be a multiple of the block length (128)
        padder = padding.PKCS7(128).padder()
        padded_bytes = padder.update(plain_bytes) + padder.finalize()
        ciphertext = encryptor.update(padded_bytes) + encryptor.finalize()
        return ciphertext

    def decrypt(self, init_vector, key, encrypted_padded_bytes):
        # decrypt ciphertext with symmetric key
        cipher = Cipher(algorithms.AES(key), modes.CBC(init_vector))
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(128).unpadder()

        padded_bytes = decryptor.update(encrypted_padded_bytes) + decryptor.finalize()
        print(padded_bytes)
        plaintext = unpadder.update(padded_bytes) + unpadder.finalize()
        return plaintext

    def decrypt_check_time(self, iv, challenge, key):
        iv_bytes = base64.standard_b64decode(iv)
        challenge_bytes = base64.standard_b64decode(challenge)
        decrypted_timestamp = self.decrypt(iv_bytes, key, challenge_bytes)
        return 300 > abs(int.from_bytes(decrypted_timestamp, 'big') - int(time.time()))
