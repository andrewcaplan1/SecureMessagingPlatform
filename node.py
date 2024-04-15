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
        self.listen_sock.listen()

        # use selectors module to manage multiple peer connections
        self.sel = selectors.DefaultSelector()
        # register this as a listening socket, monitor with sel.select()
        self.sel.register(self.listen_sock, selectors.EVENT_READ)

    def register_client(self, c_socket):
        connect, address = c_socket.accept()
        print(f"Received connection from {address}")
        connect.setblocking(False)  # to avoid BlockingIOError

        # wrap data in SimpleNamespace class
        data = types.SimpleNamespace(addr=address)
        # we use bitwise OR because we want to know when conn is ready for reading and writing
        events = selectors.EVENT_READ | selectors.EVENT_WRITE
        self.sel.register(connect, events, data=data)

    def encrypt_list(self, plain_list, key):
        iv = os.urandom(16)
        content = json.dumps(plain_list)
        encrypted = self.encrypt(iv, key, content.encode('utf-8'))
        return encrypted, iv

    def decrypt_list(self, encrypted_list, iv, key):
        encrypted_list_bytes = base64.standard_b64decode(encrypted_list)
        iv_bytes = base64.standard_b64decode(iv)
        decrypted_plain_list = self.decrypt(iv_bytes, key, encrypted_list_bytes).decode('utf-8')
        # print("decrypted plain list: ", decrypted_plain_list, type(decrypted_plain_list))

        return json.loads(decrypted_plain_list)

    def send(self, dest_sock, msg_type, **content):
        json_request = {
            'type': msg_type,
            'src': self.username,
            'dest': dest_sock.getsockname(),
        }
        for label, value in content.items():
            if isinstance(value, bytes):
                json_request[label] = base64.standard_b64encode(value).decode('utf-8')
            else:
                json_request[label] = value
        # print(f"Sending message: {json_request}")
        dest_sock.send(json.dumps(json_request).encode('utf-8'))

    def hash_and_diffie_hellman(self, password, random):
        digest = hashes.Hash(hashes.SHA256())
        digest.update(password.encode('utf-8'))
        pass_hash = int.from_bytes(digest.finalize(), 'big')
        return self.half_diffie_hellman(pass_hash, random)

    def half_diffie_hellman(self, pass_hash, random):
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
        plaintext = unpadder.update(padded_bytes) + unpadder.finalize()
        return plaintext

    def check_time(self, ts, timeout=300):
        current_time = time.time()
        return current_time > ts and timeout > abs(ts - current_time)

    def decrypt_check_time(self, iv, challenge, key):
        iv_bytes = base64.standard_b64decode(iv)
        challenge_bytes = base64.standard_b64decode(challenge)
        decrypted_timestamp = self.decrypt(iv_bytes, key, challenge_bytes)
        return self.check_time(int.from_bytes(decrypted_timestamp, 'big'))
