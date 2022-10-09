from colorama import Fore
import socket
import threading
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes, bytes_to_long
import os
from Crypto.Util.Padding import pad, unpad
import time

TIME_THRESHOLD = 5
KEY_LEN = 16
ID_LEN = 2  # address has 2 bytes
ENC_PLUS_TAG_LEN = 32
BLOCK_LEN = 16


def send_value(sock, value):
    if __debug__:
        print(Fore.BLUE+f'sending {len(value)} bytes'+Fore.WHITE)
    if __debug__:
        print(Fore.BLUE+f'sending val: ', value, Fore.WHITE)
    sock.send(value)


def recv_value(sock, size):
    data = sock.recv(size)
    if __debug__:
        print(Fore.BLUE+f'value len: {size}'+Fore.WHITE)
    if __debug__:
        print(Fore.BLUE+f'value: ', data, Fore.WHITE)
    return data


def is_auth_valid(timestamp):
    current_time = int(time.time())
    print(f'current time: {current_time}, timestamp: {timestamp}', end='')
    if current_time-timestamp > TIME_THRESHOLD:
        print(' -> INVALID!')
        return False
    else:
        print(' -> valid')
        return True


def reset_cipher(key, nonce):
    return AES.new(key, AES.MODE_CCM, nonce)


def kerberos_protocol(server):

    # receive client ID
    data = recv_value(server.csocket, ID_LEN)
    print(Fore.RED+"Client ID: ", data, Fore.WHITE)

    # send session key
    s_key = os.urandom(KEY_LEN)
    s_cipher = AES.new(s_key, AES.MODE_CCM, server.nonce)
    print('Session key: ', s_key)
    msg, mac = server.cipher.encrypt_and_digest(s_key)
    print('sending session key...')
    send_value(server.csocket, msg+mac)

    # receive authenticator
    data = recv_value(server.csocket, ENC_PLUS_TAG_LEN)
    auth = s_cipher.decrypt_and_verify(data[:BLOCK_LEN], data[BLOCK_LEN:])
    auth = bytes_to_long(unpad(auth, 16))

    print(Fore.RED+"Authenticator: ", auth, Fore.WHITE)
    if not is_auth_valid(auth):
        print("ERROR")
        # handle error
    s_cipher = reset_cipher(s_key, server.nonce)  # reset cipher

    # send IDs and keys
    id1, id2 = os.urandom(ID_LEN), os.urandom(ID_LEN)
    print(id1+b' , '+id2)
    key1, key2 = b'1'*KEY_LEN, b'2'*KEY_LEN
    print(key1+b' , '+key2)
    data = id1+id2+key1+key2

    # s_cipher.update(data)
    msg, mac = s_cipher.encrypt_and_digest(pad(data, BLOCK_LEN))
    print('sending ids and keys')
    send_value(server.csocket, msg+mac)
    print("Client at ", clientAddress, " disconnected...")


class ClientThread(threading.Thread):
    def __init__(self, clientAddress, clientsocket):
        threading.Thread.__init__(self)
        self.csocket = clientsocket
        print("New connection added: ", clientAddress)
        # crypto settings
        self.key = b'0123456789abcdef'
        self.nonce = b'a'*11
        self.cipher = AES.new(self.key, AES.MODE_CCM, self.nonce)

    def run(self):
        print("Connection from : ", clientAddress)
        kerberos_protocol(self)


# socket settings
LOCALHOST = "127.0.0.1"
PORT = 8080
bts = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
bts.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
bts.bind((LOCALHOST, PORT))


print("BTS started")
print("Waiting for Cluster Head request..")
while True:
    bts.listen(1)
    clientsock, clientAddress = bts.accept()
    newthread = ClientThread(clientAddress, clientsock)
    newthread.start()
