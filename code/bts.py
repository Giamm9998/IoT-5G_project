from colorama import Fore
import socket
import threading
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes, bytes_to_long
import os
from Crypto.Util.Padding import pad, unpad
import time

TIME_THRESHOLD = 5


def is_auth_valid(timestamp):
    current_time = int(time.time())
    print(f'current time: {current_time}, timestamp: {timestamp}', end='')
    if current_time-timestamp > TIME_THRESHOLD:
        print(' -> INVALID!')
        return False
    else:
        print(' -> valid')
        return True


def kerberos_protocol(server):
    # receive client ID
    data = server.csocket.recv(2048)
    print(Fore.GREEN+"Client ID: ", data, Fore.WHITE)
    # send session key
    s_key = os.urandom(16)
    s_cipher = AES.new(s_key, AES.MODE_CCM, server.nonce)
    print('Session key: ', s_key)
    msg = server.cipher.encrypt(s_key)+b'|'+server.cipher.digest()
    server.csocket.send(msg)

    # receive authenticator
    data = server.csocket.recv(2048).split(b'|')
    auth = bytes_to_long(unpad(s_cipher.decrypt(data[0]), 16))

    # MAC verification
    try:
        s_cipher.verify(data[1])
    except ValueError:
        print('MAC ERROR')
        exit(0)
    print(Fore.GREEN+"Authenticator: ", auth, Fore.WHITE)
    if not is_auth_valid(auth):
        print("ERROR")
        # handle error
    s_cipher = AES.new(s_key, AES.MODE_CCM, server.nonce)  # reset cipher

    # send IDs and keys
    id1, id2 = os.urandom(2), os.urandom(2)
    print(id1+b' , '+id2)
    key1, key2 = b'1'*16, b'2'*16
    print(key1+b' , '+key2)
    data = id1+b','+id2+b'|'+key1+b','+key2

    # s_cipher.update(data)
    msg = s_cipher.encrypt(pad(data, 16))+b'|'+s_cipher.digest()
    server.csocket.send(msg)
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
print("Waiting for Node request..")
while True:
    bts.listen(1)
    clientsock, clientAddress = bts.accept()
    newthread = ClientThread(clientAddress, clientsock)
    newthread.start()
