import socket
import os
from colorama import Fore
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes, bytes_to_long
import time
from Crypto.Util.Padding import pad, unpad
import threading
import hashlib


def kerberos_protocol():
    # socket settings
    SERVER = "127.0.0.1"
    PORT = 8080
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((SERVER, PORT))

    # crypto settings
    key = b'0123456789abcdef'
    nonce = b'a'*11
    cipher = AES.new(key, AES.MODE_CCM, nonce)

    # sending node ID
    node_id = os.urandom(2)
    client.sendall(node_id)

    # receiving session key
    data = client.recv(1024).split(b'|')
    s_key = cipher.decrypt(data[0])
    # cipher.update(s_key)
    # MAC verification
    try:
        cipher.verify(data[1])
    except ValueError:
        print('MAC ERROR')
        exit(0)
    print(Fore.GREEN+"From Server :", s_key, Fore.WHITE)
    s_cipher = AES.new(s_key, AES.MODE_CCM, nonce)

    # sending authenticator
    timestamp = int(time.time())
    print(f'timestamp: {timestamp}')
    # cipher.update(long_to_bytes(timestamp))
    auth = s_cipher.encrypt(
        pad(long_to_bytes(timestamp), 16))+b'|'+s_cipher.digest()
    client.send(auth)
    s_cipher = AES.new(s_key, AES.MODE_CCM, nonce)  # reset cipher

    # receiving IDs and keys
    data = client.recv(1024).split(b'|')
    data_decrypted = unpad(s_cipher.decrypt(data[0]), 16)
    # cipher.update(data_decrypted)
    ids = data_decrypted.split(b'|')[0].split(b',')
    keys = data_decrypted.split(b'|')[1].split(b',')
    try:
        s_cipher.verify(data[1])
    except ValueError:
        print('MAC ERROR')
        exit(0)
    print(Fore.GREEN+"From Server :")
    print('IDs: ', ids)
    print('Keys: ', keys, Fore.WHITE)

    client.close()


def send_values(sock, values):
    # total length of the packet is given by the length of the values to send + 1 byte each for the values length
    tot_len = int.to_bytes(len(b''.join(values))+len(values), 1, 'big')
    if __debug__:
        print(Fore.BLUE+'sending packet of length: ',
              int.from_bytes(tot_len, 'big'), Fore.WHITE)
    sock.send(tot_len)
    for val in values:
        l = int.to_bytes(len(val), 1, "big")
        if __debug__:
            print(Fore.BLUE+f'sending {l} bytes'+Fore.WHITE)
        sock.send(l)
        if __debug__:
            print(Fore.BLUE+f'sending val: ', val, Fore.WHITE)
        sock.send(val)


def recv_values(sock):
    # get total packet length
    tot_len = int.from_bytes(sock.recv(1), 'big')
    values = []
    while tot_len > 0:
        l = int.from_bytes(sock.recv(1), 'big')
        if __debug__:
            print(Fore.BLUE+f'value len: {l}'+Fore.WHITE)
        val = sock.recv(l)
        if __debug__:
            print(Fore.BLUE+'value : ', val, Fore.WHITE)
        values.append(val)
        tot_len -= (l+1)
    return values


class SensorThread(threading.Thread):
    def __init__(self, wur, mr, sensor_address, sensor_socket):
        threading.Thread.__init__(self)
        self.socket = sensor_socket
        print("New connection added: ", sensor_address)
        self.wur = wur
        self.mr = mr
        # crypto settings
        self.sensor_address = sensor_address

    def run(self):
        print("Connection from : ", self.sensor_address)
        for _ in range(10):
            token = self.wur.recv_token()
            print(Fore.GREEN+"From sensor :", token, Fore.WHITE)
            if not self.wur.verify_token(token):
                print('Error - token not correct')
                exit(0)
            print("Token correct!")
            self.mr.send_ack()
            last_msg = self.mr.recv_notification()
            self.wur.update_token(last_msg)
            self.mr.reset_cipher()
        print('Connection from : ', self.sensor_address, ' closed')


LOCALHOST = "127.0.0.1"
PORT = 8081


class Device():
    def __init__(self) -> None:
        node = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        node.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        node.bind((LOCALHOST, PORT))
        print("Cluster head started\nWaiting for a wake up call..")
        self.socket = node

    def start(self):
        while True:
            self.socket.listen(1)
            sensor_sock, sensor_address = self.socket.accept()

            newthread = SensorThread(self.WakeUp_Radio(sensor_sock), self.Main_Radio(
                sensor_sock), sensor_address, sensor_sock)
            newthread.start()
        # self.wur.wait_wakeup_call(self.mr)

    class WakeUp_Radio():
        def __init__(self, socket) -> None:
            self.socket = socket
            self.key = b'Gianmarco Arthur'
            # using sha256 hash
            self.hash_fun = hashlib.sha256()
            # first token is the first 16 bits (2 bytes) of sha256(key||cluster__head_address)
            self.hash_fun.update(self.key+b'(127.0.0.1, 8081)')
            self.token = self.hash_fun.digest()[:2]

        def send_wakeup_call(self):
            send_values(self.socket, [self.token])

        def recv_token(self):
            token = recv_values(self.socket)[0]
            return token

        def verify_token(self, token):
            if self.token == token:
                return True
            else:
                return False

        def update_token(self, last_message):
            self.hash_fun.update(self.token+last_message)
            self.token = self.hash_fun.digest()[:2]

    class Main_Radio():
        def __init__(self, socket) -> None:
            self.socket = socket
            self.key = b'Sixteen byte key'
            self.nonce = b'a'*11
            self.cipher = AES.new(self.key, AES.MODE_CCM, self.nonce)

        def reset_cipher(self):
            self.cipher = AES.new(self.key, AES.MODE_CCM, self.nonce)

        def send_ack(self):
            enc, tag = self.cipher.encrypt_and_digest(b"ACK")
            send_values(self.socket, [enc, tag])

        def recv_notification(self):
            data = recv_values(self.socket)
            self.reset_cipher()
            msg = self.cipher.decrypt_and_verify(
                data[0], data[1])
            print(Fore.GREEN+"From sensor :", msg, Fore.WHITE)
            return msg


node = Device()
node.start()
