import socket
import os
from colorama import Fore
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes, bytes_to_long
import time
from Crypto.Util.Padding import pad, unpad
import threading
import hashlib

BLOCK_LEN = 16
ID_LEN = 2
KEY_LEN = 16
LOCALHOST = "127.0.0.1"
OWN_PORT = 8081
BTS_PORT = 8080


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


class SensorThread(threading.Thread):
    def __init__(self, dev, sensor_address, sensor_socket):
        threading.Thread.__init__(self)
        self.socket = sensor_socket
        print("New connection added: ", sensor_address)
        self.dev = dev
        # crypto settings
        self.sensor_address = sensor_address

    def run(self):
        print("Connection from : ", self.sensor_address)
        for _ in range(10):
            self.dev.wu_protocol()
        print('Connection from : ', self.sensor_address, ' closed')
        self.dev.kerberos_protocol()
        print('Communication to BTS closed')


class Device():
    def __init__(self) -> None:
        node = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        node.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        node.bind((LOCALHOST, OWN_PORT))
        print("Cluster head started\nWaiting for a wake up call..")
        self.socket = node

    def start(self):
        while True:
            self.socket.listen(1)
            sensor_sock, sensor_address = self.socket.accept()
            self.wur = self.WakeUp_Radio(sensor_sock)
            self.mr = self.Main_Radio(sensor_sock)
            newthread = SensorThread(self, sensor_address, sensor_sock)
            newthread.start()
        # self.wur.wait_wakeup_call(self.mr)

    def wu_protocol(self):
        token = self.wur.recv_token()
        print(Fore.GREEN+"Token from sensor :", token, Fore.WHITE)
        self.wur.verify_token(token)
        self.mr.send_ack_of_wuc(token)
        last_msg, seq_num = self.mr.recv_notification()
        self.mr.send_ack_of_msg(seq_num)
        self.wur.update_token(last_msg)
        self.mr.reset_cipher()

    def kerberos_protocol(self):
        # socket settings
        ssocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssocket.connect((LOCALHOST, BTS_PORT))

        # crypto settings
        key = b'0123456789abcdef'
        nonce = b'a'*11
        cipher = AES.new(key, AES.MODE_CCM, nonce)

        # sending node ID (16 bits)
        node_id = os.urandom(ID_LEN)
        print('sending ID ...')
        send_value(ssocket, node_id)

        # receiving session key
        data = recv_value(ssocket, BLOCK_LEN*2)
        s_key = cipher.decrypt_and_verify(data[:BLOCK_LEN], data[BLOCK_LEN:])
        print(Fore.RED+"From BTS :", s_key, Fore.WHITE)
        s_cipher = AES.new(s_key, AES.MODE_CCM, nonce)

        # sending authenticator
        timestamp = int(time.time())
        print(f'timestamp: {timestamp}')
        auth, mac = s_cipher.encrypt_and_digest(
            pad(long_to_bytes(timestamp), 16))
        print('sending authenticator...')
        send_value(ssocket, auth+mac)
        s_cipher = AES.new(s_key, AES.MODE_CCM, nonce)  # reset cipher

        # receiving IDs and keys
        data = recv_value(ssocket, BLOCK_LEN*4)
        ids_and_keys = s_cipher.decrypt_and_verify(
            data[:-BLOCK_LEN], data[-BLOCK_LEN:])
        ids_and_keys = unpad(ids_and_keys, 16)

        ids = [ids_and_keys[:ID_LEN], ids_and_keys[ID_LEN:ID_LEN*2]]
        keys = [ids_and_keys[ID_LEN*2:ID_LEN*2+KEY_LEN],
                ids_and_keys[ID_LEN*2+KEY_LEN:ID_LEN*2+KEY_LEN*2]]

        print(Fore.RED+"From Server :")
        print('IDs: ', ids)
        print('Keys: ', keys, Fore.WHITE)

        ssocket.close()

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
            send_value(self.socket, self.token)

        def recv_token(self):
            token = recv_value(self.socket, 2)
            return token

        def verify_token(self, token):
            if self.token != token:
                print('Error token not correct - received token: ',
                      token, ' expected token: ', self.token)
                exit(0)

        def update_token(self, last_message):
            self.hash_fun.update(
                self.token+int.to_bytes(last_message, 1, 'big'))
            self.token = self.hash_fun.digest()[:2]

    class Main_Radio():
        def __init__(self, socket) -> None:
            self.socket = socket
            self.key = b'Sixteen byte key'
            self.nonce = b'a'*11
            self.cipher = AES.new(self.key, AES.MODE_CCM, self.nonce)

        def reset_cipher(self):
            self.cipher = AES.new(self.key, AES.MODE_CCM, self.nonce)

        def send_ack_of_wuc(self, token):
            hasher = hashlib.sha256()
            # the ACK is the h(token||sequence) where sequence is a fixed sequence
            # of bits pre-shared by the parties. Here we choose to use the byte 'X'
            hasher.update(token+b'X')
            ack = hasher.digest()[:2]
            print('ACK1: ', ack)
            send_value(self.socket, ack)

        def recv_notification(self):
            data = recv_value(self.socket, 32)
            self.reset_cipher()
            msg = self.cipher.decrypt_and_verify(
                data[:16], data[16:])
            msg = unpad(msg, 16)
            # first byte received is the temperature

            temp = msg[0]
            # -------------------
            # temperature checks
            # -------------------

            # second byte received is the sequence number
            seq_num = msg[1:3]
            print(Fore.GREEN+"From sensor : temp = ", temp,
                  ' | seq_num = ', seq_num, Fore.WHITE)
            return temp, seq_num

        def send_ack_of_msg(self, seq_num):
            ack = int.from_bytes(seq_num, 'big')+1
            print('ACK2: ', ack, '\n')
            send_value(self.socket, int.to_bytes(ack, 2, 'big'))


node = Device()
node.start()
