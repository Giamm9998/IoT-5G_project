import socket
import hashlib
from turtle import update
from colorama import Fore

from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Util.Padding import pad, unpad

from random import randint

SERVER = "127.0.0.1"
PORT = 8081


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


class Device():
    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.wur = self.WakeUp_Radio(self.sock)
        self.mr = self.Main_Radio(self.sock)

    def reset_radio_socket(self):
        new_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.wur.reset_socket(new_sock)
        self.mr.reset_socket(new_sock)

    def notify_ch(self):
        try:
            self.sock.connect((SERVER, PORT))
        except:
            pass
        self.wur.wakeup_ch()
        self.mr.recv_ack_of_wuc(self.wur.token)
        last_msg, seq_num = self.mr.send_notification()
        self.mr.recv_ack_of_msg(seq_num)
        self.wur.update_token(last_msg)
        self.mr.reset_cipher()
        # self.reset_radio_socket()

    class WakeUp_Radio():
        def __init__(self, socket) -> None:
            self.socket = socket
            self.key = b'Gianmarco Arthur'
            # using sha256 hash
            self.hash_fun = hashlib.sha256()
            # first token is the first 16 bits (2 bytes) of sha256(key||cluster__head_address)
            self.hash_fun.update(self.key+b'(127.0.0.1, 8081)')
            # taking the first 16 bits
            self.token = self.hash_fun.digest()[:2]

        def wakeup_ch(self):
            print('Token: ', self.token)
            send_value(self.socket, self.token)

        def update_token(self, last_message):
            self.hash_fun.update(self.token+last_message)
            self.token = self.hash_fun.digest()[:2]

        def reset_socket(self, new_sock):
            self.socket.close()
            self.socket = new_sock

    class Main_Radio():
        def __init__(self, socket) -> None:
            self.socket = socket
            self.key = b'Sixteen byte key'
            self.nonce = b'a'*11
            self.cipher = AES.new(self.key, AES.MODE_CCM, self.nonce)

        # TODO modify b'|' with something correct
        def reset_cipher(self):
            self.cipher = AES.new(self.key, AES.MODE_CCM, self.nonce)

        def recv_ack_of_wuc(self, token):
            ack = recv_value(self.socket, 2)
            hasher = hashlib.sha256()
            hasher.update(token+b'X')
            expected_ack = hasher.digest()[:2]
            if ack != expected_ack:
                print('ACK ERROR - ACK received: ', ack,
                      ' ACK expected: ', expected_ack)
                exit(0)
            print(Fore.GREEN+"ACK1 :", ack, Fore.WHITE)

        def send_notification(self):
            self.reset_cipher()
            temp = int.to_bytes(randint(0, 40), 1, 'big')
            seq_num = int.to_bytes(randint(0, 2**16-1), 2, 'big')
            last_msg = pad(temp+seq_num, 16)
            enc, tag = self.cipher.encrypt_and_digest(last_msg)
            print('sending alarm...')
            send_value(self.socket, enc+tag)
            return temp, seq_num

        def recv_ack_of_msg(self, seq_num):
            ack = int.from_bytes(recv_value(self.socket, 2), 'big')
            expected_ack = int.from_bytes(seq_num, 'big')+1
            if ack != expected_ack:
                print('ACK Error - received ack: ', ack,
                      ' | ', 'expected ack: ', expected_ack)
                exit(0)
            print(Fore.GREEN+"ACK2 :", ack, Fore.WHITE+'\n')

        def reset_socket(self, new_sock):
            self.socket.close()
            self.socket = new_sock


sensor = Device()
for i in range(10):
    sensor.notify_ch()
