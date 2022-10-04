from cgitb import reset
import socket
import hashlib
from colorama import Fore

from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Util.Padding import pad, unpad
from torch import ne

SERVER = "127.0.0.1"
PORT = 8081


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
        self.mr.recv_ack()
        last_msg = self.mr.send_notification()
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
            self.socket.send(self.token)

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

        def recv_ack(self):
            data = self.socket.recv(1024)
            ack = self.cipher.decrypt_and_verify(
                data.split(b'|')[0], data.split(b'|')[1])
            print(Fore.GREEN+"From cluster head :", ack, Fore.WHITE)

        def send_notification(self):
            # TODO is padding necessary?
            self.reset_cipher()
            last_msg = b'Temperature too high!'
            enc, tag = self.cipher.encrypt_and_digest(last_msg)
            print('sending alarm...')
            self.socket.send(enc+b'|'+tag)
            return last_msg

        def reset_socket(self, new_sock):
            self.socket.close()
            self.socket = new_sock


sensor = Device()
for i in range(10):
    sensor.notify_ch()
