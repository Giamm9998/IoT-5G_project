import socket
import hashlib
from colorama import Fore

from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Util.Padding import pad, unpad

SERVER = "127.0.0.1"
PORT = 8081


class Device():
    def __init__(self) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.wur = self.WakeUp_Radio(self.socket)
        self.mr = self.Main_Radio(self.socket)

    def notify_ch(self):
        self.wur.wakeup_ch()
        self.mr.recv_ack()

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
            self.socket.connect((SERVER, PORT))
            print('Token: ', self.token)
            self.socket.send(self.token)

    class Main_Radio():
        def __init__(self, socket) -> None:
            self.socket = socket
            self.key = b'Sixteen byte key'
            self.nonce = b'a'*11
            self.cipher = AES.new(self.key, AES.MODE_CCM, self.nonce)

        def recv_ack(self):
            data = self.socket.recv(1024)
            ack = self.cipher.decrypt_and_verify(
                data.split(b'|')[0], data.split(b'|')[1])
            print(Fore.GREEN+"From cluster head :", ack, Fore.WHITE)


sensor = Device()
sensor.notify_ch()
