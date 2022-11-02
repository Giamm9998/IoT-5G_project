import socket
import hashlib
from colorama import Fore
import time
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Util.Padding import pad, unpad

from random import randint
from my_utils import reset_cipher, send_value, recv_value
import os

SERVER = "127.0.0.1"
PORT = 8081


def reset_hash(dev, msg):
    dev.hash_fun = hashlib.sha256()
    dev.hash_fun.update(msg)


class Device():
    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.mr = self.Main_Radio(self.sock)
        self.wur = self.WakeUp_Radio(self.sock, self.mr.token)

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

        # ----------------------- time check -----------------------
        if not __debug__:
            t = time.time()
        # ----------------------------------------------------------

        token = self.mr.update_token(last_msg)
        self.wur.token = token

        # ----------------------- time check -----------------------
        if not __debug__:
            elapsed_time = (time.time()-t)
            self.mr.computation_time += elapsed_time
            print(Fore.MAGENTA, 'TIME CHECK ',
                  elapsed_time, Fore.WHITE)
        # ----------------------------------------------------------
        self.mr.nonce = self.mr.reset_cipher()
        if not __debug__:
            print(Fore.MAGENTA+"COMPUTATION TIME: ",
                  self.mr.computation_time, Fore.WHITE)
            self.mr.computation_time = 0

    class WakeUp_Radio():
        def __init__(self, socket, token) -> None:
            self.socket = socket
            self.token = token

        def wakeup_ch(self):
            print('Token: ', self.token)
            send_value(self.socket, self.token)

        def reset_socket(self, new_sock):
            self.socket.close()
            self.socket = new_sock

    class Main_Radio():
        def __init__(self, socket) -> None:
            self.socket = socket
            # Crypto settings
            self.enc_key = b'Sixteen byte key'
            self.nonce = b'a'*11
            self.cipher = None
            # hash settings
            self.token_key = b'Gianmarco Arthur'
            self.computation_time = 0

            # ----------------------- time check -----------------------
            if not __debug__:
                t = time.time()
            # ----------------------------------------------------------

            # using sha256 hash
            self.hash_fun = hashlib.sha256()
            # first token is the first 16 bits (2 bytes) of sha256(key||cluster__head_address)
            self.hash_fun.update(self.token_key+str(PORT).encode())
            # taking the first 16 bits
            self.token = self.hash_fun.digest()[:2]

            # ----------------------- time check -----------------------
            if not __debug__:
                elapsed_time = (time.time()-t)
                self.computation_time += elapsed_time
                print(Fore.MAGENTA, 'TIME CHECK ',
                      elapsed_time, Fore.WHITE)
            # ----------------------------------------------------------

        def reset_cipher(self):
            nonce = os.urandom(11)
            self.cipher = AES.new(self.enc_key, AES.MODE_CCM, nonce)
            return nonce

        def recv_ack_of_wuc(self, token):
            ack = recv_value(self.socket, 2)

            # ----------------------- time check -----------------------
            if not __debug__:
                t = time.time()
            # ----------------------------------------------------------

            reset_hash(self, token+b'X')
            expected_ack = self.hash_fun.digest()[:2]
            if ack != expected_ack:
                print('ACK ERROR - ACK received: ', ack,
                      ' ACK expected: ', expected_ack)
                exit(0)

            # ----------------------- time check -----------------------
            if not __debug__:
                elapsed_time = (time.time()-t)
                self.computation_time += elapsed_time
                print(Fore.MAGENTA, 'TIME CHECK ',
                      elapsed_time, Fore.WHITE)
            # ----------------------------------------------------------

            print(Fore.GREEN+"ACK1 :", ack, Fore.WHITE)

        def send_notification(self):
            temp = int.to_bytes(randint(0, 40), 1, 'big')

            # ----------------------- time check -----------------------
            if not __debug__:
                t = time.time()
            # ----------------------------------------------------------

            self.cipher, nonce = reset_cipher(self.enc_key)
            seq_num = int.to_bytes(randint(0, 2**16-1), 2, 'big')
            last_msg = pad(temp+seq_num, 16)
            enc, tag = self.cipher.encrypt_and_digest(last_msg)

            # ----------------------- time check -----------------------
            if not __debug__:
                elapsed_time = (time.time()-t)
                self.computation_time += elapsed_time
                print(Fore.MAGENTA, 'TIME CHECK ',
                      elapsed_time, Fore.WHITE)
            # ----------------------------------------------------------

            print('sending alarm...')
            send_value(self.socket, enc+tag+nonce)
            return temp, seq_num

        def recv_ack_of_msg(self, seq_num):
            ack = int.from_bytes(recv_value(self.socket, 2), 'big')

            # ----------------------- time check -----------------------
            if not __debug__:
                t = time.time()
            # ----------------------------------------------------------

            expected_ack = int.from_bytes(seq_num, 'big')+1
            if ack != expected_ack:
                print('ACK Error - received ack: ', ack,
                      ' | ', 'expected ack: ', expected_ack)
                exit(0)

            # ----------------------- time check -----------------------
            if not __debug__:
                elapsed_time = (time.time()-t)
                self.computation_time += elapsed_time
                print(Fore.MAGENTA, 'TIME CHECK ',
                      elapsed_time, Fore.WHITE)
            # ----------------------------------------------------------

            print(Fore.GREEN+"ACK2 :", ack, Fore.WHITE+'\n')

        def update_token(self, last_message):
            reset_hash(self, self.token+last_message)
            self.token = self.hash_fun.digest()[:2]
            return self.token

        def reset_socket(self, new_sock):
            self.socket.close()
            self.socket = new_sock


sensor = Device()
for i in range(10):
    sensor.notify_ch()
