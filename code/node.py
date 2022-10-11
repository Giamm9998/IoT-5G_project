import socket
import os
from colorama import Fore
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes, bytes_to_long
import time
from Crypto.Util.Padding import pad, unpad
import threading
import hashlib
import argparse


BLOCK_LEN = 16
ID_LEN = 2
KEY_LEN = 16
LOCALHOST = "127.0.0.1"
SENS_NUM = 20

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


def reset_cipher(key, nonce):
    return AES.new(key, AES.MODE_CCM, nonce)


def reset_hash(dev, msg):
    dev.hash_fun = hashlib.sha256()
    dev.hash_fun.update(msg)


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
        token, caller_id = self.dev.wait_token()
        if caller_id != 'base_station':
            self.dev.wu_protocol(token, caller_id)
            for _ in range(9):
                token, caller_id = self.dev.wait_token()
                self.dev.wu_protocol(token, caller_id)
            print('Connection from : ', self.sensor_address, ' closed')
            self.dev.kerberos_protocol()
            print('Communication to BTS closed')
        else:
            self.dev.start_d2d(token)


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

    def wait_token(self):
        token = self.wur.recv_token()
        print(Fore.GREEN+"Token received :", token, Fore.WHITE)
        caller_id = self.mr.verify_token(token)
        return token, caller_id

    def wu_protocol(self, token, caller_id):
        # token = self.wur.recv_token()
        # print(Fore.GREEN+"Token received :", token, Fore.WHITE)
        # caller_id = self.mr.verify_token(token)
        print(Fore.GREEN+"ID of the sender :", caller_id, Fore.WHITE)
        self.mr.send_ack_of_wuc(token)
        last_msg, seq_num = self.mr.recv_notification()
        self.mr.send_ack_of_msg(seq_num)
        token = self.mr.update_token(last_msg, caller_id, token)
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

    def start_d2d(self, token):
        self.mr.send_ack_of_wuc(token)
        # self.mr.recv_ticket_and_auth()

    class WakeUp_Radio():
        def __init__(self, socket) -> None:
            self.socket = socket

        def recv_token(self):
            token = recv_value(self.socket, 2)
            return token

    class Main_Radio():
        def __init__(self, socket) -> None:
            self.socket = socket

            # crypto settings
            # TODO Implement different keys for different nodes?
            self.enc_key = b'Sixteen byte key'
            # TODO cange nonce every encryption?
            self.nonce = b'a'*11
            self.cipher = AES.new(self.enc_key, AES.MODE_CCM, self.nonce)

            # hash settings
            # using sha256 hash
            self.hash_fun = hashlib.sha256()
            # first token is the first 16 bits (2 bytes) of sha256(key||cluster__head_address)

            # set dictionary with the keys of the sensors and bts
            self.token_dict = {}
            for i in range(SENS_NUM):
                reset_hash(self, os.urandom(KEY_LEN)+str(OWN_PORT).encode())
                self.token_dict[self.hash_fun.digest()[:ID_LEN]] = f"sens{i+1}"
            reset_hash(self, b'a'*KEY_LEN+str(OWN_PORT).encode())
            self.token_dict[self.hash_fun.digest()[:ID_LEN]] = 'base_station'
            reset_hash(self, b'Gianmarco Arthur'+str(OWN_PORT).encode())
            self.token_dict[self.hash_fun.digest()[:ID_LEN]] = 'sens0'
            if __debug__:
                print('---------------------')
                print(self.token_dict)
                print('---------------------')

        def reset_cipher(self):
            self.cipher = AES.new(self.enc_key, AES.MODE_CCM, self.nonce)

        def send_ack_of_wuc(self, token):
            # the ACK is the h(token||sequence) where sequence is a fixed sequence
            # of bits pre-shared by the parties. Here we choose to use the byte 'X'
            reset_hash(self, token+b'X')
            ack = self.hash_fun.digest()[:ID_LEN]
            print('ACK1: ', ack)
            send_value(self.socket, ack)

        def recv_notification(self):
            data = recv_value(self.socket, BLOCK_LEN*2)
            self.reset_cipher()
            msg = self.cipher.decrypt_and_verify(
                data[:BLOCK_LEN], data[BLOCK_LEN:])
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

        def verify_token(self, token):
            if token in self.token_dict:
                return self.token_dict[token]
            else:
                print('Error token not correct - received token: ',
                      token, ' List of valid tokens: ', self.token_dict)
                exit(0)

        def update_token(self, last_message, caller_id, old_token):
            self.token_dict.pop(old_token)
            reset_hash(self, old_token +
                       int.to_bytes(last_message, 1, 'big'))
            new_token = self.hash_fun.digest()[:ID_LEN]
            self.token_dict[new_token] = caller_id
            return new_token

        def recv_ticket_and_auth(self):
            reset_cipher(self.enc_key, self.nonce)
            data = recv_value(self.socket, BLOCK_LEN*3)
            data = self.cipher.decrypt_and_verify(
                data[:BLOCK_LEN*2], data[BLOCK_LEN*2:])
            id, d2d_key = unpad(data[:BLOCK_LEN]), data[BLOCK_LEN:]
            id = int(id.decode())
            return d2d_key


# Create the parser
parser = argparse.ArgumentParser()
# Add an argument
parser.add_argument('--port', type=int, required=True)
# Parse the argument
args = parser.parse_args()

OWN_PORT = args.port

node = Device()
node.start()
