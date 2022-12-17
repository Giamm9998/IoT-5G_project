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
from my_utils import *
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256

BLOCK_LEN = 16
ID_LEN = 2
KEY_LEN = 16
LOCALHOST = "127.0.0.1"

SENS_NUM = 100
PORT_LEN = 4
BTS_PORT = 8080
NONCE_LEN = 11
D2D_PORT = 9000
times = []


def reset_hash(dev, msg):
    dev.hash_fun = hashlib.sha256()
    dev.hash_fun.update(msg)


class SensorThread(threading.Thread):
    def __init__(self, dev, sensor_address, sensor_socket):
        threading.Thread.__init__(self)
        self.socket = sensor_socket
        self.dev = dev
        # crypto settings
        self.sensor_address = sensor_address

    def run(self):
        print("Connection from : ", self.sensor_address)
        token, caller_id = self.dev.wait_token()
        if caller_id != 'base_station':
            self.dev.wu_protocol(token, caller_id)
            if not __debug__:
                print(Fore.MAGENTA+"COMPUTATION TIME: ",
                      self.dev.mr.computation_time, Fore.WHITE)
                times.append(self.dev.mr.computation_time)
                self.dev.mr.computation_time = 0
            for _ in range(CALLS-1):
                token, caller_id = self.dev.wait_token()
                self.dev.wu_protocol(token, caller_id)
                if not __debug__:
                    print(Fore.MAGENTA+"COMPUTATION TIME: ",
                          self.dev.mr.computation_time, Fore.WHITE)
                    times.append(self.dev.mr.computation_time)
                    self.dev.mr.computation_time = 0
            print('Connection from : ', self.sensor_address, ' closed')
            if not __debug__:
                print(Fore.MAGENTA+"Times: ",
                      times, Fore.WHITE)
            # wait input before starting kerberos
            # input()
            # ----------------------- time check -----------------------
            if not __debug__:
                t = time.time()
            # ----------------------------------------------------------
            id, d2d_key = self.dev.kerberos_protocol()
            # ----------------------- time check -----------------------
            if not __debug__:
                self.dev.mr.assisted_time += time_check(t)
                print(Fore.MAGENTA+"ASSISTED D2D TIME: ",
                      self.dev.mr.assisted_time, Fore.WHITE)
            # ----------------------------------------------------------
            print('Communication to BTS closed, waiting for D2D...')
            sock = self.dev.d2d(id, d2d_key)
            d2d_key = self.dev.unassisted_d2d(sock, d2d_key)
        else:
            print('Communication to BTS closed, starting D2D...')
            self.dev.start_d2d(token)


class Device():
    def __init__(self) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket .bind((LOCALHOST, OWN_PORT))
        print("\nCluster head started\nWaiting for a wake up call..")

    def start(self):
        while True:
            self.socket.listen(1)
            sensor_sock, sensor_address = self.socket.accept()
            self.mr = self.Main_Radio(sensor_sock)
            self.wur = self.WakeUp_Radio(sensor_sock, self.mr.token_dict)
            newthread = SensorThread(self, sensor_address, sensor_sock)
            newthread.start()

    def wait_token(self):
        token = self.wur.recv_token()
        print(Fore.YELLOW+"Token received :", token, Fore.WHITE)
        # ----------------------- time check -----------------------
        if not __debug__:
            t = time.time()
        # ----------------------------------------------------------
        caller_id = self.wur.verify_token(token)
        # ----------------------- time check -----------------------
        if not __debug__:
            self.mr.computation_time += time_check(t)
        # ----------------------------------------------------------

        return token, caller_id

    def wu_protocol(self, token, caller_id):
        print("ID of the sender :", caller_id)
        self.mr.send_ack_of_wuc(token)
        last_msg, seq_num = self.mr.recv_notification()
        self.mr.send_ack_of_msg(seq_num)
        token = self.mr.update_token(last_msg, caller_id, token, self.wur)

    def kerberos_protocol(self):
        # socket settings
        ssocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssocket.connect((LOCALHOST, BTS_PORT))

        # crypto settings
        k_a = BTS_KEY
        # nonce = os.urandom(16)
        # cipher = AES.new(k_a, AES.MODE_CCM, nonce)

        # sending node ID (16 bits)
        node_id = str(OWN_PORT).encode()
        print('sending ID ...')
        send_value(ssocket, node_id)

        # receiving session key
        data = recv_value(ssocket, BLOCK_LEN*2+NONCE_LEN)
        data, nonce = data[:-NONCE_LEN], data[-NONCE_LEN:]
        cipher = reset_cipher(k_a, nonce)
        s_key = cipher.decrypt_and_verify(data[:BLOCK_LEN], data[BLOCK_LEN:])
        print(Fore.RED+"Session key :", s_key, Fore.WHITE)

        # sending authenticator
        s_cipher, nonce = reset_cipher(s_key)
        timestamp = int(time.time())
        if not __debug__:
            print(f'timestamp: {timestamp}')
        auth, mac = s_cipher.encrypt_and_digest(
            pad(long_to_bytes(timestamp), 16))
        print('sending authenticator...')
        send_value(ssocket, auth+mac+nonce)

        # receiving IDs and keys
        # 20 bytes for each node (4 id + 16 key) +16 bytes MAC + 16 bytes padding + 11 bytes nonce
        # ----------------------- time check -----------------------
        if not __debug__:
            t = time.time()
        # ----------------------------------------------------------
        data = recv_value(ssocket, (N_NEIGHBORS+1) *
                          (KEY_LEN+PORT_LEN)+BLOCK_LEN*2+NONCE_LEN)
        data, nonce = data[:-NONCE_LEN], data[-NONCE_LEN:]
        s_cipher = reset_cipher(s_key, nonce)  # reset cipher
        ids_and_keys = s_cipher.decrypt_and_verify(
            data[:-BLOCK_LEN], data[-BLOCK_LEN:])
        ids_and_keys = unpad(ids_and_keys, BLOCK_LEN)
        # each neighbors correspond to 16 bytes of key + 4 of ID = 20 bytes
        neighbors_number = len(ids_and_keys)//(BLOCK_LEN+PORT_LEN)
        ids = ids_and_keys[:PORT_LEN*neighbors_number]
        keys = ids_and_keys[PORT_LEN*neighbors_number:]
        # ----------------------- time check -----------------------
        if not __debug__:
            print(Fore.MAGENTA+f"COMPUTATION TIME WITH {N_NEIGHBORS+1} NEIGHBORS: ",
                  time_check(t), Fore.WHITE)
        # ----------------------------------------------------------

        print(Fore.RED+"Neighbors data :")
        print('IDs: ', ids)
        print('Keys: ', keys, Fore.WHITE)
        ssocket.close()

        # According to the scope of the project only the
        # communication with 1 neighbor is implemented

        return ids[:PORT_LEN], keys[:KEY_LEN]

    def start_d2d(self, token):
        # last part of kerberos
        # ----------------------- time check -----------------------
        if not __debug__:
            t = time.time()
        # ----------------------------------------------------------
        self.mr.send_ack_of_wuc(token)
        d2d_key, auth, id = self.mr.recv_ticket_and_auth()
        self.mr.send_ack_of_auth(d2d_key, auth)
        # ----------------------- time check -----------------------
        if not __debug__:
            self.mr.assisted_time += time_check(t)
            print(Fore.MAGENTA+"ASSISTED D2D TIME: ",
                  self.mr.assisted_time, Fore.WHITE)
        # ----------------------------------------------------------
        # Starting actual d2d
        ch_sock = self.mr.connect_to_ch(id)
        self.mr.send_d2d_data(ch_sock, d2d_key)
        self.mr.recv_d2d_data(ch_sock, d2d_key)
        # ----------------------- time check -----------------------
        if not __debug__:
            t = time.time()
        # ----------------------------------------------------------
        new_key, token_id = self.mr.send_resumption_data(d2d_key, ch_sock)
        self.mr.resume_conn(ch_sock, token_id)
        # ----------------------- time check -----------------------
        if not __debug__:
            print(Fore.MAGENTA+"UNASSISTED D2D TIME: ",
                  time_check(t), Fore.WHITE)
        # ----------------------------------------------------------
        self.mr.send_d2d_data(ch_sock, new_key)
        self.mr.recv_d2d_data(ch_sock, new_key)

        print("Closing connection with ch")
        ch_sock.close()
        return new_key

    def d2d(self, id, d2d_key):
        ch_sock = self.mr.wait_d2d(self.socket)
        self.mr.recv_d2d_data(ch_sock, d2d_key)
        self.mr.send_d2d_data(ch_sock, d2d_key)
        # ----------------------- time check -----------------------
        if not __debug__:
            t = time.time()
        # ----------------------------------------------------------
        self.mr.recv_resumption_data(d2d_key, ch_sock)
        # ----------------------- time check -----------------------
        if not __debug__:
            self.mr.unassisted_time += time_check(t)
            print(Fore.MAGENTA+"UNASSISTED D2D TIME: ",
                  self.mr.unassisted_time, Fore.WHITE)
        # ----------------------------------------------------------
        return ch_sock

    def unassisted_d2d(self, ch_sock, old_key):
        # ----------------------- time check -----------------------
        if not __debug__:
            t = time.time()
        # ----------------------------------------------------------
        d2d_key = self.mr.gen_new_key(ch_sock, old_key)
        # ----------------------- time check -----------------------
        if not __debug__:
            self.mr.unassisted_time += time_check(t)
            print(Fore.MAGENTA+"UNASSISTED D2D TIME: ",
                  self.mr.unassisted_time, Fore.WHITE)
        # ----------------------------------------------------------
        self.mr.recv_d2d_data(ch_sock, d2d_key)
        self.mr.send_d2d_data(ch_sock, d2d_key)
        print("Closing connection with ch")
        return d2d_key

    class WakeUp_Radio():
        def __init__(self, socket, token_dict) -> None:
            self.socket = socket
            self.token_dict = token_dict

        def recv_token(self):
            token = recv_value(self.socket, 2)
            return token

        def verify_token(self, token):
            if token in self.token_dict:
                return self.token_dict[token]
            else:
                if not __debug__:
                    print('Error token not correct - received token: ',
                          token, ' List of valid tokens: ', self.token_dict)
                exit(0)

    class Main_Radio():
        def __init__(self, socket) -> None:
            self.socket = socket
            if not __debug__:
                self.unassisted_time = 0
                self.assisted_time = 0
                self.computation_time = 0
            # crypto settings
            self.enc_key = b'Sixteen byte key'
            self.nonce = b'a'*11

            # first encryption takes longer time for some reason,
            # so the following line is useless, but for evaluation purposes
            if not __debug__:
                self.cipher = AES.new(self.enc_key, AES.MODE_CCM, self.nonce)

            # ----------------------- time check -----------------------
            if not __debug__:
                t = time.time()
            # ----------------------------------------------------------
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
            # ----------------------- time check -----------------------
            if not __debug__:
                self.computation_time += time_check(t)
            # ----------------------------------------------------------
            if not __debug__:
                print('---------------------')
                print(self.token_dict)
                print('---------------------')

            # Table used to resume connection without bts assistance
            self.resumption_table = {}

        def send_ack_of_wuc(self, token):
            # ----------------------- time check -----------------------
            if not __debug__:
                t = time.time()
            # ----------------------------------------------------------
            # the ACK is the h(token||sequence) where sequence is a fixed sequence
            # of bits pre-shared by the parties. Here we choose to use the byte 'X'
            reset_hash(self, token+b'X')
            ack = self.hash_fun.digest()[:ID_LEN]
            # ----------------------- time check -----------------------
            if not __debug__:
                self.computation_time += time_check(t)
            # ----------------------------------------------------------
            print('sending ack of the token ...')
            send_value(self.socket, ack)

        def recv_notification(self):
            data = recv_value(self.socket, BLOCK_LEN*2+NONCE_LEN)

            # first encryption takes longer time for some reason,
            # so the following line is useless, but for evaluation purposes
            if not __debug__:
                tmp1, tmp2 = data[:-NONCE_LEN], data[-NONCE_LEN:]
                self.cipher = reset_cipher(self.enc_key, tmp2)
                msg = self.cipher.decrypt_and_verify(
                    tmp1[:BLOCK_LEN], tmp1[BLOCK_LEN:])

            # ----------------------- time check -----------------------
            if not __debug__:
                t = time.time()
            # ----------------------------------------------------------
            data, nonce = data[:-NONCE_LEN], data[-NONCE_LEN:]
            self.cipher = reset_cipher(self.enc_key, nonce)
            msg = self.cipher.decrypt_and_verify(
                data[:BLOCK_LEN], data[BLOCK_LEN:])
            msg = unpad(msg, 16)
            # first byte received is the temperature
            temp = msg[0]
            # ----------------------------------------------------
            #                 temperature checks
            # ----------------------------------------------------
            # second byte received is the sequence number
            seq_num = msg[1:3]
            # ----------------------- time check -----------------------
            if not __debug__:
                self.computation_time += time_check(t)
            # ----------------------------------------------------------
            print(Fore.GREEN+"Sensor data : temp = ", temp,
                  ' | seq_num = ', int.from_bytes(seq_num, 'big'), Fore.WHITE)
            return temp, seq_num

        def send_ack_of_msg(self, seq_num):
            ack = int.from_bytes(seq_num, 'big')+1
            print('ACK2: ', ack, '\n')
            send_value(self.socket, int.to_bytes(ack, 2, 'big'))

        def update_token(self, last_message, caller_id, old_token, wur):
            # ----------------------- time check -----------------------
            if not __debug__:
                t = time.time()
            # ----------------------------------------------------------
            self.token_dict.pop(old_token)
            reset_hash(self, old_token +
                       int.to_bytes(last_message, 1, 'big'))
            new_token = self.hash_fun.digest()[:ID_LEN]
            self.token_dict[new_token] = caller_id
            wur.token_dict = self.token_dict
            # ----------------------- time check -----------------------
            if not __debug__:
                self.computation_time += time_check(t)
            # ----------------------------------------------------------
            return new_token

        def recv_ticket_and_auth(self):
            data = recv_value(self.socket, BLOCK_LEN*4+NONCE_LEN)
            data, nonce = data[:-NONCE_LEN], data[-NONCE_LEN:]
            cipher = reset_cipher(BTS_KEY, nonce)
            data = cipher.decrypt_and_verify(
                data[:BLOCK_LEN*3], data[BLOCK_LEN*3:])
            # receive ID and key
            id_and_d2d_key = unpad(data[:BLOCK_LEN*2], 16)
            id, d2d_key = id_and_d2d_key[:PORT_LEN], id_and_d2d_key[PORT_LEN:]
            print(Fore.BLUE+"ID: ", id, Fore.WHITE)
            print(Fore.BLUE+"D2D KEY: ", d2d_key, Fore.WHITE)
            # receive authenticator
            auth = bytes_to_long(unpad(data[BLOCK_LEN*2:BLOCK_LEN*3], 16))
            print(Fore.BLUE+"Authenticator: ", auth, Fore.WHITE)
            if not is_auth_valid(auth):
                print("ERROR")
                exit(0)

            id = int(id.decode())
            return d2d_key, auth, id

        def send_ack_of_auth(self, key, auth):
            cipher, nonce = reset_cipher(key)
            ack = pad(long_to_bytes(auth+1), 16)
            ack, tag = cipher.encrypt_and_digest(ack)
            print('sending ack of the authenticator ...')
            send_value(self.socket, ack+tag+nonce)

        def connect_to_ch(self, id):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # TODO implement socket with id
            sock.connect((LOCALHOST, D2D_PORT))
            print("Connecting with sock ", sock.getsockname())
            return sock

        def wait_d2d(self, sock):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((LOCALHOST, D2D_PORT))
            sock.listen(1)
            clientsock, clientAddress = sock.accept()
            return clientsock

        def send_d2d_data(self, sock, d2d_key):
            data = pad(b'test', BLOCK_LEN)
            cipher, nonce = reset_cipher(d2d_key)
            enc_data, tag = cipher.encrypt_and_digest(data)
            send_value(sock, enc_data+tag+nonce)

        def recv_d2d_data(self, sock, d2d_key):
            data = recv_value(sock, BLOCK_LEN*2+NONCE_LEN)
            data, nonce = data[:-NONCE_LEN], data[-NONCE_LEN:]
            cipher = reset_cipher(d2d_key, nonce)
            data = cipher.decrypt_and_verify(
                data[:BLOCK_LEN], data[BLOCK_LEN:])
            print(Fore.BLUE+"D2D data: ", unpad(data, BLOCK_LEN), Fore.WHITE)

        def send_resumption_data(self, d2d_key, socket):
            res_nonce = os.urandom(16)
            token_id = os.urandom(1)

            cipher, nonce = reset_cipher(d2d_key)
            enc_data, tag = cipher.encrypt_and_digest(res_nonce+token_id)
            send_value(socket, enc_data+tag+nonce)

            new_key = HKDF(d2d_key, 32, res_nonce, SHA256)
            print(Fore.BLUE+"New key: ", new_key, Fore.WHITE)
            return new_key, token_id

        def recv_resumption_data(self, d2d_key, socket):
            data = recv_value(socket, BLOCK_LEN*2+1+NONCE_LEN)
            data, nonce = data[:-NONCE_LEN], data[-NONCE_LEN:]
            cipher = reset_cipher(d2d_key, nonce)
            data = cipher.decrypt_and_verify(
                data[:BLOCK_LEN+1], data[BLOCK_LEN+1:BLOCK_LEN*2+1])
            res_nonce, token_id = data[:16], data[-1]
            self.resumption_table[token_id] = res_nonce
            print(Fore.BLUE+"Resumption data: nonce= ",
                  res_nonce, ", id= ", token_id, Fore.WHITE)

        def resume_conn(self, socket, token_id):
            send_value(socket, token_id)
            print("Resuming connection...")

        def gen_new_key(self, socket, d2d_key):
            token_id = int.from_bytes(recv_value(socket, 1), 'big')
            print("Connection resumed...")

            if token_id in self.resumption_table:
                new_key = HKDF(
                    d2d_key, 32, self.resumption_table[token_id], SHA256)
                print(Fore.BLUE+"New key: ", new_key, Fore.WHITE)

                return new_key
            else:
                print("Resumption table: ", self.resumption_table)
                print("Error, resumption not possible")
                exit(1)

            # Create the parser
parser = argparse.ArgumentParser()
# Add an argument
parser.add_argument('--port', type=int, required=True)
parser.add_argument('--key', type=str, required=True)
# Parse the argument
args = parser.parse_args()

OWN_PORT = args.port
BTS_KEY = (args.key).encode()

ch = Device()
ch.start()
