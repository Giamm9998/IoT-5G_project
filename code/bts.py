import hashlib
from colorama import Fore
import socket
import threading
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes, bytes_to_long
import os
from Crypto.Util.Padding import pad, unpad
import time
from my_utils import send_value, recv_value, is_auth_valid, reset_cipher

TIME_THRESHOLD = 5
KEY_LEN = 16
ID_LEN = 2  # address has 2 bytes
ENC_PLUS_TAG_LEN = 32
BLOCK_LEN = 16
LOCALHOST = "127.0.0.1"
N_PORT = 8082
PORT_LEN = 4


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
        exit(0)
        # handle error
    s_cipher = reset_cipher(s_key, server.nonce)  # reset cipher

    # send IDs and keys
    id1, id2 = b'8082', os.urandom(PORT_LEN)
    print(id1+b' , '+id2)
    key1, key2 = b'1'*KEY_LEN, b'2'*KEY_LEN
    print(key1+b' , '+key2)
    data = id1+id2+key1+key2

    msg, mac = s_cipher.encrypt_and_digest(pad(data, BLOCK_LEN))
    print('sending ids and keys')
    send_value(server.csocket, msg+mac)
    print("Client at ", clientAddress, " disconnected...")

    # wait 5 seconds before wake up
    time.sleep(1)

    # wake up neighbor
    nsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    nsocket.connect((LOCALHOST, N_PORT))

    # token of the neghbor TODO implement a table for all neighbors? TODO Implement token update?
    # send token
    n_token_key = b'a'*16
    hasher = hashlib.sha256()
    hasher.update(n_token_key+str(N_PORT).encode())
    n_token = hasher.digest()[:2]
    send_value(nsocket, n_token)

    # receive ack
    ack = recv_value(nsocket, 2)
    print(Fore.BLUE+"ACK: ", ack, Fore.WHITE)
    hasher = hashlib.sha256()
    hasher.update(n_token+b'X')
    expected_ack = hasher.digest()[:ID_LEN]
    if ack != expected_ack:
        print("ACK not correct")
        exit(0)

    # send ticket and auth
    print('Sending ticket and auth')
    ticket = pad(b'8081'+key1, 16)
    k_b = b'fedcba9876543210'
    t_cipher = reset_cipher(k_b, server.nonce)
    auth = pad(long_to_bytes(time.time()), 16)
    ticket, tag = t_cipher.encrypt_and_digest(ticket+auth)
    send_value(nsocket, ticket+tag)

    # receive ack
    data = recv_value(nsocket, BLOCK_LEN*2)
    a_cipher = reset_cipher(key1, server.nonce)
    ack = a_cipher.decrypt_and_verify(data[:BLOCK_LEN], data[BLOCK_LEN:])
    ack = bytes_to_long(unpad(ack, 16))
    print(Fore.BLUE+"Authenticator + 1: ", ack, Fore.WHITE)
    auth = bytes_to_long(unpad(auth, 16))
    if ack != (auth+1):
        print('Wrong authenticator')
        exit(0)

    print('Connection with ', LOCALHOST, ':', N_PORT, ' closed')


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
        print()


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
