import time
from Crypto.Cipher import AES
from colorama import Fore
import os


NONCE_LEN = 11
TIME_THRESHOLD = 5
CALLS = 2


def is_auth_valid(timestamp):
    current_time = int(time.time())
    if not __debug__:
        print(
            f'Timestamp check => current time: {current_time}, timestamp: {timestamp}', end='')
    if current_time-timestamp > TIME_THRESHOLD:
        if not __debug__:
            print(' -> INVALID!')
        return False
    else:
        if not __debug__:
            print(' -> valid')
        return True


def reset_cipher(key, nonce=None):
    # We are encrypting, we need a new nonce
    if nonce == None:
        new_nonce = os.urandom(NONCE_LEN)
        cipher = AES.new(key, AES.MODE_CCM, new_nonce)
        return cipher, new_nonce
    # We are decrypting, we need to use the received nonce
    else:
        cipher = AES.new(key, AES.MODE_CCM, nonce)
        return cipher


def send_value(sock, value):
    if not __debug__:
        print(Fore.CYAN+f'sending {len(value)} bytes'+Fore.WHITE)
    if not __debug__:
        print(Fore.CYAN+f'sending val: ', value, Fore.WHITE)
    sock.send(value)


def recv_value(sock, size):
    data = sock.recv(size)
    if not __debug__:
        print(Fore.CYAN+f'value len: {size}'+Fore.WHITE)
    if not __debug__:
        print(Fore.CYAN+f'value received: ', data, Fore.WHITE)
    return data


def time_check(t):
    elapsed_time = (time.time()-t)
    print(Fore.MAGENTA, 'TIME CHECK ', elapsed_time, Fore.WHITE)
    return elapsed_time
