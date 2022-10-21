import time
from Crypto.Cipher import AES
from colorama import Fore

TIME_THRESHOLD = 5


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


def reset_cipher(key, nonce):
    return AES.new(key, AES.MODE_CCM, nonce)


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
