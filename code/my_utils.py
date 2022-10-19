import time
from Crypto.Cipher import AES
from colorama import Fore

TIME_THRESHOLD = 5


def is_auth_valid(timestamp):
    current_time = int(time.time())
    print(f'current time: {current_time}, timestamp: {timestamp}', end='')
    if current_time-timestamp > TIME_THRESHOLD:
        print(' -> INVALID!')
        return False
    else:
        print(' -> valid')
        return True


def reset_cipher(key, nonce):
    return AES.new(key, AES.MODE_CCM, nonce)


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
