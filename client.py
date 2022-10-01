import socket
import os
from colorama import Fore
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes, bytes_to_long
import time
from Crypto.Util.Padding import pad, unpad


# socket settings
SERVER = "127.0.0.1"
PORT = 8080
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((SERVER, PORT))

# crypto settings
key = b'0123456789abcdef'
iv = b'a'*16
cipher = AES.new(key, AES.MODE_CBC, iv)

# sending node ID
node_id = os.urandom(2)
client.sendall(node_id)

# receiving session key
s_key = client.recv(1024)
s_key = cipher.decrypt(s_key)
print(Fore.RED+"From Server :", s_key, Fore.WHITE)
s_cipher = AES.new(s_key, AES.MODE_CBC, iv)

# sending authenticator
timestamp = int(time.time())
print(f'timestamp: {timestamp}')
auth = s_cipher.encrypt(pad(long_to_bytes(timestamp), 16))
client.send(auth)
s_cipher = AES.new(s_key, AES.MODE_CBC, iv)  # reset cipher

# receiving IDs and keys
data = client.recv(1024)
data = unpad(s_cipher.decrypt(data), 16)
ids = data.split(b'|')[0].split(b',')
keys = data.split(b'|')[1].split(b',')
print(Fore.RED+"From Server :")
print('IDs: ', ids)
print('Keys: ', keys, Fore.WHITE)


client.close()
