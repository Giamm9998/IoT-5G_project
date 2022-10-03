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
nonce = b'a'*11
cipher = AES.new(key, AES.MODE_CCM, nonce)

# sending node ID
node_id = os.urandom(2)
client.sendall(node_id)

# receiving session key
data = client.recv(1024).split(b'|')
s_key = cipher.decrypt(data[0])
# cipher.update(s_key)
# MAC verification
try:
    cipher.verify(data[1])
except ValueError:
    print('MAC ERROR')
    exit(0)
print(Fore.RED+"From Server :", s_key, Fore.WHITE)
s_cipher = AES.new(s_key, AES.MODE_CCM, nonce)

# sending authenticator
timestamp = int(time.time())
print(f'timestamp: {timestamp}')
# cipher.update(long_to_bytes(timestamp))
auth = s_cipher.encrypt(
    pad(long_to_bytes(timestamp), 16))+b'|'+s_cipher.digest()
client.send(auth)
s_cipher = AES.new(s_key, AES.MODE_CCM, nonce)  # reset cipher

# receiving IDs and keys
data = client.recv(1024).split(b'|')
data_decrypted = unpad(s_cipher.decrypt(data[0]), 16)
# cipher.update(data_decrypted)
ids = data_decrypted.split(b'|')[0].split(b',')
keys = data_decrypted.split(b'|')[1].split(b',')
try:
    s_cipher.verify(data[1])
except ValueError:
    print('MAC ERROR')
    exit(0)
print(Fore.RED+"From Server :")
print('IDs: ', ids)
print('Keys: ', keys, Fore.WHITE)


client.close()
