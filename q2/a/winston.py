import socket
import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES

key = 'asdfghjkl'



class AESCipher(object):

    def __init__(self, key): 
        self.bs = 32
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))


    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)



def send_message(ip, port):
    # Reimplement me! (b1)
    connection = socket.socket()
    try:
        connection.connect((ip, port))
        msg = 'I love you'
        aescipher = AESCipher(key)
        encrypt_msg = aescipher.encrypt(msg)

        connection.send(encrypt_msg)
    finally:
        connection.close()


def main():
    send_message('127.0.0.1', 1984)


if __name__ == '__main__':
    main()

