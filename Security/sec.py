from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util import Counter
import hashlib
import os
import string
import random
import paramiko
from paramiko.ssh_exception import SSHException


# All file arguments should contain full path to file
class Sec:

    @staticmethod
    def gen_rsa(file_name):
        key = RSA.generate(4096)
        f = open("{}_private".format(file_name), "wb+")
        f.write(key.exportKey(format='PEM'))
        f.close()
        f = open("{}_public".format(file_name), "wb+")
        f.write(key.publickey().exportKey(format='PEM'))
        f.close()

    @staticmethod
    def rsa_encrypt(in_file, key_file, out_file):

        f = open(key_file, "rb")
        key_str = f.read()
        f.close()

        key = RSA.importKey(key_str)

        f = open(in_file, "rb")
        text = f.read()
        f.close()
        enc = PKCS1_OAEP.new(key)
        ct = enc.encrypt(text)
        f = open(out_file, "wb")
        f.write(ct)
        f.close()

    @staticmethod
    def rsa_decrypt(in_file, key_file, out_file):

        f = open(key_file, "rb")
        key_str = f.read()
        f.close()

        key = RSA.importKey(key_str)

        f = open(in_file, "rb")
        text = f.read()
        f.close()
        dec = PKCS1_OAEP.new(key)
        pt = dec.decrypt(text)
        f = open(out_file, "wb")
        f.write(pt)
        f.close()

    @staticmethod
    def create_key(file_name, password=''):
        password = password or ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(16))
        key = hashlib.sha256(password.encode("utf8")).digest()
        ctr_iv = os.urandom(32)

        f = open(file_name, "wb+")
        f.write(key)
        f.write("------------".encode("utf8"))
        f.write(ctr_iv)
        f.close()

    @staticmethod
    def encrypt(in_file, key_file, out_file, mode):

        f = open(key_file, "rb+")
        st = f.read()
        f.close()
        s = st.split("------------".encode("utf8"))
        key = s[0][:32]
        ctr_iv = s[1][:16]

        if mode == 'ctr':
            ctr = Counter.new(128, initial_value=int.from_bytes(ctr_iv, byteorder='big'))
            encr = AES.new(key, 6, counter=ctr)
        else:
            encr = AES.new(key, 3, IV=ctr_iv)

        f = open(in_file, "rb")
        text = f.read()
        f.close()
        ct = encr.encrypt(text)
        f = open(out_file, "wb")
        f.write(ct)
        f.close()

    @staticmethod
    def decrypt(in_file, key_file, out_file, mode):

        f = open(key_file, "rb+")
        st = f.read()
        f.close()
        s = st.split("------------".encode("utf8"))
        key = s[0][:32]
        ctr_iv = s[1][:16]

        if mode == 'ctr':
            ctr = Counter.new(128, initial_value=int.from_bytes(ctr_iv, byteorder='big'))
            decr = AES.new(key, 6, counter=ctr)
        else:
            decr = AES.new(key, 3, IV=ctr_iv)

        f = open(in_file, "rb")
        text = f.read()
        f.close()
        ct = decr.decrypt(text)
        f = open(out_file, "wb")
        f.write(ct)
        f.close()

    @staticmethod
    def scp_to_remote(loc_file, remote_file, remote_ip, remote_user, remote_password):
        try:
            ssh = paramiko.SSHClient()
            ssh.load_system_host_keys()
            ssh.connect(remote_ip, username=remote_user, password=remote_password, timeout=30)
            sftp = ssh.open_sftp()
            sftp.put("{}".format(loc_file), "{}".format(remote_file))
            sftp.close()
            ssh.close()
        except Exception:
            raise SSHException()

    @staticmethod
    def scp_from_remote(remote_file, loc_file, remote_ip, remote_user, remote_password):
        try:
            ssh = paramiko.SSHClient()
            ssh.load_system_host_keys()
            ssh.connect(remote_ip, username=remote_user, password=remote_password, timeout=30)
            sftp = ssh.open_sftp()
            sftp.get("{}".format(remote_file), "{}".format(loc_file))
            sftp.close()
            ssh.close()
        except Exception:
            raise SSHException()
