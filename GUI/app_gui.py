import tkinter as tk
from tkinter import simpledialog as sd
from tkinter import filedialog as fd
import os
from AES import aes_enc as cr


class App:

    def __init__(self):
        self._root = tk.Tk()
        self._main_label = tk.Label(self._root, text="do something")
        self._main_label.pack()
        self._keys_button = tk.Button(self._root, text="generate rsa keys", command=self._generate_keys)
        self._keys_button.pack()
        self._encrypt_button = tk.Button(self._root, text="encrypt file", command=self._encrypt_file)
        self._encrypt_button.pack()
        self._decrypt_button = tk.Button(self._root, text="decrypt file", command=self._decrypt_file)
        self._decrypt_button.pack()

    def run(self):
        self._root.mainloop()

    @staticmethod
    def _generate_keys():
        try:
            path = fd.askdirectory(title="select target directory", initialdir=os.getenv("HOME"))
            print("path: {}".format(path))
            filename = sd.askstring("Pretty Little String Dialog", "input name of key_file")
            print("filename: {}".format(filename))
            out_file = os.path.join(path, filename)
            print("out_file: {}".format(out_file))
            cr.AesEnc.gen_rsa(out_file)
            ip = sd.askstring("Pretty Little String Dialog", "remote device IP")
            print("ip: {}".format(ip))
            user = sd.askstring("Pretty Little String Dialog", "remote device user")
            print("user: {}".format(user))
            password = sd.askstring("Pretty Little String Dialog", "remote device password")
            print("password: {}".format(password))
            cr.AesEnc.scp_to_remote("{}_private".format(out_file), "not_keys/{}_private".format(filename), ip, user, password)
            os.remove(os.path.join(path, "{}_private".format(filename)))
            print("done")
        except Exception:
            print("ya fucked up")

    @staticmethod
    def _encrypt_file():
        try:
            filename = fd.askopenfilename(title="select file to encrypt", initialdir=os.getenv("HOME"))
            print("filename: {}".format(filename))
            rsa_key = fd.askopenfilename(title="select public key", initialdir=os.getenv("HOME"))
            print("public key: {}".format(rsa_key))
            path = fd.askdirectory(title="select target directory", initialdir=os.getenv("HOME"))
            print("path: {}".format(path))
            key_file = os.path.join(path, "{}_key".format(filename))
            enc_file = os.path.join(path, filename)
            cr.AesEnc.create_key(key_file)
            cr.AesEnc.encrypt(filename, key_file, enc_file, "ctr")
            cr.AesEnc.rsa_encrypt(key_file, rsa_key, key_file)
#            if filename != enc_file:
#                os.remove(filename)
            print("done")
        except Exception:
            print("ya fucked up")

    @staticmethod
    def _decrypt_file():
        try:
            filename = fd.askopenfilename(title="select file to decrypt", initialdir=os.getenv("HOME"))
            print("filename: {}".format(filename))
            key_name = fd.askopenfilename(title="select key file", initialdir=os.getenv("HOME"))
            print("key_name: {}".format(key_name))
            path = fd.askdirectory(title="select target directory", initialdir=os.getenv("HOME"))
            print("path: {}".format(path))
            rsa_file = sd.askstring("Pretty Little String Dialog", "RSA private key name")
            print("rsa_file: {}".format(rsa_file))
            ip = sd.askstring("Pretty Little String Dialog", "remote device IP")
            print("ip: {}".format(ip))
            user = sd.askstring("Pretty Little String Dialog", "remote device user")
            print("user: {}".format(user))
            password = sd.askstring("Pretty Little String Dialog", "remote device password")
            print("password: {}".format(password))
            cr.AesEnc.scp_from_remote("not_keys/{}".format(rsa_file), os.path.join(path, "private.pem"), ip, user, password)
            cr.AesEnc.rsa_decrypt(key_name, os.path.join(path, "private.pem"), os.path.join(path, "key_file"))
            cr.AesEnc.decrypt(filename, os.path.join(path, "key_file"), os.path.join(path, "outfile"), "ctr")
            os.remove(os.path.join(path, "private.pem"))
            os.remove(os.path.join(path, "key_file"))
            print("done")
        except Exception:
            print("ya fucked up")
