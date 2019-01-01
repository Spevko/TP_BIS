import tkinter as tk
from tkinter import simpledialog as sd
from tkinter import filedialog as fd
from tkinter import messagebox as mb
import os
from AES import aes_enc as cr
from paramiko.ssh_exception import SSHException


class App:

    def __init__(self):
        self._root = tk.Tk()
        self._root.title("TP - BIS - 2018")
        self._root.geometry('350x320')
        self._main_label = tk.Label(self._root, text="choose wisely...", font="Helvetica 12 bold")
        self._main_label.pack()
        self._remote = tk.Button(self._root, text="configure remote", command=self._config_remote, width=15)
        self._remote.pack()
        self._remote_info = tk.Button(self._root, text="remote info", command=self._show_remote, width=15)
        self._remote_info.pack()
        self._remote_configured = False
        self._remote_ip = 0
        self._remote_user = ""
        self._label1 = tk.Label(self._root, text="image encryption", font="Helvetica 12 bold")
        self._label1.pack()
        self._keys_button = tk.Button(self._root, text="generate rsa keys", command=self._generate_keys, width=15)
        self._keys_button.pack()
        self._encrypt_button = tk.Button(self._root, text="encrypt file", command=self._encrypt_file, width=15)
        self._encrypt_button.pack()
        self._encrypt_batch_button = tk.Button(self._root, text="encrypt directory", command=self._encrypt_file, width=15)
        self._encrypt_batch_button.pack()
        self._decrypt_button = tk.Button(self._root, text="decrypt file", command=self._decrypt_file, width=15)
        self._decrypt_button.pack()
        self._label2 = tk.Label(self._root, text="image hashing", font="Helvetica 12 bold")
        self._label2.pack()
        self._hash_button = tk.Button(self._root, text="create image hash", command=self._generate_keys, width=15)
        self._hash_button.pack()
        self._compare_button = tk.Button(self._root, text="compare hashes", command=self._encrypt_file, width=15)
        self._compare_button.pack()
        #mb.askokcancel("WARNING!", "you are about to overwrite the original file\n(/home/jspevak/TP/testing/image.jpg)\nContinue?")

    def run(self):
        self._root.mainloop()

    def _config_remote(self):
        try:
            ip = sd.askstring("  ", "remote device IP:")
            user = sd.askstring("  ", "remote device user:")
        except Exception:
            print("ya fucked up")
            return
        self._remote_ip = ip
        self._remote_user = user
        self._remote_configured = True
        mb.showinfo("Remote device info", "{}@{}".format(self._remote_user, self._remote_ip))

    def _show_remote(self):
        if not self._remote_configured:
            s = "remote not configured"
        else:
            s = "{}@{}".format(self._remote_user, self._remote_ip)
        mb.showinfo("Remote device info", s)

    def _generate_keys(self):
        if not self._remote_configured:
            mb.showerror("ERROR", "remote device not configured!")
            return
        error = False
        files = False
        try:
            filename = fd.asksaveasfilename(title="save as", initialdir=os.getenv("HOME"))
            if not filename:
                raise ValueError("file name not provided!")
            out_file = filename
            cr.AesEnc.gen_rsa(out_file)
            files = True
            password = sd.askstring("    ", "remote device password:", show='*')
            if not password:
                raise ValueError("password not provided!")
            cr.AesEnc.scp_to_remote("{}_private".format(filename),
                                    "not_keys/{}_private".format(os.path.split(filename)[1]),
                                    self._remote_ip, self._remote_user, password)
            print("done")
        except ValueError as err:
            print(err.args)
            mb.showerror("ERROR", err.args[0])
            error = True
        except SSHException:
            print("SSH connection to remote {}@{} failed!".format(self._remote_user, self._remote_ip))
            mb.showerror("ERROR", "SSH connection to remote {}@{} failed!".format(self._remote_user, self._remote_ip))
            error = True

        if files:
            os.remove("{}_private".format(filename))
            if error:
                os.remove("{}_public".format(filename))
                return
        if not error:
            mb.showinfo("done", "public-private key pair\n'{}'\ncreated in {}".format(os.path.split(filename)[1],
                                                                                os.path.split(filename)[0]))

    @staticmethod
    def _encrypt_file():
        try:
            filename = fd.askopenfilename(title="select file to encrypt", initialdir=os.getenv("HOME"))
            rsa_key = fd.askopenfilename(title="select public key", initialdir=os.getenv("HOME"))
            path = fd.asksaveasfilename(title="save as", initialdir=os.getenv("HOME"))
            key_file = os.path.join("{}_key".format(path))
            enc_file = os.path.join(path)
            cr.AesEnc.create_key(key_file)
            cr.AesEnc.encrypt(filename, key_file, enc_file, "ctr")
            cr.AesEnc.rsa_encrypt(key_file, rsa_key, key_file)
            print("done")
        except Exception:
            print("ya fucked up")

    def _decrypt_file(self):
        if not self._remote_configured:
            print("remote not configured")
            return
        try:
            filename = fd.askopenfilename(title="select file to decrypt", initialdir=os.getenv("HOME"))
            key_name = fd.askopenfilename(title="select key file", initialdir=os.getenv("HOME"))
            path = fd.askdirectory(title="select target directory", initialdir=os.getenv("HOME"))
            rsa_file = sd.askstring("Pretty Little String Dialog", "RSA private key name")
            password = sd.askstring("Pretty Little String Dialog", "remote device password", show='*')
            cr.AesEnc.scp_from_remote("not_keys/{}_private".format(rsa_file), os.path.join(path, "private.pem"),
                                      self._remote_ip, self._remote_user, password)
            cr.AesEnc.rsa_decrypt(key_name, os.path.join(path, "private.pem"), os.path.join(path, "key_file"))
            cr.AesEnc.decrypt(filename, os.path.join(path, "key_file"), os.path.join(path, "outfile"), "ctr")
            os.remove(os.path.join(path, "private.pem"))
            os.remove(os.path.join(path, "key_file"))
            print("done")
        except Exception:
            print("ya fucked up")
