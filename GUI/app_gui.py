import tkinter as tk
from tkinter import simpledialog as sd
from tkinter import filedialog as fd
from tkinter import messagebox as mb
import os
from Security import sec as cr
from Hash import Hash as hs
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
        self._encrypt_batch_button = tk.Button(self._root, text="encrypt directory", command=self._encrypt_dir, width=15)
        self._encrypt_batch_button.pack()
        self._decrypt_button = tk.Button(self._root, text="decrypt file", command=self._decrypt_file, width=15)
        self._decrypt_button.pack()
        self._label2 = tk.Label(self._root, text="image hashing", font="Helvetica 12 bold")
        self._label2.pack()
        self._hash_button = tk.Button(self._root, text="create image hash", command=self._file_hash, width=15)
        self._hash_button.pack()
        self._compare_button = tk.Button(self._root, text="compare hashes", command=self._compare_hash, width=15)
        self._compare_button.pack()

    def run(self):
        self._root.mainloop()

    def _config_remote(self):
        try:
            ip = sd.askstring("  ", "remote device IP:")
            if not ip:
                raise ValueError("IP address not provided!")
            user = sd.askstring("  ", "remote device user:")
            if not user:
                raise ValueError("username not provided!")
        except ValueError as err:
            print(err.args)
            mb.showerror(err.args[0])
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
        filename = ""
        try:
            filename = fd.asksaveasfilename(title="save as", initialdir=os.getenv("HOME"))
            if not filename:
                raise ValueError("file name not provided!")
            cr.Sec.gen_rsa(filename)
            password = sd.askstring("    ", "remote device password:", show='*')
            if not password:
                raise ValueError("password not provided!")
            cr.Sec.scp_to_remote("{}_private".format(filename),
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

        if os.path.isfile("{}_private".format(filename)):
            os.remove("{}_private".format(filename))
            if error:
                os.remove("{}_public".format(filename))

        if not error:
            mb.showinfo("done", "public-private key pair\n'{}'\ncreated in {}".format(os.path.split(filename)[1],
                                                                                      os.path.split(filename)[0]))

    @staticmethod
    def _encrypt_file():
        try:
            filename = fd.askopenfilename(title="select file to encrypt", initialdir=os.getenv("HOME"))
            if not filename:
                raise ValueError("no file selected for encryption!")
            rsa_key = fd.askopenfilename(title="select public key", initialdir=os.getenv("HOME"))
            if not rsa_key:
                raise ValueError("no RSA key file selected!")
            path = fd.asksaveasfilename(title="save as", initialdir=os.getenv("HOME"))
            if not path:
                raise ValueError("no path provided!")
            if filename == path:
                r = mb.askokcancel("WARNING!",
                                   "You are about to overwrite the original file\n({})\nContinue?".format(filename))
                if not r:
                    mb.showinfo(message="aborting")
                    return
            key_file = os.path.join("{}_key".format(path))
            enc_file = path
            cr.Sec.create_key(key_file)
            cr.Sec.encrypt(filename, key_file, enc_file, "ctr")
            cr.Sec.rsa_encrypt(key_file, rsa_key, key_file)
            print("done")
        except ValueError as err:
            print(err.args)
            mb.showerror(err.args[0])
            return

        mb.showinfo("done", "file '{}' encrypted,\nsaved as '{}'".format(filename, enc_file))

    @staticmethod
    def _encrypt_dir():
        try:
            dirname = fd.askdirectory(title="select directory to encrypt", initialdir=os.getenv("HOME"))
            if not dirname:
                raise ValueError("no directory selected for encryption!")
            rsa_key = fd.askopenfilename(title="select public key", initialdir=os.getenv("HOME"))
            if not rsa_key:
                raise ValueError("no RSA key file selected!")
            path = fd.askdirectory(title="save to", initialdir=os.getenv("HOME"))
            if not path:
                raise ValueError("no path provided!")
            if dirname == path:
                r = mb.askokcancel("WARNING!",
                                   "You are about to overwrite the original files in\n({})\nContinue?".format(dirname))
                if not r:
                    mb.showinfo(message="aborting")
                    return
            file_list = os.listdir(dirname)
            if not file_list:
                mb.showinfo("info", "directory '{}' contains no files".format(dirname))
                return
            for item in file_list:
                if os.path.isfile(os.path.join(dirname, item)):
                    key_file = os.path.join(path, "{}_key".format(item))
                    enc_file = os.path.join(path, item)
                    cr.Sec.create_key(key_file)
                    cr.Sec.encrypt(os.path.join(dirname, item), key_file, enc_file, "ctr")
                    cr.Sec.rsa_encrypt(key_file, rsa_key, key_file)
            print("done")
        except ValueError as err:
            print(err.args)
            mb.showerror(err.args[0])
            return

        mb.showinfo("done", "files in '{}' encrypted,\nsaved in '{}'".format(dirname, path))

    def _decrypt_file(self):
        if not self._remote_configured:
            mb.showerror("ERROR", "remote device not configured!")
            return
        try:
            filename = fd.askopenfilename(title="select file to decrypt", initialdir=os.getenv("HOME"))
            if not filename:
                raise ValueError("no encrypted file selected!")
            key_name = fd.askopenfilename(title="select key file", initialdir=os.getenv("HOME"))
            if not key_name:
                raise ValueError("no key file selected!")
            path = fd.askdirectory(title="select target directory", initialdir=os.getenv("HOME"))
            if not path:
                raise ValueError("target directory not provided!")
            rsa_file = sd.askstring("  ", "RSA private key name (without _private)")
            if not rsa_file:
                raise ValueError("RSA key file name not provided!")
            password = sd.askstring("  ", "remote device password", show='*')
            if not password:
                raise ValueError("password not provided!")
            cr.Sec.scp_from_remote("not_keys/{}_private".format(rsa_file), os.path.join(path, "private.pem"),
                                   self._remote_ip, self._remote_user, password)
            cr.Sec.rsa_decrypt(key_name, os.path.join(path, "private.pem"), os.path.join(path, "key_file"))
            cr.Sec.decrypt(filename, os.path.join(path, "key_file"), os.path.join(path, os.path.split(
                filename)[1]), "ctr")
            os.remove(os.path.join(path, "private.pem"))
            os.remove(os.path.join(path, "key_file"))
            print("done")
        except ValueError as err:
            print(err.args)
            mb.showerror(err.args[0])
            return
        except SSHException:
            print("SSH connection to remote {}@{} failed!".format(self._remote_user, self._remote_ip))
            mb.showerror("ERROR", "SSH connection to remote {}@{} failed!".format(self._remote_user, self._remote_ip))
            return

        mb.showinfo("done", "file '{}' decrypted, saved as '{}'".format(filename, os.path.join(
            path, os.path.split(filename)[1])))

    @staticmethod
    def _file_hash():
        try:
            filename = fd.askopenfilename(title="select file to hash", initialdir=os.getenv("HOME"))
            if not filename:
                raise ValueError("no file selected for encryption!")
            path = fd.asksaveasfilename(title="save as", initialdir=os.getenv("HOME"))
            if not path:
                raise ValueError("no path provided!")
            if filename == path:
                r = mb.askokcancel("WARNING!",
                                   "You are about to overwrite the original file\n({})\nContinue?".format(filename))
                if not r:
                    mb.showinfo(message="aborting")
                    return
            val = hs.Hash.img_hash(filename, hash_size=64)
            f = open(path, "w")
            f.write(val)
            f.close()
        except ValueError as err:
            print(err.args)
            mb.showerror(err.args[0])
            return

        mb.showinfo("done", "hash of file '{}' saved in '{}'".format(filename, path))

    @staticmethod
    def _compare_hash():
        try:
            fn1 = fd.askopenfilename(title="select first file", initialdir=os.getenv("HOME"))
            if not fn1:
                raise ValueError("no file selected!")
            fn2 = fd.askopenfilename(title="select second file", initialdir=os.getenv("HOME"))
            if not fn2:
                raise ValueError("no file selected!")
            f1 = open(fn1)
            f2 = open(fn2)
            s1 = f1.read()
            s2 = f2.read()
            f1.close()
            f2.close()
            ret_val = hs.Hash.similar_per(s1, s2)
            mb.showinfo("done", "files '{}' and '{}' match rate:\n{} %".format(fn1, fn2, ret_val))
        except ValueError as err:
            print(err.args)
            mb.showerror(err.args[0])
            return
