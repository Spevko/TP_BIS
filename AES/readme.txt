# supported modes for encrypt/decrypt are 'cfb' and 'ctr', others require input to be padded (which I can't be bothered to do...)
# requires pycrypto or pycryptodome library

# import as:

from aes_enc import AesEnc

# (or something along those lines)

# all 'file' arguments require the full path to files

# example of full encryption and decryption process:
    AesEnc.create_key("/tmp/crypto/key_file", "HereBePasswords")
    AesEnc.encrypt("/home/User/Images/input.jpg", "/tmp/crypto/key_file", "/tmp/crypto/enc_file", "ctr")

    --------------------------------

    AesEnc.decrypt("/tmp/crypto/enc_file", "/tmp/crypto/key_file", "/home/User/Images/output.jpg", "ctr")
