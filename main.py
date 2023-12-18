import hashlib

MD5_LENGTH = 32
SHA3_512_LENGTH = 128
SHA_256_LENGTH = 64

def file_to_list(file):
    with open(file, 'r') as f:
        return f.read().splitlines()

def crack_hash(hashed_password, wordlist):
    password_length = len(hashed_password)
    if password_length == MD5_LENGTH:
        format = "md5"
    elif password_length == SHA3_512_LENGTH:
        format = "sha3_512"
    elif password_length == SHA_256_LENGTH:
        format = "sha256"
        crack_hash = hashlib.sha256
    else:
        print("Nieznany format hasha")

wordlist = file_to_list("wordlist.txt")
hash = "e10adc3949ba59abbe56e057f20f883e"  
hash_type = "md5" 
        