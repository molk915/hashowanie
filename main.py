import hashlib
import sys

MD5_LENGTH = 32
SHA3_512_LENGTH = 128
SHA_256_LENGTH = 64

def file_to_list(file):
    with open(file, 'r') as f:
        return f.read().splitlines()

def crack_hash(hashed_password, wordlist):
    for password in wordlist:
        if hashed_password == hashlib.md5(password.encode()).hexdigest() and len(hashed_password) == MD5_LENGTH:
            return password, "md5"
        elif hashed_password == hashlib.sha3_512(password.encode()).hexdigest() and len(hashed_password) == SHA3_512_LENGTH:
            return password, "sha3_512"
        elif hashed_password == hashlib.sha256(password.encode()).hexdigest() and len(hashed_password) == SHA_256_LENGTH:
            return password, "sha256"
    return None, None

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Użycie: python main.py <hash> <wordlist>")
        sys.exit(1)

    hash_value = sys.argv[1]
    wordlist_file = sys.argv[2]

    if len(hash_value) == MD5_LENGTH:
        format_hash = "md5"
    elif len(hash_value) == SHA3_512_LENGTH:
        format_hash = "sha3_512"
    elif len(hash_value) == SHA_256_LENGTH:
        format_hash = "sha256"
    else:
        print("Nieznany format hasha")
        sys.exit(1)

    wordlist = file_to_list(wordlist_file)

    cracked_password, cracked_format = crack_hash(hash_value, wordlist)

    if cracked_password is not None:
        print(f"Hasło znalezione: {cracked_password}")
        print(f"Format hasha: {cracked_format}")
    else:
        print("Nie udało się złamać hasła.")
