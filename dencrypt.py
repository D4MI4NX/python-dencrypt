#!/usr/bin/env python3
# modules required: argparse, pycryptodome, tqdm, argon2, argon2-cffi, pwinput(optional)
import os, hashlib, argparse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from getpass import getpass
from tqdm import tqdm
import argon2

try:
    from pwinput import pwinput
    passinput = "pwinput"
except:
    passinput = "getpass"

#path = os.path.dirname(os.path.abspath(__file__))
#os.chdir(path)

path = os.getcwd()

verbose = True

parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument("-m", "--mode", action="store", help="Encrypt: e  Decrypt: d")
parser.add_argument("-ph", "--phash", action="store_true", help = "Print SHA-256 of password")
parser.add_argument("-sh", "--shash", action="store_true", help = "Save SHA-256 of password in a file")
parser.add_argument("-nh", "--nhash", action="store_true", help = "Dont ask about hashed password")
parser.add_argument("-op", "--otherpass", action="store_true", help = "Use other password than the one saved in .password.sha256")
parser.add_argument("-f", "--force", action="store_true", help = "Dont ask about en/decrypting files")
parser.add_argument("-F", "--file", action="store", help = "En/Decrypt only a single file")
parser.add_argument("-s", "--salt", action="store", help = "Specify file containing salt")
parser.add_argument("-ns", "--no-salt", action="store_true", help = "Disable salt in key generation")
args = parser.parse_args()

if args.salt is not None and not args.no_salt:
    if not os.path.isfile(args.salt):
        exit("File containing salt not found!")


def encrypt_file(key, file):
    with open(file, "rb") as f:
        plaintext = f.read()
    try:
        iv = os.urandom(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_plaintext = pad(plaintext, AES.block_size)
        ciphertext = cipher.encrypt(padded_plaintext)
        file_name, ext = os.path.splitext(file)
        new_file = file_name + ".enc" + ext
        with open(file, "wb") as f:
            f.write(iv + ciphertext)
        os.rename(file, new_file)
        return 0
    except KeyboardInterrupt:
        print("\nRestoring file...")
        with open(file, "wb") as f:
            f.write(plaintext)
        print(f"Restored {file}!")
        return 2
    except:
        return 1

def decrypt_file(key, file):
    with open(file, "rb") as f:
        ciphertext = f.read()
    iv = ciphertext[:16]
    _ciphertext = ciphertext[16:]
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_plaintext = cipher.decrypt(_ciphertext)
        plaintext = unpad(padded_plaintext, AES.block_size)
        file_name, ext = os.path.splitext(file)
        if "." in file_name:
            new_file = file_name[:-4] + ext
        else:
            new_file = file_name
        with open(file, "wb") as f:
            f.write(plaintext)
        os.rename(file, new_file)
        return 0
    except KeyboardInterrupt:
        print(f"\nRestoring {file}...")
        with open(file, "wb") as f:
            f.write(ciphertext)
        print(f"Restored {file}!")
        return 2
    except:
        return 1

def file_loop(files, _mode, key):
    error = False
    error_files = []
    if _mode == "e":
        for file in tqdm(files, desc="Encrypting files"):
            if verbose: print(f"Encrypting {file}...")
            func = encrypt_file(key, file)
            if func != 0:
                error = True
                error_files.append(file)
            if func == 1:
                print("Unknown error!")
            elif func == 2:
                exit()
            else:
                if verbose: print(f"Encrypted {file}!")

    if _mode == "d":
        for file in tqdm(files, "Decrypting files"):
            if verbose: print(f"Decrypting {file}...")
            func = decrypt_file(key, file)
            if func != 0:
                error = True
                error_files.append(file)
            if func == 1:
                print("Unknown error!")
            elif func == 2:
                exit()
            else:
                if verbose: print(f"Decrypted {file}!")

    if not error:
        print(f"Successfully {'encrypted' if _mode == 'e' else 'decrypted'} files!")
    if error:
        print(f"{error_files} {'have' if len(files) > 1 else 'has'} encountered an error!")

def gen_key(password, gensalt=False):
    if not args.no_salt:
        if args.salt is None:
            if os.path.isfile(".salt"):
                salt = open(".salt", "rb").read()
        else:
            if os.path.isfile(args.salt):
                salt = open(args.salt, "rb").read()
            else:
                exit(".salt doesnt exists! Try specifying the salt file with the -s option.")
        if gensalt and args.salt is None:
            salt = os.urandom(16)
            open(".salt", "wb").write(salt)
    key = argon2.hash_password_raw(password, salt=b"1234567890123456" if args.no_salt else salt, time_cost=32, memory_cost=131072)
    return key

def prompt_password():
    while True:
        global plain_pass
        global password
        password = pwinput("Password[max. 32 chars]: ") if passinput == "pwinput" else getpass("Password[max. 32 chars]: ")
        if len(password) > 32:
            print("Password cant be longer than 32 characters!")
        else:
            plain_pass = password
            password = bytes(password, "utf-8")
            break


files = []
enc_files = []
ignored_files = [os.path.basename(__file__), "dencrypt.py", "dencrypt.exe", "dencrypt", "dencrypt.c", "dencrypt_win.py", "dencrypt_argon2", "dencrypt_kdf2"]

for file in os.listdir():
    if file not in ignored_files and os.path.isfile(file) and not file.startswith("."):
        if ".enc" in file:
            enc_files.append(file)
        else:
            files.append(file)
    else:
        continue

if len(files) == 0 and len(enc_files) == 0:
    exit(f"No files found!")

mode = input("[E]ncrypt or [D]ecrypt?\n>") if args.mode is None and args.file is None else (args.mode if args.file is None else ("d" if ".enc" in args.file else "e"))
if mode.lower() not in ["e", "d"]:
    exit("[exited]")

if mode.lower() == "e":
    if len(enc_files) > 0 and len(files) == 0:
        exit("All files are already encrypted!")
    if args.file is not None:
        if os.path.isfile(args.file):
            files = [args.file]
        else:
            exit(f"{args.file} not found or doesnt exists!")
    prompt_password()
    pass_sha = hashlib.sha256(bytes(plain_pass, "utf-8")).hexdigest()
    if os.path.isfile(".password.sha256"):
        if open(".password.sha256", "r").read() != pass_sha and not args.otherpass:
            upa = input("Password is different from the one saved in .password.sha256.\nContinue? [y|n]\n>")
            if upa.lower() != "y":
                exit("[cancelled]")
            else:
                upa = False
        else:
            upa = True
    else:
        upa = False
    inp = input("Print SHA-256 or save SHA-256 of password to file? [y|s|n]\n>") if not args.phash and not args.shash and not args.nhash and not upa else ""
    if inp.lower() == "y" or args.phash:
        print("SHA-256:", pass_sha)
    if inp.lower() == "s" or args.shash:
        with open(".password.sha256", "w") as hashfile:
            hashfile.write(pass_sha)
        print(f"SHA-256 of password saved to {path}/.password.sha256!")

    print(files)
    inp = input("\nEncrypt these files? [y|n]\n>") if not args.force else "y"
    if inp.lower() != "y":
        exit("[cancelled]")
    print("Generating key...")
    key = gen_key(password, True if len(enc_files) == 0 else False)
    print("Key generated!")
    file_loop(files, "e", key)
if mode.lower() == "d":
    if len(enc_files) <= 0:
        exit("No files are encrypted!")
    files = enc_files
    if args.file is not None:
        if os.path.isfile(args.file):
            files = [args.file]
        else:
            exit(f"{args.file} not found or doesnt exists!")
    prompt_password()
    print(files)
    inp = input("\nDecrypt these files? [y|n]\n>") if not args.force else "y"
    if inp.lower() != "y":
        exit("[cancelled]")
    print("Generating key...")
    key = gen_key(password)
    print("Key generated!")
    file_loop(files, "d", key)