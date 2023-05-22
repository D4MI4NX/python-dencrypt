#!/usr/bin/env python3
'''Dencrypt is a python script for file encryption and decryption. It uses AES encryption with CBC mode and Argon2 key derivation function for secure encryption.

Copyright (C) 2023  D4MI4NX

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation version 3.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>'''

# modules required: argparse, pycryptodome, tqdm, argon2-cffi, pwinput(optional)
import os, hashlib, argparse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from getpass import getpass
from tqdm import tqdm
import argon2
from glob import glob

try:
    from pwinput import pwinput
    passinput = "pwinput"
except:
    passinput = "getpass"

verbose = True
no_hash = False # Set to True if you dont wanna be asked about printing/storing the SHA-256 hashed password

parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument("-m", "--mode", action="store", help="Encrypt: e  Decrypt: d")
parser.add_argument("-ph", "--phash", action="store_true", help = "Print SHA-256 of password")
parser.add_argument("-sh", "--shash", action="store_true", help = "Save SHA-256 of password in a file")
parser.add_argument("-nh", "--nhash", action="store_true", help = "Dont ask about hashed password")
parser.add_argument("-op", "--other-pass", action="store_true", help = "Use other password than the one saved in .password.sha256")
parser.add_argument("-f", "--force", action="store_true", help = "Dont ask about en/decrypting files")
parser.add_argument("-F", "--file", action="store", help = "En/Decrypt only a single file")
parser.add_argument("-s", "--salt", action="store", help = "Specify file containing salt")
parser.add_argument("-ns", "--no-salt", action="store_true", help = "Disable salt in key generation")
parser.add_argument("-hs", "--home-salt", action="store_true", help = "Read or write salt from/to the home directory (~/.salt)")
parser.add_argument("-sd", "--script-dir", action="store_true", help = "Use the directory the script is stored in")
args = parser.parse_args()

if no_hash:
    args.nhash = True

if args.script_dir:
    path = os.path.dirname(os.path.abspath(__file__))
    os.chdir(path)
else:
    path = os.getcwd()
home_dir = os.path.expanduser("~")

if args.home_salt and args.salt is not None:
    exit("Use either -hs/--home-salt or -s/--salt, but not both!")

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
        print(f"\nRestoring {file}...")
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
        salt_file = ".salt" if not args.home_salt else f"{home_dir}/.salt"
        if args.salt is None:
            if os.path.isfile(salt_file):
                salt = open(salt_file, "rb").read()
        else:
            if os.path.isfile(args.salt):
                salt = open(args.salt, "rb").read()
            else:
                exit(".salt doesnt exists! Try specifying the salt file with the -s option.")
        if gensalt and args.salt is None:
            salt = os.urandom(16)
            open(salt_file, "wb").write(salt)
    key = argon2.hash_password_raw(password, salt=b"1234567890123456" if args.no_salt else salt, time_cost=32, memory_cost=131072)
    return key

def prompt_password(confirm=False):
    while True:
        global password
        global pass_sha
        pass_match = False
        password = pwinput("Password[max. 32 chars]: ") if passinput == "pwinput" else getpass("Password[max. 32 chars]: ")
        pass_sha = hashlib.sha256(bytes(password, "utf-8")).hexdigest()
        if len(password) > 32:
            print("Password cant be longer than 32 characters!")
            continue
        if os.path.isfile(".password.sha256") and mode == "e":
            if open(".password.sha256", "r").read() == pass_sha:
                confirm = False
            else:
                confirm = True
        if confirm:
            pass_confirm = pwinput("Confirm password: ") if passinput == "pwinput" else getpass("Confirm password: ")
            if password == pass_confirm and password != "":
                pass_match = True
            elif password == "" and pass_confirm == "":
                inp = input("[E]xit or [c]ontinue with empty password?\n>")
                if inp.lower() == "e":
                    exit("[exited]")
                elif inp.lower() == "c":
                    pass_match = True
                    print("Continueing with empty password!")
                else:
                    exit("[exited]")
            else:
                print("Passwords didnt match. Please try again.")
        if len(password) <= 32 and pass_match if confirm else True:
            password = bytes(password, "utf-8")
            break
        pass_match = False


files = []
enc_files = []
ignored_files = [os.path.basename(__file__), "dencrypt.py", "dencrypt.exe", "dencrypt", "dencrypt.c", "dencrypt_win.py", "dencrypt_argon2", "dencrypt_kdf2", "LICENSE", "README.md", "requirements.txt"]
mode_prompt = True

if args.file is None:
    for file in os.listdir():
        if file not in ignored_files and os.path.isfile(file) and not file.startswith("."):
            files.append(file)
else:
    if "*" in args.file:
        files = glob(args.file)
        for file in files.copy():
            if file in ignored_files or not os.path.isfile(file):
                files.remove(file)
    elif "," in args.file:
        files = args.file.split(",")
        for file in files.copy():
            if file in ignored_files or not os.path.isfile(file):
                files.remove(file)
    else:
        if ".enc" in args.file:
            mode = "d"
        else:
            mode = "e"
        if not os.path.isfile(args.file):
            exit(f"{args.file} not found!")
        files = [args.file]
        mode_prompt = False
    if len(files) == 1:
        if ".enc" in files[0]:
            mode = "d"
        else:
            mode = "e"
        mode_prompt = False

if len(files) == 0 and len(enc_files) == 0:
    exit(f"No files found!")

for file in files.copy():
    if ".enc" in file:
        enc_files.append(file)
        files.remove(file)

if len(files) > 0 and len(enc_files) < 1:
    mode = "e"
    mode_prompt = False
elif len(files) < 1 and len(enc_files) > 0:
    mode = "d"
    mode_prompt = False


if mode_prompt and args.mode is None:
    mode = input("[E]ncrypt or [D]ecrypt?\n>")
elif args.mode is not None:
    mode = args.mode
mode = mode.lower()

if mode.lower() not in ["e", "d"]:
    exit("[exited]")

if mode == "e" and len(files) < 1:
    exit("No selected files are not encrypted!")

if args.home_salt and mode == "d":
    if not os.path.isfile(f"{home_dir}/.salt"):
        exit(f"No salt found in {home_dir}/.salt !")

if mode.lower() == "e":
    if len(enc_files) > 0 and len(files) == 0:
        exit("All files are already encrypted!")
    prompt_password(confirm=True)
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
    prompt_password()
    print(files)
    inp = input("\nDecrypt these files? [y|n]\n>") if not args.force else "y"
    if inp.lower() != "y":
        exit("[cancelled]")
    print("Generating key...")
    key = gen_key(password)
    print("Key generated!")
    file_loop(files, "d", key)
