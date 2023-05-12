# python-dencrypt
Dencrypt is a python script for file encryption and decryption. It uses AES encryption with CBC mode and Argon2 key derivation function for secure encryption.



# Prerequisites

Dencrypt requires the following modules to be installed:

    argparse
    pycryptodome
    tqdm
    argon2
    argon2-cffi
    pwinput (optional)

You can install these modules using pip:

pip install argparse pycryptodome tqdm argon2 argon2-cffi pwinput



# Usage

The script is fully interactive and can be run without any arguments. Run the script using the following command:

python dencrypt.py [options]



# Options

The script supports the following command-line options:

    -m, --mode: Specify the mode of operation. Use e for encryption and d for decryption.
    -ph, --phash: Print SHA-256 hash of the password.
    -sh, --shash: Save SHA-256 hash of the password in a file.
    -nh, --nhash: Don't ask about hashed password.
    -op, --otherpass: Use a password other than the one saved in .password.sha256.
    -f, --force: Don't ask about encrypting or decrypting files.
    -F, --file: Encrypt or decrypt a single file.
    -s, --salt: Specify a file containing the salt for key generation.
    -ns, --no-salt: Disable salt in key generation.

Note: If the pwinput module is not available, the script falls back to using getpass for password input.


# Encrypting Files

To encrypt files, use the following command:

python dencrypt.py -m e [options]

The script will prompt for a password (maximum 32 characters) and generate a key using Argon2 key derivation function. The generated key will be used for file encryption. By default, the script encrypts all files in the current directory, excluding certain ignored files such as hidden ones (files that start with a ´.´). You can also specify a single file to encrypt using the -F, --file option.

After entering the password, you will have the option to print the SHA-256 hash of the password or save it to a file. If you enter 'y', the script will print the SHA-256 hash of the password. If you enter 's', it will save the hash to a file named '.password.sha256' in the current directory. If you enter 'n', the script will continue without saving or printing the hash.

Saving the SHA-256 hash of the password can be useful when decrypting files and wanting to encrypt them again. If the entered password does not match the SHA-256 hash saved in '.password.sha256', the script will issue a warning, preventing accidental encryption with a mistyped password. However, note that storing the hash introduces the risk of someone potentially cracking the password if they gain access to the hash file.

Exercise caution when deciding whether to save the password hash, as it introduces a trade-off between convenience and security. If you don´t wanna be prompted for this, use the ´-nh´ option.



# Decrypting Files

To decrypt files, use the following command:

python dencrypt.py -m d [options]

The script will prompt for the password used for encryption and generate the key using Argon2. The generated key will be used for file decryption. By default, the script decrypts all encrypted files in the current directory. You can also specify a single file to decrypt using the -F, --file option.



# Notes

    If no files are found in the current directory or the specified files, the script will exit.
    If the password provided is different from the one saved in the .password.sha256 file (if exists), the script will prompt for confirmation before continuing.
    The script generates a 16-byte salt by default and saves it in the .salt file. You can specify a custom salt file using the -s, --salt option.
    Every time you encrypt one or all file(s) and no encrypted files are in the current directory, the script will generate new salt.
    The generated key is derived from the password and the salt using the Argon2 key derivation function.
    The encrypted files will have the extension .enc added to their original filenames.
    The decrypted files will have the .enc extension removed from their original filenames.
    If any errors occur during encryption or decryption, the script will display the error and restore the original files.
