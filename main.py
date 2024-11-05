import argparse
from colorama import Fore, init
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from hashlib import sha256
import os

# Definition of the version
PYKSPC_VERSION = "1.2-sh4"

init(autoreset=True)

# Utilities for encryption and decryption
def encrypt_file(file_path, key, keep_metadata, keep_format, keep_info, return_bool):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()

        # Extract metadata or use default values
        metadata, content = extract_metadata(data) if keep_metadata else (b'', data)

        # Add or modify the PyKspc field in the metadata if -Mi is specified
        if keep_info:
            metadata = update_metadata_info(metadata, True)

        cipher_content = aes_encrypt(content, key)

        # Change the extension if the keep_format option is not specified
        new_file_path = f"{file_path}.kspc" if not keep_format else file_path

        with open(new_file_path, 'wb') as f:
            f.write(metadata + cipher_content)

        # Delete the old file if the keep_format option is not specified
        if not keep_format:
            os.remove(file_path)

        if return_bool:
            print("true")
        else:
            print(Fore.GREEN + "[+] File encrypted and saved to " + new_file_path)
    except Exception as e:
        if return_bool:
            print("false")
        else:
            print(Fore.RED + f"[-] Error during encryption: {e}")

def decrypt_file(file_path, key, keep_metadata, keep_format, keep_info, return_bool):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()

        # Extract metadata or use default values
        metadata, content = extract_metadata(data) if keep_metadata else (b'', data)
        plain_content = aes_decrypt(content, key)

        # Remove the .kspc extension if the keep_format option is not specified
        new_file_path = file_path.replace(".kspc", "") if not keep_format else file_path

        with open(new_file_path, 'wb') as f:
            # Update the PyKspc field in the metadata if -Mi is specified
            if keep_info:
                metadata = update_metadata_info(metadata, False)

            f.write(metadata + plain_content)

        # Delete the old file if the keep_format option is not specified
        if not keep_format:
            os.remove(file_path)

        if return_bool:
            print("true")
        else:
            print(Fore.GREEN + "[+] File decrypted and saved to " + new_file_path)
    except Exception as e:
        if return_bool:
            print("false")
        else:
            print(Fore.RED + f"[-] Error during decryption: {e}")

# Function to update the PyKspc field in the metadata
def update_metadata_info(metadata, is_encrypted):
    metadata_str = metadata.decode()
    status = "true" if is_encrypted else "false"

    # Replace the old PyKspc value or add it
    if "PyKspc:" in metadata_str:
        metadata_str = metadata_str.replace("PyKspc:true", f"PyKspc:{status}")
        metadata_str = metadata_str.replace("PyKspc:false", f"PyKspc:{status}")
    else:
        # Add PyKspc with the appropriate value
        # Insert the status before ~!!#
        end_marker = '~!!#'
        if end_marker in metadata_str:
            metadata_str = metadata_str.replace(end_marker, f"    PyKspc:{status}\n{end_marker}")

    return metadata_str.encode()

# AES Function
def aes_encrypt(data, key):
    key = sha256(key.encode()).digest()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return iv + encryptor.update(data) + encryptor.finalize()

def aes_decrypt(data, key):
    key = sha256(key.encode()).digest()
    iv = data[:16]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(data[16:]) + decryptor.finalize()

# Metadata extraction
def extract_metadata(data):
    start = data.find(b'#!!')
    end = data.find(b'~!!#') + 4
    if start != -1 and end != -1:
        metadata = data[start:end]
        content = data[:start] + data[end:]
        return metadata, content
    return b'', data

# Custom help display function
def print_full_help(parser, subparsers):
    parser.print_help()  # Display general help
    print("\nSubcommands and specific options:\n")
    
    # Display help for each subcommand
    for subcommand, subparser in subparsers.items():
        print("\n" + "-"*40 + "\n")
        print(f"Command '{subcommand}':")
        print(subparser.format_help())

# main
def main():
    # Set up the main parser with help disabled
    parser = argparse.ArgumentParser(
        description="PyKspc - File encryption/decryption tool with AES-256",
        add_help=False
    )
    parser.add_argument('-v', '--version', action='version', version=f"PyKspc {PYKSPC_VERSION}")
    parser.add_argument('-h', '--help', action='store_true', help="Show full help")

    # Create subcommands
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Dictionary to store subparsers (for custom help)
    subparsers_dict = {}

    # Encrypt subcommand
    encrypt_parser = subparsers.add_parser(
        'encrypt', help="Encrypt a file with AES-256"
    )
    encrypt_parser.add_argument('file', type=str, help="Path to the file to be encrypted")
    encrypt_parser.add_argument('key', type=str, help="Encryption key (AES-256)")
    encrypt_parser.add_argument('-k', '--keep_format', action='store_true', help="Do not change the file format after encryption")
    encrypt_parser.add_argument('-M', '--keep_metadata', action='store_true', help="Preserve the file's metadata")
    encrypt_parser.add_argument('-Mi', '--keep_info', action='store_true', help="Keep PyKspc status information during encryption")
    encrypt_parser.add_argument('-b', '--boolean', action='store_true', help="Return only true or false upon success")
    subparsers_dict['encrypt'] = encrypt_parser

    # Decrypt subcommand
    decrypt_parser = subparsers.add_parser(
        'decrypt', help="Decrypt a file with AES-256"
    )
    decrypt_parser.add_argument('file', type=str, help="Path to the file to be decrypted")
    decrypt_parser.add_argument('key', type=str, help="Decryption key (AES-256)")
    decrypt_parser.add_argument('-k', '--keep_format', action='store_true', help="Do not change the file format after decryption")
    decrypt_parser.add_argument('-M', '--keep_metadata', action='store_true', help="Preserve the file's metadata")
    decrypt_parser.add_argument('-Mi', '--keep_info', action='store_true', help="Keep PyKspc status information during decryption")
    decrypt_parser.add_argument('-b', '--boolean', action='store_true', help="Return only true or false upon success")
    subparsers_dict['decrypt'] = decrypt_parser

    # Genkey subcommand
    genkey_parser = subparsers.add_parser(
        'genkey', help="Generate a unique key"
    )
    genkey_parser.add_argument('-l', '--key-length', type=int, default=32, help="Key length (default 32 for AES-256)")
    genkey_parser.add_argument('-b', '--boolean', action='store_true', help="Return only key or false upon success")
    genkey_parser.add_argument('-s', '--save_key', action='store_true', help="Indicates whether the key should be saved in a file.")
    genkey_parser.add_argument('-f', '--file', type=str, default="./key.ksp", help="Path to file where key is saved (default: ./key.ksp)")
    genkey_parser.add_argument('-a', '--append', action='store_true', help="Add the key to the end of the file instead of overwriting it")
    genkey_parser.add_argument('-ep', '--env_param', type=str, help="Name of the parameter to save the key as (format: name=(key))")
    subparsers_dict['genkey'] = genkey_parser
    
    # Analyse des arguments
    args = parser.parse_args()

    if args.help:
        print_full_help(parser, subparsers_dict)
        return

    # Call functions according to the specified subcommand
    if args.command == 'encrypt':
        encrypt_file(args.file, args.key, args.keep_metadata, args.keep_format, args.keep_info, args.boolean)
    elif args.command == 'decrypt':
        decrypt_file(args.file, args.key, args.keep_metadata, args.keep_format, args.keep_info, args.boolean)
    # Traitement de la commande genkey
    elif args.command == 'genkey':
        if args.key_length <= 0:
            if args.boolean:
                print("false")
            else:
                print(f"{Fore.RED}[-] Please specify a valid key length")
        else:
            key = os.urandom(args.key_length)  # Génération de la clé
            if args.save_key:
                mode = 'a' if args.append else 'w'  # Déterminer le mode d'ouverture du fichier

                try:
                    with open(args.file, mode) as f:
                        # Formater la clé selon l'option d'argument
                        if args.env_param:
                            # Si un nom de paramètre est donné, formater comme (param_name)=(key)
                            line_to_write = f"{args.env_param}={key.hex()}\n"
                        else:
                            # Si aucun paramètre, utiliser KSPC_KEY=(key)
                            line_to_write = f"KSPC_KEY={key.hex()}\n"

                        f.write(line_to_write)  # Écrire dans le fichier

                    # Vérification de la création du fichier
                    if os.path.isfile(args.file):
                        if args.boolean:
                            print("true")
                        else:
                            action = "appended to" if args.append else "saved to"
                            print(f"{Fore.GREEN}[+] Generated key (hex) {action}: {args.file}")
                    else:
                        if args.boolean:
                            print("false")
                        else:
                            print(f"{Fore.RED}[-] Failed to create the file: {args.file}")

                except Exception as e:
                    if args.boolean:
                        print("false")
                    else:
                        print(f"{Fore.RED}[-] Error saving key to file: {e}")
            else:
                # Afficher la clé générée
                if args.boolean:
                    print(key.hex())
                else:
                    print(f"{Fore.GREEN}[+] Generated key (hex): {key.hex()}")
    else:
        print(f"{Fore.RED}[-] use -h or --help for help")

if __name__ == "__main__":
    main()