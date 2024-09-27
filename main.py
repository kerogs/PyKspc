import argparse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from hashlib import sha256
import os

# Definition of the version
PYKSPC_VERSION = "1.1"

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
            print(f"File encrypted and saved to {new_file_path}")
    except Exception as e:
        if return_bool:
            print("false")
        else:
            print(f"Error during encryption: {e}")

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
            print(f"File decrypted and saved to {new_file_path}")
    except Exception as e:
        if return_bool:
            print("false")
        else:
            print(f"Error during decryption: {e}")

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

# Main Program
def main():
    parser = argparse.ArgumentParser(description='File encryption/decryption tool with AES-256')
    parser.add_argument('file', type=str, nargs='?', help='Path to the file to be processed')
    parser.add_argument('key', type=str, nargs='?', help='Encryption key (AES-256)')
    parser.add_argument('-e', '--encode', action='store_true', help='Encode the file')
    parser.add_argument('-d', '--decode', action='store_true', help='Decode the file')
    parser.add_argument('-k', '--keep_format', action='store_true', help="Do not change the file format after encryption")
    parser.add_argument('-M', '--keep_metadata', action='store_true', help="Keep the file's metadata")
    parser.add_argument('-Mi', '--keep_info', action='store_true', help="Keep the PyKspc status information during encryption")
    parser.add_argument('-b', '--boolean', action='store_true', help="Return only true or false for success")
    parser.add_argument('-v', '--version', action='store_true', help="Display the program version")

    args = parser.parse_args()

    # Display the version if -v is specified
    if args.version:
        print(f"PyKspc Version: {PYKSPC_VERSION}")
        return

    # If -Mi is specified, also enable -M
    if args.keep_info:
        args.keep_metadata = True

    if args.encode:
        encrypt_file(args.file, args.key, args.keep_metadata, args.keep_format, args.keep_info, args.boolean)
    elif args.decode:
        decrypt_file(args.file, args.key, args.keep_metadata, args.keep_format, args.keep_info, args.boolean)
    else:
        print("Please specify an action: -e (encode) or -d (decode)")

if __name__ == "__main__":
    main()
