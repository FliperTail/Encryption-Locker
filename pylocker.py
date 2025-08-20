import os
import hashlib
import getpass
from pathlib import Path
import subprocess
import platform
import binascii
import string
import shutil
import re

# === SETTINGS ===
LOCKER_FOLDER = Path("Locker")
PASSWORD_CHECK_FILE = LOCKER_FOLDER / ".password_check"
PASSWORD_CHECK_CONTENT = b"Password OK"
HEX_CHARS = set(string.hexdigits)  # For filename validation

# === FUNCTIONS ===
def password_to_key(password: str) -> bytes:
    return hashlib.sha256(password.encode()).digest()

def xor_data(data: bytes, key: bytes) -> bytes:
    key_len = len(key)
    return bytes([data[i] ^ key[i % key_len] for i in range(len(data))])

def encrypt_filename(filename: str, key: bytes) -> str:
    encrypted = xor_data(filename.encode(), key)
    return binascii.hexlify(encrypted).decode()

def decrypt_filename(encrypted_name: str, key: bytes) -> str:
    if len(encrypted_name) % 2 != 0:
        return None
    if not all(ch in HEX_CHARS for ch in encrypted_name):
        return None
    try:
        encrypted_bytes = binascii.unhexlify(encrypted_name)
    except (binascii.Error, ValueError):
        return None
    decrypted = xor_data(encrypted_bytes, key)
    name = decrypted.decode(errors="ignore")
    return name if name else None

def is_hex_name(name: str) -> bool:
    return len(name) % 2 == 0 and all(ch in HEX_CHARS for ch in name)

def hide_folder(path: Path):
    if platform.system() == "Windows":
        subprocess.call(["attrib", "+h", str(path)])

def is_valid_filename(name: str) -> bool:
    if not name or any(ch in name for ch in '<>:"/\\|?*'):
        return False
    if re.search(r'[\x00-\x1f]', name):
        return False
    if name[-1] in (' ', '.'):
        return False
    return True

def encrypt_path(path: Path, key: bytes):
    if path.is_dir():
        for child in list(path.iterdir()):
            # Skip password check file
            if child == PASSWORD_CHECK_FILE:
                continue
            encrypt_path(child, key)
        if not is_hex_name(path.name):
            new_name = encrypt_filename(path.name, key)
            new_path = path.with_name(new_name)
            path.rename(new_path)
            print(f"Encrypted folder: {new_name}")
    else:
        # Skip password check file
        if path == PASSWORD_CHECK_FILE:
            return
        if is_hex_name(path.name):
            print(f"Skipping file {path.name} (already encrypted)")
            return
        with open(path, "rb") as f:
            data = f.read()
        encrypted_data = xor_data(data, key)
        with open(path, "wb") as f:
            f.write(encrypted_data)
        new_name = encrypt_filename(path.name, key)
        new_path = path.with_name(new_name)
        path.rename(new_path)
        print(f"Encrypted file: {new_name}")

def decrypt_path(path: Path, key: bytes):
    if path.is_dir():
        for child in list(path.iterdir()):
            # Skip password check file
            if child == PASSWORD_CHECK_FILE:
                continue
            decrypt_path(child, key)

        original_name = decrypt_filename(path.name, key)
        if original_name and is_valid_filename(original_name):
            new_path = path.with_name(original_name)
            path.rename(new_path)
            path = new_path
            print(f"Decrypted folder: {original_name}")
        else:
            print(f"Skipping folder {path.name} (not encrypted, wrong password, or invalid name)")
            return
    else:
        # Skip password check file
        if path == PASSWORD_CHECK_FILE:
            return
        original_name = decrypt_filename(path.name, key)
        if not original_name or not is_valid_filename(original_name):
            print(f"Skipping file {path.name} (not encrypted, wrong password, or invalid name)")
            return
        with open(path, "rb") as f:
            data = f.read()
        decrypted_data = xor_data(data, key)
        with open(path, "wb") as f:
            f.write(decrypted_data)
        new_path = path.with_name(original_name)
        path.rename(new_path)
        print(f"Decrypted file: {original_name}")

def create_password_check_file(key: bytes):
    encrypted = xor_data(PASSWORD_CHECK_CONTENT, key)
    with open(PASSWORD_CHECK_FILE, "wb") as f:
        f.write(encrypted)

def verify_password(key: bytes) -> bool:
    if not PASSWORD_CHECK_FILE.exists():
        return False
    try:
        with open(PASSWORD_CHECK_FILE, "rb") as f:
            encrypted = f.read()
        decrypted = xor_data(encrypted, key)
        return decrypted == PASSWORD_CHECK_CONTENT
    except Exception:
        return False

# === MAIN LOGIC ===
if not LOCKER_FOLDER.exists():
    LOCKER_FOLDER.mkdir()
    hide_folder(LOCKER_FOLDER)
    print(f"Created hidden folder: {LOCKER_FOLDER}")

    while True:
        try:
            password = getpass.getpass("Set a password: ")
            if not password:
                print("Password cannot be empty. Please try again.")
                continue
            confirm = getpass.getpass("Confirm password: ")
            if password != confirm:
                print("Passwords do not match. Please try again.")
                continue
            break
        except (KeyboardInterrupt, EOFError):
            print("\nSetup aborted. Removing empty Locker folder.")
            shutil.rmtree(LOCKER_FOLDER)
            exit()
    key = password_to_key(password)
    create_password_check_file(key)
else:
    # Loop until correct password entered
    while True:
        password = getpass.getpass("Enter your password: ")
        key = password_to_key(password)
        if verify_password(key):
            print("Password verified.")
            break
        else:
            print("Wrong password, please try again.")

choice = input("(E)ncrypt or (D)ecrypt files and folders? ").strip().lower()
if choice == "e":
    for item in LOCKER_FOLDER.iterdir():
        encrypt_path(item, key)
elif choice == "d":
    for item in LOCKER_FOLDER.iterdir():
        decrypt_path(item, key)
else:
    print("Invalid choice.")
