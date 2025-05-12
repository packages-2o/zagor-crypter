✔️ AES-256 encryption (FIPS 197 standard)

✔️ Secure key derivation (PBKDF2-HMAC-SHA512)

✔️ File integrity check (HMAC)

✔️ GUI interface (Tkinter)

✔️ Open source code

📜 Code:
python
# SECURE FILE ENCRYPTION TOOL (GITHUB COMPLIANT)
# Legal use only - Personal data protection

import os
import tkinter as tk
from tkinter import filedialog
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import HMAC, SHA512
from Crypto.Random import get_random_bytes

# Constants
SALT_SIZE = 32
ITERATIONS = 100000

def derive_key(password: str, salt: bytes) -> bytes:
 return PBKDF2(password.encode(), salt, dkLen=32, count=ITERATIONS, hmac_hash_module=SHA512)

def encrypt_file():
 file_path = filedialog.askopenfilename()
 password = password_entry.get()
    
    salt = get_random_bytes(SALT_SIZE)
 key = derive_key(password, salt)
    
    cipher = AES.new(key, AES.MODE_GCM)
 hmac = HMAC.new(key, digestmod=SHA512)
    
    with open(file_path, 'rb') as f:
 data = f.read()
    
    ciphertext, tag = cipher.encrypt_and_digest(data)
 hmac.update(ciphertext)
    
    output_path = file_path + ".enc"
 with open(output_path, 'wb') as f:
 [f.write(x) for x in (salt, cipher.nonce, tag, hmac.digest(), ciphertext)]
    
    status_label.config(text=f "Encrypted: {output_path}")

def decrypt_file():
    # ... (Message for full code) ...

# GUI Setup
app = tk.Tk()
app.title("Secure File Vault - GitHub Compliant")
app.geometry("400x200
