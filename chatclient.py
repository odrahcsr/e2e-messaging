import socket
import rsa
import psutil
import threading
from Crypto.Cipher import AES
import base64
import os

def encrypt_aes(key, plaintext):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    return base64.b64encode(nonce + ciphertext).decode()

def decrypt_aes(key, encrypted_text):
    encrypted_data = base64.b64decode(encrypted_text)
    nonce = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt(ciphertext).decode()

def monitor_ram():
    """Monitor and display RAM usage every few seconds."""
    while True:
        ram_usage = psutil.virtual_memory().used / (1024 ** 2)  
        print(f"[RAM USAGE] Client RAM: {ram_usage:.2f} MB")
        threading.Event().wait(5)  

def client_program():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("127.0.0.1", 5555))
    server_public_key = rsa.PublicKey.load_pkcs1(client_socket.recv(1024))
    aes_key = os.urandom(32)
    encrypted_aes_key = rsa.encrypt(aes_key, server_public_key)
    client_socket.send(encrypted_aes_key)

    print("[*] Secure connection established!")
    
    threading.Thread(target=monitor_ram, daemon=True).start()

    def receive_messages():
        while True:
            try:
                encrypted_msg = client_socket.recv(1024).decode()
                if encrypted_msg:
                    decrypted_msg = decrypt_aes(aes_key, encrypted_msg)
                    print(f"\n[Friend]: {decrypted_msg}")
            except:
                break
    threading.Thread(target=receive_messages, daemon=True).start()

    while True:
        msg = input("You: ")
        if msg.lower() == "exit":
            break
        encrypted_msg = encrypt_aes(aes_key, msg)
        client_socket.send(encrypted_msg.encode())

    client_socket.close()

client_program()
