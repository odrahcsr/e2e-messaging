import socket
import threading
import rsa
import psutil
from Crypto.Cipher import AES
import base64
import os

public_key, private_key = rsa.newkeys(2048)

clients = {}

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
        print(f"[RAM USAGE] Server RAM: {ram_usage:.2f} MB")
        threading.Event().wait(5)  

def handle_client(client_socket, address):
    print(f"[+] New connection from {address}")

    client_socket.send(public_key.save_pkcs1("PEM"))

    encrypted_aes_key = client_socket.recv(1024)
    aes_key = rsa.decrypt(encrypted_aes_key, private_key)

    clients[client_socket] = aes_key

    while True:
        try:
            encrypted_msg = client_socket.recv(1024).decode()
            if not encrypted_msg:
                break
            decrypted_msg = decrypt_aes(aes_key, encrypted_msg)
            print(f"[{address}] {decrypted_msg}")
            for client in clients:
                if client != client_socket:
                    client.send(encrypt_aes(clients[client], decrypted_msg).encode())

        except Exception as e:
            print(f"[-] Connection with {address} lost: {e}")
            break

    del clients[client_socket]
    client_socket.close()

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("0.0.0.0", 5555))
    server_socket.listen(5)
    print("[*] Server started on port 5555")
    threading.Thread(target=monitor_ram, daemon=True).start()

    while True:
        client_socket, address = server_socket.accept()
        client_thread = threading.Thread(target=handle_client, args=(client_socket, address))
        client_thread.start()

start_server()
