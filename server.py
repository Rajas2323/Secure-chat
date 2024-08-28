import threading
import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

message_end = b'\x7f@\x83\xdb\xa1\xabY\x91\xb2'
key = RSA.generate(2048)
private_key = key.export_key()
public_key = key.publickey().export_key()
aes_key = get_random_bytes(16)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("localhost", 4444))
s.listen(100)
print("Listening to connections...")

connections: dict[socket.socket, dict] = {}

def encrypt_message(message, pub_key):
    recipient_key = RSA.import_key(pub_key)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    encrypted_message = cipher_rsa.encrypt(message)
    return encrypted_message

def decrypt_message(encrypted_message, priv_key):
    private_key = RSA.import_key(priv_key)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted_message = cipher_rsa.decrypt(encrypted_message)
    return decrypted_message

def encrypt_aes(message, key):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    padded_message = pad(message, AES.block_size)
    encrypted_message = cipher.encrypt(padded_message)
    return iv + encrypted_message

def decrypt_aes(encrypted_message, key):
    iv = encrypted_message[:16]
    
    actual_encrypted_message = encrypted_message[16:]
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    decrypted_message = unpad(cipher.decrypt(actual_encrypted_message), AES.block_size)
    
    return decrypted_message

def infinite_receive(conn:socket.socket):
    message = b""
    while not message_end in message:
        message += conn.recv(1024)
    
    return message

def receive_and_broadcast(conn:socket.socket, name:str):
    while True:
        try:
            message = infinite_receive(conn)[:-9]
            message = decrypt_aes(message, aes_key)

            for connection, data in connections.items():
                connection.send(encrypt_aes(f"{name}: {message.decode()}".encode(), aes_key) + message_end)
                
        except ConnectionResetError:
            name = connections[conn]["name"]
            connections.pop(conn)
            for conn in connections.keys():
                conn.send(encrypt_aes(f"{name} has left the chat!!!".encode(), aes_key) + message_end)
            break

def accept_new_connections():
    while True:
        conn, addr = s.accept()
        client_public_key = conn.recv(4096)
        encrypted_aes_key = encrypt_message(aes_key, client_public_key)
        conn.send(encrypted_aes_key)
        
        name = decrypt_aes(conn.recv(4096), aes_key)
        connections[conn] = {
            "name": name.decode(),
        }

        for conn in connections.keys():
            conn.send(encrypt_aes(f"{name.decode()} has joined the chat!".encode(), aes_key) + message_end)
        print("Connection received")
        threading.Thread(target=receive_and_broadcast, args=(conn, name.decode(), )).start()

threading.Thread(target=accept_new_connections).start()

