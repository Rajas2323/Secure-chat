import socket
import threading
from tkinter import *
from tkinter.simpledialog import askstring
from tkinter.scrolledtext import ScrolledText
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import PKCS1_OAEP, AES
from tkinter.messagebox import showerror

message_end = b'\x7f@\x83\xdb\xa1\xabY\x91\xb2'

def receive_and_display():
    while True:
        message = infinite_receive(s)[:-9]
        message = decrypt_aes(message, aes_key)
        textarea.configure(state="normal")
        textarea.insert(0.0, f"{message.decode()}\n")
        textarea.configure(state="disabled")

def sender():
    s.send(encrypt_aes(message_box.get().encode(), aes_key) + message_end)
    message_box.delete(0, END)

def infinite_receive(conn:socket.socket):
    message = b""
    while not message_end in message:
        message += conn.recv(1024)
    
    return message


# Encrypt message using the public key
def encrypt_message(message, pub_key):
    recipient_key = RSA.import_key(pub_key)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    encrypted_message = cipher_rsa.encrypt(message)
    return encrypted_message

# Decrypt message using the private key
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

s = socket.socket()
try:
    s.connect(("localhost", 4444))
except ConnectionRefusedError:
    showerror("Connection Error", "Either the connection is failed or the server is not running!!!")
    exit(0)

name = askstring("Chat Name", "Enter your chat name")
if name.strip() == "":
    exit()

key = RSA.generate(2048)
private_key = key.export_key()
public_key = key.publickey().export_key()
s.send(public_key)
encrypted_aes_key = s.recv(2048)
aes_key = decrypt_message(encrypted_aes_key, private_key)

s.send(encrypt_aes(name.encode(), aes_key))

root = Tk()
root.resizable(False, False)

textarea = ScrolledText(root, font="Calibiri 18", width=29, height=20, state="normal")
textarea.pack()

message_box = Entry(font="Calibiri 20", bd=2)
message_box.pack(side=LEFT)

button = Button(root, text="Send", font="Calibiri 20", command=sender)
button.pack(side=LEFT)

threading.Thread(target=receive_and_display, daemon=True).start()

root.mainloop()

