
# Secure Chat

This is a simple group chat program written in python with the help of socket library. This implelentation is named as Secure Chat because the communication in this program is end to end encrypted using AES.

## How it works
It is not a fully furnished application, this is just to explain how encrypted chat system works. First of all RSA is used to transfer the AES key from server to client. And then that AES key is used for encryption and decryption of data making it impossible for any hacker in a network to intercept data using MITM attack.

The application has a simple server script and a client script. The server can have n number of clients which are basically the users interacting with each others using this chat system.

Tkinter library has been used to implement the GUI of this program.

## Usage & Requirements

### Requirements
* Python3
* pycryptodome

### Usage
* Install pycryptodome using the command 
```pip install pycryptodome```

Edit the server ip and client ip inside the server and client scripts according to your needs and then simply run them using the following commands

```python server.py```

```python client.py```



## Authors

- [@Rajas](https://www.github.com/Rajas2323)

