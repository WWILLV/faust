# -*- coding: UTF-8 -*-
__author__ = 'WILL_V'

import socket

HOST = 'localhost'
# HOST = '172.26.206.195'
PORT = 9335


def send_message(message, host=HOST, port=PORT):
    print(f'EXTENSION [-] Sending to {host}:{message}')
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(message.encode())
        data = s.recv(1024)
        print('EXTENSION [-] Received:', data.decode())
        s.close()
        return data.decode()


def callback(msg, host=HOST, port=PORT):
    if type(msg) == dict:
        msg = str(msg).replace("'", '"')
    if msg == '':
        return 'EXTENSION [x] ERROR: No message input.'
    else:
        return send_message(msg, host, port)


if __name__ == '__main__':
    msg = {"path":"/home/nsab2022/wwz/malicious/cshttps.pcap","action":"client_hello_host","parm":{"index":20},"msg":"test"}
    print(callback(msg))
