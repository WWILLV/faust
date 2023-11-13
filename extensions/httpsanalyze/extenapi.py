# -*- coding: UTF-8 -*-
__author__ = 'WILL_V'

import socket
import json
import analyze


def resp_handle(resp):
    result = ''
    try:
        resp = eval(resp)
        path = resp["path"]
        action = resp["action"]
        parm = resp["parm"]
        msg = resp["msg"]
    except Exception as e:
        print(e.message)
        return 'ERROR: ' + e.message
    if msg.lower() == 'exit':
        return 'exit'
    ha = analyze.Https_analyze(path)
    if action == 'client_hello_host':
        result = ha.get_client_hello_host(parm['index'])
    elif action == 'certificate_host':
        result = ha.get_certificate_host(parm['index'])
    elif action == 'search_client_hello':
        result = ha.search_client_hello(parm['searchlist'])
    return result


def api_server(server_port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('127.0.0.1', server_port))
    server_socket.listen(1)
    print('Server listening on ' + str(server_port))
    while True:
        (client_socket, client_address) = server_socket.accept()
        try:
            message = client_socket.recv(1024).decode()
            print('[-] Received message from ' + str(client_address[0]) + ':' + message)
            response = json.loads(message)
            # {'path':'','action':'','parm':{},'msg':''}
            result = resp_handle(json.dumps(response).encode())
            if result == 'exit':
                client_socket.close()
                break
            else:
                client_socket.send(str(result))
                print('[-] Sent message to ' + str(client_address[0]) + ':' + str(result))
                client_socket.close()
        except Exception as e:
            print(e.message)
            client_socket.send("ERROR:"+e.message)
            client_socket.close()
    client_socket.close()


if __name__ == '__main__':
    p = port = 9335
    # try:
    #     p = input("Please input the port (default:9335): ")
    # except Exception as e:
    #     p = 9335
    # finally:
    #     port = p
    api_server(port)
