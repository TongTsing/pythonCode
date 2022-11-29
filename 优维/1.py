import socket
import time
addr = ("127.0.0.1", 1132)
mainSocket = socket.socket(type=socket.SOCK_STREAM, family=socket.AF_INET)
mainSocket.bind(addr)
mainSocket.listen(3)
l1 = []
while 1:
    cliSocket, cliaddr = mainSocket.accept()

    print("socket conn:{}".format(cliSocket))
    time.sleep(60)
    print(cliSocket.recv(10).decode())
    time.sleep(5)
    cliSocket.send("hhhhh".encode())
    print("send ok")
    print(cliSocket.recv(10).decode())
    cliSocket.close()