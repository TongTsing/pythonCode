import socket
import time

addr = ("127.0.0.1", 1132)

cliSock = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
# cliSock.bind(("127.0.0.1", 1134))
i = 0

cliSock.connect(addr)
while 1:
    # time.sleep(1)
    cliSock = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
    cliSock.bind(("127.0.0.1", 1133))
    i +=1
    cliSock.connect(addr)
    time.sleep(60)
    cliSock.send(str(i).encode("utf-8"))
    print(cliSock.recv(100).decode())
    # time.sleep(2)
    # cliSock.close()
    print("ok")
    exit()
    # time.sleep(1)