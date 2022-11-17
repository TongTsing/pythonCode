import socket
import subprocess

class client(object):
    def __init__(self):
        self.targetServerIp = "127.0.0.1"
        self.targetServerPort = 1132

    def mainProcess(self):
        self.targetServerIp = input("input target server ip:")
        self.targetServerPort = input("input target server port:")
        self.connToServer()

    def connToServer(self):



addr = ("127.0.0.1", 1132)
clientSock = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
clientSock.connect(addr)
clientSock.send("synTime ".encode("utf-8"))
strTime=clientSock.recv(10240).decode("utf-8")
print(strTime)
cmdStatus = subprocess.check_output(f"date -s {strTime}".format(strTime=strTime))
clientSock.close()