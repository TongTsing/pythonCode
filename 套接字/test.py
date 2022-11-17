import threading
import time

lock = threading.Lock()

def targetFunc(threadNum):
    # lock.acquire()
    # time.sleep(1)
    print(f"this is thread:{threadNum}".format(threadNum))
    time.sleep(2)
    print(f"thread: {threadNum} sleep over!".format(threadNum=threadNum))
    lock.acquire()
    lock.release()
    return True

def mainThread():
    threadObjList = []
    threadArgList = list(i for i in range(100))

    for i in range(100):
        # print("i")
        tmpThreadObject = threading.Thread(target=targetFunc, args=(threadArgList[i],))
        threadObjList.append(tmpThreadObject)
    for i in range(len(threadObjList)):
        obj = threadObjList[i]
        obj.start()
        # obj.join()

mainThread()
