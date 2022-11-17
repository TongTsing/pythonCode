import threading
from time import sleep, ctime

loops = [4, 2]
def loop(nloop, nsec):
    print("start loop", nloop, "at:", ctime())
    sleep(nsec)
    print("loop", nloop, "done at:", ctime())

def main():
    print("main starting at:", ctime())
    threads = []
    nloops = range(len(loops))
    for i in nloops:
        # Thread类名，所以threading.Thread()返回的是Thread类的一个实例；
        t = threading.Thread(target=loop, args=(i, loops[i]))
        threads.append(t)
    for thread in threads:
        thread.start()
    # for thread in threads:
    #     thread.join()
    for thread in threads:
        with open("status.txt", "a", encoding="utf-8") as f:
            f.write(str(thread.getName())+":"+str(thread.is_alive()))
    print("all Done at:", ctime())

if __name__ == '__main__':
    main()
