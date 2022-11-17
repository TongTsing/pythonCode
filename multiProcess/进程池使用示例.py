from multiprocessing import Pool, Process
import time
import os

def info():
    print("-----info start------")
    print("module name:", __name__)
    print('parent process:', os.getppid())
    print('process id', os.getpid())
    print("-----info end------")
def f(name):
    info()
    time.sleep(20)
    with open("../execise/1.txt", "a+") as f:
        f.write('hhhh')
    print('hello f', name)
def f1(name):
    info()
    time.sleep(5)
    with open("../execise/1.txt", "a+") as f:
        f.write('hhhh')
    print("f1")
if __name__ == '__main__':
    p = Process(target=f, args=("bob", ))
    p.daemon=False
    # p.run()
    p.start()
    p.join(10)
    print("\n-----main_print-----")
    print('name:', p.name)
    print('is_alive', p.is_alive())
    print('exitcode', p.exitcode)
    print("-----main_print_end-----")