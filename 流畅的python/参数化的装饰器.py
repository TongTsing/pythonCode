def dec1(arg2):
    def inner1(func):
        print("iarg1={}".format(func))
        func()
        return inner2
    def inner2(iarg2=arg2):
        print("iarg2={}".format(iarg2))
        return 0

    return inner1

def dec2(func, diy):
    print("dec2")
    if diy:
        print(diy)
    return func
def hello():
    print("hello world!\b")

@dec1(arg2=2)
def func():
    print("func:{}".format("fun1"))

print("hhh")
func()