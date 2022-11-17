def yj(func):
    def fun1():
        obj = func()
        print(next(obj))
        return obj
    return fun1

@yj
def yieA():
    print("gen start")
    yield
    i = -1
    while 1:
        if i == 100:
            break
        i += 1
        inPut = yield i
        print("input into yieA objectL:{inPut}".format(inPut=inPut))
    print("ended")

def main():
    print("main start")
    print("you will get a yieA object")
    a = yieA()
    b = yieA()
    count = 0
    while(1):
        try:
            print(a.send(count))
        except:
            break
        finally:
            count += 1
    print("b:{b}".format(b=b.send(1)))

if __name__ == '__main__':
    main()