class Vector(object):
    def __init__(self, x, y):
        self.x = float(x)
        self.y = float(y)

    #上下文管理器开始函数
    def __enter__(self):
        return(self.x, self.y)

    #上下问管理器结束执行的函数
    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    # str(类的实例)/repr(类的实例)时候调用的函数; 如果没有定义__str__，使用str(实例)会调用__repr__
    def __repr__(self):
        return "he"
        # return "Vector({x}, {y})".format(x=self.x, y=self.y)

    def __str__(self):
        return "hello __str__"

    def __iter__(self):

if __name__ == "__main__":
    v1 =Vector(3, 4)
    # x, y = v1
    # print(x,y)
    print(str(v1))
    print(v1.x, v1.y)