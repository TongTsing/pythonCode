def fun1():
    print("hello fun1")
    fun2()
    return

def fun2():
    print("hello fun2")
    return

fun1()

"http://{HOST}/object/{ID}/instance/_search".format(HOST=cmdb_host, ID=model)