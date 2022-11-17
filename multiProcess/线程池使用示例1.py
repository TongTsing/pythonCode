from multiprocessing import Pool
import time
def test(p):
       print(p)
       time.sleep(3)
if __name__=="__main__":
    pool = Pool(processes=3)
    for i in range(500):
        '''
        ('\n'
         '	（1）遍历500个可迭代对象，往进程池放一个子进程\n'
         '	（2）执行这个子进程，等子进程执行完毕，再往进程池放一个子进程，再执行。（同时只执行一个子进程）\n'
         '	 for循环执行完毕，再执行print函数。\n'
         '	')
        '''
        pool.apply(test, args=(i,))   #维持执行的进程总数为10，当一个进程执行完后启动一个新进程.
    print('test over')
    pool.close()
    pool.join()