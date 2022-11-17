import json
import traceback

# 该类用来展示__getitem__/索引取值， __setitem__/设置序列在索引处的值
class sequence(object):
    def __init__(self, sequence):
        self.item = list(sequence)
        return
    def __getitem__(self, position):
        return self.item[position]
        # try:
        #     return self.item[position]
        # except Exception as e:
        #     return e

    def __setitem__(self, key, value):
        self.item[key] = value
        # try:
        #     self.item[key] = value
        # except Exception as e:
        #     print("hh")


#

def testSequence():
    objA = sequence([i for i in range(100)])
    objA[1] = "j"
    print(objA[:])
    for i in objA:
        print(i)
def testjson():
    a = {"name":"tq", "age":12, "area": "ch"}
    print(json.dumps(a))



if __name__ == "__main__":
    # testSequence()
    testjson()