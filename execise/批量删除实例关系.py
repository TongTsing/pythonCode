import requests
import time
import json

headers = {
    "host": "cmdb_resource.easyops-only.com",
    "user": "easyops",
    "org": "1967130",
    "Content-type": "application/json"
}


def getInstanceList(model, relationId, fieldsValues, page, IP):
    data = {
        "fields": ["instanceId", fieldsValues],
        "query": {
            "tag": {
                "$like": "%%"
            },
        },
        "page_size": 1000,
        "page": page
    }
    url = "http://" + IP + "/v3/object/" + model + "/instance/_search"
    res = requests.post(url=url, headers=headers, json=data)
    print(res)
    leftInstanceList = []
    relationDictList = []
    rightInstanceList = []
    if res.status_code != 200:
        print("page over...")
        return
    res = res.json()
    for ins in res["data"]["list"]:
        print(ins)
        if ins[relationId]:
            leftInstanceList.append(ins["instanceId"])
        for i in ins[relationId]:
            rightInstanceList.append(i["instanceId"])
        if rightInstanceList:
            relationDictList.append({"leftInstanceList": leftInstanceList, "rightInstanceList": rightInstanceList})
        leftInstanceList = []
        rightInstanceList = []
    return relationDictList


# 获取每个实例的关系对端拼接成列表
"""
relationDictList--->
{[]}
"""


def getL2RdictList(leftModel, relationId, fieldsValues, IP):
    relationDictList = []
    for i in range(100):
        a = getInstanceList(model=leftModel, relationId=relationId, fieldsValues=fieldsValues, page=i, IP=IP)
        if a:
            relationDictList.extend(a)
        # time.sleep(1)
    print(relationDictList)
    return relationDictList


def delRelation(leftList, rightList, relationSideId, IP, leftModel):
    uri = "/object/" + leftModel + "/relation/" + relationSideId + "/remove"
    url = "http://" + IP + uri
    data = {
        "instance_ids": leftList,
        "related_instance_ids": rightList
    }
    tag = 0
    # 删除关系
    while (1):
        tag += 1
        if tag == 10:
            with open(file="./info.txt", mode="a+") as f:
                f.write("del relation failed, please try again")
                # f.write("del relation failed:{leftList}, please try again".format(leftList=leftList))
            break
        res = requests.post(url=url, headers=headers, json=data)
        if res.status_code == 200:
            print("delRelation...")
            print(res.status_code)
            print("delRelation from leftInstance{instanceId} Done...".format(instanceId=leftList))
            break

def main():
    LEFTMODEL = 'MODEL1'
    RIGHTMODEL = "M2"
    RELATIONID = "M1_M2"
    IP = "192.168.110.24"
    relationDictList = getL2RdictList(leftModel=LEFTMODEL, relationId=RELATIONID,
                                      fieldsValues=(RELATIONID + ".instanceId"), IP=IP)
    print(len(relationDictList))
    for i in relationDictList:
        delRelation(leftList=i["leftInstanceList"], rightList=i["rightInstanceList"], relationSideId=RELATIONID,
                    leftModel=LEFTMODEL, IP=IP)


"""

"""
if __name__ == "__main__":

    # delstatu = 0
    # intrptstatu = 0
    # with open(file="./intrpt.txt", mode="a+")as f:
    #     tmp = f.readline()
    #     if tmp=="interrupt acured! pleases tye again!":
    #         intrptstatu = 1
    #     print(tmp)
    # with open(file="./tmp.txt", mode="r+") as f:
    #     tmp=f.read()
    #     if tmp=="\ndel relation failed, please try again":
    #         delstatu=1
    # if delstatu or intrptstatu:
    with open(file="./intrpt.txt", mode="w+") as f:
        f.write("no intrpt!")
    with open(file="./tmp.txt", mode="r+") as f:
        f.write("no failed delOperation!")
    try:
        main()
    except:
        with open(file="./intrpt.txt", mode="w+") as f1:
            f1.write("interrupt acured! pleases tye again!")