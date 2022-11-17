# '''---codeby--tongqing'''
# 代码中的所有ip字段且是cmdb_service组件所在机器；如需修改可以自行修改
# 代码中所有的org为客户环境的org

import requests
#请求头
headers={
    "host": "cmdb_resource.easyops-only.com",
    "org": "21200519",
    "user": "easyops",
    "Content-Type": "application/json"
}
# 获取交换机模型的实例列表
instanceList=[]
def getInstanceList():
    data = {
        "fields": ["sysName"],
        "query": {
            "sysName": {
                "$like": "%%"
            }
        }
    }
    url = "http://10.195.128.133/v3/object/_SWITCH/instance/_search"
    res=requests.post(url=url, headers=headers, json=data).json()
    for ins in res["data"]["list"]:
        instanceList.append(ins["instanceId"])
# 查询需要徐交换机中某个实例建立关系的实例列表
relationList=[]
def getRelationInstanceList(instanceId):
    tempList=[]
    getRelationInstanceListURL = "http://10.195.128.133/object/_SWITCH/instance/_search"
    postData={
    "fields": {"sysName": True, "inclNETDPORT.connectedHOST": True}
    "query": {
        "instanceId":{
            "$eq": instanceId
        }
        }
    }
    res=requests.post(url=getRelationInstanceListURL, headers=headers, json=postData).json()
    for i in res["data"]["list"]:
        for j in i["inclNETDPORT"]:
            for k in j["connectedHOST"]:
                tempList.append(k["instanceId"])
    return tempList

# 给交换机的实例A，和查询到的需要与交换机实例A建立关系的主机实例列表添加该系
def appendRelation(instanceId, relationList):
    appendRelationUrl="http://10.195.128.133/object/inclNETDPORT/relation/connectedHOST/append"
    postData={
        "related_instance_ids": relationList,
        "instance_ids": [
            instanceId
        ]
    }
    res=requests.post(url=appendRelationUrl, headers=headers, json=postData)
    print(res)
#main
getInstanceList()
for ins in instanceList:
    tmp_LIST=getRelationInstanceList(ins)
    appendRelation(ins, tmp_LIST)
