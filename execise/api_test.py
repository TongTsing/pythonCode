import json

import requests

object = 'TESTTQ'


url = "http://192.168.110.174/v3/object/{object}/instance/_search".format(object=object)
# update_user_url = "http://" + SERVER_IP + ":8061/deployStrategy?appId={}"
headers = {
    "host": "cmdb_resource.easyops-only.com",
    "user": "easyops",
    "org": "2041459",
    "Content-Type": "application/json"
}

def searchInstance(objectId:str, data:dict):
    global CMDB_HOST
    global headers
    url = "http://192.168.110.174/v3/object/{objectId}/instance/_search".format(objectId=objectId)
    reqs = requests.post(url=url, headers=headers, json=data)
    if reqs.status_code == 200:
        tmpList = reqs.json()['data']['list']
        instanceList = []
        for i in tmpList:
            instanceList.append(i['instanceId'])
        return instanceList
    else:
        print("111")


def delInstance(objectId:str, instanceList:list):
    global CMDB_HOST
    global headers
    #封装数据
    tmpList = []
    for i in instanceList:
        tmpList.append({"_object_id": objectId, "instanceId": i})
    print(tmpList)
    data = {
        "data": tmpList
    }
    url = "http://192.168.110.174/mix/object/instance/delete"
    reqs = requests.post(url=url, headers=headers, json=data)
    if reqs.status_code == 200:
        print(reqs)
    else:
        print("1111")
if __name__ == "__main__":

    data = {
        "fields": ["instanceId"],
        "query": {
            "issurvival": {
                "$like": "%no%"
            }
        }
    }
    insList=searchInstance(objectId="TESTTQ", data=data)
    print(insList)
    delInstance(objectId="TESTTQ", instanceList=insList)
