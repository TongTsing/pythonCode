import requests

def getInstanceList(objectId, queryData):
    headers = {"user": "easyops", "org": "1888", "content-type": "application/json","host": "cmdb_resource.easyops-only.com"}
    url = "http://{CMDB_HOST}/v3/object/{objectId}/instance/_search".format(CMDB_HOST="192.168.110.174",objectId=objectId)
    res = requests.post(url=url, headers=headers, json=queryData).json()
    print(res)
    if res["code"] != 0:
        return []
    instanceIdList = []
    for i in res["data"]["list"]:
        instanceIdList.append(i["instanceId"])

    return instanceIdList

def checkInstance(objectId, instanceList):
    headers = {"user": "easyops", "org": "1888", "content-type": "application/json","host": "cmdb_resource.easyops-only.com"}
    url = "http://{CMDB_HOST}/object/{objectId}/instance/_relation_count_aggregate".format(CMDB_HOST="192.168.110.174", objectId=objectId)
    #quryData
    retList=[]
    for instanceId in instanceList:
        queryData = {
            "only_my_instance": False,
            "query":{
                "instanceId": instanceId
            },
            "relation_side_ids": ["M1_M2", "M1_M3"]
        }
        res = requests.post(url=url, headers=headers, json=queryData).json()
        print(res["data"][0]["value"])
        if res["data"][0]["value"] != res["data"][1]["value"] + res["data"][2]["value"]
            retList.append(instanceId)
        return retList

if __name__ == '__main__':
    data = {
        "fields": ["instanceId"],
        "query":{
        }
    }
    instanceIdList = getInstanceList("M1", queryData=data)

    checkInstance("M1", instanceList=instanceIdList)
    print(instanceIdList)