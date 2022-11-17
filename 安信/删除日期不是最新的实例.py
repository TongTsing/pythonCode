import datetime
import time
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

def delInstance(objectId, idList):
    headers = {"user": "easyops", "org": "1888", "content-type": "application/json","host": "cmdb_resource.easyops-only.com"}
    url = "http://192.168.110.174/object/{objectId}/instance/_batch".format(objectId=objectId)
    params = ''
    tag = 1
    for tmp in idList:
        params = params + tmp + ';'
    params = params[0:-1]
    params = {"instanceIds": params}
    print(params)
    # url = url + '?' + "instanceIds="+params
    res = requests.delete(url=url, headers=headers, params=params)
    print(res.url)
    print(res)


def test():
    query = {
            "fields": ["instanceId"],
             "query": {

             }
    }
    l = getInstanceList("TIMETEST", query)
    delInstance("TIMETEST", l)

if __name__ == "__main__":
    test()