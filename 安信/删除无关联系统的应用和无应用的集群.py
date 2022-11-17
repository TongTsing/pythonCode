import requests

def getInstanceId(objectId, relationId, page_size, page):
    uri = "/object/{objectId}/instance/_search".format(objectId=objectId)
    URL = "http://{CMDB_HOST}".format(CMDB_HOST=EASYOPS_CMDB_HOST) + uri
    headers = {
        "host": "cmdb_resource.easyops-only.com",
        "org": str(EASYOPS_ORG),
        "user": "easyops",
        "Content-Type": "application/json"
    }
    queryData = {
        "fields": {"instanceId": 1},
        "query": {
            relationId: {
                "$exists": False
            }
        },
        "page_size": page_size,
        "page": page
    }
    res = requests.post(url=URL, headers=headers, json=queryData).json()
    total = res["data"]["total"]
    insList = []
    if not res["data"]["list"]:
        return insList
    for i in res["data"]["list"]:
        insList.append(i["instanceId"])
    return insList, total


def delInstance(objectId, insIds):
    url = "http://{CMDB_HOSt}/object/{objectId}/instance/_batch".format(CMDB_HOSt=EASYOPS_CMDB_HOST, objectId=objectId)
    print(url)
    headers = {
        "host": "cmdb_resource.easyops-only.com",
        "org": str(EASYOPS_ORG),
        "user": "easyops",
        "Content-Type": "application/json"
    }
    params = ''
    for insId in insIds:
        params = params + insId + ';'
    params = params[0:-1]
    url = url + '?' + "instanceIds=" + params
    print(params)
    res = requests.delete(url=url, headers=headers)
    print(res.url)
    print(res)
def getTotal(objectid):
    uri = "/object/{objectId}/instance/_search".format(objectId=objectId)
    URL = "http://{CMDB_HOST}".format(CMDB_HOST=EASYOPS_CMDB_HOST) + uri
    headers = {
        "host": "cmdb_resource.easyops-only.com",
        "org": str(EASYOPS_ORG),
        "user": "easyops",
        "Content-Type": "application/json"
    }
    queryData = {
        "fields": {"instanceId": 1},
        "query": {
        },
        "page_size": 30,
        "page": 1
    }
    res = requests.post(url=URL, headers=headers, json=queryData).json()
    print(res["data"]["list"]["total"])

def main():
    objectId = "M1"
    relationId = "M1_M2"
    page_size = 1000
    page_count = 0
    delList = []
    tmplist, total = getInstanceId(objectId="M1", relationId="M1_M2",page_size=1000, page=1)
    delList.extend(tmplist)
    if total % page_size == 0:
        pageCount = total/page_size
    else:
        pageCount = int(total/page_size) + 1

    if pageCount > 1:
        for page in range(2,pageCount+1):
            print(page)
            tmplist, total = getInstanceId(objectId="M1", relationId="M1_M2", page_size=page_size, page=page)
            delList.extend(tmplist)
    print(f"delList:{delList}".format(delList=delList))
    delInstance("M1", delList)

if __name__ == "__main__":
    getTotal("M1")