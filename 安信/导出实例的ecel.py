import requests

def importExcel(objectId, queryData):
    headers={
        "org": "3103",
        "user": "easyops",
        "host": "cmdb_resource.easyops-only.com",
        "content-type": "application/json"
    }
    url = "http://{CMDB_HOST}/export/object/{objectId}/instance/excel".format(CMDB_HOST="10.0.241.159", objectId=objectId)
    req = requests.post(url=url, json=queryData, headers=headers)
    print(req.content)
    with open(file="./test.xlsx", mode="wb+") as f:
        f.write(req.content)
def main():
    queryData = {
        "fields": {"name":True, "operationManager":True, "owner": True, "systemManager": True},
        "query": {
            "$or": [
                {"operationManager": {"$exists": False}},
                {"owner": {"$exists": False}},
                {"systemManager": {"$exists": False}}
            ]
        }
    }
    importExcel(objectId="BUSINESS", queryData=queryData)

if __name__ == "__main__":
    main()
