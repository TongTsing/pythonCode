import urllib.request
import urllib.parse
import json
url = "http://192.168.110.24:8079/v3/object/HOST/instance/_search"
# url = "http://192.168.110.24:8079/object/HOST/instance/5e561fe5f873d"
headers = {
    "Host": "cmdb_resource.easyops-only.com",
    "user": "easyops",
    "org": "2041784",
    "Content-Type": "application/json"
}

data = {
    "fields": ["hostname"],
    "query": {
        "hostname": {
            "$like": "%j%"
        }
    }
}
data = json.dumps(data)
data = bytes(data, 'utf8')
# data = urllib.parse.urlencode(data).encode("utf-8")
req = urllib.request.Request(url=url, headers=headers, data=data, method="POST")
res = urllib.request.urlopen(url=req)
print(res.read())