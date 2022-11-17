import requests
celue = "24e0ef81-189b-11ed-8b7f-00163e885b48"
ip = '192.168.110.24:8061'
uri = '/deployStrategy/' + celue

headers = {
    "host": "easyflow.easyops-only.com",
    "user": "easyops",
    "org": "2041784",
    "Content-Type": "application/json"
}

url = 'http://' + ip + uri

print(url)

res = requests.get(url=url, headers=headers).json()

print(res)