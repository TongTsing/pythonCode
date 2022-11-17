import hashlib
import hmac
import json
import time
import requests



#计算签名
def gen_signature(access_key, scret_key, request_time, method, uri, data, content_type='application/json'):
    scret_key = scret_key.encode()
    if method == 'GET':
        data = {"pageSize": 30, "page":1}
        print(data)
        url_params = ''.join(["{}{}".format(i, data[i]) for i in sorted(data.keys())])
        print("url_params", type(url_params), url_params)
        content_type=''
    else:
        url_params = ''
    body_content = ''
    if method == 'POST' or method == 'PUT':
        m = hashlib.md5()
        m.update(json.dumps(data).encode('utf-8'))
        body_content = m.hexdigest()
    else:
        body_content = ''
    srt_sign = '\n'.join(
        [
            method,
            uri,
            url_params,
            content_type,
            body_content,
            str(request_time),
            access_key
        ]
    ).encode()
    print(srt_sign)
    signature = hmac.new(scret_key, srt_sign, hashlib.sha1)
    if method == 'GET':
        url_params="page=1&pageSize=30&"
    return signature.hexdigest(), url_params

def doRequest(cmdbHost, appName, uri, method, access_key, scret_key, data):
    headers = {
        "Host": "openapi.easyops-only.com",
        # "content-type": "application/json"
    }
    expires = str(int(time.time()))
    # expires= '1666085979'
    signature, url_params = gen_signature(access_key=access_key, scret_key=scret_key, request_time=expires, method=method, uri=uri,data=data, content_type="application/json")
    print(signature)
    url = f'http://{cmdbHost}{uri}?{url_params}accesskey={access_key}&signature={signature}&expires={expires}'.format(cmdbHost=cmdbHost,appName=appName, uri=uri,url_params=url_params, access_key=access_key, signature = signature)
    print(url)
    res = requests.get(url=url, headers=headers)
    # res = requests.get(url=f"http://{cmdbHost}{uri}".format(cmdbHost=cmdbHost, uri=uri), params=[url_params, {"access_key":access_key}])
    print(res.status_code)
    print(res.json())


def test():
    access_key = 'fe5ea7b520d1f0e7ae6ab0c8'
    scret_key = '65514d4f4447446d447a52576e595351626f794b4d566a4c4a77486c697a424b'
    objectId = "HOST"
    instanceId = "5de9fa2561eed"
    uri = '/cmdbservice/object/{objectId}/instance/{instanceId}'.format(objectId=objectId, instanceId=instanceId)
    method = 'GET'
    doRequest(cmdbHost="192.168.110.169", appName="cmdbservice", uri=uri, access_key=access_key, scret_key=scret_key, method=method, data={"page_Size": 30, "page": 1})

if __name__ == '__main__':
    test()
