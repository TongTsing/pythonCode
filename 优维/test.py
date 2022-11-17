from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
import json
import sys
import hashlib
import hmac

reload(sys)
sys.setdefaultencoding('utf8')

ask = "fe5ea7b520d1f0e7ae6ab0c8"
ssk = "65514d4f4447446d447a52576e595351626f794b4d566a4c4a77486c697a424b"
cmdb_host = "192.168.110.169"


def fmt_print(msg, is_title=False):
    if is_title:
        print("=======================================================================")
        print(msg)
        print("=======================================================================")
    else:
        print(msg)


# 生成cmdb openAPI接口签名, HMAC加密
def create_cmdb_sig(method, url, data):
    # 信息预处理
    method = method.upper()
    m = hashlib.md5()
    m.update(json.dumps(data).encode("utf-8"))
    content = m.hexdigest()
    a = ''
    req_time = str(int(time.time()))
    # 信息拼接
    fields = "\n".join(
        [method,
         url,
         a,
         "application/json",
         content,
         req_time,
         ask]
    )

    # hmac加密
    signature = hmac.new(ssk, fields, hashlib.sha1).hexdigest()

    return signature, "%s?accesskey=%s&expires=%s&signature=%s" % (url, ask, req_time, signature)


# 发起请求
def do_requests(url, data={}):
    method = "post"
    # 获取签名
    sig, url = create_cmdb_sig(method, url, data)
    url_ = "http://%s%s" % (cmdb_host, url)
    headers = {"Content-Type": "application/json", "host": "openapi.easyops-only.com"}
    # 发起请求
    fmt_print("%s: %s" % (method, url_))
    try:
        r = requests.request(url=url_, method=method, headers=headers, timeout=20, json=data, verify=False)
        if r.status_code == 200:
            if r.json().get("code", 1) == 0 or r.json().get("statuscode", 1) == 0:
                fmt_print("请求成功")
                return r
        fmt_print("请求失败")
        fmt_print(r.text)
    except Exception as e:
        fmt_print("请求异常")
        fmt_print(e)

if __name__ == '__main__':
    access_key = 'fe5ea7b520d1f0e7ae6ab0c8'
    scret_key = '65514d4f4447446d447a52576e595351626f794b4d566a4c4a77486c697a424b'
    objectId = "HOST"
    instanceId = "5de9fa2561eed"
    uri = '/object/{objectId}/instance/{instanceId}'.format(objectId=objectId, instanceId=instanceId)
    do_requests(url=uri, data={})