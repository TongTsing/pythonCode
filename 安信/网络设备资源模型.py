# -*- coding: utf-8 -*-
__author__ = "raymondsun"
__date__ = "1/20/2021"

from pprint import pprint
import requests
import copy
import base64
import xmltodict
import os
from suds.client import Client


def fmt_print(msg, is_title=False   ):
    if is_title:
        print
        u"======================================================================="
        print
        msg
        print
        u"======================================================================="
    else:
        print
        msg


# 发起请求
def do_requests(url, method, **kwargs):
    url_ = "http://%s%s" % (EASYOPS_CMDB_HOST, url)
    try:
        r = requests.request(url=url_, method=method, **kwargs)
        if r.status_code == 200 and r.json()["code"] == 0:
            return r.json()['data']
        print
        url_
        print
        r.text
    except Exception as e:
        print(e)


# 分页获取过期实例数据
def get_all(obj, query, fields):
    delete_data = []
    #    query={}
    #    fields={"name":True,"IDC":True}
    headers = {"user": "easyops", "org": EASYOPS_ORG, "content-type": "application/json",
               "host": "cmdb_resource.easyops-only.com"}
    params = {"page_size": 3000,
              "page": 1,
              "fields": fields,
              "query": query
              }
    res = do_requests(url="/object/%s/instance/_search" % obj, method="post", headers=headers, json=params)
    total = res["total"]
    all_data = res["list"]
    if total > 3000:
        pages = (total / 3000) + (0 if (total % 3000) == 0 else 1)
        for i in range(2, pages + 1):
            params["page"] = i
            res = do_requests(url="/object/%s/instance/_search" % obj, method="post", headers=headers, json=params)
            all_data += res["list"]
    # print all_data

    return all_data


def update(obj, data):
    headers = {"user": "easyops", "org": EASYOPS_ORG, "content-type": "application/json",
               "host": "cmdb_resource.easyops-only.com"}
    url = "http://{}/object/{}/instance/_import".format(EASYOPS_CMDB_HOST, obj)
    res = requests.request(url=url, method="POST", headers=headers, json=data)
    print
    res.text


#   pass

def delete(obj, instanceId):
    headers = {"user": "easyops", "org": EASYOPS_ORG, "content-type": "application/json",
               "host": "cmdb_resource.easyops-only.com"}
    url = "http://{}/object/{}/instance/{}".format(EASYOPS_CMDB_HOST, obj, instanceId)
    res = requests.request(url=url, method="delete", headers=headers)
    print
    res.text


def searchInstance(CMDB_HOST, objectId, data):
    global headers
    url = "http://{CMDB_HOST}/v3/object/{objectId}/instance/_search".format(objectId=objectId, CMDB_HOST=CMDB_HOST)
    reqs = requests.post(url=url, headers=headers, json=data)
    if reqs.status_code == 200:
        tmpList = reqs.json()['data']['list']
        instanceList = []
        for i in tmpList:
            instanceList.append(i['instanceId'])
        return instanceList
    else:
        print("not 200")


def delInstance(CMDB_HOST, objectId, instanceList):
    global headers
    # 封装数据
    tmpList = []
    for i in instanceList:
        tmpList.append({"_object_id": objectId, "instanceId": i})
    print(tmpList)
    data = {
        "data": tmpList
    }
    url = "http://{CMDB_HOST}/mix/object/instance/delete".format(CMDB_HOST=CMDB_HOST)
    reqs = requests.post(url=url, headers=headers, json=data)
    if reqs.status_code == 200:
        print(reqs)
    else:
        print("res is not 200")


# 分页获取所有数据
def get_all(url, method, data=None):
    #  data = kwargs.get("json", {}) or kwargs["params"]
    data["page"] = 1
    data["page_size"] = data.get("page_size", 500)

    # 标准openAPI请求发起器
    conn = OpenApi(access_key='c51810c5c883b6fab54f9fdd',
                   secret_key='7646674564435744784c4b75464a524c4143536e477644616165776f6b4a6c42', host='10.2.239.45')
    code, r = conn.start(method=method, op_url=url, data=data)

    total = r["total"]
    pages = total / data['page_size'] + (total % data['page_size'] and total / data['page_size'] != 0)

    all_data = r["list"]

    for x in range(2, pages + 1):
        data["page"] = x
        other_code, other_data = conn.start(method='post', op_url=url, data=data)
        all_data += other_data['list']

    return True, all_data


if __name__ == "__main__":
    sourceid_list = ["SWITCH", "ROUTER", "BALANCE", "FIREWALL", "INTERNET_SERVER_IP", "NETDPORT"]
    systime = time.strftime("%Y-%m-%d", time.localtime(time.time()))
    query = {}
    fields = {"name": True, "instanceId": True, "updatetimes": True, "hashID": True}
    for obj in sourceid_list:
        updata_data = get_all(obj, query, fields)
        updata = []
        for i in updata_data:
            if i.get("updatetimes") == systime:
                i["issurvival"] = "yes"
            else:
                i["issurvival"] = "no"
            updata.append(i)

        if obj == "INTERNET_SERVER_IP" and "NETDPORT":
            updatas = {"keys": ["hashID"], "datas": updata}
        else:
            updatas = {"keys": ["name"], "datas": updata}

        update(obj=obj, data=updatas)

        # 删除issurvival字段为no的实例
        data = {
            "fields": ["instanceId"],
            "query": {
                "issurvival": {
                    "$like": "no%"
                }
            },
            "page_size": 300
        }
        for objectId in sourceid_list:
            insList = []
            for i in range(100):
                tmpList = searchInstance(CMDB_HOST=EASYOPS_CMDB_HOST, objectId=objectId, data=data)
                if not tmpList:
                    break
                delInstance(CMDB_HOST=EASYOPS_CMDB_HOST, objectId=objectId, instanceList=insList)


