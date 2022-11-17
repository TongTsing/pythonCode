# -*- coding: utf-8 -*-
__author__ = "Lon"
__date__ = "1/11/2021"
__desc__ = "上架流程更新设备序列号、设备型号、采购人、配置描述以及放置机房信息等"

from jsonpath import jsonpath
import requests
import copy


# 上报数据
def report_data(obj, datas, key="name"):
    # 预处理
    for i in datas:
        for m, n in i.items():
            if n == "" or n == []:
                del i[m]

    print
    json.dumps(datas, indent=2)

    url = "/object/%s/instance/_import" % obj
    header = {"user": "lonlin", "org": str(EASYOPS_ORG), "content-type": "application/json",
              "host": "cmdb_resource.easyops-only.com"}
    method = "POST"
    count = len(datas)

    # 分批插入, 每次200
    for m in range(1, 1000):
        print
        u"上报模型: %s; 上报总数: %d; 当前批次: %d" % (obj, count, m)
        if m * 200 >= count:
            data = {"keys": [key], "datas": datas[(m - 1) * 200: count]}
            print
            do_requests(url=url, method=method, headers=header, json=data)
            break
        else:
            data = {"keys": [key], "datas": datas[(m - 1) * 200: m * 200]}
            print
            do_requests(url=url, method=method, headers=header, json=data)


# 发起请求
def do_requests(url, method, **kwargs):
    url_ = "http://%s%s" % (EASYOPS_CMDB_HOST, url)
    try:
        r = requests.request(url=url_, method=method, **kwargs)
        if r.status_code == 200 and r.json()["code"] == 0:
            return r.json()['data']
        print
        u"请求返回错误: %s" % url_
        print
        r.text
    except Exception as e:
        print
        u"请求异常:"
        print(e)


# 获取用户
def get_user():
    headers = {"user": "lonlin", "org": str(EASYOPS_ORG), "content-type": "application/json",
               "host": "cmdb_resource.easyops-only.com"}
    data = {"fields": {"name": 1}, "page": 1, "page_size": 1000}
    datas = do_requests("/object/USER/instance/_search", "post", headers=headers, json=data)["list"]
    user_dict = {i["name"]: i["instanceId"] for i in datas}
    return user_dict


def easyops_request(url, method, params=None):
    headers = {'Host': 'cmdb_resource.easyops-only.com', 'org': str(EASYOPS_ORG), 'user': 'easyops',
               'content-type': 'application/json'}
    url = 'http://{EASYOPS_CMDB_HOST}{url}'.format(EASYOPS_CMDB_HOST=EASYOPS_CMDB_HOST.split(":")[0], url=url)
    print
    url
    #  print headers
    #  print params
    #  print method
    response = requests.request(method, url, headers=headers, json=params)
    #  print response.text
    try:
        response_json = response.json()
        if response.status_code == 200:
            if response_json['code'] == 0:
                return 0, response_json['data']  # success
            else:
                return response_json['code'], response_json['data']
        else:
            try:
                return response_json['code'], response_json['data']
            except Exception as e:
                print
                "http exception: ", e
    except Exception as e:
        print
        e


# 获取设备信息
def get_data():
    print
    u"【解析开始】"

    form_datas = json.loads(orderInfo)

    # print  json.dumps(form_datas, indent=2, ensure_ascii=False)

    form_datas = form_datas["stepList"]
    form_datas.reverse()

    zc_datas = {}
    ip_datas = []
    changes = []

    got1 = False
    got2 = False
    got3 = False

    users = get_user()

    # print  json.dumps(form_datas, indent=2, ensure_ascii=False)

    # exit()

    for i in form_datas:

        # 获取分配网络环节数据
        if i["userTaskId"] == "Activity_0w6g5g3":
            if got1:
                continue

            formData = json.loads(i["formData"])

            for k, j in enumerate(formData[0]["values"]):

                headers = {"user": "easyops", "org": str(EASYOPS_ORG), "content-type": "application/json",
                           "host": "cmdb_resource.easyops-only.com"}
                data = {
                    "fields": {"instanceId": 1, "name": 1},
                    "query": {
                        "name": {
                            "$eq": j["ip"]
                        }
                    }
                }
                url = "/object/IPADDRESS/instance/_search"
                code, res = easyops_request(url, "POST", data)
                instanceId = None
                if code == 0:
                    instanceId = res["list"][0]["instanceId"]
                    print("IPADDRESS instance searched!")
                # exit()

                hh = j.get("host") or j.get("change_host")

                if zc_datas.get(str(k)) is None:
                    zc_datas[str(k)] = {}

                # 实例选择框数据处理
                # 获取设备所在物理机器
                # headers = {"user": "lonlin", "org": str(EASYOPS_ORG), "content-type": "application/json", "host": "cmdb_resource.easyops-only.com"}
                # data={
                #     "fields": {"instanceId": 1, "PHYSICAL.name": 1},
                #     "query": {
                #         "hostname": {
                #             "$eq": j["ip"]
                #         }
                #     }
                # }
                # url = "/object/IPADDRESS/instance/_search"
                # code, res = easyops_request(url, "POST", data)

                # "name"中填入所在物理机
                # "instanceId"填入物理机的instanceId
                zc_datas[str(k)].update({"name": j["host"][0]["name"],
                                         "instanceId": j["host"][0]["instanceId"],
                                         "status": u"已上架",
                                         "productIp": j["ip"]})

                #       if j["ip"][0].get("instanceId") is not None:
                #          zc_datas[str(k)]["IPADDRESS"] = [j["ip"][0]["instanceId"]]

                if instanceId is not None:
                    zc_datas[str(k)]["IPADDRESS"] = instanceId
                # 字符串数据处理
                zc_data = copy.deepcopy(j)
                if j.get("host") is not None:
                    del zc_data["host"]

                if j.get("change_host") is not None:
                    del zc_data["change_host"]
                print("line 180 ======================")
                print(zc_data)

                del zc_data["ip"]
                # del zc_data["fvhqo3gve91"]
                # del zc_data["fvdfijjllv"]
                if zc_data.get("atype") is not None:
                    del zc_data["atype"]

                #  if zc_data.get("cluster") is not None:
                #      del zc_data["cluster"]

                zc_datas[str(k)].update(zc_data)

                # IP采集
                ip_datas.append({"name": j["ip"], "status": u"已分配"})
                print("line154++++++++++++++++++++++++++++++")

            got1 = True

            # 获取上架实施环节数据
        if i["userTaskId"] == "Activity_0u9ga6r":
            if got2:
                continue

            formData = json.loads(i["formData"])

            if formData[1]["values"][0].get("fvhxjpb1i3") is not None:
                fd = formData[1]["values"]
            else:
                fd = formData[0]["values"]

            for k, j in enumerate(fd):
                hh = j.get("host") or j.get("change_host")
                if zc_datas.get(str(k)) is None:
                    zc_datas[str(k)] = {}

                # 实例选择框数据处理
                zc_datas[str(k)].update({"_startU": j["fvhxjpb1i3"],
                                         "name": hh[0]["name"],
                                         "instanceId": hh[0]["instanceId"],
                                         "_occupiedU": j["fvhxust2l5"],
                                         "IDCRACK": [j["fvhxjpb1i2"][0]["instanceId"]]})
                # 字符串数据处理
                zc_data = copy.deepcopy(j)

                if j.get("host") is not None:
                    del zc_data["host"]

                if j.get("change_host") is not None:
                    del zc_data["change_host"]

                if len(j.get("change_host", [])) != 0:
                    changes.append(j["change_host"][0]["name"])

                del zc_data["fvhxjpb1i3"]
                del zc_data["fvhxust2l5"]
                del zc_data["fvhxjpb1i2"]
                if zc_data.get("atype") is not None:
                    del zc_data["atype"]
                if zc_data.get("business") is not None:
                    del zc_data["business"]
                zc_datas[str(k)].update(zc_data)

            got2 = True

            # 获取提交申请单环节数据
        if i["userTaskId"] == "Activity_0wuvxe3":
            if got3:
                continue

            formData = json.loads(i["formData"])

            if formData[0]["values"][0].get("fva0geov8h") is not None:
                fd1 = formData[0]["values"]
                fd2 = formData[1]["values"]
            else:
                fd1 = formData[1]["values"]
                fd2 = formData[0]["values"]

            for k, j in enumerate(fd2):
                hh = j.get("host") or j.get("change_host")

                if zc_datas.get(str(k)) is None:
                    zc_datas[str(k)] = {}

                # 实例选择框数据处理
                zc_datas[str(k)].update({"BUSINESS": [mm["instanceId"] for mm in j.get("business", [])],
                                         "name": hh[0]["name"],
                                         "instanceId": hh[0]["instanceId"],
                                         "ADMIN_A": [users[s["name"]] for s in fd1[0]["fva0geov8h"] if
                                                     users.get(s["name"]) is not None]})

            got3 = True

    '''
    host_datas = [{"ip": i.get("productIp", ""), "hostname": i.get("hostname", ""), "isAllowedWithoutMonitor": "true", "owner": i.get("ADMIN_A", []), "BUSINESS": i.get("BUSINESS", []), "sn": i["name"], "osSystem": i.get("system", ""), "PHYSICAL": [i["instanceId"]]} for i in zc_datas.values() if i.get("name", "") not in changes]
    '''

    host_datas = []
    for i in zc_datas.values():
        if i.get("name", "") not in changes:
            host_data = {}
            host_cluster = []
            host_data["ip"] = i.get("productIp", "")
            host_data["hostname"] = i.get("hostname", "")
            host_data["isAllowedWithoutMonitor"] = "true"
            host_data["owner"] = i.get("ADMIN_A", [])
            host_data["BUSINESS"] = i.get("BUSINESS", [])
            host_data["sn"] = i["name"]
            host_data["osSystem"] = i.get("system", "")
            host_data["PHYSICAL"] = [i["instanceId"]]

            if len(host_data["ip"]) > 0:
                host_data["ip"]
                search_params = {
                    "fields": {
                        "ip": True,
                        "_deviceList_CLUSTER.name": True,
                    },
                    "query": {
                        "ip": {"$eq": host_data["ip"]}
                    },
                    "page": 1,
                    "page_size": 10
                }
                search_code, search_datas = easyops_request("/object/HOST/instance/_search", "POST", search_params)
                if search_code == 0:
                    if search_datas["list"]:
                        for k in search_datas["list"][0]["_deviceList_CLUSTER"]:
                            host_cluster.append(k["instanceId"])

            if i.has_key("cluster") and len(i["cluster"]) > 0:
                for j in i["cluster"]:
                    host_cluster.append(j["instanceId"])
                host_data["_deviceList_CLUSTER"] = host_cluster

            host_datas.append(host_data)

    print
    u"【解析结束】"
    return zc_datas.values(), ip_datas, host_datas


# 主逻辑
if __name__ == "__main__":
    zc_datas, ip_datas, host_datas = get_data()

    print
    "zc_datas:"
    print
    json.dumps(zc_datas, indent=2, ensure_ascii=False)
    print"ip_datas:"
    print
    json.dumps(ip_datas, indent=2, ensure_ascii=False)
    print "host_datas:"
    print json.dumps(host_datas, indent=2, ensure_ascii=False)
    print "line290===================="
    # exit()

    # 上报
    print u"【开始上报cmdb】"
    print u"===========物理机==============="
    report_data("PHYSICAL", zc_datas)
    print u"============IP================="
    report_data("IPADDRESS", ip_datas)
    print u"===========操作系统=============="
    report_data("HOST", host_datas, key="ip")
    print u"【上报cmdb结束】"

    PutStr("code", 0)

