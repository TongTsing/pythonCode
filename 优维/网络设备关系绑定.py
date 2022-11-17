#!/usr/local/easyops/python/bin/python
# -*- coding: utf-8 -*-
from multiprocessing import Pool, Manager, cpu_count
import urlparse
import requests
import logging
import sys
import json
import re
import math
import copy

def get_logger():
    logger = logging.getLogger(__name__)
    logger_handler = logging.StreamHandler(stream=sys.stdout)
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] [%(lineno)d] %(message)s', '%Y-%m-%d %H:%M:%S')
    logger_handler.setFormatter(formatter)
    logger.addHandler(logger_handler)
    return logger


logger = get_logger()


class EasyOps(object):

    def __init__(self, model, ip, org, port=80, *args, **kwargs):
        self.model = model
        self.ip = ip
        self.port = port
        self.headers = {
            "content-type": "application/json",
            "org": str(org),
            "user": "defaultUser",
            "host": "cmdb.easyops-only.com"
        }
        self.timeout = 60
        self.args = args
        self.kwargs = kwargs

    def _upsert(self, data, upsert_list):
        # 这里的data是字典组成的列表
        result = []
        # updateKeys = upsert.get("updateKeys")
        # values = upsert.get("values")
        for i in data:
            result.append({
                "filter": {
                    key: i.get(key)
                    for key in upsert_list
                },
                "update": i,
                "upsert": True
            })
        return result

    def params(self, fields, query, page, page_size, sort):
        """
        构建查询条件体
        :param page: int 开始的页数
        :param page_size: int 每页大小
        :param query: dict 查询条件
        :param fields: dict model中需要返回的字段
        :param sort: str 指定字段排序
        """
        query = query or {}
        fields = fields or {}
        if fields:
            fields["instanceId"] = True
        _sort = {"instanceId": True}
        if sort:
            _sort = {sort: True}
        return {
            "query": query, "fields": fields, "only_my_instance": False,
            "page": page, "page_size": page_size, "sort": _sort
        }

    def getUrl(self, method, data, upsert=None):
        if upsert:
            uri = "object/{}/instance/_import-json".format(self.model)
        else:
            if isinstance(data, dict) and method == 'PUT':
                uri = '/object/{}/instance/{}'.format(self.model, data.get('instanceId'))
            elif isinstance(data, list) and method == 'PUT':
                uri = '/object/{}/instance/_batch_modify'.format(self.model)
            elif isinstance(data, dict) and method == 'POST':
                uri = '/object/{}/instance'.format(self.model)
            elif isinstance(data, list) and method == 'POST':
                uri = '/object/instance/list/{}'.format(self.model)
            elif isinstance(data, dict) and method == 'DELETE':
                uri = '/object/{}/instance/{}'.format(self.model, data.get('instanceId'))
            elif isinstance(data, list) and method == 'DELETE':
                uri = '/object/instance/{}'.format(self.model)
            else:
                uri = '/object/{}/instance/_search'.format(self.model)
        return urlparse.urljoin("http://{}:{}".format(self.ip, self.port), uri)

    def getPageCount(self, total, limit):
        pageCount = int(math.ceil(float(total) / float(limit)))
        return pageCount + 1

    def checkCode(self, response):
        result = {}
        try:
            result = response.json()
            code = result.get("code")
            flag = True
            if str(code) != "0":
                flag = False
                error = result.get("error")
                logger.error("code: {} error: {}".format(code, error.encode("utf8")))
        except BaseException as e:
            flag = False
            logger.error("{}".format(str(e)))
        return result, flag

    def post(self, data, upsert_list=None, limit=1000):
        """
        :param upsert: list 依据什么key进行更新
        """
        url = self.getUrl("POST", data, upsert_list)
        if upsert_list:
            data = self._upsert(data, upsert_list)
        pageCount = self.getPageCount(len(data), limit)
        start = 0
        for i in range(1, pageCount):
            end = limit * i
            _data = data[start:end]
            start = end
            requests.request(method="POST", url=url, headers=self.headers, json=_data, timeout=self.timeout)
        logger.debug("post {} data {} ".format(self.model, len(data)))

    def get(self, fields=None, query=None, page=1, page_size=3000, sort=None):
        """
        :param page: int 开始的页数
        :param page_size: int 每页大小
        :param query: dict 查询条件
        :param fields: dict model中需要返回的字段
        :param sort: str 指定字段排序
        :return: dict
        """
        params = self.params(fields, query, page, page_size, sort)
        url = self.getUrl("GET", params)
        response = requests.request(method="POST", url=url, headers=self.headers, json=params, timeout=self.timeout)
        response, flag = self.checkCode(response)
        result = []
        if flag:
            total = response.get('data', {}).get('total', 0)
            pageCount = self.getPageCount(total, page_size)
            if pageCount <= 1:
                return response.get("data", {}).get("list", [])
            for _page in range(1, pageCount):
                params = self.params(fields, query, _page, page_size, sort)
                response = requests.request(method="POST", url=url, headers=self.headers, json=params,
                                            timeout=self.timeout)
                response, flag = self.checkCode(response)
                if flag:
                    result.extend(response.get('data', {}).get("list", []))
        return result

    def put(self, data, upsert_list=None, limit=3000):
        """
        :param upsert: list 依据什么key进行更新
        """
        url = self.getUrl("POST", data, upsert_list)
        data = self._upsert(data, upsert_list)
        pageCount = self.getPageCount(len(data), limit)
        start = 0
        for i in range(1, pageCount):
            end = limit * i
            _data = data[start:end]
            start = end
            response = requests.request(method="POST", url=url, headers=self.headers, json=_data, timeout=self.timeout)
            self.checkCode(response)
        logger.debug("put {} data {} ".format(self.model, len(data)))

    def delete(self, data, limit=3000):
        url = self.getUrl("DELETE", data)
        pageCount = self.getPageCount(len(data), limit)
        start = 0
        for i in range(1, pageCount):
            end = limit * i
            _data = data[start:end]
            start = end
            delete = {'ids': ';'.join([row.get('instanceId') for row in _data])}
            requests.request(method="DELETE", url=url, headers=self.headers, params=delete, timeout=self.timeout)

        logger.debug("delete {} data {} ".format(self.model, len(data)))

    def autoUpload(self, data, object_id, pks, upsert=False):
        """
        自动采集接口
        :param data: [example,example,example]
        :param object_id: CMDB模型ID
        :param pks: 用于查询出唯一实例的模型字段组合
        :param upsert: 不存在时是否创建，默认为False
        """
        res = []
        for i in data:
            result = {
                'dims': {
                    "pks": pks,
                    "object_id": object_id,
                    "upsert": upsert
                },
                'vals': i  # 上报的数据
            }
            res.append(result)
        print '-----BEGIN GATHERING DATA-----'
        print json.dumps(res)
        print '-----END GATHERING DATA-----'

    def GetAvailableServerIpAndPort(self, port=10080):
        import yaml, socket, platform
        if platform.system() == "Windows":
            filename = "C:\\easyops\\agent\\easyAgent\\conf\\conf.yaml"  # windows
        else:
            filename = "/usr/local/easyops/agent/easyAgent/conf/conf.yaml"  # linux
        with open(filename, "r") as f:
            data = yaml.load(f)
            host_list = re.split("\s*,\s*", data["command"]["server_groups"][0]['hosts'][0]['ip'])
            _all = [(ip, int(port)) for ip in host_list]
        res = ()
        for ip_port in _all:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            result = s.connect_ex(ip_port)
            s.close()
            if result == 0:
                res = ip_port
                break
        return res


def GetNetdPortDevices(easyops, port, result):
    """ 获取对端设备"""
    ipaddr_fields = {
        "host": True,
        "FIREWALL": True,
    }
    switch_fields = {
        "host": "host",
    }
    remote_list = port.get("remote_list")
    if not remote_list: return
    res = {k:[] for k in switch_fields}
    for remote in remote_list:
        peer_mac = remote.get("peer_mac")
        if not peer_mac: continue
        f = copy.deepcopy(ipaddr_fields)
        ipaddress_list = easyops.get(fields=f, query={"mac": peer_mac})
        if not ipaddress_list: continue
        ipaddress = ipaddress_list[0]
        for k, v in switch_fields.items():
            res[k].extend([{"instanceId": ip["instanceId"]} for ip in ipaddress[v]])
    res["instanceId"] = port["instanceId"]
    result.append(res)



def GetPort(easyops, model):
    """ 获取对端列表 """
    easyops.model = model
    fields = {
        "ip": True,
        "port_list.remote_list": True,
    }
    #query = {
    #  "port_list.remote_list": {
    #    "$exists": True
    #  }
    # }
    query = {
#      'ip': "172.98.254.166"
    }
    switch_list = easyops.get(fields=fields, query=query)
    result = []
    for switch in switch_list:
        if "非接入交换机":
            continue
        port_list = switch.get("port_list")
        for port in port_list:
            if port.get("remote_list"):
                result.append(port)
    return result



def main():
    easyops = EasyOps("HOST", CMDB_IP, ORG)
    port_list = GetPort(easyops, "_SWITCH")
    logger.info("SWITCH COUNT: {}".format(len(port_list)))
    result = Manager().list()
    pool = Pool(int(cpu_count()/2))
    easyops.model = "IPADDRESS"
    for port in port_list:
        pool.apply_async(GetNetdPortDevices, (easyops, port, result))
    pool.close()
    pool.join()
    easyops.model = "NETDPORT"
    logger.info("NETDPORT COUNT: {}".format(len(result)))
    easyops.post(result, ["instanceId"])

if __name__ == '__main__':
    # CMDB_IP = "192.25.101.196"
    # ORG = 3109
    CMDB_IP = EASYOPS_CMDB_HOST.split(':')[0]
    ORG = EASYOPS_ORG
    """
    读取ip,判断ip关联设备,获取设备关联至网络端口.
    """
    main()
