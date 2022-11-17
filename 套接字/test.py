#!/usr/local/easyops/python/bin/python
# -*- coding: utf-8 -*-
"""
2021/08/18
"""
from collections import OrderedDict
from multiprocessing import Pool, Manager, cpu_count
import os
import subprocess
import time
import urlparse
import requests
import logging
import sys
import math
import json
import re


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
        self.timeout = 180
        self.args = args
        self.kwargs = kwargs

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

    def _upsert(self, data, upsert_list, upsert):
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
                "upsert": upsert
            })
        return result

    def getPageCount(self, total, limit):
        pageCount = int(math.ceil(float(total) / float(limit)))
        return pageCount + 1

    def checkCode(self, response):
        result = {}
        flag = False
        if response.status_code == 200:
            try:
                result = response.json()
                code = result.get("code")
                flag = True
                if str(code) != "0":
                    error = result.get("error")
                    logger.error("code: {} error: {}".format(code, error.encode("utf8")))
            except BaseException as e:
                logger.error("{}".format(str(e)))
        else:
            logger.error("request http status {}".format(response.status_code))
        return result, flag

    def error(self, number, response):
        _, flag = self.checkCode(response)
        if not flag:
            return number
        error_count = 0
        response_json = response.json()
        code = response_json.get("code")
        if str(code) == "0":
            data_list = response_json.get("data")
            if isinstance(data_list, list):
                for i in data_list:
                    if isinstance(i, dict):
                        message = i.get("message").encode("utf8")
                        instanceId = i.get("instanceId", "None")
                        if message:
                            error_count += 1
                            logger.error("instanceId: {} error:{}".format(instanceId, message))
        else:
            message = response_json.get("error").encode("utf8")
            if message:
                error_count += 1
                logger.error("{}".format(message))
        return error_count

    def post(self, data, upsert_list=None, upsert=True, model=None, limit=3000):
        """
        :param upsert_list: list 依据什么key进行更新
        :param upsert: True 存在即更新不存在即创建、 False 存在即更新

        """
        if model:
            self.model = model
        url = self.getUrl("POST", data, upsert_list)
        if upsert_list:
            data = self._upsert(data, upsert_list, upsert)
        pageCount = self.getPageCount(len(data), limit)
        start = 0
        error_count = 0
        for i in range(1, pageCount):
            end = limit * i
            _data = data[start:end]
            start = end
            response = requests.request(method="POST", url=url, headers=self.headers, json=_data, timeout=self.timeout)
            error_count += self.error(len(_data), response)
        logger.info("post: {} success: {} error: {}".format(self.model, len(data) - error_count, error_count))

    def get(self, fields=None, query=None, model=None, page=1, page_size=3000, sort=None):
        """
        :param page: int 开始的页数
        :param page_size: int 每页大小
        :param query: dict 查询条件
        :param fields: dict model中需要返回的字段
        :param sort: str 指定字段排序
        :return: dict
        """
        if model:
            self.model = model
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
                print(response)
                response, flag = self.checkCode(response)
                if flag:
                    result.extend(response.get('data', {}).get("list", []))
        return result

    def put(self, data, upsert_list=None, upsert=True, limit=3000):
        """
        :param upsert: list 依据什么key进行更新
        """
        url = self.getUrl("POST", data, upsert_list)
        data = self._upsert(data, upsert_list, upsert)
        pageCount = self.getPageCount(len(data), limit)
        start = 0
        error_count = 0
        for i in range(1, pageCount):
            end = limit * i
            _data = data[start:end]
            start = end
            response = requests.request(method="POST", url=url, headers=self.headers, json=_data, timeout=self.timeout)
            error_count += self.error(len(_data), response)
        logger.info("put: {} success: {} error: {}".format(self.model, len(data) - error_count, error_count))

    def delete(self, data, limit=3000):
        url = self.getUrl("DELETE", data)
        pageCount = self.getPageCount(len(data), limit)
        start = 0
        error_count = 0
        for i in range(1, pageCount):
            end = limit * i
            _data = data[start:end]
            start = end
            delete = {'ids': ';'.join([row.get('instanceId') for row in _data])}
            response = requests.request(method="DELETE", url=url, headers=self.headers, params=delete,
                                        timeout=self.timeout)
            error_count += self.error(len(_data), response)
        logger.info("delete: {} success: {} error: {}".format(self.model, len(data) - error_count, error_count))

    def getinstanceId(self, data, upsert_list):
        """
         获取数据id, 用于绑定关系
        :param data: list [{}, {}, {}]
        :param upsert_list:  list，用于匹配instanceId 的字段
        :return:
        """
        result = []
        for i in data:
            query = {k: i[k] for k in upsert_list if i.has_key(k)}
            value = self.get(fields={"instanceId": True}, query=query)
            if value:
                value = {"instanceId": value[0]["instanceId"]}
                result.append(value)
        return data

    @property
    def NowTime(self):
        nowTime = time.localtime(time.time())
        return time.strftime("%Y-%m-%d %H:%M:%S", nowTime)

    def deleteNotUpdate(self, key, updateTime):
        """ 删除在此之前未更新的数据 """
        query = {key: {"$gte": "1997-05-07 00:00:00", "$lte": updateTime}}
        data_list = self.get(query=query, fields={"instanceId": True})
        self.delete(data_list)

    def AutoUpload(self, data, object_id, pks, upsert=False):
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
        for ip_port in _all:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            result = s.connect_ex(ip_port)
            s.close()
            if result == 0:
                self.ip = ip_port[0]
                self.port = ip_port[1]


class SnmpWalk(object):

    def __init__(self, ip, brand, token, ResultKeys, ipAdEntKeys, RemoteKeys, FileBasePath, debug):
        self.ip = ip  # 目标ip
        self.brand = brand  # 品牌
        self.token = token  # 社区令牌
        self.FileBasePath = FileBasePath  # 文件保存位置
        self.debug = debug
        self.ResultKeys = ResultKeys  # 交换机
        self.ipAdEntKeys = ipAdEntKeys  # 网络端口
        self.RemoteKeys = RemoteKeys  # 对端列表
        self.DATA = OrderedDict()  # oid执行返回数据
        self.result = {}  # 返回结果
        self.ip_result = OrderedDict()  # 网络设备端口
        self.error_list = list()
        self.AllOid = {}  # 所有品牌-型号的oid

    def _writeFile(self, oidName, data):
        if self.FileBasePath:
            Path = os.path.join(self.FileBasePath, self.ip)
            if not os.path.exists(Path):
                os.makedirs(Path)
            filePath = os.path.join(Path, oidName)
            with open(filePath, "w") as f:
                f.write(data)

    def _ReadFile(self, oidName):
        if self.FileBasePath:
            filePath = os.path.join(self.FileBasePath, self.ip, oidName)
            data = ""
            if os.path.exists(filePath):
                with open(filePath, "r") as f:
                    data = f.read()
            return data

    def _Cmd(self, oid):
        """ snmpwalk 系统命令"""
        cmd = "snmpwalk -v 2c -c {0} {1} {2}".format(self.token, self.ip, oid)
        print(cmd)
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        stdout = p.stdout.read().decode('gbk')
        print("*"*100)
        print("test_tq_snmpwalk output")
        print(stdout)
        print("*" * 100)
        code = p.wait()
        return stdout

    def _Merge(self, dict1, key, value):
        if key in dict1:
            dict1[key].update(value)
        else:
            dict1[key] = value

    def readDATA(self, oidName):
        filePath = os.path.join(self.FileBasePath, self.ip, oidName)
        if self.debug and os.path.exists(filePath) and not self.DATA.has_key(oidName):
            with open(filePath, "r") as f:
                data = f.read()
            self.DATA[oidName] = data
        else:
            data = self.DATA.get(oidName, "")
        return data

    def _GetOidData(self, oid=None, _break=True):
        """ 执行oid命令 """
        if oid:
            Command = oid
        else:
            Command = self.AllOid[self.__class__.__name__]
        for oid, command in Command.items():
            if self.debug:
                data = self._ReadFile(oid)
            else:
                data = self._Cmd(command)
                self._writeFile(oid, data)
            if "Timeout: No Response" in data:
                self.ChangeResult(self.ResultKeys, self.result, "netSnmp", "异常")
                if self.ip not in self.error_list:
                    self.error_list.append(self.ip)
                if _break: break
            else:
                self.DATA[oid] = data

    def MacFormat(self, mac):
        """ mac 格式化"""
        res = {}
        format_list = mac.split(':')
        num = 0
        # 根据':'分隔，若位数为1，则在前面补齐0
        for i in format_list:
            num += 1
            if len(i) == 1:
                res[num] = '0' + i
            elif len(i) == 2:
                res[num] = i
        mac_addr = []
        for i in range(1, 7):
            if i not in res:
                # logger.error("ip: {} error: mac地址错误 data:{}".format(self.ip, mac))
                return ""
            mac_addr.append(res[i])
        mac_addr = ":".join(mac_addr)
        # 小写字母转换为大写

        return mac_addr.upper()

    def ChangeResult(self, KeyDict, newDict, key, value):
        """ 将返回值的key置换为模型中的ID """
        print("")
        new_key = KeyDict.get(key, "")
        if not new_key: return
        if isinstance(new_key, dict):
            pass
        else:
            newDict[new_key] = value

    def IpAndName(self):
        self.ChangeResult(self.ResultKeys, self.result, "IP", self.ip)
        sn = self.result.get(self.ResultKeys["SN"])
        name = self.ip
        if sn:
            name = "{}_{}".format(self.ip, sn)
        self.ChangeResult(self.ResultKeys, self.result, "Name", name)

    def CleaningData(self):
        for oid in self.DATA:
            if hasattr(self, oid):
                getattr(self, oid)()
        self.IpAndName()

#Public(allBrand, ip, brand, community, ResultKeys, ipAdEntKeys, RemoteKeys, FileBasePath, debug)
#
class Public(SnmpWalk):

    def __init__(self, allBrand, *args, **kwargs):
        super(Public, self).__init__(*args, **kwargs)
        self.args = args
        self.kwargs = kwargs
        self.allBrand = allBrand
        self.AllOid["Public"] = self._GetPublicOid
        self.BrandObj = None  # 品牌对象
        self.ARP = dict()  # ARP
        self.MacPort = dict()  # 临时存放数据
        self.dictPortChannel = dict()  # 聚合端口
        self.mac_port_table = dict()  # mac
        self._GetOidData()

    @property
    def _GetPublicOid(self):
        """ 保证oid顺序执行 """
        public_oid = OrderedDict()
        public_oid["ipAdEnt"] = ".1.3.6.1.2.1.4.20"
        public_oid["sysName"] = "1.3.6.1.2.1.1.5.0"
        public_oid["serial"] = "1.3.6.1.2.1.47.1.1.1.1.11"
        public_oid["sysDescr"] = "1.3.6.1.2.1.1.1.0"
        public_oid["IfDescr"] = "1.3.6.1.2.1.2.2.1.2"
        public_oid["snmpEngineId"] = ".1.3.6.1.6.3.10.2.1.3"
        public_oid["IfType"] = ".1.3.6.1.2.1.2.2.1.3"
        public_oid["IfAdminStatus"] = ".1.3.6.1.2.1.2.2.1.7"
        public_oid["IfOperStatus"] = ".1.3.6.1.2.1.2.2.1.8"
        public_oid["IfPhysAddress"] = ".1.3.6.1.2.1.2.2.1.6"
        public_oid["IfSpeed"] = ".1.3.6.1.2.1.2.2.1.5"
        public_oid["IfMTU"] = ".1.3.6.1.2.1.2.2.1.4"
        public_oid["IfName"] = "1.3.6.1.2.1.31.1.1.1.1"

        public_oid["portChannel"] = "iso.2.840.10006.300.43.1.2.1.1.13"
        public_oid["IpNetToMediaPhysAddress"] = ".1.3.6.1.2.1.4.22.1.2"

        public_oid["dot1dBasePortIfIndex"] = "1.3.6.1.2.1.17.1.4.1.2"
        public_oid["dot1qTpFdbPort"] = "1.3.6.1.2.1.17.4.3.1.2"
        public_oid["dot1qTpFdbMac"] = "1.3.6.1.2.1.17.4.3.1.1"

        public_oid["lldpRemEntry"] = "1.0.8802.1.1.2.1.4.1.1"

        return public_oid

    def GetValue(self, GetIndex, data, expression, i, name, default=None):
        index = GetIndex(i)
        if not index: return
        value_list = re.findall(expression, i)
        if value_list:
            value = value_list[0]
            if name == "peerMac":
                value = value.replace(" ", ":").upper()
        elif default is None:
            return
        else:
            value = default
        self._Merge(data, index, {name: value})

    def _getvalue(self, data, key, keys):
        _key = keys.get(key)
        result = ""
        if _key:
            result = data.get(_key, "")
        return result

    def _getPortInfo(self, data, keyName, reExp, func=None):
        """ 获取网络设备端口信息 """
        for i in data:
            array_data = i.split(" ")
            if len(array_data) < 3: continue
            idx = array_data[0]
            if self.ip_result.has_key(idx):
                if func:
                    value = func(array_data[3])
                else:
                    v_list = re.findall(reExp, array_data[3])
                    value = v_list[0]
                self.ChangeResult(self.ipAdEntKeys, self.ip_result[idx], keyName, value)

    def ipAdEnt(self):
        """
        1.3.6.1.2.1.4.20.1.1 - ipAdEntAddr              #### IP地址 ####
        1.3.6.1.2.1.4.20.1.2 - ipAdEntIfIndex           #### IP地址接口编号 ####
        1.3.6.1.2.1.4.20.1.3 - ipAdEntNetMask           #### IP地址掩码 ####
        1.3.6.1.2.1.4.20.1.4 - ipAdEntBcastAddr         #### 是否广播 ####
        1.3.6.1.2.1.4.20.1.5 - ipAdEntReasmMaxSize      #### 可重组IP报文最大值 ####
        """
        result = {}

        def getIp(data, efault, reExp, KeyNAme, result, valueType="str"):
            for i in data:
                idx = i.split()[0]
                value_list = re.findall(reExp, i)
                if value_list:
                    value = value_list[0]
                else:
                    value = efault
                if valueType == "int":
                    value = int(value)
                if result.has_key(idx):
                    result[KeyNAme] = value
                else:
                    result = {KeyNAme: value}

        data = self.readDATA(sys._getframe().f_code.co_name)

        ipAdEntAddrTxt = re.findall(r'IP-MIB::ipAdEntAddr.(.*)', data)
        getIp(ipAdEntAddrTxt, "", r'IpAddress:.(.*)', "Addr", result)

        ipAdEntIfIndexTxt = re.findall(r'IP-MIB::ipAdEntIfIndex.(.*)', data)
        getIp(ipAdEntIfIndexTxt, "0", r'INTEGER:.(.*)', "ifIdx", result)

        ipAdEntIfIndexTxt = re.findall(r'IP-MIB::ipAdEntNetMask.(.*)', data)
        getIp(ipAdEntIfIndexTxt, "255.255.255.255", r'IpAddress:.(.*)', "NetMask", result)

        ipAdEntIfIndexTxt = re.findall(r'IP-MIB::ipAdEntBcastAddr.(.*)', data)
        getIp(ipAdEntIfIndexTxt, "", r'INTEGER:.(.*)', "BcastAddr", result, "int")

        ipAdEntIfIndexTxt = re.findall(r'IP-MIB::ipAdEntReasmMaxSize.(.*)', data)
        getIp(ipAdEntIfIndexTxt, 65535, r'INTEGER:.(.*)', "ipAdEnt", result, "int")

    def serial(self):
        """ 除思科外兼容其它品牌获取sn号 """
        data = self.readDATA(sys._getframe().f_code.co_name).replace("\r\n", ';')
        sn_list = re.findall(r'.STRING: "(.*)"', data)
        if sn_list:
            self.ChangeResult(self.ResultKeys, self.result, "SN", sn_list[0])

    def sysDescr(self):
        """ 处理基本信息 """
        data = self.readDATA(sys._getframe().f_code.co_name).replace("\r\n", ';')
        self.result['name'] = self.ip
        if len(data) <= 0: return
        sys_version_list = re.findall(r'.Version (.*)', data)
        version = sys_version_list[0].split(' ')[0].replace(',', '') if sys_version_list else "unknown version"
        self.ChangeResult(self.ResultKeys, self.result, "sysVersion", version)
        sysDescrList = re.findall(r'.sysDescr.0 = STRING: (.*)', data)
        sysDescr = sysDescrList[0] if sysDescrList else ""
        self.ChangeResult(self.ResultKeys, self.result, "sysDescr", sysDescr)
        value = self.allBrand.get(self.brand, None)
        if not value:
            for key, _value in self.allBrand.items():
                _brand = data.lower().replace(" ", "")
                if key.lower() in _brand:
                    value = _value
                    self.ChangeResult(self.ResultKeys, self.result, "Brand", key)
                    break
            else:
                # TODO 无法从描述中获取品牌需单独处理
                pass
        if value:
            self.BrandObj = value(*self.args, **self.kwargs)
            self.BrandObj.DATA.update(self.DATA)
            self.BrandObj.CleaningData()
            self.result.update(self.BrandObj.result)

    def sysName(self):
        data = self.readDATA(sys._getframe().f_code.co_name).strip('\n').split(' ')
        if len(data) >= 4:
            self.ChangeResult(self.ResultKeys, self.result, "sysName", data[3])

    def snmpEngineId(self):
        """ 设备启动时间 """
        data = self.readDATA(sys._getframe().f_code.co_name)
        upTimeTxt = re.findall(r'SNMP-FRAMEWORK-MIB::snmpEngineTime.(.*)', data)
        if upTimeTxt:
            upTime_seconds = int(upTimeTxt[0].split(' ')[3])
            upTime_localTime = time.localtime(time.time() - upTime_seconds)
            dev_upTime = time.strftime("%Y-%m-%d %H:%M:%S", upTime_localTime)
        else:
            dev_upTime = "1970-01-01 00:00:00"
        self.ChangeResult(self.ResultKeys, self.result, "DevUpTime", dev_upTime)

    def IfDescr(self):
        """ 网络接口信息 """
        data = self.readDATA(sys._getframe().f_code.co_name)
        ifDescr_list = re.findall(r'IF-MIB::ifDescr.(.*)', data)
        """ 网络接口列表: 网络接口标识符 = 设备名 + ":" + 端口 """
        netport_relation = []
        for i in ifDescr_list:
            _res = {}
            v = i.split(' ')
            if len(v) < 4: continue
            netd_port_logo = self._getvalue(self.result, "sysName", self.ResultKeys) + ':' + v[3]
            idx = v[0]
            if self.ip_result.has_key(idx):
                self.ChangeResult(self.ipAdEntKeys, self.ip_result[idx], "Name", netd_port_logo)
                self.ChangeResult(self.ipAdEntKeys, self.ip_result[idx], "IfName", v[3])
            else:
                self.ChangeResult(self.ipAdEntKeys, _res, "Name", netd_port_logo)
                self.ChangeResult(self.ipAdEntKeys, _res, "IfName", v[3])
                self.ip_result[idx] = _res
            netport_relation.append({'name': netd_port_logo})
        self.ChangeResult(self.ResultKeys, self.result, "NetPort", netport_relation)

    def IfType(self):
        """ 交换机端口 -> 类型:"""
        data = re.findall(r'IF-MIB::ifType.(.*)', self.readDATA(sys._getframe().f_code.co_name))
        self._getPortInfo(data, "Type", r"(.+)[(]")

    def IfOperStatus(self):
        """ 交换机端口 -> 状态:"""
        data = re.findall(r'IF-MIB::ifOperStatus.(.*)', self.readDATA(sys._getframe().f_code.co_name))
        self._getPortInfo(data, "OperStatus", r"(.+)[(]")

    def IfAdminStatus(self):
        """ 交换机端口 -> 管理状态:"""
        data = re.findall(r'IF-MIB::ifAdminStatus.(.*)', self.readDATA(sys._getframe().f_code.co_name))
        self._getPortInfo(data, "AdminStatus", r"(.+)[(]")

    def IfPhysAddress(self):
        """ 交换机端口 -> 物理地址:"""
        data = re.findall(r'IF-MIB::ifPhysAddress.(.*)', self.readDATA(sys._getframe().f_code.co_name))
        self._getPortInfo(data, "PhysAddr", r"", self.MacFormat)

    def IfSpeed(self):
        """ 交换机端口 -> 协商速率:"""

        def func(value):
            return "{}{}".format(str(int(value) / 1000000), "Mbps")

        data = re.findall(r'IF-MIB::ifSpeed.(.*)', self.readDATA(sys._getframe().f_code.co_name))
        self._getPortInfo(data, "Speed", r"", func)

    def IfMTU(self):
        """ 交换机端口 -> MTU: 9600 或 1500"""

        def func(value):
            return value

        data = re.findall(r'IF-MIB::ifMtu.(.*)', self.readDATA(sys._getframe().f_code.co_name))
        self._getPortInfo(data, "MTU", r"", func)

    def portChannel(self):
        """ 聚合端口查询 """
        data = re.findall(r'iso.2.840.10006.300.43.1.2.1.1.13.(.*)', self.readDATA(sys._getframe().f_code.co_name))
        if not data: return
        # 该设备无聚合端口或不支持此聚合端口oid采集'
        if "No Such" in data[0]: return
        for i in data:
            array_data = i.split()
            if len(array_data) < 3: continue
            idx_port = array_data[0]
            idx_channel = array_data[3]
            if self.dictPortChannel.has_key(idx_channel):
                self.dictPortChannel[idx_channel].append({'portIndex': idx_port})
            else:
                self.dictPortChannel[idx_channel] = [{'portIndex': idx_port}]

    def IpNetToMediaPhysAddress(self):
        """ 处理ARP信息 （ MAC -> IP ) """
        data = re.findall(r'.ipNetToMediaPhysAddress.(.*)', self.readDATA(sys._getframe().f_code.co_name))
        for i in data:
            array_data = i.partition('.')[2].split(' ')
            if len(array_data) < 3: continue
            remote_ip = array_data[0]
            mac = self.MacFormat(array_data[3])
            if mac:
                self.ARP[mac] = remote_ip

    def dot1dBasePortIfIndex(self, data=None):
        """ 取出端口和接口索引的关系 """
        if not data:
            data = self.readDATA(sys._getframe().f_code.co_name)
        data = re.findall(r'SNMPv2-SMI::mib-2.17.1.4.1.2.(.*)', data)
        self.MacPort["BasePort"] = {}
        for i in data:
            li = i.split()
            if len(li) < 4: continue
            self.MacPort["BasePort"][li[0]] = li[3]

        # 5:436208128

    def dot1qTpFdbPort(self, data=None):
        if not data:
            data = self.readDATA(sys._getframe().f_code.co_name)
        data = re.findall(r'SNMPv2-SMI::mib-2.17.4.3.1.2.(.*)', data)
        self.MacPort["FdbPort"] = {}
        for i in data:
            li = i.split(" ")
            if len(li) < 4: continue
            self.MacPort["FdbPort"][li[0]] = li[3]

        # 0.0.12.7.172.184: 4195

    def dot1qTpFdbMac(self, data=None, vlan=None):
        if not data:
            data = self.readDATA(sys._getframe().f_code.co_name)
        data = re.findall(r'SNMPv2-SMI::mib-2.17.4.3.1.1.(.*)', data)
        # 0.0.12.7.172.184 :
        for i in data:
            # 0.0.12.7.172.184
            mac_idx = i.split(' ')[0]
            mac_data = re.findall(r'.Hex-STRING: (.*)', i)
            # 00:00:0C:07:AC:B8
            if mac_data:
                mac = mac_data[0].replace(' ', ':')[0:-1]
            else:
                tmp_list = mac_idx.split('.')
                #### 转化成十六进制数据 ####
                try:
                    mac_addr_list = [str(hex(int(x))).replace('0x', '').upper().zfill(2) for x in tmp_list]
                    mac = ":".join(mac_addr_list)
                except BaseException as e:
                    # logger.error("ip: %s error: %s" % (self.ip, str(e)))
                    continue
            # 根据mac十进制取出端口信息
            if not self.MacPort["FdbPort"].has_key(mac_idx):
                continue
            port_idx = self.MacPort["FdbPort"][mac_idx]
            # 根据端口信息取端口索引
            if port_idx != '0' and self.MacPort["BasePort"].has_key(port_idx):
                If_idx = self.MacPort["BasePort"][port_idx]
                # 将对应索引的mac地址存入res_If中的remote_list
                # self.mac_port_table[mac] = If_idx
                self.mac_port_table[mac] = {"If_idx": If_idx, "vlan": vlan}

    def _getMacIfTable(self, key1, key2, key3, vlan):
        """ 找出通过交换机端口学习到的MAC地址 """
        self.dot1dBasePortIfIndex(self.DATA.get(key1, ""))
        self.dot1qTpFdbPort(self.DATA.get(key2, ""))
        self.dot1qTpFdbMac(self.DATA.get(key3, ""), vlan)

    def _lldpRemEntry(self, remote_key):
        result = {}
        data = self.readDATA(sys._getframe().f_code.co_name)
        peerMacList = re.findall(r'iso.0.8802.1.1.2.1.4.1.1.5.(.*)', data)
        for i in peerMacList:
            idx = i.split('.')[1]
            peer_mac_list = re.findall(r'.Hex-STRING: (.*) ', i)
            if peer_mac_list:
                PeerMac = peer_mac_list[0].replace(' ', ':').upper()
            else:
                PeerMac = "unknown mac"
            if result.has_key(idx):
                result[idx]['PeerMac'] = PeerMac
            else:
                result[idx] = {'PeerMac': PeerMac}

        peerType = re.findall(r'iso.0.8802.1.1.2.1.4.1.1.6.(.*)', data)
        for i in peerType:
            idx = i.split('.')[1]
            PeerType = i.split(' ')[3]
            if result.has_key(idx):
                result[idx]['PeerType'] = PeerType
            else:
                result[idx] = {'PeerType': PeerType}

        peerPortList = re.findall(r'iso.0.8802.1.1.2.1.4.1.1.7.(.*)', data)
        for i in peerPortList:
            idx = i.split('.')[1]
            peer_port_list = re.findall(r'."(.*)"', i)
            if peer_port_list:
                PeerPort = peer_port_list[0]
            else:
                PeerPort = 0
            if result.has_key(idx):
                result[idx]['PeerPort'] = PeerPort
            else:
                result[idx] = {'PeerPort': PeerPort}

        portDescList = re.findall(r'iso.0.8802.1.1.2.1.4.1.1.8.(.*)', data)
        for i in portDescList:
            idx = i.split('.')[1]
            port_desc = re.findall(r'."(.*)"', i)[0]
            if result.has_key(idx):
                result[idx]['PeerPortDesc'] = port_desc
            else:
                result[idx] = {'PeerPortDesc': port_desc}

        sysNameList = re.findall(r'iso.0.8802.1.1.2.1.4.1.1.9.(.*)', data)
        for i in sysNameList:
            idx = i.split('.')[1]
            peer_device_list = re.findall(r'."(.*)"', i)
            if peer_device_list:
                PeerDevoce = peer_device_list[0]
            else:
                PeerDevoce = ""
            if result.has_key(idx):
                result[idx]['PeerDevoce'] = PeerDevoce
            else:
                result[idx] = {'PeerDevoce': PeerDevoce}

        for k, v in result.items():
            res = {}
            #### 这里产生对端端口的标识符: name = peer_device + ":" + peer_port ,做端口关联关系的必要前提
            if v.has_key('PeerDevoce'):
                if '' != v['PeerDevoce']:
                    v['Name'] = v['PeerDevoce'] + ":" + v['PeerPort']
            for v_k, v_v in v.items():
                self.ChangeResult(self.RemoteKeys, res, v_k, v_v)
            if not self.ip_result.has_key(k):
                self.ip_result[k] = {}
            if not self.ip_result[k].has_key(remote_key):
                self.ip_result[k][remote_key] = []
            self.ip_result[k][remote_key].append(res)

    def _getCdplldpPortInfo(self, remote_key):
        """
        根据cisco cdp协议，采集有邻居协议的设备;否则使用lldp采集邻居协议设备
        """
        if self.BrandObj.__class__.__name__ == "Cisco":
            cdp_result = self.BrandObj.TmpData.get("cdp_result", {})
            for k, v in cdp_result.items():
                for subIdx, d in v.items():
                    res = {}
                    if d.get("PeerDevoce", "") and d.get("PeerPort", ""):
                        name = "{}:{}".format(d.get("PeerDevoce", ""), d.get("PeerPort", ""))
                    else:
                        name = d.get("PeerIp")
                    self.ChangeResult(self.RemoteKeys, res, "Name", name)
                    self.ChangeResult(self.RemoteKeys, res, "PeerIp", d.get("PeerIp"))
                    self.ChangeResult(self.RemoteKeys, res, "PeerType", d.get("PeerType"))
                    self.ChangeResult(self.RemoteKeys, res, "PeerDevoce", d.get("PeerDevoce"))
                    self.ChangeResult(self.RemoteKeys, res, "PeerMac", "unknown mac")
                    if not self.ip_result.has_key(k):
                        self.ip_result[k] = {}
                    if not self.ip_result[k].has_key(remote_key):
                        self.ip_result[k][remote_key] = []
                    self.ip_result[k][remote_key].append(res)
        else:
            self._lldpRemEntry(remote_key)

    def _processNetdPortRemote(self, remote_key):
        """根据mac-port数据，补齐交换机模型的remote_list字段信息"""
        for key, value in self.mac_port_table.items():
            # 00:00:0C:07:AC:B8 369098851
            If_idx = value.get("If_idx")
            vlan = value.get("vlan")
            # if not self.ip_result.has_key(value): continue
            if If_idx in self.ip_result:
                self.ChangeResult(self.ipAdEntKeys, self.ip_result[If_idx], "VLAN", vlan)
            if If_idx in self.dictPortChannel: continue
            mac_ip = self.ARP.get(key, '')
            data = {}
            self.ChangeResult(RemoteKeys, data, "PeerMac", key)
            if mac_ip:
                self.ChangeResult(RemoteKeys, data, "PeerIp", mac_ip)
            if self.ip_result[If_idx].has_key(remote_key):
                self.ip_result[If_idx][remote_key].append(data)
            else:
                self.ip_result[If_idx][remote_key] = [data]
        for key, value in self.ip_result.items():
            if value.has_key("Type") and value.has_key("IfName"):
                if value['Type'] == 'propVirtual' and 'port-channel' in value['IfName'].lower():
                    if value.has_key(remote_key):
                        value[remote_key] = []
            self.ChangeResult(self.ipAdEntKeys, value, "IfIdx", key)
            type = self._getvalue(value, "Type", self.ipAdEntKeys)
            ifname = self._getvalue(value, "IfName", self.ipAdEntKeys)
            if type == 'propVirtual' and ifname == "Vlan{}".format(key):
                self.ChangeResult(self.ipAdEntKeys, value, "VLAN", key)

    def RelationData(self):
        if self.BrandObj.__class__.__name__ == "Cisco":
            # for vlan in self.BrandObj.TmpData.get("vlan_list", []):
            #     res = vlan.split()
            #     if len(res) < 4: continue
            #     if res[3] != '0':
            #         idx = res[0]
            #         if idx in self.ip_result:
            #             self.ChangeResult(self.ipAdEntKeys, self.ip_result[idx], "VLAN", res[3])
            #         if res[3] not in vlan_info and res[3] != '1':
            #             vlan_info.append(res[3])
            vlan_info = self.BrandObj.TmpData.get("vlan_list", set())
            oidall = self.AllOid.get("Public", {})
            for vlan in vlan_info:
                key1 = "dot1dBasePortIfIndex_%s" % vlan
                key2 = "dot1qTpFdbPort_%s" % vlan
                key3 = "dot1qTpFdbMac_%s" % vlan
                oid = {
                    key1: oidall.get("dot1dBasePortIfIndex"),
                    key2: oidall.get("dot1qTpFdbPort"),
                    key3: oidall.get("dot1qTpFdbMac"),
                }
                _token = self.token
                self.token = "{}@{}".format(_token, vlan)
                self._GetOidData(oid, False)
                self.token = _token
                if not (key1 in self.DATA and key2 in self.DATA and key3 in self.DATA): continue
                txt = "{}{}{}".format(self.DATA[key1], self.DATA[key2], self.DATA[key3])
                if "No Such Instance currently exists at this OID" in txt: continue
                self._getMacIfTable(key1, key2, key3, vlan)
        remote_key = self.ipAdEntKeys["RemoteList"]
        self._getCdplldpPortInfo(remote_key)
        self._processNetdPortRemote(remote_key)

    def UpdateIpaddressByArp(self, IpAddressKeys):
        """
        根据arp表去更新 IPADDRESS 模型中的数据
        :param IpAddressKeys:
        :return:
        """
        result = []
        alreadyAdd = []
        for mac, ip in self.ARP.items():
            print("UpdateIpaddressByArp")
            print("H"*40)
            print(self.ARP)
            res = {}
            if ip and mac and ip not in alreadyAdd:
                self.ChangeResult(IpAddressKeys, res, "Name", ip)
                self.ChangeResult(IpAddressKeys, res, "Mac", mac)
                self.ChangeResult(IpAddressKeys, res, "Used", u"已使用")
                alreadyAdd.append(ip)
                result.append(res)
        return result


class Cisco(SnmpWalk):

    def __init__(self, *args, **kwargs):
        super(Cisco, self).__init__(*args, **kwargs)
        self.AllOid["Cisco"] = self._GetOid
        self.TmpData = dict()  # 临时数据
        self._GetOidData()

    @property
    def _GetOid(self):
        oid = OrderedDict()
        oid["cisco_serial"] = "1.3.6.1.2.1.47.1.1.1.1.11"
        oid["cisco_module"] = "1.3.6.1.2.1.47.1.1.1.1.13"
        oid["vmVlan"] = "1.3.6.1.4.1.9.9.46.1.3.1.1.18"
        oid["cdpCacheType"] = "1.3.6.1.4.1.9.9.23.1.2.1.1.3"
        oid["cdpCacheSysName"] = "1.3.6.1.4.1.9.9.23.1.2.1.1.6"
        oid["cdpCacheIP"] = "1.3.6.1.4.1.9.9.23.1.2.1.1.4"
        oid["cdpCachePortName"] = "1.3.6.1.4.1.9.9.23.1.2.1.1.7"
        return oid

    def cisco_serial(self):
        data = self.readDATA(sys._getframe().f_code.co_name)
        serial_list = re.findall(r'STRING: "(.*)"', data)
        if serial_list:
            self.ChangeResult(self.ResultKeys, self.result, "SN", serial_list[0])

    def cisco_module(self):
        data = self.readDATA(sys._getframe().f_code.co_name)
        module_list = re.findall(r'STRING: "(.*)"', data)
        module_list = list(filter(None, module_list))
        if module_list:
            self.ChangeResult(self.ResultKeys, self.result, "Model", module_list[0])

    def vmVlan(self):
        data = re.findall(r'.9.9.46.1.3.1.1.18.1.(.*)', self.readDATA(sys._getframe().f_code.co_name))
        vlan_list = set()
        if not data: return
        for vlan in data:
            if "No Such" in data[0]: continue
            res = vlan.split()
            if len(res) < 4: continue
            if res[0] != '0':
                vlan_list.add(res[0])
        self.TmpData["vlan_list"] = vlan_list

    def cdpCacheType(self):
        """ 对端设备类型 """
        data = re.findall(r'.9.9.23.1.2.1.1.3.(.*)', self.readDATA(sys._getframe().f_code.co_name))
        self.TmpData["cdp_result"] = {}
        for i in data:
            if "No Such" in i: continue
            id = i.split('.')[0]
            subIdx = i.split(' ')[0].split('.')[1]
            cdp_type = re.findall(r'.INTEGER: (.*)', i)[0]
            if self.TmpData["cdp_result"].has_key(id):
                if self.TmpData["cdp_result"][id].has_key(subIdx):
                    # self.ChangeResult(self.RemoteKeys, self.TmpData["cdp_result"][id], "Model", cdp_type)
                    self.TmpData["cdp_result"][id][subIdx]["PeerType"] = cdp_type
                else:
                    self.TmpData["cdp_result"][id][subIdx] = {"PeerType": cdp_type}
            else:
                self.TmpData["cdp_result"][id] = {subIdx: {"PeerType": cdp_type}}

    def cdpCacheIP(self):
        """对端设备ip"""
        data = re.findall(r'.9.9.23.1.2.1.1.4.(.*)', self.readDATA(sys._getframe().f_code.co_name))
        for i in data:
            if "No Such" in i: continue
            idx_list = i.split('.')
            if len(idx_list) < 1: continue
            idx = idx_list[0]
            subIdx_list = i.split(' ')
            if len(subIdx_list) < 1: continue
            subIdx_list = subIdx_list[0].split(".")
            if len(subIdx_list) < 2: continue
            subIdx = subIdx_list[1]
            # 若type为1，则为ip
            if self.TmpData["cdp_result"][idx][subIdx]["PeerType"] != '1':
                # logger.info("idx = {}, subIdx={}".format(idx, subIdx))
                continue
            remote_ip_list = re.findall(r'.Hex-STRING: (.*)', i)
            if len(remote_ip_list) < 1: continue
            remote_ip = remote_ip_list[0]
            # 十六进制转换为十进制
            res_ip = ''
            for i in remote_ip.split():
                res_ip += (str(int(i, 16)) + '.')
            logger.debug("[CISCO_CDP_IP]idx = {}, subIdx={}, remote_ip = {}".format(idx, subIdx, res_ip[:-1]))
            if self.TmpData["cdp_result"].has_key(idx):
                if self.TmpData["cdp_result"][idx].has_key(subIdx):
                    self.TmpData["cdp_result"][idx][subIdx]["PeerIp"] = res_ip[:-1]
                else:
                    self.TmpData["cdp_result"][idx][subIdx] = {"PeerIp": res_ip[:-1]}
            else:
                self.TmpData["cdp_result"][idx] = {subIdx: {"PeerIp": res_ip[:-1]}}

    def cdpCacheSysName(self):
        """ 对端设备名称 """
        data = re.findall(r'.9.9.23.1.2.1.1.6.(.*)', self.readDATA(sys._getframe().f_code.co_name))
        for i in data:
            if "No Such" in i: continue
            idx = i.split('.')[0]
            subIdx = i.split(' ')[0].split('.')[1]
            remote_sys_name = re.findall(r'."(.*)"', i)[0]
            if self.TmpData["cdp_result"].has_key(idx):
                if self.TmpData["cdp_result"][idx].has_key(subIdx):
                    self.TmpData["cdp_result"][idx][subIdx]["PeerDevoce"] = remote_sys_name
                else:
                    self.TmpData["cdp_result"][idx][subIdx] = {"PeerDevoce": remote_sys_name}
            else:
                self.TmpData["cdp_result"][idx] = {subIdx: {"PeerDevoce": remote_sys_name}}

    def cdpCachePortName(self):
        """ 对端端口名称 """
        data = re.findall(r'.9.9.23.1.2.1.1.7.(.*)', self.readDATA(sys._getframe().f_code.co_name))
        for i in data:
            if "No Such" in i: continue
            idx = i.split('.')[0]
            subIdx = i.split(' ')[0].split('.')[1]
            remote_portName = re.findall(r'."(.*)"', i)[0]
            if self.TmpData["cdp_result"].has_key(idx):
                if self.TmpData["cdp_result"][idx].has_key(subIdx):
                    self.TmpData["cdp_result"][idx][subIdx]["PeerPort"] = remote_portName
                else:
                    self.TmpData["cdp_result"][idx][subIdx] = {"PeerPort": remote_portName}
            else:
                self.TmpData["cdp_result"][idx] = {subIdx: {"PeerPort": remote_portName}}


class HuaWei(SnmpWalk):
    def __init__(self, *args, **kwargs):
        super(HuaWei, self).__init__(*args, **kwargs)
        self.AllOid["HuaWei"] = self._GetOid
        self.TmpData = dict()  # 临时数据
        self._GetOidData()

    @property
    def _GetOid(self):
        oid = OrderedDict()
        return oid


class Juniper(SnmpWalk):

    def __init__(self, *args, **kwargs):
        super(Juniper, self).__init__(*args, **kwargs)
        self.AllOid["Juniper"] = self._GetOid
        self.TmpData = dict()  # 临时数据
        self._GetOidData()

    @property
    def _GetOid(self):
        oid = OrderedDict()
        return oid

    def sysDescr(self):
        data = self.readDATA(sys._getframe().f_code.co_name)
        data_list = data.split(',')
        model = ""
        version = ""
        if data_list:
            model_list = data_list[1].split(' ')
            if len(model_list) >= 2:
                model = model_list[2]
        if len(data_list) >= 4:
            v = re.findall(r'.JUNOS (.*)', data_list[2])
            version = v[0]

        self.ChangeResult(self.ResultKeys, self.result, "sysVersion", version)
        self.ChangeResult(self.ResultKeys, self.result, "Model", model)


class Dell(SnmpWalk):

    def __init__(self, *args, **kwargs):
        super(Dell, self).__init__(*args, **kwargs)
        self.AllOid["Dell"] = self._GetOid
        self.TmpData = dict()  # 临时数据
        self._GetOidData()

    @property
    def _GetOid(self):
        oid = OrderedDict()
        return oid


def UploadIpAddress(easyops, ipaddress_list, api=False):
    """ IP地址上报 """
    for i in ipaddress_list:
        i["updateTime"] = easyops.NowTime
    if api:
        easyops.model = "IPADDRESS"
        easyops.post(ipaddress_list, ["name"])
    else:
        easyops.AutoUpload(ipaddress_list, "IPADDRESS", ["name"], True)


def UploadSwitch(easyops, switch_list, port_list, api=False):
    if api:
        easyops.model = "NETDPORT"
        easyops.post(port_list, ["name"])
        new_switch_list = []
        for switch in switch_list:
            new_port_list = []
            for i in switch.get("port_list", []):
                port = easyops.get(fields={"name": True}, query={"name": i["name"]})
                if port:
                    port = port[0]
                    new_port_list.append({"instanceId": port["instanceId"]})
            if new_port_list:
                switch["port_list"] = new_port_list
            #有设备名称时候，增加更新时间
            if  switch.get("sname")!=None and switch.get("sname")!="":
                switch["updateTime"] = easyops.NowTime
            else:
                switch["updateTime"] = ""
            if not switch.has_key(ResultKeys["netSnmp"]):
                switch[ResultKeys["netSnmp"]] = "正常"
            new_switch_list.append(switch)
        easyops.post(new_switch_list, ["instanceId"], upsert=False, model="_SWITCH")
    else:
        easyops.AutoUpload(port_list, "NETDPORT", ["name"], True)
        easyops.AutoUpload(switch_list, "_SWITCH", ["instanceId"], True)


def GetSwitch(easyops):
    fields = {
        "ip": True,
        "community": True,
        "brand": True,
    }
    data = easyops.get(fields=fields, query=query)
    return data
# def test():
#     switch_all = [{"ip": "192.168.1.234", "instanceId": "48dsd4564ax", "brand": "sfdfd"}]
#     port_list = Manager().list()
#     ipaddress_list = Manager().list()
#     switch_list = Manager().list()
#     error_list = Manager().list()
#     for switch in switch_all:
#         SwitchCollection(switch, "community", port_list, ipaddress_list, switch_list, error_list, True)
#
#     print error_list
#     print ipaddress_list
#     print switch_list
#     print port_list
#        pool.apply_async(SwitchCollection,
#                         (switch, community, port_list, ipaddress_list, switch_list, error_list, False))
def SwitchCollection(switch_data, community, port_list, ipaddress_list, switch_list, error_list, debug):
    settings()
    ip = switch_data.get("ip")
    instanceId = switch_data.get("instanceId")
    brand = switch_data.get("brand", "")
    logger.info("start {} {}".format(ip, instanceId, brand))
    try:
        switch = Public(allBrand, ip, brand, community, ResultKeys, ipAdEntKeys, RemoteKeys, FileBasePath, debug)
        switch.CleaningData()
        switch.RelationData()
        ip_set = []
        new_ip_result = []

        for key, value in switch.ip_result.items():
            name = value.get(ipAdEntKeys["Name"])
            if not name: continue
            if name in ip_set: continue
            ip_set.append(name)
            new_ip_result.append(value)
        port_list.extend(new_ip_result)
        ipaddress_list.extend(switch.UpdateIpaddressByArp(IpAddressKeys))
        port_set = []
        new_result = []
        for i in switch.result.get(ResultKeys["NetPort"], []):
            name = i.get(ipAdEntKeys["Name"])
            if not name: continue
            if name in port_set: continue
            port_set.append(name)
            new_result.append(i)
        switch.result[ResultKeys["NetPort"]] = new_result
        switch.result["instanceId"] = instanceId
        switch_list.append(switch.result)
        error_list.extend(switch.error_list)
    except BaseException as e:
        error_list.extend([{"ip": ip, "error": str(e)}])


def ChangeName(easyops):
    """ 特殊处理暂时没有ip的交换机，修改name为 ip_sn """
    easyops.model = "_SWITCH"
    fields = {
        "sn": True,
        "ip": True,
    }
    data_list = easyops.get(fields=fields, query={"cmdbProxy": query["cmdbProxy"]})
    new_data = []
    for i in data_list:
        ip = i.get("ip", "")
        sn = i.get("sn", "")
        name = ip or sn
        if ip and sn:
            name = "{}_{}".format(ip, sn)
        new_data.append({"instanceId": i["instanceId"], "name": str(name)})
    easyops.post(new_data, ["instanceId"], upsert=False)


def DeleteUpdateTime(easyops):
    """ 清除所有设备的采集时间 """
    fields = {
        "updateTime": True,
    }
    _query = {
        "updateTime": {"$exists": True},
        "cmdbProxy": query["cmdbProxy"]
    }
    data = easyops.get(fields=fields, query=_query)
    for i in data:
        i["updateTime"] = ""
    easyops.post(data, ["instanceId"], upsert=False, model="_SWITCH")


def main():
    easyops = EasyOps("_SWITCH", CMDB_IP, ORG)
    DeleteUpdateTime(easyops)
    switch_all = GetSwitch(easyops)
    port_list = Manager().list()
    ipaddress_list = Manager().list()
    switch_list = Manager().list()
    error_list = Manager().list()
    pool = Pool(int(cpu_count() / 2))
    for switch in switch_all:
        community = LOCALS.get(switch.get("community", ""), "")
        pool.apply_async(SwitchCollection,
                         (switch, community, port_list, ipaddress_list, switch_list, error_list, False))
    pool.close()
    pool.join()
    logger.error("{}".format(error_list))
    UploadIpAddress(easyops, ipaddress_list=ipaddress_list, api=True)
    UploadSwitch(easyops, switch_list, port_list, api=True)
    ChangeName(easyops)


def test():
    switch_all = [{"ip": "172.28.240.9", "instanceId": "48dsd4564ax", "brand": "sfdfd"}]
    port_list = Manager().list()
    ipaddress_list = Manager().list()
    switch_list = Manager().list()
    error_list = Manager().list()
    for switch in switch_all:
        SwitchCollection(switch, "community", port_list, ipaddress_list, switch_list, error_list, True)
        print(port_list)
    print error_list
    print ipaddress_list
    print switch_list
    print port_list


def settings():
    global CMDB_IP, ORG, allBrand, query, ResultKeys, ipAdEntKeys, RemoteKeys, IpAddressKeys, FileBasePath
    CMDB_IP = EASYOPS_CMDB_HOST.split(':')[0]
    ORG = EASYOPS_ORG
    # CMDB_IP = "192.25.101.196"
    # ORG = "3109"
    FileBasePath = r"/tmp/switch"  # 为空不保存至本地
    # FileBasePath = r"E:\office\shell\data\switch"z

    # 品牌对应的class, key根据cmdb中存的品牌或者oid获取描述中的品牌
    allBrand = {
        "Cisco": Cisco,
        "Juniper": Juniper,
        "HuaWei": HuaWei,
    }
    PROXY = {
        "129.20.92.183": {"proxy": "上海交易(含托管)"},
        "129.20.92.182": {"proxy": "上海交易(含托管)"},
        "10.20.97.140": {"proxy": "上海管理(含信托、DMZ)"},
        "10.20.97.139": {"proxy": "上海管理(含信托、DMZ)"},
        "129.25.98.153": {"proxy": "福州管理(含DMZ)"},
        "129.25.98.152": {"proxy": "福州管理(含DMZ)"},
        "129.25.90.157": {"proxy": "福州交易(含南方中心)"},
        "129.25.90.158": {"proxy": "福州交易(含南方中心)"},
        "192.25.101.65": {"proxy": "开发测试(含测试DMZ)"},
        "10.83.0.21": {"proxy": "上海金桥"},
        "10.83.0.22": {"proxy": "上海金桥"},
        "10.53.0.21": {"proxy": "福州滨海"},
        "10.53.0.22": {"proxy": "福州滨海"},
    }
    proxy_info = PROXY[EASYOPS_LOCAL_IP]
    query = {
        "cmdbProxy": proxy_info["proxy"],
        "ip": {"$exists": True},
        "ddqk": {"$ne": "堆叠备用"}
    }
    if SW_IP:
        query["ip"] = SW_IP
    # 不需要的字段就不要填写 value
    ResultKeys = {
        "IP": "ip",  # ip
        "Name": "name",  # ip
        "netSnmp": "netSnmp",  # SNMP是否能通
        "updateTime": "updateTime",  # 更新时间
        "sysVersion": "sysVersion",  # 版本
        "Model": "sysModel",  # 型号
        "sysName": "sname",  # 设备名称
        "sysDescr": "sysdescr",  # 设备描述
        "SN": "sn",  # 序列号
        "Brand": "brand",  # 品牌
        "dev_upTime": "",  # 设备启动时间
        "NetPort": "port_list",  # 网络设备端口

    }
    # 网络设备端口
    ipAdEntKeys = {
        "Name": "name",  # 端口标识
        "IfName": "if_name",  # 端口名
        "Type": "type",  # 类型
        "OperStatus": "oper_status",  # OperStatus
        "AdminStatus": "admin_status",  # AdminStatus
        "PhysAddr": "phys_addr",  # 物理地址
        "Speed": "speed",  # 协商速率
        "MTU": "mtu",  # mtu
        "RemoteList": "remote_list",  # 对端列表
        "VLAN": "vlan",  #
        "IfIdx": "ifIdx",  # 接口号
    }
    # 对端列表
    RemoteKeys = {
        "Name": "name",  # 标识符
        "PeerMac": "peer_mac",  # 物理地址
        "PeerDevoce": "peer_device",  # 设备
        "PeerPort": "peer_port",  # 端口
        "PeerPortDesc": "peer_port",  # 端口描述
        "PeerType": "peer_type",  # 端口类型
        "PeerIp": "",  # ip
    }
    # IP地址
    IpAddressKeys = {
        "Name": "name",  # IP地址
        # "Status": "status",  # 是否分配 : 已分配; 未分配; 预分配
        "Mac": "mac",  #
        "Used": "used",
    }


def docs():
    """
    支持交换机品牌及类型
    ------------------------------------------
    1. 华为
        Quidway S7706
        5720-52X-LI-AC
        S5720-52X-SI-AC
        S6720-54C-EI-48S-AC

    2. Cisco
        C2950
        C2960
        C3560E

    3. H3C
        S10506
        S5008PV2-EI
        S5110-28P
        S5110-28P-PWR
        S5110-52P
        S5110-52P-PWR	172.24.63.40
        S5130-28S-EI	172.24.32.27
        S5130S-28P-EI	172.24.61.54
        S5560-54C-EI	10.2.213.31
        S5820V2-54QS-GE	172.24.8.5
        S6300-42QF	172.24.8.4
        S7502E	172.24.6.2
        S7503E	172.24.0.7
        S7506E	172.24.0.27
        S9810	172.24.0.4
        SR8808-X	172.24.0.102


    4. NewH3C
        S10506	172.24.0.15
        S10508	172.24.0.33
        S10510	172.24.0.12
        S5110-28P-PWR	172.24.62.52
        S5110-28P-SI	172.24.31.15
        S5110-52P	172.24.22.36
        S5110-52P-PWR	172.24.43.22
        S5130S-28S-EI	172.24.33.19
        S5130S-28S-PWR-HI	172.24.32.29
        S5130S-52S-HI	172.24.54.3
        S6800-54QF	172.24.0.6
        S7502E	172.24.75.3
        SR8804-X	172.24.0.103
        SR8808-X	172.24.0.100
        WX5540H	172.24.0.50

    5.
    """


if __name__ == '__main__':
    LOCALS = locals()
    settings()
    main()
 test()
