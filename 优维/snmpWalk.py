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
        self.ip_result = OrderedDict()  # RelationData
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
