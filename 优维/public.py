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
